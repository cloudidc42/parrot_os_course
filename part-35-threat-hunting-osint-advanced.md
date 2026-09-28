# Part 35: Threat Hunting & OSINT Advanced (Steps 341-350)

## Step 341: Threat Hunting Fundamentals

```python
#!/usr/bin/env python3
# threat_hunting_fundamentals.py

THREAT_HUNTING_OVERVIEW = """
=== Threat Hunting Methodology ===

Definition:
  Proactive search for threats that have evaded existing security controls
  NOT reactive (waiting for alerts)

Hunting Maturity Model (HMM):
  Level 0: Initial - Rely on automated alerts
  Level 1: Minimal - Use threat intel IOCs
  Level 2: Procedural - Follow documented hunts
  Level 3: Innovative - Create custom hunts
  Level 4: Leading - Data-driven threat modeling

Hunting Loop:
  1. Hypothesis Creation
     - Threat intelligence
     - Attack framework (MITRE ATT&CK)
     - Known TTPs
     - Anomaly analysis
  
  2. Data Collection
     - Logs (Windows Event, Sysmon, Network)
     - EDR telemetry
     - SIEM data
  
  3. Investigation
     - Query and filter data
     - Look for anomalies
     - Pivot and correlate
  
  4. Response
     - Document findings
     - Create/improve detection rules
     - Remediate if threat found
"""

SYSMON_HUNT_EVENTS = """
=== Sysmon Events for Threat Hunting ===

Event 1 - Process Create
  Hunt: Unusual parent-child processes
  Example: cmd.exe spawned by winword.exe

Event 3 - Network Connection  
  Hunt: Unusual outbound connections
  Example: powershell.exe connecting to external IP

Event 7 - Image Loaded
  Hunt: DLL loading from unusual paths
  Example: DLL loaded from C:\\Users\\Public\\

Event 8 - CreateRemoteThread
  Hunt: Process injection
  Example: svchost.exe injecting into explorer.exe

Event 10 - ProcessAccess
  Hunt: LSASS memory access
  Example: Unknown process opening lsass.exe with PROCESS_VM_READ

Event 11 - FileCreate
  Hunt: Suspicious file creation
  Example: exe/dll created in temp directories

Event 13 - RegistryValue Set
  Hunt: Persistence via registry
  Example: Run key modification

Event 22 - DNS Query
  Hunt: C2 communication
  Example: High-entropy domain names, DGA domains

Event 23 - FileDelete
  Hunt: Log wiping, anti-forensics
  Example: Security logs deleted
"""

print(THREAT_HUNTING_OVERVIEW)
print(SYSMON_HUNT_EVENTS)
```

## Step 342: Windows Event Log Analysis

```python
#!/usr/bin/env python3
# windows_event_analysis.py

KEY_EVENT_IDS = """
=== Key Windows Event IDs for Threat Hunting ===

Authentication:
  4624 - Logon Success
  4625 - Logon Failure  
  4634 - Logoff
  4648 - Logon with explicit credentials (RunAs)
  4672 - Special privileges assigned (admin logon)
  4768 - Kerberos TGT request
  4769 - Kerberos Service Ticket request (Kerberoasting!)
  4771 - Kerberos pre-auth failed
  4776 - NTLM authentication
  4777 - Domain controller NTLM auth failed

Account Management:
  4720 - User account created
  4722 - User account enabled
  4728 - User added to security-enabled global group
  4732 - User added to security-enabled local group
  4756 - User added to universal security group

Process:
  4688 - Process created (new process) - must enable
  4689 - Process terminated

Object Access:
  4663 - Object access attempt
  4670 - Object permissions changed

Policy Changes:
  4698 - Scheduled task created
  4702 - Scheduled task updated
  4704 - User right assigned
  4719 - Audit policy changed

Security:
  4697 - Service installed
  7045 - New service installed
  1102 - Audit log cleared (Security log)
  104 - Audit log cleared (System log)

PowerShell:
  4103 - PowerShell Module logging
  4104 - PowerShell Script Block Logging (CRITICAL!)
  400/403 - PowerShell engine state
  600 - PowerShell provider lifecycle

WMI:
  5857 - WMI activity
  5860 - WMI event registration (WMI persistence!)
  5861 - WMI event binding (WMI persistence!)
"""

PYTHON_EVENT_QUERY = '''
import win32evtlog
import win32evtlogutil
from datetime import datetime

def query_security_events(server='localhost', event_id=4625, max_records=100):
    """Query Windows security events"""
    events = []
    
    handle = win32evtlog.OpenEventLog(server, 'Security')
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    try:
        records = win32evtlog.ReadEventLog(handle, flags, 0)
        for record in records:
            if record.EventID == event_id:
                events.append({
                    'timestamp': str(record.TimeGenerated),
                    'event_id': record.EventID,
                    'source': record.SourceName,
                    'message': win32evtlogutil.SafeFormatMessage(record, 'Security')
                })
                if len(events) >= max_records:
                    break
    finally:
        win32evtlog.CloseEventLog(handle)
    
    return events

# Query failed logons
failed_logins = query_security_events(event_id=4625)
for event in failed_logins[:5]:
    print(f"Failed login at {event['timestamp']}")
'''

ELASTIC_QUERIES = """
=== ELK Stack Hunting Queries ===

# Kibana KQL / Elasticsearch queries

# 1. Failed logon spray detection
event.id: 4625 and winlog.event_data.SubStatus: 0xC000006A
| stats count by winlog.event_data.TargetUserName, source.ip
| where count > 10

# 2. Kerberoasting detection
event.id: 4769 and winlog.event_data.ServiceName: *$ and
winlog.event_data.TicketEncryptionType: 0x17  # RC4-HMAC

# 3. DCSync detection
event.id: 4662 and winlog.event_data.Properties: *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*

# 4. PowerShell script block
event.id: 4104 and winlog.event_data.ScriptBlockText: *(IEX OR Invoke-Expression OR Download*)

# 5. Process injection indicator
event.id: 8 (Sysmon) - CreateRemoteThread
process.name: lsass.exe and event.action: CreateRemoteThread

# 6. Lateral movement via PsExec
process.name: PSEXESVC.exe OR (process.name: cmd.exe and process.parent.name: services.exe)

# 7. Living off land binaries
process.name: (certutil.exe OR mshta.exe OR wscript.exe OR cscript.exe)
and network.direction: outbound
"""

print(KEY_EVENT_IDS)
print(ELASTIC_QUERIES)
```

## Step 343: Network Traffic Analysis

```python
#!/usr/bin/env python3
# network_traffic_analysis.py

from scapy.all import *
from collections import Counter, defaultdict
import struct

class NetworkThreatHunter:
    def __init__(self, pcap_file: str = None, interface: str = None):
        self.pcap_file = pcap_file
        self.interface = interface
        self.packets = []
        self.c2_indicators = []
    
    def load_packets(self):
        """Load packets from pcap or capture live"""
        if self.pcap_file:
            self.packets = rdpcap(self.pcap_file)
        elif self.interface:
            self.packets = sniff(iface=self.interface, count=1000)
        print(f"[*] Loaded {len(self.packets)} packets")
    
    def hunt_c2_beaconing(self, interval_threshold: float = 5.0) -> list:
        """Detect C2 beaconing by regular intervals"""
        # Group connections by src->dst
        connections = defaultdict(list)
        
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
                connections[key].append(float(pkt.time))
        
        beacons = []
        for conn, timestamps in connections.items():
            if len(timestamps) < 5:
                continue
            
            timestamps.sort()
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            if not intervals:
                continue
            
            avg_interval = sum(intervals) / len(intervals)
            # Low variance = regular beaconing
            variance = sum((i - avg_interval)**2 for i in intervals) / len(intervals)
            
            if avg_interval > 30 and variance < interval_threshold:
                beacons.append({
                    'src': conn[0],
                    'dst': conn[1],
                    'port': conn[2],
                    'avg_interval': avg_interval,
                    'variance': variance,
                    'count': len(timestamps)
                })
                print(f"[+] Possible beacon: {conn[0]} -> {conn[1]}:{conn[2]}")
                print(f"    Interval: {avg_interval:.1f}s, Variance: {variance:.2f}")
        
        return beacons
    
    def hunt_dns_c2(self) -> list:
        """Hunt DNS-based C2 (high entropy domain names, long subdomains)"""
        from scapy.layers.dns import DNS, DNSQR
        import math
        
        suspicious_dns = []
        
        for pkt in self.packets:
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    qname = pkt[DNSQR].qname.decode(errors='ignore').rstrip('.')
                    
                    # Calculate entropy
                    entropy = self._shannon_entropy(qname)
                    
                    # Check for long subdomains (DNS tunneling)
                    labels = qname.split('.')
                    max_label_len = max(len(l) for l in labels) if labels else 0
                    
                    suspicious = False
                    reasons = []
                    
                    if entropy > 3.5 and len(qname) > 50:
                        suspicious = True
                        reasons.append(f'High entropy: {entropy:.2f}')
                    
                    if max_label_len > 40:  # DNS tunneling sends data in labels
                        suspicious = True
                        reasons.append(f'Long label: {max_label_len}')
                    
                    if suspicious:
                        suspicious_dns.append({
                            'domain': qname,
                            'entropy': entropy,
                            'max_label_len': max_label_len,
                            'src': pkt[IP].src if pkt.haslayer(IP) else 'N/A',
                            'reasons': reasons
                        })
                        print(f"[+] Suspicious DNS: {qname} ({', '.join(reasons)})")
                except:
                    pass
        
        return suspicious_dns
    
    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0
        import math
        freq = Counter(text)
        length = len(text)
        entropy = -sum((count/length) * math.log2(count/length) 
                       for count in freq.values())
        return entropy
    
    def hunt_data_exfiltration(self) -> list:
        """Hunt for large data transfers"""
        # Track outbound bytes per destination
        outbound = defaultdict(int)
        local_subnets = ['192.168.', '10.', '172.']
        
        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                size = len(pkt)
                
                # Check if src is internal, dst is external
                is_internal_src = any(src.startswith(s) for s in local_subnets)
                is_external_dst = not any(dst.startswith(s) for s in local_subnets)
                
                if is_internal_src and is_external_dst:
                    outbound[dst] += size
        
        suspicious = []
        for dst, total_bytes in outbound.items():
            if total_bytes > 10 * 1024 * 1024:  # > 10MB to single external host
                suspicious.append({'dst': dst, 'bytes': total_bytes})
                print(f"[+] Large transfer to {dst}: {total_bytes/1024/1024:.1f} MB")
        
        return suspicious

# ZEEK/BRO analysis examples
ZEEK_QUERIES = """
=== Zeek Log Analysis ===

# conn.log - Network connections
zcat conn.log.gz | zeek-cut id.orig_h id.resp_h id.resp_p duration bytes | sort

# Find long duration connections (potential C2)
zcat conn.log.gz | zeek-cut id.orig_h id.resp_h id.resp_p duration | \
    awk '$4 > 3600' | sort -t$'\\t' -k4 -rn | head -20

# dns.log - DNS queries
zcat dns.log.gz | zeek-cut query answers | head -20

# Find DNS queries with high entropy (potential C2)
zcat dns.log.gz | zeek-cut query | \
    awk '{n=split($1,a,"."); for(i=1;i<=n;i++) print length(a[i]) " " $1}' | \
    awk '$1 > 40' | head -20

# http.log - HTTP traffic
zcat http.log.gz | zeek-cut id.orig_h host uri user_agent | head -20

# Find suspicious user agents
zcat http.log.gz | zeek-cut user_agent | sort | uniq -c | sort -rn | head -20

# files.log - Downloaded files
zcat files.log.gz | zeek-cut rx_hosts mime_type filename | head -20
"""

print(ZEEK_QUERIES)
```

## Step 344: Malware Analysis Basics

```python
#!/usr/bin/env python3
# malware_analysis_basics.py

STATIC_ANALYSIS = """
=== Static Malware Analysis ===

1. INITIAL TRIAGE
   file malware.exe          # File type
   md5sum malware.exe        # Calculate hash
   sha256sum malware.exe     # SHA256 hash
   strings malware.exe | head -50  # Extract strings
   
   # Upload hash to threat intel
   curl https://www.virustotal.com/api/v3/files/{hash}

2. STRINGS ANALYSIS
   # Interesting strings to look for:
   strings malware.exe | grep -iE 'http|ftp|cmd|powershell|reg|tasklist'
   strings malware.exe | grep -iE '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+'  # IP addresses
   strings malware.exe | grep -iE '[a-zA-Z0-9+/]{40,}'  # Base64
   strings malware.exe | grep -iE 'HKEY_|HKLM|HKCU'  # Registry
   strings malware.exe | grep -iE 'CreateProcess|VirtualAlloc|LoadLibrary'  # API calls

3. PE ANALYSIS (Windows executables)
   pestudio malware.exe      # GUI PE analyzer
   pecheck malware.exe       # Command line
   
   # PEView sections of interest:
   # .text = code, .data = initialized data, .rsrc = resources
   # High entropy sections = packed/encrypted
   
   # Check imports (API calls used)
   # Suspicious imports:
   # VirtualAllocEx, WriteProcessMemory, CreateRemoteThread = Process injection
   # RegCreateKey, RegSetValue = Registry persistence
   # WinExec, CreateProcess, ShellExecute = Execute commands
   # InternetOpen, HttpSendRequest, WinHttpOpen = Network comms

4. ENTROPY ANALYSIS
   # High entropy (>7.0) in sections = encrypted/packed
   # Normal code ~6.0-7.0 entropy
   
   python3 -c "
   import sys, math
   data = open('malware.exe', 'rb').read()
   freq = {}
   for b in data:
       freq[b] = freq.get(b, 0) + 1
   entropy = -sum((c/len(data)) * math.log2(c/len(data)) for c in freq.values())
   print(f'Entropy: {entropy:.2f}')
   "
"""

DYNAMIC_ANALYSIS = """
=== Dynamic Malware Analysis ===

Sandbox Analysis:
  - Any.run: https://app.any.run
  - JoeSandbox: https://www.joesandbox.com
  - Hybrid Analysis: https://www.hybrid-analysis.com
  - Cuckoo Sandbox (self-hosted)

Manual Dynamic Analysis:
  1. Set up isolated VM (no internet, snapshot)
  2. Start monitoring tools:
     - Process Monitor (procmon.exe)
     - Process Explorer (procexp.exe)
     - Wireshark (traffic capture)
     - Regshot (registry before/after)
     
  3. Run malware
  4. Observe:
     - New processes spawned
     - File system changes
     - Registry changes
     - Network connections
     - Services created
     
  5. Analyze captures

Process Monitor Filters:
  Path contains TEMP or STARTUP
  Result is ACCESS DENIED
  Process Name is malware.exe
  Category is Write

Network Analysis:
  - Capture with Wireshark
  - Use FakeNet-NG to intercept connections
  - INetSim for simulating internet services
  - Check DNS queries (C2 domains?)
"""

PYTHON_STATIC_ANALYSIS = '''
import pefile
import hashlib
import math
from collections import Counter

def analyze_pe(file_path: str):
    """Analyze PE file for suspicious indicators"""
    results = {}
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Hashes
    results['md5'] = hashlib.md5(data).hexdigest()
    results['sha256'] = hashlib.sha256(data).hexdigest()
    
    # Entropy
    freq = Counter(data)
    entropy = -sum((c/len(data)) * math.log2(c/len(data)) for c in freq.values())
    results['entropy'] = entropy
    
    if entropy > 7.0:
        print(f"[!] High entropy ({entropy:.2f}) - possibly packed/encrypted")
    
    try:
        pe = pefile.PE(file_path)
        
        # Import analysis
        suspicious_imports = [
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',  # Injection
            'RegCreateKeyEx', 'RegSetValueEx',  # Registry
            'WinExec', 'CreateProcess',  # Execution
            'InternetOpen', 'WinHttpOpen',  # Network
            'CryptEncrypt', 'CryptDecrypt',  # Crypto
        ]
        
        found_imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imp_name = imp.name.decode(errors='ignore')
                        if any(s.lower() in imp_name.lower() for s in suspicious_imports):
                            found_imports.append(f"{entry.dll.decode()}::{imp_name}")
        
        results['suspicious_imports'] = found_imports
        if found_imports:
            print(f"[!] Suspicious imports found:")
            for i in found_imports:
                print(f"    {i}")
        
        # Section analysis
        for section in pe.sections:
            name = section.Name.decode(errors='ignore').rstrip('\\x00')
            sect_entropy = section.get_entropy()
            if sect_entropy > 7.0:
                print(f"[!] High entropy section {name}: {sect_entropy:.2f}")
        
    except pefile.PEFormatError:
        print(f"[-] Not a PE file")
    
    return results
'''

print(STATIC_ANALYSIS)
print(DYNAMIC_ANALYSIS)
print("\n=== Python PE Analysis ===")
print(PYTHON_STATIC_ANALYSIS)
```

## Step 345: OSINT Advanced Techniques

```python
#!/usr/bin/env python3
# osint_advanced.py

import requests
import json
from typing import List, Dict, Optional

class AdvancedOSINT:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120'
        })
    
    def search_breach_data(self, email: str, api_key: str = None) -> Dict:
        """ตรวจสอบ email ในข้อมูลเสีย (HaveIBeenPwned)"""
        hibp_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {'hibp-api-key': api_key} if api_key else {}
        
        try:
            r = self.session.get(hibp_url, headers=headers, timeout=10)
            if r.status_code == 200:
                breaches = r.json()
                return {'email': email, 'breaches': breaches, 'count': len(breaches)}
            elif r.status_code == 404:
                return {'email': email, 'breaches': [], 'count': 0}
        except Exception as e:
            print(f"HIBP error: {e}")
        return {}
    
    def social_media_lookup(self, username: str) -> Dict:
        """ค้นหา username บน social media (Sherlock-like)"""
        platforms = {
            'Twitter': f'https://twitter.com/{username}',
            'GitHub': f'https://github.com/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'TikTok': f'https://tiktok.com/@{username}',
            'Medium': f'https://medium.com/@{username}',
            'HackerNews': f'https://news.ycombinator.com/user?id={username}',
            'Keybase': f'https://keybase.io/{username}',
        }
        
        found = {}
        for platform, url in platforms.items():
            try:
                r = self.session.get(url, timeout=5, allow_redirects=True)
                if r.status_code == 200 and 'not found' not in r.text.lower()[:500]:
                    found[platform] = url
                    print(f"[+] Found on {platform}: {url}")
            except:
                pass
        
        return {'username': username, 'profiles': found}
    
    def email_to_linkedin(self, email: str) -> Optional[str]:
        """Find LinkedIn profile from email"""
        # Use LinkedIn API or scraping
        search_url = f"https://www.linkedin.com/search/results/people/?keywords={email}"
        print(f"[*] Search: {search_url}")
        return search_url
    
    def dns_history_lookup(self, domain: str) -> List[Dict]:
        """หาประวัติ DNS records"""
        # SecurityTrails API
        print(f"[*] DNS history for {domain}")
        print(f"    Tools: SecurityTrails, PassiveDNS, DNSDB, VirusTotal")
        print(f"    URL: https://securitytrails.com/domain/{domain}/history/a")
        return []
    
    def google_dork_generate(self, target: str) -> List[str]:
        """สร้าง Google dorks สำหรับ target"""
        dorks = [
            f'site:{target} filetype:pdf',
            f'site:{target} filetype:xlsx OR filetype:docx OR filetype:pptx',
            f'site:{target} inurl:login OR inurl:admin OR inurl:wp-admin',
            f'site:{target} "password" OR "passwd" OR "credentials"',
            f'site:{target} "internal use only" OR "confidential"',
            f'site:{target} intitle:"index of" -html -htm',
            f'"@{target}" password',  # Email leaks with password
            f'site:pastebin.com {target}',
            f'site:github.com {target} password',
            f'site:github.com {target} api_key',
            f'site:linkedin.com employees {target}',
            f'"{target}" filetype:sql',  # SQL dumps
            f'site:trello.com {target}',  # Public Trello boards
        ]
        return dorks
    
    def github_osint(self, organization: str) -> Dict:
        """ค้นหาข้อมูลสำคัญจาก GitHub"""
        try:
            # Get org repos
            r = self.session.get(f'https://api.github.com/orgs/{organization}/repos?per_page=100')
            repos = r.json()
            
            findings = {'organization': organization, 'repos': [], 'secrets_found': []}
            
            for repo in repos[:20]:  # Limit to 20 repos
                repo_name = repo['name']
                full_name = repo['full_name']
                findings['repos'].append(repo_name)
                
                # Search for secrets in code
                secret_patterns = [
                    'password', 'secret', 'api_key', 'token',
                    'private_key', 'aws_access_key', 'PRIVATE KEY'
                ]
                
                for pattern in secret_patterns[:3]:  # Limit API calls
                    search_r = self.session.get(
                        f'https://api.github.com/search/code'
                        f'?q={pattern}+repo:{full_name}&per_page=5'
                    )
                    if search_r.status_code == 200:
                        items = search_r.json().get('items', [])
                        for item in items:
                            findings['secrets_found'].append({
                                'repo': repo_name,
                                'file': item['path'],
                                'pattern': pattern,
                                'url': item['html_url']
                            })
                            print(f"[+] Possible secret in {full_name}: {item['path']} ({pattern})")
            
            return findings
        except Exception as e:
            print(f"GitHub OSINT error: {e}")
            return {}
    
    def shodan_company_search(self, company: str, api_key: str) -> List[Dict]:
        """Shodan search for company assets"""
        try:
            import shodan
            api = shodan.Shodan(api_key)
            results = api.search(f'org:"{company}"')
            
            assets = []
            for match in results['matches']:
                assets.append({
                    'ip': match['ip_str'],
                    'port': match['port'],
                    'product': match.get('product', ''),
                    'vulns': list(match.get('vulns', {}).keys())
                })
                
                if match.get('vulns'):
                    print(f"[+] Vulnerable: {match['ip_str']} - {list(match['vulns'].keys())}")
            
            return assets
        except ImportError:
            print("Install shodan: pip install shodan")
        except Exception as e:
            print(f"Shodan error: {e}")
        return []

# Demo
osint = AdvancedOSINT()
domain = 'example.com'
print("=== Google Dorks for Target ===")
for dork in osint.google_dork_generate(domain):
    print(f"  {dork}")
```

## Step 346: Certificate Transparency Monitoring

```python
#!/usr/bin/env python3
# cert_transparency_osint.py

import requests
import json
from typing import List, Dict

class CertTransparencyMonitor:
    def __init__(self):
        self.ct_sources = {
            'crtsh': 'https://crt.sh/?q={domain}&output=json',
            'certspotter': 'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names',
        }
    
    def query_crtsh(self, domain: str) -> List[Dict]:
        """ค้นหา subdomains ผ่าน Certificate Transparency"""
        url = f'https://crt.sh/?q=%.{domain}&output=json'
        
        try:
            r = requests.get(url, timeout=15)
            certs = r.json()
            
            # Extract unique domains
            domains = set()
            for cert in certs:
                # Parse name_value (may contain multiple domains)
                name_value = cert.get('name_value', '')
                for name in name_value.split('\n'):
                    name = name.strip()
                    if name and domain in name:
                        domains.add(name.lstrip('*.'))
            
            print(f"[+] Found {len(domains)} subdomains via CT logs")
            return sorted(domains)
        
        except Exception as e:
            print(f"[-] crt.sh error: {e}")
            return []
    
    def query_certspotter(self, domain: str, api_key: str = None) -> List[str]:
        """Query CertSpotter API"""
        url = f'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names'
        headers = {}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        
        try:
            r = requests.get(url, headers=headers, timeout=10)
            issuances = r.json()
            
            domains = set()
            for issuance in issuances:
                for dns_name in issuance.get('dns_names', []):
                    if domain in dns_name:
                        domains.add(dns_name.lstrip('*.'))
            
            return sorted(domains)
        except Exception as e:
            print(f"[-] CertSpotter error: {e}")
            return []
    
    def find_new_domains(self, target_domain: str) -> Dict:
        """ค้นหา domains ใหม่ที่อาจเป็น phishing หรือของเป้าหมาย"""
        domains = self.query_crtsh(target_domain)
        
        # Analyze new certs (issued recently)
        url = f'https://crt.sh/?q=%.{target_domain}&output=json'
        r = requests.get(url, timeout=15)
        certs = r.json() if r.status_code == 200 else []
        
        recent = []
        from datetime import datetime, timedelta
        cutoff = datetime.now() - timedelta(days=30)
        
        for cert in certs:
            try:
                issued = datetime.strptime(
                    cert.get('not_before', ''), '%Y-%m-%dT%H:%M:%S'
                )
                if issued > cutoff:
                    recent.append({
                        'domain': cert.get('name_value', ''),
                        'issued': str(issued.date()),
                        'issuer': cert.get('issuer_name', '')
                    })
            except:
                pass
        
        return {
            'all_domains': domains,
            'recent_certs': recent[:20]
        }
    
    def typosquat_analysis(self, target_domain: str) -> List[str]:
        """Find typosquat domains via CT logs"""
        import itertools
        
        name, tld = target_domain.rsplit('.', 1)
        
        # Generate variations
        variations = set()
        
        # Character substitution
        char_subs = {'a': ['@', '4'], 'e': ['3'], 'i': ['1', 'l'], 'o': ['0']}
        for i, char in enumerate(name):
            if char.lower() in char_subs:
                for sub in char_subs[char.lower()]:
                    variation = name[:i] + sub + name[i+1:]
                    variations.add(f"{variation}.{tld}")
        
        # Common TLD variations
        for alt_tld in ['com', 'net', 'org', 'co', 'io', 'co.th']:
            if alt_tld != tld:
                variations.add(f"{name}.{alt_tld}")
        
        # Common additions
        for prefix in ['my', 'get', 'login', 'secure', 'app']:
            variations.add(f"{prefix}-{target_domain}")
            variations.add(f"{prefix}{target_domain}")
        
        return sorted(variations)[:20]

# Demo
monitor = CertTransparencyMonitor()
target = 'example.com'

print("=== Certificate Transparency OSINT ===")
print(f"\nQuerying crt.sh for: {target}")

# Demo typosquats
typosquats = monitor.typosquat_analysis(target)
print("\nPossible typosquat domains:")
for ts in typosquats[:10]:
    print(f"  {ts}")

print("\nCT Log tools:")
print("  crt.sh: https://crt.sh/?q=%.example.com")
print("  Sublister: python3 sublist3r.py -d example.com -o subs.txt")
print("  Amass: amass enum -d example.com -passive")
print("  subfinder: subfinder -d example.com")
```

## Step 347: People Search & Social OSINT

```python
#!/usr/bin/env python3
# people_osint.py

from typing import Dict, List
import requests

class PeopleOSINT:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        }
    
    def linkedin_company_employees(self, company: str) -> str:
        """หาพนักงานผ่าน LinkedIn (Google dork)"""
        # Google dork แทนการ scrape LinkedIn
        dork = f'site:linkedin.com/in "{company}"'
        print(f"[*] Google: {dork}")
        return dork
    
    def email_format_discovery(self, domain: str, first: str = None, last: str = None) -> List[str]:
        """หารูปแบบ email"""
        formats = [
            f'{first}.{last}@{domain}' if first and last else None,
            f'{first}{last}@{domain}' if first and last else None,
            f'{first[0]}{last}@{domain}' if first and last else None,
            f'{first[0]}.{last}@{domain}' if first and last else None,
            f'{last}.{first}@{domain}' if first and last else None,
            f'{last[0]}{first}@{domain}' if first and last else None,
        ]
        formats = [f for f in formats if f]
        
        # Tools: hunter.io, emailhippo
        print(f"[*] hunter.io: https://hunter.io/domain/{domain}")
        print(f"[*] Email format finder: https://hunter.io")
        return formats
    
    def verify_email(self, email: str, api_key: str = None) -> Dict:
        """ตรวจสอบว่า email มีอยู่จริงหรือไม่ (MX + SMTP check)"""
        import smtplib
        import dns.resolver
        
        result = {'email': email, 'valid': False, 'reason': ''}
        domain = email.split('@')[1]
        
        # Check MX record
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_host = str(mx_records[0].exchange)
            result['mx'] = mx_host
        except:
            result['reason'] = 'No MX record'
            return result
        
        # SMTP verify (RCPT TO check)
        try:
            smtp = smtplib.SMTP(mx_host, timeout=10)
            smtp.ehlo()
            smtp.mail('test@test.com')
            code, msg = smtp.rcpt(email)
            smtp.quit()
            
            if code == 250:
                result['valid'] = True
                result['reason'] = 'RCPT 250 OK'
            else:
                result['reason'] = f'RCPT returned {code}'
        except Exception as e:
            result['reason'] = str(e)
        
        return result
    
    def generate_spear_phishing_profile(self, target_name: str, company: str, 
                                         job_title: str = None) -> Dict:
        """Generate spear phishing research profile"""
        profile = {
            'target': target_name,
            'company': company,
            'job_title': job_title,
            'osint_queries': [
                f'LinkedIn: "{target_name}" "{company}"',
                f'Google: "{target_name}" "{company}" -site:linkedin.com',
                f'Twitter: search {target_name} {company}',
                f'Facebook: people search {target_name}',
            ],
            'email_guesses': self.email_format_discovery(
                company.lower().replace(' ', '') + '.com',
                target_name.split()[0].lower() if ' ' in target_name else target_name.lower(),
                target_name.split()[-1].lower() if ' ' in target_name else ''
            ),
            'potential_attack_vectors': [
                'Email phishing (personalized based on OSINT)',
                'LinkedIn connection request with malicious link',
                'Vishing using gathered info',
                'Physical tailgating (if found office location)',
            ]
        }
        return profile

# OSINT Tools Reference
OSINT_TOOLS = """
=== OSINT Tools Reference ===

Personal Information:
  Spokeo, BeenVerified, Pipl, PeopleFinder
  PACER (US court records)
  Voter registration databases

Company Information:
  LinkedIn (employees, structure)
  Hunter.io (email format, contacts)
  Crunchbase (funding, acquisitions)
  WHOIS, Shodan (technical)
  SEC EDGAR (public companies)
  OpenCorporates (company registry)

Email OSINT:
  Hunter.io, Clearbit
  HaveIBeenPwned (breach data)
  EmailRep.io (reputation)
  Emailhippo (validation)

Social Media:
  Sherlock (username search)
  Social-Analyzer
  Twint (Twitter analysis)
  Maltego (link analysis)

Domain/IP:
  Shodan, Censys
  VirusTotal, Passive Total
  SecurityTrails
  Robtex

Search Engines:
  Google dorks
  Bing dorks
  DuckDuckGo
  Yandex (reverse image)
  TinEye (reverse image)

Dark Web:
  Tor browser + .onion search engines
  DarkSearch.io
  Ahmia
"""

osint = PeopleOSINT()
print("=== People OSINT ===")
profile = osint.generate_spear_phishing_profile('John Smith', 'ACME Corp', 'IT Manager')
print(json.dumps(profile, indent=2))
print(OSINT_TOOLS)
import json
```

## Step 348: Threat Intelligence Analysis

```python
#!/usr/bin/env python3
# threat_intel_analysis.py

import requests
import json
from typing import Dict, List

class ThreatIntelAnalyzer:
    def __init__(self, vt_api_key: str = None, otx_api_key: str = None):
        self.vt_api_key = vt_api_key
        self.otx_api_key = otx_api_key
    
    def check_virustotal(self, indicator: str, itype: str = 'file') -> Dict:
        """Check indicator on VirusTotal"""
        if not self.vt_api_key:
            print("[-] No VT API key")
            return {}
        
        headers = {'x-apikey': self.vt_api_key}
        
        endpoints = {
            'file': f'https://www.virustotal.com/api/v3/files/{indicator}',
            'ip': f'https://www.virustotal.com/api/v3/ip_addresses/{indicator}',
            'domain': f'https://www.virustotal.com/api/v3/domains/{indicator}',
            'url': f'https://www.virustotal.com/api/v3/urls/{indicator}'
        }
        
        try:
            r = requests.get(endpoints.get(itype, endpoints['file']), headers=headers)
            if r.status_code == 200:
                data = r.json()
                attrs = data.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'total': sum(stats.values())
                }
        except Exception as e:
            print(f"VT error: {e}")
        return {}
    
    def check_alienvault_otx(self, indicator: str, itype: str = 'IPv4') -> Dict:
        """Check AlienVault OTX"""
        if not self.otx_api_key:
            print("[-] No OTX API key")
            return {}
        
        headers = {'X-OTX-API-KEY': self.otx_api_key}
        url = f'https://otx.alienvault.com/api/v1/indicators/{itype}/{indicator}/general'
        
        try:
            r = requests.get(url, headers=headers)
            if r.status_code == 200:
                data = r.json()
                return {
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'tags': data.get('pulse_info', {}).get('tags', [])[:5],
                    'malware_families': data.get('malware_families', [])
                }
        except Exception as e:
            print(f"OTX error: {e}")
        return {}
    
    def bulk_ioc_check(self, iocs: List[str]) -> List[Dict]:
        """Check multiple IOCs"""
        results = []
        for ioc in iocs:
            # Determine type
            import re
            if re.match(r'^[0-9a-f]{64}$', ioc):
                itype = 'file'  # SHA256
            elif re.match(r'^\d+\.\d+\.\d+\.\d+$', ioc):
                itype = 'ip'
            else:
                itype = 'domain'
            
            vt_result = self.check_virustotal(ioc, itype)
            otx_result = self.check_alienvault_otx(ioc, itype.upper() if itype != 'file' else 'FileHash-SHA256')
            
            results.append({
                'ioc': ioc,
                'type': itype,
                'virustotal': vt_result,
                'otx': otx_result,
                'verdict': 'MALICIOUS' if vt_result.get('malicious', 0) > 5 else 'CLEAN'
            })
        
        return results
    
    def misp_query(self, misp_url: str, api_key: str, attribute_value: str) -> Dict:
        """Query MISP for IOC"""
        headers = {
            'Authorization': api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        payload = {'value': attribute_value, 'searchAll': True}
        
        try:
            r = requests.post(
                f'{misp_url}/attributes/restSearch',
                json=payload, headers=headers, verify=False
            )
            return r.json()
        except Exception as e:
            print(f"MISP error: {e}")
            return {}

# STIX/TAXII
STIX_EXAMPLE = """
=== STIX/TAXII for Threat Intel Sharing ===

# STIX (Structured Threat Information Expression)
# Standard format for threat intelligence

from stix2 import Indicator, Malware, Relationship, Bundle

# Create indicator
indicator = Indicator(
    name="Malicious IP",
    pattern="[ipv4-addr:value = '192.168.1.100']",
    pattern_type="stix",
    valid_from="2024-01-01T00:00:00Z",
    labels=["malicious-activity"]
)

# Create malware object
malware = Malware(
    name="Emotet",
    is_family=True,
    labels=["trojan"]
)

# Create relationship
relationship = Relationship(
    relationship_type="indicates",
    source_ref=indicator.id,
    target_ref=malware.id
)

# Create bundle
bundle = Bundle(objects=[indicator, malware, relationship])
print(bundle.serialize(pretty=True))

# TAXII (Trusted Automated eXchange of Intelligence Information)
# Protocol for sharing STIX data
from taxii2client.v21 import Server
server = Server('https://your-taxii-server.com/taxii/', 
                user='apiuser', password='apipass')
collections = server.collections
"""

print("=== Threat Intelligence Tools ===")
print("\nFree TI Sources:")
print("  AlienVault OTX: https://otx.alienvault.com")
print("  VirusTotal: https://virustotal.com")
print("  ThreatFox: https://threatfox.abuse.ch")
print("  URLhaus: https://urlhaus.abuse.ch")
print("  MalwareBazaar: https://bazaar.abuse.ch")
print("  FeodoTracker: https://feodotracker.abuse.ch")
print("\nSelf-hosted:")
print("  MISP: malware information sharing platform")
print("  OpenCTI: open threat intelligence platform")
print("  TheHive: security incident response")
print(STIX_EXAMPLE)
```

## Step 349: Automated OSINT Framework

```python
#!/usr/bin/env python3
# osint_automation_framework.py

import subprocess
import json
import os
from typing import Dict, List

class OSINTAutomation:
    def __init__(self, target_domain: str, output_dir: str = '/tmp/osint'):
        self.target = target_domain
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.results = {}
    
    def run_amass(self) -> List[str]:
        """รัน Amass สำหรับ domain enumeration"""
        output_file = f"{self.output_dir}/amass_{self.target}.txt"
        cmd = ['amass', 'enum', '-passive', '-d', self.target, '-o', output_file]
        print(f"[*] Running: {' '.join(cmd)}")
        
        try:
            subprocess.run(cmd, timeout=300, capture_output=True)
            with open(output_file) as f:
                subdomains = [line.strip() for line in f if line.strip()]
            print(f"[+] Amass found: {len(subdomains)} subdomains")
            return subdomains
        except Exception as e:
            print(f"[-] Amass error: {e}")
            return []
    
    def run_subfinder(self) -> List[str]:
        """รัน subfinder"""
        output_file = f"{self.output_dir}/subfinder_{self.target}.txt"
        cmd = ['subfinder', '-d', self.target, '-o', output_file, '-silent']
        print(f"[*] Running: {' '.join(cmd)}")
        
        try:
            subprocess.run(cmd, timeout=120, capture_output=True)
            with open(output_file) as f:
                subdomains = [line.strip() for line in f if line.strip()]
            print(f"[+] Subfinder found: {len(subdomains)} subdomains")
            return subdomains
        except Exception as e:
            print(f"[-] Subfinder error: {e}")
            return []
    
    def run_httpx(self, subdomains: List[str]) -> List[str]:
        """ตรวจสอบว่า subdomains ไหนแอคทีฟ"""
        input_file = f"{self.output_dir}/all_subs.txt"
        output_file = f"{self.output_dir}/live_hosts.txt"
        
        with open(input_file, 'w') as f:
            f.write('\n'.join(subdomains))
        
        cmd = ['httpx', '-l', input_file, '-o', output_file, '-mc', '200,301,302,403', '-silent']
        print(f"[*] Running httpx on {len(subdomains)} subdomains")
        
        try:
            subprocess.run(cmd, timeout=300, capture_output=True)
            with open(output_file) as f:
                live = [line.strip() for line in f if line.strip()]
            print(f"[+] Live hosts: {len(live)}")
            return live
        except Exception as e:
            print(f"[-] httpx error: {e}")
            return []
    
    def run_nuclei(self, targets: List[str]) -> List[Dict]:
        """สแกน vulnerabilities ด้วย nuclei"""
        input_file = f"{self.output_dir}/nuclei_targets.txt"
        output_file = f"{self.output_dir}/nuclei_findings.json"
        
        with open(input_file, 'w') as f:
            f.write('\n'.join(targets))
        
        cmd = [
            'nuclei', '-l', input_file,
            '-t', 'cves/', '-t', 'misconfiguration/',
            '-o', output_file,
            '-json',
            '-severity', 'critical,high,medium'
        ]
        print(f"[*] Running nuclei on {len(targets)} targets")
        
        try:
            subprocess.run(cmd, timeout=600, capture_output=True)
            findings = []
            if os.path.exists(output_file):
                with open(output_file) as f:
                    for line in f:
                        try:
                            findings.append(json.loads(line))
                        except:
                            pass
            print(f"[+] Nuclei findings: {len(findings)}")
            return findings
        except Exception as e:
            print(f"[-] Nuclei error: {e}")
            return []
    
    def full_recon(self) -> Dict:
        """Run full reconnaissance pipeline"""
        print(f"[*] Starting full recon for {self.target}")
        
        # Step 1: Subdomain enumeration
        subs1 = self.run_amass()
        subs2 = self.run_subfinder()
        all_subs = list(set(subs1 + subs2))
        self.results['subdomains'] = all_subs
        print(f"[+] Total unique subdomains: {len(all_subs)}")
        
        # Step 2: Probe for live hosts
        live = self.run_httpx(all_subs)
        self.results['live_hosts'] = live
        
        # Step 3: Vulnerability scan
        findings = self.run_nuclei(live)
        self.results['vulnerabilities'] = findings
        
        # Save results
        with open(f"{self.output_dir}/full_results.json", 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        return self.results

# Demo
osint = OSINTAutomation('example.com')
print("=== OSINT Automation Pipeline ===")
print("Steps:")
print("  1. Amass + Subfinder - Subdomain discovery")
print("  2. httpx - Live host probing")
print("  3. Nuclei - Vulnerability scanning")
print("  4. Gowitness - Screenshot all hosts")
print("  5. theHarvester - Email/contact discovery")
print("  6. Shodan API - IP intelligence")
print("\nManual run commands:")
print(f"  amass enum -passive -d example.com | httpx | nuclei -severity high")
print(f"  gowitness scan file -f live_hosts.txt --threads 20")
```

## Step 350: OSINT & Threat Hunting Report

```python
#!/usr/bin/env python3
# osint_hunting_report.py

from datetime import datetime
from typing import Dict, List

class OSINTHuntingReport:
    def __init__(self, org: str, analyst: str):
        self.org = org
        self.analyst = analyst
        self.date = datetime.now().strftime('%Y-%m-%d')
        self.findings = {'osint': [], 'threat_hunting': []}
    
    def generate_report(self) -> str:
        return f"""# OSINT & Threat Hunting Report

**Organization:** {self.org}  
**Analyst:** {self.analyst}  
**Date:** {self.date}  

---

## Part 1: OSINT Findings

### External Attack Surface

This section documents the organization's external digital footprint discovered
through passive reconnaissance techniques.

### Exposed Assets
| Asset | Type | Risk | Notes |
|-------|------|------|-------|
| api.example.com | Subdomain | HIGH | API endpoint without auth |
| old.example.com | Subdomain | MEDIUM | Running outdated software |
| 203.x.x.x:8080 | Open Port | MEDIUM | Default admin credentials |

### Credential Exposure
- Found {self.org.lower().replace(' ', '')}@gmail.com in HaveIBeenPwned (3 breaches)
- Potential password hashes in public GitHub repository

### Data Leakage
- Company internal document found on Google: "Internal Use Only"
- Employee directory exposed through LinkedIn enumeration

---

## Part 2: Threat Hunting Findings

### Hypotheses Tested

| Hypothesis | Data Source | Result |
|-----------|-------------|--------|
| Credential spraying | Windows Event 4625 | Confirmed - 3 accounts targeted |
| PowerShell abuse | Event 4104 | Suspicious script found |
| DNS C2 | DNS logs | High entropy domains to investigate |
| LSASS access | Sysmon Event 10 | No indicators |

### Hunt: Credential Spraying

**Finding:** Multiple failed logon attempts (Event 4625) with SubStatus 0xC000006A 
(wrong password) against accounts IT-ADMIN01, SVCACCT02, ADMINTEST from single IP.

**Evidence:**
```
192.168.50.10 -> IT-ADMIN01: Failed (18:03:44)
192.168.50.10 -> SVCACCT02: Failed (18:03:47)
192.168.50.10 -> ADMINTEST: Failed (18:03:50)
```

**Assessment:** Possible automated credential spray from internal network.

**Action:** Investigate 192.168.50.10, check user account history.

---

## Recommendations

1. Remediate exposed API endpoint (add authentication)
2. Remove sensitive files from public access
3. Enable SIEM alerting for credential spraying patterns  
4. Investigate internal IP 192.168.50.10
5. Review PowerShell script block logs regularly
6. Deploy UEBA for baseline anomaly detection

## MITRE ATT&CK Coverage

| Technique | Coverage | Status |
|-----------|----------|--------|
| T1110 Brute Force | SIEM Rule | Active |
| T1059.001 PowerShell | Script Block Logging | Active |
| T1003 Cred Dumping | Sysmon Event 10 | Active |
| T1071 C2 via DNS | DNS Analytics | Partial |
"""

# Demo
rep = OSINTHuntingReport('ACME Financial Group', 'Threat Hunt Team')
print(rep.generate_report())
```

---
*Part 35 เสร็จสมบูรณ์ - Steps 341-350 ครอบคลุม Threat Hunting Methodology, Windows Event Log Analysis, Network Traffic Analysis, Malware Analysis Basics, OSINT Advanced, Certificate Transparency, People Search/Social OSINT, Threat Intelligence, Automated OSINT Framework และ OSINT/Threat Hunting Report*
