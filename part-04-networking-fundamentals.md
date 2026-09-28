# Part 04: Networking Fundamentals (Steps 31-40)

## บทนำ

ความเข้าใจ Networking เป็นพื้นฐานสำคัญสำหรับทุก Penetration Tester เพราะการโจมตีส่วนใหญ่เกิดขึ้นผ่านเครือข่าย ในบทนี้เราจะเรียนรู้ OSI Model, TCP/IP, Protocol ต่างๆ และการวิเคราะห์ Traffic

---

## Step 31: OSI Model และ Attacks ในแต่ละ Layer

### OSI Model ทั้ง 7 ชั้น

```
Layer 7 - Application Layer
Layer 6 - Presentation Layer
Layer 5 - Session Layer
Layer 4 - Transport Layer
Layer 3 - Network Layer
Layer 2 - Data Link Layer
Layer 1 - Physical Layer
```

### Layer 7 - Application Layer

```
โปรโตคอล: HTTP, HTTPS, FTP, SSH, DNS, SMTP, IMAP, POP3

ข้อมูลที่ส่ง: Data / Messages

การโจมตีใน Layer 7:
- SQL Injection
- XSS (Cross-Site Scripting)
- CSRF (Cross-Site Request Forgery)
- Command Injection
- Directory Traversal
- File Inclusion
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity)
- Broken Authentication
- Business Logic Flaws
- API Vulnerabilities

เครื่องมือ:
- Burp Suite
- OWASP ZAP
- nikto
- sqlmap
- dirb/gobuster
```

### Layer 6 - Presentation Layer

```
โปรโตคอล: SSL/TLS, JPEG, MPEG, ASCII, EBCDIC

ข้อมูลที่ส่ง: Formatted Data

การโจมตีใน Layer 6:
- SSL Stripping
- Certificate Forgery
- Downgrade Attacks (POODLE, BEAST)
- Weak Cipher Exploitation
- Heartbleed (OpenSSL)
- CRIME/BREACH (compression oracle)

เครื่องมือ:
- sslscan
- testssl.sh
- sslyze
- openssl s_client
```

### Layer 5 - Session Layer

```
โปรโตคอล: NetBIOS, PPTP, SAP, SDP, SSL

ข้อมูลที่ส่ง: Data (with session info)

การโจมตีใน Layer 5:
- Session Hijacking
- Session Fixation
- Brute Force Session Tokens
- Cookie Manipulation
- TCP Session Hijacking

เครื่องมือ:
- Wireshark
- Burp Suite (session tokens)
- Ettercap
```

### Layer 4 - Transport Layer

```
โปรโตคอล: TCP, UDP

ข้อมูลที่ส่ง: Segments (TCP) / Datagrams (UDP)

การโจมตีใน Layer 4:
- SYN Flood (DoS/DDoS)
- TCP Port Scanning
- UDP Port Scanning
- Session Sniffing
- TCP Reset Attack
- Fragmentation Attack
- Port Scanning

เครื่องมือ:
- nmap
- hping3
- scapy
- netcat
```

### Layer 3 - Network Layer

```
โปรโตคอล: IP, ICMP, OSPF, BGP, ARP (บางครั้งจัด Layer 3)

ข้อมูลที่ส่ง: Packets

การโจมตีใน Layer 3:
- IP Spoofing
- Smurf Attack
- ICMP Flood
- Route Table Manipulation
- OSPF/BGP Hijacking
- TTL Manipulation (Firewall Evasion)
- IP Fragmentation

เครื่องมือ:
- hping3
- nmap
- scapy
- iptables
```

### Layer 2 - Data Link Layer

```
โปรโตคอล: Ethernet, Wi-Fi (802.11), ARP, STP, VLAN

ข้อมูลที่ส่ง: Frames

การโจมตีใน Layer 2:
- ARP Spoofing/Poisoning
- ARP Cache Poisoning (MitM)
- MAC Flooding (CAM Table Overflow)
- VLAN Hopping
- STP Manipulation (BPDU attacks)
- Double Tagging
- 802.1X Bypass
- Wi-Fi Attacks (Deauth, Evil Twin)

เครื่องมือ:
- arpspoof
- ettercap
- bettercap
- macchanger
- yersinia (Layer 2)
- aircrack-ng
```

### Layer 1 - Physical Layer

```
สื่อ: Cable, Fiber, Radio waves

ข้อมูลที่ส่ง: Bits

การโจมตีใน Layer 1:
- Physical Tapping (แตะสาย)
- Rogue Wireless Access Point
- Jamming (รบกวน signal)
- Wiretapping
- Keylogger (hardware)
- Keystroke Logging

เครื่องมือ:
- Wi-Fi Pineapple
- Raspberry Pi (Rogue AP)
- Hardware Keyloggers
```

---

## Step 32: TCP/IP Protocol Suite

### IPv4 Header Structure

```
IPv4 Header (20 bytes minimum):
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

สำหรับ Pentesting:
- TTL: ระบุ OS (Linux=64, Windows=128, Cisco=255)
- Protocol: ICMP=1, TCP=6, UDP=17
- Flags: DF bit สำหรับ Path MTU Discovery
- ID/Fragment: สำหรับ Fragmentation attacks
```

### TCP Header Structure

```
TCP Header (20 bytes minimum):
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

TCP Flags:
SYN (Synchronize)  - เริ่มต้น connection
ACK (Acknowledge)  - ยืนยันรับข้อมูล
FIN (Finish)       - ต้องการ close connection
RST (Reset)        - ยกเลิก connection ฉุกเฉิน
PSH (Push)         - ส่ง data ทันที (ไม่ buffer)
URG (Urgent)       - ข้อมูลเร่งด่วน

Scan Types ตาม Flags:
SYN Scan:    SYN →, ← SYN/ACK (open) / ← RST (closed)
TCP Connect: SYN, SYN/ACK, ACK (3-way handshake complete)
FIN Scan:    FIN → ← RST (closed) / no response (open/filtered)
XMAS Scan:   FIN+URG+PSH → 
NULL Scan:   no flags →
```

### TCP Three-Way Handshake

```bash
# ==========================================
# TCP Handshake ด้วย scapy
# ==========================================

# ดู handshake ด้วย Wireshark/tcpdump
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0' -n

# สร้าง packet ด้วย scapy (Python)
python3 << 'EOF'
from scapy.all import *

# ดู 3-way handshake
target = "192.168.1.1"
port = 80

# Step 1: SYN
syn = IP(dst=target)/TCP(sport=RandShort(), dport=port, flags="S")
syn_ack = sr1(syn, timeout=2, verbose=0)

if syn_ack and syn_ack.haslayer(TCP):
    if syn_ack[TCP].flags == 0x12:  # SYN-ACK
        print(f"Port {port} is OPEN")
        
        # Step 2: ACK (ทำ connection สมบูรณ์)
        ack = IP(dst=target)/TCP(
            sport=syn_ack[TCP].dport,
            dport=port,
            flags="A",
            seq=syn_ack[TCP].ack,
            ack=syn_ack[TCP].seq + 1
        )
        send(ack, verbose=0)
        
        # Step 3: RST (ปิด connection)
        rst = IP(dst=target)/TCP(
            sport=syn_ack[TCP].dport,
            dport=port,
            flags="R",
            seq=syn_ack[TCP].ack
        )
        send(rst, verbose=0)
        
    elif syn_ack[TCP].flags == 0x14:  # RST-ACK
        print(f"Port {port} is CLOSED")
else:
    print(f"Port {port} is FILTERED")
EOF
```

---

## Step 33: IP Addressing & Subnetting

### IPv4 Addressing

```bash
# ==========================================
# IP Address Classes
# ==========================================

# Class A: 1.0.0.0 - 126.255.255.255    /8  (16M hosts)
# Class B: 128.0.0.0 - 191.255.255.255  /16 (65K hosts)
# Class C: 192.0.0.0 - 223.255.255.255  /24 (254 hosts)

# Private IP Ranges (RFC 1918):
# 10.0.0.0/8     (10.0.0.0 - 10.255.255.255)
# 172.16.0.0/12  (172.16.0.0 - 172.31.255.255)
# 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)

# Loopback: 127.0.0.0/8
# Link-Local: 169.254.0.0/16 (APIPA)
# Multicast: 224.0.0.0/4

# ==========================================
# Subnetting Calculator
# ==========================================

# ติดตั้ง ipcalc
sudo apt install ipcalc

# คำนวณ subnet
ipcalc 192.168.1.0/24
ipcalc 10.0.0.0/8
ipcalc 172.16.0.0/16

# ตัวอย่าง output:
# Address:   192.168.1.0          11000000.10101000.00000001. 00000000
# Netmask:   255.255.255.0 = 24   11111111.11111111.11111111. 00000000
# Network:   192.168.1.0/24       11000000.10101000.00000001. 00000000
# HostMin:   192.168.1.1          11000000.10101000.00000001. 00000001
# HostMax:   192.168.1.254        11000000.10101000.00000001. 11111110
# Broadcast: 192.168.1.255        11000000.10101000.00000001. 11111111
# Hosts/Net: 254                   Class C

# CIDR Notation (Cheat Sheet):
# /8  = 255.0.0.0     = 16,777,214 hosts
# /16 = 255.255.0.0   = 65,534 hosts
# /24 = 255.255.255.0 = 254 hosts
# /25 = 255.255.255.128 = 126 hosts
# /26 = 255.255.255.192 = 62 hosts
# /27 = 255.255.255.224 = 30 hosts
# /28 = 255.255.255.240 = 14 hosts
# /29 = 255.255.255.248 = 6 hosts
# /30 = 255.255.255.252 = 2 hosts
# /31 = Point-to-point
# /32 = Host address

# ==========================================
# Python: Subnet Calculator
# ==========================================
python3 << 'EOF'
import ipaddress

def subnet_info(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    print(f"Network:    {net}")
    print(f"Netmask:    {net.netmask}")
    print(f"Broadcast:  {net.broadcast_address}")
    print(f"First host: {list(net.hosts())[0]}")
    print(f"Last host:  {list(net.hosts())[-1]}")
    print(f"Num hosts:  {net.num_addresses - 2}")
    print(f"Prefix:     /{net.prefixlen}")

subnet_info("192.168.1.0/24")
print()
subnet_info("10.0.0.0/8")

# ดู hosts ทั้งหมด
net = ipaddress.ip_network("192.168.1.0/24")
print("\nAll hosts:")
for ip in list(net.hosts())[:5]:
    print(f"  {ip}")
print(f"  ... ({net.num_addresses - 2} total)")
EOF
```

---

## Step 34: Network Protocols สำหรับ Pentester

### DNS Protocol

```bash
# ==========================================
# DNS - Domain Name System
# ==========================================

# DNS Record Types:
# A     = IPv4 address
# AAAA  = IPv6 address
# CNAME = Canonical name (alias)
# MX    = Mail server
# NS    = Name server
# PTR   = Reverse lookup
# TXT   = Text records (SPF, DKIM, verification)
# SOA   = Start of Authority
# SRV   = Service records

# ==========================================
# DNS Tools
# ==========================================

# dig - ละเอียดที่สุด
dig google.com                     # A record
dig google.com A                   # เฉพาะ A
dig google.com MX                  # Mail servers
dig google.com NS                  # Name servers
dig google.com TXT                 # TXT records
dig google.com ANY                 # ทุก records
dig @8.8.8.8 google.com            # ใช้ DNS server เฉพาะ
dig +trace google.com              # trace DNS resolution
dig -x 8.8.8.8                     # reverse lookup
dig +short google.com              # IP only

# Zone Transfer (มักถูกป้องกันแล้ว)
dig axfr @ns1.example.com example.com
dig axfr @nameserver domain.com

# host
host google.com
host -t MX google.com
host -t NS google.com
host 8.8.8.8                       # reverse lookup

# nslookup (interactive)
nslookup google.com
nslookup -type=MX google.com
nslookup -type=NS google.com

# ==========================================
# DNS Enumeration Tools
# ==========================================

# dnsx - Fast DNS resolver
sudo apt install golang-go
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

echo "google.com" | dnsx
cat domains.txt | dnsx -a -mx -ns -txt

# dnsrecon
dnsrecon -d example.com           # basic recon
dnsrecon -d example.com -t axfr   # zone transfer
dnsrecon -d example.com -t std    # standard enumeration
dnsrecon -d example.com -t brt -D /usr/share/wordlists/dnsmap.txt

# fierce - DNS brute force
fierce --domain example.com
fierce --domain example.com --subdomain-file wordlist.txt

# amass - Comprehensive DNS enumeration
sudo apt install amass
amass enum -d example.com
amass enum -active -d example.com
amass enum -d example.com -o output.txt

# subfinder - Subdomain enumeration
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
subfinder -d example.com
subfinder -d example.com -all
subfinder -d example.com -o subdomains.txt
```

### ARP Protocol

```bash
# ==========================================
# ARP - Address Resolution Protocol
# ==========================================

# ARP ใช้แมป IP address เป็น MAC address บน LAN

# ดู ARP cache
arp -a
arp -n                             # ไม่ resolve hostname
ip neigh                           # ใหม่กว่า

# ARP ping
arping 192.168.1.1                 # ส่ง ARP request

# ตรวจสอบว่า IP ใดอยู่บน network
nmap -sn 192.168.1.0/24 --send-eth

# ==========================================
# ARP Spoofing/Poisoning (Man-in-the-Middle)
# ==========================================

# หลักการ: ส่ง ARP reply ปลอมเพื่อเปลี่ยน MAC address mapping
# Victim เชื่อว่า IP ของ Gateway คือ MAC ของเรา

# ใช้ arpspoof
sudo apt install dsniff

# Enable IP forwarding ก่อน (สำคัญ! ไม่งั้น traffic จะหาย)
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# ทำ ARP spoof ทั้งสองทาง
sudo arpspoof -i eth0 -t 192.168.1.100 -r 192.168.1.1

# หรือใช้ ettercap
sudo ettercap -T -q -i eth0 -M arp:remote /192.168.1.100// /192.168.1.1//

# หรือใช้ bettercap (ทันสมัยกว่า)
sudo bettercap -iface eth0
bettercap > net.probe on
bettercap > arp.spoof.targets 192.168.1.100
bettercap > arp.spoof on
bettercap > net.sniff on
```

---

## Step 35: TCP Flags และ Port States

```bash
# ==========================================
# TCP Flag Analysis
# ==========================================

# ดู flags ด้วย tcpdump
sudo tcpdump -i eth0 'tcp' -nn

# Filter ตาม flags
sudo tcpdump -i eth0 'tcp[13] & 2 != 0' -nn     # SYN
sudo tcpdump -i eth0 'tcp[13] & 18 != 0' -nn    # SYN+ACK
sudo tcpdump -i eth0 'tcp[13] & 1 != 0' -nn     # FIN
sudo tcpdump -i eth0 'tcp[13] & 4 != 0' -nn     # RST

# ==========================================
# Port States ที่ nmap ตรวจพบ
# ==========================================

# Open: รับ connection
# Closed: ปฏิเสธ connection (RST)
# Filtered: ไม่มี response (Firewall)
# Unfiltered: รับ packet แต่ไม่รู้ state
# Open|Filtered: อาจ open หรือ filtered
# Closed|Filtered: อาจ closed หรือ filtered

# ==========================================
# hping3 - Packet Crafting
# ==========================================
sudo apt install hping3

# SYN scan
hping3 -S -p 80 192.168.1.1

# Ping (ICMP)
hping3 -1 192.168.1.1             # ICMP
hping3 -1 192.168.1.1 -c 3       # 3 packets

# SYN Flood (DoS - lab only!)
hping3 -S --flood -V -p 80 192.168.1.1

# Traceroute
hping3 --traceroute -V -S -p 80 192.168.1.1

# Spoof source IP
hping3 -S -p 80 -a 1.2.3.4 192.168.1.1

# Scan ด้วย hping3
hping3 -S --scan 1-1000 192.168.1.1

# Fragment packets (firewall evasion)
hping3 -S -f -p 80 192.168.1.1
```

---

## Step 36: UDP vs TCP

```bash
# ==========================================
# UDP Services (สำคัญสำหรับ Pentesting)
# ==========================================

# Common UDP Ports:
# 53   - DNS
# 67   - DHCP Server
# 68   - DHCP Client
# 69   - TFTP
# 123  - NTP
# 137  - NetBIOS Name Service
# 138  - NetBIOS Datagram
# 161  - SNMP
# 162  - SNMP Trap
# 500  - IKE/IPsec
# 514  - Syslog
# 4500 - IPsec NAT-T

# UDP Scan ด้วย nmap (ช้ากว่า TCP มาก)
sudo nmap -sU 192.168.1.1
sudo nmap -sU -p 53,67,161 192.168.1.1
sudo nmap -sU -p 1-1000 192.168.1.1 --open

# ==========================================
# SNMP Enumeration (UDP 161)
# ==========================================

# SNMP community strings (default)
# public  = read-only
# private = read-write

# snmpwalk
snmpwalk -v2c -c public 192.168.1.1
snmpwalk -v2c -c private 192.168.1.1
snmpwalk -v2c -c public 192.168.1.1 system

# onesixtyone - SNMP brute force
sudo apt install onesixtyone
onesixtyone -c /usr/share/wordlists/metasploit/snmp_default_pass.txt -i targets.txt

# snmp-check
snmp-check 192.168.1.1

# ==========================================
# DNS Amplification Attack (DDoS)
# ==========================================
# ใช้ DNS server เป็น amplifier
# ส่ง DNS query ด้วย spoofed source IP
# Amplification factor: ~100x

# การป้องกัน:
# - Rate limiting บน DNS server
# - Response Rate Limiting (RRL)
# - Block unused UDP services
```

---

## Step 37: NAT & Port Forwarding

```bash
# ==========================================
# NAT (Network Address Translation)
# ==========================================

# NAT Types:
# Static NAT  = 1:1 mapping
# Dynamic NAT = Many:Many mapping
# PAT/NAPT    = Many:1 (Port Address Translation)

# ดู NAT connections
sudo conntrack -L 2>/dev/null
cat /proc/net/nf_conntrack

# ==========================================
# Port Forwarding ด้วย iptables
# ==========================================

# Forward port 80 ไปยัง server อื่น
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.100:80
sudo iptables -A FORWARD -p tcp -d 192.168.1.100 --dport 80 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -j MASQUERADE

# เปิด IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ==========================================
# rinetd - Port Forwarding Tool
# ==========================================
sudo apt install rinetd

# /etc/rinetd.conf
# bindaddress bindport connectaddress connectport
0.0.0.0 8080 192.168.1.100 80
0.0.0.0 2222 192.168.1.100 22

sudo service rinetd restart

# ==========================================
# socat Port Forwarding
# ==========================================
socat TCP-LISTEN:8080,fork TCP:192.168.1.100:80
socat TCP-LISTEN:2222,fork TCP:192.168.1.100:22 &
```

---

## Step 38: Wireshark เบื้องต้น

```bash
# ==========================================
# Wireshark Installation & Setup
# ==========================================
sudo apt install wireshark

# ให้สิทธิ์ capture โดยไม่ต้อง root
sudo usermod -aG wireshark $USER
# logout และ login ใหม่

# ==========================================
# Wireshark Filters ที่สำคัญ
# ==========================================

# Capture Filters (ก่อน capture)
host 192.168.1.1              # เฉพาะ host นี้
net 192.168.1.0/24            # เฉพาะ network นี้
port 80                        # เฉพาะ port 80
tcp                            # เฉพาะ TCP
udp                            # เฉพาะ UDP
tcp port 80 or tcp port 443   # HTTP/HTTPS
not arp                        # ยกเว้น ARP
not port 22                    # ยกเว้น SSH

# Display Filters (หลัง capture)
ip.addr == 192.168.1.1         # IP address
ip.src == 192.168.1.1          # Source IP
ip.dst == 192.168.1.1          # Destination IP
tcp.port == 80                  # TCP port 80
tcp.flags.syn == 1              # SYN packets
tcp.flags.reset == 1            # RST packets
http                            # HTTP packets
http.request.method == "POST"   # HTTP POST
http.response.code == 200       # HTTP 200
dns                             # DNS packets
dns.qry.name == "google.com"    # DNS query
smtp                            # SMTP
ftp                             # FTP
telnet                          # Telnet (clear text)
ssl                             # SSL/TLS
ssl.handshake.type == 1         # Client Hello

# Operators
==, !=, <, >, <=, >=
&&, ||, !
contains "text"
matches "regex"

# ==========================================
# Useful Analysis Techniques
# ==========================================

# Follow TCP Stream
# Right click packet > Follow > TCP Stream
# ดูการสนทนาทั้งหมดในรูปแบบ text

# HTTP credentials
http.authorization
http contains "password"
http.request.method == "POST" && http contains "password"

# FTP credentials (clear text)
ftp.request.command == "USER" || ftp.request.command == "PASS"

# Telnet credentials (clear text)
telnet

# Find all unique IP addresses
# Statistics > Endpoints > IPv4

# ==========================================
# การ Export ข้อมูล
# ==========================================
# File > Export Specified Packets
# File > Export Objects > HTTP (ดาวน์โหลดไฟล์จาก capture)
```

---

## Step 39: tcpdump สำหรับ Packet Analysis

```bash
# ==========================================
# tcpdump - Command Line Packet Capture
# ==========================================

# ดู interfaces
tcpdump --list-interfaces
tcpdump -D

# Basic capture
sudo tcpdump                           # capture บน default interface
sudo tcpdump -i eth0                   # เฉพาะ eth0
sudo tcpdump -i any                    # ทุก interfaces
sudo tcpdump -n                        # ไม่ resolve hostnames
sudo tcpdump -nn                       # ไม่ resolve hostnames + ports
sudo tcpdump -v                        # verbose
sudo tcpdump -vv                       # very verbose
sudo tcpdump -vvv                      # maximum verbose

# บันทึกและ read
sudo tcpdump -w capture.pcap           # บันทึกเป็นไฟล์
sudo tcpdump -r capture.pcap           # อ่านจากไฟล์
sudo tcpdump -r capture.pcap -n        # อ่านพร้อม options

# จำกัดจำนวน packets
sudo tcpdump -c 100                    # 100 packets แล้วหยุด

# ==========================================
# Filters
# ==========================================

# Hosts
tcpdump host 192.168.1.1
tcpdump src host 192.168.1.1
tcpdump dst host 192.168.1.1
tcpdump host 192.168.1.1 and host 192.168.1.2

# Ports
tcpdump port 80
tcpdump src port 1024
tcpdump dst port 443
tcpdump portrange 1-1024

# Protocols
tcpdump tcp
tcpdump udp
tcpdump icmp
tcpdump arp

# Network
tcpdump net 192.168.1.0/24
tcpdump src net 10.0.0.0/8

# Combinations
tcpdump 'host 192.168.1.1 and port 80'
tcpdump 'tcp port 80 or tcp port 443'
tcpdump 'not port 22 and not arp'

# TCP Flags
tcpdump 'tcp[tcpflags] & tcp-syn != 0'                    # SYN
tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'          # SYN/ACK
tcpdump 'tcp[tcpflags] == tcp-syn'                         # Only SYN
tcpdump 'tcp[13] == 2'                                     # SYN = bit 1

# HTTP
tcpdump -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# ==========================================
# ตัวอย่าง Security Analysis
# ==========================================

# ดู login credentials (clear text)
sudo tcpdump -A -n 'port 21 or port 23 or port 110' | grep -E "USER|PASS|login"

# ดู HTTP usernames/passwords
sudo tcpdump -A 'port 80' | grep -E "username|password|login"

# Port Scan Detection (SYN packets จำนวนมาก)
sudo tcpdump -nn 'tcp[tcpflags] == tcp-syn' | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c

# ARP Poisoning Detection
sudo tcpdump -n arp | grep "who-has"

# DNS Queries
sudo tcpdump -n 'udp port 53'

# บันทึกและวิเคราะห์ด้วย tshark (CLI Wireshark)
sudo apt install tshark
tshark -r capture.pcap -Y http
tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri
```

---

## Step 40: tcpdump และ Traffic Analysis

### การวิเคราะห์ Traffic Pattern

```bash
# ==========================================
# Traffic Analysis for Security
# ==========================================

# Statistics
tcpdump -r capture.pcap | wc -l                    # จำนวน packets
tcpdump -r capture.pcap -nn | awk '{print $3}' | sort | uniq -c | sort -rn | head 20  # Top source IPs

# ดู HTTP traffic
tcpdump -r capture.pcap -A 'port 80' | grep -E "GET|POST|HTTP"

# ดู DNS traffic
tcpdump -r capture.pcap -n 'udp port 53' | grep -v "response"

# หา anomalies
# 1. High volume traffic (DDoS indicator)
tcpdump -r capture.pcap -nn | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn

# 2. Unusual ports
tcpdump -r capture.pcap -nn | awk '{print $5}' | grep -oE "\.[0-9]+" | sort | uniq -c | sort -rn

# 3. Large packet sizes (data exfiltration)
tcpdump -r capture.pcap -nn -v | grep "length [0-9]\{3,\}"

# ==========================================
# tshark - Advanced Analysis
# ==========================================

# ดู HTTP requests
tshark -r capture.pcap -Y "http.request" -T fields \
    -e ip.src \
    -e ip.dst \
    -e http.request.method \
    -e http.request.uri \
    -E separator="|"

# ดู credentials
tshark -r capture.pcap -Y "http.request.method == POST" -T fields \
    -e ip.src \
    -e http.file_data

# Export ไฟล์จาก capture
tshark -r capture.pcap --export-objects http,./exported_files/

# DNS queries
tshark -r capture.pcap -Y dns -T fields \
    -e frame.time \
    -e ip.src \
    -e dns.qry.name

# ==========================================
# NetworkMiner (GUI Tool)
# ==========================================

# สำหรับ Windows หรือ mono บน Linux
sudo apt install mono-complete
wget https://www.netresec.com/files/NetworkMiner_2-8.zip
unzip NetworkMiner_2-8.zip
cd NetworkMiner_2-8
sudo mono NetworkMiner.exe
```

---

## สรุป Part 04

ในบทนี้คุณได้เรียนรู้:

✅ **Step 31**: OSI Model ทั้ง 7 ชั้นและ Attacks ที่เกิดในแต่ละชั้น  
✅ **Step 32**: TCP/IP Protocol Suite และโครงสร้าง Header  
✅ **Step 33**: IP Addressing & Subnetting  
✅ **Step 34**: DNS, ARP Protocols  
✅ **Step 35**: TCP Flags และ Port States  
✅ **Step 36**: UDP Services และ SNMP  
✅ **Step 37**: NAT & Port Forwarding  
✅ **Step 38**: Wireshark  
✅ **Step 39**: tcpdump  
✅ **Step 40**: Traffic Analysis  

## แบบฝึกหัด

1. ใช้ Wireshark capture traffic บน lab network แล้วหา credentials
2. ใช้ dig ทำ DNS enumeration กับ domain ทดสอบ
3. ทดสอบ ARP spoofing ระหว่าง 2 VMs ใน lab
4. วิเคราะห์ pcap file ด้วย tcpdump และหา HTTP credentials
5. สร้าง Python script ใช้ scapy ส่ง custom TCP packets

## ถัดไป: Part 05 - Reconnaissance & Information Gathering

---

*Part 04 | Steps 31-40 | ระดับ: พื้นฐาน-กลาง*
