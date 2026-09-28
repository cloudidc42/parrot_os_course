# Part 06: Nmap - Network Mapper (Steps 51-60)

## บทนำ

Nmap (Network Mapper) คือเครื่องมือ Open Source สำหรับ Network Discovery และ Security Auditing เป็นเครื่องมือที่ Pentester ใช้บ่อยที่สุด ในบทนี้จะเรียนรู้ตั้งแต่พื้นฐานจนถึงเทคนิคขั้นสูง

---

## Step 51: Nmap พื้นฐาน

### Scan Types

```bash
# ==========================================
# Installation
# ==========================================
sudo apt install nmap

nmap --version
nmap -V

# ==========================================
# Basic Scans
# ==========================================

# Ping Scan (Host Discovery)
nmap -sn 192.168.1.0/24           # ค้นหา hosts ที่ online
nmap -sn 192.168.1.1-254          # IP range
nmap -sn 192.168.1.1 192.168.1.2  # หลาย IPs
nmap -sn 192.168.1.*              # wildcard

# Default Scan (1000 common ports)
nmap 192.168.1.1

# Scan specific port
nmap -p 80 192.168.1.1
nmap -p 80,443,8080 192.168.1.1
nmap -p 1-1000 192.168.1.1
nmap -p- 192.168.1.1              # ทุก ports (1-65535)

# ==========================================
# Scan Types
# ==========================================

# SYN Scan (Default - requires root, stealthy)
sudo nmap -sS 192.168.1.1

# TCP Connect Scan (no root needed)
nmap -sT 192.168.1.1

# UDP Scan (ช้า)
sudo nmap -sU 192.168.1.1
sudo nmap -sU -p 53,161,162 192.168.1.1

# Combined TCP+UDP
sudo nmap -sS -sU 192.168.1.1

# NULL Scan (ไม่มี flags)
sudo nmap -sN 192.168.1.1

# FIN Scan (FIN flag)
sudo nmap -sF 192.168.1.1

# XMAS Scan (FIN+URG+PSH)
sudo nmap -sX 192.168.1.1

# ACK Scan (detect firewall rules)
sudo nmap -sA 192.168.1.1

# Idle/Zombie Scan (IP spoofing)
sudo nmap -sI zombie_host 192.168.1.1

# Window Scan
sudo nmap -sW 192.168.1.1

# ==========================================
# Service & Version Detection
# ==========================================

# Version Detection
nmap -sV 192.168.1.1

# OS Detection (root required)
sudo nmap -O 192.168.1.1

# Aggressive Scan (OS + Version + Scripts + Traceroute)
sudo nmap -A 192.168.1.1

# ==========================================
# Output Formats
# ==========================================

# Normal output
nmap 192.168.1.1 -oN output.txt

# XML output (สำหรับ parsing)
nmap 192.168.1.1 -oX output.xml

# Grepable output
nmap 192.168.1.1 -oG output.gnmap

# ทุกรูปแบบพร้อมกัน
nmap 192.168.1.1 -oA output        # สร้าง .nmap, .xml, .gnmap

# ==========================================
# Timing Templates
# ==========================================
# -T0 Paranoid (5 min ต่อ probe)
# -T1 Sneaky
# -T2 Polite
# -T3 Normal (default)
# -T4 Aggressive (แนะนำสำหรับ lab)
# -T5 Insane (อาจพลาด ports)

nmap -T4 192.168.1.1
nmap -T4 -A 192.168.1.0/24

# ==========================================
# Verbosity
# ==========================================
nmap -v 192.168.1.1               # verbose
nmap -vv 192.168.1.1              # very verbose
nmap -d 192.168.1.1               # debug
nmap --reason 192.168.1.1         # แสดงเหตุผล port state
```

---

## Step 52: Nmap Scripting Engine (NSE)

```bash
# ==========================================
# NSE Scripts
# ==========================================

# Scripts อยู่ที่ /usr/share/nmap/scripts/
ls /usr/share/nmap/scripts/ | head -30

# Categories:
# auth      - Authentication
# broadcast - Broadcast requests
# brute     - Brute force
# default   - Default (-sC)
# discovery - Network discovery
# exploit   - Exploit vulnerabilities
# external  - External queries
# fuzzer    - Fuzzing
# intrusive - May affect target
# malware   - Malware detection
# safe      - Safe to run
# version   - Version detection
# vuln      - Vulnerability detection

# ==========================================
# Run Scripts
# ==========================================

# Default scripts (-sC)
nmap -sC 192.168.1.1

# Specific script
nmap --script=http-title 192.168.1.1
nmap --script=ssh-brute 192.168.1.1

# Multiple scripts
nmap --script=http-title,http-headers 192.168.1.1

# By category
nmap --script=vuln 192.168.1.1
nmap --script=auth 192.168.1.1
nmap --script=discovery 192.168.1.1

# Wildcard
nmap --script="http-*" 192.168.1.1
nmap --script="smb-*" 192.168.1.1

# Script with arguments
nmap --script=http-brute --script-args="userdb=users.txt,passdb=pass.txt" 192.168.1.1
nmap --script=smb-brute --script-args=userdb=users.txt,passdb=wordlist.txt 192.168.1.1

# ==========================================
# Security Scanning Scripts
# ==========================================

# SMB Vulnerabilities
nmap --script=smb-vuln-* -p 445 192.168.1.1
nmap --script=smb-vuln-ms17-010 -p 445 192.168.1.1  # EternalBlue
nmap --script=smb-vuln-ms08-067 -p 445 192.168.1.1  # Conficker

# SSH
nmap --script=ssh-brute -p 22 192.168.1.1
nmap --script=ssh-auth-methods -p 22 192.168.1.1
nmap --script=ssh2-enum-algos -p 22 192.168.1.1

# FTP
nmap --script=ftp-anon -p 21 192.168.1.1    # Anonymous FTP
nmap --script=ftp-brute -p 21 192.168.1.1

# HTTP
nmap --script=http-methods -p 80 192.168.1.1
nmap --script=http-auth -p 80 192.168.1.1
nmap --script=http-backup-finder -p 80 192.168.1.1
nmap --script=http-config-backup -p 80 192.168.1.1
nmap --script=http-robots.txt -p 80 192.168.1.1
nmap --script=http-shellshock -p 80 192.168.1.1

# DNS
nmap --script=dns-zone-transfer -p 53 192.168.1.1
nmap --script=dns-brute --script-args="dns-brute.domain=example.com"

# MySQL
nmap --script=mysql-info -p 3306 192.168.1.1
nmap --script=mysql-empty-password -p 3306 192.168.1.1
nmap --script=mysql-brute -p 3306 192.168.1.1

# MSSQL
nmap --script=ms-sql-info -p 1433 192.168.1.1
nmap --script=ms-sql-brute -p 1433 192.168.1.1
nmap --script=ms-sql-empty-password -p 1433 192.168.1.1

# SNMP
nmap --script=snmp-info -sU -p 161 192.168.1.1
nmap --script=snmp-brute -sU -p 161 192.168.1.1

# Vulnerability scanning
nmap --script=vuln 192.168.1.1
```

---

## Step 53: Advanced Nmap Techniques

### Firewall Evasion

```bash
# ==========================================
# Firewall / IDS Evasion Techniques
# ==========================================

# Fragment packets (หลีกเลี่ยง packet inspection)
sudo nmap -f 192.168.1.1              # Fragment (8 bytes)
sudo nmap -ff 192.168.1.1             # Fragment (16 bytes)
sudo nmap --mtu 24 192.168.1.1        # Custom MTU

# Decoy Scanning (IP Spoofing ปลอม)
sudo nmap -D 1.2.3.4,5.6.7.8,ME 192.168.1.1
sudo nmap -D RND:5 192.168.1.1        # 5 random decoys

# Idle Scan (ใช้ Zombie host)
sudo nmap -sI zombie_ip:port 192.168.1.1

# Source Port Manipulation
sudo nmap --source-port 53 192.168.1.1  # แกล้งทำเป็น DNS
sudo nmap -g 80 192.168.1.1             # ใช้ port 80

# Slow Scan
sudo nmap -T0 192.168.1.1
sudo nmap --scan-delay 5000ms 192.168.1.1

# Data length
sudo nmap --data-length 25 192.168.1.1

# Append custom data
sudo nmap --data-string "GET / HTTP/1.0\r\n\r\n" 192.168.1.1

# ==========================================
# Host Discovery Options
# ==========================================

# ข้ามการ ping (เข้าถึง host ที่ block ICMP)
nmap -Pn 192.168.1.1              # No ping - สมมติ host online
nmap -PS 192.168.1.1              # SYN ping
nmap -PA 192.168.1.1              # ACK ping
nmap -PU 192.168.1.1              # UDP ping
nmap -PE 192.168.1.1              # ICMP echo
nmap -PP 192.168.1.1              # ICMP timestamp
nmap -PM 192.168.1.1              # ICMP address mask

# =============================================
# DNS Options
# =============================================

# ไม่ resolve DNS
nmap -n 192.168.1.1

# Resolve DNS
nmap -R 192.168.1.1

# ใช้ DNS server เฉพาะ
nmap --dns-servers 8.8.8.8 192.168.1.1

# =============================================
# Port Selection
# =============================================

nmap -F 192.168.1.1               # Fast (100 common ports)
nmap -p- 192.168.1.1              # ทุก ports
nmap --top-ports 1000 192.168.1.1 # Top 1000 ports
nmap --top-ports 100 192.168.1.1  # Top 100 ports
nmap -p 22-443 192.168.1.1        # Range
nmap -p U:53,111,137,T:21-25,80 192.168.1.1  # Mixed
nmap -p http,ftp,ssh 192.168.1.1   # Protocol names
```

---

## Step 54: Nmap Output Analysis

### Parsing Nmap Output

```bash
# ==========================================
# XML Output Parsing
# ==========================================

# ด้วย python-nmap
pip3 install python-nmap

python3 << 'EOF'
import nmap

nm = nmap.PortScanner()
nm.scan('192.168.1.0/24', '22,80,443', '-sV')

for host in nm.all_hosts():
    print(f'\nHost: {host}')
    print(f'State: {nm[host].state()}')
    
    for proto in nm[host].all_protocols():
        print(f'Protocol: {proto}')
        
        ports = nm[host][proto].keys()
        for port in sorted(ports):
            state = nm[host][proto][port]['state']
            service = nm[host][proto][port]['name']
            version = nm[host][proto][port].get('version', '')
            print(f'  Port {port}/{proto}: {state} ({service} {version})')
EOF

# ==========================================
# Grepable Output Analysis
# ==========================================

# ดู hosts ที่ open port 80
grep "80/open" output.gnmap | awk '{print $2}'

# ดู hosts ที่ online
grep "Status: Up" output.gnmap | awk '{print $2}'

# ดู services
grep -o '[0-9]*/open/[a-z]*' output.gnmap | sort | uniq -c | sort -rn

# ==========================================
# Tools สำหรับ Parse
# ==========================================

# grepcidr
sudo apt install grepcidr

# ndiff - เปรียบเทียบ 2 scans
ndiff scan1.xml scan2.xml

# nmap-parse-output
git clone https://github.com/ernw/nmap-parse-output.git
./nmap-parse-output/nmap-parse-output scan.xml all-ip
./nmap-parse-output/nmap-parse-output scan.xml http-ports

# ==========================================
# Zenmap (GUI)
# ==========================================
sudo apt install zenmap

# Features:
# - GUI สำหรับ nmap
# - Profile-based scanning
# - Topology visualization
# - Compare scans
# - Save/load scans
```

---

## Step 55: Masscan - Large Scale Scanning

```bash
# ==========================================
# Masscan - Mass IP Port Scanner
# ==========================================

# ติดตั้ง
sudo apt install masscan

# ==========================================
# การใช้งาน
# ==========================================

# Scan เร็วมาก (ระวัง! อาจโหลด network)
sudo masscan -p80,443 192.168.1.0/24 --rate=1000

# ทุก ports (ช้ากว่า nmap แต่รองรับ scale ใหญ่กว่า)
sudo masscan -p1-65535 192.168.1.1 --rate=10000

# Scan เร็วมาก
sudo masscan -p80 0.0.0.0/0 --rate=100000  # Internet scan (อย่าทำจริง!)

# Output format
sudo masscan -p80,443 192.168.1.0/24 -oX output.xml
sudo masscan -p80,443 192.168.1.0/24 -oJ output.json
sudo masscan -p80,443 192.168.1.0/24 -oG output.gnmap

# ==========================================
# Masscan + Nmap Combo
# ==========================================

# ขั้นตอน:
# 1. ใช้ masscan หา open ports เร็วๆ
# 2. ใช้ nmap scan ละเอียดเฉพาะ hosts/ports ที่พบ

# Step 1: masscan scan
sudo masscan -p1-65535 192.168.1.0/24 --rate=5000 -oG masscan.gnmap

# Step 2: parse ผล masscan
awk '/open/ {print $2}' masscan.gnmap | sort -u > live_hosts.txt

# Step 3: nmap ละเอียด
nmap -sV -sC -iL live_hosts.txt -p$(cat masscan.gnmap | awk '/open/ {split($NF,a,"/"); printf a[1]","} END{print ""}' | sed 's/,$//')
```

---

## Step 56: การ Scan แบบ Comprehensive

### Full Pentest Scan Workflow

```bash
#!/bin/bash
# comprehensive_scan.sh - Full Pentest Network Scan

TARGET="$1"
OUTPUT_DIR="scan_$(echo $TARGET | tr '/' '_')_$(date +%Y%m%d_%H%M%S)"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    echo "Example: $0 192.168.1.0/24"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

echo "[*] Starting comprehensive scan on $TARGET"
echo "[*] Results will be saved in $OUTPUT_DIR"

# Phase 1: Host Discovery
echo "[+] Phase 1: Host Discovery"
nmap -sn "$TARGET" -oA host_discovery --reason
grep "Status: Up" host_discovery.gnmap | awk '{print $2}' > live_hosts.txt
echo "Found $(wc -l < live_hosts.txt) live hosts"

# Phase 2: Fast Port Scan
echo "[+] Phase 2: Fast Port Scan"
nmap -T4 -F --open -iL live_hosts.txt -oA fast_scan

# Phase 3: Full Port Scan
echo "[+] Phase 3: Full Port Scan"
nmap -T4 -p- --open -iL live_hosts.txt -oA full_scan &
FULL_SCAN_PID=$!

# Phase 4: Service Detection on common ports
echo "[+] Phase 4: Service Detection"
nmap -T4 -sV -sC -iL live_hosts.txt -oA service_scan

# Phase 5: OS Detection
echo "[+] Phase 5: OS Detection"
sudo nmap -T4 -O -iL live_hosts.txt -oA os_scan

# Phase 6: Vulnerability Scan
echo "[+] Phase 6: Vulnerability Scan"
nmap -T4 --script=vuln -iL live_hosts.txt -oA vuln_scan

# Phase 7: Web Specific
echo "[+] Phase 7: Web Server Scan"
nmap -T4 -p 80,443,8080,8443 --script="http-*" -iL live_hosts.txt -oA web_scan

# รอ full scan เสร็จ
wait $FULL_SCAN_PID
echo "[+] Full port scan complete"

echo "[*] All scans complete!"
echo "[*] Summary:"
echo "    Live hosts: $(wc -l < live_hosts.txt)"
echo "    Results in: $OUTPUT_DIR/"
```

---

## Step 57: Nmap สำหรับ Specific Services

### SMB Enumeration

```bash
# ==========================================
# SMB (Server Message Block) - Port 445/139
# ==========================================

# Basic SMB scan
nmap -p 445 --script=smb-* 192.168.1.1

# SMB version
nmap --script=smb-protocols -p 445 192.168.1.1

# SMB shares
nmap --script=smb-enum-shares -p 445 192.168.1.1
nmap --script=smb-enum-shares --script-args smbuser=admin,smbpass=password -p 445 192.168.1.1

# SMB users
nmap --script=smb-enum-users -p 445 192.168.1.1

# SMB OS discovery
nmap --script=smb-os-discovery -p 445 192.168.1.1

# SMB Vulnerabilities
nmap --script=smb-vuln-ms17-010 -p 445 192.168.1.1    # EternalBlue
nmap --script=smb-vuln-ms08-067 -p 445 192.168.1.1    # MS08-067
nmap --script=smb-vuln-cve2009-3103 -p 445 192.168.1.1
nmap --script=smb-vuln-ms06-025 -p 445 192.168.1.1

# ==========================================
# HTTP/HTTPS - Port 80/443
# ==========================================

nmap --script=http-title -p 80,443 192.168.1.1
nmap --script=http-headers -p 80,443 192.168.1.1
nmap --script=http-methods -p 80,443 192.168.1.1
nmap --script=http-auth-finder -p 80 192.168.1.1
nmap --script=http-enum -p 80 192.168.1.1           # Common paths
nmap --script=http-git -p 80 192.168.1.1            # .git directory
nmap --script=http-svn-info -p 80 192.168.1.1       # SVN info
nmap --script=http-robots.txt -p 80 192.168.1.1     # robots.txt
nmap --script=http-sitemap-generator -p 80 192.168.1.1

# SSL/TLS
nmap --script=ssl-cert -p 443 192.168.1.1
nmap --script=ssl-enum-ciphers -p 443 192.168.1.1
nmap --script=ssl-dh-params -p 443 192.168.1.1
nmap --script=ssl-heartbleed -p 443 192.168.1.1   # Heartbleed

# ==========================================
# Database Services
# ==========================================

# MySQL (3306)
nmap --script=mysql-info -p 3306 192.168.1.1
nmap --script=mysql-databases --script-args=mysqluser=root,mysqlpass='' -p 3306 192.168.1.1
nmap --script=mysql-users --script-args=mysqluser=root -p 3306 192.168.1.1
nmap --script=mysql-empty-password -p 3306 192.168.1.1

# MSSQL (1433)
nmap --script=ms-sql-info -p 1433 192.168.1.1
nmap --script=ms-sql-config -p 1433 192.168.1.1

# PostgreSQL (5432)
nmap --script=pgsql-brute -p 5432 192.168.1.1

# MongoDB (27017)
nmap --script=mongodb-info -p 27017 192.168.1.1
nmap --script=mongodb-databases -p 27017 192.168.1.1

# Redis (6379)
nmap --script=redis-info -p 6379 192.168.1.1

# ==========================================
# Email Services
# ==========================================

# SMTP (25)
nmap --script=smtp-commands -p 25 192.168.1.1
nmap --script=smtp-enum-users -p 25 192.168.1.1
nmap --script=smtp-open-relay -p 25 192.168.1.1

# IMAP (143/993)
nmap --script=imap-capabilities -p 143 192.168.1.1
nmap --script=imap-brute -p 143 192.168.1.1

# POP3 (110/995)
nmap --script=pop3-capabilities -p 110 192.168.1.1
nmap --script=pop3-brute -p 110 192.168.1.1
```

---

## Step 58: การใช้ Nmap อย่างมืออาชีพ

### Nmap Best Practices

```bash
# ==========================================
# Professional Nmap Usage
# ==========================================

# 1. เริ่มจาก Host Discovery ก่อน
sudo nmap -sn --reason 192.168.1.0/24 -oA phase1_discovery

# 2. Scan open ports บน live hosts
nmap -p- -T4 --open -iL live_hosts.txt -oA phase2_ports

# 3. Service detection เฉพาะ open ports
# Parse open ports จาก phase 2
grep "open" phase2_ports.gnmap | grep -oP '\d+/open' | cut -d/ -f1 | sort -u | tr '\n' ',' | sed 's/,$//'

# 4. Version + Script ทุก ports ที่พบ
nmap -sV -sC -p $OPEN_PORTS -iL live_hosts.txt -oA phase3_services

# 5. OS Detection
sudo nmap -O -p $OPEN_PORTS -iL live_hosts.txt -oA phase4_os

# ==========================================
# Scan Report Script
# ==========================================

#!/bin/bash
# generate_nmap_report.sh

SCAN_DIR="$1"

echo "=== NMAP SCAN REPORT ===" > report.txt
echo "Generated: $(date)" >> report.txt
echo "" >> report.txt

# Live hosts
echo "=== LIVE HOSTS ===" >> report.txt
grep "Status: Up" $SCAN_DIR/*.gnmap | awk '{print $2}' | sort >> report.txt
echo "" >> report.txt

# Open ports summary
echo "=== OPEN PORTS ===" >> report.txt
grep "open" $SCAN_DIR/*.gnmap | grep -v "#" | awk '{print $2, $NF}' >> report.txt
echo "" >> report.txt

# Services
echo "=== SERVICES ===" >> report.txt
nmap -iL live_hosts.txt --reason --open -oN - 2>/dev/null >> report.txt

cat report.txt
```

---

## Step 59: Masscan + Nmap Combo Workflow

```bash
# ==========================================
# Production-Grade Scan Workflow
# ==========================================

#!/bin/bash
# pentest_scan.sh

TARGET="$1"
DATE=$(date +%Y%m%d_%H%M%S)
OUTDIR="pentest_${TARGET//\//_}_$DATE"

mkdir -p "$OUTDIR"

echo "================================"
echo " Professional Pentest Scanner"
echo " Target: $TARGET"
echo " Output: $OUTDIR"
echo "================================"

# 1. Fast host discovery
echo "[1/6] Host Discovery..."
sudo nmap -sn -T4 "$TARGET" -oA "$OUTDIR/01_discovery" 2>/dev/null
grep "Status: Up" "$OUTDIR/01_discovery.gnmap" | awk '{print $2}' > "$OUTDIR/live_hosts.txt"
LIVE=$(wc -l < "$OUTDIR/live_hosts.txt")
echo "    Found $LIVE live hosts"

# 2. Fast scan (top 1000 ports)
echo "[2/6] Fast Port Scan..."
nmap -T4 --open -iL "$OUTDIR/live_hosts.txt" -oA "$OUTDIR/02_fast_scan" 2>/dev/null

# 3. Full port scan (background)
echo "[3/6] Starting Full Port Scan (background)..."
sudo nmap -p- -T4 --open -iL "$OUTDIR/live_hosts.txt" -oA "$OUTDIR/03_full_scan" 2>/dev/null &
FULL_PID=$!

# 4. Service Detection
echo "[4/6] Service Detection..."
nmap -sV -sC -T4 -iL "$OUTDIR/live_hosts.txt" -oA "$OUTDIR/04_services" 2>/dev/null

# 5. Vulnerability Scan
echo "[5/6] Vulnerability Scan..."
nmap --script=vuln -T4 -iL "$OUTDIR/live_hosts.txt" -oA "$OUTDIR/05_vulns" 2>/dev/null

# 6. Web scan
echo "[6/6] Web Server Scan..."
nmap -p 80,443,8080,8443,8000,8888 --script="http-title,http-headers,http-methods,ssl-cert" \
    -iL "$OUTDIR/live_hosts.txt" -oA "$OUTDIR/06_web" 2>/dev/null

# Wait for full scan
echo "Waiting for full port scan..."
wait $FULL_PID

echo ""
echo "=== SCAN COMPLETE ==="
echo "Results saved in: $OUTDIR/"
ls -la "$OUTDIR/"
```

---

## Step 60: การวิเคราะห์ผล Nmap

### Nmap Output Analysis Script

```bash
#!/bin/bash
# analyze_nmap.sh - Analyze Nmap Output

GNMAP_FILE="$1"

if [ -z "$GNMAP_FILE" ]; then
    echo "Usage: $0 <scan.gnmap>"
    exit 1
fi

echo "=============================="
echo " Nmap Output Analysis"
echo "=============================="

echo ""
echo "=== LIVE HOSTS ==="
grep "Status: Up" "$GNMAP_FILE" | awk '{print $2}' | sort -V

echo ""
echo "=== HOSTS BY PORT COUNT ==="
grep "Ports:" "$GNMAP_FILE" | awk '{
    host=$2
    port_count=0
    for(i=1;i<=NF;i++) if($i ~ /\/open\//) port_count++
    print port_count, host
}' | sort -rn | head 20

echo ""
echo "=== OPEN PORTS SUMMARY ==="
grep -oP '\d+/open/[a-z]+' "$GNMAP_FILE" | awk -F/ '{print $1"/"$3}' | sort | uniq -c | sort -rn

echo ""
echo "=== POTENTIAL WEB SERVERS ==="
grep "80/open\|443/open\|8080/open\|8443/open" "$GNMAP_FILE" | awk '{print $2}'

echo ""
echo "=== POTENTIAL DATABASES ==="
grep "3306/open\|5432/open\|27017/open\|6379/open\|1433/open\|1521/open" "$GNMAP_FILE" | awk '{print $2}'

echo ""
echo "=== POTENTIAL SMB/SAMBA ==="
grep "445/open\|139/open" "$GNMAP_FILE" | awk '{print $2}'

echo ""
echo "=== POTENTIAL SSH ==="
grep "22/open" "$GNMAP_FILE" | awk '{print $2}'

echo ""
echo "=== POTENTIAL FTP ==="
grep "21/open" "$GNMAP_FILE" | awk '{print $2}'

echo ""
echo "=== POTENTIAL TELNET (INSECURE!) ==="
grep "23/open" "$GNMAP_FILE" | awk '{print $2}'
```

---

## สรุป Part 06

ในบทนี้คุณได้เรียนรู้:

✅ **Step 51**: Nmap พื้นฐาน - Scan Types ทุกประเภท  
✅ **Step 52**: Nmap Scripting Engine (NSE)  
✅ **Step 53**: Advanced Techniques - Firewall Evasion  
✅ **Step 54**: Output Analysis  
✅ **Step 55**: Masscan  
✅ **Step 56**: Comprehensive Scan Workflow  
✅ **Step 57**: Scan เฉพาะ Services  
✅ **Step 58**: Professional Practices  
✅ **Step 59**: Masscan+Nmap Combo  
✅ **Step 60**: Analysis Script  

## แบบฝึกหัด

1. Scan Metasploitable2 ด้วย nmap -A และวิเคราะห์ผล
2. ใช้ NSE scripts ค้นหา SMB vulnerabilities
3. เขียน script ที่รวม masscan + nmap
4. Compare ผล scan ด้วย ndiff
5. ทำ full pentest scan บน lab network และสร้าง report

## ถัดไป: Part 07 - Web Application Security

---

*Part 06 | Steps 51-60 | ระดับ: กลาง*
