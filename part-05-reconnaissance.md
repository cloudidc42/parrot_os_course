# Part 05: Reconnaissance & Information Gathering (Steps 41-50)

## บทนำ

Reconnaissance (Recon) คือขั้นตอนแรกและสำคัญที่สุดใน Penetration Testing Methodology ยิ่งเก็บข้อมูลได้มากเท่าไหร่ โอกาสประสบความสำเร็จยิ่งสูงขึ้น ในบทนี้จะครอบคลุมทั้ง Passive และ Active Reconnaissance

---

## Step 41: Penetration Testing Methodology

### Pentest Phases

```
1. Pre-Engagement (การเตรียมการก่อน)
   - ลงนามสัญญา
   - กำหนด Scope
   - Rules of Engagement
   - Timeline

2. Information Gathering / Reconnaissance
   - Passive Recon (ไม่ส่ง traffic ไปยัง target)
   - Active Recon (ส่ง traffic ไปยัง target)
   
3. Threat Modeling / Vulnerability Analysis
   - วิเคราะห์ช่องโหว่ที่พบ
   - จัดลำดับความสำคัญ

4. Exploitation
   - ทดสอบ exploit ช่องโหว่
   - Gain Access

5. Post-Exploitation
   - Privilege Escalation
   - Lateral Movement
   - Data Exfiltration
   - Persistence

6. Reporting
   - Technical Report
   - Executive Summary
   - Remediation Recommendations

7. Cleanup
   - ลบ backdoors
   - คืนสภาพระบบ
```

### Recon Framework

```bash
# ==========================================
# Reconnaissance Methodology
# ==========================================

# Passive Recon (ไม่ทิ้ง trace บน target):
# - Google/Bing Dorking
# - WHOIS/DNS queries
# - Shodan/Censys
# - Social Media
# - Job Postings
# - LinkedIn
# - GitHub/GitLab
# - Certificate Transparency
# - Wayback Machine
# - Pastebin

# Active Recon (ส่ง traffic ไปยัง target):
# - Port Scanning
# - Service Enumeration  
# - Banner Grabbing
# - Web Directory Brute Force
# - DNS Brute Force
# - Email Harvesting
# - OS Fingerprinting
```

---

## Step 42: Passive Reconnaissance - OSINT

### Google Dorking

```bash
# ==========================================
# Google Dorks (ค้นหาข้อมูลพิเศษด้วย Google)
# ==========================================

# Syntax:
# site:        - ค้นหาในเว็บไซต์เฉพาะ
# inurl:       - ค้นหาใน URL
# intitle:     - ค้นหาในชื่อหน้า
# intext:      - ค้นหาในเนื้อหา
# filetype:    - ค้นหาตามประเภทไฟล์
# ext:         - เหมือน filetype
# link:        - ค้นหา links
# cache:       - ดู cached version
# -            - ยกเว้น
# ""           - ตรงทั้งหมด (exact match)
# OR / |       - หรือ
# *            - wildcard

# ==========================================
# ค้นหาข้อมูล Target
# ==========================================

# ค้นหา subdomains
site:example.com

# ยกเว้น www
site:example.com -site:www.example.com

# ค้นหาหน้า login
site:example.com inurl:login
site:example.com inurl:admin
site:example.com inurl:portal

# ค้นหาไฟล์สำคัญ
site:example.com filetype:pdf
site:example.com filetype:xls "confidential"
site:example.com filetype:sql
site:example.com filetype:log

# ค้นหา config files
site:example.com filetype:env
site:example.com filetype:config
site:example.com filetype:ini
site:example.com filetype:xml inurl:config

# ค้นหา exposed directories
site:example.com intitle:"index of"
site:example.com intitle:"directory listing"

# ค้นหา email addresses
site:example.com intext:"@example.com"

# ==========================================
# General Dorks
# ==========================================

# Admin panels
intitle:"admin panel" inurl:admin
intitle:"login" inurl:admin

# Cameras
intitle:"webcamXP 5" | intitle:"WebcamXP" inurl:"8080"
inurl:/view/index.shtml

# Database dumps
intext:"sql dump" filetype:sql
intext:"INSERT INTO" filetype:sql

# Exposed passwords
inurl:passwd filetype:txt
intitle:"index of" ".htpasswd"
filetype:log intext:"password"

# Config files with credentials
filetype:env DB_PASSWORD
inurl:config.php intext:$dbpass
filetype:cfg intext:password

# Git repositories
site:github.com "example.com" password
site:gitlab.com "example.com" token

# ==========================================
# เครื่องมือ
# ==========================================

# GHDB - Google Hacking Database
# https://www.exploit-db.com/google-hacking-database

# dorkbot - Automate Google Dorks
pip3 install dorkbot
dorkbot -d example.com -i url -s google -q 'site:example.com inurl:admin'

# googler - Google search from terminal
sudo apt install googler
googler "site:example.com filetype:pdf"
```

### WHOIS & Certificate Transparency

```bash
# ==========================================
# WHOIS
# ==========================================

whois example.com                         # Domain info
whois 192.168.1.1                         # IP info
whois -h whois.arin.net 8.8.8.8           # ARIN
whois -h whois.apnic.net 1.1.1.1          # APNIC

# ข้อมูลที่ได้จาก WHOIS:
# - Registrar
# - Registration dates
# - Name servers
# - Registrant info (ถ้าไม่ privacy-protected)
# - Admin/Tech contacts

# ==========================================
# SSL Certificate Transparency
# ==========================================

# Certificate Transparency logs เก็บ SSL certs ทั้งหมด
# ใช้ค้นหา subdomains ที่ซ่อนอยู่

# crt.sh - Certificate search
curl -s "https://crt.sh/?q=%.example.com&output=json" | python3 -m json.tool
curl -s "https://crt.sh/?q=%.example.com&output=json" | python3 -c "
import sys, json
certs = json.load(sys.stdin)
domains = set()
for cert in certs:
    name = cert.get('name_value', '')
    for d in name.split('\n'):
        domains.add(d.strip().lower().lstrip('*.'))
for d in sorted(domains):
    print(d)
"

# censys.io - Internet-wide scanning
# สร้างบัญชีที่ censys.io แล้วใช้ API

# ==========================================
# DNS History
# ==========================================

# SecurityTrails (ต้องสมัคร)
# https://securitytrails.com

# DNSdumpster
# https://dnsdumpster.com

# viewdns.info
# https://viewdns.info

# HistoricalWhois
# https://research.domaintools.com/whois-history/
```

---

## Step 43: theHarvester - Email & Domain Recon

```bash
# ==========================================
# theHarvester - OSINT Tool
# ==========================================

# ติดตั้ง
sudo apt install theharvester

# หรือจาก GitHub
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
pip3 install -r requirements.txt

# ==========================================
# การใช้งาน
# ==========================================

# ค้นหาพื้นฐาน
theHarvester -d example.com -b google
theHarvester -d example.com -b bing
theHarvester -d example.com -b linkedin

# ใช้หลาย data sources
theHarvester -d example.com -b all

# Sources ที่มี:
# anubis, baidu, bing, brave, bufferoverun, certspotter
# crtsh, dnsx, duckduckgo, fullhunt, github-code
# google, hackertarget, hunter, intelx, linkedin
# omnisint, otx, pentesttools, rapiddns, rocketreach
# securityTrails, shodan, sitedossier, subdomainfinder
# threatminer, urlscan, virustotal, yahoo

# จำกัดผลลัพธ์
theHarvester -d example.com -b google -l 100

# บันทึกผล
theHarvester -d example.com -b all -f output.html
theHarvester -d example.com -b all -f output.xml

# DNS Brute Force
theHarvester -d example.com -b google -c

# Virtual Host discovery
theHarvester -d example.com -b bing -v

# ==========================================
# วิเคราะห์ผลที่ได้
# ==========================================

# ผลที่ได้จาก theHarvester:
# - Email addresses (info@example.com, hr@example.com)
# - Hostnames/Subdomains (mail.example.com, dev.example.com)
# - IP Addresses
# - Employee names (จาก LinkedIn)
# - ข้อมูลที่ใช้ใน Phishing / Password Spraying
```

---

## Step 44: Shodan - Internet-Connected Devices

```bash
# ==========================================
# Shodan - "Search Engine for IoT"
# ==========================================

# สมัครบัญชีที่ shodan.io
# ดาวน์โหลด API key

# ติดตั้ง shodan CLI
pip3 install shodan

# ตั้งค่า API key
shodan init YOUR_API_KEY

# ==========================================
# Shodan CLI
# ==========================================

# ค้นหา host
shodan host 8.8.8.8

# ค้นหาตาม query
shodan search "apache"
shodan search "nginx version:1.14"
shodan search 'hostname:example.com'

# Download results
shodan download --limit 100 results.json.gz "apache org:example.com"

# Parse results
shodan parse results.json.gz

# Count results
shodan count "apache"

# ==========================================
# Shodan Dorks
# ==========================================

# ค้นหา WebServers ของ organization
org:"Example Corp" http.title:"Login"

# ค้นหา vulnerable systems
vuln:CVE-2021-44228               # Log4Shell
vuln:CVE-2021-34527               # PrintNightmare

# ค้นหา default credentials
"default password" port:80

# ค้นหา specific services
product:Apache version:2.4.49     # Vulnerable Apache
product:OpenSSH version:7.2       # Old SSH

# ค้นหา config/backup files
http.title:"Index of /" http.html:".config"

# Databases exposed
port:3306 product:MySQL
port:5432 product:PostgreSQL
port:27017 product:MongoDB
port:6379 product:Redis

# Industrial Control Systems
product:Siemens
product:Schneider
product:GE Digital

# Cameras
product:webcam
title:"Network Camera"
port:554 rtsp

# ==========================================
# Shodan สำหรับ Organization Recon
# ==========================================

# ค้นหาทุกอย่างของ org
shodan search --fields ip_str,port,org,hostnames "org:'Example Corp'" 

# ค้นหาด้วย IP range (ASN)
shodan search "net:203.0.113.0/24"

# Python + Shodan API
python3 << 'EOF'
import shodan
import sys

API_KEY = "YOUR_API_KEY"
api = shodan.Shodan(API_KEY)

try:
    # ค้นหา
    results = api.search('org:"Example Corp"')
    print(f'Total results: {results["total"]}')
    
    for result in results['matches']:
        print(f"\nIP: {result['ip_str']}")
        print(f"Port: {result['port']}")
        print(f"Organization: {result.get('org', 'N/A')}")
        print(f"OS: {result.get('os', 'N/A')}")
        if 'http' in result:
            print(f"HTTP Title: {result['http'].get('title', 'N/A')}")
        print("---")
        
except shodan.APIError as e:
    print(f'Error: {e}')
EOF
```

---

## Step 45: Maltego พื้นฐาน

```bash
# ==========================================
# Maltego - Link Analysis Tool
# ==========================================

# Maltego คือ GUI tool สำหรับ OSINT และ relationship analysis
# ดาวน์โหลด Maltego CE (Community Edition) ได้ฟรี

# ติดตั้งบน Parrot OS
sudo apt install maltego

# หรือ download จาก maltego.com

# ==========================================
# Maltego Concepts
# ==========================================

# Entity = Object ต่างๆ (Domain, IP, Person, Email, etc.)
# Transform = การค้นหาข้อมูลเพิ่มเติม
# Graph = แผนภาพแสดงความสัมพันธ์

# ==========================================
# Entities ที่สำคัญ
# ==========================================
# Domain
# IP Address
# Person
# Email Address
# Phone Number
# Organization
# Website
# DNS Name
# URL

# ==========================================
# การทำ Recon ด้วย Maltego
# ==========================================

# 1. สร้าง Domain entity
# 2. Run transforms:
#    - DNS to IP
#    - Domain to Subdomains
#    - Domain to Email
#    - IP to Shodan
#    - Email to Social Media
# 3. ขยายความสัมพันธ์
# 4. Export graph

# ==========================================
# Maltego CLI (Canari Framework)
# ==========================================
pip3 install canari
# canari framework ช่วย run Maltego transforms จาก command line
```

---

## Step 46: DNS Enumeration ขั้นสูง

```bash
# ==========================================
# Subdomain Enumeration
# ==========================================

# amass - Comprehensive tool
sudo apt install amass

# Passive enumeration
amass enum -passive -d example.com
amass enum -passive -d example.com -o subdomains.txt

# Active enumeration
amass enum -active -d example.com

# Brute force
amass enum -brute -d example.com -w /usr/share/wordlists/amass/all.txt

# All techniques
amass enum -d example.com -all -o results.txt

# ==========================================
# subfinder
# ==========================================
# ติดตั้ง
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

subfinder -d example.com
subfinder -d example.com -all           # ใช้ทุก sources
subfinder -d example.com -silent        # output เฉพาะ subdomains
subfinder -dL domains.txt -o output.txt # หลาย domains
subfinder -d example.com -t 20          # 20 threads

# ==========================================
# assetfinder
# ==========================================
go install github.com/tomnomnom/assetfinder@latest

assetfinder example.com
assetfinder --subs-only example.com

# ==========================================
# sublist3r
# ==========================================
sudo apt install sublist3r

sublist3r -d example.com
sublist3r -d example.com -b              # brute force
sublist3r -d example.com -o output.txt

# ==========================================
# dnsx - DNS Resolution
# ==========================================
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Resolve subdomains
cat subdomains.txt | dnsx
cat subdomains.txt | dnsx -a -aaaa -cname -mx -ns -txt

# DNS Brute Force
dnsx -d example.com -w /usr/share/wordlists/dns.txt

# ==========================================
# massdns - High-Speed DNS Resolver
# ==========================================
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make

# Brute force subdomains
./massdns/bin/massdns -r /usr/share/wordlists/resolvers.txt \
    -t A -o S subdomains.txt

# ==========================================
# Zone Transfer (ส่วนใหญ่ถูก disable แล้ว)
# ==========================================

# ค้นหา name servers
dig NS example.com

# ลอง zone transfer กับทุก NS
for ns in $(dig +short NS example.com); do
    echo "=== Trying $ns ==="
    dig axfr @$ns example.com
done

# ==========================================
# DNS Reverse Lookup
# ==========================================

# Reverse lookup หลาย IPs
for ip in $(seq 1 254); do
    host 192.168.1.$ip 2>/dev/null | grep "domain name pointer"
done

# ด้วย nmap
nmap -sn --dns-servers 8.8.8.8 192.168.1.0/24 -R

# ==========================================
# Virtual Host Enumeration
# ==========================================

# VHosts คือหลาย websites บน IP เดียว
# ค้นหาโดยการส่ง Host header ต่างๆ

# ffuf
ffuf -w /usr/share/wordlists/vhosts.txt \
    -u http://192.168.1.1/ \
    -H "Host: FUZZ.example.com" \
    -fc 200 -c

# gobuster
gobuster vhost -u http://example.com \
    -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
```

---

## Step 47: Email Harvesting

```bash
# ==========================================
# Email Harvesting Techniques
# ==========================================

# ==========================================
# 1. Google Dorks
# ==========================================
# site:example.com intext:"@example.com"
# "@example.com" filetype:xls OR filetype:xlsx
# "@example.com" filetype:pdf

# ==========================================
# 2. theHarvester (ดูบท OSINT)
# ==========================================
theHarvester -d example.com -b all -f emails.html

# ==========================================
# 3. hunter.io
# ==========================================
# เว็บไซต์: hunter.io
# ค้นหา emails ของ domain
# สมัครบัญชีฟรีได้ (จำกัดจำนวน)

# CLI
pip3 install hunter
hunter domain-search example.com --api-key YOUR_KEY

# ==========================================
# 4. phonebook.cz
# ==========================================
# https://phonebook.cz/
# ค้นหา emails, domains, URLs

# ==========================================
# 5. GitHub
# ==========================================
# ค้นหา emails ที่ commit บน GitHub
# site:github.com "@example.com" email

# เครื่องมือ: git-secrets, gitleaks
pip3 install gitleaks

# ==========================================
# 6. LinkedIn
# ==========================================
# ค้นหาพนักงานของบริษัท
# สร้าง email patterns จากชื่อ

# Email formats ที่นิยม:
# firstname.lastname@example.com
# f.lastname@example.com
# firstname@example.com
# flastname@example.com
# firstname_lastname@example.com

# ==========================================
# Email Validation
# ==========================================

# ตรวจสอบ email ว่าถูกต้องหรือไม่
# verify-email
pip3 install verify-email
python3 -c "from verify_email import verify_email; print(verify_email('test@example.com'))"

# smtp-user-enum
sudo apt install smtp-user-enum

# ตรวจสอบ user ที่มีอยู่ผ่าน SMTP
smtp-user-enum -M VRFY -u admin -t mail.example.com
smtp-user-enum -M RCPT -U users.txt -t mail.example.com

# ==========================================
# Email Metadata Extraction
# ==========================================

# ดู email headers (สำหรับ Phishing Analysis)
# ข้อมูลใน email headers:
# - Original sender IP
# - Mail servers ที่ผ่าน
# - User-Agent (email client)
# - Time zone

# Tools:
# mha (Mail Header Analyzer): https://mha.danwin1210.me/
# Google Admin Toolbox: https://toolbox.googleapps.com/apps/messageheader/
```

---

## Step 48: Technology Fingerprinting

```bash
# ==========================================
# Web Technology Detection
# ==========================================

# whatweb - Web App Fingerprinting
sudo apt install whatweb

whatweb http://example.com
whatweb -a 3 http://example.com     # aggressive mode
whatweb --log-json=output.json http://example.com
whatweb -v http://example.com       # verbose

# ==========================================
# Wappalyzer (Browser Extension / CLI)
# ==========================================

# ติดตั้ง CLI
npm install -g wappalyzer

wappalyzer http://example.com
wappalyzer http://example.com --pretty

# ==========================================
# Banner Grabbing
# ==========================================

# nc/netcat
nc -v 192.168.1.1 22
nc -v 192.168.1.1 80
echo "" | nc -v -w 1 192.168.1.1 21

# curl
curl -I http://example.com             # ดู headers
curl -sv http://example.com 2>&1 | head -30

# nmap
nmap -sV -sC -p 80,443 example.com
nmap -sV --script=http-headers example.com

# ==========================================
# CMS Detection
# ==========================================

# WordPress
curl -s http://example.com/wp-login.php | grep "WordPress"
wpscan --url http://example.com

# Joomla
curl -s http://example.com/administrator/ | grep "Joomla"

# Drupal
curl -s http://example.com/user/login | grep "Drupal"

# ==========================================
# WAF Detection
# ==========================================
pip3 install wafw00f

wafw00f http://example.com
wafw00f -l                    # list known WAFs
wafw00f -a http://example.com # test all WAFs

# ==========================================
# Server Information
# ==========================================

# HTTP Server header
curl -I http://example.com | grep -i server

# X-Powered-By header
curl -I http://example.com | grep -i "x-powered-by"

# Cookies (session cookie names บอก technology)
curl -I http://example.com | grep -i "set-cookie"
# PHPSESSID = PHP
# JSESSIONID = Java
# ASP.NET_SessionId = ASP.NET
# _rails_session = Ruby on Rails

# ==========================================
# OS Detection (Network-based)
# ==========================================

# TTL ใน ping response
ping -c 1 192.168.1.1 | grep ttl
# TTL 64  = Linux/Unix
# TTL 128 = Windows
# TTL 255 = Cisco/Network devices

# nmap OS Detection
sudo nmap -O 192.168.1.1
sudo nmap -A 192.168.1.1       # All (OS + Service + Script)
```

---

## Step 49: Recon-ng Framework

```bash
# ==========================================
# Recon-ng - Modular Recon Framework
# ==========================================

# ติดตั้ง
sudo apt install recon-ng

# หรือ
pip3 install recon-ng

# เปิด recon-ng
recon-ng

# ==========================================
# Recon-ng Commands
# ==========================================

# ดู modules
marketplace search
marketplace search domain

# ติดตั้ง module
marketplace install recon/domains-hosts/hackertarget
marketplace install all

# ใช้งาน module
modules load recon/domains-hosts/hackertarget
info
options set SOURCE example.com
run

# Workspaces
workspaces create target1
workspaces list
workspaces load target1

# ==========================================
# Modules สำคัญ
# ==========================================

# DNS Enumeration
marketplace install recon/domains-hosts/google_site_web
marketplace install recon/domains-hosts/hackertarget
marketplace install recon/domains-hosts/brute_hosts

# Email Harvesting
marketplace install recon/domains-contacts/whois_pocs
marketplace install recon/domains-contacts/pgp_search

# IP Geolocation
marketplace install recon/hosts-hosts/resolve
marketplace install recon/hosts-hosts/freegeoip

# Port Scanning
marketplace install recon/hosts-ports/shodan_hostname

# ==========================================
# Scripted Recon
# ==========================================

# สร้าง script
cat > ~/recon_script.rc << 'EOF'
workspaces create example_com
options set NAMESERVER 8.8.8.8
modules load recon/domains-hosts/hackertarget
options set SOURCE example.com
run
modules load recon/hosts-hosts/resolve
run
show hosts
EOF

recon-ng -r ~/recon_script.rc

# Export results
show hosts
show contacts
save /tmp/recon_output.csv
```

---

## Step 50: Active Reconnaissance

### Web Directory Enumeration

```bash
# ==========================================
# Directory Brute Force
# ==========================================

# gobuster - เร็ว, parallel
sudo apt install gobuster

# Directory mode
gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
gobuster dir -u http://example.com -w wordlist.txt -t 50 -o output.txt
gobuster dir -u http://example.com -w wordlist.txt -k  # ignore SSL errors

# DNS mode
gobuster dns -d example.com -w /usr/share/wordlists/subdomains.txt
gobuster dns -d example.com -w wordlist.txt -t 50

# Vhost mode
gobuster vhost -u http://example.com -w wordlist.txt

# ==========================================
# ffuf - Fuzzing Tool (ยืดหยุ่นกว่า gobuster)
# ==========================================
sudo apt install ffuf

# Directory
ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# ระบุ extensions
ffuf -u http://example.com/FUZZ -w wordlist.txt -e .php,.html,.txt,.bak

# ค้นหา VHosts
ffuf -u http://example.com -H "Host: FUZZ.example.com" -w subdomains.txt

# Filter by size (remove false positives)
ffuf -u http://example.com/FUZZ -w wordlist.txt -fs 1234

# Filter by status code
ffuf -u http://example.com/FUZZ -w wordlist.txt -mc 200,301,302,403

# POST data fuzzing
ffuf -u http://example.com/login -X POST -d "user=FUZZ&pass=admin" -w users.txt

# ==========================================
# dirb - Classic Directory Scanner
# ==========================================
sudo apt install dirb

dirb http://example.com
dirb http://example.com /usr/share/wordlists/dirb/common.txt
dirb http://example.com /usr/share/wordlists/dirb/big.txt -X .php,.html
dirb http://example.com -a "Mozilla/5.0"  # custom user-agent

# ==========================================
# feroxbuster - Recursive Directory Scanner
# ==========================================
sudo apt install feroxbuster

feroxbuster -u http://example.com
feroxbuster -u http://example.com -w wordlist.txt -x php
feroxbuster -u http://example.com --depth 3  # ค้นหา 3 ชั้น

# ==========================================
# Wordlists สำหรับ Directory Bruteforce
# ==========================================

# SecLists (collection ที่ดีที่สุด)
sudo apt install seclists

# Wordlists ที่นิยมใช้:
ls /usr/share/seclists/Discovery/Web-Content/
# common.txt
# directory-list-2.3-big.txt
# directory-list-2.3-medium.txt
# directory-list-2.3-small.txt
# raft-large-directories.txt
# raft-medium-directories.txt
# quickhits.txt

ls /usr/share/wordlists/
# dirb/
# dirbuster/
# rockyou.txt
# metasploit/
```

### Web Crawling & Spidering

```bash
# ==========================================
# Web Crawling
# ==========================================

# wget recursive
wget -r -l 3 --no-parent http://example.com -P ./spider

# httrack
sudo apt install httrack
httrack http://example.com -O ./mirror

# scrapy (Python framework)
pip3 install scrapy
scrapy shell http://example.com

# katana - Modern web crawler
go install github.com/projectdiscovery/katana/cmd/katana@latest

katana -u http://example.com
katana -u http://example.com -d 3      # depth 3
katana -u http://example.com -jc       # JavaScript crawling
katana -u http://example.com -o urls.txt

# ==========================================
# Wayback Machine / Web Archives
# ==========================================

# waymore - Download all URLs from Wayback Machine
pip3 install waymore
waymore -i example.com -mode U        # URLs only
waymore -i example.com -mode S        # Screenshots

# waybackurls
go install github.com/tomnomnom/waybackurls@latest
waybackurls example.com | tee wayback.txt

# gau - Get All URLs
go install github.com/lc/gau/v2/cmd/gau@latest
gau example.com
echo "example.com" | gau

# ==========================================
# JavaScript Analysis
# ==========================================

# หา endpoints และ secrets จาก JavaScript files
# getJS
go install github.com/003random/getJS@latest

echo "http://example.com" | getJS

# LinkFinder
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
python3 linkfinder.py -i http://example.com -d -o cli

# JSParser
pip3 install jsbeautifier
```

---

## สรุป Part 05

ในบทนี้คุณได้เรียนรู้:

✅ **Step 41**: Penetration Testing Methodology  
✅ **Step 42**: Passive Recon - Google Dorking  
✅ **Step 43**: theHarvester  
✅ **Step 44**: Shodan  
✅ **Step 45**: Maltego  
✅ **Step 46**: DNS Enumeration ขั้นสูง  
✅ **Step 47**: Email Harvesting  
✅ **Step 48**: Technology Fingerprinting  
✅ **Step 49**: Recon-ng  
✅ **Step 50**: Active Recon - Web Directory Scanning  

## แบบฝึกหัด

1. ทำ Google Dorking หา exposed files ของ domain ที่ได้รับอนุญาต
2. ใช้ theHarvester เก็บ emails จาก domain
3. ทำ subdomain enumeration ด้วย amass และ subfinder
4. สร้าง Recon Script ที่รวมทุก technique
5. ทำ directory bruteforce กับ DVWA ใน lab

## ถัดไป: Part 06 - Nmap Scanning ขั้นสูง

---

*Part 05 | Steps 41-50 | ระดับ: กลาง*
