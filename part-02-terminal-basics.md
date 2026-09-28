# Part 02: การตั้งค่าระบบและ Terminal พื้นฐาน (Steps 11-20)

## บทนำ

Terminal คือหัวใจของการทำงานบน Linux และเป็นเครื่องมือหลักของทุก Penetration Tester ในบทนี้คุณจะได้เรียนรู้การใช้งาน Terminal อย่างมีประสิทธิภาพ การตั้งค่า Shell และเครื่องมือที่จำเป็นสำหรับงาน Security

---

## Step 11: ทำความรู้จัก Terminal และ Shell

### Terminal Emulators ใน Parrot OS

```bash
# Parrot OS มาพร้อม Terminal หลายตัว:

1. MATE Terminal (Default ใน MATE Desktop)
   - เปิดด้วย: Ctrl+Alt+T

2. Tilix (แนะนำสำหรับ Security)
   sudo apt install tilix
   
3. Terminator (หลาย panes)
   sudo apt install terminator
   
4. Kitty (ทันสมัย รองรับ GPU)
   sudo apt install kitty
   
5. Alacritty (เร็วมาก)
   sudo apt install alacritty

# ติดตั้ง Tilix ซึ่งเป็นแนะนำสำหรับงาน Security
sudo apt install tilix
```

### ทำความเข้าใจ Shell

```bash
# Shell คือโปรแกรมที่รับคำสั่งจากผู้ใช้และส่งให้ Kernel

# ดู Shell ที่ใช้อยู่ปัจจุบัน
echo $SHELL

# ดูรายการ Shell ที่มีในระบบ
cat /etc/shells

# Shell ที่นิยมใช้:
# /bin/bash  - Bourne Again Shell (Default)
# /bin/zsh   - Z Shell (แนะนำสำหรับ Security)
# /bin/fish  - Friendly Interactive Shell

# เปลี่ยน Default Shell เป็น Zsh
chsh -s /bin/zsh

# รีสตาร์ท Terminal เพื่อให้มีผล
```

### โครงสร้าง Command Line

```bash
# รูปแบบทั่วไปของคำสั่ง:
command [options] [arguments]

# ตัวอย่าง:
ls -la /home/user
#  |   |    |
#  |   |    └── Argument (directory path)
#  |   └── Options (-l = long format, -a = show hidden)
#  └── Command

# อ่านคู่มือการใช้งาน
man ls          # Manual page
ls --help       # Help text
info ls         # Info page (ละเอียดกว่า)

# เคล็ดลับ:
# Tab = Auto-complete
# ↑↓  = Command history
# Ctrl+C = ยกเลิก
# Ctrl+Z = หยุดชั่วคราว (background)
# Ctrl+D = ออกจาก Shell
# Ctrl+L = Clear screen (= clear command)
# Ctrl+A = ไปต้นบรรทัด
# Ctrl+E = ไปปลายบรรทัด
# Ctrl+U = ลบทั้งบรรทัด
# Ctrl+K = ลบจากตำแหน่งถึงปลายบรรทัด
# Ctrl+R = ค้นหา command history
```

---

## Step 12: การตั้งค่า Zsh + Oh-My-Zsh

### ติดตั้ง Zsh

```bash
# ติดตั้ง Zsh
sudo apt install -y zsh

# ตรวจสอบเวอร์ชัน
zsh --version

# เปลี่ยนเป็น Default Shell
chsh -s $(which zsh)

# ออกจาก Terminal แล้วเปิดใหม่
# หรือรัน:
exec zsh
```

### ติดตั้ง Oh-My-Zsh

```bash
# Oh-My-Zsh คือ Framework สำหรับจัดการ Zsh configuration

# ติดตั้งผ่าน curl
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

# หรือผ่าน wget
sh -c "$(wget -O- https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

# ถ้าต้องการติดตั้งโดยไม่ต้องยืนยัน
RUNZSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
```

### ติดตั้ง Plugins ที่มีประโยชน์

```bash
# Plugin 1: zsh-autosuggestions (แนะนำคำสั่งจาก history)
git clone https://github.com/zsh-users/zsh-autosuggestions \
    ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions

# Plugin 2: zsh-syntax-highlighting (highlight syntax)
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git \
    ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting

# Plugin 3: zsh-completions (auto-complete เพิ่มเติม)
git clone https://github.com/zsh-users/zsh-completions \
    ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-completions

# แก้ไขไฟล์ ~/.zshrc
nano ~/.zshrc

# หาบรรทัด plugins=(git) แล้วแก้เป็น:
plugins=(
    git
    zsh-autosuggestions
    zsh-syntax-highlighting
    zsh-completions
    sudo
    history
    colored-man-pages
    extract
    z
    docker
    python
)

# บันทึกและ reload
source ~/.zshrc
```

### ติดตั้ง Powerlevel10k Theme

```bash
# Powerlevel10k คือ Theme ที่สวยงามและให้ข้อมูลมาก

# ติดตั้ง Nerd Font (จำเป็นสำหรับ icons)
# ดาวน์โหลด MesloLGS NF จาก:
# https://github.com/romkatv/powerlevel10k#meslo-nerd-font-patched-for-powerlevel10k

# ติดตั้ง Theme
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git \
    ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k

# แก้ไข ~/.zshrc
# หาบรรทัด ZSH_THEME และแก้เป็น:
ZSH_THEME="powerlevel10k/powerlevel10k"

# reload และตั้งค่า
source ~/.zshrc
# จะมี wizard ให้ตั้งค่า
# ถ้าไม่มีรัน:
p10k configure
```

---

## Step 13: การตั้งค่า .bashrc / .zshrc

### Aliases ที่มีประโยชน์สำหรับ Security

```bash
# เพิ่มลงใน ~/.bashrc หรือ ~/.zshrc

# ==========================================
# Security Aliases
# ==========================================

# Network Scanning
alias nmap-quick='nmap -T4 -F'
alias nmap-full='nmap -T4 -A -v'
alias nmap-udp='nmap -sU -T4'
alias nmap-vuln='nmap --script vuln'
alias nmap-all='nmap -p- -T4'

# Web Scanning
alias nikto-scan='nikto -h'
alias gobuster-dir='gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
alias ffuf-scan='ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'

# Network Tools
alias myip='curl -s ifconfig.me'
alias myips='ip -br a'
alias ports='netstat -tulanp'
alias listening='ss -tlnp'

# File Management
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias mkdir='mkdir -pv'

# Safety Aliases
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'

# Parrot/Kali Specific
alias update='sudo apt update && sudo apt upgrade -y'
alias install='sudo apt install'
alias search='apt search'

# Python
alias python='python3'
alias pip='pip3'
alias venv='python3 -m venv'

# HTTP Servers
alias httpserver='python3 -m http.server'
alias phpserver='php -S 0.0.0.0:8080'

# Grep with color
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'

# VPN
alias vpnon='sudo openvpn --config ~/vpn/config.ovpn &'
alias vpnoff='sudo pkill openvpn'

# ==========================================
# Functions
# ==========================================

# สร้างโฟลเดอร์และเข้าไปเลย
mkcd() {
    mkdir -p "$1" && cd "$1"
}

# ค้นหาไฟล์และข้อความ
search_file() {
    grep -r "$1" . 2>/dev/null
}

# ดู IP ทุกอย่าง
myallip() {
    echo "=== Local IPs ==="
    ip -br a
    echo ""
    echo "=== Public IP ==="
    curl -s ifconfig.me
    echo ""
}

# Cheatsheet สำหรับเครื่องมือ
cheat() {
    curl -s "https://cheat.sh/$1"
}

# Base64 encode/decode
b64enc() { echo -n "$1" | base64; }
b64dec() { echo -n "$1" | base64 -d; }

# URL encode/decode
urlencode() { python3 -c "import urllib.parse; print(urllib.parse.quote('$1'))"; }
urldecode() { python3 -c "import urllib.parse; print(urllib.parse.unquote('$1'))"; }

# Apply changes
source ~/.zshrc
```

### Environment Variables สำคัญ

```bash
# เพิ่มลงใน ~/.zshrc หรือ ~/.bashrc

# ==========================================
# PATH Configuration
# ==========================================
export PATH="$HOME/.local/bin:$PATH"
export PATH="$HOME/tools:$PATH"
export PATH="/usr/local/bin:$PATH"

# ==========================================
# Security Tool Paths
# ==========================================
export WORDLISTS="/usr/share/wordlists"
export TOOLS="$HOME/tools"
export SCRIPTS="$HOME/scripts"

# ==========================================
# Metasploit
# ==========================================
export MSF_DATABASE_CONFIG=/usr/share/metasploit-framework/config/database.yml

# ==========================================
# Python
# ==========================================
export PYTHONPATH="$HOME/.local/lib/python3/site-packages:$PYTHONPATH"
export VIRTUAL_ENV_DISABLE_PROMPT=1

# ==========================================
# Terminal
# ==========================================
export TERM=xterm-256color
export EDITOR=vim
export VISUAL=vim
export PAGER=less

# สร้างโฟลเดอร์สำหรับงาน Security
mkdir -p ~/tools ~/scripts ~/wordlists ~/targets ~/reports
```

---

## Step 14: การใช้งาน vim/nano สำหรับ Security

### ทำความรู้จัก vim

```bash
# vim คือ Text Editor ทรงพลังที่ต้องเรียนรู้สำหรับ Security

# เปิดไฟล์
vim filename.txt

# vim มี 3 modes:
# 1. Normal Mode (default)  - สำหรับ navigate
# 2. Insert Mode (i)         - สำหรับพิมพ์
# 3. Visual Mode (v)         - สำหรับ select

# Normal Mode shortcuts:
h, j, k, l    = เคลื่อนที่ (←↓↑→)
w              = ไปคำถัดไป
b              = ไปคำก่อนหน้า
0              = ต้นบรรทัด
$              = ปลายบรรทัด
gg             = บรรทัดแรก
G              = บรรทัดสุดท้าย
/pattern       = ค้นหา
n              = ค้นหาถัดไป
N              = ค้นหาก่อนหน้า
:%s/old/new/g  = Replace all
dd             = ลบทั้งบรรทัด
yy             = copy บรรทัด
p              = วาง
u              = Undo
Ctrl+R         = Redo

# Enter Insert Mode:
i    = insert ก่อน cursor
a    = append หลัง cursor
o    = บรรทัดใหม่ด้านล่าง
O    = บรรทัดใหม่ด้านบน

# บันทึกและออก (Normal Mode):
:w   = บันทึก
:q   = ออก (ถ้าไม่มีการเปลี่ยนแปลง)
:wq  = บันทึกแล้วออก
:q!  = ออกโดยไม่บันทึก
:wq! = บันทึกแล้วออก (force)
```

### ตั้งค่า vim สำหรับ Security

```bash
# สร้างไฟล์ ~/.vimrc
cat > ~/.vimrc << 'EOF'
" ==========================================
" vim configuration for Security
" ==========================================

" พื้นฐาน
set nocompatible
set encoding=utf-8
set fileencoding=utf-8

" แสดงเลขบรรทัด
set number
set relativenumber

" การค้นหา
set hlsearch          " highlight ผลการค้นหา
set incsearch         " ค้นหาขณะพิมพ์
set ignorecase        " ไม่สนตัวพิมพ์เล็กใหญ่
set smartcase         " สนถ้ามีตัวพิมพ์ใหญ่

" Indentation
set autoindent
set smartindent
set tabstop=4
set shiftwidth=4
set expandtab

" Interface
set cursorline        " highlight บรรทัดปัจจุบัน
set showmatch         " highlight วงเล็บคู่
set ruler
set showcmd
set laststatus=2

" Color scheme
syntax on
colorscheme desert

" Line wrap
set wrap
set linebreak

" Clipboard
set clipboard=unnamedplus

" Backup
set nobackup
set noswapfile

" ==========================================
" Key Mappings
" ==========================================
let mapleader = ","

" บันทึกด้วย Ctrl+S
nnoremap <C-s> :w<CR>
inoremap <C-s> <Esc>:w<CR>

" ออกด้วย Ctrl+Q
nnoremap <C-q> :q<CR>

" Clear search highlight
nnoremap <leader>h :nohlsearch<CR>

" ==========================================
" Python-specific
" ==========================================
autocmd FileType python set tabstop=4 shiftwidth=4 expandtab

EOF
```

### การใช้ nano (ง่ายกว่า vim)

```bash
# nano ง่ายกว่า vim เหมาะสำหรับผู้เริ่มต้น

# เปิดไฟล์
nano filename.txt

# Shortcuts (^ = Ctrl, M = Alt):
Ctrl+X     = ออก
Ctrl+O     = บันทึก
Ctrl+K     = ตัดบรรทัด (Cut)
Ctrl+U     = วางบรรทัด (Paste)
Ctrl+W     = ค้นหา
Ctrl+\     = ค้นหาและแทนที่
Ctrl+G     = Help
Ctrl+A     = ต้นบรรทัด
Ctrl+E     = ปลายบรรทัด
Alt+A      = เริ่ม Select
Ctrl+^     = เลือกทั้งหมด
Ctrl+C     = แสดงตำแหน่ง cursor
Alt+U      = Undo
Alt+E      = Redo
```

---

## Step 15: การจัดการไฟล์และโฟลเดอร์

### คำสั่งพื้นฐาน

```bash
# ==========================================
# Navigation
# ==========================================

# แสดงโฟลเดอร์ปัจจุบัน
pwd

# รายการไฟล์
ls                  # รายการพื้นฐาน
ls -l               # รายละเอียด
ls -la              # รวมไฟล์ hidden
ls -lh              # แสดงขนาดอ่านง่าย
ls -lt              # เรียงตามเวลา
ls -lS              # เรียงตามขนาด
ls -R               # recursive

# เปลี่ยน Directory
cd /path/to/dir     # ไป absolute path
cd ..               # ย้อนกลับ 1 ระดับ
cd ~                # ไป home directory
cd -                # ไป directory ก่อนหน้า
cd /                # ไป root

# ==========================================
# File Operations
# ==========================================

# สร้างไฟล์
touch newfile.txt
touch file{1,2,3}.txt    # สร้างหลายไฟล์

# สร้างโฟลเดอร์
mkdir myfolder
mkdir -p path/to/deep/folder    # สร้าง nested

# คัดลอก
cp file1 file2              # copy ไฟล์
cp -r folder1 folder2       # copy โฟลเดอร์
cp -rv folder1 folder2      # แสดงผล verbose

# ย้าย/เปลี่ยนชื่อ
mv file1 file2              # เปลี่ยนชื่อ
mv file1 /new/path/         # ย้าย
mv file1 /new/path/file2    # ย้ายและเปลี่ยนชื่อ

# ลบ
rm file1                    # ลบไฟล์
rm -f file1                 # force ลบ
rm -r folder                # ลบโฟลเดอร์
rm -rf folder               # force ลบโฟลเดอร์ (อันตราย!)
rm -i file                  # ถามก่อนลบ

# ==========================================
# ดูเนื้อหาไฟล์
# ==========================================

cat file.txt                # แสดงทั้งไฟล์
less file.txt               # แสดงแบบ page (q ออก)
more file.txt               # แบบ page เก่า
head file.txt               # แสดง 10 บรรทัดแรก
head -n 20 file.txt         # แสดง 20 บรรทัดแรก
tail file.txt               # แสดง 10 บรรทัดสุดท้าย
tail -f file.txt            # ดูไฟล์แบบ real-time (log)
tail -n 50 file.txt         # แสดง 50 บรรทัดสุดท้าย

# ==========================================
# ค้นหาไฟล์
# ==========================================

# find
find / -name "*.conf" 2>/dev/null       # หาไฟล์ .conf
find / -name "passwd" 2>/dev/null       # หาไฟล์ passwd
find /home -user username               # หาไฟล์ของ user
find / -perm -4000 2>/dev/null          # หาไฟล์ SUID
find / -perm -2000 2>/dev/null          # หาไฟล์ SGID
find / -mtime -7 2>/dev/null            # แก้ใน 7 วัน
find /tmp -type f -name "*.php"         # หา .php ใน /tmp

# locate (เร็วกว่า find แต่ต้อง update database)
sudo updatedb
locate filename.txt

# which (หา path ของ command)
which nmap
which python3
```

### การจัดการ Permission

```bash
# ==========================================
# File Permissions
# ==========================================

# รูปแบบ permission: rwxrwxrwx
# r = read (4)
# w = write (2)  
# x = execute (1)
# - = ไม่มี permission (0)

# 3 groups: owner | group | others
# ตัวอย่าง: -rwxr-xr--
# owner: rwx (7) - อ่าน เขียน รัน
# group: r-x (5) - อ่าน รัน
# others: r-- (4) - อ่านอย่างเดียว

# ดู permission
ls -l file.txt
stat file.txt

# เปลี่ยน permission (chmod)
chmod 644 file.txt          # rw-r--r--
chmod 755 script.sh         # rwxr-xr-x
chmod 600 private_key       # rw-------
chmod +x script.sh          # เพิ่ม execute ให้ทุกคน
chmod -x script.sh          # ลบ execute
chmod u+x script.sh         # เพิ่ม execute แค่ owner
chmod o-r file.txt          # ลบ read จาก others
chmod -R 755 folder/        # recursive

# เปลี่ยน owner (chown)
sudo chown user file.txt
sudo chown user:group file.txt
sudo chown -R user:group folder/

# เปลี่ยน group (chgrp)
sudo chgrp group file.txt

# SUID, SGID, Sticky Bit (สำคัญสำหรับ Privilege Escalation)
chmod u+s file          # SUID - รันด้วย permission ของ owner
chmod g+s file          # SGID
chmod +t directory/     # Sticky bit (ป้องกันการลบของคนอื่น)
chmod 4755 file         # SUID + 755
chmod 2755 file         # SGID + 755
chmod 1777 directory    # Sticky + 777 (เช่น /tmp)

# ค้นหาไฟล์ SUID (สำคัญมากสำหรับ Privilege Escalation)
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
```

---

## Step 16: Piping, Redirection และ Text Processing

### I/O Redirection

```bash
# ==========================================
# Standard Streams
# ==========================================
# stdin  (0) = input  (keyboard)
# stdout (1) = output (screen)
# stderr (2) = errors (screen)

# Redirect stdout
command > file.txt       # เขียนทับ
command >> file.txt      # ต่อท้าย

# Redirect stderr
command 2> error.log     # เขียน error ลงไฟล์
command 2>> error.log    # ต่อท้าย

# Redirect ทั้ง stdout และ stderr
command > output.txt 2>&1
command &> output.txt    # shorthand

# Discard output (throw away)
command > /dev/null
command 2> /dev/null
command &> /dev/null

# Redirect stdin
command < input.txt

# Here Document
cat << EOF
line 1
line 2
line 3
EOF

# Here String
command <<< "input string"
```

### Pipes

```bash
# ==========================================
# Pipes (|) ส่ง output ของคำสั่งหนึ่งไปยังอีกคำสั่ง
# ==========================================

# พื้นฐาน
ls -la | less
cat /etc/passwd | grep root
ps aux | grep apache

# หลายๆ pipe
cat /etc/passwd | cut -d: -f1 | sort | uniq

# tee - แสดงผลและบันทึกพร้อมกัน
nmap -sV 192.168.1.1 | tee nmap_output.txt

# xargs - ส่ง output เป็น argument
cat targets.txt | xargs nmap -sn
find . -name "*.txt" | xargs wc -l
```

### Text Processing Tools

```bash
# ==========================================
# grep - ค้นหาข้อความ
# ==========================================
grep "pattern" file.txt          # ค้นหาพื้นฐาน
grep -i "pattern" file.txt       # ไม่สนตัวพิมพ์
grep -r "pattern" directory/     # recursive
grep -v "pattern" file.txt       # inverse (บรรทัดที่ไม่มี pattern)
grep -n "pattern" file.txt       # แสดงเลขบรรทัด
grep -c "pattern" file.txt       # นับจำนวนบรรทัด
grep -l "pattern" *.txt          # แสดงแค่ชื่อไฟล์
grep -A 2 "pattern" file.txt     # แสดง 2 บรรทัดหลัง match
grep -B 2 "pattern" file.txt     # แสดง 2 บรรทัดก่อน match
grep -E "pattern1|pattern2"      # Extended regex
grep -P "regex"                  # Perl regex

# ตัวอย่างสำหรับ Security:
grep -r "password" /var/www/ 2>/dev/null
grep -r "api_key\|secret\|token" . 2>/dev/null
cat /etc/passwd | grep -v "nologin\|false"

# ==========================================
# awk - text processing
# ==========================================
awk '{print $1}' file.txt        # แสดง column 1
awk '{print $1, $3}' file.txt    # แสดง column 1 และ 3
awk -F: '{print $1}' /etc/passwd # ใช้ : เป็น delimiter
awk '{print NR, $0}' file.txt    # เพิ่มเลขบรรทัด
awk 'NR==5' file.txt             # แสดงบรรทัดที่ 5
awk 'NR>=2 && NR<=5' file.txt    # บรรทัด 2-5
awk '{sum += $1} END {print sum}' # รวม column 1

# ==========================================
# sed - stream editor
# ==========================================
sed 's/old/new/' file.txt        # แทนที่ครั้งแรก
sed 's/old/new/g' file.txt       # แทนที่ทั้งหมด
sed 's/old/new/i' file.txt       # ไม่สนตัวพิมพ์
sed -n '5p' file.txt             # แสดงบรรทัด 5
sed -n '1,5p' file.txt           # แสดงบรรทัด 1-5
sed '/pattern/d' file.txt        # ลบบรรทัดที่มี pattern
sed -i 's/old/new/g' file.txt    # แก้ไขไฟล์โดยตรง

# ==========================================
# cut - ตัดส่วนของข้อความ
# ==========================================
cut -d: -f1 /etc/passwd          # ตัด field 1 โดยใช้ : เป็น delimiter
cut -d, -f2,4 file.csv           # ตัด field 2 และ 4 จาก CSV
cut -c1-5 file.txt               # ตัด character 1-5
cut -c-5 file.txt                # ตัด 5 characters แรก

# ==========================================
# sort และ uniq
# ==========================================
sort file.txt                    # เรียงลำดับ
sort -r file.txt                 # เรียงกลับ
sort -n file.txt                 # เรียงตามตัวเลข
sort -u file.txt                 # เรียงและลบซ้ำ
sort -t: -k3 /etc/passwd         # เรียงตาม field 3

uniq file.txt                    # ลบบรรทัดซ้ำต่อกัน
uniq -c file.txt                 # นับซ้ำ
uniq -d file.txt                 # แสดงแค่ที่ซ้ำ
uniq -u file.txt                 # แสดงแค่ที่ไม่ซ้ำ

# ==========================================
# wc - word count
# ==========================================
wc file.txt                      # lines words bytes
wc -l file.txt                   # นับบรรทัด
wc -w file.txt                   # นับคำ
wc -c file.txt                   # นับ bytes
wc -m file.txt                   # นับ characters
```

---

## Step 17: Process Management

### การดูและจัดการ Process

```bash
# ==========================================
# ดู Processes
# ==========================================

# ps - process status
ps                       # processes ของ user ปัจจุบัน
ps aux                   # ทุก processes พร้อมรายละเอียด
ps aux | grep nginx      # หา process ที่ต้องการ
ps -ef                   # full format
ps --forest              # แสดงเป็น tree
pstree                   # process tree

# top - real-time monitor
top
# Shortcuts ใน top:
# q = ออก
# k = kill process (ใส่ PID)
# r = renice (เปลี่ยน priority)
# 1 = แสดงทุก CPU
# M = เรียงตาม Memory
# P = เรียงตาม CPU

# htop (ดีกว่า top)
sudo apt install htop
htop

# ==========================================
# จัดการ Processes
# ==========================================

# kill
kill PID                 # ส่ง SIGTERM
kill -9 PID              # ส่ง SIGKILL (บังคับ)
kill -15 PID             # ส่ง SIGTERM (graceful)
killall process_name     # kill ทุก process ที่ชื่อ
pkill process_name       # kill ด้วยชื่อ
pkill -u username        # kill ทุก process ของ user

# Background/Foreground
command &                # รันใน background
jobs                     # ดู background jobs
fg                       # นำ job ล่าสุดมา foreground
fg %1                    # นำ job 1 มา foreground
bg                       # ส่ง job ไป background
Ctrl+Z                   # หยุดและส่ง background
nohup command &          # รันแม้ logout

# ==========================================
# Signals ที่สำคัญ
# ==========================================
# SIGTERM (15) - graceful shutdown
# SIGKILL (9)  - force kill
# SIGHUP (1)   - reload config
# SIGSTOP (19) - หยุดชั่วคราว
# SIGCONT (18) - ทำงานต่อ
# SIGINT (2)   - Ctrl+C

# ดูรายการ signals
kill -l
```

### Service Management

```bash
# ==========================================
# systemctl - จัดการ Services
# ==========================================

# ดู status
systemctl status apache2
systemctl status ssh
systemctl status --all

# Start/Stop/Restart
sudo systemctl start service_name
sudo systemctl stop service_name
sudo systemctl restart service_name
sudo systemctl reload service_name

# Enable/Disable (boot)
sudo systemctl enable service_name
sudo systemctl disable service_name

# ตรวจสอบว่า enable หรือไม่
systemctl is-enabled service_name
systemctl is-active service_name

# Services ที่สำคัญสำหรับ Security
sudo systemctl start ssh          # SSH Server
sudo systemctl start apache2      # Web Server
sudo systemctl start postgresql   # Database (Metasploit)
sudo systemctl start mysql        # MySQL

# ดูทุก services ที่รัน
systemctl list-units --type=service --state=active
```

---

## Step 18: Network Commands พื้นฐาน

### การตรวจสอบ Network

```bash
# ==========================================
# Interface และ IP
# ==========================================

# ดู network interfaces
ip a                     # IP addresses
ip addr show             # เหมือน ip a
ip link show             # Layer 2 info
ifconfig                 # แบบเก่า (ต้องติดตั้ง net-tools)

# ดู IP เฉพาะ interface
ip addr show eth0
ip addr show wlan0

# ==========================================
# Routing
# ==========================================
ip route                 # ดู routing table
ip route show            # เหมือน ip route
route -n                 # แบบเก่า
netstat -r               # routing table

# เพิ่ม/ลบ route
sudo ip route add 10.0.0.0/8 via 192.168.1.1
sudo ip route del 10.0.0.0/8

# ==========================================
# Connection
# ==========================================

# ดู connections ทั้งหมด
netstat -tulanp          # ทุก connections + process
ss -tulanp               # ใหม่กว่า netstat
ss -tlnp                 # เฉพาะ TCP listening
ss -ulnp                 # เฉพาะ UDP listening

# ทดสอบ connectivity
ping google.com
ping -c 4 8.8.8.8        # ping 4 ครั้ง
ping -i 0.5 192.168.1.1  # interval 0.5 วินาที

# traceroute
traceroute google.com
tracepath google.com     # ไม่ต้อง root

# DNS lookup
host google.com
nslookup google.com
dig google.com
dig google.com MX        # MX records
dig @8.8.8.8 google.com  # ใช้ DNS server เฉพาะ

# ==========================================
# Firewall
# ==========================================

# iptables
sudo iptables -L                 # ดูกฎ
sudo iptables -L -n --line-numbers   # แสดงเลขบรรทัด
sudo iptables -F                 # ล้างกฎทั้งหมด
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# ufw (ง่ายกว่า)
sudo ufw status
sudo ufw enable
sudo ufw disable
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 23/tcp
sudo ufw delete allow 22/tcp
```

---

## Step 19: การจัดการ User และ Permission

### User Management

```bash
# ==========================================
# User Commands
# ==========================================

# ดูข้อมูล user ปัจจุบัน
whoami
id
id username

# ดูรายการ users
cat /etc/passwd
awk -F: '$3 >= 1000' /etc/passwd     # users ทั่วไป (UID >= 1000)
getent passwd                         # ทุก users

# สร้าง user
sudo adduser newuser              # สร้างพร้อม home directory
sudo useradd -m -s /bin/bash newuser  # manual

# เปลี่ยน password
passwd                            # เปลี่ยน password ตัวเอง
sudo passwd username              # เปลี่ยน password ของ user อื่น

# ลบ user
sudo deluser username
sudo userdel -r username          # รวม home directory

# เพิ่ม user เข้า group
sudo usermod -aG sudo username
sudo usermod -aG docker username
sudo gpasswd -a username group

# ==========================================
# Groups
# ==========================================
groups                            # groups ของ user ปัจจุบัน
groups username                   # groups ของ user ที่ระบุ
cat /etc/group                    # ทุก groups
getent group sudo                 # ดู members ของ sudo group

# ==========================================
# sudo
# ==========================================
sudo command                      # รัน command ด้วย root
sudo -i                           # switch เป็น root shell
sudo -s                           # root shell (ยัง env เดิม)
sudo su -                         # switch เป็น root
sudo su - username                # switch เป็น user อื่น

# ดู sudo privileges
sudo -l                           # ดูว่า user ปัจจุบันมีสิทธิ์อะไร

# แก้ไข sudoers file (สำคัญ!)
sudo visudo

# ตัวอย่างใน /etc/sudoers:
# user_name ALL=(ALL:ALL) ALL          # ทุกคำสั่ง
# user_name ALL=(ALL) NOPASSWD: ALL    # ไม่ต้องใส่ password
# user_name ALL=(ALL) /bin/ls, /bin/cat # เฉพาะบาง command

# ==========================================
# ไฟล์สำคัญที่เกี่ยวกับ User
# ==========================================
/etc/passwd     # รายการ users (ไม่มี password แล้ว)
/etc/shadow     # password hashes (root อ่านได้)
/etc/group      # รายการ groups
/etc/sudoers    # sudo configuration
~/.ssh/         # SSH keys
```

---

## Step 20: Scripting พื้นฐาน

### Bash Script เบื้องต้น

```bash
#!/bin/bash
# Script แรก: hello_world.sh

echo "Hello, World!"
echo "Current user: $(whoami)"
echo "Current directory: $(pwd)"
echo "Date: $(date)"
```

```bash
# สร้างและรัน script
nano hello_world.sh
# วางเนื้อหาด้านบน

# ให้สิทธิ์รัน
chmod +x hello_world.sh

# รัน
./hello_world.sh
# หรือ
bash hello_world.sh
```

### Network Recon Script

```bash
#!/bin/bash
# network_recon.sh - Basic Network Reconnaissance

# สีสำหรับ output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

# ตรวจสอบ argument
if [ $# -eq 0 ]; then
    echo -e "${RED}Usage: $0 <target_ip_or_range>${NC}"
    echo "Example: $0 192.168.1.1"
    echo "Example: $0 192.168.1.0/24"
    exit 1
fi

TARGET=$1
OUTPUT_DIR="recon_$(date +%Y%m%d_%H%M%S)"

# สร้างโฟลเดอร์สำหรับ output
mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Network Recon Script                 ${NC}"
echo -e "${BLUE}  Target: $TARGET                      ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 1. Ping Sweep
echo -e "${YELLOW}[*] Running Ping Sweep...${NC}"
nmap -sn "$TARGET" -oN "$OUTPUT_DIR/ping_sweep.txt" 2>/dev/null
echo -e "${GREEN}[+] Ping sweep completed${NC}"

# 2. Port Scan (quick)
echo -e "${YELLOW}[*] Running Quick Port Scan...${NC}"
nmap -T4 -F "$TARGET" -oN "$OUTPUT_DIR/quick_scan.txt" 2>/dev/null
echo -e "${GREEN}[+] Quick scan completed${NC}"

# 3. Service Detection
echo -e "${YELLOW}[*] Running Service Detection...${NC}"
nmap -sV -T4 "$TARGET" -oN "$OUTPUT_DIR/service_scan.txt" 2>/dev/null
echo -e "${GREEN}[+] Service scan completed${NC}"

echo ""
echo -e "${GREEN}Results saved in: $OUTPUT_DIR/${NC}"
echo -e "${BLUE}========================================${NC}"
```

```bash
# ใช้งาน script
chmod +x network_recon.sh
./network_recon.sh 192.168.1.1
./network_recon.sh 192.168.1.0/24
```

---

## สรุป Part 02

ในบทนี้คุณได้เรียนรู้:

✅ **Step 11**: ทำความรู้จัก Terminal และ Shell  
✅ **Step 12**: การตั้งค่า Zsh + Oh-My-Zsh + Plugins  
✅ **Step 13**: การตั้งค่า .bashrc/.zshrc + Aliases + Functions  
✅ **Step 14**: การใช้งาน vim และ nano  
✅ **Step 15**: การจัดการไฟล์/โฟลเดอร์และ Permission  
✅ **Step 16**: Piping, Redirection และ Text Processing  
✅ **Step 17**: Process Management  
✅ **Step 18**: Network Commands พื้นฐาน  
✅ **Step 19**: User Management  
✅ **Step 20**: Bash Scripting เบื้องต้น  

## แบบฝึกหัด

1. ติดตั้ง Zsh + Oh-My-Zsh และ plugins ทั้งหมด
2. เพิ่ม aliases ที่มีประโยชน์ลงใน ~/.zshrc
3. ฝึกใช้คำสั่ง text processing: grep, awk, sed กับไฟล์ /etc/passwd
4. สร้าง bash script ที่แสดงข้อมูล network ของเครื่อง
5. ค้นหาไฟล์ที่มี SUID permission ในระบบ

## ถัดไป: Part 03 - Linux Command Line ขั้นสูงสำหรับ Pentester

---

*Part 02 | Steps 11-20 | ระดับ: พื้นฐาน*