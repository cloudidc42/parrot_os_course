# Part 01: แนะนำ Parrot OS และการติดตั้ง (Steps 1-10)

## บทนำ

Parrot OS (หรือ Parrot Security OS) คือระบบปฏิบัติการ Linux ที่ออกแบบมาเฉพาะสำหรับงาน Penetration Testing, Digital Forensics และ Privacy Protection พัฒนาโดย Frozenbox Team จากอิตาลี

ในบทนี้คุณจะได้เรียนรู้:
- ประวัติและที่มาของ Parrot OS
- ความแตกต่างระหว่าง Parrot OS กับ Kali Linux
- วิธีการติดตั้ง Parrot OS แบบต่างๆ
- การตั้งค่าเบื้องต้นหลังติดตั้ง

---

## Step 1: ทำความรู้จัก Parrot OS

### ประวัติความเป็นมา

Parrot OS เริ่มพัฒนาในปี 2013 โดย Lorenzo "Palinuro" Faletra และทีม Frozenbox เป้าหมายหลักคือสร้างระบบปฏิบัติการที่:
- มีน้ำหนักเบากว่า Kali Linux
- ใช้ทรัพยากรระบบน้อยกว่า
- มีเครื่องมือ Security ครบครัน
- เหมาะสำหรับทั้งการทำงานประจำวันและงาน Security

### เวอร์ชันต่างๆ ของ Parrot OS

```
Parrot OS มีให้เลือกหลายเวอร์ชัน:

1. Parrot Security Edition
   - สำหรับ Pentester และ Security Researcher
   - มีเครื่องมือครบครัน
   - ขนาด ISO: ~4.5GB

2. Parrot Home Edition  
   - สำหรับการใช้งานประจำวัน
   - เน้น Privacy มากกว่า
   - ขนาด ISO: ~2.5GB

3. Parrot HTB Edition (HackTheBox)
   - พัฒนาร่วมกับ HackTheBox
   - เครื่องมือสำหรับ CTF โดยเฉพาะ

4. Parrot OVA (VirtualBox/VMware)
   - สำหรับใช้งานบน Virtual Machine
   - ติดตั้งง่ายและเร็วกว่า
```

### เปรียบเทียบ Parrot OS vs Kali Linux

| คุณสมบัติ | Parrot OS | Kali Linux |
|-----------|-----------|------------|
| RAM ขั้นต่ำ | 512MB | 2GB |
| พื้นที่ขั้นต่ำ | 16GB | 20GB |
| Desktop | MATE/KDE | XFCE/GNOME |
| เหมาะกับ | ผู้ใช้งานทั่วไป + Security | Security โดยเฉพาะ |
| Privacy Tools | มากกว่า | น้อยกว่า |
| Anonymity | AnonSurf built-in | ต้องติดตั้งเพิ่ม |
| ความเร็ว Boot | เร็วกว่า | ช้ากว่าเล็กน้อย |

---

## Step 2: ข้อกำหนดของระบบ (System Requirements)

### ข้อกำหนดขั้นต่ำ (Minimum)

```
CPU:     Intel/AMD x86_64 (64-bit)
RAM:     512MB (แนะนำ 2GB+)
Storage: 16GB
GPU:     รองรับ 800x600 resolution
```

### ข้อกำหนดแนะนำ (Recommended)

```
CPU:     Intel Core i5/i7 หรือ AMD Ryzen 5/7 (4+ cores)
RAM:     8GB-16GB
Storage: 50GB+ SSD
GPU:     1GB+ VRAM
Network: Wireless Card ที่รองรับ Monitor Mode
```

### ข้อกำหนดสำหรับ Virtual Machine

```
Host RAM:     16GB+ (เผื่อให้ VM ใช้ 4-8GB)
Host CPU:     4+ cores (เผื่อให้ VM ใช้ 2-4 cores)
VM Storage:   40GB+ (Dynamic Allocation)
VM Network:   NAT + Host-Only Adapter
```

---

## Step 3: การดาวน์โหลด Parrot OS

### วิธีดาวน์โหลดอย่างถูกต้อง

```bash
# ขั้นตอนที่ 1: ไปที่เว็บไซต์ทางการ
# https://parrotsec.org/download/

# ขั้นตอนที่ 2: เลือกเวอร์ชันที่ต้องการ
# สำหรับหลักสูตรนี้เลือก: Parrot Security Edition

# ขั้นตอนที่ 3: ตรวจสอบ checksum หลังดาวน์โหลด

# Linux/Mac:
sha256sum parrot-security-6.x-amd64.iso

# Windows (PowerShell):
Get-FileHash parrot-security-6.x-amd64.iso -Algorithm SHA256

# เปรียบเทียบกับค่าบนเว็บไซต์ทางการ
```

### การดาวน์โหลดผ่าน Torrent (เร็วกว่า)

```bash
# ใช้ Torrent Client เช่น qBittorrent
# ดาวน์โหลด .torrent file จาก parrotsec.org
# หรือใช้ Magnet Link จากเว็บไซต์ทางการ

# ตรวจสอบ checksum เช่นเดิม
```

---

## Step 4: การสร้าง Bootable USB Drive

### วิธีที่ 1: ใช้ Rufus (Windows)

```
1. ดาวน์โหลด Rufus จาก rufus.ie
2. เปิด Rufus ด้วยสิทธิ์ Administrator
3. เลือก USB Drive (ขนาด 8GB+)
4. เลือกไฟล์ ISO ที่ดาวน์โหลด
5. เลือก Partition Scheme:
   - GPT สำหรับ UEFI
   - MBR สำหรับ Legacy BIOS
6. คลิก START และรอจนเสร็จ
```

### วิธีที่ 2: ใช้ balenaEtcher (Windows/Mac/Linux)

```
1. ดาวน์โหลด balenaEtcher จาก etcher.balena.io
2. เปิดโปรแกรม
3. เลือก "Flash from file" แล้วเลือกไฟล์ ISO
4. เลือก USB Drive
5. คลิก "Flash!" และรอจนเสร็จ
```

### วิธีที่ 3: ใช้ dd command (Linux/Mac)

```bash
# ระวัง! คำสั่งนี้อันตราย ถ้าเลือก device ผิด
# ข้อมูลใน device นั้นจะถูกลบทั้งหมด

# ดูรายการ device ก่อน
lsblk

# หรือ
fdisk -l

# สมมติว่า USB อยู่ที่ /dev/sdb
sudo dd if=parrot-security-6.x-amd64.iso of=/dev/sdb bs=4M status=progress sync

# รอจนเสร็จ (อาจใช้เวลา 10-20 นาที)
sync
```

---

## Step 5: การติดตั้ง Parrot OS บน Real Machine

### การตั้งค่า BIOS/UEFI

```
1. รีสตาร์ทคอมพิวเตอร์
2. กดปุ่ม Boot Menu:
   - ASUS: F8 หรือ ESC
   - HP: F9
   - Dell: F12
   - Lenovo: F12 หรือ Enter > F12
   - Acer: F12

3. เลือก Boot จาก USB Drive

4. หรือเข้า BIOS Settings:
   - ASUS: F2 หรือ DEL
   - HP: F10
   - Dell: F2
   - Lenovo: F1 หรือ F2
   - Acer: F2 หรือ DEL

5. เปิดใช้งาน:
   - UEFI Mode (แนะนำ) หรือ Legacy Mode
   - Secure Boot: DISABLE (สำคัญมาก!)
   - VT-x/AMD-V สำหรับ Virtualization
```

### ขั้นตอนการติดตั้ง

```
1. Boot จาก USB แล้วเลือก "Install" หรือ "Live System"
   - ถ้าต้องการทดลองก่อนเลือก "Try" หรือ "Live"
   - ถ้าพร้อมติดตั้งเลือก "Install"

2. เลือกภาษา:
   - Language: English (แนะนำสำหรับ Security)
   - Location: Thailand
   - Keyboard: Thai หรือ English

3. เลือก Partition:
   
   แบบ A - Full Disk (สำหรับผู้เริ่มต้น):
   - Erase disk and install Parrot OS
   - เลือก drive ที่ต้องการ
   - คลิก Next
   
   แบบ B - Dual Boot กับ Windows:
   - เลือก "Install alongside Windows"
   - กำหนดขนาด Partition สำหรับ Parrot OS (แนะนำ 50GB+)
   
   แบบ C - Manual Partition (ขั้นสูง):
   / (root):    30GB+ ext4
   /home:       Remaining ext4  
   /boot/efi:   512MB FAT32 (UEFI เท่านั้น)
   swap:        RAM x 1.5 (หรือ 8GB)

4. สร้างบัญชีผู้ใช้:
   - Full Name: ใส่ชื่อจริง
   - Username: ชื่อที่ใช้ login (ตัวเล็ก ไม่มีช่องว่าง)
   - Password: รหัสผ่านที่แข็งแกร่ง
   - ✓ Require password to log in

5. สรุปและยืนยัน:
   - ตรวจสอบการตั้งค่าทั้งหมด
   - คลิก Install

6. รอการติดตั้ง (15-30 นาที):
   - ระบบจะ copy files
   - ตั้งค่า bootloader
   - สร้าง user

7. รีสตาร์ทและถอด USB
```

---

## Step 6: การติดตั้ง Parrot OS บน VirtualBox

### ติดตั้ง VirtualBox

```bash
# Windows: ดาวน์โหลดจาก virtualbox.org

# Ubuntu/Debian:
sudo apt update
sudo apt install virtualbox virtualbox-ext-pack

# Fedora:
sudo dnf install VirtualBox

# macOS:
# ดาวน์โหลดจาก virtualbox.org หรือใช้ Homebrew:
brew install --cask virtualbox
```

### สร้าง Virtual Machine

```
1. เปิด VirtualBox
2. คลิก "New"

3. ตั้งค่าพื้นฐาน:
   Name:         Parrot OS Security
   Type:         Linux
   Version:      Debian (64-bit)
   
4. ตั้งค่า Memory:
   RAM:          4096MB (แนะนำ 8192MB)
   
5. สร้าง Virtual Hard Disk:
   Type:         VDI (VirtualBox Disk Image)
   Storage:      Dynamically allocated
   Size:         50GB (แนะนำ 80GB)

6. ตั้งค่า Network:
   Adapter 1:    NAT (สำหรับเชื่อมต่ออินเทอร์เน็ต)
   Adapter 2:    Host-Only Adapter (สำหรับทดสอบ)

7. ตั้งค่า Display:
   Video Memory: 128MB
   ✓ Enable 3D Acceleration

8. ตั้งค่า Storage:
   - คลิกที่ Optical Drive
   - เลือกไฟล์ ISO ที่ดาวน์โหลด

9. เปิด VM และทำการติดตั้งตามขั้นตอน Step 5
```

### ติดตั้ง VirtualBox Guest Additions

```bash
# หลังจากติดตั้ง Parrot OS ใน VM เสร็จแล้ว
# เปิด Terminal ใน Parrot OS

# อัพเดทระบบก่อน
sudo apt update && sudo apt upgrade -y

# ติดตั้ง dependencies
sudo apt install -y build-essential dkms linux-headers-$(uname -r)

# ใน VirtualBox Menu: Devices > Insert Guest Additions CD Image

# Mount CD (ถ้าไม่ mount อัตโนมัติ)
sudo mount /dev/cdrom /mnt/cdrom

# รัน script
cd /mnt/cdrom
sudo bash VBoxLinuxAdditions.run

# รีบูต
sudo reboot
```

---

## Step 7: การติดตั้ง Parrot OS บน VMware

### ใช้ Parrot OVA สำหรับ VMware (ง่ายที่สุด)

```
1. ดาวน์โหลด Parrot OVA จาก parrotsec.org/download/
2. เปิด VMware Workstation/Fusion
3. File > Open > เลือกไฟล์ .ova
4. ตั้งชื่อ VM
5. คลิก Import
6. เสร็จสิ้น! ไม่ต้องติดตั้งใหม่
```

### สร้าง VM ใหม่บน VMware

```
1. เปิด VMware Workstation
2. File > New Virtual Machine > Custom

3. เลือก Hardware Compatibility:
   - เลือก version ล่าสุด

4. เลือก ISO:
   - "Installer disc image file (iso)"
   - Browse เลือกไฟล์ ISO

5. Guest OS:
   - Linux
   - Debian 11.x 64-bit

6. ชื่อและที่บันทึก:
   - Name: Parrot OS Security
   - Location: เลือกที่ต้องการ

7. Processors:
   - Number of processors: 1
   - Number of cores: 4

8. Memory:
   - 4096MB (แนะนำ 8192MB)

9. Network Type:
   - NAT

10. Disk:
    - Create a new virtual disk
    - SCSI
    - 50GB
    - Store as a single file

11. Finish และทำการติดตั้ง
```

### ติดตั้ง VMware Tools บน Parrot OS

```bash
# ใน VMware Menu: VM > Install VMware Tools

# Terminal ใน Parrot OS:
sudo apt update

# ติดตั้ง open-vm-tools (แนะนำ)
sudo apt install -y open-vm-tools open-vm-tools-desktop

# Enable service
sudo systemctl enable vmtoolsd
sudo systemctl start vmtoolsd

# รีบูต
sudo reboot
```

---

## Step 8: การตั้งค่าแรกหลังติดตั้ง

### อัพเดทระบบ

```bash
# อัพเดท package list
sudo apt update

# อัพเดท packages ทั้งหมด
sudo apt upgrade -y

# อัพเดท distribution (ถ้ามี)
sudo apt dist-upgrade -y

# ลบ packages ที่ไม่ใช้แล้ว
sudo apt autoremove -y
sudo apt autoclean

# รีบูต
sudo reboot
```

### ตั้งค่าภาษาไทย (Optional)

```bash
# ติดตั้ง Thai fonts
sudo apt install -y fonts-thai-tlwg fonts-noto-cjk

# ติดตั้ง Thai input method
sudo apt install -y ibus ibus-table-thai

# ตั้งค่า IBus
ibus-setup

# เพิ่มใน ~/.bashrc หรือ ~/.profile:
export GTK_IM_MODULE=ibus
export QT_IM_MODULE=ibus
export XMODIFIERS=@im=ibus
```

### ตั้งค่า Timezone

```bash
# ตรวจสอบ timezone ปัจจุบัน
timedatectl

# ตั้งค่าเป็น Bangkok
sudo timedatectl set-timezone Asia/Bangkok

# ตรวจสอบอีกครั้ง
timedatectl
```

---

## Step 9: การจัดการ Repository และ Package Manager

### ทำความเข้าใจ APT Package Manager

```bash
# apt คือ Advanced Package Tool ของ Debian/Ubuntu

# คำสั่งพื้นฐาน:

# อัพเดท package list จาก repository
sudo apt update

# อัพเกรด packages ที่ติดตั้ง
sudo apt upgrade

# ติดตั้ง package
sudo apt install <package-name>

# ลบ package
sudo apt remove <package-name>

# ลบ package พร้อม config files
sudo apt purge <package-name>

# ค้นหา package
apt search <keyword>

# ดูข้อมูล package
apt show <package-name>

# ดูรายการ packages ที่ติดตั้ง
apt list --installed

# ลบ packages ที่ไม่จำเป็น
sudo apt autoremove
```

---

## Step 10: การสำรองข้อมูลและการจัดการ Snapshot

### การสร้าง Snapshot ใน VirtualBox

```
# หลักการ: สร้าง Snapshot ก่อนทดลองสิ่งใหม่ๆ

1. ปิด VM หรือหยุด VM (Pause/Save State)
2. Machine > Take Snapshot
3. ตั้งชื่อ: เช่น "Clean Install", "After Tools Install"
4. เพิ่มคำอธิบาย
5. คลิก OK

# การ Restore Snapshot:
1. Machine > Restore Snapshot
2. เลือก Snapshot ที่ต้องการ
3. คลิก Restore
```

### การสำรองข้อมูลสำคัญ

```bash
# สร้างโฟลเดอร์สำรอง
mkdir -p ~/backups

# สำรอง home directory
tar -czf ~/backups/home_backup_$(date +%Y%m%d).tar.gz \
    --exclude='~/backups' \
    ~/

# สำรองไฟล์ config สำคัญ
tar -czf ~/backups/configs_$(date +%Y%m%d).tar.gz \
    ~/.bashrc \
    ~/.zshrc \
    ~/.ssh/ \
    ~/.config/

# ตรวจสอบไฟล์ backup
tar -tzvf ~/backups/home_backup_$(date +%Y%m%d).tar.gz | head -20
```

---

## สรุป Part 01

ในบทนี้คุณได้เรียนรู้:

✅ **Step 1**: ทำความรู้จัก Parrot OS และเปรียบเทียบกับ Kali Linux  
✅ **Step 2**: ข้อกำหนดของระบบทั้ง Real Machine และ VM  
✅ **Step 3**: การดาวน์โหลดและตรวจสอบ Checksum  
✅ **Step 4**: การสร้าง Bootable USB Drive  
✅ **Step 5**: การติดตั้งบน Real Machine  
✅ **Step 6**: การติดตั้งบน VirtualBox  
✅ **Step 7**: การติดตั้งบน VMware  
✅ **Step 8**: การตั้งค่าแรกหลังติดตั้ง  
✅ **Step 9**: การจัดการ Package Manager  
✅ **Step 10**: การสำรองข้อมูลและ Snapshot  

## แบบฝึกหัด

1. ติดตั้ง Parrot OS บน VM ของคุณ
2. อัพเดทระบบให้เป็นเวอร์ชันล่าสุด
3. ติดตั้ง VirtualBox Guest Additions หรือ VMware Tools
4. สร้าง Snapshot แรกชื่อ "Clean Install"
5. ทดลองคำสั่ง apt update, upgrade, install

## ถัดไป: Part 02 - การตั้งค่าระบบและ Terminal พื้นฐาน

---

*Part 01 | Steps 1-10 | ระดับ: พื้นฐาน*
