# Part 98: Blue Team & SOC Operations (Steps 971-980)

## ภาพรวม
การดำเนินงาน Blue Team และ SOC ครอบคลุม SIEM, log analysis, threat hunting, incident response และ threat intelligence

---

## Step 971: SIEM Architecture & Log Collection

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
from datetime import datetime

class LogSource(Enum):
    WINDOWS_EVENT = "windows_event_logs"
    SYSLOG = "syslog"
    FIREWALL = "firewall_logs"
    IDS_IPS = "ids_ips_alerts"
    DNS = "dns_logs"
    PROXY = "proxy_logs"
    AD = "active_directory"
    CLOUD = "cloud_logs"
    ENDPOINT = "endpoint_logs"

class SIEMPlatform(Enum):
    SPLUNK = "splunk"
    ELASTIC = "elastic_siem"
    MICROSOFT_SENTINEL = "microsoft_sentinel"
    IBM_QRADAR = "ibm_qradar"
    SUMO_LOGIC = "sumo_logic"

@dataclass
class SIEMRule:
    """กฎ Detection rule ใน SIEM"""
    name: str
    description_th: str
    log_source: LogSource
    query: str
    platform: SIEMPlatform
    severity: str
    mitre_id: str
    false_positive_rate: str

class SIEMFramework:
    """การตั้งค่าและใช้งาน SIEM"""

    CRITICAL_RULES: List[SIEMRule] = [
        SIEMRule(
            name="Pass the Hash Detection",
            description_th="ตรวจจับการ Pass-the-Hash attack",
            log_source=LogSource.WINDOWS_EVENT,
            query="""
# Splunk Query
index=windows EventCode=4624
| where LogonType=3 AND AuthenticationPackageName="NTLM"
| stats count by ComputerName, AccountName, WorkstationName, IpAddress
| where count > 5
| eval alert="Potential Pass-the-Hash"
""",
            platform=SIEMPlatform.SPLUNK,
            severity="high",
            mitre_id="T1550.002",
            false_positive_rate="medium"
        ),
        SIEMRule(
            name="Kerberoasting Detection",
            description_th="ตรวจจับ Kerberoasting (TGS requests)",
            log_source=LogSource.AD,
            query="""
# Splunk Query
index=windows EventCode=4769
| where TicketEncryptionType="0x17" AND ServiceName!="krbtgt" AND ServiceName!="*$"
| stats count by ComputerName, AccountName, ServiceName
| where count > 3
| eval alert="Kerberoasting Detected"
""",
            platform=SIEMPlatform.SPLUNK,
            severity="high",
            mitre_id="T1558.003",
            false_positive_rate="low"
        ),
        SIEMRule(
            name="DCSync Detection",
            description_th="ตรวจจับ DCSync attack จาก non-DC",
            log_source=LogSource.AD,
            query="""
# Splunk/Elastic
index=windows EventCode=4662
| where ObjectType="controlAccessRight" AND ObjectClass="*ds-Replication-Get-Changes*"
| where SubjectUserSid!="DOMAIN-CONTROLLER-SID"
| eval alert="DCSync from non-DC"
""",
            platform=SIEMPlatform.SPLUNK,
            severity="critical",
            mitre_id="T1003.006",
            false_positive_rate="very_low"
        ),
        SIEMRule(
            name="PowerShell Download Cradle",
            description_th="ตรวจจับ PowerShell ดาวน์โหลดและ execute",
            log_source=LogSource.ENDPOINT,
            query="""
# Elastic/KQL
event.code:4104 AND
powershell.file.script_block_text:*DownloadString* OR
powershell.file.script_block_text:*DownloadFile* OR
powershell.file.script_block_text:*IEX* AND
powershell.file.script_block_text:*http*
""",
            platform=SIEMPlatform.ELASTIC,
            severity="high",
            mitre_id="T1059.001",
            false_positive_rate="medium"
        ),
        SIEMRule(
            name="LSASS Memory Access",
            description_th="ตรวจจับการเข้าถึง LSASS memory",
            log_source=LogSource.ENDPOINT,
            query="""
# Elastic
event.category:process AND
process.name:* AND
winnti.target_process_name:lsass.exe AND
event.action:("PROCESS_ACCESS" OR "OpenProcess")
""",
            platform=SIEMPlatform.ELASTIC,
            severity="critical",
            mitre_id="T1003.001",
            false_positive_rate="low"
        ),
    ]

    LOG_COLLECTION_SETUP = {
        "windows_winrm": """
# Configure WinRM for remote log collection
winrm quickconfig -y
winrm set winrm/config/service @{AllowUnencrypted="false"}
winrm set winrm/config/service/auth @{Basic="false"; Kerberos="true"}

# Group Policy to forward events
# Computer Config -> Windows Settings -> Security Settings -> Advanced Audit
# Enable: Logon/Logoff, Privilege Use, Object Access, Process Creation
""",
        "syslog_rsyslog": """
# rsyslog to forward to SIEM
# /etc/rsyslog.conf
*.* @siem-server:514        # UDP
*.* @@siem-server:514       # TCP
*.* @@siem-server:6514      # TLS

# SIEM receiving (rsyslog as collector)
modload imtcp
InputTCPServerRun 514
""",
        "elastic_beats": """
# Filebeat configuration for log collection
# /etc/filebeat/filebeat.yml
filebeat.inputs:
- type: winlog
  event_logs:
    - name: Security
    - name: System
    - name: Application
    - name: Microsoft-Windows-PowerShell/Operational
    - name: Microsoft-Windows-Sysmon/Operational

output.elasticsearch:
  hosts: ["siem-server:9200"]
  protocol: "https"
  ssl.certificate_authorities: ["/etc/filebeat/ca.crt"]
""",
    }

    SYSMON_CONFIG = """
<!-- Sysmon configuration for enhanced logging -->
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Process creation -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <CommandLine condition="is">C:\\Windows\\system32\\svchost.exe -k NetworkService -s W32Time</CommandLine>
      </ProcessCreate>
    </RuleGroup>
    
    <!-- Network connections -->
    <NetworkConnect onmatch="exclude">
      <Image condition="is">C:\\Windows\\System32\\svchost.exe</Image>
      <DestinationPort condition="is">53</DestinationPort>
    </NetworkConnect>
    
    <!-- Registry -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">\\CurrentVersion\\Run</TargetObject>
      <TargetObject condition="contains">\\CurrentVersion\\Policies\\Explorer\\Run</TargetObject>
    </RegistryEvent>
    
    <!-- File creation -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\\Temp\\</TargetFilename>
      <TargetFilename condition="contains">\\AppData\\</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
"""

    @classmethod
    def generate_detection_matrix(cls) -> str:
        lines = ["# SIEM Detection Matrix\n",
                 "| Rule | Severity | MITRE | FP Rate |",
                 "|------|----------|-------|---------|"
                 ]
        for rule in cls.CRITICAL_RULES:
            lines.append(f"| {rule.name} | {rule.severity} | {rule.mitre_id} | {rule.false_positive_rate} |")
        return "\n".join(lines)

# ตัวอย่างการใช้งาน
siem = SIEMFramework()
print(SIEMFramework.generate_detection_matrix())

print("\n### Critical SIEM Rules:")
for rule in siem.CRITICAL_RULES:
    print(f"\n#### {rule.name} [{rule.severity.upper()}]")
    print(f"Description: {rule.description_th}")
    print(f"MITRE: {rule.mitre_id}")
    print(f"Platform: {rule.platform.value}")
    print(f"Query:{rule.query}")
```

---

## Step 972: Log Analysis & Security Analytics

```python
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import re

@dataclass
class SecurityEvent:
    """เหตุการณ์ความปลอดภัย"""
    timestamp: datetime
    event_id: int
    source: str
    user: str
    ip_address: str
    action: str
    result: str
    raw_log: str

class WindowsEventAnalyzer:
    """วิเคราะห์ Windows Event Logs หาความผิดปกติ"""

    CRITICAL_EVENT_IDS = {
        4624: "Successful Logon",
        4625: "Failed Logon",
        4648: "Logon with explicit credentials",
        4672: "Special privileges assigned",
        4688: "Process Creation",
        4698: "Scheduled Task Created",
        4720: "User Account Created",
        4728: "Member added to security group",
        4732: "Member added to local group",
        4756: "Member added to universal group",
        4768: "Kerberos TGT request",
        4769: "Kerberos Service Ticket request",
        4771: "Kerberos pre-auth failed",
        4776: "NTLM Auth attempt",
        4799: "Group membership enumeration",
        7036: "Service state change",
        7045: "New service installed",
    }

    def __init__(self, events: List[SecurityEvent] = None):
        self.events = events or []
        self.alerts = []

    def detect_brute_force(self, threshold: int = 5, window_minutes: int = 5) -> List[Dict]:
        """ตรวจจับ Brute Force attacks"""
        failed_logins = defaultdict(list)
        alerts = []

        for event in self.events:
            if event.event_id == 4625:
                key = (event.user, event.ip_address)
                failed_logins[key].append(event.timestamp)

        for (user, ip), timestamps in failed_logins.items():
            timestamps.sort()
            for i in range(len(timestamps)):
                window_end = timestamps[i] + timedelta(minutes=window_minutes)
                count_in_window = sum(1 for t in timestamps[i:] if t <= window_end)
                if count_in_window >= threshold:
                    alerts.append({
                        "alert": "Brute Force Detected",
                        "user": user,
                        "source_ip": ip,
                        "count": count_in_window,
                        "window": f"{window_minutes} minutes",
                        "severity": "HIGH",
                        "mitre": "T1110.001"
                    })
                    break
        return alerts

    def detect_lateral_movement(self) -> List[Dict]:
        """ตรวจจับ Lateral Movement"""
        alerts = []
        logon_events = [e for e in self.events if e.event_id in [4624, 4648]]
        ip_by_user = defaultdict(set)

        for event in logon_events:
            if event.ip_address and event.ip_address != '127.0.0.1':
                ip_by_user[event.user].add(event.ip_address)

        for user, ips in ip_by_user.items():
            if len(ips) > 3:  # More than 3 source IPs
                alerts.append({
                    "alert": "Potential Lateral Movement",
                    "user": user,
                    "source_ips": list(ips),
                    "count": len(ips),
                    "severity": "MEDIUM",
                    "mitre": "T1021"
                })
        return alerts

    def detect_privilege_escalation(self) -> List[Dict]:
        """ตรวจจับ Privilege Escalation"""
        alerts = []
        for event in self.events:
            # Admin group membership additions
            if event.event_id in [4728, 4732, 4756]:
                alerts.append({
                    "alert": "Group Membership Change",
                    "event_id": event.event_id,
                    "user": event.user,
                    "timestamp": str(event.timestamp),
                    "severity": "HIGH",
                    "mitre": "T1078"
                })
            # New admin account created
            if event.event_id == 4720:
                alerts.append({
                    "alert": "New Account Created",
                    "user": event.user,
                    "timestamp": str(event.timestamp),
                    "severity": "MEDIUM",
                    "mitre": "T1136"
                })
        return alerts

    def analyze_process_creation(self) -> List[Dict]:
        """วิเคราะห์บันทึกการสร้าง process"""
        suspicious = []
        suspicious_patterns = [
            r'powershell.*-enc',
            r'powershell.*downloadstring',
            r'cmd.*echo.*>.*startup',
            r'wscript.*\.vbs',
            r'mshta.*http',
            r'regsvr32.*/s.*scrobj',
            r'certutil.*-urlcache',
            r'bitsadmin.*transfer',
        ]
        for event in self.events:
            if event.event_id == 4688:
                for pattern in suspicious_patterns:
                    if re.search(pattern, event.action.lower()):
                        suspicious.append({
                            "alert": "Suspicious Process",
                            "pattern": pattern,
                            "command": event.action,
                            "user": event.user,
                            "timestamp": str(event.timestamp),
                            "severity": "HIGH"
                        })
        return suspicious

    def run_all_detections(self) -> Dict[str, List]:
        return {
            "brute_force": self.detect_brute_force(),
            "lateral_movement": self.detect_lateral_movement(),
            "privilege_escalation": self.detect_privilege_escalation(),
            "suspicious_processes": self.analyze_process_creation(),
        }


class SplunkQueryLibrary:
    """คลัง Splunk SPL queries สำหรับ Blue Team"""

    QUERIES = {
        "top_failed_logins": """
index=windows EventCode=4625
| stats count by Account_Name, Workstation_Name, Source_Network_Address
| sort -count
| head 20
| rename count as "Failed Logins"
""",
        "powershell_encoded": """
index=windows EventCode=4104
| regex ScriptBlock="-[eE][nN][cC]"
| rex field=ScriptBlock "(?i)-enc(?:oded)?[\\s]+(?P<encoded>[A-Za-z0-9+/=]+)"
| eval decoded=base64decode(encoded)
| table _time, ComputerName, UserID, decoded
""",
        "new_local_admin": """
index=windows (EventCode=4728 OR EventCode=4732)
| eval group_type=case(EventCode=4732,"Local",EventCode=4728,"Domain")
| search MemberName!="*$"
| rex field=GroupName "(?P<group>[A-Za-z]+)"
| search group IN ("Administrators","Remote","Schema")
| table _time, ComputerName, MemberName, GroupName, group_type
""",
        "dns_beacon_detection": """
index=dns
| stats dc(query) as unique_queries, count as total_queries by src_ip, query_type
| where unique_queries > 100 AND total_queries > 500
| eval ratio=total_queries/unique_queries
| where ratio > 5
| sort -ratio
| eval alert="Possible DNS Tunneling/Beaconing"
""",
        "data_exfiltration": """
index=proxy OR index=firewall
| stats sum(bytes_out) as total_out by src_ip, dest_ip, dest_port
| eval total_out_mb=round(total_out/1024/1024, 2)
| where total_out_mb > 100
| sort -total_out_mb
| eval alert="Large Data Transfer"
""",
    }

    @classmethod
    def get_query(cls, name: str) -> str:
        return cls.QUERIES.get(name, "Query not found")


# ตัวอย่างการใช้งาน
analyzer = WindowsEventAnalyzer()

# จำลอง events
test_events = [
    SecurityEvent(
        timestamp=datetime.now() - timedelta(minutes=3),
        event_id=4625, source="DC01", user="admin",
        ip_address="192.168.1.100", action="Logon",
        result="Failure", raw_log=""
    ),
]
for i in range(6):
    test_events.append(SecurityEvent(
        timestamp=datetime.now() - timedelta(minutes=i),
        event_id=4625, source="DC01", user="admin",
        ip_address="192.168.1.100", action="Logon",
        result="Failure", raw_log=""
    ))

analyzer.events = test_events
alerts = analyzer.run_all_detections()
for alert_type, alert_list in alerts.items():
    if alert_list:
        print(f"\n### {alert_type.upper()}:")
        for a in alert_list:
            print(f"  {a}")

print("\n### Splunk Queries:")
for name in SplunkQueryLibrary.QUERIES.keys():
    print(f"  Available: {name}")
```

---

## Step 973: Threat Hunting Methodology

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum

class HuntType(Enum):
    HYPOTHESIS = "hypothesis_driven"
    INTEL_LED = "intelligence_led"
    ANOMALY = "anomaly_based"
    TECHNIQUE = "technique_based"

@dataclass
class ThreatHunt:
    """การ Threat Hunt"""
    hunt_id: str
    name: str
    hypothesis: str
    hunt_type: HuntType
    data_sources: List[str]
    queries: List[str]
    iocs: List[str]
    mitre_techniques: List[str]
    author: str

class ThreatHuntingFramework:
    """กรอบการ Threat Hunting"""

    HUNT_PLAYBOOKS: List[ThreatHunt] = [
        ThreatHunt(
            hunt_id="TH-001",
            name="Hunting for Kerberoasting",
            hypothesis="ผู้โจมตีอาจกำลัง request TGS tickets สำหรับ service accounts เพื่อ crack passwords offline",
            hunt_type=HuntType.TECHNIQUE,
            data_sources=["Windows Security Event Log (4769)", "AD logs"],
            queries=[
                "EventCode=4769 AND TicketEncryptionType=0x17 AND ServiceName!='krbtgt'",
                "GROUP BY ServiceName, AccountName HAVING COUNT > 5",
            ],
            iocs=[
                "RC4 encrypted TGS tickets (0x17)",
                "Many TGS requests for same service within short time",
                "TGS requests from non-admin accounts",
            ],
            mitre_techniques=["T1558.003"],
            author="SOC Team"
        ),
        ThreatHunt(
            hunt_id="TH-002",
            name="Hunting for Living Off the Land",
            hypothesis="ผู้โจมตีแอบใช้ Windows built-in tools เพื่อหลีก detection",
            hunt_type=HuntType.ANOMALY,
            data_sources=["Sysmon (Event ID 1)", "Windows Event 4688"],
            queries=[
                "process.name IN ('certutil.exe', 'mshta.exe', 'regsvr32.exe', 'wscript.exe', 'cscript.exe')",
                "process.command_line CONTAINS ('http://', 'https://', '-urlcache', '-encode')",
            ],
            iocs=[
                "certutil.exe accessing external URLs",
                "mshta.exe running from temp directory",
                "regsvr32.exe with /i: parameter pointing to URL",
            ],
            mitre_techniques=["T1218.001", "T1218.005", "T1218.010"],
            author="SOC Team"
        ),
        ThreatHunt(
            hunt_id="TH-003",
            name="Hunting for Suspicious Scheduled Tasks",
            hypothesis="ผู้โจมตีสร้าง scheduled tasks สำหรับ persistence หรือ lateral movement",
            hunt_type=HuntType.HYPOTHESIS,
            data_sources=["Windows Security (4698)", "Sysmon"],
            queries=[
                "EventCode=4698",
                "task.action CONTAINS ('powershell', 'cmd', 'wscript', 'mshta')",
                "task.trigger IN ('AtLogon', 'OnEvent') AND task.run_level = 'HighestAvailable'",
            ],
            iocs=[
                "Task names mimicking legitimate Windows tasks",
                "Tasks running PowerShell with encoded commands",
                "Tasks triggered by system events",
            ],
            mitre_techniques=["T1053.005"],
            author="SOC Team"
        ),
    ]

    HUNTING_METHODOLOGY = """
# Threat Hunting Methodology (PEAK)

## P - Prepare
1. ทำความเข้าใจ threat landscape และ business context
2. ระบุ data sources ที่มี (ตรวจสอบความครบถ้วน)
3. กำหนด scope และ timeframe
4. สร้าง hypothesis ที่สามารถปฏิเสธได้

## E - Execute
1. เริ่มจาก high-fidelity data ที่ตรงที่สุด
2. ใช้ baseline และเปรียบเทียบกับ anomalies
3. ปรับปรุง queries ตามผลลัพธ์ที่ได้
4. ใช้ TTP-based approach (dup MITRE ATT&CK)

## A - Analyze
1. คัดแยกสิ่งที่น่าสงสัย false positives ออก
2. พิสูจน์ indicators แต่ละอัน
3. สร้าง timeline ของเหตุการณ์
4. วิเคราะห์ root cause

## K - Knowledge
1. บันทึกและแบ่งปันผลลัพธ์
2. อัปเดต detection rules
3. สร้าง IOCs/IOAs ใหม่
4. อัปเดต threat model
"""

    SIGMA_RULE_EXAMPLE = """
title: Suspicious PowerShell Download Cradle
status: test
description: Detects PowerShell download cradle via Net.WebClient or DownloadString
author: SOC Team
date: 2024/01/01
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains:
            - 'Net.WebClient'
            - 'DownloadString'
            - 'DownloadFile'
            - 'IEX'
            - 'Invoke-Expression'
    filter_legit:
        ScriptBlockText|contains:
            - 'WindowsUpdate'
            - 'WSUS'
    condition: selection AND NOT filter_legit
fields:
    - ComputerName
    - UserID
    - ScriptBlockText
falsepositives:
    - Legitimate admin scripts
    - Software deployment tools
level: high
"""

    @classmethod
    def generate_hunt_plan(cls, hunt: ThreatHunt) -> str:
        lines = [f"# Threat Hunt Plan: {hunt.name}\n",
                 f"**Hunt ID:** {hunt.hunt_id}",
                 f"**Hypothesis:** {hunt.hypothesis}",
                 f"**Type:** {hunt.hunt_type.value}",
                 "\n## Data Sources"]
        for ds in hunt.data_sources:
            lines.append(f"- {ds}")
        lines.append("\n## Queries")
        for q in hunt.queries:
            lines.append(f"```\n{q}\n```")
        lines.append("\n## IOCs")
        for ioc in hunt.iocs:
            lines.append(f"- {ioc}")
        return "\n".join(lines)

# ตัวอย่างการใช้งาน
thf = ThreatHuntingFramework()
for hunt in thf.HUNT_PLAYBOOKS:
    print(ThreatHuntingFramework.generate_hunt_plan(hunt))
    print("\n---\n")

print("### Hunting Methodology:")
print(thf.HUNTING_METHODOLOGY)
```

---

## Step 974: Incident Response Automation

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
from enum import Enum
from datetime import datetime

class IncidentSeverity(Enum):
    P1_CRITICAL = "P1_critical"     # Active breach, data loss
    P2_HIGH = "P2_high"             # Confirmed compromise
    P3_MEDIUM = "P3_medium"         # Suspicious activity
    P4_LOW = "P4_low"               # Policy violation

class IncidentStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"

@dataclass
class Incident:
    """Security Incident"""
    incident_id: str
    title: str
    severity: IncidentSeverity
    status: IncidentStatus
    affected_systems: List[str]
    timeline: List[Dict]
    iocs: List[str]
    assignee: str
    created_at: datetime = field(default_factory=datetime.now)
    containment_actions: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

class IRPlaybook:
    """คู่มือ Incident Response"""

    PLAYBOOKS = {
        "ransomware": {
            "title": "Ransomware Response Playbook",
            "phases": {
                "detection": [
                    "ตรวจสอบ alerts จาก EDR (encrypted file creation, ransom note)",
                    "ระบุ affected systems จาก SIEM",
                    "ตรวจสอบ file extensions ที่ถูก encrypt",
                ],
                "containment": [
                    "แยก affected systems ออกจาก network ทันที",
                    "ปิด network shares",
                    "หยุดแนบ backups (remote backups)",
                    "ปิดการเข้าถึงจากภายนอก",
                ],
                "eradication": [
                    "ระบุ initial access vector",
                    "ระบุ patient zero และ lateral movement path",
                    "Re-image affected systems",
                    "เปลี่ยน credentials ทั้งหมด",
                ],
                "recovery": [
                    "Restore from clean backups",
                    "ตรวจสอบ integrity ของ restored data",
                    "นำ systems กลับสู่ production อย่างระมัดระวัง",
                    "เพิ่ม monitoring หลัง recovery",
                ],
                "lessons_learned": [
                    "Post-incident review ภายใน 72 ชั่วโมง",
                    "ปรับปรุง security controls",
                    "อัปเดต playbooks",
                    "Train staff on IOCs",
                ],
            },
            "timeline_sla": {
                "detection_to_containment": "4 hours",
                "containment_to_eradication": "24 hours",
                "recovery": "72 hours",
            }
        },
        "data_breach": {
            "title": "Data Breach Response Playbook",
            "phases": {
                "detection": [
                    "ตรวจสอป alerts จาก DLP หรือ CASB",
                    "ระบุ data classification ของข้อมูลที่สูญหาย",
                    "ประเมินจำนวน records",
                ],
                "legal_notification": [
                    "แจ้ง Legal/Privacy team ทันที",
                    "ประเมิน GDPR/PDPA notification requirements",
                    "Notify affected individuals within 72 hours (GDPR)",
                    "แจ้ง regulatory bodies",
                ],
            }
        },
    }

    def __init__(self):
        self.active_incidents: Dict[str, Incident] = {}
        self.incident_counter = 0

    def create_incident(
        self, title: str, severity: IncidentSeverity,
        affected_systems: List[str]
    ) -> Incident:
        self.incident_counter += 1
        incident_id = f"INC-{datetime.now().year}-{self.incident_counter:04d}"
        incident = Incident(
            incident_id=incident_id,
            title=title,
            severity=severity,
            status=IncidentStatus.OPEN,
            affected_systems=affected_systems,
            timeline=[{"timestamp": str(datetime.now()), "action": "Incident created"}],
            iocs=[],
            assignee="SOC Analyst"
        )
        self.active_incidents[incident_id] = incident
        return incident

    def update_incident_status(self, incident_id: str, status: IncidentStatus, note: str):
        if incident_id in self.active_incidents:
            incident = self.active_incidents[incident_id]
            incident.status = status
            incident.timeline.append({
                "timestamp": str(datetime.now()),
                "action": f"Status changed to {status.value}",
                "note": note
            })

    def add_containment_action(self, incident_id: str, action: str):
        if incident_id in self.active_incidents:
            self.active_incidents[incident_id].containment_actions.append(action)

    def generate_incident_report(self, incident_id: str) -> str:
        if incident_id not in self.active_incidents:
            return "Incident not found"
        
        inc = self.active_incidents[incident_id]
        report = [
            f"# Incident Report: {inc.incident_id}",
            f"**Title:** {inc.title}",
            f"**Severity:** {inc.severity.value}",
            f"**Status:** {inc.status.value}",
            f"**Created:** {inc.created_at}",
            f"\n## Affected Systems",
        ]
        for sys in inc.affected_systems:
            report.append(f"- {sys}")
        
        report.append("\n## Timeline")
        for event in inc.timeline:
            report.append(f"- {event['timestamp']}: {event['action']}")
        
        report.append("\n## Containment Actions")
        for action in inc.containment_actions:
            report.append(f"- {action}")
        
        return "\n".join(report)

# ตัวอย่างการใช้งาน
ir = IRPlaybook()

# สร้าง incident
inc = ir.create_incident(
    title="Suspected Ransomware - File encryption detected",
    severity=IncidentSeverity.P1_CRITICAL,
    affected_systems=["WS-001", "WS-002", "FS-001"]
)

# อัพเดต status
ir.update_incident_status(inc.incident_id, IncidentStatus.IN_PROGRESS, "Analysis started")
ir.add_containment_action(inc.incident_id, "Isolated WS-001 from network")
ir.add_containment_action(inc.incident_id, "Disabled compromised user account")

print(ir.generate_incident_report(inc.incident_id))
print("\n### Ransomware Playbook:")
for phase, steps in ir.PLAYBOOKS['ransomware']['phases'].items():
    print(f"\n#### {phase.upper()}:")
    for step in steps:
        print(f"  - {step}")
```

---

## Step 975: Threat Intelligence Integration

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
from datetime import datetime

class IOCType(Enum):
    IP = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    REGISTRY = "registry_key"
    MUTEX = "mutex"
    YARA = "yara_rule"

class TLPLevel(Enum):
    WHITE = "TLP:WHITE"   # Public
    GREEN = "TLP:GREEN"   # Community
    AMBER = "TLP:AMBER"   # Organization
    RED = "TLP:RED"       # Named recipients only

@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_id: str
    ioc_type: IOCType
    value: str
    tlp: TLPLevel
    confidence: int  # 0-100
    threat_actor: str
    campaign: str
    description: str
    tags: List[str]
    first_seen: datetime
    last_seen: datetime
    source: str

class ThreatIntelPlatform:
    """แพลตฟอร์ม Threat Intelligence"""

    THREAT_FEEDS = {
        "open_source": [
            {"name": "AlienVault OTX", "url": "https://otx.alienvault.com/", "type": "multi"},
            {"name": "Abuse.ch URLhaus", "url": "https://urlhaus.abuse.ch/", "type": "urls"},
            {"name": "Feodo Tracker", "url": "https://feodotracker.abuse.ch/", "type": "ips"},
            {"name": "MalwareBazaar", "url": "https://bazaar.abuse.ch/", "type": "hashes"},
            {"name": "Emerging Threats", "url": "https://rules.emergingthreats.net/", "type": "rules"},
            {"name": "OpenPhish", "url": "https://openphish.com/", "type": "phishing"},
            {"name": "PhishTank", "url": "https://phishtank.org/", "type": "phishing"},
        ],
        "commercial": [
            {"name": "Recorded Future", "type": "comprehensive"},
            {"name": "CrowdStrike Falcon X", "type": "threat_actors"},
            {"name": "Mandiant Advantage", "type": "comprehensive"},
            {"name": "Microsoft Defender TI", "type": "infrastructure"},
        ]
    }

    MISP_INTEGRATION = """
import requests
import json

class MISPClient:
    def __init__(self, misp_url: str, api_key: str):
        self.base_url = misp_url
        self.headers = {
            'Authorization': api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    
    def search_ioc(self, value: str, ioc_type: str = None) -> Dict:
        payload = {
            'value': value,
            'type': ioc_type,
            'returnFormat': 'json'
        }
        response = requests.post(
            f'{self.base_url}/attributes/restSearch',
            headers=self.headers,
            json=payload,
            verify=True
        )
        return response.json()
    
    def add_event(self, event_data: Dict) -> Dict:
        response = requests.post(
            f'{self.base_url}/events',
            headers=self.headers,
            json={'Event': event_data}
        )
        return response.json()
    
    def add_ioc(self, event_id: str, ioc: IOC) -> Dict:
        attribute = {
            'event_id': event_id,
            'type': ioc.ioc_type.value,
            'value': ioc.value,
            'comment': ioc.description,
            'to_ids': True,
            'distribution': 0  # org only
        }
        response = requests.post(
            f'{self.base_url}/attributes',
            headers=self.headers,
            json={'Attribute': attribute}
        )
        return response.json()
"""

    OPENCTI_INTEGRATION = """
import json
from pycti import OpenCTIApiClient

class OpenCTIClient:
    def __init__(self, url: str, token: str):
        self.client = OpenCTIApiClient(url, token)
    
    def create_indicator(self, pattern: str, name: str, description: str) -> Dict:
        return self.client.indicator.create(
            name=name,
            description=description,
            pattern=pattern,
            pattern_type='stix',
            x_opencti_score=75
        )
    
    def create_malware(self, name: str, description: str, aliases: List[str]) -> Dict:
        return self.client.malware.create(
            name=name,
            description=description,
            aliases=aliases,
            malware_types=['ransomware']
        )
    
    def search_by_hash(self, file_hash: str) -> List:
        return self.client.stix_cyber_observable.list(
            filters=[{'key': 'hashes_MD5', 'values': [file_hash]}]
        )
"""

    YARA_RULE_TEMPLATE = """
rule Suspicious_PowerShell_Dropper
{
    meta:
        description = "Detects suspicious PowerShell dropper patterns"
        author = "SOC Team"
        date = "2024-01-01"
        mitre = "T1059.001"
        hash = "example_hash"
    
    strings:
        $ps1 = "powershell" nocase
        $enc = "-EncodedCommand" nocase
        $iex = "IEX" fullword
        $dl1 = "DownloadString"
        $dl2 = "WebClient"
        $http = "http://" nocase
        $https = "https://" nocase
    
    condition:
        $ps1 and ($enc or ($iex and ($dl1 or $dl2) and ($http or $https)))
}
"""

    def __init__(self):
        self.ioc_database: List[IOC] = []

    def add_ioc(self, ioc: IOC):
        self.ioc_database.append(ioc)

    def search_ioc(self, value: str) -> Optional[IOC]:
        for ioc in self.ioc_database:
            if ioc.value == value:
                return ioc
        return None

    def get_high_confidence_iocs(self, min_confidence: int = 80) -> List[IOC]:
        return [ioc for ioc in self.ioc_database if ioc.confidence >= min_confidence]

    def generate_stix_bundle(self, iocs: List[IOC]) -> Dict:
        """Generate STIX 2.1 bundle"""
        objects = []
        for ioc in iocs:
            stix_indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{ioc.ioc_id}",
                "created": str(ioc.first_seen),
                "modified": str(ioc.last_seen),
                "name": f"{ioc.ioc_type.value}: {ioc.value}",
                "description": ioc.description,
                "pattern": f"[{ioc.ioc_type.value}:value = '{ioc.value}']",
                "pattern_type": "stix",
                "valid_from": str(ioc.first_seen),
                "labels": ioc.tags,
                "confidence": ioc.confidence,
            }
            objects.append(stix_indicator)
        
        return {
            "type": "bundle",
            "id": "bundle--12345",
            "objects": objects
        }

# ตัวอย่างการใช้งาน
ti = ThreatIntelPlatform()

# เพิ่ม IOC
test_ioc = IOC(
    ioc_id="ioc-001",
    ioc_type=IOCType.FILE_HASH,
    value="d41d8cd98f00b204e9800998ecf8427e",
    tlp=TLPLevel.AMBER,
    confidence=90,
    threat_actor="APT28",
    campaign="Operation Shadow",
    description="Known malware hash from APT28",
    tags=["malware", "apt28", "russia"],
    first_seen=datetime.now(),
    last_seen=datetime.now(),
    source="Internal Analysis"
)

ti.add_ioc(test_ioc)
high_conf = ti.get_high_confidence_iocs()
print(f"High confidence IOCs: {len(high_conf)}")

stix = ti.generate_stix_bundle(high_conf)
import json
print("\nSTIX Bundle:")
print(json.dumps(stix, indent=2, default=str))

print("\n### Threat Feeds:")
for feed_type, feeds in ti.THREAT_FEEDS.items():
    print(f"\n#### {feed_type}:")
    for feed in feeds:
        print(f"  - {feed['name']} ({feed['type']})")
```

---

## Step 976: Endpoint Detection & Response (EDR)

```python
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum

class EDRPlatform(Enum):
    CROWDSTRIKE = "crowdstrike_falcon"
    SENTINELONE = "sentinelone"
    DEFENDER_ATP = "microsoft_defender_atp"
    CARBON_BLACK = "vmware_carbon_black"
    ELASTIC_DEFEND = "elastic_defend"
    WAZUH = "wazuh"  # Open-source

@dataclass
class EDRQuery:
    """คำสั่งสอบถาม EDR"""
    name: str
    platform: EDRPlatform
    description_th: str
    query: str
    mitre_id: str

class EDRFramework:
    """กรอบการใช้งาน EDR"""

    CROWDSTRIKE_QUERIES = {
        "lsass_access": """
// CrowdStrike Falcon EDR - LSASS access detection
event_platform=Win event_simpleName=OpenProcess
| where TargetProcessFileName_Base="lsass.exe"
| stats count by ComputerName, UserName, ImageFileName
| sort -count
""",
        "process_injection": """
// Detect CreateRemoteThread
event_platform=Win event_simpleName=CreateRemoteThread
| where TargetProcessFileName_Base!="svchost.exe"
| table timestamp, ComputerName, UserName, SourceFileName, TargetProcessFileName
""",
        "powershell_encoded": """
// PowerShell encoded command
event_platform=Win event_simpleName=ProcessRollup2
| where CommandLine_match=("-enc") OR CommandLine_match=("-EncodedCommand")
| rex field=CommandLine "-[eE][nN][cC](?:oded)?[\\s]+(?P<encoded>[A-Za-z0-9+/=]+)"
| table timestamp, ComputerName, UserName, CommandLine
""",
        "scheduled_task_creation": """
// Suspicious scheduled task
event_platform=Win event_simpleName=ScheduledTaskRegistered
| where TaskAction_match=("cmd.exe") OR TaskAction_match=("powershell")
| table timestamp, ComputerName, UserName, TaskName, TaskAction
""",
    }

    SENTINELONE_QUERIES = {
        "fileless_execution": """
SiteId:xxxx AND EventType:"Process Creation"
AND SrcProcCmdLine:"*Invoke-Expression*" OR SrcProcCmdLine:"*IEX*"
""",
        "network_anomaly": """
SiteId:xxxx AND EventType:"IP Connect"
AND NOT DstIp:"10.0.0.0/8"
AND NOT DstIp:"192.168.0.0/16"
AND DstPort IN [4444, 1337, 9001, 8080]
""",
    }

    WAZUH_RULES = """
<!-- Wazuh rule for suspicious process -->
<rule id="100001" level="12">
    <if_group>windows</if_group>
    <id>4688</id>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(powershell|cmd).*(-enc|-e |-ec )</field>
    <description>Suspicious PowerShell encoded command</description>
    <group>attack,t1059</group>
    <mitre>
        <id>T1059.001</id>
    </mitre>
</rule>

<rule id="100002" level="15">
    <if_group>windows</if_group>
    <id>4624</id>
    <field name="win.eventdata.logonType" type="pcre2">^3$</field>
    <field name="win.eventdata.authenticationPackageName" type="pcre2">(?i)NTLM</field>
    <description>Potential Pass-the-Hash (NTLM network logon)</description>
    <group>attack,t1550</group>
    <mitre>
        <id>T1550.002</id>
    </mitre>
</rule>
"""

    EDR_RESPONSE_ACTIONS = {
        "isolate_endpoint": {
            "crowdstrike": "falcon-api containment POST /devices/entities/devices-actions/v2",
            "sentinelone": "GET /web/api/v2.1/agents/{agent_id}/actions/disconnect",
            "defender": "POST /api/machines/{machine_id}/isolate",
        },
        "kill_process": {
            "crowdstrike": "falcon-api processes POST /processes/entities/processes-actions/v1",
            "sentinelone": "POST /web/api/v2.1/agents/{agent_id}/actions/kill-process",
        },
        "run_script": {
            "crowdstrike": "falcon RTR (Real Time Response) session",
            "sentinelone": "POST /web/api/v2.1/agents/{agent_id}/actions/run-script",
        },
        "collect_evidence": {
            "crowdstrike": "falcon RTR + file download",
            "sentinelone": "GET /web/api/v2.1/threats/{id}/actions/fetch-file",
        }
    }

    @classmethod
    def generate_edr_comparison(cls) -> str:
        headers = ["Platform", "Cloud-native", "Open Source", "SOAR Integration", "Threat Intel"]
        table = [
            ["CrowdStrike", "Yes", "No", "Excellent", "Excellent"],
            ["SentinelOne", "Yes", "No", "Good", "Good"],
            ["Microsoft Defender", "Yes", "No", "Native M365", "Good"],
            ["Carbon Black", "Hybrid", "No", "Good", "Good"],
            ["Wazuh", "No", "Yes", "Manual", "Manual"],
        ]
        lines = ["| " + " | ".join(headers) + " |",
                 "|" + "---|" * len(headers)]
        for row in table:
            lines.append("| " + " | ".join(row) + " |")
        return "\n".join(lines)

# ตัวอย่างการใช้งาน
edr = EDRFramework()
print("### EDR Platform Comparison:")
print(EDRFramework.generate_edr_comparison())

print("\n### CrowdStrike Queries:")
for name, query in edr.CROWDSTRIKE_QUERIES.items():
    print(f"\n#### {name}:{query}")

print("\n### EDR Response Actions:")
for action, platforms in edr.EDR_RESPONSE_ACTIONS.items():
    print(f"\n#### {action}:")
    for platform, cmd in platforms.items():
        print(f"  [{platform}]: {cmd}")
```

---

## Step 977: Network Traffic Analysis & IDS/IPS

```python
from dataclasses import dataclass
from typing import List, Dict
from enum import Enum

class IDSType(Enum):
    SNORT = "snort"
    SURICATA = "suricata"
    ZEEK = "zeek"
    NTOPNG = "ntopng"

@dataclass
class NetworkRule:
    """กฎ Network Detection Rule"""
    name: str
    ids_type: IDSType
    rule: str
    description_th: str
    mitre_id: str
    category: str

class NetworkAnalytics:
    """การวิเคราะห์ Network Traffic"""

    SURICATA_RULES: List[NetworkRule] = [
        NetworkRule(
            name="Cobalt Strike Beacon",
            ids_type=IDSType.SURICATA,
            rule='alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"INDICATOR-COMPROMISE CobaltStrike Beacon"; flow:established,to_server; content:"Accept: */*"; http_header; content:"|0d 0a|Cookie: "; http_header; pcre:"/Cookie:\\s[a-zA-Z0-9]{4}=[a-zA-Z0-9+/]{48,}/H"; classtype:command-and-control; sid:100001; rev:1;)',
            description_th="ตรวจจับ CobaltStrike beacon communication",
            mitre_id="T1071.001",
            category="C2"
        ),
        NetworkRule(
            name="DNS Tunneling Detection",
            ids_type=IDSType.SURICATA,
            rule='alert dns any any -> any 53 (msg:"Possible DNS Tunneling"; dns.query; content:"."; pcre:"/(?:[a-z0-9]{30,})\.(?:com|net|org|io)/i"; threshold:type both,track by_src,count 100,seconds 60; classtype:policy-violation; sid:100002; rev:1;)',
            description_th="ตรวจจับ DNS Tunneling จาก query ยาวผิดปกติ",
            mitre_id="T1071.004",
            category="Exfiltration"
        ),
        NetworkRule(
            name="LDAP Enumeration",
            ids_type=IDSType.SURICATA,
            rule='alert tcp any any -> $HOME_NET 389 (msg:"LDAP Recon - BloodHound"; flow:established,to_server; content:"objectClass"; pcre:"/ldap:\/\/[^\\s]+/i"; threshold:type threshold,track by_src,count 50,seconds 10; classtype:policy-violation; sid:100003; rev:1;)',
            description_th="ตรวจจับ LDAP enumeration ที่ผิดปกติ",
            mitre_id="T1087.002",
            category="Reconnaissance"
        ),
    ]

    ZEEK_SCRIPTS = {
        "detect_beaconing": """
# Zeek script to detect network beaconing
@load base/frameworks/notice

export {
    redef enum Notice::Type += { Beaconing_Detected };
}

global connection_times: table[addr] of vector of time;

event new_connection(c: connection) {
    local src = c$id$orig_h;
    if (src !in connection_times)
        connection_times[src] = vector();
    connection_times[src] += network_time();
    
    if (|connection_times[src]| > 10) {
        # Check for regular intervals (beaconing)
        local times = connection_times[src];
        local intervals: vector of interval;
        local i = 1;
        while (i < |times|) {
            intervals += times[i] - times[i-1];
            ++i;
        }
        # Analyze variance - low variance = beaconing
        # ...
    }
}
""",
        "c2_detection": """
# Zeek C2 detection based on JA3 fingerprints
@load protocols/ssl
@load base/frameworks/notice

export {
    redef enum Notice::Type += { Suspicious_SSL_C2 };
    const known_c2_ja3: set[string] = {
        "51c64c77e60f3980eea90869b68c58a8",  # Metasploit
        "6734f37431670b3ab4292b8f60f29984",  # CobaltStrike
    } &redef;
}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) {
    local ja3 = SSL::ja3_fingerprint(c);
    if (ja3 in known_c2_ja3) {
        NOTICE([$note=Suspicious_SSL_C2,
                $conn=c,
                $msg=fmt("Possible C2 communication: JA3=%s", ja3)]);
    }
}
""",
    }

    NETWORK_FORENSICS_TOOLS = {
        "tshark": [
            "tshark -i eth0 -w capture.pcap",
            "tshark -r capture.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri",
            "tshark -r capture.pcap -q -z conv,tcp",
            "tshark -r capture.pcap -Y 'tcp.flags.syn==1 and tcp.flags.ack==0' | awk '{print $3}' | sort | uniq -c | sort -rn | head 20",
        ],
        "tcpdump": [
            "tcpdump -i eth0 -w capture.pcap port not 22",
            "tcpdump -r capture.pcap 'tcp[tcpflags] & tcp-syn != 0'",
            "tcpdump -i eth0 -nn -v 'host 192.168.1.100 and not port 22'",
        ],
        "zeek": [
            "zeek -r capture.pcap local",
            "cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration orig_bytes resp_bytes",
            "cat dns.log | zeek-cut query qtype_name answers",
            "cat http.log | zeek-cut method host uri user_agent",
        ],
    }

    @classmethod
    def generate_network_detection_guide(cls) -> str:
        lines = ["# Network Traffic Analysis Guide\n"]
        lines.append("## Suricata Rules")
        for rule in cls.SURICATA_RULES:
            lines.append(f"\n### {rule.name} ({rule.mitre_id})")
            lines.append(f"Category: {rule.category}")
            lines.append(f"Description: {rule.description_th}")
            lines.append(f"```\n{rule.rule}\n```")
        return "\n".join(lines)

# ตัวอย่างการใช้งาน
na = NetworkAnalytics()
print(NetworkAnalytics.generate_network_detection_guide())

print("\n### Network Forensics Tools:")
for tool, cmds in na.NETWORK_FORENSICS_TOOLS.items():
    print(f"\n#### {tool}:")
    for cmd in cmds:
        print(f"  {cmd}")
```

---

## Step 978: SOAR & Security Automation

```python
from dataclasses import dataclass
from typing import List, Dict, Optional, Callable
from enum import Enum

class PlaybookTrigger(Enum):
    SIEM_ALERT = "siem_alert"
    EDR_ALERT = "edr_alert"
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    WEBHOOK = "webhook"

@dataclass
class SOARAction:
    """การดำเนินงาน SOAR"""
    name: str
    action_type: str
    description_th: str
    integration: str
    parameters: Dict

@dataclass
class SOARPlaybook:
    """SOAR Automation Playbook"""
    name: str
    description_th: str
    trigger: PlaybookTrigger
    trigger_condition: str
    actions: List[SOARAction]
    sla_minutes: int

class SOARFramework:
    """กรอบ Security Orchestration, Automation and Response"""

    PLAYBOOKS: List[SOARPlaybook] = [
        SOARPlaybook(
            name="Phishing Email Response",
            description_th="ตอบสนองอัตโนมัติต่ออีเมล phishing",
            trigger=PlaybookTrigger.SIEM_ALERT,
            trigger_condition="alert_name CONTAINS 'phishing' OR alert_name CONTAINS 'email_suspicious'",
            actions=[
                SOARAction(
                    name="Extract IOCs from email",
                    action_type="analyze",
                    description_th="ดึง URLs, domains, hashes จาก email",
                    integration="email_parser",
                    parameters={"parse_headers": True, "extract_urls": True, "extract_attachments": True}
                ),
                SOARAction(
                    name="Check IOCs against TI",
                    action_type="enrich",
                    description_th="ตรวจสอบ IOCs ใน threat intel platforms",
                    integration="virustotal",
                    parameters={"check_hashes": True, "check_urls": True, "check_ips": True}
                ),
                SOARAction(
                    name="Block sender domain",
                    action_type="contain",
                    description_th="Block domain ใน email gateway",
                    integration="exchange_eop",
                    parameters={"action": "block_sender", "scope": "organization"}
                ),
                SOARAction(
                    name="Search for similar emails",
                    action_type="investigate",
                    description_th="หา emails เดียวกันที่ส่งไปยังผู้ใช้คนอื่น",
                    integration="email_gateway",
                    parameters={"search_last_days": 7, "match_subject": True, "match_sender": True}
                ),
                SOARAction(
                    name="Notify users",
                    action_type="communicate",
                    description_th="แจ้งเตือนผู้ใช้ที่ได้รับ email phishing",
                    integration="slack_teams",
                    parameters={"channel": "#security-alerts", "include_iocs": True}
                ),
            ],
            sla_minutes=15
        ),
        SOARPlaybook(
            name="Malware Alert Response",
            description_th="ตอบสนอง EDR malware alert",
            trigger=PlaybookTrigger.EDR_ALERT,
            trigger_condition="severity = 'critical' AND type = 'malware'",
            actions=[
                SOARAction(
                    name="Isolate endpoint",
                    action_type="contain",
                    description_th="แยก endpoint ออกจาก network",
                    integration="crowdstrike_falcon",
                    parameters={"action": "contain", "notify_owner": True}
                ),
                SOARAction(
                    name="Collect forensic data",
                    action_type="investigate",
                    description_th="เก็บรวบรวม memory dump, logs, running processes",
                    integration="crowdstrike_rtr",
                    parameters={"collect_memory": True, "collect_logs": True, "collect_processes": True}
                ),
                SOARAction(
                    name="Submit sample for analysis",
                    action_type="analyze",
                    description_th="ส่ง sample ไป sandbox",
                    integration="cuckoo_sandbox",
                    parameters={"analysis_time": 120, "report_format": "json"}
                ),
            ],
            sla_minutes=30
        )
    ]

    PHANTOM_CODE = """
# Splunk SOAR (Phantom) playbook example
import phantom.app as phantom
from phantom.base_connector import BaseConnector

def on_start(container):
    phantom.debug(f"Phishing playbook started for container: {container['id']}")
    return phantom.APP_SUCCESS

def email_analysis(action=None, success=None, container=None, results=None):
    if not success:
        phantom.error("Previous action failed")
        return
    
    # Get email artifact
    artifact = container.get('artifacts', [{}])[0]
    email_from = artifact.get('cef', {}).get('fromEmail', '')
    
    # Run VirusTotal check on domain
    domain = email_from.split('@')[-1] if '@' in email_from else email_from
    
    parameters = [{'domain': domain}]
    phantom.act('domain reputation',
                parameters=parameters,
                assets=['virustotal'],
                callback=virustotal_result,
                name='vt_domain_check')
    return phantom.APP_SUCCESS

def virustotal_result(action=None, success=None, container=None, results=None):
    if success:
        action_result = results[0]
        positives = action_result.get_data()[0].get('positives', 0)
        if positives > 5:
            phantom.act('block url', parameters=[{'url': action_result.get_param('domain')}],
                       assets=['bluecoat_proxy'])
"""

    @classmethod
    def generate_soar_workflow(cls, playbook: SOARPlaybook) -> str:
        lines = [f"# SOAR Playbook: {playbook.name}\n",
                 f"**Trigger:** {playbook.trigger.value}",
                 f"**SLA:** {playbook.sla_minutes} minutes",
                 f"**Condition:** {playbook.trigger_condition}",
                 f"\n## Actions"]
        for i, action in enumerate(playbook.actions, 1):
            lines.append(f"\n### {i}. {action.name} [{action.action_type.upper()}]")
            lines.append(f"Integration: {action.integration}")
            lines.append(f"Description: {action.description_th}")
        return "\n".join(lines)

# ตัวอย่างการใช้งาน
soar = SOARFramework()
for pb in soar.PLAYBOOKS:
    print(SOARFramework.generate_soar_workflow(pb))
    print("\n---\n")
```

---

## Step 979: Vulnerability Management Program

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
from datetime import datetime, timedelta

class VulnSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"

class RemediationStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RISK_ACCEPTED = "risk_accepted"
    MITIGATED = "mitigated"
    REMEDIATED = "remediated"

@dataclass
class Vulnerability:
    """ช่องโหว่ที่ตรวจพบ"""
    vuln_id: str
    cve: str
    title: str
    severity: VulnSeverity
    cvss_score: float
    affected_asset: str
    description: str
    status: RemediationStatus
    due_date: datetime
    owner: str
    remediation_guidance: str
    tags: List[str] = field(default_factory=list)

class VulnerabilityManagement:
    """โปรแกรมจัดการช่องโหว่"""

    SLA_REMEDIATION = {
        VulnSeverity.CRITICAL: timedelta(days=7),
        VulnSeverity.HIGH: timedelta(days=30),
        VulnSeverity.MEDIUM: timedelta(days=90),
        VulnSeverity.LOW: timedelta(days=180),
    }

    SCANNING_TOOLS = {
        "nessus": {
            "description": "เครื่อง VA scanner อันดับ 1 แบบ commercial",
            "commands": [
                "nessuscli update",
                "nessuscli scan new --policy \"Advanced Scan\" --targets 192.168.1.0/24",
                "nessuscli report export --id SCAN_ID --format csv",
            ]
        },
        "openvas": {
            "description": "Open-source VA scanner",
            "commands": [
                "gvm-cli socket --xml '<get_configs/>'",
                "gvm-cli socket --xml '<create_target><name>Test</name><hosts>192.168.1.0/24</hosts></create_target>'",
                "gvm-cli socket --xml '<create_task><name>Test</name><config id=\"CONFIGID\"/><target id=\"TARGETID\"/></create_task>'",
            ]
        },
        "nuclei": {
            "description": "สอบหา CVEs และ misconfigs ด้วย templates",
            "commands": [
                "nuclei -t cves/ -target https://target.com",
                "nuclei -t nuclei-templates/ -target 192.168.1.0/24 -severity critical,high",
                "nuclei -t nuclei-templates/ -list targets.txt -o results.json -json",
                "nuclei -update-templates",
            ]
        },
    }

    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []

    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)

    def get_overdue_vulnerabilities(self) -> List[Vulnerability]:
        now = datetime.now()
        return [v for v in self.vulnerabilities
                if v.status not in [RemediationStatus.REMEDIATED, RemediationStatus.RISK_ACCEPTED]
                and v.due_date < now]

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score"""
        if not self.vulnerabilities:
            return 0.0
        
        weights = {
            VulnSeverity.CRITICAL: 10,
            VulnSeverity.HIGH: 7,
            VulnSeverity.MEDIUM: 4,
            VulnSeverity.LOW: 1,
        }
        total = sum(weights.get(v.severity, 0) for v in self.vulnerabilities
                    if v.status not in [RemediationStatus.REMEDIATED])
        return total / len(self.vulnerabilities)

    def generate_vuln_report(self) -> str:
        by_severity = {}
        for vuln in self.vulnerabilities:
            sev = vuln.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        overdue = len(self.get_overdue_vulnerabilities())
        risk_score = self.calculate_risk_score()
        
        lines = ["# Vulnerability Management Report",
                 f"Total Vulnerabilities: {len(self.vulnerabilities)}",
                 f"Overdue: {overdue}",
                 f"Risk Score: {risk_score:.2f}",
                 "\n## By Severity"]
        for sev, count in sorted(by_severity.items()):
            lines.append(f"  {sev}: {count}")
        return "\n".join(lines)

# ตัวอย่างการใช้งาน
vm = VulnerabilityManagement()

# เพิ่มตัวอย่าง
vm.add_vulnerability(Vulnerability(
    vuln_id="V-001", cve="CVE-2024-1234",
    title="Apache RCE via XXE",
    severity=VulnSeverity.CRITICAL, cvss_score=9.8,
    affected_asset="web-server-01",
    description="Remote code execution via XML external entity injection",
    status=RemediationStatus.IN_PROGRESS,
    due_date=datetime.now() - timedelta(days=2),  # Overdue
    owner="Web Team",
    remediation_guidance="Upgrade Apache to latest version"
))

print(vm.generate_vuln_report())
print(f"\nOverdue vulnerabilities: {len(vm.get_overdue_vulnerabilities())}")

print("\n### Scanning Tools:")
for tool, info in vm.SCANNING_TOOLS.items():
    print(f"\n#### {tool}: {info['description']}")
    for cmd in info['commands']:
        print(f"  {cmd}")
```

---

## Step 980: Security Metrics & KPI Dashboard

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from statistics import mean, stdev
from enum import Enum

class MetricCategory(Enum):
    DETECTION = "detection"
    RESPONSE = "response"
    PREVENTION = "prevention"
    RISK = "risk"
    COMPLIANCE = "compliance"

@dataclass
class SecurityMetric:
    """ตัวชี้วัดความปลอดภัย"""
    name: str
    category: MetricCategory
    description_th: str
    unit: str
    target: float
    current_value: float
    trend: str  # up/down/stable
    formula: str

@dataclass
class SOCMetrics:
    """SOC Performance Metrics"""
    period: str
    mttd: float  # Mean Time to Detect (hours)
    mttr: float  # Mean Time to Respond (hours)
    mttc: float  # Mean Time to Contain (hours)
    false_positive_rate: float  # percentage
    alert_volume: int
    incidents_created: int
    incidents_closed: int
    critical_findings: int
    patch_compliance_rate: float  # percentage

class SecurityDashboard:
    """แดชบอร์ด Security Operations"""

    KPI_METRICS: List[SecurityMetric] = [
        SecurityMetric(
            name="MTTD",
            category=MetricCategory.DETECTION,
            description_th="เวลาเฉลี่ยในการตรวจจับภัยคุกคาม",
            unit="hours",
            target=1.0,
            current_value=2.5,
            trend="down",
            formula="sum(detection_times) / count(incidents)"
        ),
        SecurityMetric(
            name="MTTR",
            category=MetricCategory.RESPONSE,
            description_th="เวลาเฉลี่ยในการตอบสนอง",
            unit="hours",
            target=4.0,
            current_value=6.0,
            trend="stable",
            formula="sum(response_times) / count(incidents)"
        ),
        SecurityMetric(
            name="Alert False Positive Rate",
            category=MetricCategory.DETECTION,
            description_th="อัตรา alerts ที่ไม่ใช่ของจริง",
            unit="%",
            target=15.0,
            current_value=25.0,
            trend="down",
            formula="(false_positives / total_alerts) * 100"
        ),
        SecurityMetric(
            name="Patch Compliance",
            category=MetricCategory.PREVENTION,
            description_th="เปอร์เซ็นต์ systems ที่ถูก patch แล้ว",
            unit="%",
            target=95.0,
            current_value=87.0,
            trend="up",
            formula="(patched_systems / total_systems) * 100"
        ),
        SecurityMetric(
            name="Vulnerability Remediation SLA",
            category=MetricCategory.RISK,
            description_th="เปอร์เซ็นต์ critical vulns ที่แก้ไขทันใน SLA",
            unit="%",
            target=90.0,
            current_value=78.0,
            trend="up",
            formula="(on_time_remediations / total_critical_vulns) * 100"
        ),
    ]

    def generate_ascii_dashboard(self, metrics: SOCMetrics) -> str:
        """สร้าง ASCII dashboard สำหรับ SOC KPIs"""
        mttd_status = "✅" if metrics.mttd <= 1 else "⚠️" if metrics.mttd <= 4 else "❌"
        mttr_status = "✅" if metrics.mttr <= 4 else "⚠️" if metrics.mttr <= 24 else "❌"
        fp_status = "✅" if metrics.false_positive_rate <= 15 else "⚠️" if metrics.false_positive_rate <= 30 else "❌"
        patch_status = "✅" if metrics.patch_compliance_rate >= 95 else "⚠️" if metrics.patch_compliance_rate >= 80 else "❌"

        dashboard = f"""
╔══════════════════════════════════════════════════════════════╗
║ SOC SECURITY METRICS DASHBOARD - {metrics.period:<32} ║
╠══════════════════════════════════════════════════════════════╣
║ DETECTION                                                      ║
║   Mean Time to Detect (MTTD) : {metrics.mttd:>6.1f} hrs  {mttd_status}  (Target: <1hr)    ║
║   Mean Time to Respond (MTTR): {metrics.mttr:>6.1f} hrs  {mttr_status}  (Target: <4hr)    ║
║   Mean Time to Contain (MTTC): {metrics.mttc:>6.1f} hrs                           ║
╠══════════════════════════════════════════════════════════════╣
║ ALERT MANAGEMENT                                                ║
║   Total Alerts   : {metrics.alert_volume:>8}                                     ║
║   False Positive : {metrics.false_positive_rate:>6.1f}%    {fp_status}  (Target: <15%)         ║
║   Incidents      : {metrics.incidents_created:>8} created / {metrics.incidents_closed:<8} closed           ║
╠══════════════════════════════════════════════════════════════╣
║ RISK & COMPLIANCE                                               ║
║   Critical Findings     : {metrics.critical_findings:>5}                                ║
║   Patch Compliance Rate : {metrics.patch_compliance_rate:>5.1f}%  {patch_status}  (Target: >95%)         ║
╚══════════════════════════════════════════════════════════════╝
"""
        return dashboard

    def generate_trend_chart(self, values: List[float], label: str, target: float) -> str:
        """ASCII trend chart"""
        max_val = max(values) if values else 1
        height = 10
        width = len(values)
        chart_rows = []
        for row in range(height, -1, -1):
            threshold = (row / height) * max_val
            line = f"{threshold:6.1f}| "
            for val in values:
                if val >= threshold:
                    line += "█ "
                elif val >= threshold - (max_val/height):
                    line += "▄ "
                else:
                    line += "  "
            chart_rows.append(line)
        chart_rows.append(f"{'':6}  {'---' * (width + 1)}")
        chart_rows.append(f"{'':6}  {label}")
        chart_rows.append(f"{'':6}  Target: {target}")
        return "\n".join(chart_rows)

# ตัวอย่างการใช้งาน
dashboard = SecurityDashboard()

current_metrics = SOCMetrics(
    period="October 2026",
    mttd=2.5,
    mttr=8.0,
    mttc=12.0,
    false_positive_rate=22.5,
    alert_volume=4532,
    incidents_created=89,
    incidents_closed=76,
    critical_findings=12,
    patch_compliance_rate=87.3
)

print(dashboard.generate_ascii_dashboard(current_metrics))

print("\n### KPI Summary:")
for metric in dashboard.KPI_METRICS:
    status = "✅" if metric.current_value <= metric.target else "❌"
    print(f"  {status} {metric.name}: {metric.current_value} {metric.unit} (target: {metric.target}) | Trend: {metric.trend}")
```

---

## สรุป Part 98

| Step | หัวข้อ | เครื่องมือ/เทคนิค |
|------|--------|-------------------|
| 971 | SIEM Architecture | Splunk, Elastic, detection rules, Sysmon |
| 972 | Log Analysis | Windows Events, brute force detection, SPL queries |
| 973 | Threat Hunting | PEAK methodology, SIGMA rules, hunt playbooks |
| 974 | Incident Response | IR playbooks, ransomware response, PDPA/GDPR |
| 975 | Threat Intelligence | MISP, OpenCTI, STIX 2.1, IOC management |
| 976 | EDR Operations | CrowdStrike, SentinelOne, Wazuh rules |
| 977 | Network Analysis | Suricata rules, Zeek scripts, tshark/tcpdump |
| 978 | SOAR Automation | Phantom playbooks, phishing response, malware response |
| 979 | Vulnerability Management | Nessus, Nuclei, SLA tracking |
| 980 | Security Metrics | MTTD, MTTR, KPI dashboard, trend analysis |
