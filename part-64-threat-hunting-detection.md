# Part 64: Threat Hunting & Detection Engineering (Steps 631-640)

## ภาพรวม
การค้นหาภัยคุกคามเชิงรุก (Threat Hunting) และการสร้าง Detection Rules เพื่อตรวจจับการโจมตีก่อนที่จะเกิดความเสียหาย

---

## Step 631: Threat Hunting Methodology

```python
#!/usr/bin/env python3
# Threat Hunting Framework - ระเบียบวิธีการค้นหาภัยคุกคาม

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import json
import re
from datetime import datetime
from enum import Enum

class HuntingHypothesis(Enum):
    ATTACKER_IN_NETWORK = "attacker_in_network"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    CREDENTIAL_THEFT = "credential_theft"
    C2_COMMUNICATION = "c2_communication"

@dataclass
class ThreatHunt:
    hypothesis: str
    data_sources: List[str]
    hunting_techniques: List[str]
    ioc_types: List[str]
    mitre_tactics: List[str]
    priority: str = "medium"
    
class ThreatHuntingFramework:
    def __init__(self):
        self.hunt_library = self._build_hunt_library()
        self.findings = []
        
    def _build_hunt_library(self) -> Dict[str, ThreatHunt]:
        return {
            "living_off_land": ThreatHunt(
                hypothesis="Attacker using built-in OS tools to avoid detection",
                data_sources=["process_creation", "network_connections", "powershell_logs"],
                hunting_techniques=[
                    "Look for powershell.exe spawned from Office apps",
                    "wmic.exe making network connections",
                    "certutil.exe downloading files",
                    "regsvr32.exe loading remote scripts",
                    "mshta.exe executing scripts"
                ],
                ioc_types=["process_name", "command_line", "parent_process"],
                mitre_tactics=["T1059.001", "T1218", "T1197"],
                priority="high"
            ),
            "beaconing_detection": ThreatHunt(
                hypothesis="C2 beacon with periodic check-ins",
                data_sources=["network_logs", "dns_logs", "proxy_logs"],
                hunting_techniques=[
                    "Analyze connection intervals for regularity",
                    "Look for low-frequency but consistent connections",
                    "Check for jitter patterns (randomized intervals)",
                    "Identify long-duration TCP connections",
                    "Hunt for base64/hex encoded DNS queries"
                ],
                ioc_types=["ip_address", "domain", "user_agent", "connection_interval"],
                mitre_tactics=["T1071", "T1571", "T1573"],
                priority="critical"
            ),
            "credential_dumping": ThreatHunt(
                hypothesis="Attacker attempting to harvest credentials",
                data_sources=["process_creation", "file_access", "registry_access", "windows_events"],
                hunting_techniques=[
                    "Monitor lsass.exe memory access",
                    "Look for procdump/mimikatz patterns",
                    "Check for SAM/SYSTEM/NTDS.dit access",
                    "Monitor for sekurlsa:: patterns in commands",
                    "Look for Volume Shadow Copy enumeration"
                ],
                ioc_types=["process_access", "file_access", "event_id"],
                mitre_tactics=["T1003", "T1003.001", "T1003.002"],
                priority="critical"
            )
        }
    
    def create_hunt_plan(self, hypothesis_type: str) -> Dict:
        """สร้างแผนการ Hunt สำหรับ Hypothesis ที่กำหนด"""
        hunt = self.hunt_library.get(hypothesis_type)
        if not hunt:
            return {"error": f"Unknown hypothesis: {hypothesis_type}"}
        
        plan = {
            "hunt_id": f"HUNT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "hypothesis": hunt.hypothesis,
            "priority": hunt.priority,
            "data_sources_required": hunt.data_sources,
            "investigation_steps": [
                f"Step {i+1}: {technique}" 
                for i, technique in enumerate(hunt.hunting_techniques)
            ],
            "ioc_types_to_collect": hunt.ioc_types,
            "mitre_coverage": hunt.mitre_tactics,
            "estimated_time": self._estimate_hunt_time(hunt),
            "queries": self._generate_hunt_queries(hypothesis_type)
        }
        return plan
    
    def _estimate_hunt_time(self, hunt: ThreatHunt) -> str:
        base_hours = len(hunt.hunting_techniques) * 0.5
        if hunt.priority == "critical":
            base_hours *= 1.5
        return f"{base_hours:.1f} hours"
    
    def _generate_hunt_queries(self, hypothesis_type: str) -> Dict[str, str]:
        queries = {
            "living_off_land": {
                "splunk": 'index=windows EventCode=4688 | where match(CommandLine, "(?i)(certutil|mshta|regsvr32|wmic).*http") | table _time, ComputerName, CommandLine',
                "elastic": '{"query": {"bool": {"must": [{"match": {"event.code": "4688"}}, {"regexp": {"process.command_line": "(?i)(certutil|mshta|regsvr32).*http"}}]}}}',
                "sigma": "title: LOLBins Network Connection\ndetection:\n  selection:\n    EventID: 4688\n    CommandLine|contains|all:\n      - certutil\n      - http"
            },
            "beaconing_detection": {
                "splunk": 'index=network | stats count, stdev(interval) as jitter by src_ip, dest_ip | where jitter < 5 AND count > 100',
                "elastic": '{"aggs": {"by_connection": {"terms": {"field": "connection.id"}, "aggs": {"interval_stats": {"stats": {"field": "@timestamp"}}}}}}',
                "sigma": "title: Beaconing Detection\ndetection:\n  selection:\n    network.protocol: tcp\n  condition: selection | count() by destination.ip > 100"
            },
            "credential_dumping": {
                "splunk": 'index=windows EventCode=10 TargetImage="*lsass.exe" | where CallTrace LIKE "%UNKNOWN%" | table _time, SourceImage, TargetImage',
                "elastic": '{"query": {"bool": {"must": [{"match": {"event.code": "10"}}, {"match": {"winlog.event_data.TargetImage": "lsass.exe"}}]}}}',
                "sigma": "title: LSASS Memory Access\ndetection:\n  selection:\n    EventID: 10\n    TargetImage|endswith: lsass.exe\n    GrantedAccess:\n      - '0x1010'\n      - '0x1410'"
            }
        }
        return queries.get(hypothesis_type, {})
    
    def analyze_hunt_results(self, results: List[Dict]) -> Dict:
        """วิเคราะห์ผลการ Hunt"""
        analysis = {
            "total_events": len(results),
            "true_positives": [],
            "false_positives": [],
            "new_iocs": [],
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0}
        }
        
        for result in results:
            severity = self._assess_severity(result)
            analysis["severity_breakdown"][severity] += 1
            
            if self._is_true_positive(result):
                analysis["true_positives"].append({
                    "event": result,
                    "severity": severity,
                    "recommendation": self._get_recommendation(result)
                })
                
                iocs = self._extract_iocs(result)
                analysis["new_iocs"].extend(iocs)
            else:
                analysis["false_positives"].append(result)
        
        return analysis
    
    def _assess_severity(self, event: Dict) -> str:
        high_risk_processes = ["mimikatz", "procdump", "meterpreter", "cobaltstrike"]
        if any(p in str(event).lower() for p in high_risk_processes):
            return "critical"
        medium_risk = ["powershell", "wscript", "cscript", "mshta"]
        if any(p in str(event).lower() for p in medium_risk):
            return "medium"
        return "low"
    
    def _is_true_positive(self, event: Dict) -> bool:
        suspicious_patterns = [
            r"powershell.*-enc",
            r"certutil.*-urlcache",
            r"regsvr32.*scrobj",
            r"mshta.*vbscript"
        ]
        event_str = str(event).lower()
        return any(re.search(p, event_str, re.IGNORECASE) for p in suspicious_patterns)
    
    def _extract_iocs(self, event: Dict) -> List[Dict]:
        iocs = []
        event_str = str(event)
        
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        for ip in re.findall(ip_pattern, event_str):
            if not ip.startswith(('10.', '192.168.', '172.')):
                iocs.append({"type": "ip", "value": ip})
        
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        for domain in re.findall(domain_pattern, event_str):
            if len(domain) > 10 and "." in domain:
                iocs.append({"type": "domain", "value": domain})
        
        return iocs
    
    def _get_recommendation(self, event: Dict) -> str:
        recommendations = {
            "mimikatz": "Isolate host immediately, reset all passwords, check for lateral movement",
            "powershell": "Review script content, check parent process, analyze network connections",
            "certutil": "Check downloaded file hash against threat intel, quarantine if malicious"
        }
        event_lower = str(event).lower()
        for key, rec in recommendations.items():
            if key in event_lower:
                return rec
        return "Investigate further and collect additional context"


if __name__ == '__main__':
    framework = ThreatHuntingFramework()
    
    plan = framework.create_hunt_plan("credential_dumping")
    print("Hunt Plan:")
    print(json.dumps(plan, indent=2, default=str))
    
    print("\nAll available hunts:")
    for hunt_name in framework.hunt_library:
        hunt = framework.hunt_library[hunt_name]
        print(f"  - {hunt_name}: {hunt.hypothesis} (Priority: {hunt.priority})")
```

---

## Step 632: SIGMA Rule Creation

```python
#!/usr/bin/env python3
# SIGMA Rule Generator - สร้าง Detection Rules ด้วย SIGMA Framework

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Union
import yaml
import json
from datetime import datetime

@dataclass
class SigmaRule:
    title: str
    id: str
    status: str  # experimental, test, stable
    description: str
    references: List[str]
    author: str
    date: str
    tags: List[str]  # MITRE ATT&CK tags
    logsource: Dict  # product, category, service
    detection: Dict  # selection, filter, condition
    falsepositives: List[str]
    level: str  # informational, low, medium, high, critical
    
class SigmaRuleBuilder:
    def __init__(self):
        self.rules = []
        
    def build_process_creation_rule(
        self,
        title: str,
        description: str,
        process_patterns: List[str],
        cmdline_patterns: List[str],
        mitre_tags: List[str],
        level: str = "high"
    ) -> str:
        """สร้าง SIGMA Rule สำหรับ Process Creation"""
        
        rule_dict = {
            "title": title,
            "id": self._generate_uuid(),
            "status": "experimental",
            "description": description,
            "references": ["https://attack.mitre.org/"],
            "author": "Security Team",
            "date": datetime.now().strftime("%Y/%m/%d"),
            "tags": [f"attack.{tag}" for tag in mitre_tags],
            "logsource": {
                "category": "process_creation",
                "product": "windows"
            },
            "detection": {},
            "falsepositives": ["Legitimate administrative activity"],
            "level": level
        }
        
        detection = {}
        
        if process_patterns:
            detection["selection_image"] = {
                "Image|endswith": process_patterns
            }
        
        if cmdline_patterns:
            detection["selection_cmdline"] = {
                "CommandLine|contains|any": cmdline_patterns
            }
        
        if process_patterns and cmdline_patterns:
            detection["condition"] = "selection_image and selection_cmdline"
        elif process_patterns:
            detection["condition"] = "selection_image"
        else:
            detection["condition"] = "selection_cmdline"
            
        rule_dict["detection"] = detection
        
        return yaml.dump(rule_dict, default_flow_style=False, sort_keys=False)
    
    def build_network_rule(
        self,
        title: str,
        description: str,
        dest_ports: List[int],
        process_names: List[str],
        mitre_tags: List[str],
        level: str = "medium"
    ) -> str:
        """สร้าง SIGMA Rule สำหรับ Network Connections"""
        
        rule_dict = {
            "title": title,
            "id": self._generate_uuid(),
            "status": "experimental",
            "description": description,
            "references": [],
            "author": "Security Team",
            "date": datetime.now().strftime("%Y/%m/%d"),
            "tags": [f"attack.{tag}" for tag in mitre_tags],
            "logsource": {
                "category": "network_connection",
                "product": "windows"
            },
            "detection": {
                "selection": {
                    "Image|endswith": process_names,
                    "DestinationPort": dest_ports
                },
                "condition": "selection"
            },
            "falsepositives": ["Legitimate software updates"],
            "level": level
        }
        
        return yaml.dump(rule_dict, default_flow_style=False, sort_keys=False)
    
    def build_file_creation_rule(
        self,
        title: str,
        description: str,
        file_patterns: List[str],
        directories: List[str],
        mitre_tags: List[str],
        level: str = "high"
    ) -> str:
        """สร้าง SIGMA Rule สำหรับ File Creation"""
        
        rule_dict = {
            "title": title,
            "id": self._generate_uuid(),
            "status": "experimental",
            "description": description,
            "references": [],
            "author": "Security Team",
            "date": datetime.now().strftime("%Y/%m/%d"),
            "tags": [f"attack.{tag}" for tag in mitre_tags],
            "logsource": {
                "category": "file_event",
                "product": "windows"
            },
            "detection": {
                "selection_ext": {
                    "TargetFilename|endswith": file_patterns
                },
                "selection_dir": {
                    "TargetFilename|contains": directories
                },
                "condition": "selection_ext and selection_dir"
            },
            "falsepositives": ["Software installation"],
            "level": level
        }
        
        return yaml.dump(rule_dict, default_flow_style=False, sort_keys=False)
    
    def _generate_uuid(self) -> str:
        import uuid
        return str(uuid.uuid4())
    
    def create_common_rules(self) -> List[str]:
        """สร้าง Common Detection Rules สำหรับ ATT&CK Techniques"""
        rules = []
        
        # Mimikatz Detection
        mimikatz_rule = self.build_process_creation_rule(
            title="Mimikatz Command Line",
            description="Detects common Mimikatz usage patterns in command line",
            process_patterns=["\\mimikatz.exe", "\\mimilib.exe"],
            cmdline_patterns=[
                "sekurlsa::", "kerberos::", "lsadump::",
                "privilege::debug", "process::suspend"
            ],
            mitre_tags=["credential_access", "t1003"],
            level="critical"
        )
        rules.append(("mimikatz_detection", mimikatz_rule))
        
        # PowerShell Encoded Command
        ps_enc_rule = self.build_process_creation_rule(
            title="PowerShell Encoded Command Execution",
            description="Detects PowerShell with Base64 encoded commands",
            process_patterns=["\\powershell.exe", "\\pwsh.exe"],
            cmdline_patterns=[
                " -enc ", " -EncodedCommand ", "-e ", "-en ",
                "FromBase64String"
            ],
            mitre_tags=["execution", "t1059.001"],
            level="high"
        )
        rules.append(("ps_encoded_command", ps_enc_rule))
        
        # Suspicious Network Connections from Office
        office_network_rule = self.build_network_rule(
            title="Office Applications Initiating Network Connections",
            description="Detects Office apps making suspicious outbound connections",
            dest_ports=[4444, 5555, 8080, 8443, 9001, 9090],
            process_names=["\\winword.exe", "\\excel.exe", "\\powerpnt.exe", "\\outlook.exe"],
            mitre_tags=["initial_access", "t1566"],
            level="high"
        )
        rules.append(("office_network", office_network_rule))
        
        # Suspicious Startup Files
        startup_rule = self.build_file_creation_rule(
            title="Suspicious File in Startup Folder",
            description="Detects file creation in startup locations",
            file_patterns=[".exe", ".bat", ".vbs", ".ps1", ".lnk", ".scr"],
            directories=[
                "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
                "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
            ],
            mitre_tags=["persistence", "t1547.001"],
            level="medium"
        )
        rules.append(("startup_persistence", startup_rule))
        
        return rules


class SigmaConverter:
    """แปลง SIGMA Rules เป็น Query ภาษาต่างๆ"""
    
    def to_splunk(self, sigma_yaml: str) -> str:
        rule = yaml.safe_load(sigma_yaml)
        detection = rule.get("detection", {})
        condition = detection.get("condition", "")
        
        queries = []
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                sub_queries = []
                for field_name, patterns in value.items():
                    if isinstance(patterns, list):
                        if "|contains" in field_name or "|endswith" in field_name:
                            base_field = field_name.split("|")[0]
                            or_parts = " OR ".join([f'{base_field}="*{p}"' for p in patterns])
                            sub_queries.append(f"({or_parts})")
                if sub_queries:
                    queries.append(" AND ".join(sub_queries))
        
        logsource = rule.get("logsource", {})
        index_map = {
            "process_creation": "index=windows EventCode=4688",
            "network_connection": "index=network",
            "file_event": "index=windows EventCode=4663"
        }
        
        base = index_map.get(logsource.get("category", ""), "index=*")
        search = " AND ".join(queries) if queries else "*"
        
        return f"{base} {search} | table _time, ComputerName, CommandLine"
    
    def to_elastic_kql(self, sigma_yaml: str) -> str:
        rule = yaml.safe_load(sigma_yaml)
        detection = rule.get("detection", {})
        
        kql_parts = []
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                for field_name, patterns in value.items():
                    if isinstance(patterns, list):
                        base_field = field_name.split("|")[0]
                        elastic_field = base_field.lower().replace("image", "process.executable")
                        or_parts = " OR ".join([f'{elastic_field}: "{p}"' for p in patterns])
                        kql_parts.append(f"({or_parts})")
        
        return " AND ".join(kql_parts) if kql_parts else "*"


if __name__ == '__main__':
    builder = SigmaRuleBuilder()
    rules = builder.create_common_rules()
    
    converter = SigmaConverter()
    
    for name, rule_yaml in rules:
        print(f"\n{'='*60}")
        print(f"Rule: {name}")
        print("SIGMA YAML:")
        print(rule_yaml[:500] + "...")
        print("\nSplunk Query:")
        print(converter.to_splunk(rule_yaml))
        print("\nElastic KQL:")
        print(converter.to_elastic_kql(rule_yaml))
```

---

## Step 633: Yara Rule Development

```python
#!/usr/bin/env python3
# YARA Rule Builder - สร้าง YARA Rules สำหรับ Malware Detection

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import hashlib
import re

@dataclass
class YaraString:
    name: str
    value: str
    string_type: str = "text"  # text, hex, regex
    modifiers: List[str] = field(default_factory=list)  # nocase, wide, fullword, ascii

@dataclass 
class YaraRule:
    name: str
    meta: Dict[str, str]
    strings: List[YaraString]
    condition: str
    tags: List[str] = field(default_factory=list)

class YaraRuleBuilder:
    def __init__(self):
        self.rules = []
    
    def build_rule(self, rule: YaraRule) -> str:
        """แปลง YaraRule object เป็น YARA syntax"""
        lines = []
        
        tag_str = " : " + " ".join(rule.tags) if rule.tags else ""
        lines.append(f"rule {rule.name}{tag_str} {{")
        
        if rule.meta:
            lines.append("  meta:")
            for key, value in rule.meta.items():
                lines.append(f'    {key} = "{value}"')
        
        if rule.strings:
            lines.append("  strings:")
            for s in rule.strings:
                modifier_str = " ".join(s.modifiers) if s.modifiers else ""
                if s.string_type == "hex":
                    lines.append(f"    ${s.name} = {{{ s.value }}} {modifier_str}".rstrip())
                elif s.string_type == "regex":
                    lines.append(f"    ${s.name} = /{s.value}/ {modifier_str}".rstrip())
                else:
                    lines.append(f'    ${s.name} = "{s.value}" {modifier_str}'.rstrip())
        
        lines.append("  condition:")
        lines.append(f"    {rule.condition}")
        lines.append("}")
        
        return "\n".join(lines)
    
    def create_mimikatz_rule(self) -> str:
        rule = YaraRule(
            name="Mimikatz_Detection",
            tags=["credential_theft", "T1003"],
            meta={
                "description": "Detects Mimikatz credential dumping tool",
                "author": "Security Team",
                "date": "2024-01-01",
                "reference": "https://github.com/gentilkiwi/mimikatz",
                "severity": "critical"
            },
            strings=[
                YaraString("sekurlsa", "sekurlsa::logonpasswords", modifiers=["nocase", "wide", "ascii"]),
                YaraString("kerberos", "kerberos::ptt", modifiers=["nocase", "wide", "ascii"]),
                YaraString("lsadump", "lsadump::sam", modifiers=["nocase", "wide", "ascii"]),
                YaraString("privilege", "privilege::debug", modifiers=["nocase", "wide", "ascii"]),
                YaraString("gentilkiwi", "gentilkiwi", modifiers=["nocase", "wide", "ascii"]),
                YaraString("wce_magic", "WCE SERVICE", modifiers=["ascii", "wide"]),
                YaraString("hex_sig", 
                          "60 48 8B CE 48 8B C3 48 8B D5 48 8B F8 FF D0",
                          string_type="hex")
            ],
            condition="($sekurlsa or $kerberos or $lsadump or $privilege) and ($gentilkiwi or $wce_magic) or $hex_sig"
        )
        return self.build_rule(rule)
    
    def create_ransomware_rule(self) -> str:
        rule = YaraRule(
            name="Generic_Ransomware",
            tags=["ransomware", "T1486"],
            meta={
                "description": "Generic ransomware detection based on behavioral indicators",
                "author": "Security Team",
                "date": "2024-01-01",
                "severity": "critical"
            },
            strings=[
                YaraString("ransom_note1", "YOUR FILES HAVE BEEN ENCRYPTED", modifiers=["nocase", "ascii", "wide"]),
                YaraString("ransom_note2", "All your files are encrypted", modifiers=["nocase", "ascii", "wide"]),
                YaraString("ransom_note3", "send bitcoin", modifiers=["nocase", "ascii", "wide"]),
                YaraString("tor_link", ".onion", modifiers=["nocase", "ascii"]),
                YaraString("vss_delete", "vssadmin delete shadows", modifiers=["nocase", "ascii", "wide"]),
                YaraString("bcdedit", "bcdedit /set {default} recoveryenabled No", modifiers=["nocase", "ascii", "wide"]),
                YaraString("crypto_import", 
                          "43 72 79 70 74 49 6D 70 6F 72 74 4B 65 79",
                          string_type="hex"),
                YaraString("file_enum", r"\*\.(jpg|png|doc|docx|xls|pdf|db|zip)",
                          string_type="regex", modifiers=["nocase"])
            ],
            condition="(2 of ($ransom_note*)) or ($vss_delete and $bcdedit) or ($crypto_import and $file_enum)"
        )
        return self.build_rule(rule)
    
    def create_webshell_rule(self) -> str:
        rule = YaraRule(
            name="PHP_Webshell",
            tags=["webshell", "T1505.003"],
            meta={
                "description": "Detects common PHP webshell patterns",
                "author": "Security Team",
                "date": "2024-01-01",
                "severity": "high"
            },
            strings=[
                YaraString("eval_base64", "eval(base64_decode(", modifiers=["nocase", "ascii"]),
                YaraString("eval_gzinflate", "eval(gzinflate(", modifiers=["nocase", "ascii"]),
                YaraString("preg_replace_e", "preg_replace('/.*/e'", modifiers=["nocase", "ascii"]),
                YaraString("system_cmd", "system($_", modifiers=["ascii"]),
                YaraString("exec_cmd", "exec($_", modifiers=["ascii"]),
                YaraString("passthru", "passthru($_", modifiers=["ascii"]),
                YaraString("shell_exec", "shell_exec($_", modifiers=["ascii"]),
                YaraString("php_uname", "php_uname()", modifiers=["nocase", "ascii"]),
                YaraString("c99", "c99shell", modifiers=["nocase", "ascii"]),
                YaraString("r57", "r57shell", modifiers=["nocase", "ascii"])
            ],
            condition="$eval_base64 or $eval_gzinflate or $preg_replace_e or (2 of ($system_cmd, $exec_cmd, $passthru, $shell_exec)) or $c99 or $r57"
        )
        return self.build_rule(rule)
    
    def create_c2_beacon_rule(self) -> str:
        rule = YaraRule(
            name="CobaltStrike_Beacon",
            tags=["c2", "cobalt_strike", "T1573"],
            meta={
                "description": "Detects CobaltStrike beacon payload",
                "author": "Security Team",
                "date": "2024-01-01",
                "severity": "critical"
            },
            strings=[
                YaraString("cs_magic",
                          "2E 2F 61 70 70 2E 6A 73 00 2F 6A 73 2F 6A 71 75 65 72 79",
                          string_type="hex"),
                YaraString("cs_prepend1", "%s (admin)", modifiers=["ascii"]),
                YaraString("cs_prepend2", "post - www form", modifiers=["nocase", "ascii"]),
                YaraString("cs_useragent", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1)",
                          modifiers=["ascii"]),
                YaraString("cs_named_pipe", r"\\.\pipe\msagent_", modifiers=["ascii", "wide"])
            ],
            condition="($cs_magic) or (2 of ($cs_prepend*, $cs_useragent, $cs_named_pipe))"
        )
        return self.build_rule(rule)
    
    def scan_file_with_rules(self, filepath: str, rules: List[str]) -> Dict:
        """Scan file กับ YARA rules (ต้องการ yara-python)"""
        try:
            import yara
            results = {"file": filepath, "matches": []}
            
            for rule_text in rules:
                try:
                    compiled = yara.compile(source=rule_text)
                    matches = compiled.match(filepath)
                    for match in matches:
                        results["matches"].append({
                            "rule": match.rule,
                            "tags": match.tags,
                            "strings": [(s.identifier, s.instances) for s in match.strings]
                        })
                except yara.Error as e:
                    results["error"] = str(e)
            
            return results
        except ImportError:
            return {"error": "yara-python not installed. Run: pip install yara-python"}


if __name__ == '__main__':
    builder = YaraRuleBuilder()
    
    print("=== Mimikatz Detection Rule ===")
    print(builder.create_mimikatz_rule())
    
    print("\n=== Ransomware Detection Rule ===")
    print(builder.create_ransomware_rule())
    
    print("\n=== PHP Webshell Detection Rule ===")
    print(builder.create_webshell_rule())
    
    print("\n=== CobaltStrike Beacon Rule ===")
    print(builder.create_c2_beacon_rule())
```

---

## Step 634: ELK Stack Detection

```python
#!/usr/bin/env python3
# ELK Stack Detection Engineering - สร้าง Detection ใน Elasticsearch

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import json
import requests
from datetime import datetime

@dataclass
class ElasticAlert:
    name: str
    index_pattern: str
    query: Dict
    aggregations: Optional[Dict]
    threshold: int
    time_window: str  # 5m, 1h, 24h
    severity: str
    mitre_tactic: str
    response_actions: List[str]

class ELKDetectionEngine:
    def __init__(self, es_url: str = "http://localhost:9200", kibana_url: str = "http://localhost:5601"):
        self.es_url = es_url
        self.kibana_url = kibana_url
        self.headers = {"Content-Type": "application/json"}
    
    def create_detection_rule(self, alert: ElasticAlert) -> Dict:
        """สร้าง Kibana SIEM Detection Rule"""
        rule = {
            "name": alert.name,
            "description": f"Detects {alert.name} - MITRE: {alert.mitre_tactic}",
            "risk_score": self._severity_to_risk_score(alert.severity),
            "severity": alert.severity,
            "type": "query",
            "index": [alert.index_pattern],
            "query": json.dumps(alert.query),
            "language": "kuery",
            "enabled": True,
            "from": f"now-{alert.time_window}",
            "interval": "5m",
            "max_signals": 100,
            "tags": [alert.mitre_tactic],
            "threat": self._build_threat_mapping(alert.mitre_tactic),
            "references": [f"https://attack.mitre.org/techniques/{alert.mitre_tactic.replace('.', '/')}/"]
        }
        return rule
    
    def _severity_to_risk_score(self, severity: str) -> int:
        mapping = {"low": 25, "medium": 47, "high": 73, "critical": 99}
        return mapping.get(severity.lower(), 50)
    
    def _build_threat_mapping(self, mitre_id: str) -> List[Dict]:
        return [{
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": "TA0002",
                "name": "Execution",
                "reference": "https://attack.mitre.org/tactics/TA0002/"
            },
            "technique": [{
                "id": mitre_id,
                "name": "Windows Command Shell",
                "reference": f"https://attack.mitre.org/techniques/{mitre_id}/"
            }]
        }]
    
    def get_predefined_alerts(self) -> List[ElasticAlert]:
        """ชุด Detection Rules ที่พร้อมใช้"""
        return [
            ElasticAlert(
                name="Suspicious PowerShell Execution",
                index_pattern="logs-endpoint.events.process-*",
                query={
                    "bool": {
                        "must": [
                            {"match": {"process.name": "powershell.exe"}},
                            {"wildcard": {"process.command_line": "*-enc*"}}
                        ]
                    }
                },
                aggregations=None,
                threshold=1,
                time_window="5m",
                severity="high",
                mitre_tactic="T1059.001",
                response_actions=[
                    "Isolate endpoint",
                    "Capture process memory",
                    "Review script content"
                ]
            ),
            ElasticAlert(
                name="LSASS Memory Access",
                index_pattern="logs-endpoint.events.process-*",
                query={
                    "bool": {
                        "must": [
                            {"match": {"event.action": "process_accessed"}},
                            {"match": {"process.name": "lsass.exe"}}
                        ],
                        "must_not": [
                            {"terms": {"process.parent.name": ["werfault.exe", "wmiprvse.exe", "svchost.exe"]}}
                        ]
                    }
                },
                aggregations=None,
                threshold=1,
                time_window="1m",
                severity="critical",
                mitre_tactic="T1003.001",
                response_actions=[
                    "IMMEDIATE: Isolate host",
                    "Reset all domain credentials",
                    "Enable Enhanced LSA Protection",
                    "Check for lateral movement"
                ]
            ),
            ElasticAlert(
                name="Beaconing Detection - Periodic C2",
                index_pattern="logs-network_traffic.*",
                query={
                    "bool": {
                        "must": [
                            {"range": {"destination.port": {"gte": 1024}}}
                        ],
                        "must_not": [
                            {"terms": {"destination.ip": ["8.8.8.8", "1.1.1.1"]}}
                        ]
                    }
                },
                aggregations={
                    "connections": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "1m"
                        }
                    }
                },
                threshold=100,
                time_window="1h",
                severity="high",
                mitre_tactic="T1071.001",
                response_actions=[
                    "Block destination IP on firewall",
                    "Capture network traffic",
                    "Analyze beacon interval"
                ]
            )
        ]
    
    def deploy_rules(self, alerts: List[ElasticAlert]) -> List[Dict]:
        """Deploy Detection Rules ไปยัง Kibana SIEM"""
        results = []
        
        for alert in alerts:
            rule_config = self.create_detection_rule(alert)
            
            try:
                response = requests.post(
                    f"{self.kibana_url}/api/detection_engine/rules",
                    headers={**self.headers, "kbn-xsrf": "true"},
                    json=rule_config,
                    timeout=10
                )
                results.append({
                    "rule": alert.name,
                    "status": "deployed" if response.status_code == 200 else "failed",
                    "id": response.json().get("id", "")
                })
            except Exception as e:
                results.append({"rule": alert.name, "status": "error", "error": str(e)})
        
        return results
    
    def search_for_threats(self, query: Dict, index: str = "*", time_range: str = "24h") -> Dict:
        """ค้นหา Threats ใน Elasticsearch"""
        search_body = {
            "query": {
                "bool": {
                    "must": [query],
                    "filter": [{"range": {"@timestamp": {"gte": f"now-{time_range}"}}}]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 100
        }
        
        try:
            response = requests.post(
                f"{self.es_url}/{index}/_search",
                headers=self.headers,
                json=search_body,
                timeout=10
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}


if __name__ == '__main__':
    engine = ELKDetectionEngine()
    alerts = engine.get_predefined_alerts()
    
    print("Available Detection Rules:")
    for alert in alerts:
        rule = engine.create_detection_rule(alert)
        print(f"\n{alert.name} ({alert.severity.upper()})")
        print(f"  MITRE: {alert.mitre_tactic}")
        print(f"  Time Window: {alert.time_window}")
        print(f"  Response Actions: {len(alert.response_actions)} defined")
        print(f"  Risk Score: {rule['risk_score']}")
```

---

## Step 635: Windows Event Log Analysis

```python
#!/usr/bin/env python3
# Windows Event Log Threat Detection - วิเคราะห์ Windows Events เพื่อหาภัยคุกคาม

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import xml.etree.ElementTree as ET
from datetime import datetime
import json

@dataclass
class SecurityEvent:
    event_id: int
    time_created: str
    computer: str
    user: str
    event_data: Dict
    severity: str = "info"
    alert: Optional[str] = None

class WindowsEventAnalyzer:
    """
    Critical Windows Security Event IDs:
    4624 - Successful logon
    4625 - Failed logon
    4648 - Explicit credentials logon
    4688 - Process creation
    4698 - Scheduled task created
    4702 - Scheduled task modified
    4720 - User account created
    4728/4732/4756 - Member added to privileged group
    4768/4769 - Kerberos ticket request
    4771 - Kerberos pre-auth failed
    7045 - Service installed
    """
    
    CRITICAL_EVENTS = {
        4624: "Successful Logon",
        4625: "Failed Logon",
        4648: "Logon with Explicit Credentials",
        4688: "Process Creation",
        4698: "Scheduled Task Created",
        4702: "Scheduled Task Modified",
        4720: "User Account Created",
        4722: "User Account Enabled",
        4724: "Password Reset Attempt",
        4728: "Member Added to Security-Enabled Global Group",
        4732: "Member Added to Security-Enabled Local Group",
        4756: "Member Added to Security-Enabled Universal Group",
        4768: "Kerberos TGT Requested",
        4769: "Kerberos Service Ticket Requested",
        4771: "Kerberos Pre-authentication Failed",
        4776: "NTLM Authentication Attempt",
        5140: "Network Share Accessed",
        7045: "Service Installed"
    }
    
    BRUTE_FORCE_THRESHOLD = 10
    
    def __init__(self):
        self.events = []
        self.failed_logins = {}  # user -> count
        self.new_services = []
        self.privileged_group_changes = []
        
    def parse_event_xml(self, xml_string: str) -> Optional[SecurityEvent]:
        """Parse Windows Event XML format"""
        try:
            root = ET.fromstring(xml_string)
            ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            system = root.find('e:System', ns)
            event_id = int(system.find('e:EventID', ns).text)
            time_created = system.find('e:TimeCreated', ns).get('SystemTime', '')
            computer = system.find('e:Computer', ns).text
            
            event_data = {}
            data_elem = root.find('e:EventData', ns)
            if data_elem is not None:
                for data in data_elem.findall('e:Data', ns):
                    name = data.get('Name', '')
                    value = data.text or ''
                    event_data[name] = value
            
            user = event_data.get('SubjectUserName', event_data.get('TargetUserName', 'SYSTEM'))
            
            severity, alert = self._assess_event(event_id, event_data)
            
            return SecurityEvent(
                event_id=event_id,
                time_created=time_created,
                computer=computer,
                user=user,
                event_data=event_data,
                severity=severity,
                alert=alert
            )
        except ET.ParseError:
            return None
    
    def _assess_event(self, event_id: int, event_data: Dict) -> Tuple[str, Optional[str]]:
        """ประเมินความเสี่ยงของ Event"""
        
        if event_id == 4688:
            process = event_data.get('NewProcessName', '').lower()
            cmdline = event_data.get('CommandLine', '').lower()
            
            high_risk = ['mimikatz', 'procdump', 'pwdump', 'wce.exe']
            medium_risk = ['powershell', 'wscript', 'cscript', 'mshta']
            
            if any(r in process or r in cmdline for r in high_risk):
                return "critical", f"High-risk process: {event_data.get('NewProcessName', '')}"
            
            if any(r in process for r in medium_risk):
                if '-enc' in cmdline or '-encodedcommand' in cmdline:
                    return "high", f"Encoded PowerShell command detected"
                if 'downloadstring' in cmdline or 'invoke-expression' in cmdline:
                    return "high", f"PowerShell remote code execution pattern"
        
        elif event_id == 4625:
            user = event_data.get('TargetUserName', '')
            self.failed_logins[user] = self.failed_logins.get(user, 0) + 1
            if self.failed_logins[user] >= self.BRUTE_FORCE_THRESHOLD:
                return "high", f"Brute force detected: {self.failed_logins[user]} failures for {user}"
        
        elif event_id in [4728, 4732, 4756]:
            member = event_data.get('MemberName', '')
            group = event_data.get('GroupName', '')
            if any(g in group.lower() for g in ['domain admins', 'enterprise admins', 'administrators']):
                return "critical", f"User {member} added to privileged group {group}"
        
        elif event_id == 7045:
            service_name = event_data.get('ServiceName', '')
            service_path = event_data.get('ImagePath', '')
            if any(s in service_path.lower() for s in ['temp', 'appdata', 'programdata']):
                return "high", f"Suspicious service installed: {service_name} -> {service_path}"
        
        elif event_id == 4698:
            task_name = event_data.get('TaskName', '')
            task_content = event_data.get('TaskContent', '')
            if any(s in task_content.lower() for s in ['powershell', 'cmd', 'wscript', 'cscript']):
                return "medium", f"Scheduled task with script execution: {task_name}"
        
        return "info", None
    
    def analyze_logon_patterns(self, events: List[SecurityEvent]) -> Dict:
        """วิเคราะห์รูปแบบการ Logon ที่ผิดปกติ"""
        logon_events = [e for e in events if e.event_id in [4624, 4625, 4648]]
        
        analysis = {
            "failed_logins": {},
            "successful_logins": {},
            "off_hours_logins": [],
            "unusual_logon_types": [],
            "pass_the_hash_indicators": []
        }
        
        for event in logon_events:
            user = event.event_data.get('TargetUserName', 'unknown')
            logon_type = int(event.event_data.get('LogonType', 0))
            
            if event.event_id == 4625:
                analysis["failed_logins"][user] = analysis["failed_logins"].get(user, 0) + 1
            elif event.event_id == 4624:
                analysis["successful_logins"][user] = analysis["successful_logins"].get(user, 0) + 1
                
                # Check for off-hours (22:00 - 06:00)
                try:
                    event_time = datetime.fromisoformat(event.time_created[:19])
                    hour = event_time.hour
                    if hour >= 22 or hour <= 6:
                        analysis["off_hours_logins"].append({
                            "user": user,
                            "time": event.time_created,
                            "computer": event.computer
                        })
                except ValueError:
                    pass
                
                # Pass-the-Hash: LogonType=3 with NTLM authentication
                auth_pkg = event.event_data.get('AuthenticationPackageName', '')
                if logon_type == 3 and auth_pkg == 'NTLM':
                    analysis["pass_the_hash_indicators"].append({
                        "user": user,
                        "source": event.event_data.get('IpAddress', ''),
                        "time": event.time_created
                    })
        
        return analysis
    
    def generate_threat_report(self, events: List[SecurityEvent]) -> Dict:
        """สร้างรายงานภัยคุกคามจาก Windows Events"""
        critical_events = [e for e in events if e.severity == "critical"]
        high_events = [e for e in events if e.severity == "high"]
        
        report = {
            "summary": {
                "total_events": len(events),
                "critical_alerts": len(critical_events),
                "high_alerts": len(high_events),
                "unique_computers": len(set(e.computer for e in events)),
                "analysis_time": datetime.now().isoformat()
            },
            "critical_findings": [
                {
                    "event_id": e.event_id,
                    "time": e.time_created,
                    "computer": e.computer,
                    "user": e.user,
                    "alert": e.alert
                }
                for e in critical_events
            ],
            "logon_analysis": self.analyze_logon_patterns(events),
            "recommended_actions": self._get_recommendations(critical_events, high_events)
        }
        
        return report
    
    def _get_recommendations(self, critical: List, high: List) -> List[str]:
        recommendations = []
        
        if any("privileged group" in (e.alert or "") for e in critical):
            recommendations.append("Review all privileged group memberships immediately")
        
        if any("Brute force" in (e.alert or "") for e in high):
            recommendations.append("Enable account lockout policy and investigate source IPs")
        
        if any("Encoded PowerShell" in (e.alert or "") for e in high):
            recommendations.append("Enable PowerShell ScriptBlock logging and review scripts")
        
        if any("LSASS" in (e.alert or "") for e in critical):
            recommendations.append("Enable Credential Guard, isolate affected hosts")
        
        return recommendations


if __name__ == '__main__':
    analyzer = WindowsEventAnalyzer()
    
    print("Critical Windows Security Events:")
    for event_id, description in WindowsEventAnalyzer.CRITICAL_EVENTS.items():
        print(f"  Event {event_id}: {description}")
    
    print("\nEvent Analysis Framework Ready")
    print("Usage: analyzer.parse_event_xml(xml_string) -> SecurityEvent")
    print("       analyzer.analyze_logon_patterns(events) -> analysis dict")
    print("       analyzer.generate_threat_report(events) -> report dict")
```

---

## Step 636: Splunk Detection Queries

```bash
#!/bin/bash
# Splunk Threat Detection Queries - SPL Queries สำหรับหาภัยคุกคาม

# ========================================
# 1. CREDENTIAL DUMPING DETECTION
# ========================================
cat << 'EOF'
# LSASS Memory Access (Sysmon Event 10)
index=windows EventCode=10 TargetImage="*\lsass.exe"
| where GrantedAccess IN ("0x1010", "0x1410", "0x143a", "0x40", "0x1fffff")
| where SourceImage!="*\MsMpEng.exe" AND SourceImage!="*\werfault.exe"
| eval risk_score=case(
    like(GrantedAccess, "0x1fffff"), 100,
    like(GrantedAccess, "0x1410"), 90,
    1==1, 70
  )
| table _time, ComputerName, SourceImage, TargetImage, GrantedAccess, risk_score
| sort -risk_score
EOF

# ========================================
# 2. LATERAL MOVEMENT DETECTION
# ========================================
cat << 'EOF'
# PsExec / Remote Service Creation
index=windows (EventCode=7045 OR EventCode=4624)
| eval logon_type=if(EventCode=4624, LogonType, null())
| eval service=if(EventCode=7045, ServiceName, null())
| eval source_ip=if(EventCode=4624, IpAddress, null())
| stats values(logon_type) as logon_types, values(service) as services,
        values(source_ip) as source_ips by ComputerName, span=5m
| where isnotnull(services) AND isnotnull(logon_types)
| eval logon_3=mvfind(logon_types, "3")
| where isnotnull(logon_3)
| table _time, ComputerName, services, source_ips, logon_types
EOF

# ========================================
# 3. BEACONING C2 DETECTION
# ========================================
cat << 'EOF'
# Statistical Beaconing Detection
index=network dest_port!=80 dest_port!=443
| bucket _time span=1m
| stats count by _time, src_ip, dest_ip, dest_port
| eventstats avg(count) as avg_conn, stdev(count) as stdev_conn by src_ip, dest_ip, dest_port
| eval jitter=stdev_conn/avg_conn
| eval beacon_score=case(
    jitter < 0.1, 100,
    jitter < 0.3, 75,
    jitter < 0.5, 50,
    1==1, 0
  )
| where beacon_score >= 75 AND count > 50
| stats max(beacon_score) as max_score, sum(count) as total_connections
  by src_ip, dest_ip, dest_port
| sort -max_score
EOF

# ========================================
# 4. DATA EXFILTRATION DETECTION
# ========================================
cat << 'EOF'
# Large Data Transfer Detection
index=network
| stats sum(bytes_out) as total_bytes_out, 
        sum(bytes_in) as total_bytes_in,
        count as connection_count
  by src_ip, dest_ip
  span=1h
| eval exfil_ratio=total_bytes_out/total_bytes_in
| eval total_gb=total_bytes_out/1073741824
| where (total_gb > 1) OR (exfil_ratio > 10 AND total_bytes_out > 104857600)
| eval risk=case(
    total_gb > 10, "CRITICAL",
    total_gb > 5, "HIGH",
    1==1, "MEDIUM"
  )
| table _time, src_ip, dest_ip, total_gb, exfil_ratio, connection_count, risk
| sort -total_gb
EOF

# ========================================
# 5. PRIVILEGED ACCOUNT MONITORING
# ========================================
cat << 'EOF'
# Privileged Account Usage Anomaly
index=windows EventCode=4672
| lookup privileged_accounts.csv username AS Account_Name OUTPUT is_privileged
| stats count by Account_Name, Computer, _time span=1h
| eventstats avg(count) as avg_hourly_logins by Account_Name
| where count > avg_hourly_logins * 3
| eval anomaly_score=(count/avg_hourly_logins) * 100
| where anomaly_score > 300
| table _time, Account_Name, Computer, count, avg_hourly_logins, anomaly_score
| sort -anomaly_score
EOF

# ========================================
# 6. POWERSHELL ATTACK DETECTION
# ========================================
cat << 'EOF'
# Suspicious PowerShell with AMSI Bypass
index=windows EventCode=4104
| rex field=ScriptBlockText "(?i)(?<bypass>amsiutils|reflection.assembly|bypass|invoke-expression|iex)"
| rex field=ScriptBlockText "(?i)(?<download>downloadstring|webclient|invoke-webrequest)"
| where isnotnull(bypass) OR (isnotnull(download) AND len(ScriptBlockText) > 500)
| eval obfuscation_score=case(
    match(ScriptBlockText, "[A-Za-z]{1}[+]{1}[A-Za-z]{1}"), 30,
    match(ScriptBlockText, "\[char\]"), 40,
    match(ScriptBlockText, "-join"), 20,
    1==1, 0
  )
| where obfuscation_score > 0 OR isnotnull(bypass)
| table _time, ComputerName, UserName, bypass, download, obfuscation_score, ScriptBlockText
| sort -obfuscation_score
EOF

echo "Splunk SPL Queries ready for threat detection"
echo "Import these into Splunk Saved Searches or Alerts"
echo ""
echo "Key Event IDs to monitor:"
echo "  4688 - Process Creation (requires Audit Process Creation)"
echo "  4624/4625 - Logon Success/Failure"
echo "  4698/4702 - Scheduled Task Created/Modified"
echo "  7045 - Service Installed"
echo "  4104 - PowerShell Script Block Logging"
echo "  1 - Sysmon Process Create"
echo "  10 - Sysmon Process Access"
```

---

## Step 637: Network Traffic Analysis

```python
#!/usr/bin/env python3
# Network Traffic Threat Analysis - วิเคราะห์ Traffic เพื่อหาภัยคุกคาม

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import statistics
import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta
import json

@dataclass
class NetworkFlow:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int
    bytes_recv: int
    duration: float
    flags: str = ""

class NetworkThreatAnalyzer:
    def __init__(self):
        self.flows: List[NetworkFlow] = []
        self.threat_intel: Dict[str, str] = {}  # IP -> threat type
        self.whitelist_ips = set()
        self.whitelist_domains = set()
        
    def load_threat_intel(self, intel_file: str):
        """โหลด Threat Intelligence IOCs"""
        try:
            with open(intel_file, 'r') as f:
                data = json.load(f)
                self.threat_intel = data.get('ips', {})
        except FileNotFoundError:
            # Load sample threat intel
            self.threat_intel = {
                "192.168.100.200": "c2_server",
                "10.0.0.254": "malware_distribution",
            }
    
    def detect_port_scan(self, time_window: int = 60) -> List[Dict]:
        """ตรวจหา Port Scan โดยดูจำนวน Unique Ports ต่อ Source IP"""
        findings = []
        scanner_data = defaultdict(set)  # src_ip -> set of (dst_ip, dst_port)
        
        current_time = datetime.now().timestamp()
        window_flows = [f for f in self.flows 
                       if current_time - f.timestamp <= time_window]
        
        for flow in window_flows:
            scanner_data[flow.src_ip].add((flow.dst_ip, flow.dst_port))
        
        for src_ip, targets in scanner_data.items():
            unique_ports = len(set(t[1] for t in targets))
            unique_hosts = len(set(t[0] for t in targets))
            
            if unique_ports > 20:  # Port scan threshold
                scan_type = "vertical_scan" if unique_hosts < 3 else "distributed_scan"
                findings.append({
                    "type": "port_scan",
                    "src_ip": src_ip,
                    "unique_ports": unique_ports,
                    "unique_hosts": unique_hosts,
                    "scan_type": scan_type,
                    "severity": "medium" if unique_ports < 100 else "high",
                    "sampled_ports": list(set(t[1] for t in targets))[:20]
                })
        
        return findings
    
    def detect_beaconing(self, min_connections: int = 50, max_jitter: float = 0.2) -> List[Dict]:
        """ตรวจหา C2 Beaconing โดยวิเคราะห์ความสม่ำเสมอของการเชื่อมต่อ"""
        findings = []
        connection_times = defaultdict(list)
        
        for flow in self.flows:
            key = (flow.src_ip, flow.dst_ip, flow.dst_port)
            connection_times[key].append(flow.timestamp)
        
        for (src_ip, dst_ip, dst_port), timestamps in connection_times.items():
            if len(timestamps) < min_connections:
                continue
            
            timestamps.sort()
            intervals = [timestamps[i+1] - timestamps[i] 
                        for i in range(len(timestamps)-1)]
            
            if not intervals:
                continue
            
            avg_interval = statistics.mean(intervals)
            if avg_interval == 0:
                continue
                
            try:
                stdev_interval = statistics.stdev(intervals)
            except statistics.StatisticsError:
                continue
                
            jitter = stdev_interval / avg_interval
            
            if jitter <= max_jitter:
                # Check if destination is in threat intel
                threat_type = self.threat_intel.get(dst_ip, "unknown")
                
                findings.append({
                    "type": "beaconing",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "connections": len(timestamps),
                    "avg_interval_seconds": round(avg_interval, 2),
                    "jitter_coefficient": round(jitter, 4),
                    "threat_intel_match": threat_type if threat_type != "unknown" else None,
                    "severity": "critical" if threat_type != "unknown" else "high"
                })
        
        return findings
    
    def detect_data_exfiltration(self, threshold_bytes: int = 50_000_000) -> List[Dict]:
        """ตรวจหา Data Exfiltration จากปริมาณ Traffic ขาออกที่ผิดปกติ"""
        findings = []
        outbound_bytes = defaultdict(int)  # (src_ip, dst_ip) -> bytes
        outbound_flows = defaultdict(int)
        
        for flow in self.flows:
            if not ipaddress.ip_address(flow.dst_ip).is_private:
                key = (flow.src_ip, flow.dst_ip)
                outbound_bytes[key] += flow.bytes_sent
                outbound_flows[key] += 1
        
        for (src_ip, dst_ip), total_bytes in outbound_bytes.items():
            if total_bytes >= threshold_bytes:
                gb_transferred = total_bytes / (1024**3)
                
                findings.append({
                    "type": "data_exfiltration",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "bytes_transferred": total_bytes,
                    "gb_transferred": round(gb_transferred, 2),
                    "flow_count": outbound_flows[(src_ip, dst_ip)],
                    "threat_intel_match": self.threat_intel.get(dst_ip),
                    "severity": "critical" if gb_transferred > 10 else "high"
                })
        
        return sorted(findings, key=lambda x: x['bytes_transferred'], reverse=True)
    
    def detect_dns_tunneling(self, dns_flows: List[Dict]) -> List[Dict]:
        """ตรวจหา DNS Tunneling โดยวิเคราะห์ DNS Query patterns"""
        findings = []
        domain_queries = defaultdict(list)  # base_domain -> list of subdomains
        
        for flow in dns_flows:
            domain = flow.get('query', '')
            parts = domain.split('.')
            
            if len(parts) >= 3:
                base_domain = '.'.join(parts[-2:])
                subdomain = '.'.join(parts[:-2])
                domain_queries[base_domain].append(subdomain)
        
        for base_domain, subdomains in domain_queries.items():
            if len(subdomains) < 10:
                continue
            
            avg_subdomain_len = statistics.mean(len(s) for s in subdomains)
            unique_subdomains = len(set(subdomains))
            
            # DNS tunneling typically has many unique long subdomains
            if avg_subdomain_len > 20 and unique_subdomains > 50:
                findings.append({
                    "type": "dns_tunneling",
                    "base_domain": base_domain,
                    "total_queries": len(subdomains),
                    "unique_subdomains": unique_subdomains,
                    "avg_subdomain_length": round(avg_subdomain_len, 1),
                    "sample_subdomains": subdomains[:5],
                    "severity": "high"
                })
        
        return findings
    
    def generate_network_threat_report(self) -> Dict:
        """สร้างรายงาน Network Threats"""
        port_scans = self.detect_port_scan()
        beaconing = self.detect_beaconing()
        exfiltration = self.detect_data_exfiltration()
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_flows_analyzed": len(self.flows),
            "threats_detected": {
                "port_scans": len(port_scans),
                "beaconing_indicators": len(beaconing),
                "exfiltration_indicators": len(exfiltration)
            },
            "critical_findings": [
                f for f in (port_scans + beaconing + exfiltration)
                if f.get('severity') == 'critical'
            ],
            "all_findings": {
                "port_scans": port_scans,
                "beaconing": beaconing,
                "exfiltration": exfiltration
            }
        }


if __name__ == '__main__':
    analyzer = NetworkThreatAnalyzer()
    
    import random
    import time
    
    # Simulate beaconing traffic
    beacon_time = time.time() - 3600
    for i in range(60):
        analyzer.flows.append(NetworkFlow(
            timestamp=beacon_time + (i * 60) + random.uniform(-2, 2),
            src_ip="10.0.0.5",
            dst_ip="198.51.100.1",
            src_port=random.randint(49152, 65535),
            dst_port=443,
            protocol="TCP",
            bytes_sent=1024,
            bytes_recv=512,
            duration=0.5
        ))
    
    report = analyzer.generate_network_threat_report()
    print(json.dumps(report, indent=2))
```

---

## Step 638: Threat Intelligence Integration

```python
#!/usr/bin/env python3
# Threat Intelligence Platform - รวม Threat Intel จากหลายแหล่ง

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
import requests
import hashlib
import json
from datetime import datetime

@dataclass
class ThreatIndicator:
    ioc_type: str  # ip, domain, hash, url
    value: str
    confidence: int  # 0-100
    severity: str
    source: str
    tags: List[str]
    first_seen: str
    last_seen: str
    description: str = ""
    
class ThreatIntelligencePlatform:
    def __init__(self):
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.api_keys = {}
        
    def check_virustotal(self, ioc: str, ioc_type: str, api_key: str) -> Dict:
        """ตรวจสอบ IOC กับ VirusTotal"""
        endpoints = {
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
            "hash": f"https://www.virustotal.com/api/v3/files/{ioc}",
            "url": "https://www.virustotal.com/api/v3/urls"
        }
        
        headers = {"x-apikey": api_key}
        
        try:
            url = endpoints.get(ioc_type, endpoints["ip"])
            
            if ioc_type == "url":
                response = requests.post(
                    url, 
                    headers=headers,
                    data={"url": ioc},
                    timeout=10
                )
            else:
                response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    "source": "VirusTotal",
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "clean": stats.get('harmless', 0),
                    "reputation": data.get('data', {}).get('attributes', {}).get('reputation', 0)
                }
        except Exception as e:
            return {"error": str(e)}
        
        return {"error": f"HTTP {response.status_code}"}
    
    def check_abuse_ipdb(self, ip: str, api_key: str) -> Dict:
        """ตรวจสอบ IP กับ AbuseIPDB"""
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    "source": "AbuseIPDB",
                    "abuse_confidence": data.get('abuseConfidenceScore', 0),
                    "total_reports": data.get('totalReports', 0),
                    "country": data.get('countryCode', ''),
                    "isp": data.get('isp', ''),
                    "domain": data.get('domain', ''),
                    "is_tor": data.get('isTor', False),
                    "categories": data.get('reports', [{}])[0].get('categories', []) if data.get('reports') else []
                }
        except Exception as e:
            return {"error": str(e)}
    
    def check_otx_alienvault(self, ioc: str, ioc_type: str, api_key: str) -> Dict:
        """ตรวจสอบ IOC กับ AlienVault OTX"""
        type_map = {"ip": "IPv4", "domain": "domain", "hash": "file", "url": "URL"}
        otx_type = type_map.get(ioc_type, "IPv4")
        
        try:
            response = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc}/general",
                headers={"X-OTX-API-KEY": api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "source": "OTX AlienVault",
                    "pulse_count": data.get('pulse_info', {}).get('count', 0),
                    "threat_score": data.get('base_indicator', {}).get('threat_score', 0),
                    "pulses": [
                        p.get('name', '') 
                        for p in data.get('pulse_info', {}).get('pulses', [])[:5]
                    ]
                }
        except Exception as e:
            return {"error": str(e)}
    
    def enrich_ioc(self, ioc: str, ioc_type: str, api_keys: Dict[str, str]) -> Dict:
        """รวบรวมข้อมูลจากทุก Threat Intel Sources"""
        enrichment = {
            "ioc": ioc,
            "type": ioc_type,
            "timestamp": datetime.now().isoformat(),
            "sources": {}
        }
        
        if "virustotal" in api_keys:
            enrichment["sources"]["virustotal"] = self.check_virustotal(
                ioc, ioc_type, api_keys["virustotal"]
            )
        
        if "abuseipdb" in api_keys and ioc_type == "ip":
            enrichment["sources"]["abuseipdb"] = self.check_abuse_ipdb(
                ioc, api_keys["abuseipdb"]
            )
        
        if "otx" in api_keys:
            enrichment["sources"]["otx"] = self.check_otx_alienvault(
                ioc, ioc_type, api_keys["otx"]
            )
        
        # Calculate overall risk score
        enrichment["risk_score"] = self._calculate_risk_score(enrichment["sources"])
        enrichment["verdict"] = self._get_verdict(enrichment["risk_score"])
        
        return enrichment
    
    def _calculate_risk_score(self, sources: Dict) -> int:
        score = 0
        count = 0
        
        vt = sources.get("virustotal", {})
        if "malicious" in vt:
            vt_score = min(vt["malicious"] * 10, 100)
            score += vt_score
            count += 1
        
        abip = sources.get("abuseipdb", {})
        if "abuse_confidence" in abip:
            score += abip["abuse_confidence"]
            count += 1
        
        otx = sources.get("otx", {})
        if "pulse_count" in otx:
            otx_score = min(otx["pulse_count"] * 5, 100)
            score += otx_score
            count += 1
        
        return int(score / count) if count > 0 else 0
    
    def _get_verdict(self, risk_score: int) -> str:
        if risk_score >= 80:
            return "MALICIOUS"
        elif risk_score >= 50:
            return "SUSPICIOUS"
        elif risk_score >= 20:
            return "POTENTIALLY_UNWANTED"
        return "CLEAN"
    
    def create_misp_event(self, iocs: List[Dict], event_info: str) -> Dict:
        """สร้าง MISP Event จาก IOCs"""
        attributes = []
        
        type_map = {
            "ip": "ip-dst",
            "domain": "domain",
            "hash": "md5",
            "url": "url",
            "email": "email-src"
        }
        
        for ioc in iocs:
            attributes.append({
                "type": type_map.get(ioc['type'], 'other'),
                "value": ioc['value'],
                "comment": ioc.get('description', ''),
                "to_ids": True,
                "distribution": 3  # All communities
            })
        
        return {
            "Event": {
                "info": event_info,
                "date": datetime.now().strftime("%Y-%m-%d"),
                "threat_level_id": "2",  # Medium
                "analysis": "2",  # Completed
                "distribution": "3",
                "Attribute": attributes
            }
        }


if __name__ == '__main__':
    platform = ThreatIntelligencePlatform()
    
    print("Threat Intelligence Platform initialized")
    print("Supported sources: VirusTotal, AbuseIPDB, OTX AlienVault, MISP")
    
    # Example enrichment (requires API keys)
    sample_ioc = {
        "ioc": "8.8.8.8",
        "type": "ip",
        "description": "Test IP - Google DNS"
    }
    
    print(f"\nSample IOC enrichment for: {sample_ioc['ioc']}")
    print("To enrich: platform.enrich_ioc(ioc, type, {'virustotal': 'API_KEY', 'abuseipdb': 'API_KEY'})")
    
    # Create sample MISP event
    test_iocs = [
        {"type": "ip", "value": "198.51.100.1", "description": "C2 Server"},
        {"type": "domain", "value": "evil.example.com", "description": "Malware C2 Domain"},
        {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e", "description": "Malicious binary"}
    ]
    
    misp_event = platform.create_misp_event(test_iocs, "APT Campaign - 2024")
    print("\nMISP Event:")
    print(json.dumps(misp_event, indent=2))
```

---

## Step 639: Detection Rule Testing & Validation

```python
#!/usr/bin/env python3
# Detection Rule Testing - ทดสอบและ Validate Detection Rules

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
import json
import re
from datetime import datetime

@dataclass
class TestCase:
    name: str
    description: str
    input_event: Dict
    expected_detection: bool
    expected_severity: Optional[str] = None
    test_type: str = "true_positive"  # true_positive, false_positive

@dataclass
class TestResult:
    test_case: TestCase
    actual_detection: bool
    actual_severity: Optional[str]
    passed: bool
    notes: str = ""

class DetectionRuleTester:
    def __init__(self):
        self.test_cases: List[TestCase] = []
        self.results: List[TestResult] = []
        
    def add_test_case(self, test_case: TestCase):
        self.test_cases.append(test_case)
    
    def run_test(self, rule_func: Callable, test_case: TestCase) -> TestResult:
        """รัน Test Case กับ Detection Rule"""
        try:
            result = rule_func(test_case.input_event)
            detected = result.get('detected', False)
            severity = result.get('severity', None)
            
            if test_case.test_type == "true_positive":
                passed = detected == test_case.expected_detection
                if test_case.expected_severity and passed:
                    passed = severity == test_case.expected_severity
            else:  # false_positive - should NOT detect
                passed = not detected
            
            return TestResult(
                test_case=test_case,
                actual_detection=detected,
                actual_severity=severity,
                passed=passed,
                notes=result.get('reason', '')
            )
        except Exception as e:
            return TestResult(
                test_case=test_case,
                actual_detection=False,
                actual_severity=None,
                passed=False,
                notes=f"Exception: {str(e)}"
            )
    
    def run_all_tests(self, rule_func: Callable) -> Dict:
        """รัน Test Cases ทั้งหมดและสรุปผล"""
        results = []
        for test_case in self.test_cases:
            result = self.run_test(rule_func, test_case)
            results.append(result)
        
        tp = sum(1 for r in results if r.test_case.test_type == "true_positive" and r.passed)
        fp = sum(1 for r in results if r.test_case.test_type == "false_positive" and r.passed)
        fn = sum(1 for r in results if r.test_case.test_type == "true_positive" and not r.passed)
        tn = sum(1 for r in results if r.test_case.test_type == "false_positive" and not r.passed)
        
        total_tp_cases = sum(1 for r in results if r.test_case.test_type == "true_positive")
        total_fp_cases = sum(1 for r in results if r.test_case.test_type == "false_positive")
        
        precision = tp / (tp + tn) if (tp + tn) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            "summary": {
                "total_tests": len(results),
                "passed": sum(1 for r in results if r.passed),
                "failed": sum(1 for r in results if not r.passed),
                "true_positives": tp,
                "false_positives_caught": fp,
                "false_negatives": fn
            },
            "metrics": {
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "f1_score": round(f1_score, 3),
                "tp_rate": round(tp/total_tp_cases, 3) if total_tp_cases else 0,
                "fp_rate": round((total_fp_cases-fp)/total_fp_cases, 3) if total_fp_cases else 0
            },
            "failed_tests": [
                {
                    "name": r.test_case.name,
                    "type": r.test_case.test_type,
                    "expected": r.test_case.expected_detection,
                    "actual": r.actual_detection,
                    "notes": r.notes
                }
                for r in results if not r.passed
            ],
            "grade": self._calculate_grade(f1_score)
        }
    
    def _calculate_grade(self, f1: float) -> str:
        if f1 >= 0.9:
            return "A - Excellent"
        elif f1 >= 0.8:
            return "B - Good"
        elif f1 >= 0.7:
            return "C - Acceptable"
        elif f1 >= 0.6:
            return "D - Needs Improvement"
        return "F - Poor"
    
    def create_mimikatz_test_suite(self) -> List[TestCase]:
        """ชุด Test Cases สำหรับ Mimikatz Detection"""
        return [
            # True Positives
            TestCase(
                name="TP: Direct mimikatz.exe execution",
                description="Direct execution of mimikatz binary",
                input_event={"process": "mimikatz.exe", "cmdline": "sekurlsa::logonpasswords"},
                expected_detection=True,
                expected_severity="critical",
                test_type="true_positive"
            ),
            TestCase(
                name="TP: Renamed mimikatz",
                description="Mimikatz renamed to bypass simple filename detection",
                input_event={"process": "svchost32.exe", "cmdline": "privilege::debug sekurlsa::logonpasswords"},
                expected_detection=True,
                expected_severity="critical",
                test_type="true_positive"
            ),
            TestCase(
                name="TP: Invoke-Mimikatz via PowerShell",
                description="PowerShell-based mimikatz",
                input_event={"process": "powershell.exe", "cmdline": "Invoke-Mimikatz -DumpCreds"},
                expected_detection=True,
                expected_severity="critical",
                test_type="true_positive"
            ),
            # False Positives
            TestCase(
                name="FP: Legitimate process management",
                description="Normal svchost process",
                input_event={"process": "svchost.exe", "cmdline": "-k LocalServiceNoNetwork"},
                expected_detection=False,
                test_type="false_positive"
            ),
            TestCase(
                name="FP: PowerShell legitimate use",
                description="Normal PowerShell administration",
                input_event={"process": "powershell.exe", "cmdline": "Get-ADUser -Filter *"},
                expected_detection=False,
                test_type="false_positive"
            )
        ]


def example_mimikatz_detection_rule(event: Dict) -> Dict:
    """Example detection rule for testing"""
    process = event.get('process', '').lower()
    cmdline = event.get('cmdline', '').lower()
    
    mimikatz_indicators = [
        'mimikatz', 'sekurlsa::', 'kerberos::', 'lsadump::',
        'privilege::debug', 'invoke-mimikatz', 'dumpcreds'
    ]
    
    for indicator in mimikatz_indicators:
        if indicator in process or indicator in cmdline:
            return {
                'detected': True,
                'severity': 'critical',
                'reason': f'Mimikatz indicator found: {indicator}'
            }
    
    return {'detected': False, 'severity': None, 'reason': 'No indicators found'}


if __name__ == '__main__':
    tester = DetectionRuleTester()
    
    test_cases = tester.create_mimikatz_test_suite()
    for tc in test_cases:
        tester.add_test_case(tc)
    
    results = tester.run_all_tests(example_mimikatz_detection_rule)
    
    print("Detection Rule Test Results:")
    print(json.dumps(results, indent=2))
    print(f"\nGrade: {results['grade']}")
```

---

## Step 640: Automated Threat Response

```python
#!/usr/bin/env python3
# Automated Threat Response - SOAR-style Response Automation

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
import json
import subprocess
from datetime import datetime
from enum import Enum

class ResponseAction(Enum):
    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    DISABLE_USER = "disable_user"
    KILL_PROCESS = "kill_process"
    COLLECT_FORENSICS = "collect_forensics"
    NOTIFY_SOC = "notify_soc"
    CREATE_TICKET = "create_ticket"
    QUARANTINE_FILE = "quarantine_file"

@dataclass
class ResponsePlaybook:
    name: str
    trigger_conditions: List[str]  # Event types that trigger this
    severity_threshold: str
    actions: List[ResponseAction]
    auto_execute: bool = False  # ต้อง approve ก่อนรัน
    notify_teams: List[str] = field(default_factory=list)

@dataclass
class IncidentCase:
    id: str
    title: str
    severity: str
    source: str
    iocs: List[Dict]
    affected_hosts: List[str]
    affected_users: List[str]
    timeline: List[Dict] = field(default_factory=list)
    status: str = "open"
    
class AutomatedResponseEngine:
    def __init__(self):
        self.playbooks: Dict[str, ResponsePlaybook] = {}
        self.incidents: Dict[str, IncidentCase] = {}
        self.action_log: List[Dict] = []
        self._build_default_playbooks()
    
    def _build_default_playbooks(self):
        self.playbooks = {
            "ransomware_response": ResponsePlaybook(
                name="Ransomware Incident Response",
                trigger_conditions=["ransomware_detected", "mass_file_encryption"],
                severity_threshold="critical",
                actions=[
                    ResponseAction.ISOLATE_HOST,
                    ResponseAction.DISABLE_USER,
                    ResponseAction.COLLECT_FORENSICS,
                    ResponseAction.NOTIFY_SOC,
                    ResponseAction.CREATE_TICKET
                ],
                auto_execute=False,  # ต้อง manual approve
                notify_teams=["security", "management", "legal"]
            ),
            "credential_theft_response": ResponsePlaybook(
                name="Credential Theft Response",
                trigger_conditions=["mimikatz_detected", "lsass_access", "credential_dumping"],
                severity_threshold="critical",
                actions=[
                    ResponseAction.ISOLATE_HOST,
                    ResponseAction.DISABLE_USER,
                    ResponseAction.COLLECT_FORENSICS,
                    ResponseAction.NOTIFY_SOC
                ],
                auto_execute=False,
                notify_teams=["security", "identity_team"]
            ),
            "c2_communication_response": ResponsePlaybook(
                name="C2 Communication Response",
                trigger_conditions=["beaconing_detected", "c2_connection"],
                severity_threshold="high",
                actions=[
                    ResponseAction.BLOCK_IP,
                    ResponseAction.NOTIFY_SOC,
                    ResponseAction.CREATE_TICKET
                ],
                auto_execute=True,  # บล็อก IP อัตโนมัติ
                notify_teams=["security"]
            ),
            "malware_execution_response": ResponsePlaybook(
                name="Malware Execution Response",
                trigger_conditions=["malware_detected", "suspicious_process"],
                severity_threshold="high",
                actions=[
                    ResponseAction.KILL_PROCESS,
                    ResponseAction.QUARANTINE_FILE,
                    ResponseAction.COLLECT_FORENSICS,
                    ResponseAction.NOTIFY_SOC
                ],
                auto_execute=True,
                notify_teams=["security"]
            )
        }
    
    def create_incident(self, alert: Dict) -> IncidentCase:
        """สร้าง Incident Case จาก Alert"""
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        incident = IncidentCase(
            id=incident_id,
            title=alert.get('title', 'Security Incident'),
            severity=alert.get('severity', 'medium'),
            source=alert.get('source', 'SIEM'),
            iocs=alert.get('iocs', []),
            affected_hosts=alert.get('hosts', []),
            affected_users=alert.get('users', []),
            timeline=[{
                "time": datetime.now().isoformat(),
                "action": "incident_created",
                "details": f"Incident created from alert: {alert.get('title')}"
            }]
        )
        
        self.incidents[incident_id] = incident
        return incident
    
    def execute_playbook(self, incident: IncidentCase, playbook_name: str, 
                        dry_run: bool = True) -> Dict:
        """รัน Response Playbook สำหรับ Incident"""
        playbook = self.playbooks.get(playbook_name)
        if not playbook:
            return {"error": f"Playbook not found: {playbook_name}"}
        
        execution_results = {
            "incident_id": incident.id,
            "playbook": playbook_name,
            "dry_run": dry_run,
            "timestamp": datetime.now().isoformat(),
            "actions": []
        }
        
        for action in playbook.actions:
            result = self._execute_action(action, incident, dry_run)
            execution_results["actions"].append(result)
            
            incident.timeline.append({
                "time": datetime.now().isoformat(),
                "action": action.value,
                "result": result.get('status', 'unknown'),
                "dry_run": dry_run
            })
        
        # Send notifications
        for team in playbook.notify_teams:
            self._notify_team(team, incident, playbook_name)
        
        return execution_results
    
    def _execute_action(self, action: ResponseAction, 
                       incident: IncidentCase, dry_run: bool) -> Dict:
        """รัน Response Action"""
        result = {
            "action": action.value,
            "targets": [],
            "status": "dry_run" if dry_run else "executed"
        }
        
        if action == ResponseAction.ISOLATE_HOST:
            result["targets"] = incident.affected_hosts
            if not dry_run:
                for host in incident.affected_hosts:
                    self._isolate_host(host)
            result["description"] = f"Would isolate hosts: {incident.affected_hosts}"
        
        elif action == ResponseAction.BLOCK_IP:
            ips = [ioc['value'] for ioc in incident.iocs if ioc.get('type') == 'ip']
            result["targets"] = ips
            if not dry_run:
                for ip in ips:
                    self._block_ip(ip)
            result["description"] = f"Would block IPs: {ips}"
        
        elif action == ResponseAction.DISABLE_USER:
            result["targets"] = incident.affected_users
            if not dry_run:
                for user in incident.affected_users:
                    self._disable_user(user)
            result["description"] = f"Would disable users: {incident.affected_users}"
        
        elif action == ResponseAction.COLLECT_FORENSICS:
            result["targets"] = incident.affected_hosts
            result["description"] = f"Would collect forensic evidence from: {incident.affected_hosts}"
        
        elif action == ResponseAction.NOTIFY_SOC:
            result["description"] = f"Would send SOC notification for incident {incident.id}"
        
        elif action == ResponseAction.CREATE_TICKET:
            result["description"] = f"Would create ticket for incident {incident.id}"
        
        self.action_log.append({
            "time": datetime.now().isoformat(),
            "incident_id": incident.id,
            "action": action.value,
            "dry_run": dry_run,
            "result": result
        })
        
        return result
    
    def _isolate_host(self, hostname: str):
        """Isolate host โดยตัดการเชื่อมต่อ Network"""
        # ตัวอย่าง: ใช้ CrowdStrike API, Carbon Black, หรือ EDR อื่นๆ
        print(f"[ISOLATION] Isolating host: {hostname}")
        # requests.post(f"{edr_url}/v1/host/{hostname}/contain")
    
    def _block_ip(self, ip: str):
        """Block IP บน Firewall"""
        print(f"[BLOCK] Blocking IP: {ip}")
        # ตัวอย่าง: ใช้ Palo Alto API, Cisco Firepower, pfSense API
        # subprocess.run(["fw", "block", ip])
    
    def _disable_user(self, username: str):
        """Disable AD User Account"""
        print(f"[DISABLE] Disabling user: {username}")
        # ตัวอย่าง: ใช้ Active Directory API
        # subprocess.run(["Disable-ADAccount", "-Identity", username])
    
    def _notify_team(self, team: str, incident: IncidentCase, playbook: str):
        """ส่งการแจ้งเตือนไปยังทีม"""
        message = (
            f"Security Alert - Incident {incident.id}\n"
            f"Severity: {incident.severity.upper()}\n"
            f"Playbook: {playbook}\n"
            f"Affected Hosts: {', '.join(incident.affected_hosts)}\n"
            f"Affected Users: {', '.join(incident.affected_users)}"
        )
        print(f"[NOTIFY] Team '{team}': {message[:100]}...")
    
    def match_playbook(self, alert_type: str) -> Optional[str]:
        """หา Playbook ที่เหมาะสมกับ Alert Type"""
        for playbook_name, playbook in self.playbooks.items():
            if alert_type in playbook.trigger_conditions:
                return playbook_name
        return None


if __name__ == '__main__':
    engine = AutomatedResponseEngine()
    
    # Simulate incoming alert
    alert = {
        "title": "Mimikatz Detected on WORKSTATION-01",
        "severity": "critical",
        "source": "EDR",
        "type": "credential_dumping",
        "iocs": [
            {"type": "ip", "value": "192.168.1.200"},
            {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e"}
        ],
        "hosts": ["WORKSTATION-01"],
        "users": ["john.doe"]
    }
    
    incident = engine.create_incident(alert)
    playbook_name = engine.match_playbook(alert['type'])
    
    if playbook_name:
        print(f"Matched Playbook: {playbook_name}")
        results = engine.execute_playbook(incident, playbook_name, dry_run=True)
        print(json.dumps(results, indent=2, default=str))
    else:
        print("No matching playbook found")
    
    print(f"\nIncident {incident.id} created with {len(incident.timeline)} timeline events")
```

---

## สรุป Part 64

ในส่วนนี้เราได้เรียนรู้:
- **Threat Hunting Methodology**: การสร้าง Hypothesis และ Hunt Plans ตาม MITRE ATT&CK
- **SIGMA Rules**: การสร้าง Detection Rules แบบ Platform-agnostic และแปลงเป็น Splunk/Elastic
- **YARA Rules**: การเขียน Rules สำหรับตรวจจับ Malware patterns
- **ELK Detection**: การสร้าง Detection Rules ใน Kibana SIEM
- **Windows Event Analysis**: การวิเคราะห์ Critical Event IDs หาพฤติกรรมผิดปกติ
- **Splunk SPL**: Queries สำหรับ Credential Dumping, Lateral Movement, Beaconing
- **Network Traffic Analysis**: การตรวจหา Port Scan, Beaconing, Data Exfiltration
- **Threat Intelligence**: การรวม IOC จาก VirusTotal, AbuseIPDB, OTX
- **Detection Testing**: การวัด Precision, Recall, F1-Score ของ Detection Rules
- **Automated Response**: SOAR Playbooks สำหรับ Incident Response อัตโนมัติ
