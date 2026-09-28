# Part 83: Threat Intelligence Platforms (Steps 821-830)

## Step 821: Threat Intelligence Fundamentals

พื้นฐาน Threat Intelligence และประเภทของข้อมูล

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime

@dataclass
class ThreatIntelligence:
    """Threat Intelligence fundamentals and types"""
    
    def intelligence_types(self) -> Dict:
        return {
            "strategic": {
                "description": "High-level trends, threat actor motives",
                "audience": "CISO, Board",
                "examples": ["Nation-state targeting financial sector", "Ransomware trends Q4 2024"],
                "timeframe": "Months to years"
            },
            "operational": {
                "description": "Ongoing campaign details, TTPs",
                "audience": "Security Manager, IR team",
                "examples": ["APT29 currently targeting VPN vulnerabilities", "New phishing campaign uses fake DocuSign"],
                "timeframe": "Days to weeks"
            },
            "tactical": {
                "description": "Specific TTPs, malware behaviors",
                "audience": "Security analysts, Pentesters",
                "examples": ["SUNBURST uses HTTP beaconing with specific User-Agent", "MAZE ransomware double extortion TTPs"],
                "timeframe": "Hours to days"
            },
            "technical": {
                "description": "IOCs: IPs, domains, hashes, signatures",
                "audience": "SOC, SIEM engineers",
                "examples": ["Malware C2 IP: 1.2.3.4", "Hash: abc123def456...", "Domain: evil.com"],
                "timeframe": "Real-time to hours"
            }
        }
    
    def ioc_types(self) -> Dict:
        return {
            "network": ["IP addresses", "Domains/FQDNs", "URLs", "Email addresses", "SSL cert hashes"],
            "host": ["File hashes (MD5/SHA1/SHA256)", "File paths", "Registry keys", 
                    "Mutex names", "Process names"],
            "behavioral": ["YARA rules", "Sigma rules", "ATT&CK technique IDs", 
                           "Traffic patterns", "API call sequences"]
        }
    
    def intelligence_cycle(self) -> List[Dict]:
        return [
            {"phase": "Planning", "description": "Define intelligence requirements"},
            {"phase": "Collection", "description": "Gather raw data from sources"},
            {"phase": "Processing", "description": "Normalize and correlate data"},
            {"phase": "Analysis", "description": "Identify patterns, attribute actors"},
            {"phase": "Dissemination", "description": "Share with stakeholders in right format"},
            {"phase": "Feedback", "description": "Evaluate usefulness, refine requirements"}
        ]


@dataclass
class TIDataFormats:
    """Threat Intelligence sharing formats"""
    
    def formats(self) -> Dict:
        return {
            "STIX2": {
                "name": "Structured Threat Information Expression",
                "format": "JSON",
                "use": "Industry standard for TI sharing",
                "objects": ["indicator", "threat-actor", "malware", "campaign", "relationship"]
            },
            "TAXII": {
                "name": "Trusted Automated Exchange of Intelligence",
                "purpose": "Transport protocol for STIX data",
                "version": "TAXII 2.1 over HTTPS REST API"
            },
            "OpenIOC": {
                "format": "XML",
                "creator": "Mandiant/FireEye",
                "use": "Forensic indicators"
            },
            "YARA": {
                "format": "Custom DSL",
                "use": "File/memory pattern matching"
            },
            "Sigma": {
                "format": "YAML",
                "use": "SIEM detection rules (converts to Splunk/ELK/etc)"
            }
        }
    
    def stix2_indicator_example(self) -> Dict:
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--12345678-1234-1234-1234-123456789012",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "name": "Malicious IP - APT29 C2",
            "indicator_types": ["malicious-activity"],
            "pattern": "[ipv4-addr:value = '185.220.101.1']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z",
            "labels": ["malicious-activity"],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}
            ]
        }


if __name__ == '__main__':
    ti = ThreatIntelligence()
    print("Intelligence types:")
    for ti_type, info in ti.intelligence_types().items():
        print(f"  {ti_type}: {info['description']}")
    
    print("\nIntelligence cycle:")
    for phase in ti.intelligence_cycle():
        print(f"  {phase['phase']}: {phase['description']}")
    
    formats = TIDataFormats()
    stix = formats.stix2_indicator_example()
    print(f"\nSTIX2 indicator: {stix['name']}")
    print(f"Pattern: {stix['pattern']}")
```

## Step 822: MISP Platform Setup and Usage

การติดตั้งและใช้งาน MISP Threat Intelligence Platform

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class MISPPlatform:
    """MISP - Malware Information Sharing Platform"""
    
    def setup_commands(self) -> List[str]:
        return [
            "# Install MISP via Docker",
            "git clone https://github.com/MISP/misp-docker",
            "cd misp-docker",
            "cp template.env .env  # Edit .env with your settings",
            "docker-compose up -d",
            "# Access: https://localhost  admin@admin.test / admin",
            "",
            "# Or bare metal install",
            "wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh",
            "bash /tmp/INSTALL.sh -A  # Automated install"
        ]
    
    def pymisp_usage(self) -> str:
        return '''
# PyMISP - Python API for MISP
from pymisp import PyMISP, MISPEvent, MISPAttribute

misp_url = "https://misp.yourdomain.com"
misp_key = "your_automation_key"

misp = PyMISP(misp_url, misp_key, False)  # False = no SSL verify (dev)

# Create new event
event = MISPEvent()
event.info = "APT29 Campaign - Spearphishing Q1 2024"
event.distribution = 3  # All communities
event.threat_level_id = 2  # HIGH
event.analysis = 2  # Completed

# Add IOCs
attr = MISPAttribute()
attr.type = "ip-dst"
attr.value = "185.220.101.1"
attr.category = "Network activity"
attr.comment = "C2 server"
event.attributes.append(attr)

# Add domain
event.add_attribute("domain", "malicious-update.com", comment="Dropper domain")

# Add hash
event.add_attribute("sha256", "abc123...def456", comment="Malware SHA256")

# Save event
result = misp.add_event(event)
print(f"Event created: {result['Event']['id']}")

# Search for IOC
result = misp.search(value="185.220.101.1", type_attribute="ip-dst")
for event in result:
    print(f"Found in event: {event['Event']['info']}")

# Feed management
misp.enable_feed(1)  # Enable feed by ID
misp.fetch_feed(1)   # Fetch data from feed
'''
    
    def built_in_feeds(self) -> List[Dict]:
        return [
            {"name": "CIRCL OSINT", "type": "MISP", "url": "https://www.circl.lu/doc/misp/feed-osint/"},
            {"name": "Botvrij.eu", "type": "MISP", "description": "Curated threat intelligence"},
            {"name": "Abuse.ch URLhaus", "type": "CSV", "description": "Malicious URLs"},
            {"name": "Feodo Tracker", "type": "JSON", "description": "Botnet C&C IPs"},
            {"name": "AlienVault OTX", "type": "MISP", "description": "Open threat exchange"},
            {"name": "PhishTank", "type": "CSV", "description": "Phishing URLs"}
        ]


if __name__ == '__main__':
    misp = MISPPlatform()
    print("MISP setup:")
    for cmd in misp.setup_commands()[:5]:
        print(f"  {cmd}")
    
    print("\nBuilt-in feeds:")
    for feed in misp.built_in_feeds():
        print(f"  {feed['name']}: {feed.get('description', feed['type'])}")
```

## Step 823: OpenCTI Platform

การใช้ OpenCTI สำหรับจัดการ Threat Intelligence

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class OpenCTIPlatform:
    """OpenCTI Threat Intelligence Platform"""
    
    def setup(self) -> Dict:
        return {
            "docker_compose": """
# docker-compose.yml for OpenCTI
version: '3'
services:
  opencti:
    image: opencti/platform:6.0.0
    environment:
      - APP__PORT=8080
      - APP__BASE_URL=http://localhost:8080
      - APP__ADMIN__EMAIL=admin@opencti.io
      - APP__ADMIN__PASSWORD=admin123
      - REDIS__HOSTNAME=redis
      - ELASTICSEARCH__URL=http://elasticsearch:9200
      - MINIO__ENDPOINT=minio
      - RABBITMQ__HOSTNAME=rabbitmq
    ports:
      - "8080:8080"
    depends_on:
      - redis
      - elasticsearch
      - minio
      - rabbitmq
""",
            "access": "http://localhost:8080",
            "default_creds": "admin@opencti.io / admin123"
        }
    
    def python_api_usage(self) -> str:
        return '''
# OpenCTI Python API
from pycti import OpenCTIApiClient

api_url = "http://localhost:8080"
api_token = "your_api_token"

client = OpenCTIApiClient(api_url, api_token)

# Create threat actor
threat_actor = client.threat_actor.create(
    name="APT29",
    description="Russian SVR APT group",
    aliases=["Cozy Bear", "The Dukes"],
    threat_actor_types=["nation-state"]
)

# Create indicator
indicator = client.indicator.create(
    name="APT29 C2 IP",
    description="Known C2 server",
    pattern="[ipv4-addr:value = '185.220.101.1']",
    pattern_type="stix",
    indicator_types=["malicious-activity"]
)

# Create relationship
client.stix_core_relationship.create(
    relationship_type="uses",
    fromId=threat_actor["id"],
    toId=indicator["id"]
)

# Search reports
reports = client.report.list(filters=[
    {"key": "name", "values": ["APT29"]}
])
for report in reports:
    print(f"Report: {report['name']}")
'''
    
    def integrations(self) -> List[str]:
        return [
            "MISP bidirectional sync connector",
            "MITRE ATT&CK import",
            "VirusTotal enrichment connector",
            "Shodan enrichment",
            "AlienVault OTX import",
            "TAXII2 import/export",
            "Slack/TheHive alerting",
            "Cortex analyzer integration"
        ]


if __name__ == '__main__':
    opencti = OpenCTIPlatform()
    print("OpenCTI integrations:")
    for integration in opencti.integrations():
        print(f"  - {integration}")
```

## Step 824: Threat Actor Profiling and Attribution

การสร้างโปรไฟล์ Threat Actor และการกำหนดแหล่งที่มา

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class ThreatActorProfiling:
    """Threat actor profiling and attribution methodology"""
    
    def diamond_model(self) -> Dict:
        return {
            "model": "Diamond Model of Intrusion Analysis",
            "vertices": {
                "Adversary": "Who - threat actor, motive, intent",
                "Capability": "What - malware, tools, techniques",
                "Infrastructure": "How - C2, domains, IPs, physical",
                "Victim": "Target - industry, geography, role"
            },
            "relationships": [
                "Adversary -> Capability (develops/uses)",
                "Adversary -> Infrastructure (controls)",
                "Capability -> Victim (exploits via)",
                "Infrastructure -> Victim (delivers to)"
            ],
            "use": "Map intrusion events to build actor profile over time"
        }
    
    def attribution_indicators(self) -> Dict:
        return {
            "technical": [
                "Malware code reuse (unique function names, strings)",
                "C2 infrastructure overlap",
                "Shared TLS certificates",
                "Time-of-operation (working hours by timezone)",
                "Language artifacts in malware (error messages, comments)",
                "Compile timestamps"
            ],
            "behavioral": [
                "Target sector/geography preferences",
                "Operational security habits",
                "Preferred exploitation paths",
                "Data collection and exfiltration patterns"
            ],
            "open_source": [
                "Forum posts in native language",
                "Code commits on GitHub",
                "Leaked tools/infrastructure"
            ]
        }
    
    def major_threat_groups(self) -> List[Dict]:
        return [
            {
                "name": "APT28 (Fancy Bear)", "origin": "Russia/GRU",
                "targets": "Government, military, energy",
                "tools": ["X-Agent", "Sofacy", "CHOPSTICK"],
                "mitre": "G0007"
            },
            {
                "name": "APT29 (Cozy Bear)", "origin": "Russia/SVR",
                "targets": "Government, think tanks, healthcare",
                "tools": ["WELLMESS", "SUNBURST", "GoldFinder"],
                "mitre": "G0016"
            },
            {
                "name": "APT41 (Winnti)", "origin": "China/MSS",
                "targets": "Healthcare, telecom, gaming",
                "tools": ["PlugX", "ShadowPad", "MESSAGETAP"],
                "mitre": "G0096"
            },
            {
                "name": "Lazarus", "origin": "North Korea/RGB",
                "targets": "Financial, crypto, defense",
                "tools": ["HOPLIGHT", "BLINDINGCAN", "AppleJeus"],
                "mitre": "G0032"
            },
            {
                "name": "FIN7", "origin": "Financially motivated",
                "targets": "Retail, hospitality, finance (POS)",
                "tools": ["CARBANAK", "BATELEUR", "Griffon"],
                "mitre": "G0046"
            }
        ]


if __name__ == '__main__':
    profiling = ThreatActorProfiling()
    print("Diamond Model:")
    for vertex, desc in profiling.diamond_model()['vertices'].items():
        print(f"  {vertex}: {desc}")
    
    print("\nMajor threat groups:")
    for group in profiling.major_threat_groups():
        print(f"  {group['name']} ({group['origin']}): {group['targets']}")
```

## Step 825-830: TI Integration and Automation

การเชื่อมต่อและอัตโนมัติ Threat Intelligence

```python
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import json
import hashlib

@dataclass
class TIAutomation:
    """Threat Intelligence automation and integration"""
    
    def virustotal_api(self) -> str:
        return '''
import requests

VT_API_KEY = "your_api_key"
VT_BASE = "https://www.virustotal.com/api/v3"

def check_file_hash(sha256_hash: str) -> dict:
    """Check file hash against VT"""
    url = f"{VT_BASE}/files/{sha256_hash}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "undetected": stats["undetected"],
            "total": sum(stats.values()),
            "verdict": "malicious" if stats["malicious"] > 5 else "clean"
        }
    return {"error": response.status_code}

def check_ip(ip: str) -> dict:
    url = f"{VT_BASE}/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()["data"]["attributes"]
        return {
            "reputation": data.get("reputation", 0),
            "malicious_votes": data["last_analysis_stats"]["malicious"],
            "country": data.get("country", "unknown"),
            "as_owner": data.get("as_owner", "unknown")
        }
    return {}

# Bulk check from IOC list
def bulk_ioc_check(ioc_list: list) -> list:
    results = []
    for ioc in ioc_list:
        if len(ioc) in (32, 40, 64):  # Hash
            result = check_file_hash(ioc)
        elif "." in ioc and not "/" in ioc:  # IP or domain
            result = check_ip(ioc)
        result["ioc"] = ioc
        results.append(result)
    return results
'''
    
    def alienvault_otx(self) -> str:
        return '''
from OTXv2 import OTXv2, IndicatorTypes

otx = OTXv2("your_api_key")

# Get pulse (threat report)
pulse = otx.get_pulse_details("pulse_id")
print(f"Pulse: {pulse['name']} - {len(pulse['indicators'])} IOCs")

# Check IP
result = otx.get_indicator_details_by_section(
    IndicatorTypes.IPv4, "1.2.3.4", "general"
)
print(f"Reputation: {result.get('reputation', 0)}")

# Get related pulses
pulses = otx.get_indicator_details_by_section(
    IndicatorTypes.DOMAIN, "malicious.com", "general"
)
for pulse in pulses.get("pulse_info", {}).get("pulses", []):
    print(f"Related pulse: {pulse['name']}")

# Subscribe to feed
subscribed_pulses = otx.getall()  # Get all subscribed pulses
for pulse in subscribed_pulses[:5]:
    print(f"Feed: {pulse['name']} - {pulse['modified']}")
    for ioc in pulse["indicators"][:3]:
        print(f"  IOC: {ioc['type']} = {ioc['indicator']}")
'''
    
    def shodan_intelligence(self) -> str:
        return '''
import shodan

api = shodan.Shodan("your_api_key")

# Search for threat actor infrastructure
def hunt_threat_actor(cert_fingerprint: str = None, 
                      jarm_fingerprint: str = None,
                      banner_string: str = None) -> list:
    results = []
    
    if cert_fingerprint:
        query = f'ssl.cert.fingerprint:{cert_fingerprint}'
    elif jarm_fingerprint:
        query = f'ssl.jarm:{jarm_fingerprint}'
    elif banner_string:
        query = f'"{banner_string}"'
    
    try:
        search_results = api.search(query)
        for result in search_results["matches"]:
            results.append({
                "ip": result["ip_str"],
                "port": result["port"],
                "org": result.get("org", ""),
                "country": result.get("location", {}).get("country_code", "")
            })
    except shodan.APIError as e:
        print(f"Error: {e}")
    
    return results

# Hunt Cobalt Strike servers by JARM
cobalt_strike_jarm = "07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d"
cs_servers = hunt_threat_actor(jarm_fingerprint=cobalt_strike_jarm)
print(f"Found {len(cs_servers)} potential Cobalt Strike servers")
'''
    
    def ioc_scoring_model(self) -> str:
        return '''
# IOC scoring model
from dataclasses import dataclass, field
from datetime import datetime, timedelta

@dataclass
class IOCScore:
    ioc: str
    ioc_type: str  # ip, domain, hash, url
    score: float = 0.0
    sources: list = field(default_factory=list)
    
    def calculate_score(self, vt_result: dict, otx_result: dict,
                        misp_result: dict) -> float:
        score = 0.0
        
        # VirusTotal score (0-30 points)
        if vt_result.get("malicious", 0) > 0:
            score += min(vt_result["malicious"] * 2, 30)
        
        # AlienVault OTX score (0-20 points)
        pulse_count = len(otx_result.get("pulses", []))
        score += min(pulse_count * 5, 20)
        
        # MISP score (0-30 points)
        misp_events = len(misp_result.get("events", []))
        score += min(misp_events * 10, 30)
        
        # Age penalty (newer = higher risk)
        # ...
        
        self.score = min(score, 100)
        return self.score
    
    def get_verdict(self) -> str:
        if self.score >= 70: return "MALICIOUS"
        elif self.score >= 40: return "SUSPICIOUS"
        elif self.score >= 20: return "LOW RISK"
        return "CLEAN"
'''
    
    def sigma_rule_creation(self) -> str:
        return '''
# Sigma rule for threat hunting
title: APT29 SUNBURST Backdoor Detection
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects SUNBURST backdoor beacon activity
author: Security Team
date: 2024/01/01
logsource:
    category: network
    product: zeek
detection:
    selection:
        dns.query:
            - "*.appsync-api.us-east-2.avsvmcloud.com"
            - "*.appsync-api.eu-west-1.avsvmcloud.com"
    condition: selection
fields:
    - dns.query
    - src_ip
level: critical
tags:
    - attack.command_and_control
    - attack.t1071.004
    - apt.apt29
falsepositives:
    - None expected
'''


if __name__ == '__main__':
    auto = TIAutomation()
    print("TI Automation sources:")
    print("  1. VirusTotal API - file/IP/domain reputation")
    print("  2. AlienVault OTX - community threat feeds")
    print("  3. Shodan - internet-facing infrastructure hunting")
    print("  4. IOC scoring model - aggregate confidence score")
    print("  5. Sigma rules - detection rule creation")
```

---

## สรุป Part 83

| Step | หัวข้อ | เนื้อหาสำคัญ |
|------|--------|-------------|
| 821 | TI Fundamentals | Strategic/operational/tactical/technical intel |
| 822 | MISP Platform | Docker setup, PyMISP API, built-in feeds |
| 823 | OpenCTI | Docker setup, Python API, connectors |
| 824 | Threat Actor Profiling | Diamond model, attribution, APT groups |
| 825-830 | TI Automation | VT API, OTX, Shodan hunting, IOC scoring, Sigma |
