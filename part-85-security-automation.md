# Part 85: Security Automation & Orchestration (Steps 841-850)

## Step 841: SOAR Platform Fundamentals

พื้นฐาน SOAR (Security Orchestration, Automation and Response)

```python
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Optional
import json
import time

@dataclass
class SOARPlatform:
    """Security Orchestration, Automation and Response concepts"""
    
    def soar_capabilities(self) -> Dict:
        return {
            "orchestration": [
                "Connect security tools via APIs",
                "Coordinate workflows across teams",
                "Automate data enrichment from multiple sources"
            ],
            "automation": [
                "Auto-respond to common alert types",
                "Automate repetitive analyst tasks",
                "Reduce mean time to respond (MTTR)"
            ],
            "response": [
                "Automated containment (isolate host, block IP)",
                "Ticket creation and assignment",
                "Evidence collection and preservation"
            ]
        }
    
    def popular_platforms(self) -> List[Dict]:
        return [
            {"name": "Splunk SOAR (Phantom)", "type": "Commercial", "strength": "Marketplace of 400+ app connectors"},
            {"name": "Palo Alto XSOAR", "type": "Commercial", "strength": "Deep integration with Palo Alto products"},
            {"name": "TheHive", "type": "Open Source", "strength": "Case management + Cortex analyzers"},
            {"name": "Shuffle", "type": "Open Source", "strength": "Docker-based, easy workflow builder"},
            {"name": "n8n", "type": "Open Source", "strength": "General automation with security uses"},
            {"name": "Tines", "type": "Commercial", "strength": "No-code automation, simple stories"}
        ]
    
    def use_cases(self) -> List[Dict]:
        return [
            {
                "use_case": "Phishing Response",
                "trigger": "Email flagged as phishing",
                "automation": [
                    "Extract URLs and attachments",
                    "Check URLs against threat intel (VT, OTX)",
                    "Block malicious URLs in proxy/email gateway",
                    "Search for other recipients",
                    "Delete from all mailboxes if confirmed malicious",
                    "Create incident ticket"
                ],
                "time_saved": "30 min manual -> 2 min automated"
            },
            {
                "use_case": "Malware Alert Triage",
                "trigger": "EDR malware detection alert",
                "automation": [
                    "Enrich host info (owner, criticality, location)",
                    "Check file hash against VT/sandboxes",
                    "If confirmed: isolate host from network",
                    "Collect forensic artifacts",
                    "Notify owner and manager"
                ],
                "time_saved": "45 min manual -> 5 min automated"
            },
            {
                "use_case": "Brute Force Detection",
                "trigger": "SIEM alert: 10+ failed logins",
                "automation": [
                    "Check if source IP is known malicious",
                    "Check if target account is privileged",
                    "Block source IP in firewall",
                    "Disable account if successful login detected",
                    "Notify user and helpdesk"
                ]
            }
        ]


if __name__ == '__main__':
    soar = SOARPlatform()
    print("SOAR capabilities:")
    for cap, items in soar.soar_capabilities().items():
        print(f"  {cap}: {items[0]}")
    
    print("\nPhishing response automation:")
    for step in soar.use_cases()[0]['automation']:
        print(f"  -> {step}")
```

## Step 842: TheHive and Cortex Setup

การติดตั้งและใช้งาน TheHive + Cortex

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class TheHiveCortex:
    """TheHive case management + Cortex analyzer platform"""
    
    def setup(self) -> List[str]:
        return [
            "# Docker Compose setup for TheHive + Cortex + Elasticsearch",
            "git clone https://github.com/StrangeBeeCorp/thehive",
            "cd thehive",
            "docker-compose up -d",
            "# TheHive: http://localhost:9000  admin@thehive.local / secret",
            "# Cortex: http://localhost:9001"
        ]
    
    def thehive_python_api(self) -> str:
        return '''
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseTask, CaseObservable, AlertArtifact, Alert

api = TheHiveApi("http://localhost:9000", "your_api_key")

# Create incident case
case = Case(
    title="Phishing Campaign - Finance Team",
    description="Targeted phishing emails with malicious Excel attachment",
    severity=3,  # 1=Low, 2=Medium, 3=High
    tlp=2,       # 0=WHITE, 1=GREEN, 2=AMBER, 3=RED
    tags=["phishing", "finance", "malware"]
)
result = api.create_case(case)
case_id = result.json()["id"]

# Add observables (IOCs)
observables = [
    CaseObservable(dataType="ip", data="185.220.101.1", message="C2 server", tlp=2),
    CaseObservable(dataType="domain", data="malicious-docs.com", message="Dropper domain", tlp=2),
    CaseObservable(dataType="hash", data="abc123...", message="Malware SHA256", tlp=2)
]
for obs in observables:
    api.create_case_observable(case_id, obs)

# Add tasks
tasks = [
    CaseTask(title="Analyze malicious email"),
    CaseTask(title="Investigate affected hosts"),
    CaseTask(title="Block IOCs in security tools"),
    CaseTask(title="Notify affected users")
]
for task in tasks:
    api.create_case_task(case_id, task)

print(f"Case created: {case_id}")

# Create alert from SIEM
alert = Alert(
    title="Brute Force Detected",
    description="Multiple failed SSH logins",
    type="siem",
    source="Splunk",
    sourceRef="SPL-12345",
    severity=2,
    artifacts=[
        AlertArtifact(dataType="ip", data="attacker_ip"),
        AlertArtifact(dataType="hostname", data="victim_host")
    ]
)
api.create_alert(alert)
'''
    
    def cortex_analyzers(self) -> List[Dict]:
        return [
            {"name": "VirusTotal_GetReport_3_0", "input": "hash, ip, domain, url", "output": "AV scan results"},
            {"name": "Shodan_Host", "input": "ip", "output": "Open ports, services, vulnerabilities"},
            {"name": "MaxMind_GeoIP_4_0", "input": "ip", "output": "Geolocation, ASN"},
            {"name": "URLhaus_2_0", "input": "url, hash", "output": "Malware distribution status"},
            {"name": "MISP_2_0", "input": "all IOC types", "output": "Matching MISP events"},
            {"name": "CAPEsandbox_2_0", "input": "hash, file", "output": "Dynamic analysis report"}
        ]


if __name__ == '__main__':
    thehive = TheHiveCortex()
    print("Cortex analyzers:")
    for analyzer in thehive.cortex_analyzers():
        print(f"  {analyzer['name']}: {analyzer['input']} -> {analyzer['output']}")
```

## Step 843: Python Security Automation Scripts

สคริปต์ Python สำหรับอัตโนมัติงานด้านความปลฯ

```python
from dataclasses import dataclass, field
from typing import Dict, List, Callable, Optional
import concurrent.futures
import requests
import json
import hashlib
import os

@dataclass
class SecurityAutomation:
    """Python automation scripts for security operations"""
    
    def ioc_enrichment_pipeline(self, iocs: List[str]) -> List[Dict]:
        """Enrich a list of IOCs with threat intel"""
        results = []
        
        def enrich_single(ioc: str) -> Dict:
            result = {"ioc": ioc, "enrichment": {}}
            
            # Determine type
            if self._is_ip(ioc):
                result["type"] = "ip"
            elif self._is_hash(ioc):
                result["type"] = "hash"
            elif "." in ioc:
                result["type"] = "domain"
            else:
                result["type"] = "unknown"
            
            # Simulated enrichment (replace with real API calls)
            result["enrichment"] = {
                "vt_detections": 0,
                "otx_pulses": 0,
                "verdict": "clean"
            }
            
            return result
        
        # Parallel enrichment
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(enrich_single, iocs))
        
        return results
    
    def _is_ip(self, s: str) -> bool:
        import re
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s))
    
    def _is_hash(self, s: str) -> bool:
        return len(s) in (32, 40, 64) and all(c in '0123456789abcdefABCDEF' for c in s)
    
    def alert_triage_automation(self) -> str:
        return '''
# Alert triage automation
from typing import Dict

class AlertTriager:
    def __init__(self, vt_key: str, siem_url: str, soar_url: str):
        self.vt_key = vt_key
        self.siem_url = siem_url
        self.soar_url = soar_url
    
    def process_malware_alert(self, alert: Dict) -> Dict:
        verdict = {"alert_id": alert["id"], "actions_taken": []}
        
        # Step 1: Get host context
        host_info = self.get_host_context(alert["hostname"])
        verdict["host_criticality"] = host_info.get("criticality", "unknown")
        
        # Step 2: Check file hash
        if alert.get("file_hash"):
            vt_result = self.check_vt(alert["file_hash"])
            verdict["vt_malicious"] = vt_result.get("malicious", 0)
        
        # Step 3: Auto-respond based on verdict
        if verdict["vt_malicious"] > 10 or verdict["host_criticality"] == "critical":
            # Isolate host
            self.isolate_host(alert["hostname"])
            verdict["actions_taken"].append("host_isolated")
            
            # Create high-priority ticket
            ticket_id = self.create_ticket(alert, priority="P1")
            verdict["ticket"] = ticket_id
            
            # Notify on-call
            self.notify_oncall(f"Critical malware on {alert[\"hostname\"]}")
            verdict["actions_taken"].append("oncall_notified")
        else:
            # Just create medium priority ticket
            ticket_id = self.create_ticket(alert, priority="P3")
            verdict["ticket"] = ticket_id
        
        return verdict
    
    def check_vt(self, file_hash: str) -> dict:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        r = requests.get(url, headers={"x-apikey": self.vt_key})
        if r.status_code == 200:
            return r.json()["data"]["attributes"]["last_analysis_stats"]
        return {}
    
    def isolate_host(self, hostname: str):
        """Call EDR API to isolate host"""
        # Example: CrowdStrike API
        pass
    
    def create_ticket(self, alert: dict, priority: str) -> str:
        """Create ticket in JIRA/ServiceNow"""
        pass
    
    def notify_oncall(self, message: str):
        """Page on-call via PagerDuty/OpsGenie"""
        pass
    
    def get_host_context(self, hostname: str) -> dict:
        """Get asset info from CMDB"""
        pass
'''


@dataclass
class SIEMIntegration:
    """SIEM integration and alert forwarding"""
    
    def splunk_api(self) -> str:
        return '''
import splunklib.client as client
import splunklib.results as results

# Connect to Splunk
service = client.connect(
    host="splunk.company.com",
    port=8089,
    username="admin",
    password="password"
)

# Run search
search_query = """search index=windows 
    EventCode=4625 
    | stats count by src_ip 
    | where count > 10"""

job = service.jobs.create(f"search {search_query}", earliest_time="-1h")

while not job.is_done():
    import time
    time.sleep(1)
    job.refresh()

# Get results
for result in results.JSONResultsReader(job.results(output_mode="json")):
    if isinstance(result, dict):
        print(f"Brute force from {result[\"src_ip\"]}: {result[\"count\"]} attempts")

# Create alert action
def forward_to_soar(alert_data: dict):
    """Forward alert to SOAR platform"""
    requests.post("http://soar.company.com/api/alert",
                  json=alert_data,
                  headers={"Authorization": "Bearer token"})
'''


if __name__ == '__main__':
    auto = SecurityAutomation()
    sample_iocs = ["185.220.101.1", "abc123def456" + "0" * 20, "malicious.com"]
    results = auto.ioc_enrichment_pipeline(sample_iocs)
    print("IOC enrichment results:")
    for result in results:
        print(f"  {result['ioc']} ({result['type']}): {result['enrichment']['verdict']}")
```

## Step 844: Ansible Security Automation

การใช้ Ansible สำหรับอัตโนมัติความปลอดภัย

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class AnsibleSecurity:
    """Ansible for security automation"""
    
    def hardening_playbook(self) -> str:
        return '''
---
# security-hardening.yml
- name: Linux Security Hardening
  hosts: all
  become: yes
  vars:
    ssh_port: 22
    
  tasks:
    - name: Ensure SSH root login disabled
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "^PermitRootLogin"
        line: "PermitRootLogin no"
        state: present
      notify: restart sshd
    
    - name: Disable SSH password authentication
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "^PasswordAuthentication"
        line: "PasswordAuthentication no"
      notify: restart sshd
    
    - name: Set password complexity
      pamd:
        name: common-password
        type: password
        control: requisite
        module_path: pam_pwquality.so
        module_arguments: retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1
    
    - name: Set umask to 027
      lineinfile:
        path: /etc/profile
        line: "umask 027"
    
    - name: Disable unused services
      service:
        name: "{{ item }}"
        state: stopped
        enabled: no
      loop:
        - telnet
        - rsh
        - rlogin
        - vsftpd
      ignore_errors: yes
    
    - name: Configure firewall (UFW)
      ufw:
        state: enabled
        policy: deny
    
    - name: Allow SSH
      ufw:
        rule: allow
        port: "{{ ssh_port }}"
        proto: tcp
    
    - name: Enable auditd
      service:
        name: auditd
        state: started
        enabled: yes
    
    - name: Add audit rules for sensitive files
      lineinfile:
        path: /etc/audit/rules.d/security.rules
        line: "{{ item }}"
        create: yes
      loop:
        - "-w /etc/passwd -p wa -k identity"
        - "-w /etc/sudoers -p wa -k sudo_changes"
        - "-w /etc/ssh/sshd_config -p wa -k sshd_config"
    
  handlers:
    - name: restart sshd
      service:
        name: sshd
        state: restarted
'''
    
    def incident_response_playbook(self) -> str:
        return '''
---
# incident-response.yml - Automated IR actions
- name: Incident Response - Host Isolation
  hosts: "{{ affected_host }}"
  become: yes
  
  tasks:
    - name: Collect running processes snapshot
      command: ps auxf
      register: process_list
    
    - name: Collect network connections
      command: ss -tupan
      register: network_connections
    
    - name: Collect open files
      command: lsof -n
      register: open_files
    
    - name: Save artifacts to evidence directory
      copy:
        content: "{{ item.content }}"
        dest: "/tmp/ir_evidence/{{ item.filename }}"
      loop:
        - {content: "{{ process_list.stdout }}", filename: "processes.txt"}
        - {content: "{{ network_connections.stdout }}", filename: "network.txt"}
        - {content: "{{ open_files.stdout }}", filename: "open_files.txt"}
    
    - name: Block all outbound traffic (isolation)
      iptables:
        chain: OUTPUT
        policy: DROP
      when: isolation_mode | default(false)
    
    - name: Allow only management IP
      iptables:
        chain: OUTPUT
        destination: "{{ management_ip }}"
        jump: ACCEPT
      when: isolation_mode | default(false)
'''


if __name__ == '__main__':
    ansible = AnsibleSecurity()
    print("Ansible security automation:")
    print("  1. Hardening playbook - SSH, passwords, firewall, audit")
    print("  2. IR playbook - collect artifacts, isolate host")
    print("  3. Patch playbook - update packages (see Part 84)")
    print("  4. Compliance check - CIS benchmark validation")
```

## Step 845-850: Security Automation Best Practices

แนวปฏิบัติที่ดีสำหรับ Security Automation

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class AutomationBestPractices:
    """Best practices for security automation programs"""
    
    def runbook_automation(self) -> Dict:
        return {
            "concept": "Convert manual runbooks to automated playbooks",
            "approach": [
                "Document current manual process step by step",
                "Identify steps that can be automated (API calls)",
                "Identify steps requiring human judgment",
                "Build automated steps around human decision points",
                "Test with real alerts in staging environment"
            ],
            "human_in_loop_examples": [
                "Confirm before deleting account (reversible vs non-reversible)",
                "Approval for blocking production system",
                "Escalation decision for high-impact actions"
            ]
        }
    
    def metrics_to_track(self) -> Dict:
        return {
            "efficiency": [
                "Alert volume handled per analyst",
                "% alerts auto-closed vs. needing human review",
                "Mean time to detect (MTTD)",
                "Mean time to respond (MTTR)"
            ],
            "quality": [
                "False positive rate of automated actions",
                "Alert fatigue score",
                "Automation coverage (% incidents with playbook)",
                "Analyst satisfaction with automation"
            ]
        }
    
    def api_security_automation(self) -> str:
        return '''
# Centralized security automation hub
from flask import Flask, request, jsonify
import hmac
import hashlib

app = Flask(__name__)
SOAR_SECRET = b"shared_secret_key"

# Webhook receiver for SIEM alerts
@app.route("/webhook/siem", methods=["POST"])
def receive_siem_alert():
    # Verify webhook signature
    signature = request.headers.get("X-Signature")
    body = request.get_data()
    expected = hmac.new(SOAR_SECRET, body, hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(signature or "", expected):
        return jsonify({"error": "Invalid signature"}), 401
    
    alert = request.get_json()
    
    # Route to appropriate playbook
    alert_type = alert.get("type", "unknown")
    
    if alert_type == "malware_detection":
        result = run_malware_playbook(alert)
    elif alert_type == "brute_force":
        result = run_brute_force_playbook(alert)
    elif alert_type == "data_exfiltration":
        result = run_exfil_playbook(alert)
    else:
        result = create_generic_ticket(alert)
    
    return jsonify(result)

def run_malware_playbook(alert: dict) -> dict:
    # Malware response automation
    actions = []
    
    # 1. Enrich
    vt_result = check_virustotal(alert.get("file_hash"))
    actions.append({"action": "vt_lookup", "result": vt_result})
    
    # 2. Contain (if confirmed)
    if vt_result.get("malicious", 0) > 5:
        isolate_endpoint(alert.get("hostname"))
        actions.append({"action": "host_isolated"})
    
    # 3. Ticket
    ticket = create_jira_ticket(alert, priority="P1")
    actions.append({"action": "ticket_created", "id": ticket})
    
    return {"playbook": "malware_response", "actions": actions}
'''
    
    def automation_pitfalls(self) -> List[str]:
        return [
            "Automating without testing - can block legitimate traffic",
            "No human escalation path for edge cases",
            "Brittle integrations - break when APIs change",
            "Alert fatigue from too many notifications",
            "No logging of automated actions (audit trail missing)",
            "Credentials hardcoded in scripts",
            "No rollback capability for automated actions"
        ]


if __name__ == '__main__':
    bp = AutomationBestPractices()
    print("Runbook automation approach:")
    for step in bp.runbook_automation()['approach']:
        print(f"  {step}")
    
    print("\nAutomation pitfalls to avoid:")
    for pitfall in bp.automation_pitfalls():
        print(f"  - {pitfall}")
    
    print("\nKey metrics:")
    for metric in bp.metrics_to_track()['efficiency']:
        print(f"  - {metric}")
```

---

## สรุป Part 85

| Step | หัวข้อ | เนื้อหาสำคัญ |
|------|--------|-------------|
| 841 | SOAR Fundamentals | Capabilities, platforms, use cases |
| 842 | TheHive/Cortex | Setup, Python API, analyzers |
| 843 | Python Automation | IOC enrichment, alert triage, SIEM integration |
| 844 | Ansible Security | Hardening playbook, IR playbook |
| 845-850 | Best Practices | Runbooks, metrics, API hub, pitfalls |
