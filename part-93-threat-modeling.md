# Part 93: Threat Modeling (Steps 921-930)

## ภาพรวม
การทำ Threat Modeling เป็นกระบวนการเชิงรุกในการระบุ วิเคราะห์ และลด Threat ในระบบก่อนที่จะถูก Exploit
ในส่วนนี้จะครอบคลุมวิธีการ STRIDE, DREAD, PASTA, Attack Trees และการสร้าง Data Flow Diagrams

---

## Step 921: Threat Modeling Fundamentals และ STRIDE Framework

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import json

class STRIDECategory(Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"

@dataclass
class ThreatModelingFramework:
    """กรอบการทำ Threat Modeling สำหรับ Penetration Tester"""
    
    METHODOLOGIES = {
        "STRIDE": {
            "creator": "Microsoft",
            "focus": "Threat Categories",
            "best_for": "Application security",
            "components": ["Spoofing", "Tampering", "Repudiation",
                           "Information Disclosure", "DoS", "Elevation of Privilege"]
        },
        "DREAD": {
            "creator": "Microsoft",
            "focus": "Risk Scoring",
            "best_for": "Prioritizing threats",
            "components": ["Damage", "Reproducibility", "Exploitability",
                           "Affected Users", "Discoverability"]
        },
        "PASTA": {
            "creator": "VerSprite",
            "focus": "Attack Simulation",
            "best_for": "Risk-centric analysis",
            "components": ["Define Objectives", "Define Technical Scope",
                           "Decompose Application", "Threat Analysis",
                           "Vulnerability Analysis", "Attack Enumeration",
                           "Risk/Impact Analysis"]
        },
        "LINDDUN": {
            "creator": "KU Leuven",
            "focus": "Privacy threats",
            "best_for": "Privacy-sensitive systems",
            "components": ["Linkability", "Identifiability", "Non-repudiation",
                           "Detectability", "Disclosure", "Unawareness", "Non-compliance"]
        },
        "VAST": {
            "creator": "ThreatModeler",
            "focus": "Agile/DevOps",
            "best_for": "Large organizations",
            "components": ["Application TM", "Operational TM"]
        }
    }
    
    THREAT_MODEL_ARTIFACTS = [
        "Data Flow Diagram (DFD)",
        "Trust Boundary Map",
        "Asset Inventory",
        "Threat Register",
        "Risk Register",
        "Mitigation Roadmap",
        "Security Requirements"
    ]
    
    def select_methodology(self, context: Dict) -> str:
        """เลือก methodology ที่เหมาะสมตาม context"""
        if context.get("privacy_requirements"):
            return "LINDDUN"
        elif context.get("agile_team") and context.get("large_org"):
            return "VAST"
        elif context.get("need_risk_score"):
            return "DREAD"
        elif context.get("risk_centric"):
            return "PASTA"
        else:
            return "STRIDE"  # Default recommendation
    
    def threat_modeling_process(self) -> List[str]:
        """ขั้นตอนการทำ Threat Modeling"""
        return [
            "1. Define scope and objectives",
            "2. Decompose the application/system",
            "3. Identify assets and entry points",
            "4. Draw Data Flow Diagrams",
            "5. Identify trust boundaries",
            "6. Enumerate threats (STRIDE)",
            "7. Rate and prioritize threats (DREAD)",
            "8. Identify mitigations",
            "9. Validate mitigations",
            "10. Document and track"
        ]

class STRIDEThreatModeling:
    """การทำ Threat Modeling ด้วย STRIDE Framework"""
    
    STRIDE_MITIGATIONS = {
        STRIDECategory.SPOOFING: [
            "Strong authentication (MFA)",
            "Certificate pinning",
            "Digital signatures",
            "HTTPS/TLS enforcement",
            "OAuth 2.0 / OpenID Connect"
        ],
        STRIDECategory.TAMPERING: [
            "Data integrity checks (HMAC)",
            "Digital signatures",
            "Input validation",
            "Parameterized queries",
            "Checksums for files"
        ],
        STRIDECategory.REPUDIATION: [
            "Comprehensive audit logging",
            "Tamper-evident logs",
            "Digital signatures on transactions",
            "Non-repudiation services",
            "Timestamping"
        ],
        STRIDECategory.INFORMATION_DISCLOSURE: [
            "Encryption at rest and in transit",
            "Access control (least privilege)",
            "Data classification",
            "Secure error handling",
            "Key management"
        ],
        STRIDECategory.DENIAL_OF_SERVICE: [
            "Rate limiting",
            "Resource quotas",
            "Load balancing",
            "DDoS protection",
            "Circuit breakers"
        ],
        STRIDECategory.ELEVATION_OF_PRIVILEGE: [
            "Principle of least privilege",
            "Privilege separation",
            "Input validation",
            "Sandboxing",
            "RBAC/ABAC"
        ]
    }
    
    def analyze_component(self, component: str, component_type: str) -> Dict:
        """วิเคราะห์ threat สำหรับ component ด้วย STRIDE"""
        threats = {}
        
        # กำหนด threat ตามประเภทของ component
        threat_map = {
            "web_server": {
                STRIDECategory.SPOOFING: "Attacker impersonates legitimate server",
                STRIDECategory.TAMPERING: "Request/response manipulation via MITM",
                STRIDECategory.INFORMATION_DISCLOSURE: "Server error messages expose internal details",
                STRIDECategory.DENIAL_OF_SERVICE: "HTTP flood, Slowloris attacks"
            },
            "database": {
                STRIDECategory.SPOOFING: "Credential theft to impersonate DB user",
                STRIDECategory.TAMPERING: "SQL injection to modify data",
                STRIDECategory.REPUDIATION: "No audit trail for data changes",
                STRIDECategory.INFORMATION_DISCLOSURE: "SQL injection to extract data",
                STRIDECategory.ELEVATION_OF_PRIVILEGE: "Stored procedures with elevated rights"
            },
            "api": {
                STRIDECategory.SPOOFING: "JWT forgery or stolen API keys",
                STRIDECategory.TAMPERING: "Parameter tampering, Mass assignment",
                STRIDECategory.REPUDIATION: "Missing request logging",
                STRIDECategory.INFORMATION_DISCLOSURE: "Excessive data exposure",
                STRIDECategory.DENIAL_OF_SERVICE: "API abuse without rate limiting",
                STRIDECategory.ELEVATION_OF_PRIVILEGE: "BOLA/BFLA vulnerabilities"
            }
        }
        
        if component_type in threat_map:
            threats = threat_map[component_type]
        
        return {
            "component": component,
            "type": component_type,
            "threats": {cat.value: desc for cat, desc in threats.items()},
            "mitigations": {cat.value: mits for cat, mits in self.STRIDE_MITIGATIONS.items()
                           if cat in threats}
        }

if __name__ == "__main__":
    framework = ThreatModelingFramework()
    print("Threat Modeling Methodologies:")
    for name, info in framework.METHODOLOGIES.items():
        print(f"  {name}: {info['focus']}")
    
    stride = STRIDEThreatModeling()
    api_analysis = stride.analyze_component("Payment API", "api")
    print(f"\nAPI Threats: {list(api_analysis['threats'].keys())}")
```

---

## Step 922: DREAD Risk Scoring Model

```python
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class DREADScore:
    """DREAD Risk Scoring สำหรับ Threat Prioritization"""
    threat_name: str
    damage: int        # 0-10: ความเสียหายที่เกิดขึ้นถ้า exploit สำเร็จ
    reproducibility: int  # 0-10: ง่ายแค่ไหนในการ reproduce
    exploitability: int   # 0-10: ง่ายแค่ไหนในการ exploit
    affected_users: int   # 0-10: ผู้ใช้ที่ได้รับผลกระทบ
    discoverability: int  # 0-10: ง่ายแค่ไหนในการค้นพบ
    
    @property
    def total_score(self) -> float:
        return (self.damage + self.reproducibility + self.exploitability +
                self.affected_users + self.discoverability) / 5
    
    @property
    def risk_level(self) -> str:
        score = self.total_score
        if score >= 7.5:
            return "CRITICAL"
        elif score >= 5:
            return "HIGH"
        elif score >= 2.5:
            return "MEDIUM"
        else:
            return "LOW"

class DREADAnalysis:
    """การวิเคราะห์ความเสี่ยงด้วย DREAD Model"""
    
    SCORING_GUIDE = {
        "damage": {
            0: "No damage",
            3: "Individual user affected",
            6: "Multiple users affected",
            9: "Complete system/data compromise"
        },
        "reproducibility": {
            0: "Very hard, requires special circumstances",
            3: "Requires authentication or special access",
            6: "Reproducible by any user",
            10: "Always reproducible from browser"
        },
        "exploitability": {
            0: "Requires advanced skills and tools",
            3: "Requires skilled attacker",
            6: "Attacker needs some skills",
            9: "Novice attacker with available tools"
        },
        "affected_users": {
            0: "No users",
            3: "Some users (non-default config)",
            6: "Many users",
            10: "All users"
        },
        "discoverability": {
            0: "Very hard to discover",
            3: "Difficult to discover",
            6: "Obvious to an attacker",
            9: "Published vulnerability, easy to find"
        }
    }
    
    def score_threat(self, threat_name: str, scores: Dict[str, int]) -> DREADScore:
        """สร้าง DREAD score สำหรับ threat"""
        return DREADScore(
            threat_name=threat_name,
            damage=scores.get("damage", 0),
            reproducibility=scores.get("reproducibility", 0),
            exploitability=scores.get("exploitability", 0),
            affected_users=scores.get("affected_users", 0),
            discoverability=scores.get("discoverability", 0)
        )
    
    def prioritize_threats(self, threats: List[DREADScore]) -> List[DREADScore]:
        """เรียง threat ตาม priority"""
        return sorted(threats, key=lambda t: t.total_score, reverse=True)
    
    def generate_risk_report(self, threats: List[DREADScore]) -> str:
        """สร้าง Risk Report จาก DREAD scores"""
        prioritized = self.prioritize_threats(threats)
        report = ["# DREAD Risk Assessment Report\n"]
        
        for threat in prioritized:
            report.append(f"## {threat.threat_name}")
            report.append(f"- **Risk Level**: {threat.risk_level}")
            report.append(f"- **Total Score**: {threat.total_score:.1f}/10")
            report.append(f"- Damage: {threat.damage}/10")
            report.append(f"- Reproducibility: {threat.reproducibility}/10")
            report.append(f"- Exploitability: {threat.exploitability}/10")
            report.append(f"- Affected Users: {threat.affected_users}/10")
            report.append(f"- Discoverability: {threat.discoverability}/10\n")
        
        return "\n".join(report)

# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    dread = DREADAnalysis()
    
    threats = [
        dread.score_threat("SQL Injection in login", {
            "damage": 9, "reproducibility": 8, "exploitability": 7,
            "affected_users": 10, "discoverability": 6
        }),
        dread.score_threat("XSS in comment field", {
            "damage": 5, "reproducibility": 9, "exploitability": 8,
            "affected_users": 6, "discoverability": 7
        }),
        dread.score_threat("Insecure Direct Object Reference", {
            "damage": 7, "reproducibility": 9, "exploitability": 8,
            "affected_users": 8, "discoverability": 6
        })
    ]
    
    report = dread.generate_risk_report(threats)
    print(report)
```

---

## Step 923: Data Flow Diagram (DFD) Analysis

```python
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple
from enum import Enum

class DFDElementType(Enum):
    EXTERNAL_ENTITY = "External Entity"
    PROCESS = "Process"
    DATA_STORE = "Data Store"
    DATA_FLOW = "Data Flow"
    TRUST_BOUNDARY = "Trust Boundary"

@dataclass
class DFDElement:
    """องค์ประกอบใน Data Flow Diagram"""
    id: str
    name: str
    element_type: DFDElementType
    trust_level: int  # 0 = untrusted, 5 = highly trusted
    description: str = ""
    attributes: Dict = field(default_factory=dict)

@dataclass
class DataFlow:
    """การไหลของข้อมูลระหว่าง elements"""
    source_id: str
    dest_id: str
    data_description: str
    is_encrypted: bool = False
    authentication_required: bool = False
    crosses_trust_boundary: bool = False

class DFDAnalyzer:
    """วิเคราะห์ Data Flow Diagram เพื่อหา Security Threats"""
    
    def __init__(self):
        self.elements: Dict[str, DFDElement] = {}
        self.flows: List[DataFlow] = []
        self.trust_boundaries: List[Tuple[int, int]] = []  # (lower, upper) trust levels
    
    def add_element(self, element: DFDElement):
        """เพิ่ม element ลงใน DFD"""
        self.elements[element.id] = element
    
    def add_flow(self, flow: DataFlow):
        """เพิ่ม data flow"""
        # ตรวจสอบว่า flow ข้าม trust boundary หรือไม่
        if flow.source_id in self.elements and flow.dest_id in self.elements:
            src_trust = self.elements[flow.source_id].trust_level
            dst_trust = self.elements[flow.dest_id].trust_level
            if src_trust != dst_trust:
                flow.crosses_trust_boundary = True
        self.flows.append(flow)
    
    def identify_threat_surfaces(self) -> List[Dict]:
        """ระบุพื้นที่เสี่ยงจาก DFD"""
        threats = []
        
        for flow in self.flows:
            src = self.elements.get(flow.source_id)
            dst = self.elements.get(flow.dest_id)
            
            if not src or not dst:
                continue
            
            # External entity to process - injection risks
            if (src.element_type == DFDElementType.EXTERNAL_ENTITY and
                    dst.element_type == DFDElementType.PROCESS):
                threats.append({
                    "type": "Input Validation",
                    "description": f"Data from {src.name} to {dst.name} - injection risk",
                    "stride": ["Spoofing", "Tampering"],
                    "flow": f"{src.name} -> {dst.name}"
                })
            
            # Unencrypted flow across trust boundary
            if flow.crosses_trust_boundary and not flow.is_encrypted:
                threats.append({
                    "type": "Information Disclosure",
                    "description": f"Unencrypted data crossing trust boundary: {src.name} -> {dst.name}",
                    "stride": ["Information Disclosure", "Tampering"],
                    "flow": f"{src.name} -> {dst.name}"
                })
            
            # Process to data store without auth
            if (dst.element_type == DFDElementType.DATA_STORE and
                    not flow.authentication_required):
                threats.append({
                    "type": "Unauthorized Access",
                    "description": f"Data store {dst.name} accessible without auth",
                    "stride": ["Elevation of Privilege"],
                    "flow": f"{src.name} -> {dst.name}"
                })
        
        return threats
    
    def generate_dfd_report(self) -> str:
        """สร้าง DFD Security Analysis Report"""
        threats = self.identify_threat_surfaces()
        
        report = ["# DFD Security Analysis Report\n"]
        report.append(f"Elements: {len(self.elements)}")
        report.append(f"Data Flows: {len(self.flows)}")
        report.append(f"Identified Threats: {len(threats)}\n")
        
        report.append("## Trust Boundary Crossings")
        boundary_flows = [f for f in self.flows if f.crosses_trust_boundary]
        for flow in boundary_flows:
            src = self.elements.get(flow.source_id)
            dst = self.elements.get(flow.dest_id)
            if src and dst:
                enc_status = "Encrypted" if flow.is_encrypted else "UNENCRYPTED"
                report.append(f"  - {src.name} -> {dst.name} ({enc_status})")
        
        report.append("\n## Identified Threats")
        for threat in threats:
            report.append(f"\n### {threat['type']}")
            report.append(f"- {threat['description']}")
            report.append(f"- STRIDE: {', '.join(threat['stride'])}")
        
        return "\n".join(report)

# ตัวอย่าง: DFD สำหรับ Web Application
if __name__ == "__main__":
    dfd = DFDAnalyzer()
    
    # เพิ่ม elements
    dfd.add_element(DFDElement("user", "End User", DFDElementType.EXTERNAL_ENTITY, 0))
    dfd.add_element(DFDElement("webserver", "Web Server", DFDElementType.PROCESS, 3))
    dfd.add_element(DFDElement("appserver", "App Server", DFDElementType.PROCESS, 4))
    dfd.add_element(DFDElement("database", "Database", DFDElementType.DATA_STORE, 5))
    
    # เพิ่ม flows
    dfd.add_flow(DataFlow("user", "webserver", "HTTP Request", is_encrypted=True))
    dfd.add_flow(DataFlow("webserver", "appserver", "Internal API Call", is_encrypted=False))
    dfd.add_flow(DataFlow("appserver", "database", "SQL Query", authentication_required=True))
    
    report = dfd.generate_dfd_report()
    print(report)
```

---

## Step 924: Attack Trees

```python
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum

class NodeType(Enum):
    AND = "AND"  # ต้องทำทุก child node
    OR = "OR"   # ทำแค่ child node เดียวก็พอ

@dataclass
class AttackNode:
    """Node ใน Attack Tree"""
    name: str
    node_type: NodeType = NodeType.OR
    cost: float = 0.0        # ค่าใช้จ่ายในการโจมตี
    probability: float = 0.0  # โอกาสที่จะสำเร็จ (0-1)
    difficulty: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    is_leaf: bool = False
    countermeasure: str = ""
    children: List['AttackNode'] = field(default_factory=list)
    
    def add_child(self, child: 'AttackNode'):
        self.children.append(child)
        return self
    
    def calculate_min_cost(self) -> float:
        """คำนวณค่าใช้จ่ายต่ำสุดในการโจมตี"""
        if self.is_leaf:
            return self.cost
        
        child_costs = [child.calculate_min_cost() for child in self.children]
        
        if self.node_type == NodeType.AND:
            return sum(child_costs)  # AND: ต้องทำทุกอย่าง
        else:
            return min(child_costs)  # OR: เลือกทางที่ถูกที่สุด
    
    def get_attack_paths(self) -> List[List[str]]:
        """หาเส้นทางการโจมตีทั้งหมด"""
        if self.is_leaf:
            return [[self.name]]
        
        all_paths = []
        if self.node_type == NodeType.OR:
            for child in self.children:
                child_paths = child.get_attack_paths()
                for path in child_paths:
                    all_paths.append([self.name] + path)
        else:  # AND
            # รวม paths จากทุก children
            combined = [[]]
            for child in self.children:
                child_paths = child.get_attack_paths()
                new_combined = []
                for existing in combined:
                    for cp in child_paths:
                        new_combined.append(existing + cp)
                combined = new_combined
            all_paths = [[self.name] + combo for combo in combined]
        
        return all_paths

class AttackTreeBuilder:
    """สร้าง Attack Tree สำหรับ Threat Scenarios"""
    
    def build_web_app_attack_tree(self) -> AttackNode:
        """สร้าง Attack Tree สำหรับ Web Application"""
        
        # Root goal
        root = AttackNode("Compromise Web Application", NodeType.OR)
        
        # Path 1: Authentication Bypass
        auth_bypass = AttackNode("Bypass Authentication", NodeType.OR)
        sql_inject = AttackNode("SQL Injection in Login", is_leaf=True, 
                               cost=2, probability=0.4, difficulty="MEDIUM",
                               countermeasure="Parameterized queries")
        brute_force = AttackNode("Brute Force Attack", is_leaf=True,
                                cost=1, probability=0.2, difficulty="LOW",
                                countermeasure="Account lockout")
        credential_stuff = AttackNode("Credential Stuffing", is_leaf=True,
                                     cost=3, probability=0.5, difficulty="LOW",
                                     countermeasure="MFA")
        auth_bypass.add_child(sql_inject)
        auth_bypass.add_child(brute_force)
        auth_bypass.add_child(credential_stuff)
        
        # Path 2: Exploit Vulnerability
        exploit_vuln = AttackNode("Exploit Application Vulnerability", NodeType.OR)
        xss = AttackNode("Cross-Site Scripting", is_leaf=True,
                         cost=2, probability=0.6, difficulty="MEDIUM",
                         countermeasure="Output encoding")
        idor = AttackNode("IDOR Vulnerability", is_leaf=True,
                          cost=1, probability=0.7, difficulty="LOW",
                          countermeasure="Authorization checks")
        deserialization = AttackNode("Insecure Deserialization", is_leaf=True,
                                    cost=7, probability=0.3, difficulty="HIGH",
                                    countermeasure="Input validation")
        exploit_vuln.add_child(xss)
        exploit_vuln.add_child(idor)
        exploit_vuln.add_child(deserialization)
        
        root.add_child(auth_bypass)
        root.add_child(exploit_vuln)
        
        return root
    
    def print_tree(self, node: AttackNode, indent: int = 0) -> str:
        """แสดง Attack Tree แบบ text"""
        lines = []
        prefix = "  " * indent
        node_symbol = "[AND]" if node.node_type == NodeType.AND else "[OR]"
        
        if node.is_leaf:
            lines.append(f"{prefix}[LEAF] {node.name}")
            lines.append(f"{prefix}  Cost: {node.cost}, Probability: {node.probability}")
            lines.append(f"{prefix}  Countermeasure: {node.countermeasure}")
        else:
            lines.append(f"{prefix}{node_symbol} {node.name}")
            for child in node.children:
                lines.append(self.print_tree(child, indent + 1))
        
        return "\n".join(lines)

if __name__ == "__main__":
    builder = AttackTreeBuilder()
    tree = builder.build_web_app_attack_tree()
    
    print("=== Attack Tree ===")
    print(builder.print_tree(tree))
    print(f"\nMinimum attack cost: {tree.calculate_min_cost()}")
    
    paths = tree.get_attack_paths()
    print(f"\nNumber of attack paths: {len(paths)}")
```

---

## Step 925: PASTA Methodology (Process for Attack Simulation and Threat Analysis)

```python
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class PASTAAnalysis:
    """PASTA - 7-Stage Risk-Centric Threat Modeling"""
    
    STAGES = [
        {
            "stage": 1,
            "name": "Define Business Objectives",
            "activities": [
                "Identify business goals",
                "Define security requirements",
                "Identify compliance requirements (GDPR, PCI-DSS)",
                "Document risk appetite",
                "Identify key stakeholders"
            ],
            "outputs": ["Business Impact Analysis", "Risk Appetite Statement"]
        },
        {
            "stage": 2,
            "name": "Define Technical Scope",
            "activities": [
                "Enumerate application components",
                "Document infrastructure",
                "Identify third-party dependencies",
                "Map technology stack",
                "Document API endpoints"
            ],
            "outputs": ["Technology Inventory", "Architecture Diagram"]
        },
        {
            "stage": 3,
            "name": "Application Decomposition",
            "activities": [
                "Create Data Flow Diagrams",
                "Identify trust boundaries",
                "Document user roles",
                "Map data flows",
                "Identify entry/exit points"
            ],
            "outputs": ["DFD", "Use Case Diagrams", "Trust Boundary Map"]
        },
        {
            "stage": 4,
            "name": "Threat Analysis",
            "activities": [
                "Research threat intelligence",
                "Identify threat actors",
                "Map to ATT&CK framework",
                "Enumerate threats per component",
                "Use STRIDE per component"
            ],
            "outputs": ["Threat List", "Threat Actor Profiles"]
        },
        {
            "stage": 5,
            "name": "Vulnerability Analysis",
            "activities": [
                "Conduct vulnerability assessment",
                "Review CVE databases",
                "Analyze code for flaws",
                "Review security controls",
                "Analyze third-party libraries"
            ],
            "outputs": ["Vulnerability Register", "Control Gap Analysis"]
        },
        {
            "stage": 6,
            "name": "Attack Enumeration",
            "activities": [
                "Develop attack scenarios",
                "Build Attack Trees",
                "Model attack chains",
                "Simulate attacks in lab",
                "Test proof-of-concept exploits"
            ],
            "outputs": ["Attack Trees", "Attack Scenarios", "Proof of Concept"]
        },
        {
            "stage": 7,
            "name": "Risk and Impact Analysis",
            "activities": [
                "Calculate risk scores",
                "Map to business impact",
                "Prioritize remediations",
                "Cost-benefit analysis",
                "Create remediation roadmap"
            ],
            "outputs": ["Risk Register", "Remediation Roadmap", "Executive Report"]
        }
    ]
    
    def generate_pasta_template(self, application_name: str) -> Dict:
        """สร้าง PASTA template สำหรับ application"""
        return {
            "application": application_name,
            "version": "1.0",
            "stages": [
                {
                    "stage": stage["stage"],
                    "name": stage["name"],
                    "status": "NOT_STARTED",
                    "findings": [],
                    "outputs": {output: None for output in stage["outputs"]}
                }
                for stage in self.STAGES
            ]
        }
    
    def threat_actor_profiles(self) -> Dict:
        """Profile ของ Threat Actors ที่พบบ่อย"""
        return {
            "Script Kiddie": {
                "motivation": "Fun, notoriety",
                "skill_level": "Low",
                "resources": "Minimal",
                "attack_types": ["Known exploits", "Automated tools"],
                "likelihood": "HIGH"
            },
            "Cybercriminal": {
                "motivation": "Financial gain",
                "skill_level": "Medium-High",
                "resources": "Moderate",
                "attack_types": ["Ransomware", "Data theft", "BEC"],
                "likelihood": "HIGH"
            },
            "Nation-State APT": {
                "motivation": "Espionage, disruption",
                "skill_level": "Very High",
                "resources": "Extensive",
                "attack_types": ["Zero-days", "Supply chain", "Long-term persistence"],
                "likelihood": "LOW-MEDIUM"
            },
            "Insider Threat": {
                "motivation": "Financial, revenge, ideology",
                "skill_level": "Varies",
                "resources": "Internal access",
                "attack_types": ["Data exfiltration", "Sabotage"],
                "likelihood": "MEDIUM"
            },
            "Hacktivist": {
                "motivation": "Political, ideological",
                "skill_level": "Low-Medium",
                "resources": "Limited",
                "attack_types": ["DDoS", "Defacement", "Data leaks"],
                "likelihood": "LOW-MEDIUM"
            }
        }

if __name__ == "__main__":
    pasta = PASTAAnalysis()
    template = pasta.generate_pasta_template("E-Commerce Platform")
    
    print(f"PASTA Analysis for: {template['application']}")
    for stage in template["stages"]:
        print(f"  Stage {stage['stage']}: {stage['name']} - {stage['status']}")
    
    print("\nThreat Actor Profiles:")
    for actor, profile in pasta.threat_actor_profiles().items():
        print(f"  {actor}: {profile['motivation']} (Likelihood: {profile['likelihood']})")
```

---

## Step 926: Threat Intelligence Integration

```python
import json
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime, timedelta

@dataclass
class ThreatIntelligence:
    """การรวม Threat Intelligence เข้ากับ Threat Modeling"""
    
    # MITRE ATT&CK Tactics (Enterprise)
    MITRE_TACTICS = {
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0010": "Exfiltration",
        "TA0011": "Command and Control",
        "TA0040": "Impact"
    }
    
    # Common Vulnerability Indicators
    IOC_TYPES = [
        "IP Address",
        "Domain Name",
        "URL",
        "File Hash (MD5/SHA1/SHA256)",
        "Email Address",
        "Registry Key",
        "Mutex",
        "User Agent String",
        "X.509 Certificate",
        "Network Port"
    ]
    
    THREAT_FEEDS = {
        "OpenSource": [
            {"name": "AlienVault OTX", "url": "https://otx.alienvault.com", "type": "Multi-type"},
            {"name": "Abuse.ch URLhaus", "url": "https://urlhaus.abuse.ch", "type": "URLs"},
            {"name": "Emerging Threats", "url": "https://rules.emergingthreats.net", "type": "IDS Rules"},
            {"name": "MISP", "url": "https://www.misp-project.org", "type": "Platform"}
        ],
        "Government": [
            {"name": "CISA Known Exploited", "url": "https://www.cisa.gov/known-exploited-vulnerabilities"},
            {"name": "NIST NVD", "url": "https://nvd.nist.gov"}
        ]
    }
    
    def map_threats_to_attack(self, threats: List[str]) -> Dict:
        """Map threats ไปยัง MITRE ATT&CK techniques"""
        mapping = {
            "phishing": {"tactic": "TA0001", "technique": "T1566", "sub": "T1566.001"},
            "brute_force": {"tactic": "TA0006", "technique": "T1110", "sub": "T1110.001"},
            "sql_injection": {"tactic": "TA0001", "technique": "T1190", "sub": None},
            "privilege_escalation": {"tactic": "TA0004", "technique": "T1068", "sub": None},
            "lateral_movement": {"tactic": "TA0008", "technique": "T1021", "sub": "T1021.001"},
            "data_exfiltration": {"tactic": "TA0010", "technique": "T1041", "sub": None}
        }
        
        result = {}
        for threat in threats:
            threat_lower = threat.lower().replace(" ", "_")
            if threat_lower in mapping:
                mitre_info = mapping[threat_lower]
                tactic_name = self.MITRE_TACTICS.get(mitre_info["tactic"], "Unknown")
                result[threat] = {
                    "tactic": f"{mitre_info['tactic']}: {tactic_name}",
                    "technique": mitre_info["technique"],
                    "subtechnique": mitre_info["sub"]
                }
        
        return result
    
    def create_ioc_list(self, indicators: List[Dict]) -> str:
        """สร้าง IOC list ในรูปแบบ STIX-like"""
        ioc_list = {
            "version": "2.1",
            "type": "bundle",
            "created": datetime.now().isoformat(),
            "objects": []
        }
        
        for ioc in indicators:
            obj = {
                "type": "indicator",
                "id": f"indicator--{hashlib.md5(ioc.get('value', '').encode()).hexdigest()}",
                "created": datetime.now().isoformat(),
                "pattern_type": "stix",
                "pattern": f"[{ioc.get('type', 'network-traffic')}:value = '{ioc.get('value', '')}']",
                "valid_from": datetime.now().isoformat(),
                "valid_until": (datetime.now() + timedelta(days=90)).isoformat(),
                "labels": ioc.get("labels", ["malicious-activity"])
            }
            ioc_list["objects"].append(obj)
        
        return json.dumps(ioc_list, indent=2)

if __name__ == "__main__":
    ti = ThreatIntelligence()
    
    threats = ["sql_injection", "brute_force", "lateral_movement"]
    mapped = ti.map_threats_to_attack(threats)
    
    print("Threat to MITRE ATT&CK Mapping:")
    for threat, info in mapped.items():
        print(f"  {threat}: {info['tactic']} -> {info['technique']}")
```

---

## Step 927: Security Requirements Engineering

```python
from dataclasses import dataclass, field
from typing import List, Dict
from enum import Enum

class RequirementCategory(Enum):
    AUTHENTICATION = "Authentication"
    AUTHORIZATION = "Authorization"
    DATA_PROTECTION = "Data Protection"
    AUDIT_LOGGING = "Audit & Logging"
    SECURE_COMMUNICATION = "Secure Communication"
    INPUT_VALIDATION = "Input Validation"
    ERROR_HANDLING = "Error Handling"
    SESSION_MANAGEMENT = "Session Management"

@dataclass
class SecurityRequirement:
    """Security Requirement ที่ได้จาก Threat Modeling"""
    id: str
    category: RequirementCategory
    description: str
    priority: str  # MUST, SHOULD, MAY (MoSCoW)
    threat_addressed: str
    acceptance_criteria: List[str] = field(default_factory=list)
    test_cases: List[str] = field(default_factory=list)
    compliance: List[str] = field(default_factory=list)  # GDPR, PCI-DSS, etc.

class SecurityRequirementsEngine:
    """สร้าง Security Requirements จาก Threat Analysis"""
    
    OWASP_ASVS_MAPPING = {
        "Authentication": "ASVS V2",
        "Session Management": "ASVS V3",
        "Access Control": "ASVS V4",
        "Validation": "ASVS V5",
        "Cryptography": "ASVS V6",
        "Error Handling": "ASVS V7",
        "Data Protection": "ASVS V8",
        "Communications": "ASVS V9",
        "Malicious Code": "ASVS V10",
        "Business Logic": "ASVS V11",
        "Files": "ASVS V12",
        "API": "ASVS V13",
        "Configuration": "ASVS V14"
    }
    
    def threats_to_requirements(self, threats: List[Dict]) -> List[SecurityRequirement]:
        """แปลง threats เป็น security requirements"""
        requirements = []
        req_counter = 1
        
        threat_req_map = {
            "SQL Injection": SecurityRequirement(
                id=f"SR-{req_counter:03d}",
                category=RequirementCategory.INPUT_VALIDATION,
                description="All database queries MUST use parameterized statements or prepared statements",
                priority="MUST",
                threat_addressed="SQL Injection",
                acceptance_criteria=[
                    "No dynamic SQL string concatenation with user input",
                    "All queries use ORM or parameterized queries",
                    "Penetration test shows no SQLi vulnerabilities"
                ],
                test_cases=[
                    "Attempt SQL injection in all input fields",
                    "Code review for string concatenation in SQL",
                    "Automated SAST scan shows no SQL injection findings"
                ],
                compliance=["PCI-DSS 6.2.4", "OWASP ASVS V5"]
            ),
            "Authentication Bypass": SecurityRequirement(
                id=f"SR-{req_counter+1:03d}",
                category=RequirementCategory.AUTHENTICATION,
                description="Multi-factor authentication MUST be implemented for all privileged accounts",
                priority="MUST",
                threat_addressed="Authentication Bypass",
                acceptance_criteria=[
                    "MFA enabled for admin accounts",
                    "Brute force protection active (lockout after 5 attempts)",
                    "Password complexity requirements enforced"
                ],
                test_cases=[
                    "Attempt brute force on login endpoint",
                    "Verify account lockout triggers",
                    "Test MFA bypass attempts"
                ],
                compliance=["NIST 800-63B", "ISO 27001 A.9.4.2"]
            )
        }
        
        for threat in threats:
            threat_name = threat.get("name", "")
            if threat_name in threat_req_map:
                requirements.append(threat_req_map[threat_name])
        
        return requirements
    
    def generate_security_requirements_doc(self, app_name: str, requirements: List[SecurityRequirement]) -> str:
        """สร้าง Security Requirements Document"""
        doc = [f"# Security Requirements Document: {app_name}\n"]
        doc.append(f"Generated: {__import__('datetime').datetime.now().strftime('%Y-%m-%d')}\n")
        
        # Group by category
        by_category: Dict[str, List] = {}
        for req in requirements:
            cat = req.category.value
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(req)
        
        for category, reqs in by_category.items():
            doc.append(f"## {category}")
            for req in reqs:
                doc.append(f"\n### {req.id}: {req.description}")
                doc.append(f"- **Priority**: {req.priority}")
                doc.append(f"- **Threat Addressed**: {req.threat_addressed}")
                doc.append("- **Acceptance Criteria**:")
                for ac in req.acceptance_criteria:
                    doc.append(f"  - {ac}")
                doc.append("- **Test Cases**:")
                for tc in req.test_cases:
                    doc.append(f"  - {tc}")
                if req.compliance:
                    doc.append(f"- **Compliance**: {', '.join(req.compliance)}")
        
        return "\n".join(doc)

if __name__ == "__main__":
    engine = SecurityRequirementsEngine()
    threats = [
        {"name": "SQL Injection"},
        {"name": "Authentication Bypass"}
    ]
    requirements = engine.threats_to_requirements(threats)
    doc = engine.generate_security_requirements_doc("Banking App", requirements)
    print(doc[:1000])  # Print first 1000 chars
```

---

## Step 928: Threat Model Automation Tools

```python
import subprocess
import json
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict

class ThreatModelingTools:
    """เครื่องมือ Threat Modeling ยอดนิยม"""
    
    TOOLS = {
        "Microsoft Threat Modeling Tool": {
            "type": "Desktop",
            "os": "Windows",
            "methodology": "STRIDE",
            "cost": "Free",
            "features": ["DFD creation", "Automatic threat generation", "Report generation"],
            "download": "https://aka.ms/threatmodelingtool"
        },
        "OWASP Threat Dragon": {
            "type": "Web/Desktop",
            "os": "Cross-platform",
            "methodology": "STRIDE",
            "cost": "Free/Open Source",
            "features": ["DFD editor", "GitHub integration", "JSON-based models"],
            "install": "npm install -g owasp-threat-dragon"
        },
        "IriusRisk": {
            "type": "SaaS",
            "methodology": "Multiple",
            "cost": "Commercial",
            "features": ["Automated threat modeling", "CI/CD integration", "Compliance mapping"]
        },
        "ThreatSpec": {
            "type": "Code annotation",
            "methodology": "Custom",
            "cost": "Free/Open Source",
            "features": ["Inline code annotations", "Automated report", "Git integration"],
            "install": "pip install threatspec"
        },
        "pytm": {
            "type": "Python library",
            "methodology": "STRIDE",
            "cost": "Free/Open Source",
            "features": ["Code-based threat models", "DFD generation", "Report generation"],
            "install": "pip install pytm"
        }
    }
    
    PYTM_EXAMPLE = '''
# ตัวอย่างการใช้ pytm สร้าง Threat Model
from pytm import (
    TM,
    Actor,
    Boundary,
    Dataflow,
    Datastore,
    Process,
    Server,
)

tm = TM("My Threat Model")
tm.description = "Simple web application threat model"
tm.isOrdered = True
tm.mergeResponses = True

Internet = Boundary("Internet")
Server_Side = Boundary("Server Side")

user = Actor("User")
user.inBoundary = Internet

web = Server("Web Server")
web.OS = "Ubuntu"
web.isHardened = True
web.inBoundary = Server_Side

db = Datastore("Database")
db.OS = "Ubuntu"
db.isSQL = True
db.inBoundary = Server_Side
db.isShared = False

app = Process("Application")
app.inBoundary = Server_Side

web_to_db = Dataflow(web, db, "Web to DB")
web_to_db.protocol = "MySQL"
web_to_db.isEncrypted = True

tm.process()
'''
    
    THREATSPEC_ANNOTATIONS = '''
# ThreatSpec - Annotation-based Threat Modeling
# ใส่ annotation ในโค้ดเพื่อ document threats

def process_user_input(data: str) -> str:
    # @mitigates @input_validation against sql_injection with "Parameterized queries"
    # @transfers @webapp to @database of user_data with "Encrypted MySQL connection"
    # @exposes @database to unauthorized_access with "If auth fails"
    
    # Process data...
    return data

# Generate report:
# threatspec report --format markdown --output report.md
'''

class AutomatedThreatModeling:
    """Automated Threat Modeling Pipeline"""
    
    def __init__(self, model_path: str):
        self.model_path = Path(model_path)
    
    def generate_threat_dragon_model(self, app_config: Dict) -> Dict:
        """สร้าง OWASP Threat Dragon model format"""
        model = {
            "version": "2.0",
            "summary": {
                "title": app_config.get("name", "Unnamed"),
                "owner": app_config.get("owner", "Security Team"),
                "description": app_config.get("description", ""),
                "id": 0
            },
            "detail": {
                "contributors": [],
                "diagrams": [
                    {
                        "id": 0,
                        "title": "Main Data Flow",
                        "diagramType": "STRIDE",
                        "placeholder": False,
                        "thumbnail": "",
                        "version": "2.0",
                        "cells": self._generate_cells(app_config)
                    }
                ]
            }
        }
        return model
    
    def _generate_cells(self, config: Dict) -> List:
        """สร้าง diagram cells"""
        cells = []
        y_position = 100
        
        for component in config.get("components", []):
            cell = {
                "type": self._map_component_type(component["type"]),
                "id": component["id"],
                "attrs": {"text": {"text": component["name"]}},
                "position": {"x": 200, "y": y_position},
                "size": {"width": 112, "height": 60},
                "data": {
                    "type": component["type"],
                    "name": component["name"],
                    "description": component.get("description", ""),
                    "threats": []
                }
            }
            cells.append(cell)
            y_position += 150
        
        return cells
    
    def _map_component_type(self, comp_type: str) -> str:
        type_map = {
            "actor": "tm.Actor",
            "process": "tm.Process",
            "datastore": "tm.Store",
            "flow": "tm.Flow",
            "boundary": "tm.Boundary"
        }
        return type_map.get(comp_type, "tm.Process")

if __name__ == "__main__":
    tools = ThreatModelingTools()
    print("Available Threat Modeling Tools:")
    for tool, info in tools.TOOLS.items():
        print(f"  {tool}: {info.get('cost', 'Unknown')} - {info['methodology']}")
    
    atm = AutomatedThreatModeling("/tmp/model.json")
    model = atm.generate_threat_dragon_model({
        "name": "Test App",
        "owner": "Security Team",
        "description": "Test application threat model",
        "components": [
            {"id": "1", "type": "actor", "name": "End User"},
            {"id": "2", "type": "process", "name": "Web Server"},
            {"id": "3", "type": "datastore", "name": "Database"}
        ]
    })
    print(f"\nGenerated model: {model['summary']['title']}")
    print(f"Diagrams: {len(model['detail']['diagrams'])}")
```

---

## Step 929: Threat Model Report Generation

```python
from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime

@dataclass
class ThreatFinding:
    """Threat ที่พบจาก Threat Modeling"""
    id: str
    title: str
    category: str
    stride_category: str
    affected_component: str
    description: str
    impact: str
    likelihood: str  # LOW, MEDIUM, HIGH
    severity: str    # LOW, MEDIUM, HIGH, CRITICAL
    mitigations: List[str]
    status: str = "OPEN"  # OPEN, IN_PROGRESS, MITIGATED, ACCEPTED
    dread_score: float = 0.0

class ThreatModelReporter:
    """สร้าง Professional Threat Model Report"""
    
    RISK_MATRIX = {
        ("HIGH", "HIGH"): "CRITICAL",
        ("HIGH", "MEDIUM"): "HIGH",
        ("HIGH", "LOW"): "MEDIUM",
        ("MEDIUM", "HIGH"): "HIGH",
        ("MEDIUM", "MEDIUM"): "MEDIUM",
        ("MEDIUM", "LOW"): "LOW",
        ("LOW", "HIGH"): "MEDIUM",
        ("LOW", "MEDIUM"): "LOW",
        ("LOW", "LOW"): "INFO"
    }
    
    def calculate_severity(self, likelihood: str, impact: str) -> str:
        """คำนวณ severity จาก likelihood และ impact"""
        return self.RISK_MATRIX.get((likelihood, impact), "MEDIUM")
    
    def generate_executive_summary(self, findings: List[ThreatFinding], app_name: str) -> str:
        """สร้าง Executive Summary"""
        critical = sum(1 for f in findings if f.severity == "CRITICAL")
        high = sum(1 for f in findings if f.severity == "HIGH")
        medium = sum(1 for f in findings if f.severity == "MEDIUM")
        low = sum(1 for f in findings if f.severity == "LOW")
        open_count = sum(1 for f in findings if f.status == "OPEN")
        
        summary = f"""# Threat Model Report: {app_name}
**Date**: {datetime.now().strftime('%Y-%m-%d')}
**Classification**: CONFIDENTIAL

## Executive Summary

A comprehensive threat modeling exercise was conducted for **{app_name}** 
using the STRIDE and PASTA methodologies. This assessment identified 
**{len(findings)} threats** across multiple components.

### Risk Distribution
| Severity | Count |
|----------|-------|
| Critical | {critical} |
| High | {high} |
| Medium | {medium} |
| Low | {low} |
| **Total** | **{len(findings)}** |

### Key Findings Summary
- **{open_count} threats** require immediate remediation
- Most critical area: Authentication and Authorization
- Recommended priority: Address all Critical and High severity items within 30 days
"""
        return summary
    
    def generate_detailed_findings(self, findings: List[ThreatFinding]) -> str:
        """สร้าง Detailed Findings Section"""
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 4))
        
        doc = ["## Detailed Findings\n"]
        
        for finding in sorted_findings:
            doc.append(f"### {finding.id}: {finding.title}")
            doc.append(f"| Attribute | Value |")
            doc.append(f"|-----------|-------|")
            doc.append(f"| **Severity** | {finding.severity} |")
            doc.append(f"| **Category** | {finding.category} |")
            doc.append(f"| **STRIDE** | {finding.stride_category} |")
            doc.append(f"| **Component** | {finding.affected_component} |")
            doc.append(f"| **Likelihood** | {finding.likelihood} |")
            doc.append(f"| **Impact** | {finding.impact} |")
            doc.append(f"| **Status** | {finding.status} |")
            doc.append(f"\n**Description**: {finding.description}\n")
            doc.append("**Recommended Mitigations**:")
            for i, mitigation in enumerate(finding.mitigations, 1):
                doc.append(f"{i}. {mitigation}")
            doc.append("")
        
        return "\n".join(doc)
    
    def generate_full_report(self, findings: List[ThreatFinding], app_name: str) -> str:
        """สร้าง Full Threat Model Report"""
        executive = self.generate_executive_summary(findings, app_name)
        detailed = self.generate_detailed_findings(findings)
        
        mitigations_section = "\n## Mitigation Roadmap\n"
        mitigations_section += "### Immediate (0-30 days)\n"
        for f in findings:
            if f.severity in ["CRITICAL", "HIGH"]:
                mitigations_section += f"- [{f.id}] {f.title}\n"
        
        return executive + "\n" + detailed + "\n" + mitigations_section

if __name__ == "__main__":
    reporter = ThreatModelReporter()
    
    findings = [
        ThreatFinding(
            id="TM-001",
            title="SQL Injection in Login",
            category="Injection",
            stride_category="Tampering",
            affected_component="Authentication API",
            description="Login endpoint vulnerable to SQL injection",
            impact="HIGH",
            likelihood="HIGH",
            severity="CRITICAL",
            mitigations=["Use parameterized queries", "Deploy WAF", "Input validation"]
        ),
        ThreatFinding(
            id="TM-002",
            title="Reflected XSS in Search",
            category="XSS",
            stride_category="Tampering",
            affected_component="Search Feature",
            description="Search parameter reflected without encoding",
            impact="MEDIUM",
            likelihood="HIGH",
            severity="HIGH",
            mitigations=["Output encoding", "CSP headers", "Input validation"]
        )
    ]
    
    report = reporter.generate_full_report(findings, "E-Commerce Platform")
    print(report[:1500])
```

---

## Step 930: Continuous Threat Modeling in DevSecOps

```python
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class ContinuousThreatModeling:
    """Threat Modeling แบบต่อเนื่องใน DevSecOps Pipeline"""
    
    DEVSECOPS_INTEGRATION = {
        "Planning": {
            "activities": [
                "Review threat model for new features",
                "Update trust boundaries",
                "Identify new assets",
                "Security requirements in user stories"
            ],
            "tools": ["JIRA with security templates", "GitHub Issues"],
            "artifacts": ["Threat Model Update", "Security User Stories"]
        },
        "Design": {
            "activities": [
                "Architecture review with STRIDE",
                "Update DFDs",
                "New component threat analysis",
                "API security review"
            ],
            "tools": ["IriusRisk", "Threat Dragon", "pytm"],
            "artifacts": ["Updated DFD", "Threat Register", "Security Architecture"]
        },
        "Development": {
            "activities": [
                "ThreatSpec code annotations",
                "Security unit tests",
                "SAST scanning",
                "Dependency scanning"
            ],
            "tools": ["ThreatSpec", "Bandit", "SonarQube", "Snyk"],
            "artifacts": ["Inline threat docs", "SAST reports"]
        },
        "Testing": {
            "activities": [
                "Threat-based test cases",
                "Security regression testing",
                "Penetration testing",
                "Validate mitigations"
            ],
            "tools": ["OWASP ZAP", "Burp Suite", "Atomic Red Team"],
            "artifacts": ["Security test results", "Penetration test report"]
        },
        "Deployment": {
            "activities": [
                "Security configuration review",
                "Infrastructure threat model",
                "Cloud security posture",
                "Secrets management verification"
            ],
            "tools": ["Terraform sentinel", "Checkov", "Prowler"],
            "artifacts": ["Infrastructure TM", "Security baseline"]
        },
        "Operations": {
            "activities": [
                "Monitor threat landscape",
                "Update with new CVEs",
                "Incident-driven updates",
                "Annual comprehensive review"
            ],
            "tools": ["SIEM", "Vulnerability scanners", "Threat Intel platforms"],
            "artifacts": ["Updated threat model", "Incident reports"]
        }
    }
    
    CI_CD_PIPELINE_INTEGRATION = '''
# GitHub Actions: Automated Threat Model Validation
name: Threat Model CI/CD

on:
  pull_request:
    paths:
      - 'threat-model/**'
      - 'src/**'
      - 'infrastructure/**'

jobs:
  validate-threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install tools
        run: pip install pytm threatspec bandit
      
      - name: Generate threat model report
        run: |
          python threat-model/generate.py \
            --output reports/threat-model.md \
            --format markdown
      
      - name: Run SAST
        run: |
          bandit -r src/ \
            --severity-level medium \
            -f json \
            -o reports/sast-report.json
      
      - name: Check for new high severity threats
        run: |
          python scripts/check_threat_delta.py \
            --baseline threat-model/baseline.json \
            --current reports/threat-model.md \
            --fail-on-new-critical
      
      - name: Update threat model baseline
        if: github.ref == 'refs/heads/main'
        run: |
          python scripts/update_baseline.py \
            --current reports/threat-model.md
      
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: reports/
'''
    
    METRICS_TO_TRACK = [
        "Time to identify new threats",
        "Number of threats identified per sprint",
        "Mitigation coverage rate",
        "Time to mitigate critical threats",
        "Threat model update frequency",
        "Security requirements coverage",
        "False positive rate from automated tools"
    ]
    
    def generate_threat_model_update_checklist(self) -> List[str]:
        """Checklist สำหรับการ update threat model"""
        return [
            "[ ] Review change log for security-relevant changes",
            "[ ] Identify new components or data flows",
            "[ ] Update DFD to reflect changes",
            "[ ] Apply STRIDE to new components",
            "[ ] Update threat register (add/close threats)",
            "[ ] Review trust boundaries",
            "[ ] Update security requirements",
            "[ ] Notify affected teams of changes",
            "[ ] Update risk register",
            "[ ] Schedule validation testing"
        ]
    
    def threat_model_maturity_model(self) -> Dict:
        """Threat Modeling Maturity Assessment"""
        return {
            "Level 1 - Initial": {
                "description": "Ad-hoc, reactive threat modeling",
                "indicators": ["No formal process", "Threats identified after incidents"],
                "score": "0-20%"
            },
            "Level 2 - Developing": {
                "description": "Basic threat modeling on new projects",
                "indicators": ["STRIDE used occasionally", "No integration with SDLC"],
                "score": "21-40%"
            },
            "Level 3 - Defined": {
                "description": "Defined threat modeling process",
                "indicators": ["Process documented", "Integrated with design phase"],
                "score": "41-60%"
            },
            "Level 4 - Managed": {
                "description": "Metrics-driven threat modeling",
                "indicators": ["Automated tools", "CI/CD integration", "Metrics tracked"],
                "score": "61-80%"
            },
            "Level 5 - Optimizing": {
                "description": "Continuous improvement",
                "indicators": ["Full DevSecOps integration", "Threat intel feeds", "Automated validation"],
                "score": "81-100%"
            }
        }

if __name__ == "__main__":
    ctm = ContinuousThreatModeling()
    
    print("DevSecOps Threat Modeling Integration:")
    for phase, details in ctm.DEVSECOPS_INTEGRATION.items():
        print(f"\n  {phase}:")
        for activity in details["activities"]:
            print(f"    - {activity}")
    
    print("\nThreat Model Maturity Levels:")
    for level, info in ctm.threat_model_maturity_model().items():
        print(f"  {level}: {info['score']}")
    
    checklist = ctm.generate_threat_model_update_checklist()
    print(f"\nUpdate Checklist ({len(checklist)} items):")
    for item in checklist[:5]:
        print(f"  {item}")
```

---

## สรุป Part 93 (Steps 921-930)

| Step | หัวข้อ | เนื้อหา |
|------|--------|--------|
| 921 | STRIDE Framework | STRIDECategory enum, ThreatModelingFramework, STRIDEThreatModeling |
| 922 | DREAD Risk Scoring | DREADScore dataclass, DREADAnalysis, Risk prioritization |
| 923 | Data Flow Diagrams | DFDElement, DataFlow, DFDAnalyzer, Trust boundary analysis |
| 924 | Attack Trees | AttackNode, NodeType, AttackTreeBuilder, attack paths |
| 925 | PASTA Methodology | 7-stage PASTA, Threat actor profiles, Risk-centric analysis |
| 926 | Threat Intelligence | MITRE ATT&CK mapping, IOC creation, Threat feeds |
| 927 | Security Requirements | SecurityRequirement, OWASP ASVS mapping, Requirements engineering |
| 928 | Automation Tools | pytm, ThreatSpec, Threat Dragon, Automated model generation |
| 929 | Report Generation | ThreatFinding, Risk matrix, Executive and detailed reports |
| 930 | Continuous TM | DevSecOps integration, CI/CD pipeline, Maturity model |
