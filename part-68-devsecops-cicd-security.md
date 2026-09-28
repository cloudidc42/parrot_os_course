# Part 68: DevSecOps & CI/CD Security (Steps 671-680)

## Step 671: DevSecOps Pipeline Security Framework

```python
import subprocess
import json
import os
import hashlib
import yaml
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import re

@dataclass
class SecurityGate:
    """Security gate ใน CI/CD pipeline"""
    name: str
    stage: str  # build, test, deploy
    severity_threshold: str  # critical, high, medium
    blocking: bool = True
    
    def check_results(self, findings: List[Dict]) -> Tuple[bool, List[Dict]]:
        """ตรวจสอบว่าผ่าน security gate หรือไม่"""
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        threshold_level = severity_order.get(self.severity_threshold, 2)
        
        blocking_findings = [
            f for f in findings
            if severity_order.get(f.get('severity', 'info'), 0) >= threshold_level
        ]
        
        passed = len(blocking_findings) == 0
        return passed, blocking_findings


class DevSecOpsPipeline:
    """DevSecOps pipeline security framework"""
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.findings = []
        
    def run_sast_scan(self) -> List[Dict]:
        """Static Application Security Testing"""
        findings = []
        
        # Bandit สำหรับ Python
        python_files = list(self.project_path.rglob('*.py'))
        if python_files:
            print("[*] Running Bandit (Python SAST)...")
            result = subprocess.run(
                ['bandit', '-r', str(self.project_path), '-f', 'json', '-q'],
                capture_output=True, text=True
            )
            try:
                bandit_results = json.loads(result.stdout)
                for issue in bandit_results.get('results', []):
                    findings.append({
                        'tool': 'bandit',
                        'type': 'SAST',
                        'severity': issue['issue_severity'].lower(),
                        'title': issue['issue_text'],
                        'file': issue['filename'],
                        'line': issue['line_number'],
                        'cwe': issue.get('issue_cwe', {}).get('id', 'N/A')
                    })
            except json.JSONDecodeError:
                pass
        
        # Semgrep สำหรับ multiple languages
        print("[*] Running Semgrep...")
        semgrep_cmd = [
            'semgrep', '--config=auto',
            '--json', str(self.project_path)
        ]
        result = subprocess.run(semgrep_cmd, capture_output=True, text=True)
        try:
            semgrep_results = json.loads(result.stdout)
            for finding in semgrep_results.get('results', []):
                findings.append({
                    'tool': 'semgrep',
                    'type': 'SAST',
                    'severity': finding.get('extra', {}).get('severity', 'medium').lower(),
                    'title': finding.get('extra', {}).get('message', ''),
                    'file': finding['path'],
                    'line': finding['start']['line'],
                    'rule_id': finding['check_id']
                })
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def run_dependency_scan(self) -> List[Dict]:
        """Software Composition Analysis (SCA)"""
        findings = []
        
        # Safety สำหรับ Python dependencies
        req_file = self.project_path / 'requirements.txt'
        if req_file.exists():
            print("[*] Running Safety (Python dependency check)...")
            result = subprocess.run(
                ['safety', 'check', '-r', str(req_file), '--json'],
                capture_output=True, text=True
            )
            try:
                safety_results = json.loads(result.stdout)
                for vuln in safety_results:
                    findings.append({
                        'tool': 'safety',
                        'type': 'SCA',
                        'severity': 'high',
                        'package': vuln[0],
                        'installed_version': vuln[2],
                        'vuln_id': vuln[4],
                        'description': vuln[3]
                    })
            except (json.JSONDecodeError, IndexError):
                pass
        
        # npm audit สำหรับ Node.js
        package_json = self.project_path / 'package.json'
        if package_json.exists():
            print("[*] Running npm audit...")
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                capture_output=True, text=True,
                cwd=str(self.project_path)
            )
            try:
                npm_results = json.loads(result.stdout)
                for vuln_name, vuln_data in npm_results.get('vulnerabilities', {}).items():
                    findings.append({
                        'tool': 'npm_audit',
                        'type': 'SCA',
                        'severity': vuln_data.get('severity', 'medium').lower(),
                        'package': vuln_name,
                        'via': [v if isinstance(v, str) else v.get('title', '') 
                                for v in vuln_data.get('via', [])]
                    })
            except json.JSONDecodeError:
                pass
        
        return findings
    
    def run_secret_scan(self) -> List[Dict]:
        """Secret detection ใน codebase"""
        findings = []
        
        print("[*] Running Gitleaks (secret detection)...")
        result = subprocess.run(
            ['gitleaks', 'detect', '--source', str(self.project_path),
             '--report-format', 'json', '--report-path', '/tmp/gitleaks.json',
             '--no-git'],
            capture_output=True, text=True
        )
        
        try:
            with open('/tmp/gitleaks.json') as f:
                leaks = json.load(f)
            for leak in leaks:
                findings.append({
                    'tool': 'gitleaks',
                    'type': 'Secret',
                    'severity': 'critical',
                    'rule': leak.get('RuleID', ''),
                    'file': leak.get('File', ''),
                    'line': leak.get('StartLine', 0),
                    'match': leak.get('Match', '')[:50] + '...'
                })
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        
        # Trufflehog
        print("[*] Running TruffleHog...")
        result = subprocess.run(
            ['trufflehog', 'filesystem', str(self.project_path), '--json'],
            capture_output=True, text=True
        )
        
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    leak = json.loads(line)
                    findings.append({
                        'tool': 'trufflehog',
                        'type': 'Secret',
                        'severity': 'critical',
                        'detector': leak.get('DetectorName', ''),
                        'file': leak.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', ''),
                        'verified': leak.get('Verified', False)
                    })
                except json.JSONDecodeError:
                    pass
        
        return findings
    
    def run_container_scan(self, image_name: str) -> List[Dict]:
        """Container image security scanning"""
        findings = []
        
        print(f"[*] Scanning container image: {image_name}")
        
        # Trivy
        result = subprocess.run(
            ['trivy', 'image', '--format', 'json', image_name],
            capture_output=True, text=True
        )
        try:
            trivy_results = json.loads(result.stdout)
            for result_item in trivy_results.get('Results', []):
                for vuln in result_item.get('Vulnerabilities', []):
                    findings.append({
                        'tool': 'trivy',
                        'type': 'Container',
                        'severity': vuln.get('Severity', 'UNKNOWN').lower(),
                        'cve': vuln.get('VulnerabilityID', ''),
                        'package': vuln.get('PkgName', ''),
                        'installed': vuln.get('InstalledVersion', ''),
                        'fixed': vuln.get('FixedVersion', 'No fix available'),
                        'description': vuln.get('Description', '')[:200]
                    })
        except json.JSONDecodeError:
            pass
        
        # Grype
        result = subprocess.run(
            ['grype', image_name, '-o', 'json'],
            capture_output=True, text=True
        )
        try:
            grype_results = json.loads(result.stdout)
            for match in grype_results.get('matches', []):
                vuln = match.get('vulnerability', {})
                findings.append({
                    'tool': 'grype',
                    'type': 'Container',
                    'severity': vuln.get('severity', 'unknown').lower(),
                    'cve': vuln.get('id', ''),
                    'package': match.get('artifact', {}).get('name', ''),
                    'fix_state': vuln.get('fix', {}).get('state', 'unknown')
                })
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def generate_security_report(self, all_findings: List[Dict]) -> Dict:
        """สร้าง security report สรุปผล"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        type_counts = {}
        
        for finding in all_findings:
            sev = finding.get('severity', 'info')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            ftype = finding.get('type', 'unknown')
            type_counts[ftype] = type_counts.get(ftype, 0) + 1
        
        risk_score = (
            severity_counts['critical'] * 10 +
            severity_counts['high'] * 5 +
            severity_counts['medium'] * 2 +
            severity_counts['low'] * 1
        )
        
        return {
            'total_findings': len(all_findings),
            'severity_breakdown': severity_counts,
            'type_breakdown': type_counts,
            'risk_score': risk_score,
            'risk_rating': 'CRITICAL' if risk_score > 50 else 'HIGH' if risk_score > 20 else 'MEDIUM' if risk_score > 5 else 'LOW',
            'top_findings': sorted(all_findings, 
                                   key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x.get('severity', 'low'), 0),
                                   reverse=True)[:10]
        }
```

## Step 672: GitHub Actions Security Workflow

```yaml
# .github/workflows/security.yml
# GitHub Actions workflow สำหรับ DevSecOps pipeline

name: Security Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # รันทุกวันตี 2

env:
  PYTHON_VERSION: '3.11'

jobs:
  # ===== SAST (Static Analysis) =====
  sast-scan:
    name: SAST - Static Analysis
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
    
    # Bandit สำหรับ Python
    - name: Run Bandit
      uses: jpetrucciani/bandit-check@main
      with:
        path: '.'
        bandit_flags: '-ll'
    
    # Semgrep
    - name: Run Semgrep
      uses: returntocorp/semgrep-action@v1
      with:
        config: >
          p/security-audit
          p/secrets
          p/owasp-top-ten
        generateSarif: true
    
    - name: Upload Semgrep SARIF
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: semgrep.sarif
      if: always()
    
    # CodeQL
    - name: Initialize CodeQL
      uses: github/codeql-action/init@v3
      with:
        languages: python, javascript
    
    - name: Run CodeQL Analysis
      uses: github/codeql-action/analyze@v3
      with:
        category: "/language:python"
  
  # ===== Secret Detection =====
  secret-scan:
    name: Secret Detection
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
    
    # Gitleaks
    - name: Run Gitleaks
      uses: gitleaks/gitleaks-action@v2
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    
    # TruffleHog
    - name: Run TruffleHog
      uses: trufflesecurity/trufflehog@main
      with:
        path: ./
        base: ${{ github.event.repository.default_branch }}
        head: HEAD
        extra_args: --debug --only-verified
  
  # ===== SCA (Dependency Scanning) =====
  dependency-scan:
    name: Dependency Scanning
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    # Snyk
    - name: Run Snyk
      uses: snyk/actions/python@master
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      with:
        args: --severity-threshold=high --sarif-file-output=snyk.sarif
    
    - name: Upload Snyk SARIF
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: snyk.sarif
    
    # OWASP Dependency Check
    - name: Run OWASP Dependency Check
      uses: dependency-check/Dependency-Check_Action@main
      with:
        project: 'test'
        path: '.'
        format: 'SARIF'
        args: --failOnCVSS 7
    
    - name: Upload OWASP results
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: reports/dependency-check-report.sarif
  
  # ===== IaC Security =====
  iac-scan:
    name: IaC Security Scan
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    # Checkov สำหรับ Terraform/CloudFormation
    - name: Run Checkov
      uses: bridgecrewio/checkov-action@v12
      with:
        directory: .
        framework: terraform,cloudformation,dockerfile,kubernetes
        output_format: sarif
        output_file_path: checkov.sarif
    
    - name: Upload Checkov SARIF
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: checkov.sarif
    
    # Terrascan
    - name: Run Terrascan
      uses: tenable/terrascan-action@main
      with:
        iac_type: 'terraform'
        iac_version: 'v14'
        policy_type: 'aws'
        only_warn: true
        sarif_upload: true
  
  # ===== Container Security =====
  container-scan:
    name: Container Security
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Build Docker image
      run: docker build -t app:${{ github.sha }} .
    
    # Trivy
    - name: Run Trivy
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'app:${{ github.sha }}'
        format: 'sarif'
        output: 'trivy-results.sarif'
        severity: 'CRITICAL,HIGH'
        exit-code: '1'
    
    - name: Upload Trivy SARIF
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: trivy-results.sarif
    
    # Hadolint สำหรับ Dockerfile lint
    - name: Run Hadolint
      uses: hadolint/hadolint-action@v3.1.0
      with:
        dockerfile: Dockerfile
        format: sarif
        output-file: hadolint-results.sarif
        failure-threshold: error
```

## Step 673: Infrastructure as Code Security Scanner

```python
import re
import json
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class IaCFinding:
    severity: str
    rule_id: str
    resource: str
    file: str
    line: int
    message: str
    remediation: str


class TerraformSecurityScanner:
    """Scanner สำหรับตรวจสอบ Terraform configurations"""
    
    SECURITY_RULES = [
        {
            'id': 'AWS001',
            'severity': 'critical',
            'pattern': r'0\.0\.0\.0/0',
            'resource_types': ['aws_security_group'],
            'message': 'Security group allows unrestricted ingress from internet',
            'remediation': 'Restrict ingress to specific IP ranges'
        },
        {
            'id': 'AWS002', 
            'severity': 'high',
            'pattern': r'encrypted\s*=\s*false',
            'resource_types': ['aws_ebs_volume', 'aws_db_instance'],
            'message': 'Storage is not encrypted at rest',
            'remediation': 'Enable encryption by setting encrypted = true'
        },
        {
            'id': 'AWS003',
            'severity': 'high',
            'pattern': r'publicly_accessible\s*=\s*true',
            'resource_types': ['aws_db_instance', 'aws_rds_cluster'],
            'message': 'Database is publicly accessible',
            'remediation': 'Set publicly_accessible = false'
        },
        {
            'id': 'AWS004',
            'severity': 'medium',
            'pattern': r'versioning.*enabled\s*=\s*false',
            'resource_types': ['aws_s3_bucket'],
            'message': 'S3 bucket versioning is disabled',
            'remediation': 'Enable versioning for S3 buckets'
        },
        {
            'id': 'AWS005',
            'severity': 'critical',
            'pattern': r'acl\s*=\s*["\']public-read["\']',
            'resource_types': ['aws_s3_bucket'],
            'message': 'S3 bucket is publicly readable',
            'remediation': 'Remove public-read ACL or use bucket policies'
        },
        {
            'id': 'AWS006',
            'severity': 'high',
            'pattern': r'deletion_protection\s*=\s*false',
            'resource_types': ['aws_db_instance'],
            'message': 'RDS deletion protection is disabled',
            'remediation': 'Enable deletion_protection = true'
        },
        {
            'id': 'K8S001',
            'severity': 'critical',
            'pattern': r'privileged:\s*true',
            'resource_types': ['kubernetes_pod', 'kubernetes_deployment'],
            'message': 'Container running in privileged mode',
            'remediation': 'Remove privileged: true from securityContext'
        },
        {
            'id': 'K8S002',
            'severity': 'high',
            'pattern': r'runAsRoot:\s*true|runAsUser:\s*0',
            'resource_types': ['kubernetes_pod'],
            'message': 'Container running as root user',
            'remediation': 'Set runAsNonRoot: true and specify non-root user'
        },
        {
            'id': 'DOCKER001',
            'severity': 'high',
            'pattern': r'^FROM.*:latest',
            'resource_types': ['dockerfile'],
            'message': 'Docker image using latest tag',
            'remediation': 'Pin Docker base image to specific version'
        },
        {
            'id': 'DOCKER002',
            'severity': 'medium',
            'pattern': r'^USER root',
            'resource_types': ['dockerfile'],
            'message': 'Container running as root',
            'remediation': 'Add USER directive with non-root user'
        }
    ]
    
    def scan_file(self, file_path: str) -> List[IaCFinding]:
        """สแกน IaC file หา security issues"""
        findings = []
        path = Path(file_path)
        
        if not path.exists():
            return findings
        
        content = path.read_text()
        lines = content.split('\n')
        
        # กำหนดประเภทไฟล์
        if file_path.endswith('.tf'):
            file_type = 'terraform'
        elif file_path.endswith('Dockerfile'):
            file_type = 'dockerfile'
        elif file_path.endswith('.yaml') or file_path.endswith('.yml'):
            file_type = 'kubernetes'
        else:
            return findings
        
        # ตรวจสอบแต่ละ rule
        for rule in self.SECURITY_RULES:
            # กรอง rules ตาม file type
            if file_type == 'terraform' and not any(
                rt.startswith(('aws_', 'gcp_', 'azurerm_')) 
                for rt in rule['resource_types']
            ):
                if 'terraform' not in rule.get('resource_types', []):
                    continue
            
            for i, line in enumerate(lines, 1):
                if re.search(rule['pattern'], line, re.IGNORECASE):
                    # หา resource name
                    resource = self._find_resource_context(lines, i, file_type)
                    
                    findings.append(IaCFinding(
                        severity=rule['severity'],
                        rule_id=rule['id'],
                        resource=resource,
                        file=file_path,
                        line=i,
                        message=rule['message'],
                        remediation=rule['remediation']
                    ))
        
        return findings
    
    def _find_resource_context(self, lines: List[str], line_num: int, file_type: str) -> str:
        """หา resource context ในไฟล์"""
        # มองย้อนหลังหา resource declaration
        for i in range(line_num - 1, max(0, line_num - 30), -1):
            line = lines[i]
            if file_type == 'terraform':
                match = re.match(r'resource\s+"(\w+)"\s+"(\w+)"', line)
                if match:
                    return f"{match.group(1)}.{match.group(2)}"
            elif file_type == 'kubernetes':
                match = re.match(r'kind:\s*(\w+)', line)
                if match:
                    return match.group(1)
        return 'unknown'
    
    def scan_directory(self, dir_path: str) -> List[IaCFinding]:
        """สแกน directory ทั้งหมด"""
        all_findings = []
        path = Path(dir_path)
        
        # Terraform files
        for tf_file in path.rglob('*.tf'):
            all_findings.extend(self.scan_file(str(tf_file)))
        
        # Dockerfiles
        for dockerfile in path.rglob('Dockerfile*'):
            all_findings.extend(self.scan_file(str(dockerfile)))
        
        # Kubernetes manifests
        for k8s_file in path.rglob('*.yaml'):
            all_findings.extend(self.scan_file(str(k8s_file)))
        
        return all_findings
    
    def generate_report(self, findings: List[IaCFinding]) -> str:
        """สร้าง IaC security report"""
        if not findings:
            return "No IaC security issues found."
        
        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        report = ["=" * 60, "IaC Security Scan Report", "=" * 60]
        report.append(f"Total findings: {len(findings)}")
        
        for sev in ['critical', 'high', 'medium', 'low']:
            count = severity_counts.get(sev, 0)
            if count:
                report.append(f"{sev.upper()}: {count}")
        
        report.append("\n--- Findings ---")
        
        for finding in sorted(findings, 
                              key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x.severity, 4)):
            report.append(f"\n[{finding.severity.upper()}] {finding.rule_id}")
            report.append(f"  Resource: {finding.resource}")
            report.append(f"  File: {finding.file}:{finding.line}")
            report.append(f"  Issue: {finding.message}")
            report.append(f"  Fix: {finding.remediation}")
        
        return '\n'.join(report)
```

## Step 674: Supply Chain Security

```python
import hashlib
import json
import subprocess
import requests
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime

@dataclass
class PackageInfo:
    name: str
    version: str
    checksum: str
    source: str
    verified: bool = False
    vulnerabilities: List[Dict] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []


class SupplyChainSecurityScanner:
    """ตรวจสอบ supply chain security"""
    
    def __init__(self):
        self.osv_api = "https://api.osv.dev/v1/query"
        self.pypi_api = "https://pypi.org/pypi"
        
    def verify_package_integrity(self, package_name: str, version: str, 
                                  ecosystem: str = 'PyPI') -> PackageInfo:
        """ตรวจสอบ integrity ของ package"""
        if ecosystem == 'PyPI':
            return self._verify_pypi_package(package_name, version)
        return PackageInfo(name=package_name, version=version, 
                          checksum='unknown', source=ecosystem)
    
    def _verify_pypi_package(self, package_name: str, version: str) -> PackageInfo:
        """ตรวจสอบ PyPI package"""
        url = f"{self.pypi_api}/{package_name}/{version}/json"
        
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            # ดึง checksum จาก package files
            checksums = []
            for file_info in data.get('urls', []):
                if 'sha256' in file_info.get('digests', {}):
                    checksums.append(file_info['digests']['sha256'])
            
            # ตรวจสอบ maintainer info
            info = data.get('info', {})
            author = info.get('author', 'unknown')
            home_page = info.get('home_page', '')
            
            # Red flags
            suspicious = []
            if not home_page:
                suspicious.append("No homepage")
            if not info.get('requires_dist'):
                suspicious.append("No dependencies listed")
            
            package_age = self._calculate_package_age(data)
            if package_age < 7:
                suspicious.append(f"Very new package ({package_age} days old)")
            
            return PackageInfo(
                name=package_name,
                version=version,
                checksum=checksums[0] if checksums else 'unknown',
                source='PyPI',
                verified=len(suspicious) == 0
            )
            
        except Exception as e:
            return PackageInfo(
                name=package_name,
                version=version,
                checksum='error',
                source='PyPI',
                verified=False
            )
    
    def _calculate_package_age(self, pypi_data: Dict) -> int:
        """คำนวณอายุของ package (วัน)"""
        try:
            releases = pypi_data.get('releases', {})
            if releases:
                oldest = None
                for version_files in releases.values():
                    for f in version_files:
                        upload_time = datetime.fromisoformat(
                            f['upload_time'].replace('Z', '+00:00')
                        )
                        if oldest is None or upload_time < oldest:
                            oldest = upload_time
                
                if oldest:
                    delta = datetime.now(oldest.tzinfo) - oldest
                    return delta.days
        except Exception:
            pass
        return 999
    
    def check_osv_vulnerabilities(self, package_name: str, version: str, 
                                   ecosystem: str = 'PyPI') -> List[Dict]:
        """ตรวจสอบ vulnerabilities จาก OSV.dev"""
        payload = {
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }
        
        try:
            response = requests.post(self.osv_api, json=payload, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            vulns = []
            for vuln in data.get('vulns', []):
                severity = 'unknown'
                cvss_score = None
                
                for severity_info in vuln.get('severity', []):
                    if severity_info.get('type') == 'CVSS_V3':
                        score_str = severity_info.get('score', '')
                        # Parse CVSS score
                        try:
                            score_parts = score_str.split('/')
                            base_score = float(score_parts[0].split(':')[-1])
                            cvss_score = base_score
                            severity = ('critical' if base_score >= 9.0 else
                                       'high' if base_score >= 7.0 else
                                       'medium' if base_score >= 4.0 else 'low')
                        except Exception:
                            pass
                
                vulns.append({
                    'id': vuln.get('id', ''),
                    'summary': vuln.get('summary', ''),
                    'severity': severity,
                    'cvss_score': cvss_score,
                    'affected_versions': [
                        r.get('versions', []) 
                        for r in vuln.get('affected', [])
                    ],
                    'references': [r['url'] for r in vuln.get('references', [])[:3]]
                })
            
            return vulns
            
        except Exception as e:
            return []
    
    def detect_typosquatting(self, package_name: str, ecosystem: str = 'PyPI') -> List[str]:
        """ตรวจหา typosquatting packages"""
        # สร้าง typo variants ที่พบบ่อย
        variants = set()
        name = package_name.lower()
        
        # Character substitution (l->1, o->0)
        substitutions = {'l': '1', 'o': '0', 'i': '1', 'e': '3', 'a': '@'}
        for char, replacement in substitutions.items():
            if char in name:
                variants.add(name.replace(char, replacement, 1))
        
        # Character insertion
        for i in range(len(name)):
            for char in 'abcdefghijklmnopqrstuvwxyz-_':
                variants.add(name[:i] + char + name[i:])
        
        # Character deletion
        for i in range(len(name)):
            variants.add(name[:i] + name[i+1:])
        
        # Character swap
        for i in range(len(name) - 1):
            variant = list(name)
            variant[i], variant[i+1] = variant[i+1], variant[i]
            variants.add(''.join(variant))
        
        # Hyphen/underscore swap
        variants.add(name.replace('-', '_'))
        variants.add(name.replace('_', '-'))
        
        # Check which variants exist on PyPI
        existing_variants = []
        for variant in variants:
            if variant != name and len(variant) > 2:
                try:
                    resp = requests.get(
                        f"{self.pypi_api}/{variant}/json",
                        timeout=5
                    )
                    if resp.status_code == 200:
                        existing_variants.append(variant)
                except Exception:
                    pass
        
        return existing_variants
    
    def generate_sbom(self, project_path: str, format: str = 'cyclonedx') -> Dict:
        """สร้าง Software Bill of Materials (SBOM)"""
        sbom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'version': 1,
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'tools': [{'name': 'custom-sbom-generator', 'version': '1.0.0'}]
            },
            'components': []
        }
        
        # ดึง Python packages
        result = subprocess.run(
            ['pip', 'list', '--format=json'],
            capture_output=True, text=True
        )
        
        try:
            packages = json.loads(result.stdout)
            for pkg in packages:
                component = {
                    'type': 'library',
                    'name': pkg['name'],
                    'version': pkg['version'],
                    'purl': f"pkg:pypi/{pkg['name'].lower()}@{pkg['version']}"
                }
                sbom['components'].append(component)
        except json.JSONDecodeError:
            pass
        
        return sbom
```

## Step 675: Container Security Hardening

```python
import subprocess
import json
from dataclasses import dataclass
from typing import List, Dict, Optional


class DockerSecurityHardener:
    """Harden Docker containers ตาม CIS benchmarks"""
    
    SECURE_DOCKERFILE_TEMPLATE = """
# ใช้ specific version แทน latest
FROM python:{version}-slim-bookworm

# ติดตั้ง security updates
RUN apt-get update && \\
    apt-get upgrade -y && \\
    apt-get install -y --no-install-recommends \\
        ca-certificates && \\
    rm -rf /var/lib/apt/lists/* && \\
    apt-get clean

# สร้าง non-root user
RUN groupadd -r appuser && useradd -r -g appuser -s /bin/false appuser

# กำหนด working directory
WORKDIR /app

# Copy requirements ก่อน (layer caching)
COPY --chown=appuser:appuser requirements.txt .

# ติดตั้ง dependencies
RUN pip install --no-cache-dir --upgrade pip && \\
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=appuser:appuser . .

# ลบไฟล์ที่ไม่จำเป็น
RUN find /app -name "*.pyc" -delete && \\
    find /app -name "__pycache__" -type d -exec rm -rf {{}} + 2>/dev/null || true

# เปลี่ยนไปใช้ non-root user
USER appuser

# กำหนด read-only filesystem (ยกเว้น /tmp)
VOLUME ["/tmp"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD python -c "import requests; requests.get('http://localhost:{port}/health')"

# กำหนด entrypoint
EXPOSE {port}
ENTRYPOINT ["python", "-m", "gunicorn"]
CMD ["--bind", "0.0.0.0:{port}", "--workers", "4", "app:application"]
"""

    SECURE_COMPOSE_TEMPLATE = """
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    image: app:{version}
    
    # Security options
    security_opt:
      - no-new-privileges:true
      - seccomp:seccomp-profile.json
      - apparmor:docker-default
    
    # Read-only filesystem
    read_only: true
    tmpfs:
      - /tmp:size=100m,noexec,nosuid
    
    # Drop all capabilities, add only needed ones
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
    
    # Environment variables (ใช้ secrets แทน)
    secrets:
      - db_password
      - api_key
    
    # Network isolation
    networks:
      - frontend
    
    # Healthcheck
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:{port}/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    
    # Logging
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    
    # Ulimits
    ulimits:
      nproc: 65535
      nofile:
        soft: 20000
        hard: 40000
    
    ports:
      - "127.0.0.1:{port}:{port}"  # Bind to localhost only

secrets:
  db_password:
    external: true
  api_key:
    external: true

networks:
  frontend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
"""

    def audit_container(self, container_id: str) -> List[Dict]:
        """Audit running container security"""
        findings = []
        
        # ตรวจสอบ container configuration
        result = subprocess.run(
            ['docker', 'inspect', container_id],
            capture_output=True, text=True
        )
        
        try:
            config = json.loads(result.stdout)[0]
            host_config = config.get('HostConfig', {})
            
            # ตรวจสอบ privileged mode
            if host_config.get('Privileged', False):
                findings.append({
                    'severity': 'critical',
                    'issue': 'Container running in privileged mode',
                    'fix': 'Remove --privileged flag'
                })
            
            # ตรวจสอบ capabilities
            added_caps = host_config.get('CapAdd', []) or []
            dangerous_caps = ['SYS_ADMIN', 'SYS_PTRACE', 'NET_ADMIN', 'ALL']
            for cap in added_caps:
                if cap in dangerous_caps:
                    findings.append({
                        'severity': 'high',
                        'issue': f'Dangerous capability added: {cap}',
                        'fix': f'Remove --cap-add {cap}'
                    })
            
            # ตรวจสอบ user
            process_config = config.get('Config', {})
            user = process_config.get('User', '')
            if not user or user == 'root' or user == '0':
                findings.append({
                    'severity': 'high',
                    'issue': 'Container running as root user',
                    'fix': 'Add USER directive in Dockerfile or --user flag'
                })
            
            # ตรวจสอบ read-only filesystem
            if not host_config.get('ReadonlyRootfs', False):
                findings.append({
                    'severity': 'medium',
                    'issue': 'Container filesystem is writable',
                    'fix': 'Use --read-only flag'
                })
            
            # ตรวจสอบ security options
            security_opt = host_config.get('SecurityOpt', []) or []
            if not any('no-new-privileges' in opt for opt in security_opt):
                findings.append({
                    'severity': 'medium',
                    'issue': 'no-new-privileges not set',
                    'fix': 'Add --security-opt no-new-privileges'
                })
            
            # ตรวจสอบ port bindings
            port_bindings = host_config.get('PortBindings', {}) or {}
            for port, bindings in port_bindings.items():
                for binding in (bindings or []):
                    if binding.get('HostIp', '') in ('', '0.0.0.0', '::'):
                        findings.append({
                            'severity': 'medium',
                            'issue': f'Port {port} bound to all interfaces',
                            'fix': f'Bind to specific interface: 127.0.0.1:{binding.get("HostPort", "")}:{port}'
                        })
            
            # ตรวจสอบ memory limits
            memory = host_config.get('Memory', 0)
            if memory == 0:
                findings.append({
                    'severity': 'low',
                    'issue': 'No memory limit set',
                    'fix': 'Add --memory limit'
                })
                
        except (json.JSONDecodeError, IndexError, KeyError) as e:
            findings.append({
                'severity': 'error',
                'issue': f'Failed to parse container config: {e}',
                'fix': 'Ensure container is running'
            })
        
        return findings
    
    def generate_seccomp_profile(self, allowed_syscalls: List[str]) -> Dict:
        """สร้าง seccomp profile สำหรับ container"""
        # Syscalls ที่จำเป็นสำหรับ Python app
        default_allowed = [
            'accept', 'access', 'arch_prctl', 'brk', 'capget', 'capset',
            'chdir', 'chmod', 'chown', 'clock_gettime', 'clone', 'close',
            'connect', 'dup', 'dup2', 'epoll_create', 'epoll_create1',
            'epoll_ctl', 'epoll_wait', 'execve', 'exit', 'exit_group',
            'fcntl', 'fstat', 'futex', 'getcwd', 'getdents64', 'getegid',
            'geteuid', 'getgid', 'getpid', 'getppid', 'getrandom',
            'getrlimit', 'getsockname', 'getsockopt', 'getuid', 'ioctl',
            'kill', 'lstat', 'madvise', 'mkdir', 'mmap', 'mprotect',
            'munmap', 'nanosleep', 'open', 'openat', 'pipe', 'pipe2',
            'poll', 'prctl', 'pread64', 'prlimit64', 'pwrite64', 'read',
            'readlink', 'recv', 'recvfrom', 'recvmsg', 'rename', 'rmdir',
            'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn', 'select',
            'send', 'sendmsg', 'sendto', 'set_robust_list', 'set_tid_address',
            'setgid', 'setgroups', 'setuid', 'sigaltstack', 'socket',
            'stat', 'statfs', 'symlink', 'sysinfo', 'uname', 'unlink',
            'wait4', 'write', 'writev'
        ]
        
        all_allowed = list(set(default_allowed + allowed_syscalls))
        
        return {
            "defaultAction": "SCMP_ACT_ERRNO",
            "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
            "syscalls": [
                {
                    "names": all_allowed,
                    "action": "SCMP_ACT_ALLOW"
                }
            ]
        }
```

## Step 676: SAST Integration with Pre-commit Hooks

```python
# pre-commit configuration generator
import subprocess
import os
from pathlib import Path
from typing import List, Dict


PRE_COMMIT_CONFIG = """
repos:
  # Secret detection
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.1
    hooks:
      - id: gitleaks
        name: Detect secrets with Gitleaks
        description: Detect hardcoded secrets in the code
        entry: gitleaks protect --verbose --redact --staged
        language: golang
        pass_filenames: false

  # Python security
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.6
    hooks:
      - id: bandit
        args: ["-ll", "-r"]
        exclude: tests/

  # Semgrep
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.52.0
    hooks:
      - id: semgrep
        args:
          - --config=p/security-audit
          - --config=p/secrets
          - --error
        exclude: tests/|migrations/

  # Dependency scanning
  - repo: https://github.com/pypa/pip-audit
    rev: v2.6.1
    hooks:
      - id: pip-audit
        args: ["-r", "requirements.txt"]

  # Terraform security
  - repo: https://github.com/antonbabenko/pre-commit-terraform
    rev: v1.85.0
    hooks:
      - id: terraform_tflint
      - id: terraform_checkov
        args:
          - --args=--quiet
          - --args=--framework=terraform
      - id: terraform_tfsec

  # Dockerfile
  - repo: https://github.com/hadolint/hadolint
    rev: v2.12.0
    hooks:
      - id: hadolint-docker
        args: ["--failure-threshold", "error"]

  # General security
  - repo: https://github.com/Lucas-C/pre-commit-hooks-safety
    rev: v1.3.2
    hooks:
      - id: python-safety-dependencies-check
        files: requirements*.txt

  # YAML/JSON validation
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: check-yaml
      - id: check-json
      - id: detect-private-key
      - id: check-merge-conflict
      - id: no-commit-to-branch
        args: ['--branch', 'main', '--branch', 'master']
"""


class PreCommitSecuritySetup:
    """ตั้งค่า pre-commit hooks สำหรับ security"""
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        
    def setup(self):
        """ติดตั้ง pre-commit hooks"""
        config_file = self.project_path / '.pre-commit-config.yaml'
        config_file.write_text(PRE_COMMIT_CONFIG)
        print(f"[+] Written .pre-commit-config.yaml")
        
        # ติดตั้ง pre-commit
        subprocess.run(['pip', 'install', 'pre-commit'], check=True)
        
        # ติดตั้ง hooks
        subprocess.run(
            ['pre-commit', 'install', '--install-hooks'],
            cwd=str(self.project_path),
            check=True
        )
        
        # Run all hooks ครั้งแรก
        result = subprocess.run(
            ['pre-commit', 'run', '--all-files'],
            cwd=str(self.project_path),
            capture_output=True, text=True
        )
        
        print(result.stdout)
        if result.returncode != 0:
            print("[!] Some hooks failed - review issues above")
            print(result.stderr)
        else:
            print("[+] All security hooks passed!")
    
    def run_specific_hook(self, hook_id: str, files: List[str] = None) -> bool:
        """รัน specific hook"""
        cmd = ['pre-commit', 'run', hook_id]
        
        if files:
            cmd.extend(['--files'] + files)
        else:
            cmd.append('--all-files')
        
        result = subprocess.run(
            cmd,
            cwd=str(self.project_path),
            capture_output=True, text=True
        )
        
        print(result.stdout)
        return result.returncode == 0
    
    def create_security_policy(self) -> str:
        """สร้าง security policy document"""
        policy = """
# Security Policy

## Reporting Vulnerabilities

Please report security vulnerabilities to security@company.com

Do NOT open public issues for security vulnerabilities.

## Supported Versions

| Version | Supported |
|---------|----------|
| 2.x     | Yes      |
| 1.x     | No       |

## Security Controls

This project enforces the following security controls:

1. **Pre-commit hooks**: Bandit, Semgrep, Gitleaks run on every commit
2. **CI/CD Pipeline**: Full security scan on every PR
3. **Dependency scanning**: Automated CVE checking
4. **Container scanning**: Trivy/Grype on Docker images
5. **SBOM generation**: Software Bill of Materials on releases

## Security Requirements

- All dependencies must pass safety/pip-audit check
- No hardcoded secrets (enforced by Gitleaks)
- SAST findings of HIGH or CRITICAL must be fixed before merge
- Docker images must have no CRITICAL vulnerabilities
"""
        
        security_md = self.project_path / 'SECURITY.md'
        security_md.write_text(policy)
        return str(security_md)
```

## Step 677: Runtime Application Self-Protection (RASP)

```python
import functools
import re
import logging
import time
import hashlib
from typing import Callable, Any, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import threading


@dataclass
class SecurityEvent:
    timestamp: str
    event_type: str
    severity: str
    source_ip: str
    user_id: Optional[str]
    request_path: str
    details: Dict
    blocked: bool = False


class RASPEngine:
    """Runtime Application Self-Protection engine"""
    
    def __init__(self):
        self.events: List[SecurityEvent] = []
        self.blocked_ips: Dict[str, int] = {}  # ip -> block_until_timestamp
        self.rate_limits: Dict[str, List[float]] = {}  # ip -> timestamps
        self.lock = threading.Lock()
        self.logger = logging.getLogger('RASP')
        
        # Attack patterns
        self.sql_injection_patterns = [
            r"(\bUNION\b.*\bSELECT\b)",
            r"(\bDROP\b.*\bTABLE\b)",
            r"(\bINSERT\b.*\bINTO\b)",
            r"(\bDELETE\b.*\bFROM\b)",
            r"('.*--)",
            r"(;.*DROP)",
            r"(\bOR\b.*=.*--)",
            r"1=1",
            r"'\s*OR\s*'1'='1"
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=\s*[\"']?",
            r"<img[^>]+src[^>]+onerror",
            r"eval\s*\(",
            r"document\.cookie",
            r"window\.location"
        ]
        
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.%2[Ff]",
            r"%2e%2e%2f",
            r"\.\.\\"
        ]
        
        self.command_injection_patterns = [
            r"[;&|`$(){}\[\]]",
            r"\$\(",
            r"`[^`]+`",
            r"\b(cat|ls|id|whoami|uname|echo|wget|curl|nc|bash|sh|python)\b"
        ]
    
    def detect_sql_injection(self, input_str: str) -> bool:
        """ตรวจหา SQL injection"""
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                return True
        return False
    
    def detect_xss(self, input_str: str) -> bool:
        """ตรวจหา XSS"""
        for pattern in self.xss_patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                return True
        return False
    
    def detect_path_traversal(self, path: str) -> bool:
        """ตรวจหา path traversal"""
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        return False
    
    def check_rate_limit(self, ip: str, limit: int = 100, window: int = 60) -> bool:
        """ตรวจสอบ rate limiting - return True if blocked"""
        current_time = time.time()
        
        with self.lock:
            # ลบ timestamps ที่เก่า
            if ip in self.rate_limits:
                self.rate_limits[ip] = [
                    t for t in self.rate_limits[ip]
                    if current_time - t < window
                ]
            else:
                self.rate_limits[ip] = []
            
            self.rate_limits[ip].append(current_time)
            
            return len(self.rate_limits[ip]) > limit
    
    def is_blocked(self, ip: str) -> bool:
        """ตรวจสอบว่า IP ถูก block หรือไม่"""
        if ip in self.blocked_ips:
            if time.time() < self.blocked_ips[ip]:
                return True
            else:
                del self.blocked_ips[ip]
        return False
    
    def block_ip(self, ip: str, duration: int = 3600):
        """Block IP address"""
        with self.lock:
            self.blocked_ips[ip] = time.time() + duration
            self.logger.warning(f"Blocked IP {ip} for {duration} seconds")
    
    def log_event(self, event: SecurityEvent):
        """บันทึก security event"""
        with self.lock:
            self.events.append(event)
        
        log_msg = (
            f"[{event.severity.upper()}] {event.event_type} | "
            f"IP: {event.source_ip} | Path: {event.request_path} | "
            f"Blocked: {event.blocked}"
        )
        
        if event.severity == 'critical':
            self.logger.critical(log_msg)
        elif event.severity == 'high':
            self.logger.error(log_msg)
        else:
            self.logger.warning(log_msg)
    
    def protect(self, get_ip: Callable, get_path: Callable, 
                get_params: Callable, get_user: Callable = None):
        """Decorator สำหรับ protect endpoints"""
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                ip = get_ip()
                path = get_path()
                params = get_params()
                user_id = get_user() if get_user else None
                
                # ตรวจสอบ blocked IPs
                if self.is_blocked(ip):
                    return {'error': 'Access denied'}, 403
                
                # ตรวจสอบ rate limiting
                if self.check_rate_limit(ip):
                    self.log_event(SecurityEvent(
                        timestamp=datetime.now().isoformat(),
                        event_type='RATE_LIMIT_EXCEEDED',
                        severity='medium',
                        source_ip=ip,
                        user_id=user_id,
                        request_path=path,
                        details={'request_count': len(self.rate_limits.get(ip, []))},
                        blocked=True
                    ))
                    return {'error': 'Rate limit exceeded'}, 429
                
                # ตรวจสอบ input parameters
                for param_name, param_value in (params or {}).items():
                    param_str = str(param_value)
                    
                    if self.detect_sql_injection(param_str):
                        self.log_event(SecurityEvent(
                            timestamp=datetime.now().isoformat(),
                            event_type='SQL_INJECTION_ATTEMPT',
                            severity='high',
                            source_ip=ip,
                            user_id=user_id,
                            request_path=path,
                            details={'param': param_name, 'value': param_str[:100]},
                            blocked=True
                        ))
                        self.block_ip(ip, duration=1800)
                        return {'error': 'Invalid input'}, 400
                    
                    if self.detect_xss(param_str):
                        self.log_event(SecurityEvent(
                            timestamp=datetime.now().isoformat(),
                            event_type='XSS_ATTEMPT',
                            severity='high',
                            source_ip=ip,
                            user_id=user_id,
                            request_path=path,
                            details={'param': param_name},
                            blocked=True
                        ))
                        return {'error': 'Invalid input'}, 400
                
                # ตรวจสอบ path traversal
                if self.detect_path_traversal(path):
                    self.log_event(SecurityEvent(
                        timestamp=datetime.now().isoformat(),
                        event_type='PATH_TRAVERSAL_ATTEMPT',
                        severity='high',
                        source_ip=ip,
                        user_id=user_id,
                        request_path=path,
                        details={},
                        blocked=True
                    ))
                    return {'error': 'Invalid path'}, 400
                
                return func(*args, **kwargs)
            
            return wrapper
        return decorator
```

## Step 678: Security Metrics and KPIs Dashboard

```python
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import statistics


@dataclass  
class SecurityMetric:
    name: str
    value: float
    unit: str
    target: float
    trend: str  # up, down, stable
    status: str  # good, warning, critical


class SecurityMetricsDashboard:
    """Dashboard สำหรับ security metrics และ KPIs"""
    
    def __init__(self):
        self.metrics_history = []
        
    def calculate_mttr(self, vulnerabilities: List[Dict]) -> float:
        """Mean Time To Remediate (MTTR) in days"""
        remediation_times = []
        
        for vuln in vulnerabilities:
            if vuln.get('remediated_at') and vuln.get('discovered_at'):
                discovered = datetime.fromisoformat(vuln['discovered_at'])
                remediated = datetime.fromisoformat(vuln['remediated_at'])
                days = (remediated - discovered).days
                remediation_times.append(days)
        
        if not remediation_times:
            return 0
        
        return statistics.mean(remediation_times)
    
    def calculate_vulnerability_density(self, code_lines: int, 
                                         vuln_count: int) -> float:
        """Vulnerability density per 1000 lines of code"""
        if code_lines == 0:
            return 0
        return (vuln_count / code_lines) * 1000
    
    def calculate_security_debt(self, vulnerabilities: List[Dict]) -> Dict:
        """คำนวณ security debt"""
        severity_hours = {
            'critical': 40,  # ชั่วโมงในการแก้ไข
            'high': 16,
            'medium': 4,
            'low': 1
        }
        
        total_hours = 0
        breakdown = {}
        
        for vuln in vulnerabilities:
            if not vuln.get('remediated_at'):
                severity = vuln.get('severity', 'low')
                hours = severity_hours.get(severity, 1)
                total_hours += hours
                breakdown[severity] = breakdown.get(severity, 0) + 1
        
        return {
            'total_hours': total_hours,
            'estimated_days': total_hours / 8,
            'cost_estimate': total_hours * 150,  # $150/hour
            'breakdown': breakdown
        }
    
    def calculate_dora_security_metrics(self, deployments: List[Dict]) -> Dict:
        """DORA metrics with security focus"""
        successful = [d for d in deployments if d.get('status') == 'success']
        failed = [d for d in deployments if d.get('status') == 'failed']
        security_failures = [
            d for d in failed 
            if d.get('failure_reason', '').startswith('security')
        ]
        
        # Deployment frequency
        if deployments:
            first = min(datetime.fromisoformat(d['timestamp']) 
                       for d in deployments)
            last = max(datetime.fromisoformat(d['timestamp'])
                      for d in deployments)
            days = max((last - first).days, 1)
            deploy_frequency = len(deployments) / days
        else:
            deploy_frequency = 0
        
        # Change failure rate (security-related)
        change_failure_rate = (
            len(security_failures) / len(deployments) * 100
            if deployments else 0
        )
        
        # Security gate pass rate
        security_scans = [d for d in deployments if d.get('security_scan_ran')]
        passed = [d for d in security_scans if d.get('security_scan_passed')]
        gate_pass_rate = (
            len(passed) / len(security_scans) * 100
            if security_scans else 0
        )
        
        return {
            'deployment_frequency': deploy_frequency,
            'change_failure_rate_security': change_failure_rate,
            'security_gate_pass_rate': gate_pass_rate,
            'total_deployments': len(deployments),
            'security_related_failures': len(security_failures)
        }
    
    def generate_security_scorecard(self, metrics_data: Dict) -> Dict:
        """สร้าง security scorecard"""
        scores = {}
        
        # SAST coverage score
        sast_coverage = metrics_data.get('sast_coverage_percent', 0)
        scores['sast_coverage'] = SecurityMetric(
            name='SAST Coverage',
            value=sast_coverage,
            unit='%',
            target=100,
            trend='up' if sast_coverage > 80 else 'down',
            status='good' if sast_coverage >= 90 else 'warning' if sast_coverage >= 70 else 'critical'
        )
        
        # Dependency vulnerability score
        critical_vulns = metrics_data.get('critical_vulnerabilities', 0)
        scores['critical_vulns'] = SecurityMetric(
            name='Critical Vulnerabilities',
            value=critical_vulns,
            unit='count',
            target=0,
            trend='down' if critical_vulns < 5 else 'up',
            status='good' if critical_vulns == 0 else 'warning' if critical_vulns < 3 else 'critical'
        )
        
        # MTTR score
        mttr = metrics_data.get('mttr_days', 30)
        scores['mttr'] = SecurityMetric(
            name='Mean Time To Remediate',
            value=mttr,
            unit='days',
            target=7,
            trend='down' if mttr < 14 else 'up',
            status='good' if mttr <= 7 else 'warning' if mttr <= 14 else 'critical'
        )
        
        # Secret scan compliance
        secret_scan = metrics_data.get('secret_scan_compliance', 0)
        scores['secret_scan'] = SecurityMetric(
            name='Secret Scan Compliance',
            value=secret_scan,
            unit='%',
            target=100,
            trend='up' if secret_scan > 90 else 'stable',
            status='good' if secret_scan == 100 else 'warning' if secret_scan >= 90 else 'critical'
        )
        
        # Overall security score
        status_scores = {'good': 1, 'warning': 0.5, 'critical': 0}
        overall = statistics.mean(
            status_scores[m.status] for m in scores.values()
        ) * 100
        
        return {
            'metrics': scores,
            'overall_score': overall,
            'rating': 'A' if overall >= 90 else 'B' if overall >= 70 else 'C' if overall >= 50 else 'F',
            'generated_at': datetime.now().isoformat()
        }
```

## Step 679: Automated Vulnerability Management

```python
import json
import requests
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import uuid


@dataclass
class Vulnerability:
    id: str
    cve_id: Optional[str]
    title: str
    severity: str
    cvss_score: float
    asset: str
    asset_type: str  # application, container, host, dependency
    discovered_at: str
    status: str = 'open'  # open, in_progress, resolved, accepted_risk
    assignee: Optional[str] = None
    due_date: Optional[str] = None
    remediation_notes: str = ''
    tags: List[str] = field(default_factory=list)


class VulnerabilityManager:
    """ระบบจัดการ vulnerabilities"""
    
    SLA_DAYS = {
        'critical': 1,
        'high': 7,
        'medium': 30,
        'low': 90
    }
    
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        
    def add_vulnerability(self, vuln_data: Dict) -> Vulnerability:
        """เพิ่ม vulnerability ใหม่"""
        severity = vuln_data.get('severity', 'medium')
        
        # คำนวณ due date จาก SLA
        sla_days = self.SLA_DAYS.get(severity, 30)
        due_date = (datetime.now() + timedelta(days=sla_days)).isoformat()
        
        vuln = Vulnerability(
            id=str(uuid.uuid4())[:8],
            cve_id=vuln_data.get('cve_id'),
            title=vuln_data['title'],
            severity=severity,
            cvss_score=vuln_data.get('cvss_score', 0),
            asset=vuln_data['asset'],
            asset_type=vuln_data.get('asset_type', 'application'),
            discovered_at=datetime.now().isoformat(),
            due_date=due_date,
            tags=vuln_data.get('tags', [])
        )
        
        self.vulnerabilities.append(vuln)
        return vuln
    
    def get_overdue_vulnerabilities(self) -> List[Vulnerability]:
        """หา vulnerabilities ที่เกิน SLA"""
        now = datetime.now()
        overdue = []
        
        for vuln in self.vulnerabilities:
            if vuln.status in ('resolved', 'accepted_risk'):
                continue
            
            if vuln.due_date:
                due = datetime.fromisoformat(vuln.due_date)
                if now > due:
                    overdue.append(vuln)
        
        return overdue
    
    def prioritize_vulnerabilities(self) -> List[Vulnerability]:
        """เรียงลำดับ priority ของ vulnerabilities"""
        def priority_score(vuln: Vulnerability) -> float:
            score = vuln.cvss_score
            
            # Boost score ถ้าเป็น critical
            if vuln.severity == 'critical':
                score += 5
            
            # Boost ถ้าเกิน SLA
            if vuln.due_date:
                due = datetime.fromisoformat(vuln.due_date)
                if datetime.now() > due:
                    score += 3
            
            # Boost สำหรับ assets ที่สำคัญ
            if 'production' in vuln.tags:
                score += 2
            
            return score
        
        open_vulns = [v for v in self.vulnerabilities 
                     if v.status in ('open', 'in_progress')]
        return sorted(open_vulns, key=priority_score, reverse=True)
    
    def generate_remediation_plan(self, vulnerabilities: List[Vulnerability]) -> List[Dict]:
        """สร้างแผนการแก้ไข vulnerabilities"""
        plan = []
        
        for vuln in vulnerabilities:
            remediation = {
                'vuln_id': vuln.id,
                'title': vuln.title,
                'severity': vuln.severity,
                'asset': vuln.asset,
                'priority': len(plan) + 1,
                'estimated_effort': self._estimate_effort(vuln),
                'steps': self._get_remediation_steps(vuln),
                'due_date': vuln.due_date
            }
            plan.append(remediation)
        
        return plan
    
    def _estimate_effort(self, vuln: Vulnerability) -> str:
        """ประมาณเวลาในการแก้ไข"""
        effort_map = {
            'critical': '1-2 days',
            'high': '3-5 days',
            'medium': '1-2 weeks',
            'low': '2-4 weeks'
        }
        return effort_map.get(vuln.severity, '2 weeks')
    
    def _get_remediation_steps(self, vuln: Vulnerability) -> List[str]:
        """ขั้นตอนการแก้ไขทั่วไป"""
        steps = [
            f"1. Review {vuln.title} in {vuln.asset}",
            "2. Identify affected code/component",
            "3. Implement fix/patch",
            "4. Test fix in development environment",
            "5. Deploy to staging and verify",
            "6. Deploy to production",
            "7. Verify fix and close ticket"
        ]
        
        if vuln.cve_id:
            steps.insert(1, f"1b. Review CVE details: https://nvd.nist.gov/vuln/detail/{vuln.cve_id}")
        
        return steps
    
    def export_report(self, format: str = 'json') -> str:
        """Export vulnerability report"""
        data = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total': len(self.vulnerabilities),
                'open': len([v for v in self.vulnerabilities if v.status == 'open']),
                'critical': len([v for v in self.vulnerabilities if v.severity == 'critical']),
                'high': len([v for v in self.vulnerabilities if v.severity == 'high']),
                'overdue': len(self.get_overdue_vulnerabilities())
            },
            'vulnerabilities': [
                {
                    'id': v.id,
                    'cve': v.cve_id,
                    'title': v.title,
                    'severity': v.severity,
                    'cvss': v.cvss_score,
                    'asset': v.asset,
                    'status': v.status,
                    'due_date': v.due_date
                }
                for v in self.vulnerabilities
            ]
        }
        
        if format == 'json':
            return json.dumps(data, indent=2)
        return str(data)
```

## Step 680: Security Pipeline Integration Test

```python
import subprocess
import json
import time
from dataclasses import dataclass
from typing import List, Dict
from datetime import datetime


@dataclass
class PipelineStage:
    name: str
    status: str  # pending, running, passed, failed, skipped
    duration: float = 0
    findings: List[Dict] = None
    
    def __post_init__(self):
        if self.findings is None:
            self.findings = []


class SecurityPipelineRunner:
    """รัน security pipeline และรายงานผล"""
    
    def __init__(self, project_path: str, config: Dict = None):
        self.project_path = project_path
        self.config = config or self._default_config()
        self.stages: List[PipelineStage] = []
        
    def _default_config(self) -> Dict:
        return {
            'fail_on_critical': True,
            'fail_on_high': False,
            'sast_enabled': True,
            'sca_enabled': True,
            'secret_scan_enabled': True,
            'iac_scan_enabled': True,
            'container_scan_enabled': False
        }
    
    def run_full_pipeline(self) -> Dict:
        """รัน full security pipeline"""
        print("=" * 60)
        print("DevSecOps Security Pipeline")
        print(f"Project: {self.project_path}")
        print(f"Started: {datetime.now().isoformat()}")
        print("=" * 60)
        
        all_findings = []
        pipeline_start = time.time()
        
        # Stage 1: Secret Scanning
        if self.config.get('secret_scan_enabled'):
            stage = self._run_stage(
                'Secret Scanning',
                ['gitleaks', 'detect', '--source', self.project_path,
                 '--report-format', 'json', '--no-git']
            )
            self.stages.append(stage)
            all_findings.extend(stage.findings)
        
        # Stage 2: SAST
        if self.config.get('sast_enabled'):
            stage = self._run_stage(
                'SAST (Bandit)',
                ['bandit', '-r', self.project_path, '-f', 'json', '-q']
            )
            self.stages.append(stage)
            all_findings.extend(stage.findings)
        
        # Stage 3: Dependency Scanning
        if self.config.get('sca_enabled'):
            stage = self._run_stage(
                'Dependency Scanning',
                ['safety', 'check', '--json']
            )
            self.stages.append(stage)
            all_findings.extend(stage.findings)
        
        # Stage 4: IaC Scanning
        if self.config.get('iac_scan_enabled'):
            stage = self._run_stage(
                'IaC Security (Checkov)',
                ['checkov', '-d', self.project_path, '-o', 'json']
            )
            self.stages.append(stage)
            all_findings.extend(stage.findings)
        
        # คำนวณ pipeline duration
        pipeline_duration = time.time() - pipeline_start
        
        # สรุปผล
        critical_count = len([f for f in all_findings if f.get('severity') == 'critical'])
        high_count = len([f for f in all_findings if f.get('severity') == 'high'])
        
        # กำหนด pipeline status
        if self.config.get('fail_on_critical') and critical_count > 0:
            pipeline_status = 'FAILED'
            fail_reason = f"{critical_count} critical findings"
        elif self.config.get('fail_on_high') and high_count > 0:
            pipeline_status = 'FAILED'
            fail_reason = f"{high_count} high findings"
        else:
            pipeline_status = 'PASSED'
            fail_reason = None
        
        result = {
            'status': pipeline_status,
            'duration_seconds': pipeline_duration,
            'total_findings': len(all_findings),
            'critical': critical_count,
            'high': high_count,
            'fail_reason': fail_reason,
            'stages': [
                {
                    'name': s.name,
                    'status': s.status,
                    'duration': s.duration,
                    'findings': len(s.findings)
                }
                for s in self.stages
            ]
        }
        
        self._print_summary(result)
        return result
    
    def _run_stage(self, stage_name: str, command: List[str]) -> PipelineStage:
        """รัน pipeline stage"""
        print(f"\n[*] Running: {stage_name}")
        stage = PipelineStage(name=stage_name, status='running')
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=self.project_path
            )
            
            stage.duration = time.time() - start_time
            stage.findings = self._parse_findings(result.stdout, stage_name)
            stage.status = 'passed' if result.returncode == 0 else 'failed'
            
        except subprocess.TimeoutExpired:
            stage.duration = time.time() - start_time
            stage.status = 'failed'
            stage.findings = [{'severity': 'error', 'message': 'Stage timeout'}]
            
        except FileNotFoundError:
            stage.duration = 0
            stage.status = 'skipped'
            print(f"  [!] Tool not found, skipping {stage_name}")
        
        status_icon = {'passed': '✓', 'failed': '✗', 'skipped': '-'}.get(stage.status, '?')
        print(f"  [{status_icon}] {stage_name}: {len(stage.findings)} findings ({stage.duration:.1f}s)")
        
        return stage
    
    def _parse_findings(self, output: str, stage_name: str) -> List[Dict]:
        """Parse findings จาก tool output"""
        findings = []
        try:
            data = json.loads(output)
            if isinstance(data, list):
                return [{'severity': f.get('severity', 'medium'), **f} for f in data]
            elif isinstance(data, dict):
                # Bandit format
                for issue in data.get('results', []):
                    findings.append({
                        'severity': issue.get('issue_severity', 'medium').lower(),
                        'title': issue.get('issue_text', ''),
                        'file': issue.get('filename', ''),
                        'tool': stage_name
                    })
        except json.JSONDecodeError:
            pass
        return findings
    
    def _print_summary(self, result: Dict):
        """แสดง pipeline summary"""
        print("\n" + "=" * 60)
        print("Pipeline Summary")
        print("=" * 60)
        status_color = "PASS" if result['status'] == 'PASSED' else "FAIL"
        print(f"Status: [{status_color}] {result['status']}")
        print(f"Duration: {result['duration_seconds']:.1f}s")
        print(f"Total Findings: {result['total_findings']}")
        print(f"  Critical: {result['critical']}")
        print(f"  High: {result['high']}")
        
        if result.get('fail_reason'):
            print(f"Fail Reason: {result['fail_reason']}")


if __name__ == '__main__':
    # Demo DevSecOps pipeline
    pipeline = SecurityPipelineRunner(
        project_path='/tmp/test-project',
        config={
            'fail_on_critical': True,
            'fail_on_high': False,
            'sast_enabled': True,
            'sca_enabled': True,
            'secret_scan_enabled': True,
            'iac_scan_enabled': True,
            'container_scan_enabled': False
        }
    )
    
    result = pipeline.run_full_pipeline()
    
    # IaC Scanner
    scanner = TerraformSecurityScanner()
    findings = scanner.scan_directory('/tmp/terraform')
    print(scanner.generate_report(findings))
    
    # Supply Chain
    sc_scanner = SupplyChainSecurityScanner()
    pkg_info = sc_scanner.verify_package_integrity('requests', '2.31.0')
    vulns = sc_scanner.check_osv_vulnerabilities('requests', '2.31.0')
    print(f"Package verified: {pkg_info.verified}")
    print(f"Vulnerabilities found: {len(vulns)}")
    
    # Security Metrics
    dashboard = SecurityMetricsDashboard()
    scorecard = dashboard.generate_security_scorecard({
        'sast_coverage_percent': 95,
        'critical_vulnerabilities': 2,
        'mttr_days': 10,
        'secret_scan_compliance': 100
    })
    print(f"Security Score: {scorecard['overall_score']:.1f}/100 ({scorecard['rating']})")
```
