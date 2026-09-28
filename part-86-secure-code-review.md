# Part 86: Secure Code Review (Steps 851-860)

## ภาพรวม
การตรวจสอบโค้ดด้านความปลอดภัย (Secure Code Review) เป็นกระบวนการวิเคราะห์ซอร์สโค้ดเพื่อค้นหาช่องโหว่ด้านความปลอดภัยก่อนที่แอปพลิเคชันจะถูก deploy ใช้งานจริง

---

## Step 851: Secure Code Review Fundamentals

หลักการและกระบวนการตรวจสอบโค้ดด้านความปลอดภัย

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum

class VulnSeverity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

class VulnCategory(Enum):
    INJECTION = "Injection"
    XSS = "Cross-Site Scripting"
    BROKEN_AUTH = "Broken Authentication"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    XXE = "XML External Entities"
    BROKEN_ACCESS = "Broken Access Control"
    SECURITY_MISCONFIG = "Security Misconfiguration"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    VULN_COMPONENTS = "Using Components with Known Vulnerabilities"
    INSUFFICIENT_LOGGING = "Insufficient Logging & Monitoring"

@dataclass
class CodeReviewFinding:
    file_path: str
    line_number: int
    severity: VulnSeverity
    category: VulnCategory
    description: str
    vulnerable_code: str
    recommendation: str
    cwe_id: str
    cvss_score: float

class SecureCodeReview:
    """กรอบการทำงานสำหรับ Secure Code Review"""
    
    # OWASP Top 10 2021 review checklist
    OWASP_CHECKLIST = {
        "A01_Broken_Access_Control": [
            "Check for missing authorization checks",
            "Verify IDOR protections",
            "Review directory traversal prevention",
            "Check CORS configuration"
        ],
        "A02_Cryptographic_Failures": [
            "Verify strong encryption algorithms",
            "Check for hardcoded secrets",
            "Review TLS configuration",
            "Validate key management"
        ],
        "A03_Injection": [
            "Check SQL query parameterization",
            "Review OS command execution",
            "Verify LDAP injection prevention",
            "Check XPath injection"
        ],
        "A04_Insecure_Design": [
            "Review threat modeling artifacts",
            "Check rate limiting implementation",
            "Verify business logic controls"
        ],
        "A05_Security_Misconfiguration": [
            "Check default credentials",
            "Review error handling (no stack traces)",
            "Verify security headers",
            "Check unnecessary features disabled"
        ]
    }
    
    # CWE patterns to look for
    CWE_PATTERNS = {
        "CWE-89": {"name": "SQL Injection", "patterns": ["execute(", "cursor.execute(", "raw(", "RawSQL("]},
        "CWE-79": {"name": "XSS", "patterns": ["innerHTML", "document.write(", "eval(", "dangerouslySetInnerHTML"]},
        "CWE-22": {"name": "Path Traversal", "patterns": ["../", "path.join(", "open(", "os.path"]},
        "CWE-78": {"name": "OS Command Injection", "patterns": ["subprocess.call(", "os.system(", "shell=True"]},
        "CWE-798": {"name": "Hardcoded Credentials", "patterns": ["password=", "secret=", "api_key=", "token="]},
        "CWE-327": {"name": "Broken Crypto", "patterns": ["MD5", "SHA1", "DES", "RC4", "ECB"]}
    }
    
    def generate_report_template(self) -> str:
        return """
# Secure Code Review Report
## Project: {project_name}
## Reviewer: {reviewer}
## Date: {date}

## Executive Summary
- Total Findings: {total}
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Low: {low}

## Scope
- Languages reviewed: {languages}
- Files reviewed: {file_count}
- Lines of code: {loc}

## Methodology
1. Automated SAST scanning
2. Manual code review
3. Business logic analysis
4. Dependency audit

## Findings
{findings}

## Recommendations
{recommendations}
        """

if __name__ == '__main__':
    review = SecureCodeReview()
    print("OWASP Top 10 Checklist Categories:")
    for category in review.OWASP_CHECKLIST:
        print(f"  - {category}: {len(review.OWASP_CHECKLIST[category])} checks")
    print("\nCWE Patterns to detect:")
    for cwe_id, info in review.CWE_PATTERNS.items():
        print(f"  - {cwe_id}: {info['name']}")
```

---

## Step 852: Static Application Security Testing (SAST)

การใช้เครื่องมือ SAST สำหรับวิเคราะห์โค้ดอัตโนมัติ

```python
import subprocess
import json
import os
from pathlib import Path

class SASTScanner:
    """Static Application Security Testing automation"""
    
    # Semgrep rules สำหรับ Python security
    SEMGREP_RULES = {
        "sql_injection": """
rules:
  - id: sql-injection-string-format
    patterns:
      - pattern: |
          $QUERY = "...%s..." % $VAR
          $DB.execute($QUERY)
    message: Potential SQL injection via string formatting
    severity: ERROR
    languages: [python]
""",
        "command_injection": """
rules:
  - id: command-injection-shell-true
    pattern: subprocess.run(..., shell=True, ...)
    message: Command injection risk with shell=True
    severity: ERROR
    languages: [python]
""",
        "hardcoded_secrets": """
rules:
  - id: hardcoded-password
    patterns:
      - pattern: password = "..."
      - pattern: PASSWORD = "..."
    message: Hardcoded password detected
    severity: ERROR
    languages: [python, javascript]
"""
    }
    
    def run_bandit(self, target_path: str) -> dict:
        """Run Bandit SAST scanner for Python"""
        # pip install bandit
        cmd = [
            "bandit",
            "-r",           # recursive
            "-f", "json",   # JSON output
            "-ll",          # low severity level
            target_path
        ]
        
        # Example command execution
        print(f"Command: {' '.join(cmd)}")
        
        # Simulated Bandit output structure
        return {
            "results": [
                {
                    "filename": "app/auth.py",
                    "line_number": 45,
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": "Use of MD5 message digest",
                    "test_id": "B303",
                    "test_name": "md5"
                },
                {
                    "filename": "app/db.py",
                    "line_number": 23,
                    "issue_severity": "HIGH",
                    "issue_confidence": "MEDIUM",
                    "issue_text": "Possible SQL injection via string-based query construction",
                    "test_id": "B608",
                    "test_name": "hardcoded_sql_expressions"
                }
            ],
            "metrics": {
                "total_issues": {
                    "HIGH": 2,
                    "MEDIUM": 5,
                    "LOW": 12
                }
            }
        }
    
    def run_semgrep(self, target_path: str, config: str = "auto") -> dict:
        """Run Semgrep for multi-language SAST"""
        cmd = [
            "semgrep",
            "--config", config,  # auto, p/python, p/javascript, etc.
            "--json",
            target_path
        ]
        print(f"Command: {' '.join(cmd)}")
        
        # Simulated output
        return {
            "results": [
                {
                    "check_id": "python.django.security.audit.xss.template-autoescape-off",
                    "path": "templates/views.py",
                    "start": {"line": 12},
                    "extra": {
                        "message": "Autoescape is disabled - XSS risk",
                        "severity": "ERROR"
                    }
                }
            ]
        }
    
    def run_sonarqube_analysis(self, project_key: str, sonar_host: str) -> dict:
        """Trigger SonarQube analysis"""
        # Requires sonar-scanner installed
        cmd = [
            "sonar-scanner",
            f"-Dsonar.projectKey={project_key}",
            f"-Dsonar.host.url={sonar_host}",
            "-Dsonar.sources=.",
            "-Dsonar.language=python"
        ]
        print(f"SonarQube scan command: {' '.join(cmd)}")
        print("Check results at: http://sonarhost:9000/dashboard?id=" + project_key)
    
    def parse_findings_to_markdown(self, bandit_results: dict) -> str:
        """แปลงผลการสแกนเป็น Markdown report"""
        md = "## SAST Findings\n\n"
        md += "| File | Line | Severity | Issue |\n"
        md += "|------|------|----------|-------|\n"
        
        for finding in bandit_results.get("results", []):
            md += f"| {finding['filename']} | {finding['line_number']} | "
            md += f"{finding['issue_severity']} | {finding['issue_text']} |\n"
        
        return md

if __name__ == '__main__':
    scanner = SASTScanner()
    results = scanner.run_bandit("/app/source")
    report = scanner.parse_findings_to_markdown(results)
    print(report)
    print("\nRunning Semgrep...")
    scanner.run_semgrep("/app/source", "p/owasp-top-ten")
```

---

## Step 853: Manual Code Review Techniques

เทคนิคการตรวจสอบโค้ดด้วยตนเองสำหรับช่องโหว่ที่ซับซ้อน

```python
import re
from typing import Tuple

class ManualReviewTechniques:
    """เทคนิคการตรวจสอบโค้ดด้วยตนเอง"""
    
    # Dangerous patterns ใน Python
    PYTHON_DANGEROUS_PATTERNS = {
        "sql_injection": [
            r'execute\s*\(\s*[f\'\"](.*%s.*|.*format.*|.*\{\}.*)',  # f-string/format in execute
            r'cursor\.execute\s*\([^,)]+\+',  # string concatenation in execute
            r'\.raw\s*\(',  # Django raw SQL
        ],
        "command_injection": [
            r'os\.system\s*\(',
            r'subprocess\..*shell\s*=\s*True',
            r'eval\s*\(',
            r'exec\s*\(',
        ],
        "path_traversal": [
            r'open\s*\(.*\+',  # string concat in file open
            r'os\.path\.join\s*\(.*request',  # user input in path join
        ],
        "deserialization": [
            r'pickle\.loads\s*\(',
            r'yaml\.load\s*\([^,)]+\)',  # yaml.load without Loader=
            r'marshal\.loads\s*\(',
        ],
        "xxe": [
            r'etree\.parse\s*\(',
            r'lxml.*XMLParser',
            r'xml\.dom\.minidom\.parse',
        ],
        "crypto_weakness": [
            r'hashlib\.md5\s*\(',
            r'hashlib\.sha1\s*\(',
            r'Crypto\.Cipher\.DES',
            r'random\.random\s*\(',  # non-cryptographic random
        ]
    }
    
    def scan_file_for_patterns(self, file_path: str, content: str) -> List[dict]:
        """สแกนไฟล์หา dangerous patterns"""
        findings = []
        lines = content.split('\n')
        
        for category, patterns in self.PYTHON_DANGEROUS_PATTERNS.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "file": file_path,
                            "line": line_num,
                            "category": category,
                            "code": line.strip(),
                            "pattern": pattern
                        })
        return findings
    
    def review_authentication_code(self, code: str) -> List[str]:
        """ตรวจสอบโค้ด authentication"""
        issues = []
        
        # Check for timing attacks in password comparison
        if "==" in code and ("password" in code.lower() or "token" in code.lower()):
            if "hmac.compare_digest" not in code and "secrets.compare_digest" not in code:
                issues.append("TIMING ATTACK: Use hmac.compare_digest() for password comparison")
        
        # Check session management
        if "session" in code.lower():
            if "httponly" not in code.lower():
                issues.append("SESSION: Missing HttpOnly flag on session cookies")
            if "secure" not in code.lower():
                issues.append("SESSION: Missing Secure flag on session cookies")
            if "samesite" not in code.lower():
                issues.append("SESSION: Missing SameSite attribute (CSRF risk)")
        
        # Check JWT implementation
        if "jwt" in code.lower():
            if "algorithm='HS256'" in code or 'algorithm="HS256"' in code:
                issues.append("JWT: Consider RS256 over HS256 for better security")
            if "verify=False" in code or "options={'verify_signature': False}" in code:
                issues.append("JWT CRITICAL: Signature verification disabled!")
            if "'none'" in code.lower() or '"none"' in code.lower():
                issues.append("JWT CRITICAL: Algorithm 'none' accepted - bypass risk!")
        
        return issues
    
    def review_authorization_code(self, code: str) -> List[str]:
        """ตรวจสอบโค้ด authorization"""
        issues = []
        
        # Missing authorization checks
        endpoints = re.findall(r'@app\.route\([^)]+\)', code)
        auth_decorators = re.findall(r'@(login_required|permission_required|jwt_required)', code)
        
        if len(endpoints) > len(auth_decorators):
            issues.append(f"MISSING AUTH: {len(endpoints)} routes, only {len(auth_decorators)} auth decorators")
        
        # Direct object reference checks
        if re.search(r'get_object_or_404\(.*request\.', code):
            issues.append("IDOR RISK: Check if object belongs to requesting user")
        
        return issues
    
    # Business logic review questions
    BUSINESS_LOGIC_CHECKLIST = [
        "Can a user access another user's data by manipulating IDs?",
        "Can price/quantity values be manipulated in requests?",
        "Can workflow steps be skipped (e.g., payment before checkout)?",
        "Are rate limits enforced on sensitive operations?",
        "Can race conditions be exploited in multi-step operations?",
        "Is negative/zero quantity handled properly?",
        "Can admin functions be accessed by regular users?"
    ]

if __name__ == '__main__':
    reviewer = ManualReviewTechniques()
    
    # Test code snippet
    test_code = """
    password = request.form['password']
    if password == stored_hash:
        session['user'] = user_id
    """
    
    issues = reviewer.review_authentication_code(test_code)
    print("Authentication Issues Found:")
    for issue in issues:
        print(f"  [!] {issue}")
    
    print("\nBusiness Logic Checklist:")
    for item in reviewer.BUSINESS_LOGIC_CHECKLIST:
        print(f"  [ ] {item}")
```

---

## Step 854: SQL Injection Code Review

การตรวจสอบช่องโหว่ SQL Injection ในโค้ด

```python
import re
from typing import List, Dict

class SQLInjectionReview:
    """ตรวจสอบและแก้ไขช่องโหว่ SQL Injection"""
    
    # ตัวอย่างโค้ดที่มีช่องโหว่ vs โค้ดที่ปลอดภัย
    VULNERABLE_EXAMPLES = {
        "python_mysql": {
            "vulnerable": """
# ช่องโหว่: String concatenation
def get_user(username):
    query = "SELECT * FROM users WHERE username='" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
""",
            "secure": """
# ปลอดภัย: Parameterized query
def get_user(username):
    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    return cursor.fetchone()
"""
        },
        "python_sqlite": {
            "vulnerable": """
# ช่องโหว่: f-string in query
def authenticate(username, password):
    query = f"SELECT * FROM users WHERE user='{username}' AND pass='{password}'"
    conn.execute(query)
""",
            "secure": """
# ปลอดภัย: Parameterized
def authenticate(username, password):
    query = "SELECT * FROM users WHERE user=? AND pass=?"
    conn.execute(query, (username, password))
"""
        },
        "django_orm": {
            "vulnerable": """
# ช่องโหว่: Raw SQL with format
def search_products(search_term):
    return Product.objects.raw(
        f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    )
""",
            "secure": """
# ปลอดภัย: ORM filter or parameterized raw
def search_products(search_term):
    # Option 1: ORM (best)
    return Product.objects.filter(name__icontains=search_term)
    
    # Option 2: Parameterized raw
    return Product.objects.raw(
        "SELECT * FROM products WHERE name LIKE %s",
        [f'%{search_term}%']
    )
"""
        },
        "sqlalchemy": {
            "vulnerable": """
# ช่องโหว่: text() with format
from sqlalchemy import text
def get_orders(user_id):
    result = db.execute(text(f"SELECT * FROM orders WHERE user_id={user_id}"))
""",
            "secure": """
# ปลอดภัย: Bound parameters
from sqlalchemy import text
def get_orders(user_id):
    result = db.execute(
        text("SELECT * FROM orders WHERE user_id=:uid"),
        {"uid": user_id}
    )
"""
        }
    }
    
    def detect_sqli_patterns(self, code: str) -> List[Dict]:
        """ตรวจจับ SQL injection patterns"""
        findings = []
        
        # Pattern 1: String concatenation in SQL
        concat_pattern = r'(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^;]*\+\s*\w+'
        for match in re.finditer(concat_pattern, code, re.IGNORECASE):
            findings.append({
                "type": "String Concatenation",
                "match": match.group(),
                "position": match.start(),
                "risk": "HIGH"
            })
        
        # Pattern 2: f-string in SQL execution
        fstring_pattern = r'(?:execute|raw|query)\s*\(\s*f[\'"].*SELECT'
        for match in re.finditer(fstring_pattern, code, re.IGNORECASE):
            findings.append({
                "type": "F-string in SQL",
                "match": match.group(),
                "position": match.start(),
                "risk": "HIGH"
            })
        
        # Pattern 3: % format string in SQL
        format_pattern = r'(?:execute|raw)\s*\(.*%\s*(?:\w+|\()'
        for match in re.finditer(format_pattern, code, re.IGNORECASE):
            # Check if it's parameterized (%s with tuple) vs formatted (% var)
            context = code[match.start():match.start()+200]
            if not re.search(r'%s.*,\s*\(', context):
                findings.append({
                    "type": "Format String in SQL",
                    "match": match.group(),
                    "position": match.start(),
                    "risk": "HIGH"
                })
        
        return findings
    
    def generate_remediation_guide(self) -> str:
        return """
## SQL Injection Remediation Guide

### 1. Always Use Parameterized Queries
- Python sqlite3: cursor.execute("SELECT * WHERE id=?", (id,))
- Python MySQL: cursor.execute("SELECT * WHERE id=%s", (id,))
- SQLAlchemy: db.execute(text("SELECT * WHERE id=:id"), {"id": id})
- Django ORM: Model.objects.filter(id=id)

### 2. Use ORM when possible
- Django ORM, SQLAlchemy ORM auto-escape values
- Avoid .raw() and db.execute() with user input

### 3. Input Validation (Defense in Depth)
- Validate type (int, UUID, etc.)
- Whitelist allowed characters
- Never rely solely on input validation

### 4. Least Privilege DB Accounts
- App accounts should only have SELECT/INSERT/UPDATE
- No DROP, ALTER, CREATE permissions
- Separate read-only accounts for reporting
        """

if __name__ == '__main__':
    reviewer = SQLInjectionReview()
    print("SQL Injection Examples:")
    for db_type, examples in reviewer.VULNERABLE_EXAMPLES.items():
        print(f"\n[{db_type.upper()}]")
        print("VULNERABLE:", examples['vulnerable'][:100], "...")
    
    # Test detection
    test_code = '''
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
    '''
    findings = reviewer.detect_sqli_patterns(test_code)
    print(f"\nFound {len(findings)} SQL injection patterns")
    print(reviewer.generate_remediation_guide())
```

---

## Step 855: XSS Code Review

การตรวจสอบช่องโหว่ Cross-Site Scripting

```python
import re
from typing import List

class XSSReview:
    """ตรวจสอบช่องโหว่ Cross-Site Scripting"""
    
    XSS_VULNERABLE_PATTERNS = {
        "javascript": [
            r'innerHTML\s*=\s*(?![\'"]).+',  # innerHTML with variable
            r'document\.write\s*\(',
            r'eval\s*\(.*(?:request|param|input)',
            r'\$\(.*\)\.html\s*\(',  # jQuery .html() with variable
            r'v-html\s*=\s*[^"\']',  # Vue v-html with variable
            r'dangerouslySetInnerHTML',  # React
        ],
        "python_flask": [
            r'Markup\s*\(',  # Flask Markup wraps as safe
            r'render_template_string\s*\(.*%',  # Template injection
            r'\|\s*safe',  # Jinja2 safe filter
        ],
        "python_django": [
            r'mark_safe\s*\(',  # Django mark_safe
            r'format_html\s*\(.*(?:request|user_input)',
        ]
    }
    
    # ตัวอย่างโค้ดที่มีช่องโหว่
    VULNERABLE_CODE_EXAMPLES = {
        "stored_xss_flask": """
# ช่องโหว่ Stored XSS
@app.route('/profile')
def show_profile():
    username = db.get_username(session['user_id'])
    # ช่องโหว่: ไม่ escape HTML
    return f'<h1>Hello {username}</h1>'
""",
        "reflected_xss_flask": """
# ช่องโหว่ Reflected XSS
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # ช่องโหว่: inject query ลงใน HTML โดยตรง
    return render_template_string(f'<p>Results for: {query}</p>')
""",
        "dom_xss_js": """
// ช่องโหว่ DOM XSS
const search = new URLSearchParams(window.location.search);
const term = search.get('term');
// ช่องโหว่: innerHTML กับ untrusted data
document.getElementById('results').innerHTML = 'Search: ' + term;
"""
    }
    
    # ตัวอย่างโค้ดที่ปลอดภัย
    SECURE_CODE_EXAMPLES = {
        "flask_auto_escape": """
# ปลอดภัย: ใช้ render_template (auto-escaping)
@app.route('/profile')
def show_profile():
    username = db.get_username(session['user_id'])
    return render_template('profile.html', username=username)
    # ใน template: {{ username }} — auto-escaped
""",
        "flask_explicit_escape": """
# ปลอดภัย: Explicit escaping ด้วย markupsafe
from markupsafe import escape
@app.route('/search')
def search():
    query = request.args.get('q', '')
    safe_query = escape(query)  # converts < > & " ' to HTML entities
    return f'<p>Results for: {safe_query}</p>'
""",
        "js_textcontent": """
// ปลอดภัย: ใช้ textContent แทน innerHTML
const search = new URLSearchParams(window.location.search);
const term = search.get('term');
document.getElementById('results').textContent = 'Search: ' + term;
// หรือใช้ DOM APIs
const span = document.createElement('span');
span.textContent = term;
document.getElementById('results').appendChild(span);
"""
    }
    
    CSP_POLICY_EXAMPLES = {
        "strict": (
            "Content-Security-Policy: "
            "default-src 'self'; "
            "script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self' 'nonce-{nonce}'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self';"
        ),
        "report_only": (
            "Content-Security-Policy-Report-Only: "
            "default-src 'self'; "
            "report-uri /csp-report;"
        )
    }
    
    def check_csp_headers(self, headers: dict) -> List[str]:
        """ตรวจสอบ Content Security Policy"""
        issues = []
        csp = headers.get("Content-Security-Policy", "")
        
        if not csp:
            issues.append("MISSING: Content-Security-Policy header not set")
            return issues
        
        if "unsafe-inline" in csp:
            issues.append("WEAK CSP: 'unsafe-inline' defeats XSS protection")
        if "unsafe-eval" in csp:
            issues.append("WEAK CSP: 'unsafe-eval' allows eval() - XSS risk")
        if "*" in csp.split("default-src ")[-1].split(";")[0]:
            issues.append("WEAK CSP: Wildcard (*) in default-src")
        
        return issues

if __name__ == '__main__':
    reviewer = XSSReview()
    print("XSS Vulnerable Patterns by Language:")
    for lang, patterns in reviewer.XSS_VULNERABLE_PATTERNS.items():
        print(f"  {lang}: {len(patterns)} patterns")
    
    # Check CSP
    test_headers = {
        "Content-Security-Policy": "default-src * 'unsafe-inline' 'unsafe-eval'"
    }
    issues = reviewer.check_csp_headers(test_headers)
    print("\nCSP Issues:")
    for issue in issues:
        print(f"  [!] {issue}")
    
    print("\nStrict CSP Example:")
    print(reviewer.CSP_POLICY_EXAMPLES["strict"])
```

---

## Step 856: Cryptographic Issues Review

การตรวจสอบการใช้งาน Cryptography ในโค้ด

```python
import hashlib
import secrets
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CryptographyReview:
    """ตรวจสอบและแก้ไขการใช้งาน Cryptography"""
    
    # อัลกอริธึมที่ไม่ปลอดภัย
    BROKEN_ALGORITHMS = {
        "hash": ["MD5", "SHA1", "CRC32"],
        "encryption": ["DES", "3DES", "RC4", "RC2", "Blowfish"],
        "mode": ["ECB"],  # CBC without authenticated encryption is also risky
        "key_exchange": ["DH-512", "RSA-512", "RSA-1024"],
        "random": ["random.random", "random.randint", "Math.random", "rand()"],
    }
    
    # ตัวอย่างโค้ดที่มีช่องโหว่ด้านการเข้ารหัส
    VULNERABLE_EXAMPLES = {
        "weak_password_hash": """
# ช่องโหว่: MD5 สำหรับ password hashing
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
""",
        "hardcoded_key": """
# ช่องโหว่: Hardcoded encryption key
SECRET_KEY = "MySuperSecretKey123"
AES_KEY = b"0123456789abcdef"
""",
        "weak_random": """
# ช่องโหว่: Non-cryptographic random for security tokens
import random
def generate_token():
    return str(random.randint(100000, 999999))
""",
        "ecb_mode": """
# ช่องโหว่: ECB mode (reveals patterns)
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(data)
"""
    }
    
    # โค้ดที่ถูกต้อง
    def secure_password_hash(self, password: str, salt: bytes = None) -> tuple:
        """ปลอดภัย: ใช้ bcrypt/argon2/PBKDF2 สำหรับ password"""
        # Option 1: bcrypt (recommended)
        # import bcrypt
        # hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        
        # Option 2: PBKDF2 (built-in)
        if salt is None:
            salt = secrets.token_bytes(32)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,  # NIST recommended 2023
        )
        key = base64.b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def secure_encrypt(self, plaintext: bytes, key: bytes = None) -> tuple:
        """ปลอดภัย: AES-256-GCM (authenticated encryption)"""
        if key is None:
            key = secrets.token_bytes(32)  # 256-bit key
        
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext, key
    
    def secure_token_generation(self, length: int = 32) -> str:
        """ปลอดภัย: ใช้ secrets module สำหรับ cryptographic random"""
        return secrets.token_urlsafe(length)
    
    def review_crypto_usage(self, code: str) -> List[str]:
        """ตรวจสอบการใช้ crypto ในโค้ด"""
        import re
        issues = []
        
        # Check for broken hash algorithms
        for algo in self.BROKEN_ALGORITHMS["hash"]:
            if re.search(rf'hashlib\.{algo.lower()}\s*\(', code, re.IGNORECASE):
                issues.append(f"WEAK HASH: {algo} is cryptographically broken. Use SHA-256 or better")
        
        # Check for broken encryption
        for algo in self.BROKEN_ALGORITHMS["encryption"]:
            if re.search(rf'\b{algo}\b', code, re.IGNORECASE):
                issues.append(f"WEAK ENCRYPTION: {algo} is insecure. Use AES-256-GCM")
        
        # Check for ECB mode
        if "ECB" in code or "MODE_ECB" in code:
            issues.append("WEAK MODE: ECB mode reveals patterns. Use GCM or CBC with HMAC")
        
        # Check for non-crypto random
        if re.search(r'random\.random|random\.randint|random\.choice', code):
            if any(sec_word in code.lower() for sec_word in ['token', 'key', 'secret', 'password', 'nonce']):
                issues.append("WEAK RANDOM: Use secrets module for security-sensitive random values")
        
        # Check for hardcoded secrets
        hardcoded_patterns = [
            r'(?:password|secret|key|token)\s*=\s*[\'"][^{\'"\$]+[\'"]',
        ]
        for pattern in hardcoded_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                issues.append("HARDCODED SECRET: Store secrets in environment variables or secret manager")
                break
        
        return issues
    
    def key_management_checklist(self) -> List[str]:
        return [
            "[ ] Keys stored in environment variables or secrets manager (not code)",
            "[ ] Different keys for different environments (dev/stage/prod)",
            "[ ] Key rotation procedure documented and tested",
            "[ ] Key length: AES-256, RSA-2048+, EC-256+",
            "[ ] Private keys never logged or transmitted",
            "[ ] Encrypted key backup with separate recovery procedure"
        ]

if __name__ == '__main__':
    import secrets as sec_module
    reviewer = CryptographyReview()
    
    # Test password hashing
    password = "MyP@ssw0rd"
    hashed, salt = reviewer.secure_password_hash(password)
    print(f"Secure password hash (PBKDF2): {hashed[:20]}...")
    
    # Test encryption
    plaintext = b"Sensitive data here"
    encrypted, key = reviewer.secure_encrypt(plaintext)
    print(f"AES-GCM encrypted (bytes): {len(encrypted)} bytes")
    
    # Test token generation
    token = reviewer.secure_token_generation()
    print(f"Secure token: {token[:20]}...")
    
    # Review test code
    test_code = '''
    import hashlib, random
    password_hash = hashlib.md5(password.encode()).hexdigest()
    token = random.randint(100000, 999999)
    SECRET = "hardcoded-secret-key"
    '''
    issues = reviewer.review_crypto_usage(test_code)
    print("\nCrypto Issues:")
    for issue in issues:
        print(f"  [!] {issue}")
```

---

## Step 857: Authentication & Authorization Code Review

การตรวจสอบโค้ด Authentication และ Authorization

```python
import re
from typing import List, Dict

class AuthReview:
    """ตรวจสอบโค้ด Authentication และ Authorization"""
    
    # ช่องโหว่ที่พบบ่อยใน Authentication
    AUTH_VULNERABILITIES = {
        "brute_force": {
            "description": "ไม่มีการจำกัดจำนวนครั้งในการพยายาม login",
            "fix": "Implement account lockout, rate limiting, CAPTCHA",
            "code_pattern": r'def\s+(?:login|authenticate)\s*\(',
            "check": "Look for rate limiting decorator or lockout logic"
        },
        "weak_session_id": {
            "description": "Session ID สร้างจาก predictable values",
            "fix": "Use cryptographically secure random (secrets.token_urlsafe)",
            "code_pattern": r'session_id\s*=.*(?:random|time|uuid4)',
            "check": "Ensure 128+ bits of entropy"
        },
        "missing_reauthentication": {
            "description": "ไม่มีการยืนยันตัวตนก่อนการดำเนินการสำคัญ",
            "fix": "Require password confirmation for sensitive changes",
            "sensitive_ops": ["change_password", "change_email", "delete_account", "transfer_funds"]
        }
    }
    
    # Django REST Framework permission examples
    DRF_PERMISSION_EXAMPLES = {
        "missing_permission": """
# ช่องโหว่: ไม่มี permission class
class UserDataView(APIView):
    def get(self, request, user_id):
        user_data = User.objects.get(id=user_id)
        return Response(UserSerializer(user_data).data)
""",
        "secure_permission": """
# ปลอดภัย: ตรวจสอบ permission
class UserDataView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, user_id):
        # ตรวจสอบว่า user สามารถเข้าถึงข้อมูล user_id ได้
        if request.user.id != user_id and not request.user.is_staff:
            raise PermissionDenied("Access denied")
        user_data = get_object_or_404(User, id=user_id)
        return Response(UserSerializer(user_data).data)
"""
    }
    
    def detect_missing_auth_checks(self, code: str) -> List[Dict]:
        """ตรวจจับ endpoints ที่ขาด auth checks"""
        issues = []
        
        # Flask routes without login_required
        flask_routes = re.findall(
            r'@app\.route\([^)]+\)[^@]*def\s+(\w+)',
            code, re.DOTALL
        )
        
        # Check if functions have login_required before them
        for func_name in flask_routes:
            # Look for login_required decorator before this function
            pattern = rf'@login_required\s+@app\.route[^@]*def\s+{func_name}|@app\.route[^@]*@login_required\s+def\s+{func_name}'
            if not re.search(pattern, code):
                # Check if it's a public endpoint by name
                public_names = ['index', 'login', 'signup', 'register', 'health', 'static']
                if func_name.lower() not in public_names:
                    issues.append({
                        "type": "Missing Authentication",
                        "function": func_name,
                        "severity": "HIGH",
                        "message": f"Function '{func_name}' may lack @login_required decorator"
                    })
        
        return issues
    
    def check_jwt_implementation(self, code: str) -> List[str]:
        """ตรวจสอบ JWT implementation"""
        issues = []
        
        # Algorithm confusion attack
        if "decode" in code and "algorithms" not in code:
            issues.append("JWT CRITICAL: Not specifying 'algorithms' parameter allows algorithm confusion")
        
        # None algorithm acceptance
        if "none" in code.lower() and "jwt" in code.lower():
            issues.append("JWT CRITICAL: 'none' algorithm should never be accepted")
        
        # No expiration check
        if "decode" in code and "exp" not in code and "verify_exp" not in code:
            issues.append("JWT MEDIUM: Expiration (exp) claim may not be verified")
        
        # HS256 with public key confusion
        if "HS256" in code and ("public_key" in code or "PUBLIC_KEY" in code):
            issues.append("JWT CRITICAL: HS256 with public key - algorithm confusion attack possible")
        
        # Weak secret
        if re.search(r'SECRET\s*=\s*[\'"][\w]{1,16}[\'"]', code):
            issues.append("JWT WEAK SECRET: JWT secret is short - susceptible to brute force")
        
        return issues
    
    def oauth2_review_checklist(self) -> Dict[str, List[str]]:
        return {
            "authorization_code_flow": [
                "[ ] state parameter used to prevent CSRF",
                "[ ] PKCE (code_challenge) implemented for public clients",
                "[ ] redirect_uri validated against whitelist",
                "[ ] Authorization code single-use and short-lived (< 10 min)",
                "[ ] Access tokens short-lived (< 1 hour)",
                "[ ] Refresh tokens rotated on use"
            ],
            "token_storage": [
                "[ ] Tokens not stored in localStorage (XSS risk)",
                "[ ] Tokens stored in httpOnly, Secure cookies",
                "[ ] CSRF token used with cookie-based storage"
            ]
        }

if __name__ == '__main__':
    reviewer = AuthReview()
    
    # Test code
    test_code = """
    @app.route('/admin/users')
    def list_users():
        return jsonify(User.query.all())
    
    @app.route('/profile')
    @login_required
    def profile():
        return jsonify(current_user.to_dict())
    """
    
    issues = reviewer.detect_missing_auth_checks(test_code)
    print("Missing Auth Checks:")
    for issue in issues:
        print(f"  [!] {issue['message']}")
    
    # Test JWT review
    jwt_code = """
    import jwt
    data = jwt.decode(token, SECRET, algorithms=['HS256', 'none'])
    """
    jwt_issues = reviewer.check_jwt_implementation(jwt_code)
    print("\nJWT Issues:")
    for issue in jwt_issues:
        print(f"  [!] {issue}")
```

---

## Step 858: Dependency & Supply Chain Security Review

การตรวจสอบ dependencies และความปลอดภัยของ supply chain

```python
import json
import subprocess
from typing import List, Dict
from datetime import datetime

class DependencySecurityReview:
    """ตรวจสอบความปลอดภัยของ dependencies"""
    
    def run_pip_audit(self, requirements_file: str = None) -> dict:
        """ใช้ pip-audit ตรวจสอบ Python packages"""
        # pip install pip-audit
        cmd = ["pip-audit", "--format", "json"]
        if requirements_file:
            cmd.extend(["-r", requirements_file])
        
        print(f"Command: {' '.join(cmd)}")
        
        # Simulated pip-audit output
        return {
            "vulnerabilities": [
                {
                    "name": "Pillow",
                    "version": "9.0.0",
                    "id": "PYSEC-2023-175",
                    "fix_versions": ["10.0.1"],
                    "description": "PIL/Pillow heap buffer overflow in ImagingFliVertical"
                },
                {
                    "name": "requests",
                    "version": "2.25.0",
                    "id": "PYSEC-2023-74",
                    "fix_versions": ["2.31.0"],
                    "description": "Proxy-Authorization header leak on redirect"
                }
            ]
        }
    
    def run_npm_audit(self, project_dir: str) -> dict:
        """ใช้ npm audit ตรวจสอบ Node.js packages"""
        cmd = ["npm", "audit", "--json"]
        print(f"Command (in {project_dir}): {' '.join(cmd)}")
        
        return {
            "vulnerabilities": {
                "lodash": {
                    "severity": "high",
                    "via": ["prototype-pollution"],
                    "fixAvailable": True,
                    "fixVersion": "4.17.21"
                }
            },
            "metadata": {
                "vulnerabilities": {"critical": 0, "high": 1, "moderate": 3, "low": 5}
            }
        }
    
    def check_license_compliance(self, packages: List[Dict]) -> List[str]:
        """ตรวจสอบ license ของ packages"""
        issues = []
        
        # Licenses ที่อาจมีปัญหาในเชิงพาณิชย์
        restrictive_licenses = ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1"]
        
        for pkg in packages:
            if pkg.get("license") in restrictive_licenses:
                issues.append(
                    f"LICENSE RISK: {pkg['name']} uses {pkg['license']} - "
                    f"may require open-sourcing your code"
                )
        
        return issues
    
    def check_supply_chain_integrity(self) -> Dict[str, List[str]]:
        """ตรวจสอบความสมบูรณ์ของ supply chain"""
        return {
            "package_integrity": [
                "Use lock files (requirements.txt pinned versions, package-lock.json)",
                "Verify package checksums (--require-hashes in pip)",
                "Use private package registry mirror",
                "Enable Sigstore/PyPI trusted publishing"
            ],
            "dependency_confusion": [
                "Use private registry scope (@company/package)",
                "Check if internal package names exist on public registry",
                "Use dependency pinning with hash verification"
            ],
            "typosquatting": [
                "Verify exact package names before installing",
                "Check download counts (popular packages have millions)",
                "Review package maintainer and creation date"
            ],
            "ci_cd_security": [
                "Pin GitHub Actions to commit SHA, not tag",
                "Review third-party Action permissions",
                "Use OIDC for cloud deployments instead of stored secrets",
                "Enable branch protection and required reviews"
            ]
        }
    
    def generate_sbom(self, format: str = "cyclonedx") -> str:
        """Generate Software Bill of Materials"""
        # pip install cyclonedx-bom
        # npm install -g @cyclonedx/cyclonedx-npm
        
        commands = {
            "cyclonedx_python": "cyclonedx-py --format json > sbom.json",
            "cyclonedx_npm": "cyclonedx-npm --output-file sbom.json",
            "syft": "syft dir:. -o cyclonedx-json=sbom.json",
            "trivy": "trivy fs --format cyclonedx --output sbom.json ."
        }
        
        print("SBOM Generation Commands:")
        for tool, cmd in commands.items():
            print(f"  {tool}: {cmd}")
        
        return "SBOM generated - check sbom.json"
    
    def check_outdated_packages(self) -> str:
        """ตรวจสอบ packages ที่ล้าสมัย"""
        commands = [
            "pip list --outdated --format=columns",  # Python
            "npm outdated",                           # Node.js
            "composer outdated",                     # PHP
            "bundle outdated"                        # Ruby
        ]
        return "\n".join(commands)

if __name__ == '__main__':
    reviewer = DependencySecurityReview()
    
    # Run pip audit
    results = reviewer.run_pip_audit("requirements.txt")
    print(f"pip-audit found {len(results['vulnerabilities'])} vulnerabilities:")
    for vuln in results['vulnerabilities']:
        print(f"  [{vuln['name']} {vuln['version']}] {vuln['id']}: {vuln['description'][:50]}...")
    
    print("\nSupply Chain Security Controls:")
    controls = reviewer.check_supply_chain_integrity()
    for category, items in controls.items():
        print(f"\n{category.upper()}:")
        for item in items:
            print(f"  - {item}")
```

---

## Step 859: Secrets & Sensitive Data Review

การตรวจสอบ secrets และข้อมูลที่มีความสำคัญในโค้ด

```python
import re
import os
from typing import List, Dict, Tuple

class SecretsReview:
    """ตรวจจับและจัดการ secrets ในโค้ด"""
    
    # Patterns สำหรับตรวจจับ secrets
    SECRET_PATTERNS = {
        "aws_access_key": {
            "pattern": r'AKIA[0-9A-Z]{16}',
            "severity": "CRITICAL",
            "description": "AWS Access Key ID"
        },
        "aws_secret_key": {
            "pattern": r'(?i)aws.*secret.*[\'"]([a-z0-9/+=]{40})[\'"]',
            "severity": "CRITICAL",
            "description": "AWS Secret Access Key"
        },
        "github_token": {
            "pattern": r'ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}',
            "severity": "CRITICAL",
            "description": "GitHub Personal Access Token"
        },
        "google_api_key": {
            "pattern": r'AIza[0-9A-Za-z\-_]{35}',
            "severity": "HIGH",
            "description": "Google API Key"
        },
        "jwt_token": {
            "pattern": r'eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+',
            "severity": "HIGH",
            "description": "JWT Token (potentially hardcoded)"
        },
        "private_key": {
            "pattern": r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
            "severity": "CRITICAL",
            "description": "Private Key"
        },
        "generic_password": {
            "pattern": r'(?i)(?:password|passwd|pwd)\s*[=:]\s*[\'"][^\s\'"]{8,}[\'"]',
            "severity": "HIGH",
            "description": "Hardcoded Password"
        },
        "connection_string": {
            "pattern": r'(?i)(?:mongodb|mysql|postgresql|redis)://[^\s\'"]+:[^\s\'"@]+@',
            "severity": "CRITICAL",
            "description": "Database connection string with credentials"
        }
    }
    
    def scan_file(self, content: str, filename: str) -> List[Dict]:
        """สแกนไฟล์หา secrets"""
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            
            for secret_type, config in self.SECRET_PATTERNS.items():
                matches = re.finditer(config['pattern'], line)
                for match in matches:
                    # Mask the actual secret value
                    matched_str = match.group()
                    masked = matched_str[:4] + '*' * (len(matched_str) - 8) + matched_str[-4:] if len(matched_str) > 8 else '****'
                    
                    findings.append({
                        "file": filename,
                        "line": line_num,
                        "type": secret_type,
                        "severity": config['severity'],
                        "description": config['description'],
                        "masked_value": masked
                    })
        
        return findings
    
    def run_gitleaks(self, repo_path: str = ".") -> str:
        """Run Gitleaks to scan git history for secrets"""
        return (
            f"gitleaks detect --source {repo_path} "
            "--report-format json --report-path gitleaks-report.json"
        )
    
    def run_trufflehog(self, repo_url: str) -> str:
        """Run TruffleHog for deep secret scanning"""
        return f"trufflehog git {repo_url} --json"
    
    def check_env_var_usage(self, code: str) -> Tuple[List[str], List[str]]:
        """ตรวจสอบการใช้ environment variables อย่างถูกต้อง"""
        good_patterns = []
        bad_patterns = []
        
        # Good: os.environ.get or os.getenv
        good_matches = re.findall(r'os\.(?:environ\.get|getenv)\([\'"]([\w_]+)[\'"]', code)
        good_patterns.extend(good_matches)
        
        # Bad: Hardcoded sensitive values
        bad_matches = re.findall(
            r'(?i)(?:API_KEY|SECRET|PASSWORD|TOKEN)\s*=\s*[\'"][^\$\s][^\'"]+[\'"]',
            code
        )
        bad_patterns.extend(bad_matches)
        
        return good_patterns, bad_patterns
    
    def secrets_management_recommendations(self) -> Dict[str, str]:
        return {
            "development": "Use .env files with python-dotenv (never commit .env)",
            "staging_production": "Use cloud secret managers: AWS Secrets Manager, Azure Key Vault, GCP Secret Manager",
            "kubernetes": "Use Kubernetes Secrets with encryption at rest + External Secrets Operator",
            "ci_cd": "Use CI/CD secret variables (GitHub Actions secrets, GitLab CI variables)",
            "rotation": "Implement automatic secret rotation (90-day maximum)",
            "audit": "Enable secret access logging and audit trails",
            "emergency": "Have incident response plan for secret exposure (immediate rotation)"
        }
    
    def generate_gitignore_additions(self) -> str:
        """สร้าง .gitignore entries สำหรับ secrets"""
        return """
# Secrets & Credentials
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*.pfx
credentials.json
secrets.json
config/secrets.yml

# Cloud credentials
.aws/credentials
.gcp_credentials.json
terraform.tfvars
*tfstate*
        """

if __name__ == '__main__':
    reviewer = SecretsReview()
    
    # Test scanning
    test_code = """
    AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'
    DB_PASSWORD = 'SuperSecret123'
    API_KEY = os.getenv('OPENAI_API_KEY')
    connection = f'postgresql://admin:password123@db.host/mydb'
    """
    
    findings = reviewer.scan_file(test_code, "config.py")
    print(f"Found {len(findings)} potential secrets:")
    for f in findings:
        print(f"  [{f['severity']}] Line {f['line']}: {f['description']} - {f['masked_value']}")
    
    good, bad = reviewer.check_env_var_usage(test_code)
    print(f"\nGood env var usage: {good}")
    print(f"Bad hardcoded secrets: {len(bad)} found")
    
    print("\nSecrets Management:")
    for env, rec in reviewer.secrets_management_recommendations().items():
        print(f"  {env}: {rec}")
```

---

## Step 860: Code Review Automation & CI/CD Integration

การรวม Secure Code Review เข้ากับ CI/CD pipeline

```python
from typing import Dict, List
import json

class CodeReviewCICD:
    """รวม security code review เข้ากับ CI/CD pipeline"""
    
    # GitHub Actions workflow สำหรับ security scanning
    GITHUB_ACTIONS_WORKFLOW = """
name: Security Code Review

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  sast-scan:
    name: SAST Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for gitleaks
      
      # Python SAST with Bandit
      - name: Run Bandit
        run: |
          pip install bandit
          bandit -r . -f json -o bandit-report.json -ll || true
      
      # Multi-language SAST with Semgrep
      - name: Run Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten
            p/python
            p/secrets
          generateSarif: true
      
      # Upload SARIF to GitHub Code Scanning
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif
      
      # Secrets scanning with Gitleaks
      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      # Dependency scanning
      - name: Run pip-audit
        run: |
          pip install pip-audit
          pip-audit --format json -o pip-audit-report.json || true
      
      # SBOM generation
      - name: Generate SBOM
        run: |
          pip install cyclonedx-bom
          cyclonedx-py --format json > sbom.json
      
      - name: Upload Reports
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: |
            bandit-report.json
            pip-audit-report.json
            sbom.json
"""
    
    # GitLab CI security scanning
    GITLAB_CI_SECURITY = """
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml

variables:
  SAST_EXCLUDED_ANALYZERS: "eslint"
  SECRET_DETECTION_HISTORIC_SCAN: "true"  # Scan full git history
  DS_PYTHON_VERSION: 3

# Custom security stage
custom-bandit:
  stage: test
  image: python:3.11
  script:
    - pip install bandit
    - bandit -r . -f json -o bandit-report.json -ll
  artifacts:
    reports:
      sast: bandit-report.json
  allow_failure: true
"""
    
    def generate_security_gate_config(self) -> Dict:
        """กำหนด security gates สำหรับ pipeline"""
        return {
            "block_on": [
                "Any CRITICAL severity finding",
                "Exposed secrets/credentials",
                "CVE with CVSS >= 9.0 in direct dependencies"
            ],
            "warn_on": [
                "HIGH severity findings (non-blocking)",
                "CVE with CVSS 7.0-8.9",
                "Outdated dependencies with known issues"
            ],
            "report_only": [
                "MEDIUM and LOW findings",
                "Style/best practice violations"
            ],
            "exceptions_process": [
                "Security team approval required for blocking exceptions",
                "Exception documented in security tracking system",
                "Exception expires after 90 days"
            ]
        }
    
    def create_code_review_template(self) -> str:
        """Template สำหรับ PR code review"""
        return """
## Security Review Checklist

### Authentication & Authorization
- [ ] New endpoints have proper authentication
- [ ] Authorization checks prevent unauthorized access
- [ ] No IDOR vulnerabilities

### Input Handling
- [ ] All user input is validated
- [ ] SQL queries use parameterized statements
- [ ] Output is properly escaped (XSS prevention)

### Cryptography
- [ ] No weak algorithms (MD5, SHA1, DES)
- [ ] No hardcoded secrets
- [ ] Cryptographic random used for security values

### Data Handling
- [ ] Sensitive data not logged
- [ ] PII handled per data classification policy
- [ ] Encryption at rest for sensitive data

### Dependencies
- [ ] New dependencies reviewed for known vulnerabilities
- [ ] License compatibility verified
- [ ] Versions pinned in lock file
        """
    
    def generate_metrics_dashboard(self) -> Dict:
        """KPIs สำหรับติดตาม Secure Code Review"""
        return {
            "mttr_security_bugs": "Mean Time to Remediate security findings",
            "vuln_density": "Vulnerabilities per 1000 lines of code",
            "sast_coverage": "% of codebase scanned",
            "false_positive_rate": "% of SAST findings that are false positives",
            "escape_rate": "Security bugs found in production vs development",
            "review_coverage": "% of PRs that underwent security review"
        }

if __name__ == '__main__':
    cicd = CodeReviewCICD()
    
    print("GitHub Actions Security Workflow saved")
    print("(see GITHUB_ACTIONS_WORKFLOW attribute)")
    
    print("\nSecurity Gate Configuration:")
    gates = cicd.generate_security_gate_config()
    print("BLOCK on:")
    for item in gates['block_on']:
        print(f"  - {item}")
    print("WARN on:")
    for item in gates['warn_on']:
        print(f"  - {item}")
    
    print("\nSecurity Metrics:")
    metrics = cicd.generate_metrics_dashboard()
    for metric, description in metrics.items():
        print(f"  {metric}: {description}")
    
    print("\nPR Code Review Template:")
    print(cicd.create_code_review_template()[:300], "...")
```

---

## สรุป Part 86

ในส่วนนี้เราได้เรียนรู้เกี่ยวกับ Secure Code Review ครอบคลุม:

1. **Step 851**: หลักการ Secure Code Review, OWASP checklist, CWE patterns
2. **Step 852**: SAST tools - Bandit, Semgrep, SonarQube automation
3. **Step 853**: Manual review techniques - pattern scanning, auth/authz review
4. **Step 854**: SQL Injection review - detection patterns, ORM vs raw SQL
5. **Step 855**: XSS review - vulnerable patterns, CSP policy analysis
6. **Step 856**: Cryptography review - broken algorithms, secure alternatives
7. **Step 857**: Auth/AuthZ review - JWT, OAuth2, missing auth detection
8. **Step 858**: Dependency security - pip-audit, npm audit, supply chain
9. **Step 859**: Secrets detection - pattern matching, Gitleaks, env var usage
10. **Step 860**: CI/CD integration - GitHub Actions, GitLab CI, security gates

**เครื่องมือหลัก**: Bandit, Semgrep, SonarQube, Gitleaks, TruffleHog, pip-audit
