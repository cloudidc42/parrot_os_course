# Part 63: Digital Forensics & Incident Response (Steps 621-630)

## Step 621: Memory Forensics with Volatility 3

การวิเคราะห์ memory dump เพื่อหาร่อรอยของ malware

```python
import subprocess
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import re

@dataclass
class MemoryArtifact:
    artifact_type: str
    pid: Optional[int]
    process_name: str
    details: str
    severity: str = "MEDIUM"
    ioc: str = ""

class Volatility3Analyzer:
    def __init__(self, memory_dump: str):
        self.dump_path = memory_dump
        self.artifacts: List[MemoryArtifact] = []
        self.vol_cmd = ["python3", "/opt/volatility3/vol.py", 
                         "-f", memory_dump]
    
    def _run_plugin(self, plugin: str, 
                     extra_args: List[str] = None) -> str:
        """Run Volatility plugin"""
        cmd = self.vol_cmd + [plugin]
        if extra_args:
            cmd.extend(extra_args)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout
    
    def list_processes(self) -> List[dict]:
        """List running processes"""
        output = self._run_plugin("windows.pslist.PsList")
        processes = []
        
        for line in output.split('\n')[2:]:  # Skip header
            parts = line.split()
            if len(parts) >= 4:
                processes.append({
                    "pid": parts[0],
                    "ppid": parts[1],
                    "name": parts[2],
                    "threads": parts[3],
                    "handles": parts[4] if len(parts) > 4 else "N/A"
                })
        
        return processes
    
    def find_hidden_processes(self) -> List[dict]:
        """Compare pslist vs psscan to find hidden processes"""
        pslist_out = self._run_plugin("windows.pslist.PsList")
        psscan_out = self._run_plugin("windows.psscan.PsScan")
        
        # Parse PIDs from each
        def extract_pids(output):
            pids = set()
            for line in output.split('\n'):
                parts = line.split()
                if parts and parts[0].isdigit():
                    pids.add(parts[0])
            return pids
        
        pslist_pids = extract_pids(pslist_out)
        psscan_pids = extract_pids(psscan_out)
        
        # PIDs in psscan but not pslist = potentially hidden
        hidden_pids = psscan_pids - pslist_pids
        
        hidden_processes = []
        for pid in hidden_pids:
            self.artifacts.append(MemoryArtifact(
                artifact_type="Hidden Process",
                pid=int(pid),
                process_name="Unknown",
                details=f"PID {pid} visible in psscan but not pslist",
                severity="HIGH",
                ioc=f"HIDDEN_PID_{pid}"
            ))
            hidden_processes.append({"pid": pid, "reason": "Not in pslist"})
        
        return hidden_processes
    
    def find_injected_code(self) -> str:
        """Find code injection via malfind"""
        output = self._run_plugin("windows.malfind.Malfind")
        
        injected_regions = []
        for line in output.split('\n'):
            if 'MZ' in line or 'VAD' in line.upper():
                # PE header indicators
                injected_regions.append(line)
        
        if injected_regions:
            self.artifacts.append(MemoryArtifact(
                artifact_type="Code Injection",
                pid=None,
                process_name="Unknown",
                details=f"Found {len(injected_regions)} suspicious memory regions",
                severity="CRITICAL"
            ))
        
        return output[:2000]
    
    def extract_network_artifacts(self) -> List[dict]:
        """Extract network connections from memory"""
        output = self._run_plugin("windows.netstat.NetStat")
        connections = []
        
        for line in output.split('\n')[2:]:
            parts = line.split()
            if len(parts) >= 5:
                conn = {
                    "offset": parts[0] if len(parts) > 0 else "",
                    "proto": parts[1] if len(parts) > 1 else "",
                    "local_addr": parts[2] if len(parts) > 2 else "",
                    "remote_addr": parts[3] if len(parts) > 3 else "",
                    "state": parts[4] if len(parts) > 4 else "",
                    "pid": parts[5] if len(parts) > 5 else "",
                    "process": parts[6] if len(parts) > 6 else ""
                }
                connections.append(conn)
                
                # Flag suspicious connections
                if conn["remote_addr"] and not conn["remote_addr"].startswith(('10.', '192.168.', '172.')):
                    self.artifacts.append(MemoryArtifact(
                        artifact_type="External Connection",
                        pid=int(conn["pid"]) if conn["pid"].isdigit() else None,
                        process_name=conn["process"],
                        details=f"{conn['process']} -> {conn['remote_addr']}",
                        severity="MEDIUM",
                        ioc=conn["remote_addr"]
                    ))
        
        return connections
    
    def dump_process_memory(self, pid: int, output_dir: str = "/tmp/vol_dumps") -> str:
        """Dump specific process memory"""
        Path(output_dir).mkdir(exist_ok=True)
        
        output = self._run_plugin(
            "windows.memmap.Memmap",
            ["--pid", str(pid), "--dump", "--output-file", output_dir]
        )
        
        return f"Memory dumped to {output_dir}/pid.{pid}.dmp"
    
    def extract_registry_hives(self, output_dir: str = "/tmp/vol_reg") -> List[str]:
        """Extract Windows registry hives"""
        Path(output_dir).mkdir(exist_ok=True)
        
        # List registry hives
        hives_output = self._run_plugin("windows.registry.hivelist.HiveList")
        
        hive_files = []
        for line in hives_output.split('\n'):
            if 'CurrentControlSet' in line or 'SAM' in line or 'SYSTEM' in line:
                hive_files.append(line)
        
        return hive_files
    
    def extract_credentials(self) -> dict:
        """Extract credentials from memory"""
        results = {}
        
        # Dump SAM hashes
        sam_output = self._run_plugin("windows.hashdump.Hashdump")
        results['sam_hashes'] = sam_output
        
        # LSA secrets
        lsa_output = self._run_plugin("windows.lsadump.Lsadump")
        results['lsa_secrets'] = lsa_output
        
        # Cached credentials
        cached_output = self._run_plugin("windows.cachedump.Cachedump")
        results['cached_creds'] = cached_output
        
        return results
    
    def timeline_analysis(self) -> str:
        """Create timeline of process activity"""
        pstree_output = self._run_plugin("windows.pstree.PsTree")
        cmdline_output = self._run_plugin("windows.cmdline.CmdLine")
        
        timeline = "Process Timeline\n" + "="*40 + "\n"
        timeline += pstree_output[:1000]
        timeline += "\nCommand Lines:\n" + "="*40 + "\n"
        timeline += cmdline_output[:1000]
        
        return timeline
    
    def generate_ioc_report(self) -> dict:
        """Generate IOC report from findings"""
        report = {
            "memory_dump": self.dump_path,
            "artifacts_found": len(self.artifacts),
            "critical_findings": [],
            "high_findings": [],
            "iocs": {
                "ips": [],
                "processes": [],
                "pids": []
            }
        }
        
        for artifact in self.artifacts:
            finding = {
                "type": artifact.artifact_type,
                "process": artifact.process_name,
                "pid": artifact.pid,
                "details": artifact.details
            }
            
            if artifact.severity == "CRITICAL":
                report["critical_findings"].append(finding)
            elif artifact.severity == "HIGH":
                report["high_findings"].append(finding)
            
            if artifact.ioc:
                # Categorize IOC
                if re.match(r'\d+\.\d+\.\d+\.\d+', artifact.ioc):
                    report["iocs"]["ips"].append(artifact.ioc)
                elif "HIDDEN_PID" in artifact.ioc:
                    report["iocs"]["pids"].append(artifact.ioc)
        
        return report

if __name__ == '__main__':
    # Example usage
    print("[*] Volatility 3 Memory Forensics")
    print("\n[*] Common plugins:")
    plugins = [
        ("windows.pslist.PsList", "List processes"),
        ("windows.psscan.PsScan", "Scan for processes (finds hidden)"),
        ("windows.pstree.PsTree", "Process tree"),
        ("windows.cmdline.CmdLine", "Process command lines"),
        ("windows.malfind.Malfind", "Find injected code"),
        ("windows.netstat.NetStat", "Network connections"),
        ("windows.hashdump.Hashdump", "SAM hashes"),
        ("windows.registry.hivelist.HiveList", "Registry hives"),
        ("windows.dlllist.DllList", "Loaded DLLs"),
        ("windows.handles.Handles", "Open handles"),
        ("windows.filescan.FileScan", "File handles"),
        ("windows.svcscan.SvcScan", "Windows services")
    ]
    
    for plugin, description in plugins:
        print(f"  vol.py -f memory.dmp {plugin}  # {description}")
```

## Step 622: Disk Forensics & Evidence Collection

การเก็บหลักฐานจาก disk อย่าง forensically sound

```python
import subprocess
import hashlib
import os
from pathlib import Path
from dataclasses import dataclass
from typing import List
import json
import time
import datetime

class DiskForensicsTools:
    def create_forensic_image(self, source_device: str, 
                               output_file: str,
                               method: str = "dd") -> dict:
        """Create forensic image of disk/device"""
        
        if method == "dd":
            cmd = [
                "dd",
                f"if={source_device}",
                f"of={output_file}",
                "bs=512",
                "conv=noerror,sync",
                "status=progress"
            ]
            cmd_str = ' '.join(cmd)
            
        elif method == "dcfldd":
            # dcfldd with hash verification
            cmd_str = f"dcfldd if={source_device} of={output_file} hash=sha256 hashlog={output_file}.hash bs=512"
        
        elif method == "ewfacquire":
            # Expert Witness Format (EWF/E01)
            cmd_str = f"ewfacquire {source_device} -t {output_file} -c best -S 2g"
        
        return {
            "method": method,
            "command": cmd_str,
            "verify_hash": f"sha256sum {output_file} > {output_file}.sha256",
            "mount_image": f"sudo losetup -f {output_file} && sudo mount /dev/loop0 /mnt/forensics -o ro"
        }
    
    def analyze_filesystem_timeline(self, image_path: str) -> dict:
        """Create filesystem timeline for forensic analysis"""
        commands = {
            "mount_image": f"sudo losetup -f {image_path}",
            "list_partitions": f"sudo fdisk -l {image_path}",
            "mount_partition": "sudo mount -o ro,loop,offset=$((512*2048)) image.dd /mnt/forensics",
            
            # Sleuth Kit tools
            "fls_list": f"fls -r {image_path}  # Recursive file listing",
            "istat_file": f"istat {image_path} <inode>  # File metadata",
            "fcat_file": f"fcat {image_path} <inode>  # File content",
            
            # Timeline with mactime
            "generate_body": f"fls -r -m '/' {image_path} > bodyfile.txt",
            "create_timeline": "mactime -b bodyfile.txt -d > timeline.csv",
            "filter_timeline": "grep '2024' timeline.csv | sort -t',' -k1",
            
            # Recover deleted files
            "recover_deleted": f"tsk_recover {image_path} /tmp/recovered_files",
            "photorec": f"photorec {image_path}  # Recover files by signature"
        }
        
        return commands
    
    def extract_artifacts(self, mount_point: str) -> dict:
        """Extract forensic artifacts from mounted filesystem"""
        artifacts = {}
        
        # Windows artifacts
        windows_artifacts = {
            "event_logs": f"{mount_point}/Windows/System32/winevt/Logs/",
            "prefetch": f"{mount_point}/Windows/Prefetch/",
            "registry_hives": {
                "system": f"{mount_point}/Windows/System32/config/SYSTEM",
                "sam": f"{mount_point}/Windows/System32/config/SAM",
                "software": f"{mount_point}/Windows/System32/config/SOFTWARE",
                "ntuser": f"{mount_point}/Users/*/NTUSER.DAT"
            },
            "lnk_files": f"{mount_point}/Users/*/AppData/Roaming/Microsoft/Windows/Recent/",
            "jump_lists": f"{mount_point}/Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/",
            "browser_history": {
                "chrome": f"{mount_point}/Users/*/AppData/Local/Google/Chrome/User Data/Default/History",
                "firefox": f"{mount_point}/Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
                "ie_history": f"{mount_point}/Users/*/AppData/Local/Microsoft/Windows/History/"
            },
            "pagefile": f"{mount_point}/pagefile.sys",
            "hiberfil": f"{mount_point}/hiberfil.sys",
            "amcache": f"{mount_point}/Windows/AppCompat/Programs/Amcache.hve",
            "shimcache": "Extract from SYSTEM hive: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache"
        }
        
        # Linux artifacts
        linux_artifacts = {
            "bash_history": f"{mount_point}/home/*/.bash_history",
            "auth_logs": f"{mount_point}/var/log/auth.log",
            "syslog": f"{mount_point}/var/log/syslog",
            "crontabs": f"{mount_point}/etc/cron.d/",
            "passwd": f"{mount_point}/etc/passwd",
            "shadow": f"{mount_point}/etc/shadow",
            "ssh_keys": f"{mount_point}/home/*/.ssh/",
            "authorized_keys": f"{mount_point}/home/*/.ssh/authorized_keys",
            "web_logs": f"{mount_point}/var/log/apache2/access.log",
            "systemd_journal": f"{mount_point}/var/log/journal/"
        }
        
        artifacts["windows"] = windows_artifacts
        artifacts["linux"] = linux_artifacts
        
        return artifacts
    
    def analyze_windows_registry(self, hive_path: str) -> dict:
        """Analyze Windows registry hive"""
        commands = {
            "list_keys": f"reglookup {hive_path}",
            "run_key": f"reglookup -p 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' {hive_path}",
            "user_assist": f"reglookup -p 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist' {hive_path}",
            "typed_paths": f"reglookup -p 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths' {hive_path}",
            "recent_docs": f"reglookup -p 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs' {hive_path}",
            "network_adapters": f"reglookup -p 'SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces' {hive_path}",
            "installed_software": f"reglookup -p 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall' {hive_path}",
            
            # With RegRipper
            "regripper_all": f"rip.pl -r {hive_path} -a  # Run all plugins",
            "regripper_specific": f"rip.pl -r {hive_path} -p autorun  # Specific plugin"
        }
        
        return commands
    
    def parse_evtx_logs(self, evtx_path: str) -> dict:
        """Parse Windows Event Logs"""
        critical_event_ids = {
            "4624": "Successful logon",
            "4625": "Failed logon",
            "4634": "Logoff",
            "4648": "Logon using explicit credentials",
            "4672": "Special privileges assigned",
            "4688": "Process creation",
            "4698": "Scheduled task created",
            "4720": "User account created",
            "4732": "User added to security group",
            "4776": "NTLM authentication",
            "7045": "Service installed",
            "1102": "Audit log cleared - SUSPICIOUS",
            "4104": "PowerShell script block logging",
            "4103": "PowerShell module logging"
        }
        
        return {
            "critical_event_ids": critical_event_ids,
            "parse_command": f"python3 -m evtx {evtx_path}",
            "hayabusa_command": f"hayabusa csv-timeline -d {evtx_path} -o timeline.csv",
            "chainsaw_command": f"chainsaw hunt {evtx_path} --sigma sigma_rules/ --mapping mapping.yml -o results/",
            "grep_logon": f"evtxdump.py {evtx_path} | grep EventID=4624"
        }

if __name__ == '__main__':
    forensics = DiskForensicsTools()
    
    # Image creation
    image_cmd = forensics.create_forensic_image("/dev/sdb", "/forensics/evidence.dd")
    print(f"[*] Create forensic image: {image_cmd['command']}")
    
    # Artifacts
    artifacts = forensics.extract_artifacts("/mnt/evidence")
    print("\n[*] Windows Artifacts:")
    for name, path in list(artifacts['windows'].items())[:5]:
        if isinstance(path, str):
            print(f"  {name}: {path}")
    
    # Event log analysis
    evtx = forensics.parse_evtx_logs("/mnt/evidence/Windows/System32/winevt/Logs/Security.evtx")
    print("\n[*] Critical Event IDs:")
    for eid, desc in list(evtx['critical_event_ids'].items())[:5]:
        print(f"  {eid}: {desc}")
```

## Step 623-630: Incident Response Automation

```python
import subprocess
import json
import os
import socket
import datetime
from dataclasses import dataclass, field
from typing import List, Dict
import platform
import hashlib

@dataclass
class IRFinding:
    category: str
    severity: str
    description: str
    artifact_path: str
    timestamp: str = ""
    recommendation: str = ""

class IncidentResponseTriage:
    def __init__(self):
        self.hostname = socket.gethostname()
        self.timestamp = datetime.datetime.utcnow().isoformat()
        self.findings: List[IRFinding] = []
    
    def collect_volatile_data(self) -> dict:
        """Collect volatile evidence first (memory, processes, network)"""
        volatile_data = {}
        
        # System info
        volatile_data['hostname'] = self.hostname
        volatile_data['timestamp'] = self.timestamp
        volatile_data['os'] = platform.system()
        volatile_data['os_version'] = platform.version()
        
        if platform.system() == 'Linux':
            commands = {
                'processes': 'ps auxf',
                'network_connections': 'ss -tunap',
                'listening_ports': 'ss -tlnp',
                'arp_table': 'arp -n',
                'routing': 'ip route',
                'users_logged': 'w',
                'last_logins': 'last -n 20',
                'failed_logins': 'lastb -n 20',
                'scheduled_tasks': 'crontab -l',
                'services': 'systemctl list-units --type=service --state=running',
                'open_files': 'lsof -nP',
                'loaded_modules': 'lsmod',
                'env_vars': 'env'
            }
        else:  # Windows (via cmd/powershell)
            commands = {
                'processes': 'tasklist /v',
                'network_connections': 'netstat -ano',
                'services': 'sc query type= all',
                'users': 'net user',
                'logged_users': 'query user',
                'scheduled_tasks': 'schtasks /query /fo LIST /v',
                'startup': 'wmic startup list full',
                'registry_run': 'reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'autostart': 'autostart.exe /accepteula -a'
            }
        
        for key, cmd in commands.items():
            try:
                result = subprocess.run(
                    cmd.split(), 
                    capture_output=True, 
                    text=True, 
                    timeout=30
                )
                volatile_data[key] = result.stdout[:5000]
            except Exception as e:
                volatile_data[key] = f"Error: {e}"
        
        return volatile_data
    
    def find_persistence_mechanisms(self) -> List[IRFinding]:
        """Check common persistence locations"""
        findings = []
        
        linux_persistence = [
            ("/etc/cron.d/", "Cron jobs"),
            ("/etc/cron.hourly/", "Hourly cron"),
            ("/var/spool/cron/", "User crontabs"),
            ("/etc/rc.local", "RC local startup"),
            ("/etc/init.d/", "Init.d services"),
            ("/etc/systemd/system/", "Systemd units"),
            ("/etc/profile.d/", "Profile scripts"),
            ("/root/.bashrc", "Root bashrc"),
            ("/etc/bashrc", "System bashrc"),
            ("/etc/ssh/authorized_keys", "System SSH keys"),
            ("/root/.ssh/authorized_keys", "Root SSH keys")
        ]
        
        for path, description in linux_persistence:
            if os.path.exists(path):
                # Check if recently modified
                mtime = os.path.getmtime(path)
                mtime_dt = datetime.datetime.fromtimestamp(mtime)
                age_hours = (datetime.datetime.now() - mtime_dt).total_seconds() / 3600
                
                if age_hours < 24:  # Modified in last 24 hours
                    finding = IRFinding(
                        category="Persistence",
                        severity="HIGH",
                        description=f"Recently modified persistence location: {description}",
                        artifact_path=path,
                        timestamp=mtime_dt.isoformat(),
                        recommendation=f"Review contents of {path}"
                    )
                    findings.append(finding)
                    self.findings.append(finding)
        
        return findings
    
    def check_rootkit_indicators(self) -> List[IRFinding]:
        """Check for rootkit indicators"""
        findings = []
        
        # Check for suspicious hidden files
        try:
            result = subprocess.run(
                ['find', '/', '-name', '.*', '-newer', '/tmp'],
                capture_output=True, text=True, timeout=30
            )
            
            for hidden_file in result.stdout.split('\n'):
                if hidden_file and '.bash_history' not in hidden_file:
                    finding = IRFinding(
                        category="Rootkit",
                        severity="MEDIUM",
                        description=f"Suspicious hidden file: {hidden_file}",
                        artifact_path=hidden_file,
                        recommendation="Analyze file contents and creation time"
                    )
                    findings.append(finding)
        except Exception:
            pass
        
        # Check /proc/net discrepancies (potential network rootkit)
        try:
            # Compare ss output vs /proc/net/tcp
            ss_result = subprocess.run(['ss', '-tln'], capture_output=True, text=True)
            proc_tcp = open('/proc/net/tcp').read() if os.path.exists('/proc/net/tcp') else ""
            
            ss_ports = set(re.findall(r':(\d+) ', ss_result.stdout))
            proc_ports = set(re.findall(r':[0-9A-F]{4} ', proc_tcp))
            
            # Convert hex to decimal
            proc_ports_dec = {str(int(p.strip().replace(':', ''), 16)) for p in proc_ports}
            
            hidden_ports = proc_ports_dec - ss_ports
            if hidden_ports:
                finding = IRFinding(
                    category="Rootkit",
                    severity="CRITICAL",
                    description=f"Ports visible in /proc/net/tcp but not ss: {hidden_ports}",
                    artifact_path="/proc/net/tcp",
                    recommendation="Investigate network rootkit"
                )
                findings.append(finding)
        except Exception:
            pass
        
        return findings
    
    def collect_ioc_hash_list(self, directories: List[str] = None) -> List[dict]:
        """Collect file hashes for IOC comparison"""
        if directories is None:
            directories = ['/tmp', '/var/tmp', '/dev/shm', '/run']
        
        file_hashes = []
        
        for directory in directories:
            if not os.path.exists(directory):
                continue
            
            for root, dirs, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    try:
                        with open(filepath, 'rb') as f:
                            content = f.read()
                            sha256 = hashlib.sha256(content).hexdigest()
                            md5 = hashlib.md5(content).hexdigest()
                        
                        stat = os.stat(filepath)
                        file_hashes.append({
                            "path": filepath,
                            "sha256": sha256,
                            "md5": md5,
                            "size": stat.st_size,
                            "mtime": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "ctime": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat()
                        })
                    except (IOError, PermissionError):
                        pass
        
        return file_hashes
    
    def generate_ir_report(self) -> dict:
        """Generate incident response report"""
        return {
            "incident_id": f"IR-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "hostname": self.hostname,
            "investigation_start": self.timestamp,
            "findings_count": len(self.findings),
            "critical_findings": [f for f in self.findings if f.severity == "CRITICAL"],
            "high_findings": [f for f in self.findings if f.severity == "HIGH"],
            "recommendations": [
                "Isolate affected system from network",
                "Preserve memory dump before any changes",
                "Clone/image disk before remediation",
                "Change all potentially compromised credentials",
                "Review authentication logs for unauthorized access",
                "Check for lateral movement to other systems",
                "Identify attack vector and patch vulnerability"
            ]
        }
    
    def containment_procedures(self) -> dict:
        """Immediate containment actions"""
        return {
            "network_isolation": [
                "# Block outbound connections (Linux):",
                "iptables -I OUTPUT -j DROP  # Block all outbound",
                "iptables -I OUTPUT -d 10.0.0.0/8 -j ACCEPT  # Allow internal",
                "# OR isolate via switch port VLAN"
            ],
            "preserve_evidence": [
                "# Memory dump:",
                "avml /evidence/memory.lime",
                "# Disk image:",
                "dd if=/dev/sda of=/evidence/disk.dd bs=4M status=progress",
                "# Running processes:",
                "ps auxf > /evidence/processes.txt",
                "# Network connections:",
                "ss -tunap > /evidence/connections.txt"
            ],
            "terminate_attacker": [
                "# Kill suspicious processes:",
                "kill -9 <suspicious_pid>",
                "# Revoke compromised accounts:",
                "passwd -l <username>  # Lock account",
                "usermod -s /sbin/nologin <username>  # Disable shell"
            ]
        }

if __name__ == '__main__':
    ir_triage = IncidentResponseTriage()
    
    print(f"[*] Starting IR Triage on: {ir_triage.hostname}")
    print(f"[*] Timestamp: {ir_triage.timestamp}")
    
    # Collect volatile data
    print("\n[*] Collecting volatile data...")
    volatile = ir_triage.collect_volatile_data()
    print(f"[+] Collected {len(volatile)} data points")
    
    # Check persistence
    print("\n[*] Checking persistence mechanisms...")
    persistence = ir_triage.find_persistence_mechanisms()
    print(f"[+] Found {len(persistence)} persistence findings")
    
    # Rootkit check
    print("\n[*] Checking for rootkit indicators...")
    rootkit = ir_triage.check_rootkit_indicators()
    print(f"[+] Found {len(rootkit)} rootkit indicators")
    
    # Generate report
    report = ir_triage.generate_ir_report()
    print(f"\n[+] IR Report: {report['incident_id']}")
    print(f"[+] Total findings: {report['findings_count']}")
    
    # Containment
    containment = ir_triage.containment_procedures()
    print("\n[*] Containment procedures:")
    for action in containment['preserve_evidence'][:3]:
        print(f"  {action}")
```
