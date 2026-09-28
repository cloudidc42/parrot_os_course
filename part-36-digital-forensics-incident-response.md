# Part 36: Digital Forensics & Incident Response (Steps 351-360)

## Step 351: Disk Forensics และ Evidence Acquisition

การได้มาซึ่งหลักฐานดิจิทัลอย่างถูกต้องเป็นพื้นฐานของ Digital Forensics

```bash
#!/bin/bash
# disk_forensics.sh - Disk Forensics & Evidence Acquisition

# ========== Evidence Acquisition ==========

# สร้าง forensic image ด้วย dd
acquire_disk_image() {
    local source_device=$1
    local output_file=$2
    local case_id=$3
    
    echo "[*] Starting forensic acquisition..."
    echo "[*] Source: $source_device"
    echo "[*] Output: $output_file"
    echo "[*] Case ID: $case_id"
    
    # บันทึก metadata ก่อน acquisition
    cat > "${output_file}.metadata" <<EOF
Case ID: $case_id
Acquisition Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Examiner: $(whoami)
Source Device: $source_device
Source Size: $(blockdev --getsize64 $source_device 2>/dev/null || fdisk -l $source_device 2>/dev/null | grep bytes | awk '{print $5}')
Hostname: $(hostname)
OS: $(uname -a)
EOF
    
    # คำนวณ hash ก่อน acquisition
    echo "[*] Computing pre-acquisition hash..."
    local pre_hash=$(sha256sum $source_device | awk '{print $1}')
    echo "Pre-acquisition SHA256: $pre_hash" >> "${output_file}.metadata"
    
    # Acquire disk image
    echo "[*] Acquiring disk image..."
    dd if=$source_device of=$output_file bs=512 conv=noerror,sync status=progress
    
    # คำนวณ hash หลัง acquisition
    echo "[*] Computing post-acquisition hash..."
    local post_hash=$(sha256sum $output_file | awk '{print $1}')
    echo "Post-acquisition SHA256: $post_hash" >> "${output_file}.metadata"
    
    # ตรวจสอบ integrity
    if [ "$pre_hash" == "$post_hash" ]; then
        echo "[+] Hash verification PASSED - Image integrity confirmed"
    else
        echo "[-] Hash verification FAILED - Image may be corrupted"
    fi
    
    # สร้าง evidence file
    echo "Acquisition Log:" >> "${output_file}.metadata"
    echo "Source Hash: $pre_hash" >> "${output_file}.metadata"
    echo "Image Hash: $post_hash" >> "${output_file}.metadata"
    echo "Verification: $([ "$pre_hash" == "$post_hash" ] && echo PASSED || echo FAILED)" >> "${output_file}.metadata"
}

# ใช้ dcfldd สำหรับ hashing ระหว่าง acquisition
acquire_with_dcfldd() {
    local source=$1
    local output=$2
    
    dcfldd if=$source of=$output \
        hash=sha256 \
        hashlog=${output}.sha256 \
        hashwindow=1G \
        bs=512 \
        conv=noerror,sync \
        statusinterval=32
}

# ใช้ ewfacquire สำหรับ E01 format (Expert Witness Format)
acquire_ewf_format() {
    local source=$1
    local output_dir=$2
    local case_num=$3
    local examiner=$4
    
    ewfacquire $source \
        -t "${output_dir}/evidence" \
        -C "$case_num" \
        -D "Forensic acquisition" \
        -E "$examiner" \
        -f encase6 \
        -c best \
        -b 64
}

# Network forensics - capture traffic
acquire_network_traffic() {
    local interface=$1
    local output_file=$2
    local duration=$3  # seconds
    
    echo "[*] Capturing network traffic for ${duration}s on $interface"
    tcpdump -i $interface \
        -w $output_file \
        -G $duration \
        -W 1 \
        -s 0 \
        -Z root
    
    # คำนวณ hash
    sha256sum $output_file > ${output_file}.sha256
    echo "[+] Capture complete: $output_file"
}

# Memory acquisition
acquire_memory() {
    local output_file=$1
    
    # ใช้ /dev/mem หรือ /proc/kcore
    if [ -f /proc/kcore ]; then
        echo "[*] Acquiring memory via /proc/kcore..."
        dd if=/proc/kcore of=$output_file bs=1M status=progress 2>/dev/null
    fi
    
    # ใช้ LiME (Linux Memory Extractor) สำหรับ full acquisition
    echo "[*] Loading LiME kernel module..."
    # insmod lime.ko "path=$output_file format=lime"
    
    sha256sum $output_file > ${output_file}.sha256
    echo "[+] Memory acquisition complete"
}

# Mount forensic image read-only
mount_forensic_image() {
    local image_file=$1
    local mount_point=$2
    
    mkdir -p $mount_point
    
    # Mount แบบ read-only เพื่อป้องกันการแก้ไข
    mount -o ro,loop,noatime $image_file $mount_point
    
    # หรือใช้ affuse สำหรับ AFF format
    # affuse $image_file /mnt/aff
    
    # ใช้ ewfmount สำหรับ E01
    # ewfmount evidence.E01 /mnt/ewf
    # mount -o ro,loop /mnt/ewf/ewf1 $mount_point
    
    echo "[+] Image mounted read-only at $mount_point"
}

# ========== Chain of Custody ==========
create_chain_of_custody() {
    local case_id=$1
    local evidence_id=$2
    
    cat > "CoC_${case_id}_${evidence_id}.txt" <<EOF
=====================================
CHAIN OF CUSTODY DOCUMENT
=====================================
Case Number: $case_id
Evidence ID: $evidence_id
Date/Time: $(date -u)
Examiner: $(whoami)
Organization: [Organization Name]

Description of Evidence:
[Describe the evidence item]

Collection Information:
Date Collected: $(date -u)
Location: [Location where evidence was collected]
Collected By: $(whoami)
Collection Method: [Method used]

Storage Information:
Location: [Storage location]
Storage Conditions: [Conditions]

Chain of Custody Log:
+----+------------+----------+----------+--------+---------+
| No | Date/Time  | Received | Released | Reason | Initials|
+----+------------+----------+----------+--------+---------+
|  1 | $(date +%Y-%m-%d) | $(whoami)  | -        | Initial| [Init]  |
+----+------------+----------+----------+--------+---------+

Signatures:
Examiner: ___________________  Date: ___________
Witness:  ___________________  Date: ___________
=====================================
EOF
    echo "[+] Chain of Custody document created"
}

# Main
echo "=== Digital Forensics Toolkit ==="
echo "1. Acquire disk image: acquire_disk_image /dev/sdb evidence.dd CASE001"
echo "2. Acquire with dcfldd: acquire_with_dcfldd /dev/sdb evidence.dd"
echo "3. Acquire memory: acquire_memory memory.lime"
echo "4. Mount image: mount_forensic_image evidence.dd /mnt/forensics"
```

## Step 352: Memory Forensics ด้วย Volatility

การวิเคราะห์ memory dump เพื่อหา artifacts และ malware

```python
#!/usr/bin/env python3
# memory_forensics.py - Memory Analysis with Volatility

import subprocess
import json
import os
import re
from pathlib import Path
from datetime import datetime

class MemoryForensics:
    def __init__(self, memory_dump: str, profile: str = None):
        self.dump = memory_dump
        self.profile = profile
        self.vol_cmd = "vol3"  # Volatility 3
        self.results = {}
        
    def run_plugin(self, plugin: str, args: list = None) -> str:
        cmd = [self.vol_cmd, "-f", self.dump]
        if self.profile:
            cmd.extend(["--profile", self.profile])
        cmd.append(plugin)
        if args:
            cmd.extend(args)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"Plugin {plugin} timed out"
        except Exception as e:
            return f"Error: {e}"
    
    def identify_os(self) -> dict:
        """ระบุ OS จาก memory dump"""
        print("[*] Identifying operating system...")
        
        # Volatility 3 - auto-detect
        result = self.run_plugin("windows.info")
        if "Windows" in result:
            os_info = {"type": "Windows"}
            # Extract version
            for line in result.split("\n"):
                if "NtBuildLab" in line:
                    os_info["build"] = line.split()[-1]
                if "NtMajorVersion" in line:
                    os_info["major"] = line.split()[-1]
            return os_info
        
        result = self.run_plugin("linux.banner")
        if result:
            return {"type": "Linux", "banner": result.strip()}
        
        return {"type": "Unknown"}
    
    def list_processes(self) -> list:
        """แสดงรายการ processes"""
        print("[*] Listing processes...")
        
        # Windows
        result = self.run_plugin("windows.pslist")
        processes = []
        
        for line in result.split("\n")[2:]:  # Skip header
            if line.strip():
                parts = line.split()
                if len(parts) >= 7:
                    proc = {
                        "pid": parts[2],
                        "ppid": parts[3],
                        "name": parts[1],
                        "offset": parts[0],
                        "threads": parts[4],
                        "handles": parts[5],
                        "create_time": f"{parts[6]} {parts[7]}" if len(parts) > 7 else "N/A"
                    }
                    processes.append(proc)
        
        self.results["processes"] = processes
        return processes
    
    def detect_process_injection(self) -> list:
        """ตรวจหา process injection"""
        print("[*] Detecting process injection...")
        findings = []
        
        # malfind - ค้นหา injected code
        result = self.run_plugin("windows.malfind")
        
        for line in result.split("\n"):
            if "MZ" in line or "PAGE_EXECUTE_READWRITE" in line:
                findings.append({
                    "type": "Suspicious Memory Region",
                    "details": line.strip()
                })
        
        # vadinfo - Virtual Address Descriptor
        result = self.run_plugin("windows.vadinfo")
        
        # หา private executable memory
        current_process = None
        for line in result.split("\n"):
            if "Process:" in line:
                current_process = line
            if "EXECUTE" in line and "Private" in line:
                findings.append({
                    "type": "Private Executable Memory",
                    "process": current_process,
                    "details": line.strip()
                })
        
        return findings
    
    def analyze_network(self) -> list:
        """วิเคราะห์ network connections"""
        print("[*] Analyzing network connections...")
        connections = []
        
        # Windows network connections
        result = self.run_plugin("windows.netstat")
        
        for line in result.split("\n")[2:]:
            if line.strip() and not line.startswith("Volatility"):
                parts = line.split()
                if len(parts) >= 6:
                    conn = {
                        "proto": parts[0] if len(parts) > 0 else "N/A",
                        "local": parts[1] if len(parts) > 1 else "N/A",
                        "remote": parts[2] if len(parts) > 2 else "N/A",
                        "state": parts[3] if len(parts) > 3 else "N/A",
                        "pid": parts[4] if len(parts) > 4 else "N/A",
                        "process": parts[5] if len(parts) > 5 else "N/A"
                    }
                    connections.append(conn)
                    
                    # Flag suspicious connections
                    if conn["state"] == "ESTABLISHED":
                        remote_ip = conn["remote"].split(":")[0]
                        # ตรวจสอบ known malicious ports
                        suspicious_ports = [4444, 5555, 7777, 8888, 9999, 1337, 31337]
                        if ":" in conn["remote"]:
                            port = int(conn["remote"].split(":")[-1]) if conn["remote"].split(":")[-1].isdigit() else 0
                            if port in suspicious_ports:
                                conn["suspicious"] = True
                                print(f"  [!] Suspicious connection: {conn['process']} -> {conn['remote']}")
        
        self.results["connections"] = connections
        return connections
    
    def extract_credentials(self) -> dict:
        """ดึง credentials จาก memory"""
        print("[*] Extracting credentials...")
        creds = {}
        
        # Windows hashes via hashdump
        result = self.run_plugin("windows.hashdump")
        if result:
            creds["windows_hashes"] = result
        
        # LSASS credentials
        result = self.run_plugin("windows.lsadump")
        if result:
            creds["lsa_secrets"] = result
        
        # Cached credentials
        result = self.run_plugin("windows.cachedump")
        if result:
            creds["cached_creds"] = result
        
        return creds
    
    def analyze_registry(self) -> dict:
        """วิเคราะห์ registry hive จาก memory"""
        print("[*] Analyzing registry...")
        reg_data = {}
        
        # Print registry keys
        result = self.run_plugin("windows.registry.printkey", 
                                   ["--key", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"])
        reg_data["startup_programs"] = result
        
        # ค้นหา registry keys
        result = self.run_plugin("windows.registry.hivelist")
        reg_data["hive_list"] = result
        
        return reg_data
    
    def extract_files(self, output_dir: str) -> list:
        """ดึงไฟล์จาก memory"""
        print(f"[*] Extracting files to {output_dir}...")
        os.makedirs(output_dir, exist_ok=True)
        
        files = []
        
        # Windows filescan
        result = self.run_plugin("windows.filescan")
        
        # หาไฟล์ที่น่าสนใจ
        suspicious_extensions = [".exe", ".dll", ".bat", ".ps1", ".vbs", ".js"]
        for line in result.split("\n"):
            for ext in suspicious_extensions:
                if ext.lower() in line.lower():
                    parts = line.split()
                    if parts:
                        offset = parts[0]
                        # dumpfiles
                        self.run_plugin("windows.dumpfiles", ["--virtaddr", offset, "--dump-dir", output_dir])
                        files.append(line.strip())
        
        return files
    
    def timeline_analysis(self) -> list:
        """สร้าง timeline จาก memory artifacts"""
        print("[*] Creating memory timeline...")
        timeline = []
        
        # Process creation times
        processes = self.list_processes()
        for proc in processes:
            if proc.get("create_time") != "N/A":
                timeline.append({
                    "time": proc["create_time"],
                    "type": "Process Created",
                    "details": f"PID {proc['pid']}: {proc['name']}"
                })
        
        # Sort by time
        timeline.sort(key=lambda x: x.get("time", ""))
        return timeline
    
    def generate_report(self, output_file: str):
        """สร้าง forensics report"""
        print(f"[*] Generating report: {output_file}")
        
        report = f"""# Memory Forensics Report

**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Analyst:** [Analyst Name]
**Memory Dump:** {self.dump}

## Executive Summary
[Summary of findings]

## System Information
{json.dumps(self.identify_os(), indent=2)}

## Process Analysis
Total Processes: {len(self.results.get('processes', []))}

### Suspicious Processes
[List suspicious processes]

## Network Analysis
Total Connections: {len(self.results.get('connections', []))}

### Suspicious Connections
{json.dumps([c for c in self.results.get('connections', []) if c.get('suspicious')], indent=2)}

## Injection Detection
[Injection findings]

## Recommendations
1. Investigate suspicious processes
2. Block malicious C2 IPs
3. Rebuild compromised systems
"""
        
        with open(output_file, "w") as f:
            f.write(report)
        print(f"[+] Report saved: {output_file}")


# Volatility 2 commands (legacy)
VOLATILITY2_COMMANDS = """
# Identify profile
vol.py -f memory.raw imageinfo
vol.py -f memory.raw kdbgscan

# Process analysis
vol.py -f memory.raw --profile=Win10x64 pslist
vol.py -f memory.raw --profile=Win10x64 pstree
vol.py -f memory.raw --profile=Win10x64 psscan  # Find hidden processes
vol.py -f memory.raw --profile=Win10x64 cmdline
vol.py -f memory.raw --profile=Win10x64 dlllist -p 1234

# Network
vol.py -f memory.raw --profile=Win10x64 netscan
vol.py -f memory.raw --profile=Win10x64 connscan

# Registry
vol.py -f memory.raw --profile=Win10x64 hivelist
vol.py -f memory.raw --profile=Win10x64 printkey -K "SAM\\Domains\\Account\\Users"

# Credentials
vol.py -f memory.raw --profile=Win10x64 hashdump
vol.py -f memory.raw --profile=Win10x64 lsadump
vol.py -f memory.raw --profile=Win10x64 mimikatz

# Malware detection
vol.py -f memory.raw --profile=Win10x64 malfind
vol.py -f memory.raw --profile=Win10x64 hollowfind
vol.py -f memory.raw --profile=Win10x64 apihooks

# File extraction
vol.py -f memory.raw --profile=Win10x64 filescan | grep -i evil
vol.py -f memory.raw --profile=Win10x64 dumpfiles -Q 0x12345678 -D /tmp/dump/

# Linux
vol.py -f linux.lime --profile=LinuxUbuntu16x64 linux_pslist
vol.py -f linux.lime --profile=LinuxUbuntu16x64 linux_netstat
vol.py -f linux.lime --profile=LinuxUbuntu16x64 linux_bash
"""

if __name__ == "__main__":
    # Example usage
    analyzer = MemoryForensics("/path/to/memory.raw")
    analyzer.identify_os()
    analyzer.list_processes()
    analyzer.detect_process_injection()
    analyzer.analyze_network()
    analyzer.generate_report("memory_forensics_report.md")
```

## Step 353: Filesystem Forensics และ Artifact Analysis

การวิเคราะห์ filesystem artifacts เพื่อสร้าง timeline

```python
#!/usr/bin/env python3
# filesystem_forensics.py - Filesystem Analysis

import os
import stat
import hashlib
import sqlite3
import struct
from datetime import datetime, timezone
from pathlib import Path
import json

class FilesystemForensics:
    def __init__(self, mount_point: str):
        self.mount = mount_point
        self.timeline = []
        self.artifacts = {}
        
    def analyze_mft(self, mft_file: str = None):
        """วิเคราะห์ MFT (Master File Table) - Windows"""
        print("[*] Analyzing MFT...")
        
        # ใช้ analyzeMFT หรือ mftparser
        if mft_file:
            # python analyzeMFT.py -f $MFT -o output.csv
            print(f"[*] Parse with: analyzeMFT.py -f {mft_file} -o mft_output.csv")
        
        # ใช้ The Sleuth Kit
        # istat -f ntfs /dev/sdb 0  # MFT entry 0
        # fls -r -m / /dev/sdb  # List all files with timestamps
        print("[*] Commands:")
        print("  fls -r -m / image.dd > bodyfile.txt")
        print("  mactime -b bodyfile.txt -d > timeline.csv")
        print("  icat image.dd 0 > mft.raw  # Extract MFT")
    
    def analyze_prefetch(self, prefetch_dir: str = None) -> list:
        """วิเคราะห์ Prefetch files - Windows execution artifacts"""
        print("[*] Analyzing Prefetch files...")
        executions = []
        
        if prefetch_dir is None:
            prefetch_dir = os.path.join(self.mount, "Windows", "Prefetch")
        
        if not os.path.exists(prefetch_dir):
            print(f"  [-] Prefetch directory not found: {prefetch_dir}")
            return executions
        
        for pf_file in Path(prefetch_dir).glob("*.pf"):
            try:
                # Parse prefetch file header
                with open(pf_file, "rb") as f:
                    data = f.read()
                
                # Simple parsing (version 30 - Windows 10)
                # Offset 0x00: Version (4 bytes)
                # Offset 0x04: Signature "SCCA" (4 bytes)
                # Offset 0x0C: File size (4 bytes)
                # Offset 0x10: Executable name (60 bytes)
                # Offset 0x4C: Prefetch hash (4 bytes)
                
                if data[4:8] == b'SCCA':
                    exe_name = data[0x10:0x70].decode('utf-16-le', errors='ignore').rstrip('\x00')
                    
                    # Get run count and last run time from file metadata
                    stat_info = os.stat(pf_file)
                    last_run = datetime.fromtimestamp(stat_info.st_mtime)
                    
                    executions.append({
                        "file": str(pf_file.name),
                        "executable": exe_name,
                        "last_run": str(last_run),
                        "size": stat_info.st_size
                    })
                    
            except Exception as e:
                pass
        
        print(f"[+] Found {len(executions)} prefetch files")
        return executions
    
    def analyze_registry_hive(self, hive_path: str) -> dict:
        """วิเคราะห์ Registry Hive ด้วย regipy"""
        print(f"[*] Analyzing registry hive: {hive_path}")
        
        # ใช้ regipy library
        try:
            from regipy.registry import RegistryHive
            hive = RegistryHive(hive_path)
            
            interesting_keys = {}
            
            # Run keys
            run_key_paths = [
                "\\Microsoft\\Windows\\CurrentVersion\\Run",
                "\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
            ]
            
            for key_path in run_key_paths:
                try:
                    key = hive.get_key(key_path)
                    values = {v.name: v.value for v in key.iter_values()}
                    interesting_keys[key_path] = values
                except:
                    pass
            
            return interesting_keys
            
        except ImportError:
            print("  [!] regipy not installed. Use: pip install regipy")
            return {}
    
    def analyze_event_logs(self, evtx_path: str) -> list:
        """วิเคราะห์ Windows Event Logs"""
        print(f"[*] Analyzing event logs: {evtx_path}")
        events = []
        
        try:
            import Evtx.Evtx as evtx
            import Evtx.Views as views
            
            with evtx.Evtx(evtx_path) as log:
                for record in log.records():
                    xml = record.xml()
                    # Parse specific event IDs
                    if '<EventID>4624</EventID>' in xml:  # Logon
                        events.append({"id": 4624, "type": "Logon", "xml": xml[:200]})
                    elif '<EventID>4625</EventID>' in xml:  # Failed logon
                        events.append({"id": 4625, "type": "Failed Logon", "xml": xml[:200]})
                    elif '<EventID>4688</EventID>' in xml:  # Process creation
                        events.append({"id": 4688, "type": "Process Created", "xml": xml[:200]})
                        
        except ImportError:
            print("  [!] python-evtx not installed. Use: pip install python-evtx")
        
        return events
    
    def analyze_browser_history(self) -> dict:
        """วิเคราะห์ Browser history"""
        print("[*] Analyzing browser history...")
        history = {}
        
        # Chrome history paths
        chrome_paths = [
            "Users/*/AppData/Local/Google/Chrome/User Data/Default/History",
            "home/*/.config/google-chrome/Default/History"
        ]
        
        for pattern in chrome_paths:
            import glob
            for db_path in glob.glob(os.path.join(self.mount, pattern)):
                try:
                    # Copy to temp (SQLite may be locked)
                    import shutil
                    temp_db = "/tmp/chrome_history_temp.db"
                    shutil.copy2(db_path, temp_db)
                    
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.execute("""
                        SELECT urls.url, urls.title, visits.visit_time
                        FROM urls, visits
                        WHERE urls.id = visits.url
                        ORDER BY visits.visit_time DESC
                        LIMIT 100
                    """)
                    
                    chrome_history = []
                    for row in cursor.fetchall():
                        url, title, visit_time = row
                        # Convert Chrome timestamp (microseconds since 1601-01-01)
                        timestamp = datetime(1601, 1, 1) + __import__('datetime').timedelta(microseconds=visit_time)
                        chrome_history.append({
                            "url": url,
                            "title": title,
                            "time": str(timestamp)
                        })
                    
                    conn.close()
                    history["chrome"] = chrome_history
                    print(f"  [+] Found {len(chrome_history)} Chrome history entries")
                    
                except Exception as e:
                    print(f"  [-] Error reading Chrome history: {e}")
        
        return history
    
    def create_super_timeline(self, output_file: str):
        """สร้าง Super Timeline ด้วย Plaso"""
        print("[*] Creating super timeline with Plaso...")
        
        commands = [
            f"# สร้าง Plaso storage file",
            f"log2timeline.py --parsers win7,win_gen timeline.plaso {self.mount}/",
            f"",
            f"# แปลงเป็น CSV",
            f"psort.py -o l2tcsv -w timeline.csv timeline.plaso",
            f"",
            f"# Filter by time range",
            f"psort.py -o l2tcsv -w filtered.csv timeline.plaso \"date > '2024-01-01' AND date < '2024-12-31'\"",
            f"",
            f"# ใช้ pinfo เพื่อดู storage info",
            f"pinfo.py timeline.plaso"
        ]
        
        for cmd in commands:
            print(f"  {cmd}")


# Autopsy/Sleuth Kit commands
SLEUTH_KIT_COMMANDS = """
# Basic disk analysis
mmls image.dd           # Show partition layout
fsstat -f ntfs image.dd # Filesystem statistics

# File listing with timestamps
fls -r -m / image.dd > bodyfile.txt
mactime -b bodyfile.txt -d > timeline.csv

# Find deleted files
ils -f ntfs image.dd | mactime -b - -d

# Recover deleted files
tsk_recover -e image.dd /output/dir/

# String search
srch_strings image.dd | grep -i password

# Hash databases
hfind -i md5 /nsrl/ <hash>
md5sum *.exe > hashes.txt

# Autopsy GUI
autopsy &
# Access via: http://localhost:9999/autopsy
"""

if __name__ == "__main__":
    forensics = FilesystemForensics("/mnt/forensic")
    forensics.analyze_mft()
    prefetch = forensics.analyze_prefetch()
    history = forensics.analyze_browser_history()
    forensics.create_super_timeline("super_timeline.csv")
```

## Step 354: Network Forensics

การวิเคราะห์ network traffic สำหรับ incident response

```python
#!/usr/bin/env python3
# network_forensics.py - Network Traffic Analysis

import subprocess
from scapy.all import *
from collections import defaultdict, Counter
import json
import re
from datetime import datetime

class NetworkForensics:
    def __init__(self, pcap_file: str):
        self.pcap = pcap_file
        self.packets = None
        self.stats = defaultdict(int)
        
    def load_pcap(self):
        """โหลด PCAP file"""
        print(f"[*] Loading {self.pcap}...")
        self.packets = rdpcap(self.pcap)
        print(f"[+] Loaded {len(self.packets)} packets")
        
    def extract_http_traffic(self) -> list:
        """ดึง HTTP requests/responses"""
        http_data = []
        
        if not self.packets:
            self.load_pcap()
        
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                
                # HTTP Request
                if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                    lines = payload.split("\r\n")
                    method_url = lines[0].split(" ")
                    
                    headers = {}
                    for line in lines[1:]:
                        if ": " in line:
                            key, val = line.split(": ", 1)
                            headers[key] = val
                    
                    http_data.append({
                        "type": "request",
                        "method": method_url[0] if len(method_url) > 0 else "",
                        "url": method_url[1] if len(method_url) > 1 else "",
                        "src": f"{pkt[IP].src}:{pkt[TCP].sport}",
                        "dst": f"{pkt[IP].dst}:{pkt[TCP].dport}",
                        "host": headers.get("Host", ""),
                        "user_agent": headers.get("User-Agent", "")
                    })
                    
                    # ตรวจหา credential submission
                    if method_url[0] == "POST":
                        body = payload.split("\r\n\r\n")[-1] if "\r\n\r\n" in payload else ""
                        if any(kw in body.lower() for kw in ["password", "passwd", "pwd", "pass"]):
                            print(f"  [!] Possible credential submission: {pkt[IP].src} -> {pkt[IP].dst}:{pkt[TCP].dport}")
                            print(f"      Body: {body[:200]}")
        
        return http_data
    
    def extract_dns_queries(self) -> list:
        """ดึง DNS queries"""
        dns_queries = []
        
        if not self.packets:
            self.load_pcap()
        
        for pkt in self.packets:
            if pkt.haslayer(DNSQR):
                query = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip(".")
                qtype = pkt[DNSQR].qtype
                
                dns_queries.append({
                    "query": query,
                    "type": qtype,
                    "src": pkt[IP].src if pkt.haslayer(IP) else "N/A",
                    "dst": pkt[IP].dst if pkt.haslayer(IP) else "N/A"
                })
                
                # ตรวจหา DNS tunneling
                if len(query) > 50:  # ชื่อ subdomain ยาวผิดปกติ
                    print(f"  [!] Possible DNS tunneling: {query[:80]}")
                    
                # ตรวจหา DGA (Domain Generation Algorithm)
                # High entropy domains
                import math
                entropy = 0
                if query:
                    domain_part = query.split(".")[0] if "." in query else query
                    prob = [domain_part.count(c) / len(domain_part) for c in set(domain_part)]
                    entropy = -sum(p * math.log2(p) for p in prob if p > 0)
                    if entropy > 3.8 and len(domain_part) > 12:
                        print(f"  [!] Possible DGA domain (entropy={entropy:.2f}): {query}")
        
        return dns_queries
    
    def detect_c2_beaconing(self, threshold_secs: int = 60) -> list:
        """ตรวจหา C2 beaconing patterns"""
        print("[*] Detecting C2 beaconing...")
        
        if not self.packets:
            self.load_pcap()
        
        # เก็บ timestamp ของแต่ละ connection pair
        connections = defaultdict(list)
        
        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                key = f"{pkt[IP].src}:{pkt[TCP].sport}->{pkt[IP].dst}:{pkt[TCP].dport}"
                connections[key].append(float(pkt.time))
        
        beacons = []
        for conn, timestamps in connections.items():
            if len(timestamps) > 10:
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
                    std_dev = variance ** 0.5
                    
                    # Low variance = regular beaconing
                    if std_dev < avg_interval * 0.1 and avg_interval < 3600:
                        beacons.append({
                            "connection": conn,
                            "count": len(timestamps),
                            "avg_interval": round(avg_interval, 2),
                            "std_dev": round(std_dev, 2),
                            "suspicion": "HIGH" if std_dev < 5 else "MEDIUM"
                        })
        
        if beacons:
            print(f"  [!] Found {len(beacons)} potential C2 beacons")
            for b in beacons[:5]:
                print(f"      {b['connection']}: interval={b['avg_interval']}s, stddev={b['std_dev']}s")
        
        return beacons
    
    def extract_files_from_pcap(self, output_dir: str):
        """ดึงไฟล์จาก network traffic"""
        os.makedirs(output_dir, exist_ok=True)
        print(f"[*] Extracting files to {output_dir}...")
        
        # ใช้ NetworkMiner หรือ Foremost จาก pcap
        # foremost -t all -i capture.pcap -o output/
        # tcpflow -r capture.pcap -o flows/ && foremost -t all -i flows/
        
        # ใช้ tshark
        commands = [
            f"tshark -r {self.pcap} --export-objects http,{output_dir}",
            f"tshark -r {self.pcap} --export-objects smb,{output_dir}",
            f"tshark -r {self.pcap} --export-objects ftp-data,{output_dir}"
        ]
        
        for cmd in commands:
            print(f"  Running: {cmd}")
    
    def analyze_with_zeek(self) -> dict:
        """วิเคราะห์ด้วย Zeek"""
        print("[*] Analyzing with Zeek...")
        
        zeek_cmd = f"zeek -r {self.pcap} /opt/zeek/share/zeek/policy/tuning/defaults/"
        print(f"  Running: {zeek_cmd}")
        
        zeek_logs = {
            "conn.log": "Connection summary",
            "dns.log": "DNS queries",
            "http.log": "HTTP traffic",
            "ssl.log": "SSL/TLS connections",
            "files.log": "Transferred files",
            "weird.log": "Protocol anomalies",
            "notice.log": "Security notices"
        }
        
        print("  Zeek log files generated:")
        for log, desc in zeek_logs.items():
            print(f"    {log}: {desc}")
        
        return zeek_logs
    
    def generate_report(self) -> str:
        """สร้าง network forensics report"""
        http = self.extract_http_traffic()
        dns = self.extract_dns_queries()
        beacons = self.detect_c2_beaconing()
        
        report = f"""# Network Forensics Report

**PCAP File:** {self.pcap}
**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Statistics
- HTTP Requests: {len([h for h in http if h['type'] == 'request'])}
- DNS Queries: {len(dns)}
- C2 Beacons Detected: {len(beacons)}

## Key Findings

### Suspicious DNS Queries
{json.dumps([d for d in dns if len(d.get('query', '')) > 50][:10], indent=2)}

### Potential C2 Beacons
{json.dumps(beacons[:5], indent=2)}

## Recommendations
1. Block identified C2 IP addresses
2. Investigate high-entropy DNS queries
3. Analyze credential submissions in HTTP POST
"""
        return report


if __name__ == "__main__":
    nf = NetworkForensics("/path/to/capture.pcap")
    nf.load_pcap()
    report = nf.generate_report()
    print(report)
```

## Step 355: Log Analysis & SIEM Integration

การวิเคราะห์ log files สำหรับ incident response

```python
#!/usr/bin/env python3
# log_analysis.py - Log Analysis for IR

import re
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path

class LogAnalyzer:
    def __init__(self):
        self.events = []
        self.alerts = []
        self.iocs = set()
        
    def parse_syslog(self, log_file: str) -> list:
        """Parse Linux syslog"""
        events = []
        
        syslog_pattern = re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s+(.*)'
        )
        
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                m = syslog_pattern.match(line.strip())
                if m:
                    events.append({
                        "time": m.group(1),
                        "host": m.group(2),
                        "process": m.group(3),
                        "message": m.group(4)
                    })
        
        return events
    
    def parse_auth_log(self, auth_log: str = "/var/log/auth.log") -> dict:
        """วิเคราะห์ authentication log"""
        print("[*] Analyzing auth log...")
        
        failed_logins = defaultdict(int)
        successful_logins = []
        sudo_commands = []
        ssh_sessions = []
        
        with open(auth_log, 'r', errors='ignore') as f:
            for line in f:
                # Failed SSH login
                if "Failed password" in line or "Invalid user" in line:
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    user_match = re.search(r'user (\w+)', line) or re.search(r'for (\w+) from', line)
                    if ip_match:
                        failed_logins[ip_match.group(1)] += 1
                
                # Successful login
                elif "Accepted password" in line or "Accepted publickey" in line:
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    user_match = re.search(r'for (\w+) from', line)
                    if ip_match and user_match:
                        successful_logins.append({
                            "user": user_match.group(1),
                            "ip": ip_match.group(1),
                            "time": line[:15]
                        })
                
                # Sudo commands
                elif "sudo" in line and "COMMAND" in line:
                    cmd_match = re.search(r'COMMAND=(.*)', line)
                    user_match = re.search(r'(\w+)\s*:', line)
                    if cmd_match:
                        sudo_commands.append({
                            "command": cmd_match.group(1).strip(),
                            "time": line[:15]
                        })
                
                # SSH sessions
                elif "sshd" in line and "session opened" in line:
                    user_match = re.search(r'for user (\w+)', line)
                    if user_match:
                        ssh_sessions.append({
                            "user": user_match.group(1),
                            "time": line[:15],
                            "action": "opened"
                        })
        
        # ตรวจหา brute force
        brute_force = {ip: count for ip, count in failed_logins.items() if count > 10}
        if brute_force:
            print(f"  [!] Brute force detected from: {list(brute_force.keys())}")
        
        return {
            "failed_logins": dict(failed_logins),
            "brute_force_ips": brute_force,
            "successful_logins": successful_logins,
            "sudo_commands": sudo_commands,
            "ssh_sessions": ssh_sessions
        }
    
    def parse_apache_log(self, log_file: str) -> dict:
        """วิเคราะห์ Apache/Nginx access log"""
        print("[*] Analyzing web server log...")
        
        combined_log_pattern = re.compile(
            r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+) "([^"]*)" "([^"]*)"'
        )
        
        attacks = []
        attack_patterns = {
            "SQL Injection": [r"union.*select", r"'; DROP", r"1=1", r"OR '1'='1'"],
            "XSS": [r"<script", r"javascript:", r"onerror=", r"alert\("],
            "Path Traversal": [r"\.\./", r"%2e%2e", r"etc/passwd"],
            "Command Injection": [r"; ?ls", r"\| ?id", r"\| ?cat", r"`id`"],
            "Scanner": [r"sqlmap", r"nikto", r"nmap", r"masscan", r"dirbuster", r"gobuster"]
        }
        
        ip_requests = Counter()
        status_codes = Counter()
        
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                m = combined_log_pattern.match(line)
                if m:
                    ip = m.group(1)
                    url = m.group(4)
                    status = m.group(5)
                    ua = m.group(8)
                    
                    ip_requests[ip] += 1
                    status_codes[status] += 1
                    
                    # ตรวจหา attacks
                    for attack_type, patterns in attack_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, url, re.IGNORECASE) or \
                               re.search(pattern, ua, re.IGNORECASE):
                                attacks.append({
                                    "type": attack_type,
                                    "ip": ip,
                                    "url": url[:100],
                                    "ua": ua[:100],
                                    "status": status
                                })
                                self.iocs.add(ip)
                                break
        
        # Top attacking IPs
        top_ips = ip_requests.most_common(10)
        
        print(f"  [+] Total attacks detected: {len(attacks)}")
        print(f"  [+] Unique attack IPs: {len(set(a['ip'] for a in attacks))}")
        
        return {
            "attacks": attacks[:100],
            "top_ips": top_ips,
            "status_codes": dict(status_codes),
            "attack_ips": list(self.iocs)
        }
    
    def correlate_events(self, time_window: int = 300) -> list:
        """Correlate events across multiple log sources"""
        print("[*] Correlating events...")
        
        incidents = []
        
        # ตัวอย่าง: ตรวจหา brute force ตามด้วย successful login
        # จากนั้นตามด้วย privilege escalation
        
        # Rule: Brute force -> Success within 5 min -> Sudo/Root
        events_by_ip = defaultdict(list)
        for event in self.events:
            if "ip" in event:
                events_by_ip[event["ip"]].append(event)
        
        for ip, ip_events in events_by_ip.items():
            has_brute = any(e.get("type") == "failed_login" for e in ip_events)
            has_success = any(e.get("type") == "success_login" for e in ip_events)
            has_priv_esc = any(e.get("type") == "sudo" for e in ip_events)
            
            if has_brute and has_success:
                severity = "HIGH" if has_priv_esc else "MEDIUM"
                incidents.append({
                    "ip": ip,
                    "type": "Brute Force -> Successful Login" + (" -> Privilege Escalation" if has_priv_esc else ""),
                    "severity": severity,
                    "event_count": len(ip_events)
                })
        
        return incidents
    
    def generate_ioc_list(self) -> dict:
        """สร้างรายการ IOCs จากการวิเคราะห์"""
        return {
            "ips": list(self.iocs),
            "domains": [],
            "hashes": [],
            "urls": [],
            "generated": datetime.now().isoformat()
        }


# ELK Stack queries for SIEM
ELK_QUERIES = """
# Kibana KQL queries for IR

# ค้นหา failed logins
event.action:"authentication_failure" AND source.ip:* 

# Brute force detection (> 5 failures in 5 min)
event.action:"authentication_failure" AND source.ip:* | stats count by source.ip | where count > 5

# PowerShell execution
process.name:("powershell.exe" OR "pwsh.exe") AND command_line:*

# Lateral movement
event.action:("network_connection" OR "process_creation") AND 
  destination.port:(445 OR 135 OR 5985 OR 5986 OR 3389)

# Data exfiltration
network.bytes_out > 10000000 AND NOT destination.ip:10.0.0.0/8

# Scheduled task creation
event.action:"scheduled_task_created"

# New service installation
event.action:"service_installed"

# Suspicious registry modifications
registry.path:("*\\CurrentVersion\\Run*" OR "*\\Winlogon*" OR "*\\Image File Execution*")

# Elasticsearch/Kibana index pattern: filebeat-*
# Time range: Last 24 hours
"""

if __name__ == "__main__":
    analyzer = LogAnalyzer()
    
    # วิเคราะห์ auth log
    if Path("/var/log/auth.log").exists():
        auth_results = analyzer.parse_auth_log()
        print(json.dumps(auth_results, indent=2))
```

## Step 356: Incident Response Procedures

ขั้นตอนการตอบสนองต่อ incident อย่างเป็นระบบ

```python
#!/usr/bin/env python3
# incident_response.py - IR Procedures & Playbooks

import json
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional

class Severity(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFORMATIONAL = 5

class IncidentStatus(Enum):
    NEW = "New"
    TRIAGE = "Triage"
    CONTAINMENT = "Containment"
    ERADICATION = "Eradication"
    RECOVERY = "Recovery"
    LESSONS_LEARNED = "Lessons Learned"
    CLOSED = "Closed"

@dataclass
class Incident:
    id: str
    title: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.NEW
    detected_time: str = field(default_factory=lambda: datetime.now().isoformat())
    assigned_to: str = ""
    affected_systems: List[str] = field(default_factory=list)
    iocs: List[dict] = field(default_factory=list)
    timeline: List[dict] = field(default_factory=list)
    actions_taken: List[str] = field(default_factory=list)
    description: str = ""
    
    def add_timeline_entry(self, time: str, event: str, actor: str = "Analyst"):
        self.timeline.append({
            "time": time,
            "event": event,
            "actor": actor
        })
    
    def add_ioc(self, ioc_type: str, value: str, description: str = ""):
        self.iocs.append({
            "type": ioc_type,
            "value": value,
            "description": description,
            "added": datetime.now().isoformat()
        })
    
    def to_report(self) -> str:
        return json.dumps({
            "id": self.id,
            "title": self.title,
            "severity": self.severity.name,
            "status": self.status.value,
            "detected": self.detected_time,
            "affected_systems": self.affected_systems,
            "iocs": self.iocs,
            "timeline": self.timeline,
            "actions": self.actions_taken
        }, indent=2)


class IRPlaybook:
    """Incident Response Playbooks"""
    
    @staticmethod
    def ransomware_playbook() -> dict:
        return {
            "name": "Ransomware Incident Response",
            "phases": {
                "1_detection": [
                    "ตรวจสอบ alerts จาก EDR/AV/SIEM",
                    "ยืนยัน ransomware activity (ไฟล์ถูกเข้ารหัส, ransom note)",
                    "ระบุ affected systems ทั้งหมด",
                    "ตรวจสอบ backup status",
                    "บันทึก initial indicators"
                ],
                "2_containment": [
                    "DISCONNECT affected systems จาก network ทันที",
                    "Isolate network segments ที่ถูก affect",
                    "Block malicious IPs/domains ที่ firewall",
                    "Disable compromised accounts",
                    "ป้องกัน lateral movement ด้วย network segmentation",
                    "Preserve forensic evidence ก่อน action ใดๆ"
                ],
                "3_eradication": [
                    "ระบุ patient zero และ infection vector",
                    "ค้นหา malware samples ทั้งหมด",
                    "ลบ malicious files, registry keys, scheduled tasks",
                    "ปิด backdoors และ persistence mechanisms",
                    "Patch exploited vulnerabilities"
                ],
                "4_recovery": [
                    "Restore จาก clean backups ที่ verified",
                    "ติดตั้ง OS ใหม่ถ้าจำเป็น",
                    "Reset passwords ทุก account",
                    "Monitor systems อย่างใกล้ชิดหลัง restore",
                    "ทดสอบ systems ก่อน put back in production"
                ],
                "5_lessons_learned": [
                    "สร้าง incident timeline",
                    "ระบุ root cause",
                    "Document lessons learned",
                    "Update security controls",
                    "Update IR procedures",
                    "Train staff ตาม findings"
                ]
            },
            "key_iocs": [
                "Ransom note filename/content",
                "Encrypted file extensions",
                "C2 IP addresses/domains",
                "Malware hashes",
                "Registry keys for persistence"
            ],
            "tools": ["ID Ransomware", "No More Ransom", "Endpoint forensics", "Network monitoring"]
        }
    
    @staticmethod
    def phishing_playbook() -> dict:
        return {
            "name": "Phishing Email Incident Response",
            "phases": {
                "1_identification": [
                    "รับ report จาก user",
                    "วิเคราะห์ email headers (Return-Path, X-Originating-IP)",
                    "ตรวจสอบ email ทุกคนที่ได้รับ email เดียวกัน",
                    "Analyze attachments/links อย่างปลอดภัย (sandbox)",
                    "ตรวจสอบว่ามี users คลิก links หรือเปิด attachments"
                ],
                "2_analysis": [
                    "ดึง attachments ไป sandbox (Any.run, Cuckoo)",
                    "วิเคราะห์ phishing URLs",
                    "ค้นหา credential harvesting infrastructure",
                    "ตรวจสอบ email gateway logs",
                    "ค้นหา similar emails ที่อาจส่งถึงคนอื่น"
                ],
                "3_containment": [
                    "Block phishing URLs ที่ web proxy/firewall",
                    "Quarantine phishing emails ที่ยังไม่ได้เปิด",
                    "Reset passwords ของ users ที่อาจ compromised",
                    "Enable MFA ถ้ายังไม่ได้เปิด",
                    "Block sender domains/IPs"
                ],
                "4_notification": [
                    "แจ้ง affected users",
                    "ส่ง awareness reminder ถึงทุกคน",
                    "รายงาน phishing site ไปยัง relevant parties",
                    "Update phishing filter signatures"
                ]
            }
        }
    
    @staticmethod
    def data_breach_playbook() -> dict:
        return {
            "name": "Data Breach Response",
            "phases": {
                "1_detection_verification": [
                    "ยืนยัน data breach ด้วย evidence",
                    "ระบุ scope - ข้อมูลอะไร ปริมาณเท่าไหร่",
                    "ระบุ affected individuals",
                    "ตรวจสอบ access logs และ audit trails"
                ],
                "2_legal_compliance": [
                    "แจ้ง Legal team และ DPO ทันที",
                    "ประเมิน PDPA/GDPR notification requirements",
                    "บันทึกทุก actions ด้วยเหตุผล (legal documentation)",
                    "เตรียม breach notification (ภายใน 72 ชั่วโมง สำหรับ GDPR)"
                ],
                "3_technical_response": [
                    "Containment - หยุดการ exfiltration",
                    "Preserve evidence (logs, forensic images)",
                    "ระบุ attack vector และ close it",
                    "Review access controls"
                ],
                "4_notification": [
                    "แจ้ง affected individuals",
                    "แจ้ง regulatory authorities (ตามกฎหมาย)",
                    "เตรียม FAQ สำหรับ affected parties",
                    "จัดตั้ง call center ถ้าจำเป็น"
                ]
            },
            "legal_requirements": {
                "GDPR": "72 hours to notify DPA, without undue delay for individuals",
                "PDPA_TH": "72 hours to notify PDPC for high-risk breaches"
            }
        }


# IR Communication Templates
IR_TEMPLATES = {
    "initial_notification": """
SUBJECT: [CONFIDENTIAL] Security Incident Notification - {incident_id}

Dear {recipient},

This is to notify you of a security incident that has been detected in our environment.

Incident ID: {incident_id}
Detected: {detection_time}
Severity: {severity}
Status: Under Investigation

Affected Systems: {affected_systems}

Immediate Actions Required:
{immediate_actions}

Our IR team is actively investigating. We will provide updates every {update_frequency}.

IR Team
""",
    "status_update": """
SUBJECT: [UPDATE] Security Incident {incident_id} - Status Update {update_num}

Current Status: {current_status}
Last Update: {last_update}

Progress Summary:
{progress_summary}

Next Steps:
{next_steps}

Estimated Resolution: {eta}
""",
    "closure_report": """
SUBJECT: Security Incident {incident_id} - Closed

The security incident has been resolved.

Root Cause: {root_cause}
Resolution: {resolution}
Prevention Measures: {prevention}

Detailed report available upon request.
"""
}


if __name__ == "__main__":
    # สร้าง incident
    incident = Incident(
        id="IR-2024-001",
        title="Ransomware Attack on File Server",
        severity=Severity.CRITICAL,
        affected_systems=["FS01", "FS02", "BACKUP01"]
    )
    
    incident.add_timeline_entry(
        "2024-01-15 08:30",
        "EDR alert triggered - suspicious file encryption activity on FS01"
    )
    incident.add_timeline_entry(
        "2024-01-15 08:45",
        "IR team notified, initial assessment started"
    )
    incident.add_ioc("hash", "d41d8cd98f00b204e9800998ecf8427e", "Ransomware executable")
    incident.add_ioc("ip", "185.220.101.5", "C2 server")
    
    print(incident.to_report())
    
    playbook = IRPlaybook.ransomware_playbook()
    print(json.dumps(playbook, indent=2, ensure_ascii=False))
```

## Step 357: Malware Analysis ใน Forensics Context

การวิเคราะห์ malware ในบริบท incident response

```bash
#!/bin/bash
# malware_analysis_ir.sh - Malware Analysis for IR

# ========== Static Analysis ==========

static_analysis() {
    local sample=$1
    local output_dir="/opt/ir/malware_analysis/$(date +%Y%m%d_%H%M%S)"
    mkdir -p $output_dir
    
    echo "[*] Static analysis of: $sample"
    echo "[*] Output dir: $output_dir"
    
    # Basic file info
    echo "=== File Info ===" > $output_dir/analysis.txt
    file $sample >> $output_dir/analysis.txt
    ls -la $sample >> $output_dir/analysis.txt
    
    # Hash values
    echo "\n=== File Hashes ===" >> $output_dir/analysis.txt
    md5sum $sample >> $output_dir/analysis.txt
    sha1sum $sample >> $output_dir/analysis.txt
    sha256sum $sample >> $output_dir/analysis.txt
    
    # ค้นหาใน VirusTotal
    local sha256=$(sha256sum $sample | cut -d' ' -f1)
    echo "[*] Check hash in VirusTotal: https://www.virustotal.com/gui/file/$sha256"
    
    # Strings extraction
    echo "\n=== Interesting Strings ===" >> $output_dir/analysis.txt
    strings -n 8 $sample | grep -E '(http|ftp|smtp|cmd|powershell|CreateRemoteThread|VirtualAlloc|LoadLibrary|GetProcAddress|RegOpenKey|CreateService)' >> $output_dir/analysis.txt
    
    # PE analysis (Windows executables)
    if file $sample | grep -q "PE32"; then
        echo "\n=== PE Analysis ===" >> $output_dir/analysis.txt
        
        # Sections
        objdump -h $sample 2>/dev/null >> $output_dir/analysis.txt
        
        # Imports
        if command -v pefile > /dev/null 2>&1; then
            python3 -c "
import pefile
pe = pefile.PE('$sample')
print('--- Imports ---')
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f'DLL: {entry.dll.decode()}')
        for imp in entry.imports:
            if imp.name:
                print(f'  {imp.name.decode()}')
" >> $output_dir/analysis.txt 2>/dev/null
        fi
        
        # Entropy (packed = high entropy)
        python3 -c "
import math, sys
with open('$sample', 'rb') as f:
    data = f.read()
byte_counts = [data.count(bytes([i])) for i in range(256)]
total = len(data)
entropy = -sum((c/total) * math.log2(c/total) for c in byte_counts if c > 0)
print(f'File entropy: {entropy:.4f}')
if entropy > 7.0:
    print('WARNING: High entropy - possibly packed/encrypted')
"
    fi
    
    echo "[+] Static analysis complete: $output_dir/analysis.txt"
}

# ========== Dynamic Analysis ==========

dynamic_analysis_setup() {
    echo "[*] Setting up dynamic analysis environment..."
    
    # Cuckoo Sandbox
    echo "Option 1: Cuckoo Sandbox"
    echo "  cuckoo submit /path/to/malware.exe"
    echo "  cuckoo web runserver"
    echo "  Access: http://localhost:8000"
    
    # Any.run (online)
    echo "Option 2: Any.run"
    echo "  https://any.run - Online sandbox"
    
    # FlareVM + FakeNet
    echo "Option 3: FlareVM"
    echo "  fakenet-ng - Network simulation"
    echo "  procmon - Process monitoring"
    echo "  regshot - Registry snapshot"
    echo "  wireshark - Network capture"
}

monitor_malware_execution() {
    local sample=$1
    local output_dir="/opt/ir/dynamic_$(date +%Y%m%d_%H%M%S)"
    mkdir -p $output_dir
    
    # Linux dynamic analysis
    echo "[*] Starting dynamic analysis monitoring..."
    
    # Start network capture
    tcpdump -i any -w $output_dir/network.pcap &
    TCPDUMP_PID=$!
    
    # Monitor file system changes
    inotifywait -m -r /tmp /var/tmp /home --format '%T %w%f %e' \
        --timefmt '%Y-%m-%d %H:%M:%S' \
        > $output_dir/fs_changes.log &
    INOTIFY_PID=$!
    
    # Monitor processes
    (while true; do ps aux >> $output_dir/processes.log; sleep 1; done) &
    PS_PID=$!
    
    # Monitor network connections  
    (while true; do netstat -antup 2>/dev/null >> $output_dir/netstat.log; sleep 2; done) &
    NET_PID=$!
    
    echo "[*] Monitoring started. Execute sample now."
    echo "[*] Press ENTER when analysis complete..."
    read
    
    # Stop monitoring
    kill $TCPDUMP_PID $INOTIFY_PID $PS_PID $NET_PID 2>/dev/null
    
    echo "[+] Dynamic analysis complete"
    echo "[+] Results in: $output_dir"
    ls -la $output_dir
}

# ========== YARA Rules ==========

create_yara_rules() {
    cat > /tmp/incident_iocs.yar << 'YARA_EOF'
rule Ransomware_Generic {
    meta:
        description = "Generic ransomware indicators"
        author = "IR Team"
        date = "2024-01-01"
    strings:
        $ransom_note1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii nocase
        $ransom_note2 = "bitcoin" ascii nocase
        $ransom_note3 = "tor2web" ascii nocase
        $encrypt_func1 = "CryptEncrypt" ascii
        $encrypt_func2 = "BCryptEncrypt" ascii
        $file_rename = ".encrypted" ascii nocase
    condition:
        2 of ($ransom_note*) or 2 of ($encrypt_func*) or $file_rename
}

rule Malware_Network_C2 {
    meta:
        description = "Potential C2 communication"
    strings:
        $ua1 = "Mozilla/5.0 (Windows NT" ascii
        $base64 = /[A-Za-z0-9+\/]{50,}={0,2}/ ascii
        $c2_func = "InternetConnect" ascii
        $c2_func2 = "HttpSendRequest" ascii
    condition:
        $c2_func or $c2_func2 and $ua1
}

rule Injector_Generic {
    meta:
        description = "Process injection techniques"
    strings:
        $inject1 = "VirtualAllocEx" ascii
        $inject2 = "WriteProcessMemory" ascii
        $inject3 = "CreateRemoteThread" ascii
        $inject4 = "NtCreateThreadEx" ascii
        $inject5 = "QueueUserAPC" ascii
    condition:
        3 of them
}
YARA_EOF
    
    echo "[+] YARA rules created: /tmp/incident_iocs.yar"
    
    # สแกนด้วย YARA
    # yara -r /tmp/incident_iocs.yar /path/to/scan/
}

# ========== Threat Intel Lookup ==========

lookup_ioc() {
    local ioc=$1
    local api_key=${VT_API_KEY:-"your_vt_api_key"}
    
    echo "[*] Looking up IOC: $ioc"
    
    # VirusTotal lookup
    if [[ $ioc =~ ^[0-9a-f]{64}$ ]]; then
        # SHA256 hash
        curl -s "https://www.virustotal.com/api/v3/files/$ioc" \
            -H "x-apikey: $api_key" | python3 -m json.tool
    elif [[ $ioc =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        # IP address
        curl -s "https://www.virustotal.com/api/v3/ip_addresses/$ioc" \
            -H "x-apikey: $api_key" | python3 -m json.tool
    else
        # Domain
        curl -s "https://www.virustotal.com/api/v3/domains/$ioc" \
            -H "x-apikey: $api_key" | python3 -m json.tool
    fi
}

# Main
echo "=== IR Malware Analysis Toolkit ==="
echo "1. Static analysis: static_analysis <sample>"
echo "2. Dynamic monitoring: monitor_malware_execution <sample>"
echo "3. Create YARA rules: create_yara_rules"
echo "4. IOC lookup: lookup_ioc <hash|ip|domain>"
```

## Step 358: Timeline Analysis & Reconstruction

การสร้าง timeline ของเหตุการณ์เพื่อทำความเข้าใจ attack chain

```python
#!/usr/bin/env python3
# timeline_analysis.py - Forensic Timeline Reconstruction

from datetime import datetime
import csv
import json
from collections import defaultdict
from pathlib import Path

class ForensicTimeline:
    def __init__(self):
        self.events = []
        self.incident_start = None
        self.incident_end = None
        
    def add_event(self, timestamp: str, source: str, event_type: str, 
                  description: str, host: str = "", user: str = "",
                  ioc: bool = False, mitre: str = ""):
        """เพิ่ม event เข้า timeline"""
        event = {
            "timestamp": timestamp,
            "source": source,
            "type": event_type,
            "description": description,
            "host": host,
            "user": user,
            "ioc": ioc,
            "mitre": mitre
        }
        self.events.append(event)
        self.events.sort(key=lambda x: x["timestamp"])
        
    def import_from_csv(self, csv_file: str, 
                        time_col: str = "datetime",
                        desc_col: str = "desc",
                        source_col: str = "source"):
        """นำเข้า events จาก CSV (เช่น Plaso output)"""
        with open(csv_file, newline='', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if time_col in row:
                    self.add_event(
                        timestamp=row.get(time_col, ""),
                        source=row.get(source_col, "Unknown"),
                        event_type=row.get("type", "Unknown"),
                        description=row.get(desc_col, "")
                    )
        print(f"[+] Imported {len(self.events)} events from {csv_file}")
    
    def filter_by_host(self, hostname: str) -> list:
        return [e for e in self.events if hostname.lower() in e["host"].lower()]
    
    def filter_by_timerange(self, start: str, end: str) -> list:
        return [e for e in self.events if start <= e["timestamp"] <= end]
    
    def filter_iocs_only(self) -> list:
        return [e for e in self.events if e["ioc"]]
    
    def get_mitre_coverage(self) -> dict:
        """สรุป MITRE ATT&CK tactics observed"""
        mitre_map = defaultdict(list)
        for event in self.events:
            if event.get("mitre"):
                tactic = event["mitre"].split(".")[0] if "." in event["mitre"] else event["mitre"]
                mitre_map[tactic].append(event["description"])
        return dict(mitre_map)
    
    def generate_attack_narrative(self) -> str:
        """สร้าง attack narrative จาก timeline"""
        if not self.events:
            return "No events found"
        
        narrative = f"""# Attack Timeline Narrative

**Total Events:** {len(self.events)}
**Time Range:** {self.events[0]['timestamp']} to {self.events[-1]['timestamp']}

## Phase Analysis

"""
        # จัดกลุ่ม events ตาม MITRE phase
        phases = {
            "Initial Access": [],
            "Execution": [],
            "Persistence": [],
            "Privilege Escalation": [],
            "Defense Evasion": [],
            "Credential Access": [],
            "Discovery": [],
            "Lateral Movement": [],
            "Collection": [],
            "Command & Control": [],
            "Exfiltration": [],
            "Impact": []
        }
        
        for event in self.events:
            for phase in phases:
                if phase.lower() in event.get("type", "").lower() or \
                   phase.lower() in event.get("mitre", "").lower():
                    phases[phase].append(event)
                    break
        
        for phase, events in phases.items():
            if events:
                narrative += f"### {phase}\n"
                for e in events[:5]:  # แสดงแค่ 5 events ต่อ phase
                    narrative += f"- **[{e['timestamp']}]** {e['description']}\n"
                narrative += "\n"
        
        return narrative
    
    def export_to_html(self, output_file: str):
        """Export timeline เป็น HTML interactive visualization"""
        events_json = json.dumps(self.events, indent=2)
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Forensic Timeline</title>
    <style>
        body {{ font-family: Arial; margin: 20px; }}
        .event {{ border-left: 4px solid #007bff; padding: 10px; margin: 10px 0; }}
        .ioc {{ border-left-color: #dc3545; background: #fff3f3; }}
        .timestamp {{ color: #666; font-size: 0.9em; }}
        .source {{ color: #28a745; font-weight: bold; }}
    </style>
</head>
<body>
<h1>Forensic Timeline</h1>
<p>Total events: {len(self.events)}</p>
<div id="timeline">
"""
        for event in self.events:
            css_class = "event ioc" if event.get("ioc") else "event"
            html += f"""
<div class="{css_class}">
    <div class="timestamp">{event['timestamp']}</div>
    <div class="source">[{event['source']}] {event['type']}</div>
    <div>{event['description']}</div>
    {f'<div style="color:red">MITRE: {event["mitre"]}</div>' if event.get('mitre') else ''}
    {f'<div style="color:red">Host: {event["host"]}</div>' if event.get('host') else ''}
</div>"""
        
        html += """</div></body></html>"""
        
        with open(output_file, 'w') as f:
            f.write(html)
        print(f"[+] Timeline exported to {output_file}")
    
    def generate_executive_report(self) -> str:
        mitre_coverage = self.get_mitre_coverage()
        ioc_events = self.filter_iocs_only()
        
        return f"""# Executive Summary - Incident Timeline Analysis

## Overview
- **Total Evidence Items:** {len(self.events)}
- **Timeline:** {self.events[0]['timestamp'] if self.events else 'N/A'} to {self.events[-1]['timestamp'] if self.events else 'N/A'}
- **IOC Count:** {len(ioc_events)}

## Attack Phases Observed
{chr(10).join(f'- {phase}: {len(events)} events' for phase, events in mitre_coverage.items())}

## Key Indicators of Compromise
{chr(10).join(f'- {e["description"]}' for e in ioc_events[:10])}

## Recommendations
1. Implement network segmentation
2. Enable advanced endpoint detection
3. Review and restrict privileged access
4. Implement log centralization
5. Conduct security awareness training
"""


if __name__ == "__main__":
    timeline = ForensicTimeline()
    
    # เพิ่ม sample events
    timeline.add_event("2024-01-15 07:23:14", "Email Gateway", "Initial Access",
                       "Phishing email received: invoice_urgent.exe attached",
                       ioc=True, mitre="T1566.001")
    
    timeline.add_event("2024-01-15 08:05:33", "EDR", "Execution",
                       "invoice_urgent.exe executed on WORKSTATION-01",
                       host="WORKSTATION-01", user="john.doe",
                       ioc=True, mitre="T1204.002")
    
    timeline.add_event("2024-01-15 08:05:45", "EDR", "Defense Evasion",
                       "PowerShell launched with -EncodedCommand flag",
                       host="WORKSTATION-01", mitre="T1059.001")
    
    timeline.add_event("2024-01-15 08:06:01", "Network", "Command & Control",
                       "HTTPS connection to 185.220.101.5:443 established",
                       host="WORKSTATION-01", ioc=True, mitre="T1071.001")
    
    timeline.add_event("2024-01-15 09:15:22", "AD Logs", "Lateral Movement",
                       "Pass-the-Hash authentication from WORKSTATION-01 to SERVER-01",
                       host="SERVER-01", ioc=True, mitre="T1550.002")
    
    timeline.add_event("2024-01-15 09:45:00", "DLP", "Exfiltration",
                       "Large file transfer (2.3GB) to external IP 185.220.101.5",
                       ioc=True, mitre="T1041")
    
    print(timeline.generate_attack_narrative())
    timeline.export_to_html("/tmp/forensic_timeline.html")
    print(timeline.generate_executive_report())
```

## Step 359: Forensic Report Writing

การเขียนรายงาน forensics อย่างมืออาชีพ

```python
#!/usr/bin/env python3
# forensic_report.py - Professional Forensics Report Generator

from datetime import datetime
import json
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class ForensicFinding:
    id: str
    title: str
    severity: str  # Critical, High, Medium, Low
    category: str
    description: str
    evidence: List[str] = field(default_factory=list)
    recommendation: str = ""
    mitre_technique: str = ""
    cvss_score: float = 0.0


class ForensicReportGenerator:
    def __init__(self, case_id: str, examiner: str, organization: str):
        self.case_id = case_id
        self.examiner = examiner
        self.organization = organization
        self.findings = []
        self.evidence_items = []
        self.timeline_summary = []
        self.case_summary = ""
        
    def add_finding(self, finding: ForensicFinding):
        self.findings.append(finding)
        
    def add_evidence(self, evidence_id: str, description: str, 
                     hash_sha256: str, acquisition_date: str):
        self.evidence_items.append({
            "id": evidence_id,
            "description": description,
            "sha256": hash_sha256,
            "acquired": acquisition_date
        })
    
    def generate_full_report(self) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Count by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in self.findings:
            if f.severity in severity_counts:
                severity_counts[f.severity] += 1
        
        report = f"""# DIGITAL FORENSICS EXAMINATION REPORT

---

## Report Information

| Field | Value |
|-------|-------|
| **Case Number** | {self.case_id} |
| **Report Date** | {now} |
| **Prepared By** | {self.examiner} |
| **Organization** | {self.organization} |
| **Classification** | CONFIDENTIAL |

---

## Executive Summary

{self.case_summary}

### Finding Summary

| Severity | Count |
|----------|-------|
| Critical | {severity_counts['Critical']} |
| High | {severity_counts['High']} |
| Medium | {severity_counts['Medium']} |
| Low | {severity_counts['Low']} |
| **Total** | **{len(self.findings)}** |

---

## Evidence Examined

| ID | Description | SHA-256 | Acquired |
|----|-------------|---------|----------|
"""
        for ev in self.evidence_items:
            report += f"| {ev['id']} | {ev['description']} | `{ev['sha256'][:16]}...` | {ev['acquired']} |\n"
        
        report += f"""
---

## Methodology

การตรวจสอบนี้ดำเนินการตาม:
- NIST SP 800-86: Guide to Integrating Forensic Techniques into IR
- ACPO Good Practice Guide for Digital Evidence
- ISO/IEC 27037: Guidelines for identification, collection, acquisition and preservation

ขั้นตอน:
1. **Identification** - ระบุ evidence ที่เกี่ยวข้อง
2. **Collection & Preservation** - เก็บ evidence ตาม forensic best practices
3. **Examination** - ตรวจสอบ evidence ด้วย forensic tools
4. **Analysis** - วิเคราะห์และตีความข้อมูลที่พบ
5. **Reporting** - สรุปผลและข้อเสนอแนะ

---

## Detailed Findings

"""
        
        for i, finding in enumerate(self.findings, 1):
            severity_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
            emoji = severity_emoji.get(finding.severity, "⚪")
            
            report += f"""
### {i}. {finding.title}

**Severity:** {emoji} {finding.severity}
**Category:** {finding.category}
**MITRE ATT&CK:** {finding.mitre_technique or 'N/A'}
**CVSS Score:** {finding.cvss_score or 'N/A'}

#### Description
{finding.description}

#### Supporting Evidence
"""
            for ev in finding.evidence:
                report += f"- {ev}\n"
            
            report += f"""
#### Recommendation
{finding.recommendation}

---
"""
        
        report += f"""

## Timeline of Events

"""
        for event in self.timeline_summary:
            report += f"- **{event.get('time', 'N/A')}**: {event.get('description', '')}\n"
        
        report += f"""

## Conclusions

จากการตรวจสอบพบว่า:

1. ระบบถูก compromise ผ่าน [Initial Access Vector]
2. Attacker ดำเนินการ [Key Actions]
3. มีการ exfiltrate ข้อมูล [Data Type] จำนวน [Amount]

## Recommendations

### Immediate Actions (0-7 days)
1. Reset all privileged account passwords
2. Revoke and reissue all certificates
3. Implement emergency firewall rules
4. Enable additional monitoring

### Short-term (1-30 days)
1. Patch all identified vulnerabilities
2. Implement MFA for all accounts
3. Review and update security policies
4. Conduct security awareness training

### Long-term (30-90 days)
1. Implement Zero Trust architecture
2. Deploy EDR solution enterprise-wide
3. Establish SOC capabilities
4. Regular red team exercises

---

## Appendices

### Appendix A: IOC List
[IOC table]

### Appendix B: Tool Output
[Raw tool output]

### Appendix C: Hash Values
[Evidence hashes]

---

*Report prepared by {self.examiner} on {now}*
*This report contains confidential information*
"""
        return report


if __name__ == "__main__":
    report_gen = ForensicReportGenerator(
        case_id="CASE-2024-001",
        examiner="Forensic Analyst",
        organization="Company Security Team"
    )
    
    report_gen.case_summary = """
On January 15, 2024, a ransomware incident was detected affecting 15 systems in the Finance department.
Forensic examination revealed the attack originated from a phishing email, leading to credential theft
and subsequent lateral movement. Approximately 50GB of financial data was exfiltrated before
encryption began.
"""
    
    report_gen.add_evidence(
        "EVD-001", "Disk image of WORKSTATION-01",
        "a3f2d8e9b1c4567890abcdef1234567890abcdef1234567890abcdef12345678",
        "2024-01-15 10:30:00"
    )
    
    report_gen.add_finding(ForensicFinding(
        id="F-001",
        title="Ransomware Execution via Phishing Email",
        severity="Critical",
        category="Malware",
        description="Ransomware was delivered via phishing email attachment 'invoice_urgent.exe'.",
        evidence=[
            "Email header shows origin from spoofed domain finance-dept[.]com",
            "EDR logs show invoice_urgent.exe execution at 08:05:33",
            "Memory analysis reveals LockBit 3.0 indicators"
        ],
        recommendation="Implement email attachment sandboxing and block executable attachments.",
        mitre_technique="T1566.001 - Phishing: Spearphishing Attachment",
        cvss_score=9.8
    ))
    
    report_gen.timeline_summary = [
        {"time": "2024-01-15 07:23", "description": "Phishing email received"},
        {"time": "2024-01-15 08:05", "description": "Malware execution"},
        {"time": "2024-01-15 09:15", "description": "Lateral movement to servers"}
    ]
    
    report = report_gen.generate_full_report()
    
    with open("/tmp/forensic_report.md", "w") as f:
        f.write(report)
    print("[+] Report generated: /tmp/forensic_report.md")
    print(report[:2000])
```

## Step 360: Automated IR Toolkit

เครื่องมืออัตโนมัติสำหรับ incident response

```python
#!/usr/bin/env python3
# ir_toolkit.py - Automated Incident Response Toolkit

import os
import sys
import json
import socket
import platform
import subprocess
import hashlib
import datetime
from pathlib import Path
from collections import defaultdict

class IRTriage:
    """Live Response / IR Triage Tool"""
    
    def __init__(self, case_id: str, output_dir: str):
        self.case_id = case_id
        self.output_dir = Path(output_dir) / case_id
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = defaultdict(dict)
        
    def run_command(self, cmd: list) -> str:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout + result.stderr
        except Exception as e:
            return f"Error: {e}"
    
    def collect_system_info(self):
        print("[*] Collecting system information...")
        
        info = {
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "timestamp_utc": datetime.datetime.utcnow().isoformat(),
            "timestamp_local": datetime.datetime.now().isoformat()
        }
        
        # Network info
        try:
            info["ip"] = socket.gethostbyname(socket.gethostname())
        except:
            info["ip"] = "Unable to determine"
        
        self.results["system_info"] = info
        self._save_result("system_info", info)
        print(f"  [+] Hostname: {info['hostname']}, OS: {info['os']}")
    
    def collect_processes(self):
        print("[*] Collecting running processes...")
        
        processes = []
        
        if platform.system() == "Windows":
            output = self.run_command(["tasklist", "/v", "/fo", "csv"])
            for line in output.split("\n")[1:]:
                if line.strip():
                    processes.append(line.strip())
        else:
            output = self.run_command(["ps", "auxww"])
            for line in output.split("\n")[1:]:
                if line.strip():
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        processes.append({
                            "user": parts[0],
                            "pid": parts[1],
                            "cpu": parts[2],
                            "mem": parts[3],
                            "command": parts[10] if len(parts) > 10 else ""
                        })
        
        self.results["processes"] = processes
        self._save_result("processes", processes)
        print(f"  [+] Collected {len(processes)} processes")
    
    def collect_network_connections(self):
        print("[*] Collecting network connections...")
        
        if platform.system() == "Windows":
            output = self.run_command(["netstat", "-ano"])
        else:
            output = self.run_command(["ss", "-tunap"])
        
        self._save_result("network_connections", {"raw": output})
        
        # Parse established connections
        connections = []
        for line in output.split("\n"):
            if "ESTABLISHED" in line or "LISTEN" in line:
                connections.append(line.strip())
        
        print(f"  [+] Found {len(connections)} active connections")
        return connections
    
    def collect_persistence_mechanisms(self):
        print("[*] Checking persistence mechanisms...")
        
        persistence = {}
        
        if platform.system() == "Linux":
            # Crontabs
            cron_paths = ["/etc/cron*", "/var/spool/cron*"]
            persistence["crontabs"] = []
            for path in cron_paths:
                import glob
                for f in glob.glob(path):
                    persistence["crontabs"].append(f)
            
            # Startup scripts
            persistence["startup"] = self.run_command(["ls", "-la", "/etc/init.d/"])
            
            # systemd services
            persistence["systemd"] = self.run_command(["systemctl", "list-units", "--type=service", "--state=enabled"])
            
            # SSH authorized keys
            authorized_keys = []
            for user_dir in Path("/home").iterdir():
                ssh_file = user_dir / ".ssh" / "authorized_keys"
                if ssh_file.exists():
                    authorized_keys.append(str(ssh_file))
            if Path("/root/.ssh/authorized_keys").exists():
                authorized_keys.append("/root/.ssh/authorized_keys")
            persistence["authorized_keys"] = authorized_keys
        
        self.results["persistence"] = persistence
        self._save_result("persistence", persistence)
    
    def collect_user_activity(self):
        print("[*] Collecting user activity...")
        
        activity = {}
        
        if platform.system() == "Linux":
            # Last logins
            activity["last_logins"] = self.run_command(["last", "-20"])
            
            # Failed logins
            activity["failed_logins"] = self.run_command(["lastb", "-20"])
            
            # Currently logged in users
            activity["current_users"] = self.run_command(["w"])
            
            # Shell history
            history_files = []
            for user_dir in list(Path("/home").iterdir()) + [Path("/root")]:
                for hist_file in [".bash_history", ".zsh_history", ".history"]:
                    hist_path = user_dir / hist_file
                    if hist_path.exists():
                        history_files.append(str(hist_path))
            activity["history_files"] = history_files
        
        self.results["user_activity"] = activity
        self._save_result("user_activity", activity)
    
    def hash_critical_files(self):
        print("[*] Hashing critical system files...")
        
        critical_files = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/hosts",
            "/bin/bash", "/bin/sh", "/usr/bin/sudo",
            "/usr/bin/ssh", "/usr/sbin/sshd"
        ]
        
        hashes = {}
        for filepath in critical_files:
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        sha256 = hashlib.sha256(f.read()).hexdigest()
                    hashes[filepath] = sha256
                except PermissionError:
                    hashes[filepath] = "Permission denied"
        
        self.results["file_hashes"] = hashes
        self._save_result("file_hashes", hashes)
        print(f"  [+] Hashed {len(hashes)} files")
    
    def _save_result(self, name: str, data):
        output_file = self.output_dir / f"{name}_{self.timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def run_full_triage(self):
        print(f"\n{'='*60}")
        print(f"IR TRIAGE - Case: {self.case_id}")
        print(f"Start: {datetime.datetime.now().isoformat()}")
        print(f"Output: {self.output_dir}")
        print(f"{'='*60}\n")
        
        self.collect_system_info()
        self.collect_processes()
        self.collect_network_connections()
        self.collect_persistence_mechanisms()
        self.collect_user_activity()
        self.hash_critical_files()
        
        # สร้าง summary
        summary = {
            "case_id": self.case_id,
            "triage_time": datetime.datetime.now().isoformat(),
            "hostname": self.results.get("system_info", {}).get("hostname", "Unknown"),
            "process_count": len(self.results.get("processes", [])),
            "output_directory": str(self.output_dir)
        }
        
        self._save_result("summary", summary)
        
        print(f"\n{'='*60}")
        print(f"[+] Triage complete! Results saved to: {self.output_dir}")
        print(f"[+] Files collected:")
        for f in self.output_dir.iterdir():
            print(f"    {f.name}")
        print(f"{'='*60}\n")
        
        return summary


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='IR Triage Tool')
    parser.add_argument('--case', required=True, help='Case ID')
    parser.add_argument('--output', default='/tmp/ir_triage', help='Output directory')
    args = parser.parse_args()
    
    triage = IRTriage(args.case, args.output)
    summary = triage.run_full_triage()
    print(json.dumps(summary, indent=2))
```

---
*Part 36 ครอบคลุม Steps 351-360: Digital Forensics & Incident Response รวมถึง disk forensics, memory analysis ด้วย Volatility, filesystem artifacts, network forensics, log analysis, IR procedures, malware analysis, timeline reconstruction, forensic reporting และ automated IR triage toolkit*
