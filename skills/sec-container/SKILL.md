---
name: sec-container
description: >
  Container and Kubernetes security analysis skill. Analyzes Docker images,
  Dockerfiles, container configs, and K8s manifests for vulnerabilities,
  misconfigurations, and runtime risks. Trigger on /sec container, or when
  user shares Dockerfile, docker-compose.yml, K8s deployment YAML, asks
  scan this image, is my container secure, container hardening, K8s security,
  Trivy scan, pod security, or shares container image names.
---

# sec-container — Container and Kubernetes Security

Containers are not a security boundary. Treat them like the thin wrapper they are.

---

## Phase 1: Dockerfile Security Analysis

Insecure Dockerfile patterns:
```dockerfile
FROM ubuntu:latest     # Mutable tag — supply chain risk
RUN apt-get install -y curl wget  # Attack tools
COPY . /app            # Copies .git, .env, secrets
ENV DB_PASSWORD=secret123         # Secret baked into image layer
USER root              # Explicit root
EXPOSE 22              # SSH in container

# SECURE baseline:
FROM ubuntu:22.04@sha256:<digest>
RUN apt-get install -y --no-install-recommends <minimal>
COPY src/ /app/src/
USER 1000:1000
EXPOSE 8080
```

Dockerfile checklist:
- [ ] FROM latest or mutable tag — use digest pinning
- [ ] USER root or no USER directive (defaults to root)
- [ ] ENV containing secrets, passwords, API keys
- [ ] COPY . /app — copies entire context including .env, .git
- [ ] RUN curl | bash or wget | sh — arbitrary code execution
- [ ] Build args with secrets (visible in docker history)
- [ ] EXPOSE 22 — SSH in container
- [ ] ADD with remote URL — bypasses build cache

---

## Phase 2: Image Vulnerability Scanning

```bash
# Scan image for CVEs
trivy image --severity HIGH,CRITICAL <image-name>

# Scan Dockerfile
trivy config Dockerfile

# Full scan with JSON output
trivy image --format json --output scan.json \
  --severity HIGH,CRITICAL <image-name>
```

CVE triage — not all CVEs matter equally:
- Is the vulnerable package actually called? (reachability)
- Does CVE require local access? (most container CVEs do)
- Is there a fix available?
- Does runtime have compensating controls? (seccomp, AppArmor)

| Severity | SLA | Action |
|----------|-----|--------|
| Critical | Now | Block deployment, patch immediately |
| High | 7 days | Schedule this sprint |
| Medium | 30 days | Add to backlog |
| Low | 90 days | Track, fix when convenient |

---

## Phase 3: Docker Compose Runtime Checks

```yaml
# CRITICAL: Privileged container — full host access
services:
  app:
    privileged: true

    # CRITICAL: Docker socket = container escape to host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

    # CRITICAL: Host network bypasses container isolation
    network_mode: host

# SECURE baseline:
    security_opt:
      - no-new-privileges:true
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    user: "1000:1000"
```

Runtime checklist:
- [ ] privileged:true — container escape to host
- [ ] Docker socket mounted — full Docker daemon access
- [ ] network_mode:host — bypass network isolation
- [ ] pid:host — see and signal host processes
- [ ] Sensitive host paths mounted (/etc, /proc, /sys, /)
- [ ] SYS_ADMIN, SYS_PTRACE, NET_ADMIN capabilities added
- [ ] no-new-privileges not set
- [ ] No seccomp profile
- [ ] Writable root filesystem
- [ ] No resource limits (CPU/memory)

---

## Phase 4: Kubernetes Pod Security

```yaml
# CRITICAL: Missing or insecure security context
securityContext:
  privileged: true         # Container escape
  runAsUser: 0             # Root in container
  allowPrivilegeEscalation: true

# SECURE:
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

K8s checklist:
- [ ] privileged:true — node escape
- [ ] runAsUser:0 or no runAsNonRoot:true
- [ ] allowPrivilegeEscalation:true or missing
- [ ] hostPID / hostIPC / hostNetwork enabled
- [ ] docker.sock mounted as hostPath
- [ ] No resource limits — DoS vector
- [ ] Secrets in environment variables (use secretKeyRef)
- [ ] No NetworkPolicy — all pod-to-pod traffic allowed
- [ ] ServiceAccount automountServiceAccountToken:true when not needed
- [ ] Cluster-admin RBAC wildcard permissions
- [ ] latest image tag in production

---

## Severity Ratings

| Finding | Severity |
|---------|----------|
| Privileged container | Critical |
| Docker socket mounted | Critical |
| Critical CVE in base image | Critical |
| Running as root + writable FS | Critical |
| host network/PID/IPC mode | High |
| Sensitive host path mounted | High |
| SYS_ADMIN capability | High |
| No seccomp/AppArmor profile | High |
| High CVE in base image | High |
| latest tag in production | Medium |
| No resource limits | Medium |
| Secret in ENV var | High |
| No NetworkPolicy | Medium |

---

## Output

Write to CONTAINER-SECURITY-REPORT.md. Terminal summary:
```
[sec-container] Container Security Analysis
Images analyzed:    XX
CVEs found:         XX (Critical: X | High: X)
Config findings:    XX (Critical: X | High: X | Medium: X)
CRITICAL: Privileged container in deployment/api
CRITICAL: Docker socket mounted in docker-compose.yml
HIGH: 3 CVEs in node:18 base image (fix: node:20-alpine)
Full report: CONTAINER-SECURITY-REPORT.md
```

## File Structure
```
sec-container/
├── SKILL.md
├── references/
│   ├── dockerfile-hardening.md
│   ├── k8s-security-context.md
│   ├── cve-severity-guide.md
│   └── runtime-defense.md
└── scripts/
    ├── dockerfile_audit.py
    └── k8s_sec_context_check.py
```
