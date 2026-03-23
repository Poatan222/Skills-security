---
name: sec-iac
description: >
  IaC security review skill. Analyzes Terraform, CloudFormation, Pulumi,
  Bicep, and Kubernetes YAML for misconfigurations, privilege escalation,
  insecure defaults, and compliance violations. Trigger on /sec iac, or
  when user shares .tf, .tfvars, template.yaml, cloudformation.json,
  deployment.yaml, values.yaml, or asks to review Terraform, check K8s
  config, IaC security review, cloud misconfiguration.
---

# sec-iac — Infrastructure-as-Code Security Review

Review IaC before it becomes a cloud incident. Catch misconfigs at commit time.

---

## Supported Formats

| Format | File Patterns | Provider |
|--------|--------------|----------|
| Terraform | *.tf, *.tfvars | AWS, Azure, GCP |
| CloudFormation | template.yaml, *-stack.yaml | AWS |
| Kubernetes | deployment.yaml, *.yaml with apiVersion: | K8s |
| Helm | values.yaml, templates/*.yaml | K8s |
| Bicep | *.bicep | Azure |

---

## Step 1: Identify Format and Scope

1. Detect format from file extension and content structure
2. Map all resources: IAM, security groups, storage, compute, databases, networking
3. Build resource dependency graph — understand what talks to what
4. Identify provider and regions

---

## Step 2: AWS IAM Checks (Highest Priority)

Wildcard permissions — CRITICAL finding:
```hcl
resource "aws_iam_policy" "bad" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"       # Flag: wildcard action
      Resource = "*"       # Flag: wildcard resource
    }]
  })
}
```

IAM checklist:
- [ ] Wildcard Action:"*" or Resource:"*" in policies
- [ ] AdministratorAccess attached to non-break-glass roles
- [ ] IAM users with programmatic access (prefer roles)
- [ ] Roles with no trust policy conditions (anyone can assume)
- [ ] Password policy: min length, complexity, rotation enforced
- [ ] MFA not required for console access
- [ ] Inline policies (prefer managed for auditability)
- [ ] Cross-account trust without external ID condition
- [ ] sts:AssumeRole with no MFA/IP conditions

## Step 3: S3 Storage Checks

- [ ] acl = "public-read" or "public-read-write" — CRITICAL
- [ ] block_public_acls = false — CRITICAL
- [ ] block_public_policy = false — CRITICAL
- [ ] Bucket policy allows Principal:"*" without conditions
- [ ] Versioning disabled on sensitive data buckets
- [ ] Server-side encryption not configured
- [ ] S3 access logging disabled
- [ ] MFA delete not enabled on critical buckets

---

## Step 4: Networking and Security Groups

CRITICAL — internet-accessible management ports:
```hcl
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # Flag: SSH open to internet
}
```

Checks:
- [ ] SSH (22) or RDP (3389) open to 0.0.0.0/0
- [ ] Database ports (3306, 5432, 27017, 6379) open to 0.0.0.0/0
- [ ] 0.0.0.0/0 on any sensitive port
- [ ] VPC with no flow logs
- [ ] Default VPC in use (should use custom)
- [ ] Internet Gateway attached to subnets with sensitive resources

---

## Step 5: Compute

- [ ] EC2 with public IP and no security group restrictions
- [ ] User data scripts containing secrets or credentials
- [ ] IMDSv1 enabled (SSRF → credential theft via 169.254.169.254)
- [ ] Lambda env vars with hardcoded secrets
- [ ] Lambda with overly permissive execution role
- [ ] ECS task definitions with privileged:true
- [ ] ECS secrets hardcoded in environment variables

---

## Step 6: Databases

- [ ] RDS publicly_accessible = true
- [ ] RDS encryption at rest disabled
- [ ] RDS automated backups disabled
- [ ] ElastiCache with no auth token (Redis)
- [ ] ElastiCache encryption in-transit disabled

---

## Step 7: Logging and Monitoring

- [ ] CloudTrail disabled or not multi-region
- [ ] CloudTrail log file validation disabled
- [ ] GuardDuty not enabled
- [ ] AWS Config not enabled
- [ ] VPC Flow Logs not enabled
- [ ] S3 access logging disabled on sensitive buckets

---

## Step 8: Hardcoded Secrets

- [ ] Secrets anywhere in IaC files (passwords, keys, tokens)
- [ ] Passwords passed as plain-text parameters
- [ ] Not using Secrets Manager or Parameter Store (SSM)
- [ ] KMS key rotation disabled
- [ ] Secrets in tfvars or output blocks

---

## Step 9: Kubernetes YAML Checks

CRITICAL security context issues:
```yaml
# CRITICAL: Privileged container — container escape
securityContext:
  privileged: true

# CRITICAL: Running as root
securityContext:
  runAsUser: 0
```

Secure baseline to enforce:
```yaml
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
- [ ] privileged:true — container escape to host
- [ ] runAsUser:0 or no runAsNonRoot:true
- [ ] allowPrivilegeEscalation:true or missing
- [ ] hostPID, hostIPC, hostNetwork enabled
- [ ] hostPath volume mounts (especially /var/run/docker.sock)
- [ ] docker.sock mounted — full node escape
- [ ] No resource limits — DoS vector
- [ ] Secrets in env variables (use secretKeyRef)
- [ ] No NetworkPolicy defined — all pod-to-pod traffic allowed
- [ ] ClusterRoleBindings with wildcard permissions
- [ ] Default service account with elevated permissions
- [ ] Images using mutable :latest tag

---

## Finding Template

```markdown
## [IAC-001] <Title>

**Severity:** Critical / High / Medium / Low
**Resource:** <resource type and name>
**File:** <filename>:<line-number>
**Compliance:** CIS X.X / PCI DSS X.X / SOC2 CCX.X

### Vulnerable Configuration
[exact code snippet from the file]

### Risk
[What can an attacker do with this misconfiguration?]

### Secure Configuration
[corrected code]

### References
- [CIS Benchmark link]
- [AWS/GCP/Azure security docs]
```

---

## Severity Ratings

| Finding | Severity |
|---------|----------|
| Wildcard IAM with Resource:"*" | Critical |
| S3 bucket publicly writable | Critical |
| SSH/RDP open to 0.0.0.0/0 | Critical |
| Privileged K8s container | Critical |
| Hardcoded secret/credential | Critical |
| Docker socket mounted | Critical |
| IMDSv1 enabled (SSRF → credential theft) | High |
| RDS publicly accessible | High |
| CloudTrail disabled | High |
| K8s cluster-admin wildcard RBAC | High |
| Encryption at rest disabled | High |
| No NetworkPolicy in K8s | Medium |
| No resource limits on pods | Medium |
| Missing tags/labels | Low |

---

## Output

Write findings to `IAC-SECURITY-REPORT.md`. Terminal summary:
```
[sec-iac] IaC Security Review Complete
Files analyzed:    XX (.tf, .yaml, etc.)
Resources scanned: XX
Findings:          XX (Critical: X | High: X | Medium: X | Low: X)
Top Finding: <title> — <file>:<line>
Full report: IAC-SECURITY-REPORT.md
```

## File Structure
```
sec-iac/
├── SKILL.md
├── references/
│   ├── aws-checks.md
│   ├── k8s-checks.md
│   ├── azure-checks.md
│   └── compliance-mapping.md
└── scripts/
    ├── tf_parser.py
    └── k8s_parser.py
```
