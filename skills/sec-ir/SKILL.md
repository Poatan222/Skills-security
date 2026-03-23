---
name: sec-ir
description: >
  Incident response triage skill. Parses logs, constructs attack timelines,
  identifies blast radius, and recommends containment actions. Trigger on
  /sec ir, or when user describes a breach, suspicious activity, weird logs,
  possible intrusion, unauthorized access, data exfil, shares CloudTrail,
  VPC Flow Logs, auth logs, nginx logs, K8s audit logs, or asks to
  investigate, triage this incident, find the attacker, what happened.
---

# sec-ir — Incident Response Triage

Fast triage. Establish timeline. Scope the blast radius. Contain before you investigate.

**IR Priority Order:**
1. **Contain** — Stop active damage first
2. **Scope** — How far did they get?
3. **Timeline** — What happened and when?
4. **Evidence** — Preserve before it rotates
5. **Remediate** — Kick them out and close the door
6. **Report** — Document for legal, compliance, leadership

---

## Step 1: Incident Classification

| Class | Signals | Initial Response |
|-------|---------|-----------------|
| Active Intrusion | Live attacker, ongoing lateral movement | Immediate isolation |
| Data Breach | PII/IP exfiltrated, unauthorized data access | Evidence preservation, legal prep |
| Account Compromise | Unauthorized auth, privilege escalation | Credential rotation, session termination |
| Malware/Ransomware | Encrypted files, C2 callbacks | Network isolation — do NOT pay |
| Insider Threat | Anomalous access by legit user | Log preservation, HR/legal escalation |
| Supply Chain | Compromised dependency, build pipeline attack | Freeze deployments, audit changes |
| Cloud Misconfiguration Exploit | Exposed bucket, IMDSv2 bypass | Close exposure, audit access |

---

## Step 2: Log Triage by Source

### AWS CloudTrail — Run These First

High-value events to hunt immediately:
```python
critical_events = [
    "ConsoleLogin",       # Who logged in, from where
    "AssumeRole",         # Role assumption chains — lateral movement
    "CreateUser",         # New IAM users created
    "AttachUserPolicy",   # Privilege escalation
    "CreateAccessKey",    # New API keys — persistence
    "GetSecretValue",     # Secrets accessed
    "DeleteTrail",        # Attacker covering tracks — URGENT
    "StopLogging",        # Attacker disabling logging — URGENT
    "GetObject",          # Mass S3 downloads — data exfil
    "ListBuckets",        # Reconnaissance
    "RunInstances",       # New compute — cryptomining, C2
]
```

Timeline reconstruction from CloudTrail JSON:
```python
import json
events = []
for line in open('cloudtrail.json'):
    r = json.loads(line)
    events.append({
        'time': r['eventTime'],
        'user': r.get('userIdentity', {}).get('arn', 'unknown'),
        'event': r['eventName'],
        'ip': r.get('sourceIPAddress', 'N/A'),
        'region': r.get('awsRegion', 'N/A'),
    })
for e in sorted(events, key=lambda x: x['time']):
    print(f"{e['time']} | {e['event']:40} | {e['user'][:50]} | {e['ip']}")
```

CloudTrail red flags:
- ConsoleLogin from unknown IP (Tor exit nodes, unfamiliar geo)
- CreateAccessKey for existing user you didn't authorize
- API calls from EC2 instances that shouldn't be making API calls
- DeleteTrail or StopLogging — attacker covering tracks
- Spike in GetObject on sensitive buckets — data exfiltration
- AssumeRole chains across accounts — lateral movement
- API calls from regions you don't operate in
- Root account activity (should be near-zero)

### VPC Flow Logs
```bash
# High-volume outbound to single IP — exfiltration
awk '{print $5, $6, $7, $8, $13}' flow-log.txt | sort | uniq -c | sort -rn | head -20

# Connections to unusual ports
awk '$7 > 1024 && $7 != 443 && $7 != 80' flow-log.txt | awk '{print $7,$5}' | sort | uniq -c | sort -rn

# REJECT records — scanning/probing
grep "REJECT" flow-log.txt | awk '{print $5}' | sort | uniq -c | sort -rn
```

Red flags: high-volume egress to single external IP, SSH/RDP from unexpected IPs,
unusual inter-subnet traffic, ICMP to external IPs (C2 channel).

### Linux Auth Logs
```bash
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20
grep "Accepted" /var/log/auth.log | awk '{print $9, $11}' | sort | uniq
grep "sudo" /var/log/auth.log | grep -v "pam_"
grep -E "(useradd|groupadd|usermod)" /var/log/auth.log
```

### Web Server Logs
```bash
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20
grep -E "\.\./|%2e%2e" access.log   # Path traversal
grep -iE "(union|select|1=1|' or)" access.log   # SQLi probes
grep -E "\.(php|asp|aspx|jsp)\?" access.log | grep -E "(cmd=|exec=|system\()"  # Webshell
```

### Kubernetes Audit Logs
```bash
grep '"verb":"create"' k8s-audit.log | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    if e.get('objectRef', {}).get('resource') in ['clusterrolebindings', 'rolebindings']:
        print(e['requestReceivedTimestamp'], e['user']['username'], e['objectRef'])
"
grep '"exec"' k8s-audit.log | grep '"pods"'  # Exec into pods
grep '"secrets"' k8s-audit.log | grep '"get\|list"'  # Secrets access
```

---

## Step 3: Attack Timeline Construction

```markdown
## Attack Timeline

| Time (UTC) | Event | Source | Evidence | Significance |
|------------|-------|--------|----------|-------------|
| 02:31:44 | Initial access — SSH from 185.x.x.x | auth.log | "Accepted publickey" | First malicious access |
| 02:33:45 | AWS credential theft | CloudTrail | IMDS 169.254.169.254 request | Pivoted to cloud |
| 02:35:02 | Cloud recon | CloudTrail | ListBuckets, ListInstances | Mapping environment |
| 02:41:17 | Data exfiltration | CloudTrail + VPC Flow | 847 GetObject on prod-data | Data stolen |
| 02:43:55 | Evidence destruction | CloudTrail | DeleteTrail, StopLogging | Covering tracks |
```

---

## Step 4: Blast Radius Assessment

**Access Scope:**
- [ ] What credentials were compromised? (User, role, service account, API key)
- [ ] What permissions did those credentials have?
- [ ] What resources were accessible with those permissions?
- [ ] Were other accounts/environments accessible (cross-account, staging/prod)?

**Data Exposure:**
- [ ] What data was accessible in the blast radius?
- [ ] Was any data accessed (confirmed read)?
- [ ] Was any data exfiltrated (confirmed egress)?
- [ ] Breach notification triggers? (PII → GDPR/CCPA, PHI → HIPAA, card data → PCI)

**Persistence Mechanisms:**
- [ ] New IAM users or access keys created?
- [ ] SSH keys added to authorized_keys?
- [ ] Cron jobs or startup scripts modified?
- [ ] New containers/pods deployed?
- [ ] Lambda functions added or modified?
- [ ] GitHub Actions secrets or runners compromised?

## Step 5: Containment Actions

Immediate (Do Now):
```bash
# Revoke compromised AWS credentials
aws iam delete-access-key --access-key-id AKIA... --user-name <user>
aws iam delete-login-profile --user-name <user>

# Isolate compromised EC2 instance (move to deny-all security group)
aws ec2 modify-instance-attribute --instance-id i-xxx --groups <isolated-sg-id>

# Revoke role sessions
aws iam delete-role-policy --role-name <role> --policy-name <policy>
```

Within 1 hour:
- Rotate ALL credentials in blast radius (not just confirmed compromised)
- Enable MFA for all IAM users if not already enforced
- Re-enable CloudTrail if disabled by attacker
- Snapshot affected instances before any changes (preserve evidence)

Within 24 hours:
- Full credential audit — who has access to what
- Review CloudTrail for 30 days prior (establish baseline)
- Patch the initial access vector
- Implement alerting for the TTPs used

---

## Output: IR-TRIAGE-REPORT.md

```markdown
# Incident Response Triage Report
**Incident Class:** <class>
**Severity:** Critical / High / Medium / Low
**Status:** Ongoing / Contained / Resolved

## Executive Summary
[What happened, how bad, current status, immediate actions needed]

## Indicators of Compromise (IoCs)
- IPs: <list>
- AWS ARNs: <list>
- File Hashes: <list>
- Domain Names: <list>

## Attack Timeline
[Chronological table]

## Blast Radius
[Structured assessment]

## Containment Status
| Action | Status | Owner | ETA |

## Notification Requirements
- [ ] GDPR (72hr from discovery)
- [ ] HIPAA (60 days)
- [ ] PCI-DSS (24hr to card brands)
- [ ] SEC (4 business days for material incidents)
```

## File Structure
```
sec-ir/
├── SKILL.md
├── references/
│   ├── log-parsers.md
│   ├── ioc-hunting-queries.md
│   ├── notification-reqs.md
│   └── mitre-attack-map.md
└── scripts/
    ├── cloudtrail_timeline.py
    ├── vpc_flow_analyzer.py
    └── log_ioc_scanner.py
```
