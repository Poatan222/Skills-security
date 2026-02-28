---
name: cspm-prowler
description: >
  Analyze Prowler CSPM scan outputs, prioritize cloud misconfigurations
  by risk, and generate remediation plans with compliance mapping.
  Supports AWS, Azure, and GCP findings. Trigger when user uploads
  Prowler output files (.csv, .json, .html), mentions "Prowler",
  "CSPM", "cloud security posture", "cloud misconfiguration",
  "CIS benchmark", "cloud compliance scan", or asks about cloud
  security findings. Also trigger when user pastes Prowler CLI
  output or asks how to run Prowler against their cloud environment.
---

# CSPM Prowler Skill

Analyze Prowler scan results, prioritize cloud misconfigurations by actual risk, and generate actionable remediation plans with compliance mapping.

Prowler is an open-source CSPM tool that checks AWS, Azure, GCP, and Kubernetes against CIS Benchmarks, PCI-DSS, HIPAA, SOC2, NIST, and other frameworks. This skill turns raw Prowler output into prioritized, team-ready action items.

## Workflow

### Step 1: Determine Mode

This skill operates in two modes:

**Mode A: Analyze Existing Scan Results**
User uploads or pastes Prowler output (CSV, JSON-OCSF, or HTML). Proceed to Step 2.

**Mode B: Guide Scan Execution**
User wants to run Prowler. Load the appropriate cloud provider reference from `references/cloud-providers/` and guide them through setup and execution. Proceed to Step 2 once results are available.

### Step 2: Ingest Prowler Output

Parse the Prowler findings into a normalized schema:

**Expected fields from Prowler output:**

- `check_id` — Prowler check identifier (e.g., `s3_bucket_public_access`)
- `check_title` — Human-readable check name
- `status` — PASS, FAIL, INFO, WARNING
- `severity` — critical, high, medium, low, informational
- `service` — AWS/Azure/GCP service name
- `region` — Cloud region
- `resource_id` — ARN, resource ID, or resource name
- `account_id` — Cloud account/subscription/project
- `compliance` — Framework mappings (CIS, PCI, etc.)
- `remediation` — Prowler's built-in remediation guidance
- `risk` — Description of the risk

**Filter:** Only process FAIL findings. PASS findings are excluded from the report (but count toward posture score).

**Staleness:** If scan timestamp is older than 7 days, warn the user.

### Step 3: Enrich and Contextualize

For each FAIL finding, add context:

**1. Asset Criticality**

Cross-reference resource IDs against `references/asset-criticality.md` to determine if the affected resource is Tier 1 (crown jewel), Tier 2 (business critical), or Tier 3 (standard).

**2. Exposure Assessment**

- Is the resource internet-facing? (public IPs, public subnets, open security groups)
- Is the resource in a production account or dev/staging?
- Does the misconfiguration expose data or enable lateral movement?

**3. Blast Radius**

- IAM misconfigs on root/admin accounts = high blast radius
- Network misconfigs on VPCs with database subnets = high blast radius
- Logging/monitoring gaps across all accounts = detection blind spot

### Step 4: Prioritize Findings

Group by effective risk, not just Prowler severity:

| Priority | Criteria | Action |
|----------|----------|--------|
| P1 - Immediate | Public data exposure, open admin access, disabled logging on prod, IAM root without MFA | Fix within 24-48 hours |
| P2 - This Sprint | Internet-facing misconfigs, encryption gaps on Tier 1/2 resources, overly permissive IAM | Fix this sprint |
| P3 - Backlog | Internal-only misconfigs, Tier 3 resources, informational best-practice gaps | Backlog with tracking |
| P4 - Accept Risk | Dev/staging findings, low-impact informational findings | Document and accept |

**Auto-elevate rules:**

- Any finding affecting IAM root account = P1
- Public S3/Storage/GCS bucket with data = P1
- Security group allowing 0.0.0.0/0 to SSH/RDP on production = P1
- CloudTrail/Activity Log/Audit Log disabled = P1
- Encryption disabled on database or storage with Tier 1 data = P1

### Step 5: Map to Compliance Frameworks

Using the compliance data from Prowler output and `references/compliance-mapping.md`, map each finding to relevant framework controls:

- CIS Benchmarks (AWS/Azure/GCP)
- PCI DSS v4.0
- SOC 2 Type II
- HIPAA
- NIST 800-53
- ISO 27001

This enables the user to generate compliance-specific reports for auditors.

### Step 6: Generate Outputs

**6a. Posture Summary Report**

```markdown
# Cloud Security Posture Report
**Provider**: [AWS/Azure/GCP] | **Scan Date**: [date] | **Accounts Scanned**: [count]

## Executive Summary
- Total checks: X | Passed: X (Y%) | Failed: X (Y%)
- P1 (Immediate): X | P2 (This Sprint): X | P3 (Backlog): X | P4 (Accept): X
- Top 3 riskiest services: [service, fail count, highest severity]
- Top 3 riskiest accounts: [account, fail count]
- Compliance posture: [framework: pass %]

## P1 Findings (Fix Immediately)
### [Check ID] — [Check Title]
- **Resource**: [resource ID/ARN]
- **Account**: [account] | **Region**: [region]
- **Why P1**: [1-line risk justification]
- **Remediation**: [specific steps or CLI commands]
- **Compliance**: [framework controls affected]

## P2 Findings (This Sprint)
[Same format]

## P3/P4 Summary
[Table: Check ID | Service | Count | Severity | Priority]

## Compliance Dashboard
[Table: Framework | Total Controls | Passing | Failing | % Compliant]

## Trend (if previous scan available)
- New failures since last scan: X
- Resolved since last scan: X
- Posture change: +/-X%
```

**6b. Remediation Tickets**

For P1 and P2 findings, generate tickets with:

- **Summary:** `[CSPM] [service] — [check title] — [account]`
- **Description:** Risk description, affected resources, remediation steps (with CLI commands where applicable)
- **Assignee:** Cloud account owner
- **Priority:** Blocker (P1) or High (P2)
- **Labels:** `cspm-prowler`, `cloud-security`, `[framework]`

**6c. Prowler CLI Command for Re-scan**

After remediation, provide the targeted re-scan command:

```bash
# Re-scan specific checks
prowler aws --checks [check_id_1] [check_id_2] -M csv json-ocsf

# Re-scan specific service
prowler aws --services [service] --region [region]

# Re-scan specific account with role assumption
prowler aws -R arn:aws:iam::[ACCOUNT]:role/ProwlerRole --checks [check_id]
```

## Edge Cases

| Scenario | Action |
|----------|--------|
| Prowler output is from an old version | Warn user. Check field names, adapt parsing if needed. |
| Multi-account scan with inconsistent roles | Note which accounts had partial access. Flag incomplete scans. |
| Finding is on a shared/managed service | Identify if remediation is user-responsibility or provider-managed. |
| Same misconfiguration across 100+ resources | Group into single finding with resource count. Do not create 100 tickets. |
| User asks to run Prowler but lacks permissions | Guide them to request SecurityAudit + ViewOnlyAccess (AWS) or equivalent. |
| Conflicting findings (e.g., encryption check passes in one scan, fails in another) | Use most recent scan. Note discrepancy. |
| User wants compliance report only (not remediation) | Generate compliance dashboard section only. Skip remediation tickets. |

## File Structure

```text
cspm-prowler/
├── SKILL.md                            # This file
├── references/
│   ├── asset-criticality.md            # Map cloud resources to criticality tiers
│   ├── compliance-mapping.md           # Framework controls mapping
│   ├── prowler-checks-severity.md      # Override Prowler default severities
│   └── cloud-providers/
│       ├── aws.md                      # AWS-specific Prowler setup and checks
│       ├── azure.md                    # Azure-specific Prowler setup and checks
│       └── gcp.md                      # GCP-specific Prowler setup and checks
└── scripts/
    └── parse_prowler_csv.py            # Normalize Prowler CSV output to JSON
```
