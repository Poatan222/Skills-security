---
name: vuln-triage
description: >
  Triage vulnerability scan results by cross-referencing CVEs against
  asset criticality, EPSS scores, CISA KEV status, and known public
  exploits. Produces a prioritized remediation list with org-defined
  risk buckets and creates Jira tickets for critical/high findings.
  Trigger when user uploads scan exports (.csv, .json, .nessus, .xml),
  mentions "vuln triage", "CVE prioritization", "scan results",
  "vulnerability report", "prioritize findings", or "what should we
  patch first". Also trigger when user pastes raw CVE lists or asks
  about exploitability of specific CVEs.
---

# Vulnerability Triage Skill

Automate the analyst workflow: ingest scan results, enrich with threat intel, score contextually, human review, actionable output.

This skill augments analyst judgment — it does not replace it. Critical findings always require human approval before action.

## Workflow

### Step 1: Ingest and Normalize

Parse the uploaded scan file and normalize into a standard schema.

**Accepted formats:** `.csv`, `.json`, `.nessus` (XML), `.xml` (generic)

**Normalized fields:**

- `cve_id` — e.g. CVE-2024-3094
- `cvss_version` — v3.1 or v4.0 (track which version the score uses)
- `cvss_base` — float, 0-10
- `asset` — hostname or IP
- `port` / `service` — affected service
- `description` — vulnerability summary
- `scanner_source` — which tool produced this finding

**Deduplication:** Same CVE + same asset from multiple scanners = 1 finding. Keep the highest CVSS if scores conflict. Log the discrepancy.

**Staleness check:** If scan timestamp is older than 7 days, warn the user before proceeding.

**Volume check:** If more than 50,000 findings, notify user of estimated processing time. Process in batches of 5,000 with progress updates.

### Step 2: Enrich Each CVE

For every unique CVE, gather contextual data:

**1. EPSS Score (Exploit Prediction Scoring System)**

- Use `scripts/epss_lookup.py` for batch API queries
- EPSS is a probability (0-1) of exploitation in the next 30 days
- There is no universal EPSS threshold. FIRST explicitly states orgs should set thresholds based on their risk appetite and resource constraints. The defaults below are starting points.
- Reference: https://www.first.org/epss/model

**2. Known Exploit Status**

- Check `references/known-exploits.md` for public PoC availability (GitHub, exploit-db) and active exploitation in the wild
- Check CISA KEV (Known Exploited Vulnerabilities) catalog
- KEV listing = confirmed active exploitation, not theoretical risk

**3. Asset Criticality**

Map asset to criticality tier using `references/asset-inventory.md`:

- **Tier 1 — Crown Jewels:** Customer data stores, authentication systems, payment processing, production databases
- **Tier 2 — Business Critical:** Internal SaaS, CI/CD pipelines, identity providers, monitoring infrastructure
- **Tier 3 — Standard:** Developer workstations, staging environments, internal wikis, non-sensitive tooling
- If asset is not in inventory, flag as UNKNOWN. See edge cases below.

**4. Exposure Status**

- Internet-facing vs internal-only
- Behind WAF/CDN or directly exposed
- Network segmentation context (if available)

### Step 3: Score and Prioritize

Calculate priority using a weighted model:

```text
Priority = f(CVSS, EPSS, exposure, asset_criticality, exploit_availability)
```

**Default thresholds (customize per org in `references/risk-policy.md`):**

| Bucket | Default Criteria | Default SLA |
|--------|------------------|-------------|
| CRITICAL | CISA KEV listed OR (EPSS >= 0.7 + Tier 1 + internet-facing) | Per org policy |
| HIGH | CVSS >= 8 + internet-facing, OR Tier 1/2 + public exploit | Per org policy |
| MEDIUM | CVSS >= 5, no known exploit, Tier 2/3 asset | Per org policy |
| LOW | CVSS < 5, internal only, Tier 3, no exploit | Accept risk |

> **Important:** These thresholds are starting points. Every org must define SLAs that reflect their own risk tolerance, regulatory requirements, and remediation capacity. Federal agencies bound by BOD 22-01 must remediate KEV entries within CISA-mandated timelines (typically 14 days for post-2021 CVEs). Private orgs should define equivalent policies in `references/risk-policy.md`.

**Scoring rules:**

- CISA KEV listing automatically elevates to CRITICAL regardless of CVSS
- Internet-facing + public PoC = minimum HIGH
- Tier 1 asset + any CVE with CVSS >= 7 = minimum HIGH
- For LOW/accept-risk: ALWAYS document justification and risk owner sign-off

### Step 4: Human Review Gate (CRITICAL findings)

Before creating tickets for CRITICAL findings:

1. Present the CRITICAL findings list to the analyst with full context
2. For each finding, show: CVE details, why it scored CRITICAL, asset impact, and proposed remediation
3. **Wait for analyst confirmation** before proceeding to ticket creation
4. Log the reviewer name and timestamp for audit trail

This step exists because automated triage can miss context that only a human would know — planned decommissions, active incidents on the same asset, vendor-coordinated disclosure timelines, or compensating controls already in place.

HIGH findings may proceed to auto-ticketing if org policy allows.

### Step 5: Generate Outputs

Produce three deliverables:

#### 5a. Markdown Report

Use this exact structure:

```markdown
# Vulnerability Triage Report
**Scan Date**: [date] | **Triage Date**: [today] | **Assets Scanned**: [count]
**CVSS Version**: [v3.1/v4.0] | **EPSS Model**: [version]

## Executive Summary
- Total findings: X (deduplicated)
- Critical: X | High: X | Medium: X | Low: X
- Top 3 riskiest assets: [list with reasoning]
- CISA KEV matches: X
- Comparison vs. last scan: [delta if available]
- Findings requiring compensating controls: X

## Critical Findings (Human-Reviewed)
### [CVE-ID] — [short title]
- **Asset**: [hostname/IP] | **Tier**: [1/2/3]
- **CVSS**: [score (version)] | **EPSS**: [score] | **KEV**: [yes/no]
- **Exposure**: [internet-facing / internal]
- **Why Critical**: [1-line reasoning]
- **Remediation**: [specific fix steps]
- **If patch unavailable**: [compensating control recommendation]
- **Reviewed by**: [analyst] at [timestamp]

## High Findings (This Sprint)
[same format, minus review fields if auto-ticketed]

## Medium Findings (Backlog)
[summary table, no per-CVE detail unless requested]

## Accepted Risk
[CVE-ID, asset, justification, risk owner sign-off for each]

## Findings Requiring Compensating Controls
[CVE-ID, asset, why patch is unavailable, recommended control]
```

#### 5b. Jira Tickets (CRITICAL and HIGH only)

For each finding, create a ticket with:

- **Summary:** `[VULN-TRIAGE] CVE-XXXX-XXXXX — [asset] — [bucket]`
- **Description:** CVE details, risk reasoning, remediation steps, compensating control options if patch is unavailable
- **Assignee:** Asset owner from `references/asset-inventory.md`
- **Priority:** Blocker (critical) or High
- **Labels:** `vuln-triage-auto`, `security`, `[scanner-source]`
- **Due Date:** Based on org-defined SLA from `references/risk-policy.md`
- **Custom field:** EPSS score at time of triage (for trend tracking)

#### 5c. Slack Notification

Post to `#security-ops`:

```text
Vuln Triage Complete
--------------------
Critical: X (human-reviewed) | High: X | Medium: X | Low: X
CISA KEV matches: X
Report: [link]
Jira tickets created: X
Oldest unpatched critical: [CVE-ID, age in days]
```

## Edge Cases

Handle these explicitly. Do not guess or skip silently.

| Scenario | Action |
|----------|--------|
| EPSS API unavailable | Fall back to CVSS base + exploit-db lookup. Note in report. |
| Asset not in inventory | Flag as UNKNOWN_ASSET. Escalate to asset management. Do NOT auto-close or assign LOW. Default to HIGH. |
| Conflicting CVSS across scanners | Use the highest score. Note the conflict in report. |
| CVSS v3 vs v4 mismatch | Log both scores. Use whichever version org policy mandates. |
| Known false positive pattern | Check `references/false-positives.md`. If match, mark as FP with reference. Still include in report appendix. |
| Scan file corrupt or unparseable | Notify user immediately. Do not attempt partial parse. |
| CVE has no CVSS score yet | Use EPSS + exploit status only. Flag as "awaiting NVD." |
| Patch unavailable (EOL, vendor) | Recommend compensating controls from `references/compensating-controls.md`. Flag for risk acceptance workflow with owner sign-off. |
| Asset scheduled for decommission | Note in report. Reduce priority if decom is within SLA window. |
| Multiple CVEs on same asset | Group findings by asset in report. Calculate aggregate risk. Flag high-density assets for focused attention. |

## File Structure

```text
vuln-triage/
├── SKILL.md                          # This file — workflow logic
├── references/
│   ├── risk-policy.md                # Org-specific SLAs, thresholds, EPSS cutoffs
│   ├── asset-inventory.md            # Asset → owner → criticality tier
│   ├── known-exploits.md             # CVEs with public PoCs / active exploitation
│   ├── false-positives.md            # Scanner-specific FP patterns to skip
│   ├── compensating-controls.md      # Controls when patching isn't possible
│   ├── compliance-mapping.md         # CVE → compliance control mapping (PCI, SOC2, ISO27001)
│   └── remediation-templates/
│       ├── linux-patching.md         # OS-level remediation steps
│       ├── container-images.md       # Rebuild / re-tag / base image update guidance
│       ├── web-app-vulns.md          # OWASP-style fixes
│       └── cloud-misconfigs.md       # AWS/GCP/Azure remediation
└── scripts/
    ├── normalize_scan.py             # Parse .nessus / .csv / .xml → unified JSON
    ├── epss_lookup.py                # Batch EPSS API queries with caching
    └── jira_create.py                # Create tickets via Jira REST API
```

## Extending This Skill

This skill is a starting point. Common extensions:

- **GRC/Compliance mapping:** Map Critical/High CVEs to compliance controls (PCI-DSS 6.3.3, SOC2 CC7.1, ISO 27001 A.12.6) using `references/compliance-mapping.md`
- **SLA tracking and MTTR:** Compare triage dates against remediation dates to calculate mean-time-to-remediate trends per team/tier
- **CSPM integration:** Enrich with cloud security posture data — is the asset in a public subnet? Is the security group open? Is the IAM role overprivileged?
- **SBOM correlation:** Cross-reference CVEs against Software Bill of Materials to identify vulnerable dependencies across your supply chain
- **Retest validation:** After remediation, trigger a targeted re-scan on specific assets and confirm CVE is resolved before closing ticket
- **Risk exception workflow:** For accept-risk items, route to risk owner for formal sign-off with expiration date and review cadence
