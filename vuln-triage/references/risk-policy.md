# Risk Policy Configuration

This file defines org-specific thresholds, SLAs, and escalation paths. Customize all values below before production use.

## EPSS Thresholds

FIRST does not define universal thresholds. These are starting points — adjust based on your risk appetite and remediation capacity.

| Category | EPSS Range | Interpretation |
|----------|-----------|----------------|
| High Likelihood | >= 0.7 | Likely to be exploited within 30 days. Immediate attention. |
| Medium Likelihood | 0.4 - 0.69 | Monitor closely. Plan remediation this sprint. |
| Low Likelihood | < 0.4 | Lower urgency. Backlog unless other risk factors elevate. |

Reference: https://www.first.org/epss/model

## Remediation SLAs

| Bucket | SLA | Escalation if Missed |
|--------|-----|---------------------|
| CRITICAL | 48 hours | Auto-escalate to CISO + Eng Director |
| HIGH | Current sprint (2 weeks) | Notify Security Lead + Asset Owner's manager |
| MEDIUM | Next sprint (4 weeks) | Flag in monthly vuln review |
| LOW | Accept risk with documented justification | Quarterly review for status change |

For federal agencies: BOD 22-01 mandates KEV remediation within CISA-specified timelines (typically 14 days for post-2021 CVEs). Override the above SLAs for any CISA KEV finding.

## Escalation Contacts

| Role | Contact | When |
|------|---------|------|
| Security Lead | [YOUR_SECURITY_LEAD] | All CRITICAL findings |
| CISO | [YOUR_CISO] | CRITICAL SLA breach, KEV findings |
| Eng Director | [YOUR_ENG_DIRECTOR] | CRITICAL findings on Tier 1 assets |
| Asset Management | [YOUR_ASSET_MGMT] | Unknown assets discovered in scan |

## Risk Acceptance Policy

- LOW findings may be accepted with documented justification
- MEDIUM findings require Security Lead approval for risk acceptance
- HIGH/CRITICAL findings require CISO approval for risk acceptance
- All risk acceptances expire after 90 days and must be re-reviewed
- Risk acceptances must include: CVE ID, asset, justification, compensating controls, owner, expiry date
