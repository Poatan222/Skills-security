---
name: sec-report-pdf
description: >
  Professional security report PDF generation skill. Converts raw findings,
  markdown reports, or scan outputs into client-ready PDF reports with
  executive summary, risk ratings, findings, and remediation roadmap.
  Trigger on /sec report, or when user asks generate PDF report, create
  pentest report, client report, executive summary, make this presentable,
  or after completing an audit with SECURITY-AUDIT.md.
---

# sec-report-pdf — Professional Security Report Generator

Turn raw findings into a report that lands with executives and engineers alike.

---

## Report Types

| Type | Flag | Audience | Length |
|------|------|----------|--------|
| Executive Summary | --type exec | CISO, CTO, Board | 2-3 pages |
| Technical Pentest | --type pentest | Engineering, Security | 15-30 pages |
| Vulnerability Assessment | --type vuln | Engineering, DevOps | 10-20 pages |
| Compliance Gap | --type compliance | Security, Legal | 10-15 pages |
| Incident Report | --type incident | Exec, Legal | 5-10 pages |
| Full Audit (default) | /sec report | Mixed | 20-40 pages |

---

## Accepted Input Formats

- SECURITY-AUDIT.md — from /sec audit
- DAST-REPORT.md — from /sec dast
- IAC-SECURITY-REPORT.md — from /sec iac
- RECON-REPORT.md — from /sec recon
- CICD-SECURITY-REPORT.md — from /sec cicd
- CONTAINER-SECURITY-REPORT.md — from /sec container
- SBOM-REPORT.md — from /sec sbom
- IR-TRIAGE-REPORT.md — from /sec ir
- Raw finding notes (freeform text or JSON)
- Multiple files combined: /sec report *.md

---

## Generation Workflow

### Step 1: Parse and Normalize Findings

Normalize all inputs to a standard schema:
```python
finding = {
    "id": "FINDING-001",
    "title": "SQL Injection in /search",
    "severity": "critical",       # critical/high/medium/low/info
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "category": "Injection",
    "cwe": "CWE-89",
    "owasp": "A03:2021",
    "affected_component": "GET /api/v1/search?q=",
    "description": "...",
    "evidence": "...",            # PoC request/response
    "impact": "...",
    "remediation": "...",
    "status": "open",
}
```

### Step 2: Risk Score Calculation

```
Risk Score =
  (Critical × 10 + High × 7 + Medium × 4 + Low × 1)
  ÷ Max_possible × 100

90-100 → CRITICAL
70-89  → HIGH
40-69  → MEDIUM
10-39  → LOW
```

### Step 3: Executive Summary (Write for non-technical audience)

Cover: what was tested, overall risk posture, most critical finding
(plain English business impact), top 3 recommended actions.

### Step 4: Risk Dashboard

```
OVERALL RISK SCORE: XX/100   ████████████████░░░░  HIGH

CRITICAL  HIGH  MEDIUM  LOW
   X        X      X      X
```

### Step 5: Findings — Critical and High (Full Detail)

For each critical/high finding:
```markdown
### Finding [ID]: [Title]

| Attribute | Value |
|-----------|-------|
| Severity | CRITICAL |
| CVSS Score | 9.8 |
| CWE | CWE-89 |
| Affected | GET /api/v1/search?q= |

**Description** — what the bug is and why it matters

**Proof of Concept** — exact reproduction steps with request/response

**Business Impact** — what attacker can do; breach scope, compliance impact

**Remediation** — specific fix with code example where possible
```

### Step 6: Findings Summary Table (Medium and Low)

```markdown
| ID | Title | Severity | Component | Status |
|----|-------|----------|-----------|--------|
| M-001 | Reflected XSS | Medium | /search | Open |
| L-001 | Missing headers | Low | All pages | Open |
```

---

### Step 7: Remediation Roadmap

```markdown
## Remediation Roadmap

### Immediate (24-48 hours)
| Finding | Owner | Effort |
|---------|-------|--------|
| [Critical finding] | Backend | 2h |

### This Sprint (7 days)
### This Month (30 days)
### Backlog (90 days)
```

### Step 8: PDF Generation

```python
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table

COLORS = {
    'critical': colors.HexColor('#DC2626'),
    'high':     colors.HexColor('#EA580C'),
    'medium':   colors.HexColor('#D97706'),
    'low':      colors.HexColor('#16A34A'),
    'dark':     colors.HexColor('#1E293B'),
}

doc = SimpleDocTemplate("SECURITY-REPORT.pdf", pagesize=A4)
# Sections: cover page, TOC, exec summary, risk dashboard,
# per-finding detail, summary table, roadmap, appendix
```

PDF features:
- Cover page with engagement details and CONFIDENTIAL classification
- Auto-generated table of contents with page numbers
- Color-coded severity badges (red/orange/yellow/green)
- Syntax-highlighted code blocks for PoC evidence
- CONFIDENTIAL footer on every page

---

## Output

```
[sec-report-pdf] Report Generation Complete
Input files:    X (SECURITY-AUDIT.md, DAST-REPORT.md)
Total findings: XX
Report type:    Full Pentest Report
SECURITY-REPORT.pdf generated (XX pages)
Classification: CONFIDENTIAL
Ready for client delivery.
```

## File Structure
```
sec-report-pdf/
├── SKILL.md
├── references/
│   ├── report-templates/
│   │   ├── pentest-template.md
│   │   ├── exec-summary-template.md
│   │   └── compliance-template.md
│   └── severity-definitions.md
└── scripts/
    ├── generate_pdf_report.py
    ├── normalize_findings.py
    └── risk_scorer.py
```
