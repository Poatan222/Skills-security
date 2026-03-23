# Claude Code Security Suite

A production-grade security skill suite for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).
Built for security practitioners who work hands-on — not for generating generic reports,
but for finding real vulnerabilities, building PoCs, and delivering client-ready output.

**Philosophy:** PoC and GTFO. Find the critical bug first. Prove it. Report it. Move on.

---

## What This Does

```
> /sec audit https://app.example.com

Target: https://app.example.com
Mode: Full Engagement (4 parallel agents)

  [1] sec-recon       Complete — 3 findings (1H, 2M)
  [2] sec-dast        Complete — 5 findings (1C, 2H, 2M)
  [3] api-pentest     CRITICAL FOUND — GTFO triggered
  [4] secure-code     Complete — 4 findings (2H, 2L)

Total: 13 findings | Critical: 1 | High: 5 | Medium: 4 | Low: 3
Risk Score: 87/100 — CRITICAL

Full report: SECURITY-AUDIT.md
PDF:         /sec report SECURITY-AUDIT.md
```

---

## New Skills (this suite)

| Command | Skill | Description |
|---------|-------|-------------|
| `/sec recon <target>` | sec-recon | Subdomain enum, secrets scanning, attack surface mapping |
| `/sec iac <path>` | sec-iac | Terraform, CloudFormation, K8s YAML security review |
| `/sec container <image>` | sec-container | Docker image and K8s manifest security |
| `/sec ir <logs>` | sec-ir | Incident response triage, log analysis, blast radius |
| `/sec dast <url>` | sec-dast | Web application active security testing |
| `/sec cicd <repo>` | sec-cicd | GitHub Actions, Jenkins, GitLab CI security review |
| `/sec sbom <manifest>` | sec-sbom | SBOM, dependency CVEs, supply chain risk |
| `/sec report <findings>` | sec-report-pdf | Professional PDF security report |
| `/sec audit <target>` | Orchestrated | Full engagement — 4 parallel agents |

## Integrated Skills (from original Skills-security repo)

| Command | Skill | Description |
|---------|-------|-------------|
| `/sec api <url>` | api-pentest | GTFO-first API pentesting — BOLA, AuthN, Injection, SSRF |
| `/sec triage <scan>` | vuln-triage | Vulnerability triage with EPSS, CISA KEV, asset criticality |
| `/sec threat <arch>` | threat-modeling | STRIDE-based threat modeling |
| `/sec cspm <o>` | cspm-prowler | AWS/Azure/GCP cloud security posture via Prowler |
| `/sec code <file>` | secure-code-review | Taint, data flow, control flow for Java/Python/Node |

---

## Installation

```bash
# One-command install
curl -fsSL https://raw.githubusercontent.com/Poatan222/Skills-security/main/install.sh | bash

# Manual install (inspect first)
git clone https://github.com/Poatan222/Skills-security.git
cd Skills-security
cat install.sh
./install.sh

# Optional: PDF report generation
pip install reportlab

# Optional: Enhanced scanning tools
brew install subfinder amass syft trivy
```

---

## Architecture

```
Skills-security/
├── sec/SKILL.md                     # Main orchestrator — routes all /sec commands
├── skills/
│   ├── sec-recon/SKILL.md           # Attack surface recon
│   ├── sec-iac/SKILL.md             # IaC security review
│   ├── sec-container/SKILL.md       # Container and K8s security
│   ├── sec-ir/SKILL.md              # Incident response triage
│   ├── sec-dast/SKILL.md            # Web app dynamic testing
│   ├── sec-cicd/SKILL.md            # CI/CD pipeline security
│   ├── sec-sbom/SKILL.md            # SBOM and dependency risk
│   └── sec-report-pdf/SKILL.md      # PDF report generation
├── api-pentest/                     # Existing: API pentest
├── vuln-triage/                     # Existing: Vuln triage
├── threat-modeling/                 # Existing: Threat modeling
├── cspm-prowler/                    # Existing: Cloud security posture
└── secure-code-review/              # Existing: Secure code review
```

---

## Output Files

| Skill | Output |
|-------|--------|
| /sec audit | SECURITY-AUDIT.md |
| /sec recon | RECON-REPORT.md |
| /sec dast | DAST-REPORT.md |
| /sec iac | IAC-SECURITY-REPORT.md |
| /sec container | CONTAINER-SECURITY-REPORT.md |
| /sec cicd | CICD-SECURITY-REPORT.md |
| /sec sbom | SBOM-REPORT.md |
| /sec ir | IR-TRIAGE-REPORT.md |
| /sec report | SECURITY-REPORT.pdf |

---

## Responsible Use

Confirm you own the target or have written authorization before running active tests.
The orchestrator enforces scope confirmation before any active probing.

---

## Contributing

PRs welcome for new attack modules (GraphQL, gRPC, WebSockets),
new framework references, new skills (forensics, OSINT automation, red team playbooks).

## License

MIT — use freely, customize for your environment before production use.
