---
name: sec
description: >
  Main security suite orchestrator. Routes all /sec commands to specialist
  skills. Trigger on any /sec command or when user asks to run a security
  assessment, pentest, audit, recon, threat model, IR triage, IaC review,
  container scan, CI/CD review, SBOM analysis, or security report.
---

# Claude Code Security Suite — Orchestrator

Routing engine for the /sec command suite. Read the command, identify
the target skill, load it, execute. For /sec audit, orchestrate 4
parallel subagents for full-engagement assessment.

Philosophy: PoC and GTFO. Find real bugs. Prove them. Report them.

## Command Routing Table

| Command | Sub-Skill | Description |
|---------|-----------|-------------|
| /sec recon <target> | sec-recon | Attack surface, subdomain enum, secrets |
| /sec iac <path> | sec-iac | Terraform, CloudFormation, K8s YAML |
| /sec container <image> | sec-container | Container and K8s security |
| /sec ir <logs> | sec-ir | IR triage, log analysis, blast radius |
| /sec dast <url> | sec-dast | Web app dynamic security testing |
| /sec cicd <repo> | sec-cicd | CI/CD pipeline security review |
| /sec sbom <manifest> | sec-sbom | SBOM and dependency risk |
| /sec report <findings> | sec-report-pdf | PDF report generation |
| /sec api <url> | api-pentest | API pentest GTFO-first |
| /sec triage <scan> | vuln-triage | Vuln triage EPSS/KEV |
| /sec threat <arch> | threat-modeling | STRIDE threat modeling |
| /sec cspm <o> | cspm-prowler | Cloud security posture |
| /sec code <file> | secure-code-review | Taint/data flow analysis |
| /sec audit <target> | PARALLEL | Full engagement: 4 agents |

## Trigger Conditions

Trigger when user:
- Types any /sec <subcommand>
- Says "security assessment", "pentest", "find vulnerabilities in"
- Shares a URL and asks "is this secure", "test this"
- Shares code and asks for "security review", "SAST", "vuln check"
- Shares IaC files (.tf, .yaml, .json) with security questions
- Shares log files or describes an incident
- Asks "what is my attack surface", "find exposed secrets"
- Shares CI/CD workflow files and asks about security

## Routing Logic

### Step 1: Parse the Command
Extract subcommand, target, flags from /sec <sub> <target> [--flags]

Disambiguation if no subcommand given:
| Target Type | Default Route |
|-------------|---------------|
| URL (http/https) | sec-dast |
| *.tf, *.tfvars, CloudFormation YAML | sec-iac |
| Docker image or Dockerfile | sec-container |
| *.log, incident description | sec-ir |
| GitHub repo URL | sec-recon |
| package.json, requirements.txt, go.mod | sec-sbom |
| .github/workflows/, Jenkinsfile | sec-cicd |
| Prowler/Nessus/Nuclei scan output | vuln-triage |

### Step 2: Validate Scope
Before any active testing ask: "Confirming this is a target you are
authorized to test?" Never skip scope validation for external URLs/IPs.

### Step 3: Load and Execute Sub-Skill
Read the sub-skill SKILL.md and execute its workflow.

## /sec audit — Full Engagement

Pre-audit: classify target, confirm scope, fingerprint tech stack.

4 parallel subagents:
1. sec-recon    — subdomain enum, secrets, attack surface map
2. sec-dast     — active web app testing, auth, injection, headers
3. api-pentest  — BOLA/IDOR, auth bypass, GTFO on first critical
4. secure-code  — taint analysis, hardcoded secrets (if repo provided)

Synthesis: deduplicate, correlate (DAST confirmed SAST = higher confidence),
rank by Severity > Exploitability > Asset Criticality, write SECURITY-AUDIT.md

## Terminal Output

    Target: <target>
    Mode: Full Engagement (4 parallel agents)
      [1] sec-recon    ... Running
      [2] sec-dast     ... Running
      [3] api-pentest  ... CRITICAL FOUND (GTFO)
      [4] secure-code  ... Running

    Critical: X | High: X | Medium: X | Low: X
    Risk Score: XX/100
    Full report: SECURITY-AUDIT.md
    PDF: /sec report SECURITY-AUDIT.md

## Error Handling
| Error | Action |
|-------|--------|
| Target unreachable | Report, suggest VPN/allowlisting |
| Scope unclear | Stop. Ask for explicit confirmation |
| Auth required | Ask for test credentials. Never brute-force |
| Rate limiting | Back off. Note as potential finding |
| Subagent failure | Continue with others, note gap in report |
| Production signals | Warn, switch read-only, require confirmation |

## Cross-Skill Integration
- If THREAT-MODEL.md exists, feed to sec-dast and api-pentest
- If prowler-output.json exists, auto-route to cspm-prowler
- After audit suggest: /sec report SECURITY-AUDIT.md
- Suggest follow-up: /sec threat to model root causes
