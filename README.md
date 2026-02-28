# Security Skills for AI Agents

A collection of production-ready Skills that teach AI agents how to perform core security workflows. Built for Claude, adaptable to any agentic AI platform (LangGraph, OpenAI Agents, Copilot, etc).

## What are Skills?

Skills are reusable instruction sets that teach AI agents **how** to do a specific job — not just what to do, but the reasoning, tool sequences, edge cases, and output formats. Think of them as runbooks an agent can follow autonomously.

## Skills Included

| Skill | Description | Use Case |
|-------|-------------|----------|
| [vuln-triage](./vuln-triage/) | Triage vulnerability scan results using EPSS, CISA KEV, and asset criticality | Vulnerability Management |
| [threat-modeling](./threat-modeling/) | Generate STRIDE-based threat models from architecture descriptions | Threat Modeling |
| [cspm-prowler](./cspm-prowler/) | Analyze Prowler CSPM scan outputs and prioritize cloud misconfigurations | Cloud Security Posture Management |
| [api-pentest](./api-pentest/) | GTFO-first API penetration testing across 5 attack families with PoC-driven findings | API Security Testing |
| [secure-code-review](./secure-code-review/) | Taint, data flow, and control flow analysis for Java/Spring, Python/Django/Flask, Node/Express | Application Security |

## Structure

Each skill follows the same anatomy:

```text
skill-name/
├── SKILL.md                # Workflow logic (the skill itself)
├── references/             # Data files loaded on demand
├── scripts/                # Helper scripts for deterministic tasks
└── assets/                 # Templates, icons, output formats
```

## How to Use

**With Claude (claude.ai or Claude Code):**
Upload the skill folder or add it to your project. Claude reads SKILL.md when the trigger conditions match.

**With other agents:**
Adapt SKILL.md as a system prompt or tool instruction. The workflow logic is agent-agnostic.

## Skill Details

### Vulnerability Triage
Ingests scan output from any scanner, normalizes to CVSS + EPSS + CISA KEV, scores by asset criticality, and generates prioritized remediation tickets. Includes human review gate for critical findings. References: risk policy, asset inventory, compensating controls, compliance mapping, remediation templates (Linux, containers, cloud).

### Threat Modeling
STRIDE-based analysis from architecture descriptions or diagrams. Identifies trust boundaries, classifies data sensitivity, and produces a threat register with risk ratings and mitigations. References: STRIDE patterns, OWASP Top 10 mapping, mitigation library, data classification tiers.

### CSPM with Prowler
Analyzes Prowler scan results across AWS, Azure, and GCP. Re-prioritizes findings using asset criticality and exposure context (not just Prowler severity). Generates compliance dashboards and targeted re-scan commands. References: provider-specific setup guides, compliance framework mapping, severity overrides.

### API Penetration Testing
GTFO-first approach: test attack families in order of highest-impact-finding likelihood. Five modules: BOLA/IDOR, AuthN/AuthZ, Input Validation (SQLi/XSS/CMDi/NoSQLi), SSRF, and Business Logic. Every finding requires a working PoC. Includes WAF bypass techniques, filter evasion, and blind detection methods.

### Secure Code Review
Four analysis techniques: taint analysis (source-to-sink), data flow analysis, control flow analysis, and framework-specific pattern matching. Framework references cover dangerous defaults, insecure configurations, parser differentials, and common anti-patterns for Spring Boot, Django, Flask, and Express.

## Customization

Every skill ships with default thresholds and policies. Customize for your org:

- `references/risk-policy.md` — SLAs, EPSS thresholds, escalation paths
- `references/asset-inventory.md` — Your crown jewels and asset tiers
- Compliance mappings — Which frameworks matter to you

## Contributing

These skills are open reference points. Fork, adapt, extend. PRs welcome for:
- New attack family modules (e.g., GraphQL, gRPC)
- New framework references (e.g., .NET, Go, Ruby on Rails)
- New security skills (e.g., incident response, forensics, DAST)

## License

MIT — use freely, no warranty. Customize for your environment before production use.
