---
name: threat-modeling
description: >
  Generate STRIDE-based threat models from architecture descriptions,
  diagrams, or design documents. Produces a structured threat register
  with risk ratings, mitigations, and data flow analysis.
  Trigger when user mentions "threat model", "STRIDE", "attack surface",
  "security review", "design review", "architecture review", "threat
  assessment", or uploads architecture diagrams, system design docs,
  or data flow diagrams. Also trigger when user describes a new feature
  or system and asks about security implications.
---

# Threat Modeling Skill

Generate structured threat models from architecture descriptions. Follows STRIDE methodology with risk-rated threats and actionable mitigations.

This skill helps security teams and developers identify threats early in the design phase, not after deployment.

## Workflow

### Step 1: Gather Architecture Context

Extract or request the following from the user:

**Required inputs (ask if missing):**

- System name and purpose (one-sentence description)
- Components (services, databases, APIs, queues, caches, etc.)
- Data flows (what data moves between which components)
- Trust boundaries (where do privilege levels change)
- Authentication and authorization mechanisms
- External dependencies (third-party APIs, SaaS, CDNs)

**Optional but valuable:**

- Technology stack (languages, frameworks, cloud provider)
- Deployment model (containerized, serverless, VM-based)
- Existing security controls already in place
- Compliance requirements (PCI, HIPAA, SOC2, etc.)
- User types and access levels

If the user provides a diagram image, extract components and data flows from the visual. If they provide a text description, structure it into components and flows.

### Step 2: Identify Assets and Data Classification

From the architecture, identify:

**Data assets:**

- Personal Identifiable Information (PII)
- Authentication credentials / secrets
- Financial data / payment information
- Business-sensitive data
- System configuration and infrastructure data

**System assets:**

- Internet-facing endpoints
- Internal services with elevated privileges
- Data stores (databases, object storage, caches)
- CI/CD pipelines and deployment infrastructure
- Identity providers and auth services

Classify each asset using `references/data-classification.md`.

### Step 3: Map Trust Boundaries

Identify every point where trust level changes:

- Internet to DMZ / public-facing service
- Public-facing service to internal backend
- Backend to database / data store
- User-space to admin-space
- Your infrastructure to third-party services
- CI/CD pipeline to production environment

Each trust boundary crossing is a high-priority area for threat analysis.

### Step 4: Apply STRIDE per Component

For each component that crosses a trust boundary, analyze using STRIDE:

| Category | Question | Common Threats |
|----------|----------|----------------|
| **S**poofing | Can an attacker impersonate a user, service, or data source? | Session hijacking, credential stuffing, token theft |
| **T**ampering | Can data be modified in transit or at rest? | Man-in-the-middle, SQL injection, unsigned artifacts |
| **R**epudiation | Can actions be performed without traceability? | Missing audit logs, unsigned transactions |
| **I**nformation Disclosure | Can sensitive data leak to unauthorized parties? | Verbose errors, unencrypted storage, SSRF |
| **D**enial of Service | Can the service be made unavailable? | Resource exhaustion, amplification attacks |
| **E**levation of Privilege | Can a low-privilege user gain higher access? | IDOR, broken access control, container escape |

Load the full STRIDE reference from `references/frameworks/stride.md` for detailed threat patterns per category.

### Step 5: Rate Each Threat

Use a simplified risk rating:

```text
Risk = Likelihood x Impact
```

| Rating | Likelihood | Impact | Action |
|--------|-----------|--------|--------|
| Critical | Easily exploitable, public PoC or common pattern | Data breach, full system compromise, regulatory penalty | Must address before deployment |
| High | Exploitable with moderate skill | Significant data exposure, service compromise | Address this sprint |
| Medium | Requires specific conditions or insider access | Limited data exposure, partial service impact | Backlog with tracking |
| Low | Theoretical, requires chained exploits | Minimal impact, no sensitive data affected | Document and accept risk |

### Step 6: Recommend Mitigations

For each threat, provide:

1. **Primary mitigation** — the recommended fix
2. **Alternative mitigation** — if the primary is not feasible
3. **Detection mechanism** — how to detect if the threat is exploited

Load mitigation patterns from `references/frameworks/mitigations.md`.

### Step 7: Generate Output

**Threat Model Report** using this exact structure:

```markdown
# Threat Model: [System Name]
**Date**: [today] | **Author**: [user/agent] | **Review Status**: Draft

## System Overview
[1-2 paragraph description of the system, its purpose, and key components]

## Architecture Summary
### Components
[Table: Component | Type | Exposure | Data Handled]

### Data Flows
[Table: Source | Destination | Data Type | Protocol | Encrypted?]

### Trust Boundaries
[Numbered list of trust boundary crossings]

## Threat Register

### [THREAT-001] [Threat Title]
- **STRIDE Category**: [S/T/R/I/D/E]
- **Affected Component**: [component name]
- **Risk Rating**: [Critical/High/Medium/Low]
- **Description**: [2-3 sentences describing the threat]
- **Attack Scenario**: [Step-by-step attack path]
- **Mitigation**: [Primary recommendation]
- **Alternative Mitigation**: [If primary is not feasible]
- **Detection**: [How to detect exploitation]
- **Status**: Open

[Repeat for each threat]

## Summary Matrix
[Table: Threat ID | Category | Component | Rating | Mitigation Status]

## Recommendations Priority
1. [Highest priority action]
2. [Second priority]
3. [Third priority]

## Appendix
- Assumptions made during analysis
- Out-of-scope items
- References to compliance requirements if applicable
```

## Edge Cases

| Scenario | Action |
|----------|--------|
| User provides only a vague description | Ask clarifying questions about components, data flows, and trust boundaries before proceeding |
| Architecture has no authentication | Flag as CRITICAL threat — Spoofing and Elevation of Privilege apply to every component |
| System handles no sensitive data | Still analyze for availability (DoS) and integrity (Tampering) threats |
| User asks for threat model of a third-party service | Analyze the integration points and trust boundaries from your side, not the internal architecture of the third-party |
| Architecture diagram is unclear or partial | State assumptions explicitly, note gaps, and recommend follow-up with the system owner |
| User wants a specific framework (PASTA, LINDDUN) | Load the relevant reference from `references/frameworks/` and adapt the analysis |

## File Structure

```text
threat-modeling/
├── SKILL.md                           # This file
├── references/
│   ├── data-classification.md         # Data sensitivity tiers and handling rules
│   └── frameworks/
│       ├── stride.md                  # Detailed STRIDE threat patterns
│       ├── mitigations.md             # Mitigation patterns by threat category
│       └── owasp-top10.md            # OWASP Top 10 mapping for web apps
└── assets/
    └── threat-model-template.md       # Blank template for quick starts
```
