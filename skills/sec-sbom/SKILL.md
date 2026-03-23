---
name: sec-sbom
description: >
  SBOM generation and dependency risk analysis skill. Analyzes package
  manifests, generates Software Bill of Materials, identifies vulnerable
  dependencies, license risks, and supply chain threats. Trigger on
  /sec sbom, or when user shares package.json, requirements.txt, go.mod,
  pom.xml, Gemfile, Cargo.toml, or asks check my dependencies, vulnerable
  packages, supply chain risk, dependency audit, license compliance, SBOM.
---

# sec-sbom — SBOM and Dependency Risk Analysis

Know what's in your software. Every dependency is a trust decision.

---

## Supported Formats

| Ecosystem | Files | Tool |
|-----------|-------|------|
| Node.js | package.json, package-lock.json, yarn.lock | npm audit, syft |
| Python | requirements.txt, Pipfile, pyproject.toml | pip-audit, safety |
| Java | pom.xml, build.gradle | dependency-check, syft |
| Go | go.mod, go.sum | govulncheck, syft |
| Ruby | Gemfile, Gemfile.lock | bundle audit |
| Rust | Cargo.toml, Cargo.lock | cargo audit |
| .NET | *.csproj, packages.config | dotnet list package --vulnerable |

---

## Phase 1: SBOM Generation

```bash
# Universal SBOM generator (CycloneDX format)
syft <image-or-path> -o cyclonedx-json > sbom.json

# NPM
npm sbom --sbom-format cyclonedx > sbom.json

# Python
cyclonedx-py environment -o sbom.json

# Go
cyclonedx-gomod app -output sbom.json
```

---

## Phase 2: Vulnerability Analysis

NPM:
```bash
npm audit --json | python3 -c "
import sys, json
d = json.load(sys.stdin)
for pkg, info in d.get('vulnerabilities', {}).items():
    if info['severity'] in ['high', 'critical']:
        print(f\"[{info['severity'].upper()}] {pkg} — {info.get('title','?')}\")
        print(f\"  Fix: {info.get('fixAvailable', 'No fix')}\")
"
```

Python:
```bash
pip-audit -r requirements.txt --format json
safety check -r requirements.txt --json
```

Go:
```bash
govulncheck ./...
# Only reports reachable vulnerabilities — much less noise
```

Java:
```bash
dependency-check --project myapp --scan . --format JSON \
  --out dependency-check-report.json
dependency-check --failOnCVSS 7 --scan pom.xml
```

---

## Phase 3: Supply Chain Threat Analysis

Dependency confusion check — internal package names on public registries:
```python
import json
manifest = json.load(open('package.json'))
deps = {**manifest.get('dependencies',{}), **manifest.get('devDependencies',{})}
for pkg in deps:
    if not pkg.startswith('@company-scope'):
        print(f"Verify on public registry: {pkg}")
```

Postinstall script detection — can execute arbitrary code at install time:
```bash
cat package-lock.json | python3 -c "
import sys, json
lock = json.load(sys.stdin)
for pkg, info in lock.get('packages', {}).items():
    scripts = info.get('scripts', {})
    if any(k in scripts for k in ['postinstall','preinstall','install']):
        print(f'WARNING {pkg}: has install script: {scripts}')
"
```

Typosquatting patterns to flag:
- Missing hyphens: react-router vs reactrouter
- Character substitution: lodash vs 1odash (l→1)
- Common suffixes: requests vs requests2
- Abandoned packages not updated in >2 years

---

## Phase 4: License Compliance

```bash
license-checker --json > licenses.json   # NPM
pip-licenses --format=json > licenses.json  # Python
```

License risk matrix:
| License | Commercial Use | Risk |
|---------|---------------|------|
| MIT, BSD, Apache-2.0 | Yes | None — safe for all |
| LGPL | Yes (dynamic linking) | Acceptable with care |
| GPL-2.0/3.0 | Only if open source | Risk in proprietary products |
| AGPL-3.0 | Strong network copyleft | Flag for legal review |
| Unknown / No License | No rights granted | Block |

Auto-flag: GPL/AGPL in commercial closed-source products, unknown licenses.

---

## Phase 5: Risk Scoring

Triage decision matrix:
| CVSS | Reachable | Fix Available | Action |
|------|-----------|---------------|--------|
| 9.0+ | Yes | Yes | Fix this sprint — block deployment |
| 9.0+ | Yes | No | Mitigate + escalate to security team |
| 7.0-8.9 | Yes | Yes | Fix within 7 days |
| 4.0-6.9 | Yes | Yes | Fix within 30 days |
| < 4.0 | Any | Any | Backlog |

---

## Output

Write to SBOM-REPORT.md. Terminal summary:
```
[sec-sbom] Dependency Security Analysis
Total dependencies: XXX (direct: XX, transitive: XXX)
Vulnerable:         XX (Critical: X | High: X | Medium: X)
Supply chain risks: X
License issues:     X
CRITICAL: lodash@4.17.20 — Prototype pollution (fix: 4.17.21)
HIGH:     axios@0.21.1 — SSRF (fix: 0.21.2)
Full report: SBOM-REPORT.md
SBOM artifact: sbom.json (CycloneDX)
```

## File Structure
```
sec-sbom/
├── SKILL.md
├── references/
│   ├── license-matrix.md
│   ├── typosquatting-patterns.md
│   └── supply-chain-ttps.md
└── scripts/
    ├── sbom_generator.py
    ├── license_auditor.py
    └── dep_confusion_check.py
```
