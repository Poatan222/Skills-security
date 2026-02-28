# Compliance Mapping

Map vulnerability findings to compliance framework controls for audit reporting.

## Framework Controls

### PCI DSS v4.0

| Requirement | Control | Relevance to Vuln Triage |
|-------------|---------|--------------------------|
| 6.3.3 | Patch critical/high vulnerabilities within one month | CRITICAL/HIGH findings on in-scope assets |
| 6.2.4 | Address common coding vulnerabilities | Web app vulns (OWASP Top 10) |
| 11.3.1 | Internal vulnerability scanning quarterly | Validates scan cadence |
| 11.3.2 | External vulnerability scanning quarterly | Internet-facing asset findings |

### SOC 2

| Criteria | Control | Relevance to Vuln Triage |
|----------|---------|--------------------------|
| CC7.1 | Monitor infrastructure components for vulnerabilities | All triage findings |
| CC8.1 | Monitor, evaluate, and respond to system changes | New findings vs. previous scan |
| CC6.1 | Logical access security | Privilege escalation findings |

### ISO 27001:2022

| Control | Description | Relevance to Vuln Triage |
|---------|-------------|--------------------------|
| A.8.8 | Management of technical vulnerabilities | Entire vuln triage workflow |
| A.8.9 | Configuration management | Misconfig-related findings |
| A.5.7 | Threat intelligence | EPSS/KEV enrichment step |

### NIST CSF 2.0

| Function | Category | Relevance |
|----------|----------|-----------|
| Identify (ID) | ID.RA - Risk Assessment | Asset criticality mapping |
| Protect (PR) | PR.IP - Information Protection | Remediation and patching |
| Detect (DE) | DE.CM - Security Continuous Monitoring | Scan cadence and triage |
| Respond (RS) | RS.MI - Mitigation | Compensating controls |
