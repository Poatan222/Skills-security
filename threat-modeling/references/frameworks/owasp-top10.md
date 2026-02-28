# OWASP Top 10 (2021) Mapping

When threat modeling web applications, map identified threats to OWASP Top 10 categories for industry-standard classification.

## Categories

| Rank | Category | STRIDE Mapping | Common Threats |
|------|----------|---------------|----------------|
| A01 | Broken Access Control | Elevation of Privilege, Info Disclosure | IDOR, missing function-level auth, CORS misconfiguration |
| A02 | Cryptographic Failures | Info Disclosure | Unencrypted data, weak algorithms, exposed keys |
| A03 | Injection | Tampering | SQL injection, XSS, command injection, LDAP injection |
| A04 | Insecure Design | Multiple | Missing threat model, insecure business logic, no rate limiting |
| A05 | Security Misconfiguration | Multiple | Default credentials, unnecessary features, verbose errors |
| A06 | Vulnerable and Outdated Components | Multiple | Unpatched libraries, EOL frameworks |
| A07 | Identification and Authentication Failures | Spoofing | Weak passwords, missing MFA, session fixation |
| A08 | Software and Data Integrity Failures | Tampering | Unsigned updates, CI/CD pipeline compromise, deserialization |
| A09 | Security Logging and Monitoring Failures | Repudiation | Missing audit logs, no alerting, insufficient log retention |
| A10 | Server-Side Request Forgery (SSRF) | Info Disclosure | Internal service access via crafted URLs |

## Usage in Threat Models

When analyzing a web application, check each component against all 10 categories. For each applicable category, create a threat entry in the threat register with the OWASP reference for traceability.
