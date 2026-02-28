# Mitigation Patterns

Standard mitigations organized by threat category. Select the most appropriate for each identified threat.

## Authentication and Identity

| Mitigation | Addresses | Implementation Notes |
|------------|-----------|---------------------|
| Multi-factor authentication (MFA) | Spoofing | Enforce for all user accounts, prefer FIDO2/WebAuthn over SMS |
| Mutual TLS (mTLS) | Spoofing (service-to-service) | Certificate-based auth between microservices |
| OAuth 2.0 + PKCE | Spoofing | For public clients (SPAs, mobile apps) |
| API key rotation | Spoofing | Rotate keys every 90 days, revoke on compromise |
| Session timeout | Spoofing | 15-min idle timeout, 8-hour absolute timeout |

## Data Protection

| Mitigation | Addresses | Implementation Notes |
|------------|-----------|---------------------|
| TLS 1.3 everywhere | Tampering, Info Disclosure | No exceptions for internal traffic |
| Encryption at rest (AES-256) | Info Disclosure | Use KMS-managed keys, not application-managed |
| Input validation | Tampering | Allowlist validation, reject unexpected input |
| Parameterized queries | Tampering (SQLi) | Never concatenate user input into queries |
| Output encoding | Info Disclosure (XSS) | Context-aware encoding (HTML, JS, URL) |
| Data masking | Info Disclosure | Mask PII in logs, non-production environments |

## Access Control

| Mitigation | Addresses | Implementation Notes |
|------------|-----------|---------------------|
| RBAC / ABAC | Elevation of Privilege | Principle of least privilege, deny by default |
| Object-level authorization | Elevation of Privilege (IDOR) | Verify ownership on every object access |
| Function-level authorization | Elevation of Privilege | Check permissions on every API endpoint |
| Network segmentation | Multiple | Isolate tiers, restrict lateral movement |
| Zero Trust architecture | Multiple | Verify every request regardless of network location |

## Logging and Monitoring

| Mitigation | Addresses | Implementation Notes |
|------------|-----------|---------------------|
| Centralized logging (SIEM) | Repudiation | Ship logs to immutable central store |
| Audit trail for critical operations | Repudiation | Log who, what, when, from where |
| Alerting on anomalies | Multiple | Alert on auth failures, privilege changes, data access spikes |
| Log integrity protection | Repudiation | Append-only logs, hash chains, or write-once storage |

## Availability

| Mitigation | Addresses | Implementation Notes |
|------------|-----------|---------------------|
| Rate limiting | Denial of Service | Per-user/IP rate limits at API gateway |
| Circuit breakers | Denial of Service | Fail gracefully when dependencies are down |
| Auto-scaling | Denial of Service | Scale horizontally under load |
| Input size limits | Denial of Service | Max request body, max file upload size |
| Request timeouts | Denial of Service | Timeout slow requests, prevent resource holding |
| CDN / DDoS protection | Denial of Service | Absorb volumetric attacks at edge |
