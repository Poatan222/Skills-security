# STRIDE Threat Patterns

Detailed threat patterns for each STRIDE category. Use when analyzing specific components.

## Spoofing

Attacker impersonates a legitimate entity.

| Pattern | Target | Example |
|---------|--------|---------|
| Credential stuffing | Authentication endpoints | Reuse of breached username/password pairs |
| Session hijacking | Session tokens | Stealing session cookies via XSS or network sniffing |
| Token forgery | JWT/OAuth tokens | Weak signing keys, algorithm confusion (none/HS256) |
| DNS spoofing | Service discovery | Redirecting traffic to attacker-controlled servers |
| Service impersonation | Internal microservices | No mTLS between services, attacker on same network |
| IP spoofing | IP-based access controls | Bypassing allowlists that rely on source IP |

**Key mitigations:** MFA, strong session management, mTLS, certificate pinning, token validation.

## Tampering

Attacker modifies data in transit or at rest.

| Pattern | Target | Example |
|---------|--------|---------|
| SQL injection | Database queries | Unparameterized queries allow data modification |
| Man-in-the-middle | Network traffic | Unencrypted HTTP between services |
| Parameter tampering | API request parameters | Modifying price, quantity, user ID in requests |
| Unsigned artifacts | CI/CD pipeline | Deploying tampered container images or packages |
| Log tampering | Audit logs | Attacker modifies logs to cover tracks |
| Cache poisoning | CDN / reverse proxy | Injecting malicious content into cached responses |

**Key mitigations:** Input validation, parameterized queries, TLS everywhere, signed artifacts, immutable logging.

## Repudiation

Actions cannot be traced or verified.

| Pattern | Target | Example |
|---------|--------|---------|
| Missing audit logs | Critical operations | No record of who deleted data or changed config |
| Unsigned transactions | Financial operations | No proof that a specific user authorized a payment |
| Shared credentials | Admin operations | Multiple admins using same account, cannot attribute |
| Log gaps | Time-sensitive events | Log rotation deletes evidence before review |

**Key mitigations:** Centralized logging, tamper-proof audit trails, individual accounts, digital signatures.

## Information Disclosure

Sensitive data leaks to unauthorized parties.

| Pattern | Target | Example |
|---------|--------|---------|
| Verbose error messages | API responses | Stack traces, database connection strings in errors |
| SSRF | Internal services | Attacker forces server to read internal resources |
| Directory traversal | File systems | Reading /etc/passwd or config files via path manipulation |
| Insecure direct object reference | API endpoints | Accessing other users' data by changing an ID |
| Unencrypted storage | Databases, S3 buckets | Sensitive data stored without encryption at rest |
| Side-channel leaks | Timing, error codes | Different response times reveal valid vs. invalid users |

**Key mitigations:** Generic error messages, input validation, encryption at rest/transit, access controls, SSRF protection.

## Denial of Service

Service is made unavailable.

| Pattern | Target | Example |
|---------|--------|---------|
| Resource exhaustion | CPU/memory/disk | Sending large payloads, zip bombs, regex DoS |
| Amplification attack | Public endpoints | Small request triggers large server-side computation |
| Connection exhaustion | TCP/HTTP connections | Slowloris, HTTP keep-alive abuse |
| Dependency failure | External services | Third-party API goes down, taking your service with it |
| Data store flooding | Databases | Unbounded writes filling disk, locking tables |

**Key mitigations:** Rate limiting, input size limits, circuit breakers, auto-scaling, request timeouts.

## Elevation of Privilege

Low-privilege user gains higher access.

| Pattern | Target | Example |
|---------|--------|---------|
| Broken access control | API authorization | Regular user accesses admin endpoints |
| IDOR | Object-level access | Accessing resources by guessing/incrementing IDs |
| Container escape | Container runtime | Breaking out of container to host OS |
| Privilege escalation via misconfiguration | IAM/RBAC | Overly permissive roles, wildcard permissions |
| Dependency confusion | Package managers | Malicious package with internal package name |

**Key mitigations:** Principle of least privilege, RBAC, input validation, container hardening, dependency pinning.
