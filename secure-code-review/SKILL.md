---
name: secure-code-review
description: >
  Perform security-focused code review using taint analysis, data flow
  analysis, control flow analysis, and framework-specific insecure
  patterns. Covers Java/Spring Boot, Python/Django/Flask, and
  Node.js/Express. Identifies vulnerabilities at the code level with
  exact file/line references, PoC scenarios, and remediation code.
  Trigger when user mentions "code review", "security review",
  "secure code review", "find vulnerabilities in this code",
  "audit this code", "is this code secure", "taint analysis",
  or uploads source code files, pull requests, or git diffs.
  Also trigger when user asks about insecure coding patterns,
  dangerous functions, or framework-specific security issues.
---

# Secure Code Review Skill

Find real vulnerabilities in source code using structured analysis techniques. Not a linter — this is how a senior AppSec engineer reviews code.

## Analysis Techniques

This skill uses four complementary analysis approaches:

1. **Taint Analysis** — Track user-controlled input (sources) through the code to dangerous operations (sinks). If tainted data reaches a sink without sanitization, it's a vulnerability.

2. **Data Flow Analysis** — Follow how data moves between functions, classes, and services. Identify where sensitive data is created, transformed, stored, and exposed.

3. **Control Flow Analysis** — Examine authentication checks, authorization gates, error handling paths, and conditional branches. Identify paths where security checks can be bypassed.

4. **Framework-Specific Pattern Matching** — Each framework has known insecure defaults, dangerous configurations, and common developer mistakes. Match code against these patterns.

## Workflow

### Step 1: Understand the Code Context

Before reviewing, establish:

**From the user (ask if not provided):**
- What does this code do? (One sentence)
- What framework and language version?
- Is this a new feature, a bugfix, or a full application review?
- What's the trust boundary? (API endpoint, internal service, CLI tool)
- Any known security requirements? (Auth model, data sensitivity)

**From the code itself:**
- Entry points (routes, handlers, controllers)
- Dependencies (check for known vulnerable packages)
- Configuration files (secrets, debug mode, CORS, CSP)
- Database interaction patterns (ORM vs raw queries)
- Authentication/authorization middleware

### Step 2: Identify Sources and Sinks

**Sources** (user-controlled input — these are tainted):

| Framework | Sources |
|-----------|---------|
| Spring Boot | `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `HttpServletRequest.getParameter()`, `@CookieValue` |
| Django | `request.GET`, `request.POST`, `request.body`, `request.FILES`, `request.META`, `request.COOKIES`, URL kwargs |
| Flask | `request.args`, `request.form`, `request.json`, `request.files`, `request.headers`, `request.cookies` |
| Express | `req.params`, `req.query`, `req.body`, `req.headers`, `req.cookies`, `req.file` |

**Sinks** (dangerous operations — tainted data must not reach these unsanitized):

| Category | Sinks |
|----------|-------|
| SQL Injection | Raw SQL queries, string concatenation in queries, `.raw()`, `.extra()`, template strings in queries |
| Command Injection | `Runtime.exec()`, `ProcessBuilder`, `os.system()`, `subprocess`, `child_process.exec()` |
| XSS | Direct HTML rendering, template `safe`/`raw` filters, `dangerouslySetInnerHTML`, `res.send()` with user input |
| Path Traversal | File operations with user-controlled paths, `new File()`, `open()`, `fs.readFile()` |
| Deserialization | `ObjectInputStream`, `pickle.loads()`, `yaml.load()` (unsafe), `JSON.parse()` of untrusted complex objects |
| SSRF | HTTP clients with user-controlled URLs, `requests.get()`, `fetch()`, `RestTemplate` |
| LDAP Injection | LDAP queries with string concatenation |
| Template Injection | Template rendering with user-controlled template strings |

Load framework-specific details from `references/frameworks/`.

### Step 3: Trace Taint Paths

For each source identified in Step 2:

1. Follow the data through assignments, function calls, and transformations
2. Check if the data passes through any sanitization or validation
3. If it reaches a sink unsanitized — flag it as a finding
4. Document the full path: source -> [transforms] -> sink

**Sanitization that breaks taint:**

| Sink Type | Valid Sanitization |
|-----------|--------------------|
| SQLi | Parameterized queries, ORM methods (without `.raw()`/`.extra()`) |
| XSS | Context-aware output encoding, auto-escaping templates (when not bypassed) |
| Command Injection | Allowlist validation, avoid shell entirely, use array-based exec |
| Path Traversal | Canonicalize + validate against allowed directory |
| SSRF | URL parsing + allowlist of permitted hosts |

**Sanitization that does NOT break taint (common mistakes):**

| Approach | Why It Fails |
|----------|-------------|
| Blocklist filtering (e.g., strip `<script>`) | Bypassable with encoding, alternate tags |
| `htmlspecialchars()` without ENT_QUOTES | Misses attribute context XSS |
| URL validation by string matching | Bypassable with open redirect, IP formats |
| Input length limits | Doesn't prevent injection, just limits payload size |
| WAF (alone) | Defense in depth, not a code-level fix |

### Step 4: Analyze Control Flow

Check these security-critical control flow patterns:

**Authentication gates:**
- Is every route/endpoint protected by auth middleware?
- Are there routes that should be protected but aren't?
- Can auth middleware be bypassed via path manipulation?

**Authorization checks:**
- Is object-level authorization enforced (not just role-based)?
- Are authorization checks applied consistently across all HTTP methods?
- Can authorization be bypassed by accessing the resource via a different code path?

**Error handling:**
- Do catch blocks leak sensitive info (stack traces, DB errors, internal paths)?
- Do error paths skip security checks that the happy path enforces?
- Is there a global error handler, or do some routes have unhandled exceptions?

**Race conditions:**
- Are there check-then-act patterns without locking?
- Can concurrent requests bypass validation (e.g., balance checks)?

### Step 5: Check Framework-Specific Patterns

Load the appropriate framework reference from `references/frameworks/`:

- `references/frameworks/spring-boot.md` for Java/Spring Boot
- `references/frameworks/django-flask.md` for Python/Django/Flask
- `references/frameworks/express-node.md` for Node.js/Express

Each reference contains framework-specific insecure defaults, dangerous configurations, common anti-patterns, and parser attack surfaces.

### Step 6: Check Dependencies

- Look at `pom.xml` / `build.gradle` (Java), `requirements.txt` / `Pipfile` (Python), `package.json` (Node)
- Flag obviously outdated major versions
- Check for packages known to have critical vulnerabilities (e.g., `log4j` < 2.17, `lodash` prototype pollution, `PyYAML` unsafe load)
- Note: a full SCA scan is out of scope for code review, but obvious issues should be flagged

### Step 7: Generate Report

For each finding, produce:

```markdown
## [SCR-001] [Vulnerability Type]: [Brief Description]

**Severity:** Critical / High / Medium / Low
**CWE:** [CWE-XXX — Name]
**File:** `path/to/file.java:LINE_NUMBER`
**Analysis Method:** Taint / Data Flow / Control Flow / Pattern Match

### Taint Path (if applicable)
` ` `
SOURCE: request.getParameter("id") [UserController.java:42]
  -> passed to: findById(id) [UserService.java:18]
  -> passed to: "SELECT * FROM users WHERE id = " + id [UserDAO.java:33]
SINK: Raw SQL concatenation [UserDAO.java:33]
SANITIZATION: None
` ` `

### Vulnerable Code
` ` `java
// UserDAO.java:33
public User findById(String id) {
    String query = "SELECT * FROM users WHERE id = " + id;  // VULNERABLE
    return jdbcTemplate.queryForObject(query, new UserRowMapper());
}
` ` `

### PoC Scenario
[How an attacker would exploit this, with example payload]
` ` `bash
curl "https://api.target.com/users?id=1' UNION SELECT username,password FROM admins--"
` ` `

### Remediation
` ` `java
// FIXED: Use parameterized query
public User findById(String id) {
    String query = "SELECT * FROM users WHERE id = ?";
    return jdbcTemplate.queryForObject(query, new UserRowMapper(), id);
}
` ` `

### References
- [CWE link]
- [Framework-specific documentation link]
```

## Edge Cases

| Scenario | Action |
|----------|--------|
| User provides only a code snippet, not full application | Review the snippet, note assumptions, flag if context would change the assessment |
| Code uses a custom framework or unusual patterns | Fall back to general taint/dataflow analysis. Note that framework-specific checks were skipped. |
| Code is obfuscated or minified | Ask for unminified source. Note that obfuscated code cannot be reliably reviewed. |
| Large codebase (thousands of files) | Focus on entry points (controllers/routes), auth middleware, and data access layers first |
| Pull request review (diff only) | Review the diff but check surrounding context. A safe change can introduce a vuln in combination with existing code. |
| Code has existing security annotations/decorators | Verify they're applied correctly — `@PreAuthorize` with wrong SpEL, `@login_required` on the wrong method |

## File Structure

```text
secure-code-review/
├── SKILL.md                              # This file
├── references/
│   ├── frameworks/
│   │   ├── spring-boot.md                # Java/Spring Boot insecure patterns
│   │   ├── django-flask.md               # Python/Django/Flask insecure patterns
│   │   └── express-node.md               # Node.js/Express insecure patterns
│   └── attack-patterns/
│       ├── taint-analysis-guide.md       # How to trace taint paths systematically
│       └── parser-differentials.md       # URL/path/header parsing inconsistencies
└── assets/
    └── review-report-template.md         # Blank report template
```
