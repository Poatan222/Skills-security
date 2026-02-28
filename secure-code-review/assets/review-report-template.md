# Secure Code Review Report

**Application:** [Name]
**Framework:** [Java/Spring Boot | Python/Django | Python/Flask | Node.js/Express]
**Date:** [YYYY-MM-DD]
**Reviewer:** [Name / Agent]
**Scope:** [Full application | Specific module | Pull request #XXX]
**Status:** Draft

---

## Executive Summary

[2-3 sentences: scope of review, number of findings by severity, most critical issue]

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info | 0 |
| **Total** | **0** |

---

## Methodology

**Analysis techniques used:**
- [ ] Taint analysis (source-to-sink tracing)
- [ ] Data flow analysis (sensitive data tracking)
- [ ] Control flow analysis (auth/authz path verification)
- [ ] Framework-specific pattern matching

**Files reviewed:** [count or list]
**Entry points analyzed:** [list of routes/controllers]

---

## Findings

### [SCR-001] [Vulnerability Type]: [Brief Description]

**Severity:** Critical / High / Medium / Low
**CWE:** [CWE-XXX — Name]
**File:** `path/to/file:LINE`
**Analysis Method:** Taint / Data Flow / Control Flow / Pattern Match

#### Taint Path

```text
SOURCE: [where user input enters]
  -> [function/assignment]
  -> [function/assignment]
SINK: [dangerous operation]
SANITIZATION: None / Insufficient / Bypassed
```

#### Vulnerable Code

```
[code snippet with vulnerable line highlighted]
```

#### PoC Scenario

```bash
[curl command or exploit steps]
```

#### Impact

[What an attacker achieves]

#### Remediation

```
[fixed code]
```

#### References

- [CWE link]
- [Framework docs]

---

## Positive Findings

[List security controls that were correctly implemented — gives the development team credit]

- [ ] Parameterized queries used consistently in [module]
- [ ] CSRF protection enabled globally
- [ ] Authentication middleware applied to all protected routes

---

## Recommendations

1. [Highest priority fix]
2. [Second priority]
3. [Third priority]

## Appendix

### Dependency Notes

[Any flagged dependency issues]

### Assumptions

[Assumptions made during review]

### Out of Scope

[What was not reviewed and why]
