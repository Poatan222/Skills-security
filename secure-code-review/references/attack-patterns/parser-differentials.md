# Parser Differentials

Security vulnerabilities caused by different components parsing the same input differently. When a security filter and the application backend disagree on how to parse a URL, path, or header — an attacker can bypass the filter.

## URL Parsing Differentials

### Path Normalization Mismatch

```text
Security filter sees:  /public/../admin/users  -> blocks "/admin"
Application sees:      /admin/users            -> serves admin page

Security filter sees:  /admin/users;.js        -> allows (looks like .js file)
Application sees:      /admin/users            -> serves admin endpoint (ignores ;.js)

Security filter sees:  /public/%2e%2e/admin    -> allows (%2e%2e is not decoded)
Application sees:      /admin                  -> decodes %2e%2e as ".."
```

### Framework-Specific Path Parsing

| Framework | Behavior | Exploit |
|-----------|----------|---------|
| Spring Boot | Ignores trailing `/` and `;` path params | `/admin/users;bypass=true` |
| Spring Boot | `//` is collapsed to `/` | `//admin/users` bypasses `/admin/**` filter |
| Express | `req.path` decodes URL, `req.originalUrl` doesn't | Filter on originalUrl, logic on path |
| Django | Appends trailing slash (APPEND_SLASH=True) | `/admin` redirects to `/admin/`, bypass if filter only checks `/admin` |
| Flask | Strict slashes by default | `/admin` vs `/admin/` are different routes |
| Nginx + backend | Nginx normalizes before proxying, backend sees different path | Double encoding bypasses |

### Double Encoding

```text
Normal:     ../     -> blocked by WAF
URL-encoded: %2e%2e%2f -> may be blocked
Double-encoded: %252e%252e%252f -> passes WAF, decoded by backend

Test: If the backend decodes twice, send %252e%252e%252f
WAF sees: %252e%252e%252f (not a traversal)
Backend round 1: %2e%2e%2f
Backend round 2: ../ (traversal!)
```

## Host Header Parsing

### Host Header Injection

```text
# Multiple Host headers
Host: legitimate.com
Host: attacker.com
# Which does the app use? Which does the reverse proxy use?

# Port confusion
Host: legitimate.com:@attacker.com

# Absolute URL in request line
GET https://attacker.com/path HTTP/1.1
Host: legitimate.com
# Some servers use the request line URL, some use Host header
```

### X-Forwarded-Host Abuse

```text
# If app uses X-Forwarded-Host for generating links (password reset, etc.)
Host: legitimate.com
X-Forwarded-Host: attacker.com
# Password reset link points to attacker.com -> token theft
```

## Content-Type Parsing

### Content-Type Confusion

```text
# API expects JSON but also parses form data
Content-Type: application/x-www-form-urlencoded
# This enables CSRF on APIs that rely on "JSON APIs aren't CSRF-vulnerable"

# Charset tricks
Content-Type: application/json; charset=utf-7
# May cause different parsing of special characters

# Multipart boundary confusion
Content-Type: multipart/form-data; boundary=----XYZ
Content-Type: application/json
# Which Content-Type does the server use? Some check first, some check last.
```

## JSON Parsing Differentials

### Duplicate Keys

```json
{"role": "user", "role": "admin"}
```

- RFC 7159: behavior is undefined for duplicate keys
- Most parsers use the **last** value
- Some parsers use the **first** value
- If security check uses one parser and business logic uses another — bypass

### Comment and Trailing Comma Handling

```json
{"role": "admin"/* comment */, }
```

- Standard JSON doesn't allow comments or trailing commas
- Some lenient parsers accept them
- WAF might reject as invalid JSON (so it skips inspection)
- Backend lenient parser accepts it

## Request Smuggling (HTTP Desync)

### CL.TE (Content-Length vs Transfer-Encoding)

```text
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- Front-end uses Content-Length, sees 13 bytes
- Back-end uses Transfer-Encoding, sees chunked ending at "0\r\n\r\n"
- "SMUGGLED" is treated as the start of the next request

### TE.CL

```text
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

- Front-end uses Transfer-Encoding, reads chunks
- Back-end uses Content-Length, reads only 3 bytes

## How to Use This in Code Review

When reviewing security middleware, auth filters, or input validation:

1. **Check:** Does the filter and the business logic use the same parser/normalizer?
2. **Check:** Are URLs decoded the same number of times in both paths?
3. **Check:** Does the app handle `//`, `../`, `%2e`, trailing slashes, semicolons consistently?
4. **Check:** Is Content-Type validated before parsing the body?
5. **Check:** Are there multiple ways for the same data to enter the application (headers, query params, body)?
