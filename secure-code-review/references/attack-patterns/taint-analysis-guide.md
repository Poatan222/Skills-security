# Taint Analysis Guide

A systematic approach to tracing user-controlled input through code to identify injection vulnerabilities.

## Core Concept

```text
SOURCE (user input) --> [propagation] --> SINK (dangerous operation)
                              |
                        SANITIZER (breaks taint if correct)
```

If tainted data reaches a sink without passing through a valid sanitizer, it's a vulnerability.

## Step-by-Step Process

### 1. Enumerate All Sources

Start at entry points and list every source of external input:

**Direct sources (always tainted):**
- HTTP request parameters (query, body, headers, cookies, path)
- File uploads (filename, content, content-type)
- WebSocket messages
- Database values that were originally user-provided
- Environment variables set by external systems
- Message queue payloads
- External API responses (if attacker can influence the external API)

**Indirect sources (conditionally tainted):**
- Database reads (tainted if the stored value was user-provided and not sanitized before storage)
- Cache reads (same as database)
- Configuration files (tainted if editable by users)
- Log files (tainted if they contain user input and are later parsed)

### 2. Enumerate All Sinks

For each sink category, list the specific functions/methods in the codebase:

| Category | What to Search For |
|----------|-------------------|
| SQL | `query()`, `.raw()`, `.extra()`, `execute()`, `createQuery()`, template literals near DB calls |
| Command | `exec()`, `system()`, `popen()`, `spawn()`, `ProcessBuilder`, `Runtime.exec()` |
| File | `open()`, `readFile()`, `writeFile()`, `sendFile()`, `Paths.get()`, `new File()` |
| XSS | `innerHTML`, `document.write()`, `res.send()`, `mark_safe()`, `\|safe`, `render_template_string()` |
| SSRF | `requests.get()`, `fetch()`, `axios()`, `RestTemplate`, `HttpClient`, `URL.openConnection()` |
| Deserialize | `pickle.loads()`, `yaml.load()`, `ObjectInputStream`, `eval()`, `new Function()` |
| LDAP | `search()` with string-concatenated filters |
| XPath | `evaluate()` with string-concatenated expressions |
| Template | `render_template_string()`, `ejs.render()` with user-controlled template |

### 3. Trace Each Source Forward

For each source, follow the data:

```text
req.body.name                          [SOURCE - tainted]
  |
  v = req.body.name                    [assignment - still tainted]
  |
  sanitized = validator.escape(v)      [sanitizer - check if valid for target sink]
  |
  db.query(`... WHERE name = '${v}'`)  [SINK - uses 'v' not 'sanitized'!]
                                       [VULNERABILITY: tainted data reaches sink]
```

**Track through:**
- Variable assignments
- Function parameters (follow into function body)
- Return values (follow back to caller)
- Object properties (`user.name = tainted` means `user.name` is tainted)
- Array elements
- String concatenation (taint propagates)
- Ternary/conditional (both branches may be tainted)

### 4. Validate Sanitizers

When you find a sanitizer on a taint path, verify:

| Question | If No |
|----------|-------|
| Is the sanitizer appropriate for this sink type? | Invalid — taint continues. HTML encoding doesn't prevent SQLi. |
| Is the sanitizer applied to the exact variable that reaches the sink? | Invalid — sanitizer on copy, original still tainted. |
| Can the sanitizer be bypassed? (encoding, double encoding, truncation) | Partially valid — note bypass conditions. |
| Is the sanitizer applied before every path to the sink? | Invalid — if any code path skips the sanitizer. |

### 5. Check for Taint Laundering

Common patterns where taint is "lost" but data is still dangerous:

```python
# Taint laundering via database (Second-Order Injection)
db.save(user_input)       # Stored without sanitization
# ... later ...
value = db.read()         # "Clean" read, but data is still attacker-controlled
db.raw_query(value)       # Second-order SQLi

# Taint laundering via serialization
data = json.dumps({"q": user_input})
# ... passed between services ...
parsed = json.loads(data)
db.query(parsed["q"])     # Still tainted despite serialize/deserialize

# Taint laundering via logging
log.info(f"Search: {user_input}")
# ... log analysis system reads log ...
# If log is parsed and values extracted — SSRF/injection in log analysis tool
```

## Taint Tracking Shortcuts

For large codebases, use this focused approach:

1. **Grep for sinks first** — find all dangerous function calls
2. **Trace backward from each sink** — where does the argument come from?
3. **If the argument traces back to a source without sanitization** — finding confirmed
4. **Focus on crossing trust boundaries** — data that passes from controller to service to DAO is high priority

```bash
# Example: find potential SQLi sinks in Java
grep -rn "createQuery\|createNativeQuery\|\.raw\|\.extra\|execute.*+" --include="*.java" src/
# Then trace each match backward to see if the argument is user-controlled
```
