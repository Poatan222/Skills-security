# Lab 05 — Vulnerable Node.js App

Expected detections:
- [CRITICAL] SQL Injection — /users?name= (string concat)
- [CRITICAL] SQL Injection — /login (direct interpolation)
- [CRITICAL] Command Injection — /ping?host= (exec with user input)
- [CRITICAL] Insecure Deserialization — /restore (RCE via node-serialize)
- [HIGH] Path Traversal — /file?name= (no sanitization)
- [HIGH] Hardcoded DB credentials (password: password123)
- [HIGH] No rate limiting on /login (brute force)
- [MEDIUM] No input validation across all endpoints
