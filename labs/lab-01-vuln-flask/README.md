# Lab 01 — Vulnerable Flask App

Expected detections:
- [CRITICAL] SQL Injection — /search?q= parameter
- [CRITICAL] SSTI (Jinja2) — /greet?name= -> RCE
- [HIGH] SSRF — /fetch?url= -> internal service access
- [HIGH] IDOR — /user/<id> no authorization check
- [HIGH] Stored XSS — /comment POST
- [HIGH] Hardcoded credentials (SECRET_KEY, DB_PASSWORD, AWS_KEY)
- [MEDIUM] Debug mode enabled in production

Test commands:
  SQLi:  curl "http://localhost:5000/search?q=' OR '1'='1"
  SSTI:  curl "http://localhost:5000/greet?name={{7*7}}"
  SSRF:  curl "http://localhost:5000/fetch?url=http://169.254.169.254/latest/meta-data/"
  IDOR:  curl "http://localhost:5000/user/2" (as user 1)
  XSS:   curl -X POST http://localhost:5000/comment -d "text=<script>alert(1)</script>"
