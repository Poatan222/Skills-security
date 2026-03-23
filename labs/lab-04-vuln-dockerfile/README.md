# Lab 04 — Vulnerable Dockerfile + docker-compose

Expected detections:
- [CRITICAL] Privileged container (docker-compose)
- [CRITICAL] Docker socket mounted — container escape
- [HIGH] Running as root (no USER directive)
- [HIGH] Secrets in ENV layers (DB_PASSWORD, AWS_SECRET, API_KEY)
- [HIGH] COPY . copies .git, .env, secrets into image
- [HIGH] SYS_ADMIN capability
- [HIGH] host network mode
- [MEDIUM] FROM ubuntu:latest — mutable tag
- [MEDIUM] curl | bash in RUN step
- [MEDIUM] SSH exposed (port 22)
- [MEDIUM] No HEALTHCHECK
- [LOW] No resource limits
