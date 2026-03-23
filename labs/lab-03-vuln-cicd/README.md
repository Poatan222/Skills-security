# Lab 03 — Vulnerable GitHub Actions

Expected detections:
- [CRITICAL] pull_request_target + checkout of PR head SHA (code injection)
- [CRITICAL] Expression injection: ${{ github.event.pull_request.title }} in run:
- [CRITICAL] Expression injection: ${{ github.head_ref }} in run:
- [CRITICAL] Self-hosted runner on public-facing workflow
- [CRITICAL] Hardcoded API key in env
- [HIGH] actions/checkout@v3 — mutable tag not SHA-pinned
- [HIGH] id-token:write on all jobs (not just deploy)
- [HIGH] contents:write — overly permissive
- [HIGH] Secret passed to unvetted third-party action (some-random-publisher)
- [HIGH] actions:write permission — workflow modification
- [MEDIUM] No environment protection rules on production deployment
