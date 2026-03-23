---
name: sec-recon
description: >
  Attack surface reconnaissance skill. Maps subdomains, exposed services,
  leaked secrets, misconfigured cloud storage, and passive intel from public
  sources. Trigger on /sec recon, or when user asks about attack surface,
  subdomain enum, exposed secrets, passive recon, what can an attacker see,
  Google dork, find exposed assets, or OSINT on company/target.
---

# sec-recon — Attack Surface Reconnaissance

Map what's exposed before an attacker does. Produces an authoritative attack
surface inventory with risk-ranked findings.

**Scope rule:** Only run against targets the user owns or is explicitly
authorized to assess. Confirm before executing active techniques.

---

## Phase 1: Passive Recon (No active probing)

### 1.1 DNS and Subdomain Enumeration

Certificate transparency logs — pure passive, no target contact:
```bash
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
  python3 -c "import sys,json; [print(r['name_value']) for r in json.load(sys.stdin)]" | \
  sort -u

subfinder -d example.com -silent
amass enum -passive -d example.com
```

Collect: all subdomains/IPs, MX/NS/TXT records, CNAME chains for takeover candidates.

Subdomain takeover check — for each CNAME, verify target service is still registered:

| CNAME Pattern | Service | Takeover Possible? |
|---------------|---------|-------------------|
| *.s3.amazonaws.com | AWS S3 | Yes — if bucket unclaimed |
| *.github.io | GitHub Pages | Yes — if repo deleted |
| *.azurewebsites.net | Azure Web Apps | Yes — if app deleted |
| *.netlify.app | Netlify | Yes — if site removed |
| *.herokuapp.com | Heroku | Yes — if dyno removed |

### 1.2 Exposed Secrets Scanning

GitHub/GitLab dork queries — run these manually or via GitHub search API:
```
org:<target-org> password
org:<target-org> api_key
org:<target-org> secret_key
org:<target-org> aws_access_key
org:<target-org> BEGIN RSA PRIVATE KEY
org:<target-org> .env
org:<target-org> database_url
org:<target-org> AKIA
```

In-browser JavaScript secrets — extract JS files and scan:
```bash
curl -s https://target.com | grep -oP 'src="[^"]+\.js"' | sed 's/src="//;s/"//'
grep -E "(api_key|apikey|secret|password|token|auth|bearer|private_key|AWS_)" extracted.js
grep -E "AKIA[0-9A-Z]{16}" extracted.js
grep -E "[0-9a-f]{32,64}" extracted.js
```

Cloud storage exposure checks:
```bash
aws s3 ls s3://<bucket-name> --no-sign-request 2>/dev/null
curl -s https://<bucket-name>.s3.amazonaws.com/
curl -s "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"
curl -s https://storage.googleapis.com/<bucket-name>/
```

### 1.3 Technology Fingerprinting

```bash
curl -s -I https://target.com | grep -E "(Server:|X-Powered-By:|X-Framework:|Via:)"
```

High-value paths to probe — just check existence:
```
/.git/config          # Exposed git repo — source code leak
/.env                 # Environment variables with secrets
/actuator/env         # Spring Boot — full env dump
/actuator/health      # Spring Boot service info
/graphql              # GraphQL endpoint
/swagger.json         # API spec disclosure
/openapi.json         # API spec disclosure
/api/v1/users         # Potentially unauthenticated API
/admin                # Admin panel
/.DS_Store            # macOS metadata leak
/robots.txt           # Disavowed paths = attack surface
/sitemap.xml          # Full URL inventory
```

### 1.4 OSINT

Shodan queries if API key available:
```
org:"Company Name"
ssl:"company.com"
http.title:"Company App"
hostname:company.com port:22,3389,5900
```

Look for: exposed databases (3306, 5432, 27017, 6379), remote access (22, 3389, 5900),
dev/staging environments on non-standard ports.

---

## Phase 2: Active Recon (Requires scope confirmation)

**Always confirm first:** "I'm about to send active probes to `<target>`. Confirming authorized?"

### 2.1 Port and Service Scanning
```bash
nmap -T4 -F --open -sV <target-ip>          # Fast top-port scan
nmap -p- -T3 --open <target-ip>             # Full port scan
nmap -sV -sC -p <open-ports> <target-ip>    # Service version + scripts
```

High-risk open port findings:
| Port | Service | Risk |
|------|---------|------|
| 22 | SSH | Brute-force surface, key exposure |
| 23 | Telnet | Cleartext credentials |
| 3306 | MySQL | Direct DB access |
| 5432 | PostgreSQL | Direct DB access |
| 27017 | MongoDB | Often unauthenticated |
| 6379 | Redis | Often unauthenticated, RCE via config |
| 9200 | Elasticsearch | Data exposure, often open |
| 2375/2376 | Docker API | Container escape, RCE |
| 10250 | Kubelet API | K8s node takeover |
| 3389 | RDP | Brute-force, BlueKeep |
| 5900 | VNC | Often weak/no auth |

### 2.2 Directory Discovery
```bash
ffuf -w /usr/share/wordlists/dirb/common.txt \
  -u https://target.com/FUZZ \
  -mc 200,301,302,403 \
  -o recon-dirs.json

ffuf -w backup-extensions.txt \
  -u https://target.com/FUZZ \
  -e .bak,.old,.backup,.zip,.tar.gz,.sql
```

---

## Phase 3: Attack Surface Map Output

Compile all findings into structured output:

```markdown
## Attack Surface Map: <target>

### External Hostnames
| Hostname | IP | Services | Notes |

### Exposed Services (Flagged)
| Host | Port | Service | Risk | Finding |

### Cloud Storage
| Provider | Bucket/Container | Public? | Contents Preview |

### Exposed Secrets
| Source | Secret Type | Evidence | Risk |

### Subdomain Takeover Candidates
| Subdomain | CNAME Target | Service | Status |

### High-Value Endpoints
| URL | Response | Notes |
```

---

## Severity Ratings

| Finding | Severity |
|---------|----------|
| Exposed AWS/GCP/Azure credentials | Critical |
| Subdomain takeover possible | Critical |
| Unauthenticated database access | Critical |
| Docker API exposed (no auth) | Critical |
| Kubelet API exposed | Critical |
| Private key or hardcoded secret in public repo | Critical |
| S3 bucket publicly writable | Critical |
| Admin panel with no auth | High |
| Exposed .env or config file | High |
| Exposed .git directory | High |
| Swagger/OpenAPI spec disclosure | Medium |
| Verbose server headers | Low |

---

## Output

Write findings to `RECON-REPORT.md`. Terminal summary:
```
[sec-recon] Attack Surface Summary: <target>
Subdomains discovered: XX  |  Live hosts: XX
Exposed services:      XX  |  Cloud storage: XX (public: X)
Secret exposures:      XX  |  Takeover candidates: XX
Risk: CRITICAL/HIGH/MEDIUM/LOW
Full report: RECON-REPORT.md
```

## File Structure
```
sec-recon/
├── SKILL.md
├── references/
│   ├── subdomain-wordlist.txt
│   ├── secret-patterns.txt
│   ├── high-value-paths.txt
│   └── takeover-signatures.md
└── scripts/
    ├── js_secret_scanner.py
    ├── bucket_checker.py
    └── cname_takeover_check.py
```
