# Lab 02 — Vulnerable Terraform

Expected detections:
- [CRITICAL] Wildcard IAM policy Action:"*" Resource:"*"
- [CRITICAL] S3 bucket acl=public-read-write
- [CRITICAL] S3 block_public_acls=false
- [CRITICAL] SSH open to 0.0.0.0/0
- [CRITICAL] MySQL port open to 0.0.0.0/0
- [HIGH] IMDSv1 enabled (http_tokens=optional)
- [HIGH] Hardcoded secrets in user_data
- [HIGH] RDS publicly_accessible=true
- [HIGH] RDS storage_encrypted=false
- [HIGH] Hardcoded DB password
