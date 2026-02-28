# Prowler GCP Reference

## Prerequisites

**Authentication:**

- Application Default Credentials (`gcloud auth application-default login`)
- Service account key file
- Workload Identity (for GKE-hosted scans)

**Required permissions:**

- `roles/viewer` on target projects
- `roles/iam.securityReviewer` for IAM checks
- `roles/cloudasset.viewer` for asset inventory checks

## Common Scan Commands

```bash
# Full GCP scan
prowler gcp

# Scan specific project
prowler gcp --project-ids [PROJECT_ID]

# Scan specific services
prowler gcp --services iam compute storage

# Scan against CIS GCP Benchmark
prowler gcp --compliance cis_2.0_gcp

# Output formats
prowler gcp -M csv json-ocsf html

# List GCP-specific checks
prowler gcp --list-checks
```

## High-Priority GCP Checks

| Check ID | Service | Why It Matters |
|----------|---------|----------------|
| iam_sa_no_user_managed_keys | IAM | Service account keys are long-lived credentials |
| compute_firewall_allow_ingress_from_internet | Compute | Open firewall rules to internet |
| storage_bucket_uniform_access | Storage | Uniform access prevents ACL-based misconfigs |
| logging_sink_configured | Logging | Audit logs must be exported and retained |
| compute_instance_public_ip | Compute | VMs with public IPs increase attack surface |
| kms_key_rotation_enabled | KMS | Encryption key rotation |
