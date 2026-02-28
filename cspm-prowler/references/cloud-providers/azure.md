# Prowler Azure Reference

## Prerequisites

**Authentication options:**

1. **Service Principal with Secret** — For automated/scheduled scans
2. **Azure CLI authentication** — For interactive scans (`az login`)
3. **Managed Identity** — For scans running inside Azure (VMs, Functions)

**Required permissions:**

- `Reader` role on target subscriptions
- `Security Reader` for Defender for Cloud checks
- `Directory Reader` for Entra ID checks (optional)

## Installation

```bash
# Via pip
pip install prowler

# Via Docker
docker run -it --rm \
  -e AZURE_CLIENT_ID=xxx \
  -e AZURE_CLIENT_SECRET=xxx \
  -e AZURE_TENANT_ID=xxx \
  ghcr.io/prowler-cloud/prowler:latest azure
```

## Common Scan Commands

```bash
# Full Azure scan (uses az login credentials)
prowler azure

# Scan with service principal
prowler azure \
  --sp-env-auth \
  --tenant-id [TENANT_ID]

# Scan specific subscription
prowler azure --subscription-ids [SUB_ID]

# Scan specific services
prowler azure --services storage defender iam

# Scan against CIS Azure Benchmark
prowler azure --compliance cis_2.0_azure

# Output formats
prowler azure -M csv json-ocsf html

# List Azure-specific checks
prowler azure --list-checks
```

## High-Priority Azure Checks

| Check ID | Service | Why It Matters |
|----------|---------|----------------|
| storage_blob_public_access_level_is_disabled | Storage | Public blob access = data exposure |
| iam_no_custom_subscription_owner_roles | IAM | Custom owner roles can bypass controls |
| defender_ensure_defender_for_containers | Defender | Container workload protection |
| network_nsg_ssh_restricted | Network | SSH open to internet on NSGs |
| keyvault_key_rotation_enabled | Key Vault | Key rotation for compliance |
| monitor_diagnostic_settings_enabled | Monitor | Audit logging must be active |
