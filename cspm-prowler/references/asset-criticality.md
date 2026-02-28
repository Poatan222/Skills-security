# Cloud Asset Criticality

Map cloud resources to criticality tiers. Used to elevate or de-prioritize Prowler findings based on what the resource actually does.

## Tier Definitions

| Tier | Label | Description |
|------|-------|-------------|
| 1 | Crown Jewels | Production databases, customer-facing APIs, auth services, payment processing |
| 2 | Business Critical | CI/CD pipelines, monitoring, internal APIs, identity providers |
| 3 | Standard | Dev/staging environments, internal tools, non-sensitive workloads |

## Resource Mapping

Customize the patterns below for your environment. Use resource name patterns, tags, or account/project IDs.

### By Account/Project

| Account/Project ID | Tier | Owner | Description |
|--------------------|------|-------|-------------|
| [prod-account-id] | 1 | @platform-team | Production workloads |
| [staging-account-id] | 3 | @qa-team | Staging/QA |
| [dev-account-id] | 3 | @dev-team | Development |
| [security-account-id] | 2 | @security-team | Security tooling |

### By Resource Tag

| Tag Key | Tag Value | Tier |
|---------|-----------|------|
| environment | production | 1 |
| environment | staging | 3 |
| data-classification | restricted | 1 |
| data-classification | confidential | 2 |
| data-classification | internal | 3 |

### By Service Pattern

| Resource Pattern | Tier | Reasoning |
|-----------------|------|-----------|
| RDS/CloudSQL instances in prod | 1 | Production databases hold customer data |
| S3/GCS buckets with `backup` or `logs` prefix | 2 | Contain operational data |
| IAM root/org-admin accounts | 1 | Full control of cloud environment |
| CloudTrail/Audit Log configs | 2 | Detection capability — blind spot if misconfigured |
| VPC/VNet/Firewall rules on prod | 1 | Network boundary of production |

## Unknown Resources

If a resource does not match any pattern: default to Tier 2 and flag for asset management review. Do not default to Tier 3 — unknown resources in cloud may be shadow IT.
