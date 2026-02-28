# Prowler AWS Reference

## Prerequisites

**Required IAM permissions (attach to role or user):**

- `SecurityAudit` (AWS managed policy)
- `ViewOnlyAccess` (AWS managed policy)

For multi-account scanning, create a cross-account role `ProwlerRole` in each target account with these policies, and a trust policy allowing the scanning account to assume it.

## Installation

```bash
# Via pip (recommended)
pip install prowler

# Via Docker
docker run -it --rm \
  -v ~/.aws:/root/.aws \
  ghcr.io/prowler-cloud/prowler:latest aws
```

## Common Scan Commands

```bash
# Full AWS scan (all checks, all regions)
prowler aws

# Scan specific services
prowler aws --services s3 iam ec2 rds

# Scan against CIS Benchmark
prowler aws --compliance cis_2.0_aws

# Scan against PCI-DSS
prowler aws --compliance pci_3.2.1_aws

# Scan specific regions
prowler aws --region us-east-1 eu-west-1

# Scan with role assumption (multi-account)
prowler aws -R arn:aws:iam::123456789012:role/ProwlerRole

# Output formats
prowler aws -M csv json-ocsf html

# Scan only critical and high severity
prowler aws --severity critical high

# List all available checks
prowler aws --list-checks

# List available compliance frameworks
prowler aws --list-compliance
```

## High-Priority AWS Checks

These checks commonly surface the most critical findings:

| Check ID | Service | Why It Matters |
|----------|---------|----------------|
| iam_root_mfa_enabled | IAM | Root account without MFA = full account compromise |
| iam_root_hardware_mfa_enabled | IAM | Hardware MFA is stronger than virtual |
| s3_account_level_public_access_blocks | S3 | Prevents accidental public exposure of all buckets |
| s3_bucket_public_access | S3 | Individual bucket public access |
| cloudtrail_multi_region_enabled | CloudTrail | Without this, you have no visibility into API calls |
| ec2_securitygroup_allow_ingress_from_internet_to_any_port | EC2 | Open security groups = direct attack surface |
| rds_instance_storage_encrypted | RDS | Unencrypted databases with sensitive data |
| guardduty_is_enabled | GuardDuty | Threat detection must be active |
| kms_cmk_rotation_enabled | KMS | Key rotation is a compliance requirement |

## AWS Security Hub Integration

Push Prowler findings to Security Hub for centralized view:

```bash
prowler aws -M json-asff --send-sh-only-fails --security-hub
```

Requires Security Hub to be enabled in the target region.
