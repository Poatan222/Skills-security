# CSPM Compliance Mapping

Map Prowler findings to compliance framework controls for audit-ready reporting.

## Prowler Built-in Frameworks

Prowler natively maps checks to these frameworks. Use `--compliance` flag:

| Framework | Prowler Flag | Notes |
|-----------|-------------|-------|
| CIS AWS Foundations v2.0 | `cis_2.0_aws` | Industry standard for AWS |
| CIS Azure Foundations v2.0 | `cis_2.0_azure` | Industry standard for Azure |
| CIS GCP Foundations v2.0 | `cis_2.0_gcp` | Industry standard for GCP |
| PCI DSS v3.2.1 | `pci_3.2.1_aws` | Payment card data |
| HIPAA | `hipaa_aws` | Healthcare data |
| NIST 800-53 | `nist_800_53_revision_5_aws` | Federal systems |
| SOC 2 | `soc2_aws` | Service organization controls |
| GDPR | `gdpr_aws` | EU data protection |
| ISO 27001 | `iso27001_2013_aws` | Information security management |

## Cross-Framework Summary

Common cloud misconfigurations and which frameworks they violate:

| Misconfiguration Category | CIS | PCI | SOC2 | HIPAA | ISO27001 |
|--------------------------|-----|-----|------|-------|----------|
| Public storage (S3/Blob/GCS) | Yes | Yes | Yes | Yes | Yes |
| Unencrypted data at rest | Yes | Yes | Yes | Yes | Yes |
| IAM root without MFA | Yes | Yes | Yes | Yes | Yes |
| Open security groups/firewall | Yes | Yes | Yes | Yes | Yes |
| Audit logging disabled | Yes | Yes | Yes | Yes | Yes |
| No key rotation | Yes | Yes | Yes | No | Yes |
| Unencrypted data in transit | Yes | Yes | Yes | Yes | Yes |
| Overly permissive IAM policies | Yes | Yes | Yes | Yes | Yes |

## Generating Compliance Reports

For auditors, generate a per-framework report showing:

1. Total controls assessed
2. Controls passing vs failing
3. Percentage compliance
4. Specific failing checks with remediation status
5. Evidence of remediation (re-scan results)
