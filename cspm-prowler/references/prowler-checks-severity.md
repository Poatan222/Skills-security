# Prowler Severity Overrides

Override Prowler's default severities based on your org's risk posture. Prowler assigns severity per-check, but your context matters more.

## Override Rules

| Condition | Override To | Reason |
|-----------|------------|--------|
| Any FAIL on Tier 1 resource + Prowler severity >= medium | HIGH or CRITICAL | Crown jewel resources deserve elevated attention |
| Any IAM root/admin finding | CRITICAL (regardless of Prowler rating) | Root account compromise = total loss of control |
| Public data exposure on production | CRITICAL | Potential data breach |
| Logging/monitoring disabled on production | CRITICAL | You cannot detect incidents |
| Findings on dev/staging accounts only | De-escalate one level (max) | Lower blast radius, but do not ignore |
| Finding already has compensating control | De-escalate one level with documentation | Control must be verified, not assumed |

## Prowler Default Severities

For reference, Prowler uses: `critical`, `high`, `medium`, `low`, `informational`.

These are based on the check definition, not your environment context. Always apply the override rules above to get effective severity.

## Custom Severity for Org-Specific Checks

If your org has unique requirements (e.g., all databases must use customer-managed keys, not AWS-managed), you can add custom severity overrides here:

| Check Pattern | Default Severity | Your Override | Reason |
|--------------|-----------------|---------------|--------|
| [Add your custom overrides] | | | |
