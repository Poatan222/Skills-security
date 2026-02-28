# False Positive Patterns

Known scanner false positives specific to your environment. Findings matching these patterns are marked as FP but still included in the report appendix for audit trail.

## How to Use

When a finding matches a pattern below, the skill marks it as `FALSE_POSITIVE` with the pattern ID as reference. The finding is moved to the report appendix — never silently dropped.

## FP Patterns

| Pattern ID | Scanner | CVE/Check | Asset Pattern | Reason | Added By | Date |
|------------|---------|-----------|---------------|--------|----------|------|
| FP-001 | SAMPLE | SAMPLE-CVE | SAMPLE-asset | Replace with your known FPs | @analyst | 2025-01-01 |

## Adding New FP Patterns

Before adding a false positive pattern:

1. Confirm the finding is genuinely a false positive (not just low risk)
2. Document the specific technical reason it does not apply
3. Get Security Lead approval
4. Add the pattern with your name and date
5. Set a review date (max 6 months) — FP patterns expire and must be re-validated

## Review Cadence

- Review all FP patterns quarterly
- Remove patterns for decommissioned assets or updated scanners
- Scanner version upgrades may resolve previous FPs — re-validate after upgrades
