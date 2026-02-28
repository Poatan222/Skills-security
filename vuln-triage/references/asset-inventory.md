# Asset Inventory

Map assets to owners, criticality tiers, and exposure status. Update this file as infrastructure changes.

## Tier Definitions

| Tier | Label | Description | Examples |
|------|-------|-------------|----------|
| 1 | Crown Jewels | Direct customer data, auth systems, payment processing | prod-db-*, auth-*, payment-* |
| 2 | Business Critical | Internal SaaS, CI/CD, identity providers, monitoring | jenkins-*, idp-*, grafana-* |
| 3 | Standard | Dev workstations, staging, internal wikis, non-sensitive | dev-*, staging-*, wiki-* |

## Asset Registry

Replace the sample entries below with your actual assets.

| Asset Pattern | Tier | Owner | Exposure | Notes |
|---------------|------|-------|----------|-------|
| prod-db-* | 1 | @db-team | Internal, VPC-isolated | PCI scope |
| auth-api-* | 1 | @identity-team | Internet-facing, behind WAF | SSO/SAML provider |
| payment-svc-* | 1 | @payments-team | Internet-facing, behind CDN | PCI DSS scope |
| prod-api-* | 2 | @platform-team | Internet-facing, behind WAF | Core product APIs |
| jenkins-* | 2 | @devops-team | Internal only | CI/CD — high blast radius |
| grafana-* | 2 | @sre-team | Internal, VPN-only | Monitoring dashboards |
| k8s-node-* | 2 | @platform-team | Mixed | Check per-node exposure |
| dev-ws-* | 3 | Individual developer | Internal | Standard patching cycle |
| staging-* | 3 | @qa-team | Internal | Mirror of prod, no real data |

## Unknown Asset Handling

If an asset from a scan does not match any pattern above:

1. Flag as `UNKNOWN_ASSET` in the triage report
2. Default to HIGH priority (not LOW — unknown assets may be shadow IT)
3. Escalate to Asset Management team for classification
4. Do NOT auto-close or suppress the finding
