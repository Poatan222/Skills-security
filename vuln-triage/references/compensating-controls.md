# Compensating Controls

When a vulnerability cannot be patched (EOL system, vendor dependency, business-critical uptime), apply compensating controls and document the risk acceptance.

## When to Use

- Vendor has not released a patch
- System is end-of-life with no upgrade path available
- Patch requires downtime on a system with 99.99% SLA
- Patch breaks application functionality (confirmed in staging)
- Third-party dependency with no alternative

## Control Options by Vulnerability Type

### Remote Code Execution (RCE)

| Control | Effectiveness | Implementation |
|---------|--------------|----------------|
| Network segmentation / micro-segmentation | High | Isolate affected asset to dedicated VLAN/subnet |
| WAF rules blocking known exploit patterns | Medium-High | Deploy virtual patching rules targeting the specific CVE |
| Disable affected service/port if not required | High | Confirm with asset owner, then disable |
| Enhanced monitoring (IDS/IPS signatures) | Medium | Deploy Snort/Suricata rules for known exploit traffic |

### Privilege Escalation

| Control | Effectiveness | Implementation |
|---------|--------------|----------------|
| Restrict local admin access | High | Remove unnecessary admin/root privileges |
| Application allowlisting | High | Only permit approved executables |
| Enhanced audit logging | Medium | Log all privilege changes, alert on anomalies |

### Information Disclosure

| Control | Effectiveness | Implementation |
|---------|--------------|----------------|
| Network ACLs restricting access | High | Limit access to authorized IPs/subnets |
| Encrypt data at rest and in transit | High | Enable TLS, encrypt storage volumes |
| Remove sensitive data from affected system | High | Migrate data to patched system |

### Denial of Service

| Control | Effectiveness | Implementation |
|---------|--------------|----------------|
| Rate limiting | Medium-High | Configure at load balancer/WAF |
| DDoS protection service | High | Enable cloud-native DDoS protection |
| Auto-scaling | Medium | Absorb traffic spikes automatically |

## Risk Acceptance Template

Every compensating control must be accompanied by a risk acceptance:

```text
CVE: [CVE-ID]
Asset: [hostname/IP]
Why patch is unavailable: [specific reason]
Compensating controls applied: [list controls]
Residual risk: [description of remaining exposure]
Risk owner: [name and title]
Approved by: [Security Lead / CISO]
Expiry date: [max 90 days from approval]
Review date: [next scheduled review]
```
