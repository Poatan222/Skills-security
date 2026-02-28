# Linux Patching Remediation

Standard steps for OS-level vulnerability remediation on Linux hosts.

## Pre-Patch Checklist

1. Confirm asset is in a maintenance window or has change approval
2. Take a snapshot/backup if VM-based
3. Verify rollback procedure is documented
4. Notify asset owner and on-call team

## Patch Commands

### RHEL/CentOS/Amazon Linux

```bash
# Check available updates for specific CVE
yum updateinfo list --cves CVE-XXXX-XXXXX

# Apply specific security update
yum update --cves CVE-XXXX-XXXXX -y

# Apply all security updates
yum update --security -y

# Verify patch applied
rpm -qa --changelog | grep CVE-XXXX-XXXXX
```

### Ubuntu/Debian

```bash
# Check if CVE fix is available
apt list --upgradable 2>/dev/null | grep [package-name]

# Apply specific package update
apt-get install --only-upgrade [package-name] -y

# Apply all security updates
unattended-upgrade --dry-run  # preview
unattended-upgrade             # apply

# Verify
apt show [package-name] | grep Version
```

## Post-Patch Verification

1. Verify service is running: `systemctl status [service]`
2. Run application health check
3. Re-scan the specific asset to confirm CVE is resolved
4. Update Jira ticket with remediation evidence
