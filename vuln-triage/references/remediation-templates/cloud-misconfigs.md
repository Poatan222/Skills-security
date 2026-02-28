# Cloud Misconfiguration Remediation

Common remediation steps for AWS, GCP, and Azure misconfigurations found in vulnerability scans.

## AWS

### S3 Bucket Public Access

```bash
# Block all public access at account level
aws s3control put-public-access-block \
  --account-id [ACCOUNT_ID] \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Block at bucket level
aws s3api put-public-access-block --bucket [BUCKET] \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### Security Group Open to World

```bash
# Revoke 0.0.0.0/0 ingress
aws ec2 revoke-security-group-ingress \
  --group-id [SG_ID] \
  --protocol tcp --port [PORT] --cidr 0.0.0.0/0
```

### IAM Root Account MFA

Remediation: Enable MFA on root via AWS Console > IAM > Security credentials. Cannot be done via CLI.

## Azure

### Storage Account Public Access

```bash
az storage account update \
  --name [ACCOUNT] --resource-group [RG] \
  --allow-blob-public-access false
```

### Network Security Group Overly Permissive

```bash
az network nsg rule delete \
  --resource-group [RG] --nsg-name [NSG] --name [RULE_NAME]
```

## GCP

### Public Cloud Storage Bucket

```bash
gcloud storage buckets update gs://[BUCKET] \
  --uniform-bucket-level-access
gcloud storage buckets remove-iam-policy-binding gs://[BUCKET] \
  --member=allUsers --role=roles/storage.objectViewer
```
