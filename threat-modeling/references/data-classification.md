# Data Classification

Classify data assets identified during threat modeling to determine appropriate protection levels.

## Classification Tiers

| Tier | Label | Description | Examples | Required Controls |
|------|-------|-------------|----------|-------------------|
| 1 | Restricted | Severe harm if disclosed. Regulatory impact. | PII, payment data, health records, credentials, encryption keys | Encryption at rest + transit, access logging, MFA, DLP, minimal retention |
| 2 | Confidential | Business harm if disclosed. Internal only. | Source code, internal APIs, business strategy, employee data | Encryption in transit, access controls, audit logging |
| 3 | Internal | Low harm if disclosed. Not for public. | Internal wikis, architecture docs, meeting notes | Basic access controls, authentication required |
| 4 | Public | No harm if disclosed. Intended for public. | Marketing site, public API docs, open-source code | Integrity protection (prevent tampering) |

## Regulatory Data Categories

| Data Type | Regulation | Classification Tier | Key Requirements |
|-----------|-----------|--------------------|--------------------|
| Cardholder data | PCI DSS | Restricted | Encrypt, restrict access, log all access, quarterly scans |
| Protected health info (PHI) | HIPAA | Restricted | Encrypt, access controls, audit trails, BAAs with vendors |
| Personal data (EU residents) | GDPR | Restricted | Consent, right to deletion, breach notification within 72h |
| Personal data (general) | Various privacy laws | Confidential-Restricted | Minimize collection, purpose limitation, retention limits |

## Using This in Threat Models

When identifying data in a data flow:

1. Classify the data using the tiers above
2. Tier 1 data flows across trust boundaries = **automatic HIGH threat**
3. Tier 1 data at rest without encryption = **automatic CRITICAL threat**
4. Any data flow without TLS = **minimum MEDIUM threat** (HIGH if Tier 1-2)
