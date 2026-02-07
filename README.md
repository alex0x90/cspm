# AWS Security Misconfiguration Detection System (CSPM)

A Python-based Cloud Security Posture Management tool that scans AWS services for security misconfigurations, identifies risks, and provides step-by-step remediation guidance.

---

## Architecture

```
                        ┌───────────────────┐
                        │    USER (CLI)     │
                        └────────┬──────────┘
                                 │
                                 ▼
                        ┌───────────────────┐
                        │     main.py       │
                        │   Entry Point     │
                        └────────┬──────────┘
                                 │
                                 ▼
                        ┌───────────────────┐
                        │   detector.py     │
                        │   Orchestrator    │
                        └──┬──────┬──────┬──┘
                           │      │      │
              ┌────────────┘      │      └────────────┐
              ▼                   ▼                    ▼
     ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
     │  S3 Checks   │   │  RDS Checks  │   │  EC2 Checks  │
     │  (9 rules)   │   │  (5 rules)   │   │  (5 rules)   │
     └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
            │                  │                   │
            └──────────────────┼───────────────────┘
                               │
                               ▼
                      ┌─────────────────┐
                      │   base_check    │
                      │  (ABC + error   │
                      │   handling)     │
                      └────────┬────────┘
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
        ┌────────────┐ ┌────────────┐ ┌────────────┐
        │  findings  │ │ aws_client │ │ formatter  │
        │  (models)  │ │ (boto3)    │ │ (output)   │
        └────────────┘ └──────┬─────┘ └──────┬─────┘
                              │              │
                              ▼              ▼
                     ┌──────────────┐ ┌────────────┐
                     │  AWS Cloud   │ │  JSON/Text │
                     │  S3/RDS/EC2  │ │  Report    │
                     └──────────────┘ └────────────┘
```

## Project Structure

```
cspm/
├── README.md                     # This file
├── requirements.txt              # Python dependencies
├── config/
│   └── aws_config.py             # AWS credential loading & defaults
├── src/
│   ├── main.py                   # CLI entry point (argparse)
│   ├── detector.py               # Orchestrator - runs all checks
│   ├── checks/
│   │   ├── base_check.py         # Abstract base class for checks
│   │   ├── s3_checks.py          # 9 S3 security checks
│   │   ├── rds_checks.py         # 5 RDS security checks
│   │   └── ec2_checks.py         # 5 EC2 security checks
│   ├── models/
│   │   └── findings.py           # Finding & ScanReport data models
│   └── utils/
│       ├── aws_client.py         # Boto3 client factory & credential validation
│       ├── error_handler.py      # AWS error parsing & classification
│       └── formatter.py          # JSON & plain text report formatters
├── research/
│   └── misconfigurations.md      # Detailed research on 15 misconfigurations
└── tests/
    └── test_checks.py            # 42 unit tests with mocked Boto3 responses
```

## Prerequisites

- **Python 3.8+**
- **AWS Account** with IAM credentials configured
- **IAM Permissions** — the scanning identity needs read-only access:
  - `s3:ListAllMyBuckets`, `s3:GetBucketPolicy`, `s3:GetBucketAcl`, `s3:GetBucketEncryption`, `s3:GetBucketVersioning`, `s3:GetPublicAccessBlock`, `s3:GetBucketLogging`, `s3:GetObjectLockConfiguration`
  - `s3control:GetPublicAccessBlock` (account-level public access block)
  - `rds:DescribeDBInstances`
  - `ec2:DescribeSecurityGroups`, `ec2:DescribeVolumes`, `ec2:DescribeInstances`, `ec2:DescribeKeyPairs`
  - `sts:GetCallerIdentity`

## Installation

```bash
# Clone the repository
cd cspm

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate          # Windows

# Install dependencies
pip install -r requirements.txt
```

## Configuration

AWS credentials can be provided in any of these ways (in order of priority):

1. **AWS CLI profile** — pass `--profile <name>` to the CLI
2. **Environment variables**:
   ```bash
   export AWS_ACCESS_KEY_ID=your_key
   export AWS_SECRET_ACCESS_KEY=your_secret
   export AWS_DEFAULT_REGION=us-east-1
   ```
3. **`.env` file** in the project root:
   ```
   AWS_ACCESS_KEY_ID=your_key
   AWS_SECRET_ACCESS_KEY=your_secret
   AWS_DEFAULT_REGION=us-east-1
   ```
4. **Default AWS CLI credentials** (`~/.aws/credentials`)

## Usage

### Scan all services

```bash
python -m src.main --service all --region us-east-1
```

### Scan a specific service

```bash
python -m src.main --service s3 --region us-east-1
python -m src.main --service rds --region us-west-2
python -m src.main --service ec2 --region eu-west-1
```

### Run a specific check

```bash
python -m src.main --service s3 --region us-east-1 --check S3-001
python -m src.main --service ec2 --region us-east-1 --check EC2-001
```

### Export results to a file

```bash
# JSON output (default)
python -m src.main --service all --region us-east-1 --output-file report.json

# Plain text output
python -m src.main --service all --region us-east-1 --output text --output-file report.txt
```

### Use a named AWS profile

```bash
python -m src.main --service all --region us-east-1 --profile my-profile
```

### CLI Reference

| Argument        | Default      | Description                                      |
|-----------------|--------------|--------------------------------------------------|
| `--service`     | `all`        | Service to scan: `s3`, `rds`, `ec2`, or `all`   |
| `--region`      | `us-east-1`  | AWS region to scan                               |
| `--check`       | *(all)*      | Run a specific check by ID (e.g., `S3-001`)      |
| `--output`      | `json`       | Output format: `json` or `text`                  |
| `--output-file` | *(stdout)*   | Export results to a file                         |
| `--profile`     | *(default)*  | AWS CLI profile name                             |

### Exit Codes

| Code | Meaning                                |
|------|----------------------------------------|
| `0`  | All checks passed — no findings        |
| `1`  | Misconfigurations detected             |
| `2`  | Error occurred (credentials, network)  |

## Security Checks

### S3 Checks (9)

| ID     | Check                            | Severity | What It Detects                                              |
|--------|----------------------------------|----------|--------------------------------------------------------------|
| S3-001 | Public Bucket Access             | HIGH     | Public read/write via policies or ACLs                       |
| S3-002 | Bucket Encryption                | HIGH     | Missing SSE-KMS encryption (distinguishes SSE-S3 vs SSE-KMS)|
| S3-003 | Bucket Versioning                | MEDIUM   | Versioning not enabled (includes MFA Delete status)          |
| S3-004 | Public Access Block              | HIGH     | Missing or partially disabled bucket-level public access block|
| S3-005 | Bucket Logging                   | MEDIUM   | Server access logging not enabled                            |
| S3-006 | Encryption in Transit (HTTPS)    | HIGH     | Missing aws:SecureTransport deny policy                      |
| S3-007 | MFA Delete                       | MEDIUM   | MFA Delete not enabled on versioned buckets                  |
| S3-008 | Object Lock                      | MEDIUM   | Object Lock (WORM) not enabled for immutability              |
| S3-009 | Account-Level Public Access Block| HIGH     | Account-level public access block not configured             |

### RDS Checks (5)

| ID      | Check                  | Severity | What It Detects                              |
|---------|------------------------|----------|----------------------------------------------|
| RDS-001 | Public Access          | HIGH     | PubliclyAccessible flag set to True           |
| RDS-002 | Storage Encryption     | HIGH     | StorageEncrypted is False                     |
| RDS-003 | VPC Configuration      | HIGH     | Instance not deployed in a VPC                |
| RDS-004 | Automated Backups      | MEDIUM   | Backup retention period is 0 days             |
| RDS-005 | Engine Version         | MEDIUM   | Running outdated database engine version      |

### EC2 Checks (5)

| ID      | Check                  | Severity | What It Detects                                          |
|---------|------------------------|----------|----------------------------------------------------------|
| EC2-001 | Open Security Groups   | HIGH     | 0.0.0.0/0 on sensitive ports (22, 3389, 3306, etc.)     |
| EC2-002 | EBS Encryption         | HIGH     | Unencrypted EBS volumes                                  |
| EC2-003 | Public IP Assignment   | MEDIUM   | Instances with public IPv4 addresses                     |
| EC2-004 | IAM Instance Profile   | MEDIUM   | Instances without an IAM role attached                   |
| EC2-005 | Key Pair Usage         | LOW      | Unused/orphaned key pairs                                |

## Example Output (JSON Report)

When misconfigurations are found, a JSON report is saved to `reports/` with `description` and `impact` for each issue:

```json
{
  "scan_date": "2026-02-07T12:00:00.000000",
  "account_id": "123456789012",
  "region": "us-east-1",
  "total_misconfigurations": 2,
  "misconfigurations": [
    {
      "check_id": "S3-006",
      "check_name": "S3 Encryption in Transit (HTTPS)",
      "severity": "HIGH",
      "resource_id": "my-bucket",
      "description": "Checks whether S3 buckets enforce HTTPS-only access by having a bucket policy that denies requests when aws:SecureTransport is false.",
      "issue": "Bucket 'my-bucket' does not enforce HTTPS-only access. Data in transit may be unencrypted.",
      "impact": "Without enforced HTTPS, data transferred to/from S3 can be intercepted via man-in-the-middle (MITM) attacks on unencrypted HTTP connections. Attackers on the same network can capture sensitive data in plaintext. This violates encryption-in-transit requirements of PCI DSS, HIPAA, and most security frameworks.",
      "remediation": [
        "1. Open the S3 console and select the bucket.",
        "2. Go to the 'Permissions' tab > 'Bucket Policy'.",
        "3. Add a policy statement that denies all S3 actions when aws:SecureTransport is false.",
        "4. This ensures all data in transit is encrypted via TLS/HTTPS."
      ]
    },
    {
      "check_id": "S3-003",
      "check_name": "S3 Bucket Versioning",
      "severity": "MEDIUM",
      "resource_id": "my-bucket",
      "description": "Checks whether S3 buckets have versioning enabled to protect against accidental deletion or overwrites. Also checks if MFA Delete is enabled.",
      "issue": "Bucket 'my-bucket' does not have versioning enabled (Status: Disabled).",
      "impact": "Without versioning, accidental or malicious deletion of objects is permanent and unrecoverable. Versioning protects against ransomware attacks, application bugs that corrupt data, and human errors.",
      "remediation": [
        "1. Open the S3 console and select the bucket.",
        "2. Go to 'Properties' > 'Bucket Versioning'.",
        "3. Click 'Edit' and enable versioning.",
        "4. Configure lifecycle rules to manage version retention and storage costs.",
        "5. Enable MFA Delete for additional protection against unauthorized deletions."
      ]
    }
  ]
}
```

## Running Tests

All tests use mocked Boto3 responses — no AWS credentials required:

```bash
source venv/bin/activate
python -m unittest tests.test_checks -v
```

```
Ran 42 tests in 0.029s
OK
```

## Research

The full security research document with 19 misconfigurations (9 for S3, 5 for RDS, 5 for EC2), including attack scenarios and step-by-step remediation, is available at:

[research/misconfigurations.md](research/misconfigurations.md)

