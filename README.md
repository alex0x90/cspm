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
     │  (5 rules)   │   │  (5 rules)   │   │  (5 rules)   │
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
│   │   ├── s3_checks.py          # 5 S3 security checks
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
  - `s3:ListAllMyBuckets`, `s3:GetBucketPolicy`, `s3:GetBucketAcl`, `s3:GetBucketEncryption`, `s3:GetBucketVersioning`, `s3:GetPublicAccessBlock`, `s3:GetBucketLogging`
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

### S3 Checks (5)

| ID     | Check                      | Severity | What It Detects                                 |
|--------|----------------------------|----------|--------------------------------------------------|
| S3-001 | Public Bucket Access       | HIGH     | Public read/write via policies or ACLs           |
| S3-002 | Bucket Encryption          | HIGH     | Missing default server-side encryption           |
| S3-003 | Bucket Versioning          | MEDIUM   | Versioning not enabled                           |
| S3-004 | Public Access Block        | HIGH     | Missing or partially disabled public access block|
| S3-005 | Bucket Logging             | MEDIUM   | Server access logging not enabled                |

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

## Example Output (JSON)

```json
{
  "scan_date": "2026-02-07T12:00:00.000000",
  "services": ["s3", "rds", "ec2"],
  "region": "us-east-1",
  "account_id": "123456789012",
  "summary": {
    "total_checks": 42,
    "passed": 35,
    "failed": 5,
    "errors": 2
  },
  "findings": [
    {
      "check_id": "S3-001",
      "check_name": "S3 Public Bucket Access",
      "severity": "HIGH",
      "status": "FAILED",
      "description": "Checks whether S3 buckets have public read or write access...",
      "finding": "Bucket 'my-bucket' has public access via: bucket policy.",
      "remediation": "1. Navigate to the S3 console...\n2. Go to Permissions...",
      "resource_id": "my-bucket",
      "region": "us-east-1",
      "error_message": ""
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

The full security research document with 15 misconfigurations (5 per service), including attack scenarios and step-by-step remediation, is available at:

[research/misconfigurations.md](research/misconfigurations.md)

