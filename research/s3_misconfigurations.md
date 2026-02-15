# Amazon S3 — Security Misconfiguration Analysis

## Service Overview
- Object storage service for storing and retrieving any amount of data
- Key features: bucket policies, ACLs, encryption, versioning, logging, replication, Object Lock
- Assets: files, backups, logs, static website content, data lakes
- Attack surface: publicly exposed buckets, unencrypted data, missing audit trails, insecure transit

---

## HIGH Severity

### Public Bucket Access (S3-001)
- **Description**: S3 buckets configured with public read/write permissions via bucket policies or ACLs, allowing unauthenticated access to stored objects.
- **Risk**: Sensitive data (PII, credentials, backups) exposed to the internet. Data can be exfiltrated, modified, or deleted by anyone.
- **Attack Scenario**: An attacker discovers a publicly readable bucket using tools like bucket-finder or GrayhatWarfare. They enumerate objects, download sensitive files (database backups, config files with credentials), and use those to pivot into the internal network.
- **Remediation**:
  1. Navigate to the S3 console and select the affected bucket.
  2. Go to the "Permissions" tab.
  3. Review and remove any bucket policy statements with `"Principal": "*"` or `"Principal": {"AWS": "*"}`.
  4. Under "Access Control List", ensure no grants are given to "Everyone" or "Authenticated Users".
  5. Enable S3 Block Public Access at the bucket level.
  6. Use AWS Config rule `s3-bucket-public-read-prohibited` and `s3-bucket-public-write-prohibited` to monitor.
- **Likelihood**: High

---

### Unencrypted Buckets (S3-002)
- **Description**: S3 buckets without default server-side encryption enabled, leaving objects stored in plaintext. SSE-KMS provides stronger protection than SSE-S3 with customer-managed keys and CloudTrail audit trails.
- **Risk**: Data at rest is vulnerable if storage media is compromised. Non-compliant with regulations (HIPAA, PCI-DSS, GDPR). Without SSE-KMS, there is no audit trail of key usage.
- **Attack Scenario**: An insider or attacker with read access to the underlying storage infrastructure can access plaintext data. In a multi-tenant breach, unencrypted data is immediately usable without needing decryption keys.
- **Remediation**:
  1. Open the S3 console and select the bucket.
  2. Go to "Properties" > "Default encryption".
  3. Enable default encryption with SSE-KMS for stronger protection.
  4. For SSE-KMS, select or create a Customer Managed Key with appropriate key policies.
  5. Enable Bucket Key to reduce KMS request costs.
  6. Apply a bucket policy that denies `s3:PutObject` requests without encryption headers:
     ```json
     {"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::BUCKET/*","Condition":{"StringNotEquals":{"s3:x-amz-server-side-encryption":"aws:kms"}}}
     ```
  7. Re-encrypt existing unencrypted objects using S3 Batch Operations.
- **Likelihood**: High

---

### Public Access Block Disabled (S3-003)
- **Description**: The S3 Block Public Access feature is not enabled at the bucket level, leaving buckets vulnerable to accidental public exposure.
- **Risk**: Future policy changes or ACL modifications could inadvertently make buckets public. Serves as a critical safety net that is missing.
- **Attack Scenario**: A developer accidentally sets a bucket policy to public while debugging. Without Block Public Access enabled, the bucket is immediately publicly accessible. Automated scanners detect it within minutes.
- **Remediation**:
  1. Open the S3 console > select the bucket > "Permissions" tab.
  2. Under "Block public access", click "Edit".
  3. Enable all four settings:
     - Block public access to buckets and objects granted through new ACLs
     - Block public access to buckets and objects granted through any ACLs
     - Block public and cross-account access through new public bucket or access point policies
     - Block public and cross-account access through any public bucket or access point policies
  4. Click "Save changes".
  5. Use AWS Config rule `s3-bucket-level-public-access-prohibited` to enforce.
- **Likelihood**: High

---

### Encryption in Transit Not Enforced (S3-004)
- **Description**: S3 bucket does not have a bucket policy that denies requests when `aws:SecureTransport` is `false`, allowing unencrypted HTTP access.
- **Risk**: Data transferred to/from S3 over HTTP can be intercepted via man-in-the-middle (MITM) attacks. Violates encryption-in-transit requirements of PCI DSS, HIPAA, and most security frameworks.
- **Attack Scenario**: An application on a compromised network sends S3 API calls over HTTP instead of HTTPS. An attacker performing a MITM attack on the same network captures the plaintext traffic — including AWS credentials in request headers and sensitive data in request/response bodies.
- **Remediation**:
  1. Open the S3 console and select the bucket.
  2. Go to the "Permissions" tab > "Bucket Policy".
  3. Add a policy statement that denies all S3 actions when `aws:SecureTransport` is `false`:
     ```json
     {
       "Effect": "Deny",
       "Principal": "*",
       "Action": "s3:*",
       "Resource": [
         "arn:aws:s3:::BUCKET",
         "arn:aws:s3:::BUCKET/*"
       ],
       "Condition": {
         "Bool": { "aws:SecureTransport": "false" }
       }
     }
     ```
  4. This ensures all data in transit is encrypted via TLS/HTTPS.
  5. Verify by testing with `--no-sign-request` and `http://` to confirm denial.
- **Likelihood**: High

---

### Account-Level Public Access Block Disabled (S3-005)
- **Description**: S3 Account-Level Public Access Block is not enabled. This is a defense-in-depth control separate from bucket-level settings that acts as a safety net across all buckets in the account.
- **Risk**: Without account-level blocking, any new or existing bucket can be made public through a misconfigured policy or ACL, even if individual bucket settings were previously correct.
- **Attack Scenario**: A new S3 bucket is created by an automated pipeline without Block Public Access settings. A subsequent policy change makes it public. Because account-level blocking is not enabled, there is no safety net to prevent exposure. Sensitive data is indexed by search engines within hours.
- **Remediation**:
  1. Open the S3 console > "Block Public Access settings for this account".
  2. Click "Edit" and enable all four settings:
     - Block public access granted through new ACLs
     - Block public access granted through any ACLs
     - Block public access through new public bucket or access point policies
     - Block public and cross-account access through any public bucket or access point policies
  3. Or use CLI:
     ```bash
     aws s3control put-public-access-block \
       --account-id ACCOUNT_ID \
       --public-access-block-configuration \
       BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
     ```
  4. Use AWS Config rule `s3-account-level-public-access-blocks` to enforce.
- **Likelihood**: High
