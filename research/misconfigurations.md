# AWS S3 Security Misconfiguration Analysis

## Amazon S3 (Simple Storage Service)

### Service Overview
- Object storage service for storing and retrieving any amount of data
- Key features: bucket policies, ACLs, encryption, versioning, logging, replication, Object Lock
- Assets: files, backups, logs, static website content, data lakes
- Attack surface: publicly exposed buckets, unencrypted data, missing audit trails, weak deletion controls

---

### Misconfiguration 1: Public Bucket Access (S3-001 — Severity: HIGH)
- **Description**: S3 buckets configured with public read/write permissions via bucket policies or ACLs, allowing unauthenticated access to stored objects.
- **Risk**: Sensitive data (PII, credentials, backups) exposed to the internet. Data can be exfiltrated, modified, or deleted by anyone.
- **Attack Scenario**: An attacker discovers a publicly readable bucket using tools like bucket-finder or GrayhatWarfare. They enumerate objects, download sensitive files (database backups, config files with credentials), and use those to pivot into the internal network.
- **Impact**: Publicly accessible S3 buckets can lead to unauthorized data access, data exfiltration, data tampering, or hosting of malicious content. Attackers can read sensitive files (PII, credentials, backups) or write malicious objects. This is one of the most common causes of cloud data breaches.
- **Remediation**:
  1. Navigate to the S3 console and select the affected bucket.
  2. Go to the "Permissions" tab.
  3. Review and remove any bucket policy statements with `"Principal": "*"` or `"Principal": {"AWS": "*"}`.
  4. Under "Access Control List", ensure no grants are given to "Everyone" or "Authenticated Users".
  5. Enable S3 Block Public Access at the bucket level.
  6. Use AWS Config rule `s3-bucket-public-read-prohibited` and `s3-bucket-public-write-prohibited` to monitor.
- **Likelihood**: High

### Misconfiguration 2: Unencrypted Buckets (S3-002 — Severity: HIGH)
- **Description**: S3 buckets without default server-side encryption enabled, leaving objects stored in plaintext. SSE-KMS provides stronger protection with customer-managed keys and audit trails via CloudTrail.
- **Risk**: Data at rest is vulnerable if storage media is compromised. Non-compliant with regulations (HIPAA, PCI-DSS, GDPR). Without SSE-KMS, there is no audit trail of key usage.
- **Attack Scenario**: An insider or attacker with read access to the underlying storage infrastructure can access plaintext data. In a multi-tenant breach, unencrypted data is immediately usable without needing decryption keys. Even with SSE-S3, there is no CloudTrail visibility into who accessed the encryption keys.
- **Impact**: Without server-side encryption (or with only SSE-S3), data at rest lacks customer-controlled key management and detailed audit trails. SSE-KMS provides envelope encryption with CloudTrail logging of every key usage, enabling detection of unauthorized access. Without it, compromised storage could expose plaintext data with no visibility into who accessed it.
- **Remediation**:
  1. Open the S3 console and select the bucket.
  2. Go to "Properties" > "Default encryption".
  3. Enable default encryption with SSE-KMS for stronger protection.
  4. For SSE-KMS, select or create a Customer Managed Key with appropriate key policies.
  5. Enable Bucket Key to reduce KMS request costs.
  6. Apply a bucket policy that denies `s3:PutObject` requests without encryption headers.
  7. Re-encrypt existing unencrypted objects using S3 Batch Operations.
- **Likelihood**: High

### Misconfiguration 3: Bucket Versioning Disabled (S3-003 — Severity: MEDIUM)
- **Description**: S3 bucket versioning is not enabled, meaning overwritten or deleted objects cannot be recovered. Also checks if MFA Delete is enabled to protect versioning from being disabled by compromised credentials.
- **Risk**: No protection against accidental deletion or ransomware attacks that overwrite objects. No audit trail of object changes. Without MFA Delete, an attacker who compromises credentials can suspend versioning.
- **Attack Scenario**: An attacker with write access overwrites critical files (e.g., application configs, backups) with malicious content. Without versioning, the original data is permanently lost, and rollback is impossible. Ransomware variants encrypt S3 objects and demand payment.
- **Impact**: Without versioning, accidental or malicious deletion of objects is permanent and unrecoverable. Versioning protects against ransomware attacks (where attackers overwrite files with encrypted copies), application bugs that corrupt data, and human errors. It also enables point-in-time recovery of any object.
- **Remediation**:
  1. Open the S3 console and select the bucket.
  2. Go to "Properties" > "Bucket Versioning".
  3. Click "Edit" and enable versioning.
  4. Configure lifecycle rules to manage version retention and storage costs.
  5. Enable MFA Delete for additional protection against unauthorized deletions.
  6. Note: Versioning cannot be disabled once enabled, only suspended.
- **Likelihood**: Medium

### Misconfiguration 4: Public Access Block Disabled (S3-004 — Severity: HIGH)
- **Description**: The S3 Block Public Access feature is not enabled at the bucket level, leaving buckets vulnerable to accidental public exposure.
- **Risk**: Future policy changes or ACL modifications could inadvertently make buckets public. Serves as a critical safety net that is missing.
- **Attack Scenario**: A developer accidentally sets a bucket policy to public while debugging. Without Block Public Access enabled, the bucket is immediately publicly accessible. Automated scanners detect it within minutes.
- **Impact**: Without all four Block Public Access settings enabled, S3 buckets are vulnerable to accidental public exposure through misconfigured bucket policies or ACLs. A single misconfigured policy or ACL could expose all bucket contents to the internet, leading to data breaches. Block Public Access acts as a safety net against human error.
- **Remediation**:
  1. Open the S3 console > select the bucket > "Permissions" tab.
  2. Under "Block public access", click "Edit".
  3. Enable all four settings:
     - Block public access to buckets and objects granted through new ACLs
     - Block public access to buckets and objects granted through any ACLs
     - Block public and cross-account access to buckets and objects through any public bucket policies
     - Block public and cross-account access to buckets and objects through new public bucket policies
  4. Also enable Block Public Access at the AWS account level via S3 settings.
  5. Use AWS Config rule `s3-account-level-public-access-blocks` to enforce.
- **Likelihood**: High

### Misconfiguration 5: Bucket Logging Disabled (S3-005 — Severity: MEDIUM)
- **Description**: Server access logging is not enabled for S3 buckets, meaning no record of requests made to the bucket.
- **Risk**: Unable to detect unauthorized access, track data exfiltration, or perform forensic analysis after a security incident.
- **Attack Scenario**: An attacker accesses and exfiltrates data from a bucket over several weeks. Without access logs, the organization has no visibility into what was accessed, when, or by whom, making incident response and impact assessment impossible.
- **Impact**: Without server access logging, there is no record of who accessed the bucket, what operations were performed, or when. This makes it impossible to detect unauthorized access, investigate security incidents, or meet compliance audit requirements (PCI DSS, HIPAA, SOC 2). Attackers can exfiltrate data undetected.
- **Remediation**:
  1. Create a dedicated logging bucket (e.g., `my-bucket-logs`) in the same region.
  2. Grant the S3 log delivery group write permission to the logging bucket.
  3. Open the source bucket > "Properties" > "Server access logging".
  4. Enable logging and specify the target logging bucket and prefix.
  5. Alternatively, enable AWS CloudTrail data events for S3 for more detailed API-level logging.
  6. Set up lifecycle policies on the logging bucket to manage log retention.
- **Likelihood**: Medium

### Misconfiguration 6: Encryption in Transit Not Enforced (S3-006 — Severity: HIGH)
- **Description**: S3 buckets do not enforce HTTPS-only access. Without a bucket policy denying requests where `aws:SecureTransport` is `false`, data can be transmitted over unencrypted HTTP connections.
- **Risk**: Data in transit can be intercepted via man-in-the-middle (MITM) attacks. Sensitive data (credentials, PII, application data) may be captured in plaintext on the network.
- **Attack Scenario**: An attacker on the same network (e.g., a compromised VPC, shared Wi-Fi, or ISP-level interception) captures HTTP traffic to an S3 bucket. They intercept API keys, authentication tokens, and sensitive file uploads being sent over unencrypted connections.
- **Impact**: Without enforced HTTPS, data transferred to/from S3 can be intercepted via man-in-the-middle (MITM) attacks on unencrypted HTTP connections. Attackers on the same network can capture sensitive data (credentials, PII, application data) in plaintext. This violates encryption-in-transit requirements of PCI DSS, HIPAA, and most security frameworks.
- **Remediation**:
  1. Open the S3 console and select the bucket.
  2. Go to the "Permissions" tab > "Bucket Policy".
  3. Add a policy statement that denies all S3 actions when `aws:SecureTransport` is `false`:
     ```json
     {"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::BUCKET","arn:aws:s3:::BUCKET/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}
     ```
  4. This ensures all data in transit is encrypted via TLS/HTTPS.
- **Likelihood**: High

### Misconfiguration 7: MFA Delete Not Enabled (S3-007 — Severity: MEDIUM)
- **Description**: S3 buckets with versioning enabled do not have MFA Delete enabled. MFA Delete requires multi-factor authentication to change the versioning state or permanently delete object versions, protecting against ransomware and compromised credentials.
- **Risk**: An attacker who compromises IAM credentials can suspend versioning and permanently delete all object versions, making data unrecoverable. This is a common ransomware attack pattern.
- **Attack Scenario**: An attacker compromises an IAM user's credentials through phishing. They use the credentials to suspend versioning on critical buckets, delete all object versions, and demand a ransom. Without MFA Delete, no additional authentication is required to perform these destructive actions.
- **Impact**: Without MFA Delete, an attacker who compromises IAM credentials can suspend versioning and permanently delete all object versions, making data unrecoverable. This is a key ransomware attack vector — attackers disable versioning, encrypt files with their own KMS key, and demand payment. MFA Delete requires physical MFA device access to change versioning state.
- **Remediation**:
  1. MFA Delete can only be enabled via the AWS CLI or API (not the console).
  2. Use the root account credentials with an MFA device configured.
  3. Run: `aws s3api put-bucket-versioning --bucket BUCKET_NAME --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa 'arn:aws:iam::ACCOUNT:mfa/DEVICE TOTP_CODE'`
  4. Ensure your root account has an MFA device configured.
  5. Note: Only the bucket owner (root account) can enable MFA Delete.
- **Likelihood**: Medium

### Misconfiguration 8: Object Lock Not Enabled (S3-008 — Severity: MEDIUM)
- **Description**: S3 buckets do not have Object Lock enabled. Object Lock provides immutability protection using a WORM (Write Once Read Many) model, preventing objects from being deleted or overwritten even by the root account. Supports Governance Mode (time-limited) and Compliance Mode (indefinite).
- **Risk**: Without immutability protection, even a compromised root account or bucket owner can delete or overwrite objects. Critical for regulatory compliance in financial services and healthcare.
- **Attack Scenario**: An attacker gains root account access and deletes all objects in S3, including backups and audit logs. Without Object Lock, there is no mechanism to prevent this — even versioning can be suspended by root. In Compliance Mode, Object Lock makes this attack impossible.
- **Impact**: Without Object Lock, even a compromised root account or bucket owner can delete or overwrite objects. Object Lock provides immutability (WORM) that protects against ransomware, insider threats, and accidental deletion. In Compliance Mode, no one — including AWS — can delete protected objects before the retention period expires. Required for regulatory compliance in financial services and healthcare.
- **Remediation**:
  1. Object Lock can only be enabled at bucket creation time.
  2. Create a new bucket with Object Lock enabled.
  3. Configure a default retention period and mode:
     - Governance Mode: Protects for a set retention period.
     - Compliance Mode: Protects indefinitely (cannot be overridden).
  4. Migrate existing objects to the new bucket using S3 Batch Operations.
  5. Object Lock requires versioning to be enabled (automatically enabled).
- **Likelihood**: Medium

### Misconfiguration 9: Account-Level Public Access Block Disabled (S3-009 — Severity: HIGH)
- **Description**: S3 Account-Level Public Access Block is not enabled. This provides a safety net across all buckets in the account, preventing accidental public exposure even if individual bucket settings are misconfigured.
- **Risk**: Without account-level blocking, any new or existing bucket can be made public through a misconfigured policy or ACL. A future configuration error on any single bucket could lead to a data breach.
- **Attack Scenario**: A new developer creates an S3 bucket for a quick prototype and accidentally sets the bucket policy to allow public access. Without account-level Block Public Access, the bucket is immediately exposed. Automated scanners (e.g., GrayhatWarfare) detect and index it within hours. Sensitive test data (which often mirrors production data) is now publicly accessible.
- **Impact**: Without account-level Block Public Access, any new or existing bucket in the account can be made public through a misconfigured policy or ACL. This is a defense-in-depth control — even if individual bucket settings are correct today, a future misconfiguration could expose data. Account-level blocking overrides all bucket-level settings, preventing accidental public exposure across the entire account.
- **Remediation**:
  1. Open the S3 console > "Block Public Access settings for this account".
  2. Click "Edit" and enable all four settings:
     - Block public access granted through new ACLs
     - Block public access granted through any ACLs
     - Block public access through new public bucket or access point policies
     - Block public and cross-account access through any public bucket or access point policies
  3. Or use CLI: `aws s3control put-public-access-block --account-id ACCOUNT_ID --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`
- **Likelihood**: High
