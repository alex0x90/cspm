# AWS Security Misconfiguration Analysis

## 1. Amazon S3 (Simple Storage Service)

### Service Overview
- Object storage service for storing and retrieving any amount of data
- Key features: bucket policies, ACLs, encryption, versioning, logging, replication
- Assets: files, backups, logs, static website content, data lakes
- Attack surface: publicly exposed buckets, unencrypted data, missing audit trails

---

### Misconfiguration 1: Public Bucket Access (Severity: HIGH)
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

### Misconfiguration 2: Unencrypted Buckets (Severity: HIGH)
- **Description**: S3 buckets without default server-side encryption enabled, leaving objects stored in plaintext.
- **Risk**: Data at rest is vulnerable if storage media is compromised. Non-compliant with regulations (HIPAA, PCI-DSS, GDPR).
- **Attack Scenario**: An insider or attacker with read access to the underlying storage infrastructure can access plaintext data. In a multi-tenant breach, unencrypted data is immediately usable without needing decryption keys.
- **Remediation**:
  1. Open the S3 console and select the bucket.
  2. Go to "Properties" > "Default encryption".
  3. Enable default encryption with either SSE-S3 (AES-256) or SSE-KMS.
  4. For SSE-KMS, select or create a KMS key with appropriate key policies.
  5. Apply a bucket policy that denies `s3:PutObject` requests without encryption headers:
     ```json
     {"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::BUCKET/*","Condition":{"StringNotEquals":{"s3:x-amz-server-side-encryption":"aws:kms"}}}
     ```
  6. Re-encrypt existing unencrypted objects using S3 Batch Operations.
- **Likelihood**: High

### Misconfiguration 3: Bucket Versioning Disabled (Severity: MEDIUM)
- **Description**: S3 bucket versioning is not enabled, meaning overwritten or deleted objects cannot be recovered.
- **Risk**: No protection against accidental deletion or ransomware attacks that overwrite objects. No audit trail of object changes.
- **Attack Scenario**: An attacker with write access overwrites critical files (e.g., application configs, backups) with malicious content. Without versioning, the original data is permanently lost, and rollback is impossible.
- **Remediation**:
  1. Open the S3 console and select the bucket.
  2. Go to "Properties" > "Bucket Versioning".
  3. Click "Edit" and enable versioning.
  4. Configure lifecycle rules to manage version retention and storage costs.
  5. Enable MFA Delete for additional protection against unauthorized deletions.
  6. Note: Versioning cannot be disabled once enabled, only suspended.
- **Likelihood**: Medium

### Misconfiguration 4: Public Access Block Disabled (Severity: HIGH)
- **Description**: The S3 Block Public Access feature is not enabled at the bucket or account level, leaving buckets vulnerable to accidental public exposure.
- **Risk**: Future policy changes or ACL modifications could inadvertently make buckets public. Serves as a critical safety net that is missing.
- **Attack Scenario**: A developer accidentally sets a bucket policy to public while debugging. Without Block Public Access enabled, the bucket is immediately publicly accessible. Automated scanners detect it within minutes.
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

### Misconfiguration 5: Bucket Logging Disabled (Severity: MEDIUM)
- **Description**: Server access logging is not enabled for S3 buckets, meaning no record of requests made to the bucket.
- **Risk**: Unable to detect unauthorized access, track data exfiltration, or perform forensic analysis after a security incident.
- **Attack Scenario**: An attacker accesses and exfiltrates data from a bucket over several weeks. Without access logs, the organization has no visibility into what was accessed, when, or by whom, making incident response and impact assessment impossible.
- **Remediation**:
  1. Create a dedicated logging bucket (e.g., `my-bucket-logs`) in the same region.
  2. Grant the S3 log delivery group write permission to the logging bucket.
  3. Open the source bucket > "Properties" > "Server access logging".
  4. Enable logging and specify the target logging bucket and prefix.
  5. Alternatively, enable AWS CloudTrail data events for S3 for more detailed API-level logging.
  6. Set up lifecycle policies on the logging bucket to manage log retention.
- **Likelihood**: Medium

---

## 2. Amazon RDS (Relational Database Service)

### Service Overview
- Managed relational database service supporting MySQL, PostgreSQL, MariaDB, Oracle, SQL Server, and Aurora
- Key features: automated backups, encryption, VPC isolation, Multi-AZ, read replicas
- Assets: application databases, user data, transaction records, business-critical data
- Attack surface: network exposure, unencrypted storage, weak authentication, missing backups

---

### Misconfiguration 1: Publicly Accessible Database (Severity: HIGH)
- **Description**: RDS instance has the `PubliclyAccessible` flag set to `True`, assigning a public IP and making the database reachable from the internet.
- **Risk**: Database exposed to brute-force attacks, SQL injection from the internet, and unauthorized data access. Even with security groups, the public endpoint increases attack surface.
- **Attack Scenario**: An attacker scans for publicly accessible RDS endpoints using tools like Shodan or masscan. They identify a MySQL instance, brute-force the admin password, and dump the entire database containing customer PII.
- **Remediation**:
  1. Open the RDS console and select the affected DB instance.
  2. Click "Modify".
  3. Under "Connectivity", set "Publicly accessible" to "No".
  4. Click "Continue" and apply changes (may require a brief outage).
  5. Ensure the DB is in a private subnet within your VPC.
  6. Use a bastion host or VPN for administrative access.
  7. Review security groups to ensure no `0.0.0.0/0` inbound rules.
- **Likelihood**: High

### Misconfiguration 2: Unencrypted Database Storage (Severity: HIGH)
- **Description**: RDS instance storage is not encrypted, leaving data at rest in plaintext on the underlying storage volumes.
- **Risk**: Data vulnerable to physical media theft or unauthorized access at the storage layer. Non-compliant with PCI-DSS, HIPAA, and GDPR requirements for encryption at rest.
- **Attack Scenario**: In a cloud provider infrastructure breach or through a shared responsibility model gap, unencrypted database storage can be accessed directly, bypassing all application-level controls.
- **Remediation**:
  1. Note: Encryption cannot be enabled on an existing unencrypted RDS instance directly.
  2. Create a snapshot of the unencrypted DB instance.
  3. Copy the snapshot and enable encryption (select a KMS key).
  4. Restore a new DB instance from the encrypted snapshot.
  5. Update application connection strings to point to the new encrypted instance.
  6. Verify the application works, then delete the old unencrypted instance.
  7. Enable encryption by default for new instances in your organization's CloudFormation/Terraform templates.
- **Likelihood**: Medium

### Misconfiguration 3: Database Not in VPC (Severity: HIGH)
- **Description**: RDS instance is deployed in EC2-Classic mode instead of within a VPC, lacking network isolation.
- **Risk**: Without VPC isolation, the database lacks subnet-level access controls, network ACLs, and proper security group scoping.
- **Attack Scenario**: An attacker who compromises any EC2 instance in the classic network can directly reach the database, as there are no VPC-level network boundaries to limit lateral movement.
- **Remediation**:
  1. Create a VPC with private subnets across multiple Availability Zones.
  2. Create a DB subnet group using the private subnets.
  3. Create a snapshot of the existing DB instance.
  4. Restore the snapshot into the VPC using the new DB subnet group.
  5. Update security groups to restrict inbound access to only application subnets.
  6. Update application connection endpoints.
  7. Test connectivity and delete the old non-VPC instance.
- **Likelihood**: Low

### Misconfiguration 4: Automated Backups Disabled (Severity: MEDIUM)
- **Description**: RDS automated backup retention period is set to 0, meaning no automated backups are being created.
- **Risk**: No point-in-time recovery capability. Data loss in case of accidental deletion, corruption, or ransomware attack is permanent.
- **Attack Scenario**: A disgruntled employee or attacker with database admin access drops all tables. Without automated backups, the data is permanently lost, causing severe business impact and potential regulatory violations.
- **Remediation**:
  1. Open the RDS console and select the DB instance.
  2. Click "Modify".
  3. Set "Backup retention period" to at least 7 days (AWS maximum is 35 days).
  4. Configure a backup window during low-traffic periods.
  5. Enable "Copy tags to snapshots" for easier management.
  6. Consider enabling cross-region backup replication for disaster recovery.
  7. Test restore procedures regularly to ensure backups are valid.
- **Likelihood**: Medium

### Misconfiguration 5: Outdated Database Engine Version (Severity: MEDIUM)
- **Description**: RDS instance is running an outdated or deprecated database engine version that may contain known security vulnerabilities.
- **Risk**: Known CVEs in older database versions can be exploited. AWS may stop providing patches for end-of-life versions.
- **Attack Scenario**: An attacker identifies the database engine version through error messages or banner grabbing. They exploit a known CVE in the outdated version to gain unauthorized access or escalate privileges.
- **Remediation**:
  1. Check the current engine version in the RDS console.
  2. Review AWS documentation for the latest supported major version.
  3. Test the upgrade in a non-production environment first.
  4. Create a manual snapshot before upgrading.
  5. Apply minor version upgrade: Modify instance > "DB engine version" > select latest minor version.
  6. For major version upgrades, plan a maintenance window and test application compatibility.
  7. Enable "Auto minor version upgrade" to automatically apply future patches.
- **Likelihood**: Medium

---

## 3. Amazon EC2 (Elastic Compute Cloud)

### Service Overview
- Virtual server hosting service in the AWS cloud
- Key features: instances, security groups, EBS volumes, key pairs, IAM roles, VPC networking
- Assets: application servers, web servers, databases, microservices, development environments
- Attack surface: open ports, public IPs, unencrypted storage, missing IAM roles, exposed credentials

---

### Misconfiguration 1: Open Security Group Ports (Severity: HIGH)
- **Description**: Security groups with inbound rules allowing traffic from `0.0.0.0/0` (any IP) on sensitive ports like SSH (22), RDP (3389), database ports (3306, 5432, 1433, 27017).
- **Risk**: Critical services exposed to the entire internet, enabling brute-force attacks, vulnerability exploitation, and unauthorized access.
- **Attack Scenario**: An attacker scans for open SSH ports on port 22 across AWS IP ranges. They find an instance with a weak SSH password or a known vulnerability in the SSH daemon. They gain shell access, install a reverse shell, and use the compromised instance to pivot into the internal network.
- **Remediation**:
  1. Open the EC2 console > "Security Groups".
  2. Identify security groups with `0.0.0.0/0` or `::/0` on sensitive ports.
  3. Remove overly permissive rules.
  4. Replace with specific CIDR ranges (e.g., your office IP: `203.0.113.0/24`).
  5. For SSH, use AWS Systems Manager Session Manager instead of direct SSH.
  6. For RDP, use AWS WorkSpaces or a VPN connection.
  7. Implement AWS Config rule `restricted-ssh` and `restricted-common-ports`.
- **Likelihood**: High

### Misconfiguration 2: Unencrypted EBS Volumes (Severity: HIGH)
- **Description**: EBS volumes attached to EC2 instances are not encrypted, leaving data at rest in plaintext.
- **Risk**: Snapshots of unencrypted volumes can be shared or copied without encryption. Data on decommissioned hardware may be recoverable.
- **Attack Scenario**: An attacker gains access to the AWS account and creates snapshots of unencrypted EBS volumes. They share the snapshots with their own AWS account, attach them as volumes, and read all data including credentials, application code, and database files.
- **Remediation**:
  1. Enable EBS encryption by default in the EC2 console > "EBS Encryption" > "Manage".
  2. For existing unencrypted volumes:
     a. Create a snapshot of the unencrypted volume.
     b. Copy the snapshot with encryption enabled.
     c. Create a new volume from the encrypted snapshot.
     d. Stop the instance, detach the old volume, attach the new encrypted volume.
     e. Start the instance and verify functionality.
  3. Delete the old unencrypted volume and snapshot.
  4. Use AWS Config rule `encrypted-volumes` to monitor.
- **Likelihood**: Medium

### Misconfiguration 3: EC2 Instances with Public IPs (Severity: MEDIUM)
- **Description**: EC2 instances are assigned public IPv4 addresses, making them directly reachable from the internet.
- **Risk**: Increases the attack surface. Combined with open security groups, instances become prime targets for automated scanning and exploitation.
- **Attack Scenario**: An attacker discovers a public EC2 instance through Shodan or Censys. The instance runs a web application with a known vulnerability (e.g., Log4Shell). The attacker exploits it to gain code execution and access internal resources.
- **Remediation**:
  1. Evaluate if the instance truly needs a public IP.
  2. For web-facing workloads, place instances behind an Application Load Balancer (ALB).
  3. Move instances to private subnets and use a NAT Gateway for outbound internet access.
  4. Release and disassociate any unnecessary Elastic IP addresses.
  5. Disable "Auto-assign public IP" in the subnet settings.
  6. Use AWS Systems Manager for remote management instead of direct SSH/RDP.
  7. Implement VPC endpoints for AWS service access without internet routing.
- **Likelihood**: High

### Misconfiguration 4: Missing IAM Instance Profiles (Severity: MEDIUM)
- **Description**: EC2 instances running without an attached IAM instance profile (IAM role), forcing applications to use hard-coded or environment-variable credentials.
- **Risk**: Hard-coded credentials can be leaked through code repositories, logs, or instance metadata. No automatic credential rotation.
- **Attack Scenario**: An application on an EC2 instance uses hard-coded AWS access keys stored in a config file. The keys are accidentally committed to a public GitHub repository. An attacker finds them using tools like truffleHog, and uses the keys to access S3 buckets and other AWS resources.
- **Remediation**:
  1. Create an IAM role with the minimum required permissions for the application.
  2. Attach the role as an instance profile:
     a. Go to EC2 console > select instance > "Actions" > "Security" > "Modify IAM role".
     b. Select the appropriate IAM role.
  3. Update the application to use the AWS SDK's default credential chain (which automatically uses instance profile credentials).
  4. Remove any hard-coded access keys from application code, config files, and environment variables.
  5. Rotate and deactivate the old access keys.
  6. Use AWS Config rule `ec2-instance-profile-attached` to enforce.
- **Likelihood**: Medium

### Misconfiguration 5: Unused or Exposed Key Pairs (Severity: LOW)
- **Description**: EC2 key pairs that are no longer in use, or instances using default/shared key pairs without proper rotation.
- **Risk**: Stale key pairs increase the risk of compromised credentials being used for unauthorized access. Shared keys make it impossible to attribute access to specific users.
- **Attack Scenario**: A former employee retains a copy of a shared SSH key pair. Months after leaving, they use the key to access production EC2 instances, exfiltrate data, or plant backdoors.
- **Remediation**:
  1. Audit all EC2 key pairs: `aws ec2 describe-key-pairs`.
  2. Identify which instances use each key pair: cross-reference with `describe-instances`.
  3. For unused key pairs, delete them: `aws ec2 delete-key-pair --key-name KEY_NAME`.
  4. For active instances, rotate keys:
     a. Generate a new key pair.
     b. Add the new public key to `~/.ssh/authorized_keys` on each instance.
     c. Remove the old public key.
     d. Delete the old key pair from AWS.
  5. Migrate to AWS Systems Manager Session Manager to eliminate SSH key management entirely.
  6. Implement a key rotation policy (e.g., every 90 days).
- **Likelihood**: Medium

