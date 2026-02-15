# Amazon RDS — Security Misconfiguration Analysis

## Service Overview
- Managed relational database service supporting MySQL, PostgreSQL, MariaDB, Oracle, SQL Server, and Aurora
- Key features: automated backups, encryption, VPC isolation, Multi-AZ, read replicas
- Assets: application databases, user data, transaction records, business-critical data
- Attack surface: network exposure, unencrypted storage, weak authentication, missing backups

---

### Misconfiguration 1: Publicly Accessible Database (RDS-001 — Severity: HIGH)
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

---

### Misconfiguration 2: Unencrypted Database Storage (RDS-002 — Severity: HIGH)
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

---

### Misconfiguration 3: Database Not in VPC (RDS-003 — Severity: HIGH)
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

---

### Misconfiguration 4: Automated Backups Disabled (RDS-004 — Severity: MEDIUM)
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

---

### Misconfiguration 5: Outdated Database Engine Version (RDS-005 — Severity: MEDIUM)
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
