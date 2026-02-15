# Amazon EC2 — Security Misconfiguration Analysis

## Service Overview
- Virtual server hosting service in the AWS cloud
- Key features: instances, security groups, EBS volumes, key pairs, IAM roles, VPC networking
- Assets: application servers, web servers, databases, microservices, development environments
- Attack surface: open ports, public IPs, unencrypted storage, missing IAM roles, exposed credentials

---

### Misconfiguration 1: Open Security Group Ports (EC2-001 — Severity: HIGH)
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

---

### Misconfiguration 2: Unencrypted EBS Volumes (EC2-002 — Severity: HIGH)
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

---

### Misconfiguration 3: EC2 Instances with Public IPs (EC2-003 — Severity: MEDIUM)
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

---

### Misconfiguration 4: Missing IAM Instance Profiles (EC2-004 — Severity: MEDIUM)
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

---

### Misconfiguration 5: Unused or Exposed Key Pairs (EC2-005 — Severity: LOW)
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
