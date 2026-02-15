"""
EC2 Security Checks Module

Implements 5 security checks for Amazon EC2:
1. Open Security Group Ports
2. Unencrypted EBS Volumes
3. EC2 Instances with Public IPs
4. Missing IAM Instance Profiles
5. Unused or Exposed Key Pairs
"""

from typing import List

from botocore.exceptions import ClientError

from src.checks.base_check import BaseCheck
from src.checks.constants import SENSITIVE_PORTS
from src.models.findings import Finding, Severity, Status


# ------------------------------------------------------------------
# EC2-001: Open Security Group Ports
# ------------------------------------------------------------------

class EC2OpenPortsCheck(BaseCheck):
    """Check for security groups with open inbound rules on sensitive ports."""

    check_name = "EC2 Open Security Group Ports"
    service = "ec2"
    severity = Severity.HIGH
    finding_id = "EC2-001"
    description = (
        "Checks whether EC2 security groups allow inbound traffic from "
        "0.0.0.0/0 or ::/0 on sensitive ports (SSH, RDP, database ports)."
    )
    impact = (
        "Open sensitive ports (SSH, RDP, database) to 0.0.0.0/0 expose services to "
        "brute-force attacks, credential stuffing, and exploitation of known vulnerabilities "
        "from any source on the internet."
    )
    remediation = [
        "1. Open the EC2 console > 'Security Groups'.",
        "2. Identify security groups with 0.0.0.0/0 or ::/0 on sensitive ports.",
        "3. Remove overly permissive rules.",
        "4. Replace with specific CIDR ranges (e.g., your office IP).",
        "5. For SSH, use AWS Systems Manager Session Manager instead of direct SSH.",
        "6. For RDP, use AWS WorkSpaces or a VPN connection.",
        "7. Implement AWS Config rule 'restricted-ssh' and 'restricted-common-ports'.",
    ]

    _PORT_NAMES = {
        22: "SSH", 3389: "RDP", 3306: "MySQL",
        1433: "MSSQL", 5432: "PostgreSQL", 27017: "MongoDB",
    }

    def _get_port_name(self, port):
        """Return a human-readable name for a well-known port."""
        return self._PORT_NAMES.get(port, str(port))

    def check(self) -> List[Finding]:
        findings = []
        paginator = self.client.get_paginator("describe_security_groups")

        sgs_found = False
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sgs_found = True
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "N/A")
                vpc_id = sg.get("VpcId", "N/A")
                open_ports = []

                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)

                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            for port in SENSITIVE_PORTS:
                                if from_port <= port <= to_port:
                                    open_ports.append(f"{port} ({self._get_port_name(port)})")

                    for ip_range in rule.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            for port in SENSITIVE_PORTS:
                                if from_port <= port <= to_port:
                                    port_str = f"{port} ({self._get_port_name(port)})"
                                    if port_str not in open_ports:
                                        open_ports.append(port_str)

                if open_ports:
                    unique_ports = sorted(set(open_ports))
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"Security group '{sg_name}' ({sg_id}) in VPC '{vpc_id}' "
                        f"allows inbound traffic from 0.0.0.0/0 on sensitive ports: "
                        f"{', '.join(unique_ports)}.",
                        resource_id=sg_id,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"Security group '{sg_name}' ({sg_id}) does not have "
                        f"open sensitive ports to the internet.",
                        resource_id=sg_id,
                    ))

        if not sgs_found:
            findings.append(self._make_finding(
                Status.PASSED, "No security groups found in this region.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# EC2-002: Unencrypted EBS Volumes
# ------------------------------------------------------------------

class EC2UnencryptedEBSCheck(BaseCheck):
    """Check for unencrypted EBS volumes."""

    check_name = "EC2 EBS Volume Encryption"
    service = "ec2"
    severity = Severity.HIGH
    finding_id = "EC2-002"
    description = (
        "Checks whether EBS volumes attached to EC2 instances are "
        "encrypted to protect data at rest."
    )
    impact = (
        "Unencrypted EBS volumes expose data at rest to unauthorized access if the "
        "underlying storage is compromised. This violates compliance requirements "
        "and increases the risk of data breaches."
    )
    remediation = [
        "1. Enable EBS encryption by default in the EC2 console > 'EBS Encryption' > 'Manage'.",
        "2. For existing unencrypted volumes:",
        "   a. Create a snapshot of the unencrypted volume.",
        "   b. Copy the snapshot with encryption enabled.",
        "   c. Create a new volume from the encrypted snapshot.",
        "   d. Stop the instance, detach the old volume, attach the new encrypted volume.",
        "   e. Start the instance and verify functionality.",
        "3. Delete the old unencrypted volume and snapshot.",
        "4. Use AWS Config rule 'encrypted-volumes' to monitor.",
    ]

    def check(self) -> List[Finding]:
        findings = []
        paginator = self.client.get_paginator("describe_volumes")

        volumes_found = False
        for page in paginator.paginate():
            for volume in page.get("Volumes", []):
                volumes_found = True
                vol_id = volume["VolumeId"]
                encrypted = volume.get("Encrypted", False)
                state = volume.get("State", "unknown")
                attachments = volume.get("Attachments", [])
                attached_to = ", ".join(
                    a.get("InstanceId", "N/A") for a in attachments
                ) if attachments else "Not attached"

                if encrypted:
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"EBS volume '{vol_id}' is encrypted (attached to: {attached_to}).",
                        resource_id=vol_id,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"EBS volume '{vol_id}' is NOT encrypted "
                        f"(state: {state}, attached to: {attached_to}).",
                        resource_id=vol_id,
                    ))

        if not volumes_found:
            findings.append(self._make_finding(
                Status.PASSED, "No EBS volumes found in this region.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# EC2-003: Public IP Assignment
# ------------------------------------------------------------------

class EC2PublicIPCheck(BaseCheck):
    """Check for EC2 instances with public IP addresses."""

    check_name = "EC2 Public IP Assignment"
    service = "ec2"
    severity = Severity.MEDIUM
    finding_id = "EC2-003"
    description = (
        "Checks whether EC2 instances have public IPv4 addresses assigned, "
        "making them directly reachable from the internet."
    )
    impact = (
        "EC2 instances with public IPs are directly reachable from the internet, "
        "increasing the attack surface. Attackers can scan and target these instances "
        "for vulnerabilities, open ports, or misconfigured services."
    )
    remediation = [
        "1. Evaluate if the instance truly needs a public IP.",
        "2. For web-facing workloads, place instances behind an Application Load Balancer (ALB).",
        "3. Move instances to private subnets and use a NAT Gateway for outbound internet access.",
        "4. Release and disassociate any unnecessary Elastic IP addresses.",
        "5. Disable 'Auto-assign public IP' in the subnet settings.",
        "6. Use AWS Systems Manager for remote management instead of direct SSH/RDP.",
        "7. Implement VPC endpoints for AWS service access without internet routing.",
    ]

    def check(self) -> List[Finding]:
        findings = []
        paginator = self.client.get_paginator("describe_instances")

        instances_found = False
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    state = instance.get("State", {}).get("Name", "")
                    if state == "terminated":
                        continue

                    instances_found = True
                    instance_id = instance["InstanceId"]
                    public_ip = instance.get("PublicIpAddress")
                    public_dns = instance.get("PublicDnsName", "")

                    name = "N/A"
                    for tag in instance.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                            break

                    if public_ip:
                        findings.append(self._make_finding(
                            Status.FAILED,
                            f"EC2 instance '{instance_id}' (Name: {name}) has a public IP: "
                            f"{public_ip} (DNS: {public_dns}).",
                            resource_id=instance_id,
                        ))
                    else:
                        findings.append(self._make_finding(
                            Status.PASSED,
                            f"EC2 instance '{instance_id}' (Name: {name}) does not have a public IP.",
                            resource_id=instance_id,
                        ))

        if not instances_found:
            findings.append(self._make_finding(
                Status.PASSED, "No running EC2 instances found in this region.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# EC2-004: IAM Instance Profile
# ------------------------------------------------------------------

class EC2IAMRoleCheck(BaseCheck):
    """Check for EC2 instances without IAM instance profiles."""

    check_name = "EC2 IAM Instance Profile"
    service = "ec2"
    severity = Severity.MEDIUM
    finding_id = "EC2-004"
    description = (
        "Checks whether EC2 instances have an IAM instance profile (IAM role) "
        "attached, avoiding the need for hard-coded credentials."
    )
    impact = (
        "Without an IAM instance profile, applications on the instance may rely on "
        "hard-coded access keys, which are difficult to rotate and easily leaked. "
        "This increases the risk of credential compromise and unauthorized access."
    )
    remediation = [
        "1. Create an IAM role with the minimum required permissions for the application.",
        "2. Attach the role as an instance profile:",
        "   a. Go to EC2 console > select instance > 'Actions' > 'Security' > 'Modify IAM role'.",
        "   b. Select the appropriate IAM role.",
        "3. Update the application to use the AWS SDK's default credential chain.",
        "4. Remove any hard-coded access keys from application code, config files, and environment variables.",
        "5. Rotate and deactivate the old access keys.",
        "6. Use AWS Config rule 'ec2-instance-profile-attached' to enforce.",
    ]

    def check(self) -> List[Finding]:
        findings = []
        paginator = self.client.get_paginator("describe_instances")

        instances_found = False
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    state = instance.get("State", {}).get("Name", "")
                    if state == "terminated":
                        continue

                    instances_found = True
                    instance_id = instance["InstanceId"]
                    iam_profile = instance.get("IamInstanceProfile")

                    name = "N/A"
                    for tag in instance.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                            break

                    if iam_profile:
                        profile_arn = iam_profile.get("Arn", "N/A")
                        findings.append(self._make_finding(
                            Status.PASSED,
                            f"EC2 instance '{instance_id}' (Name: {name}) has an IAM "
                            f"instance profile attached: {profile_arn}.",
                            resource_id=instance_id,
                        ))
                    else:
                        findings.append(self._make_finding(
                            Status.FAILED,
                            f"EC2 instance '{instance_id}' (Name: {name}) does NOT have "
                            f"an IAM instance profile attached.",
                            resource_id=instance_id,
                        ))

        if not instances_found:
            findings.append(self._make_finding(
                Status.PASSED, "No running EC2 instances found in this region.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# EC2-005: Key Pair Usage
# ------------------------------------------------------------------

class EC2KeyPairCheck(BaseCheck):
    """Check for unused or potentially exposed EC2 key pairs."""

    check_name = "EC2 Key Pair Usage"
    service = "ec2"
    severity = Severity.LOW
    finding_id = "EC2-005"
    description = (
        "Checks for EC2 key pairs that are not currently in use by any "
        "running instance, which may indicate stale or orphaned keys."
    )
    impact = (
        "Unused key pairs represent stale credentials that increase the risk of "
        "unauthorized access if compromised. They also indicate a lack of key "
        "management hygiene, making it harder to track active credentials."
    )
    remediation = [
        "1. Audit all EC2 key pairs: aws ec2 describe-key-pairs.",
        "2. Identify which instances use each key pair by cross-referencing with describe-instances.",
        "3. For unused key pairs, delete them: aws ec2 delete-key-pair --key-name KEY_NAME.",
        "4. For active instances, rotate keys:",
        "   a. Generate a new key pair.",
        "   b. Add the new public key to ~/.ssh/authorized_keys on each instance.",
        "   c. Remove the old public key.",
        "   d. Delete the old key pair from AWS.",
        "5. Migrate to AWS Systems Manager Session Manager to eliminate SSH key management.",
        "6. Implement a key rotation policy (e.g., every 90 days).",
    ]

    def check(self) -> List[Finding]:
        findings = []

        key_pairs_response = self.client.describe_key_pairs()
        key_pairs = key_pairs_response.get("KeyPairs", [])

        if not key_pairs:
            findings.append(self._make_finding(
                Status.PASSED, "No EC2 key pairs found in this region.", resource_id="N/A",
            ))
            return findings

        used_key_names = set()
        paginator = self.client.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped", "pending"]}]
        ):
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    key_name = instance.get("KeyName")
                    if key_name:
                        used_key_names.add(key_name)

        for kp in key_pairs:
            kp_name = kp["KeyName"]
            kp_id = kp.get("KeyPairId", kp_name)

            if kp_name in used_key_names:
                findings.append(self._make_finding(
                    Status.PASSED,
                    f"Key pair '{kp_name}' ({kp_id}) is in use by running/stopped instances.",
                    resource_id=kp_id,
                ))
            else:
                findings.append(self._make_finding(
                    Status.FAILED,
                    f"Key pair '{kp_name}' ({kp_id}) is NOT used by any "
                    f"running/stopped instances. Consider deleting or rotating.",
                    resource_id=kp_id,
                ))

        return findings


# Registry of all EC2 checks for easy discovery
EC2_CHECKS = [
    EC2OpenPortsCheck,
    EC2UnencryptedEBSCheck,
    EC2PublicIPCheck,
    EC2IAMRoleCheck,
    EC2KeyPairCheck,
]
