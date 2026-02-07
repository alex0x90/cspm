"""
EC2 Security Checks Module

Implements 5 security checks for Amazon EC2:
1. Open Security Group Ports
2. Unencrypted EBS Volumes
3. EC2 Instances with Public IPs
4. Missing IAM Instance Profiles
5. Unused or Exposed Key Pairs
"""

import sys
from typing import List

from botocore.exceptions import ClientError

from src.checks.base_check import BaseCheck
from src.models.findings import Finding, Severity, Status

sys.path.insert(0, __file__.rsplit("/src/", 1)[0])
from config.aws_config import SENSITIVE_PORTS


class EC2OpenPortsCheck(BaseCheck):
    """Check for security groups with open inbound rules on sensitive ports."""

    @property
    def check_name(self) -> str:
        return "EC2 Open Security Group Ports"

    @property
    def service(self) -> str:
        return "ec2"

    def get_severity(self) -> str:
        return Severity.HIGH

    def get_description(self) -> str:
        return (
            "Checks whether EC2 security groups allow inbound traffic from "
            "0.0.0.0/0 or ::/0 on sensitive ports (SSH, RDP, database ports)."
        )

    def get_remediation(self) -> str:
        return (
            "1. Open the EC2 console > 'Security Groups'.\n"
            "2. Identify security groups with 0.0.0.0/0 or ::/0 on sensitive ports.\n"
            "3. Remove overly permissive rules.\n"
            "4. Replace with specific CIDR ranges (e.g., your office IP).\n"
            "5. For SSH, use AWS Systems Manager Session Manager instead of direct SSH.\n"
            "6. For RDP, use AWS WorkSpaces or a VPN connection.\n"
            "7. Implement AWS Config rule 'restricted-ssh' and 'restricted-common-ports'."
        )

    def get_finding_id(self) -> str:
        return "EC2-001"

    def _get_port_name(self, port):
        """Return a human-readable name for a well-known port."""
        port_names = {
            22: "SSH",
            3389: "RDP",
            3306: "MySQL",
            1433: "MSSQL",
            5432: "PostgreSQL",
            27017: "MongoDB",
        }
        return port_names.get(port, str(port))

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

                    # Check IPv4 ranges
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            for port in SENSITIVE_PORTS:
                                if from_port <= port <= to_port:
                                    open_ports.append(f"{port} ({self._get_port_name(port)})")

                    # Check IPv6 ranges
                    for ip_range in rule.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            for port in SENSITIVE_PORTS:
                                if from_port <= port <= to_port:
                                    port_str = f"{port} ({self._get_port_name(port)})"
                                    if port_str not in open_ports:
                                        open_ports.append(port_str)

                if open_ports:
                    unique_ports = sorted(set(open_ports))
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=(
                            f"Security group '{sg_name}' ({sg_id}) in VPC '{vpc_id}' "
                            f"allows inbound traffic from 0.0.0.0/0 on sensitive ports: "
                            f"{', '.join(unique_ports)}."
                        ),
                        remediation=self.get_remediation(),
                        resource_id=sg_id,
                        region=self.region,
                    ))
                else:
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=(
                            f"Security group '{sg_name}' ({sg_id}) does not have "
                            f"open sensitive ports to the internet."
                        ),
                        resource_id=sg_id,
                        region=self.region,
                    ))

        if not sgs_found:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No security groups found in this region.",
                resource_id="N/A",
                region=self.region,
            ))

        return findings


class EC2UnencryptedEBSCheck(BaseCheck):
    """Check for unencrypted EBS volumes."""

    @property
    def check_name(self) -> str:
        return "EC2 EBS Volume Encryption"

    @property
    def service(self) -> str:
        return "ec2"

    def get_severity(self) -> str:
        return Severity.HIGH

    def get_description(self) -> str:
        return (
            "Checks whether EBS volumes attached to EC2 instances are "
            "encrypted to protect data at rest."
        )

    def get_remediation(self) -> str:
        return (
            "1. Enable EBS encryption by default in the EC2 console > 'EBS Encryption' > 'Manage'.\n"
            "2. For existing unencrypted volumes:\n"
            "   a. Create a snapshot of the unencrypted volume.\n"
            "   b. Copy the snapshot with encryption enabled.\n"
            "   c. Create a new volume from the encrypted snapshot.\n"
            "   d. Stop the instance, detach the old volume, attach the new encrypted volume.\n"
            "   e. Start the instance and verify functionality.\n"
            "3. Delete the old unencrypted volume and snapshot.\n"
            "4. Use AWS Config rule 'encrypted-volumes' to monitor."
        )

    def get_finding_id(self) -> str:
        return "EC2-002"

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
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=f"EBS volume '{vol_id}' is encrypted (attached to: {attached_to}).",
                        resource_id=vol_id,
                        region=self.region,
                    ))
                else:
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=(
                            f"EBS volume '{vol_id}' is NOT encrypted "
                            f"(state: {state}, attached to: {attached_to})."
                        ),
                        remediation=self.get_remediation(),
                        resource_id=vol_id,
                        region=self.region,
                    ))

        if not volumes_found:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No EBS volumes found in this region.",
                resource_id="N/A",
                region=self.region,
            ))

        return findings


class EC2PublicIPCheck(BaseCheck):
    """Check for EC2 instances with public IP addresses."""

    @property
    def check_name(self) -> str:
        return "EC2 Public IP Assignment"

    @property
    def service(self) -> str:
        return "ec2"

    def get_severity(self) -> str:
        return Severity.MEDIUM

    def get_description(self) -> str:
        return (
            "Checks whether EC2 instances have public IPv4 addresses assigned, "
            "making them directly reachable from the internet."
        )

    def get_remediation(self) -> str:
        return (
            "1. Evaluate if the instance truly needs a public IP.\n"
            "2. For web-facing workloads, place instances behind an Application Load Balancer (ALB).\n"
            "3. Move instances to private subnets and use a NAT Gateway for outbound internet access.\n"
            "4. Release and disassociate any unnecessary Elastic IP addresses.\n"
            "5. Disable 'Auto-assign public IP' in the subnet settings.\n"
            "6. Use AWS Systems Manager for remote management instead of direct SSH/RDP.\n"
            "7. Implement VPC endpoints for AWS service access without internet routing."
        )

    def get_finding_id(self) -> str:
        return "EC2-003"

    def check(self) -> List[Finding]:
        findings = []
        paginator = self.client.get_paginator("describe_instances")

        instances_found = False
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    # Skip terminated instances
                    state = instance.get("State", {}).get("Name", "")
                    if state == "terminated":
                        continue

                    instances_found = True
                    instance_id = instance["InstanceId"]
                    public_ip = instance.get("PublicIpAddress")
                    public_dns = instance.get("PublicDnsName", "")

                    # Get instance name from tags
                    name = "N/A"
                    for tag in instance.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                            break

                    if public_ip:
                        findings.append(Finding(
                            check_id=self.get_finding_id(),
                            check_name=self.check_name,
                            severity=self.get_severity(),
                            status=Status.FAILED,
                            description=self.get_description(),
                            finding=(
                                f"EC2 instance '{instance_id}' (Name: {name}) has a public IP: "
                                f"{public_ip} (DNS: {public_dns})."
                            ),
                            remediation=self.get_remediation(),
                            resource_id=instance_id,
                            region=self.region,
                        ))
                    else:
                        findings.append(Finding(
                            check_id=self.get_finding_id(),
                            check_name=self.check_name,
                            severity=self.get_severity(),
                            status=Status.PASSED,
                            description=self.get_description(),
                            finding=f"EC2 instance '{instance_id}' (Name: {name}) does not have a public IP.",
                            resource_id=instance_id,
                            region=self.region,
                        ))

        if not instances_found:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No running EC2 instances found in this region.",
                resource_id="N/A",
                region=self.region,
            ))

        return findings


class EC2IAMRoleCheck(BaseCheck):
    """Check for EC2 instances without IAM instance profiles."""

    @property
    def check_name(self) -> str:
        return "EC2 IAM Instance Profile"

    @property
    def service(self) -> str:
        return "ec2"

    def get_severity(self) -> str:
        return Severity.MEDIUM

    def get_description(self) -> str:
        return (
            "Checks whether EC2 instances have an IAM instance profile (IAM role) "
            "attached, avoiding the need for hard-coded credentials."
        )

    def get_remediation(self) -> str:
        return (
            "1. Create an IAM role with the minimum required permissions for the application.\n"
            "2. Attach the role as an instance profile:\n"
            "   a. Go to EC2 console > select instance > 'Actions' > 'Security' > 'Modify IAM role'.\n"
            "   b. Select the appropriate IAM role.\n"
            "3. Update the application to use the AWS SDK's default credential chain.\n"
            "4. Remove any hard-coded access keys from application code, config files, "
            "and environment variables.\n"
            "5. Rotate and deactivate the old access keys.\n"
            "6. Use AWS Config rule 'ec2-instance-profile-attached' to enforce."
        )

    def get_finding_id(self) -> str:
        return "EC2-004"

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

                    # Get instance name from tags
                    name = "N/A"
                    for tag in instance.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                            break

                    if iam_profile:
                        profile_arn = iam_profile.get("Arn", "N/A")
                        findings.append(Finding(
                            check_id=self.get_finding_id(),
                            check_name=self.check_name,
                            severity=self.get_severity(),
                            status=Status.PASSED,
                            description=self.get_description(),
                            finding=(
                                f"EC2 instance '{instance_id}' (Name: {name}) has an IAM "
                                f"instance profile attached: {profile_arn}."
                            ),
                            resource_id=instance_id,
                            region=self.region,
                        ))
                    else:
                        findings.append(Finding(
                            check_id=self.get_finding_id(),
                            check_name=self.check_name,
                            severity=self.get_severity(),
                            status=Status.FAILED,
                            description=self.get_description(),
                            finding=(
                                f"EC2 instance '{instance_id}' (Name: {name}) does NOT have "
                                f"an IAM instance profile attached."
                            ),
                            remediation=self.get_remediation(),
                            resource_id=instance_id,
                            region=self.region,
                        ))

        if not instances_found:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No running EC2 instances found in this region.",
                resource_id="N/A",
                region=self.region,
            ))

        return findings


class EC2KeyPairCheck(BaseCheck):
    """Check for unused or potentially exposed EC2 key pairs."""

    @property
    def check_name(self) -> str:
        return "EC2 Key Pair Usage"

    @property
    def service(self) -> str:
        return "ec2"

    def get_severity(self) -> str:
        return Severity.LOW

    def get_description(self) -> str:
        return (
            "Checks for EC2 key pairs that are not currently in use by any "
            "running instance, which may indicate stale or orphaned keys."
        )

    def get_remediation(self) -> str:
        return (
            "1. Audit all EC2 key pairs: aws ec2 describe-key-pairs.\n"
            "2. Identify which instances use each key pair by cross-referencing with describe-instances.\n"
            "3. For unused key pairs, delete them: aws ec2 delete-key-pair --key-name KEY_NAME.\n"
            "4. For active instances, rotate keys:\n"
            "   a. Generate a new key pair.\n"
            "   b. Add the new public key to ~/.ssh/authorized_keys on each instance.\n"
            "   c. Remove the old public key.\n"
            "   d. Delete the old key pair from AWS.\n"
            "5. Migrate to AWS Systems Manager Session Manager to eliminate SSH key management.\n"
            "6. Implement a key rotation policy (e.g., every 90 days)."
        )

    def get_finding_id(self) -> str:
        return "EC2-005"

    def check(self) -> List[Finding]:
        findings = []

        # Get all key pairs
        key_pairs_response = self.client.describe_key_pairs()
        key_pairs = key_pairs_response.get("KeyPairs", [])

        if not key_pairs:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No EC2 key pairs found in this region.",
                resource_id="N/A",
                region=self.region,
            ))
            return findings

        # Get all running instances and their key pairs
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

        # Check each key pair
        for kp in key_pairs:
            kp_name = kp["KeyName"]
            kp_id = kp.get("KeyPairId", kp_name)

            if kp_name in used_key_names:
                findings.append(Finding(
                    check_id=self.get_finding_id(),
                    check_name=self.check_name,
                    severity=self.get_severity(),
                    status=Status.PASSED,
                    description=self.get_description(),
                    finding=f"Key pair '{kp_name}' ({kp_id}) is in use by running/stopped instances.",
                    resource_id=kp_id,
                    region=self.region,
                ))
            else:
                findings.append(Finding(
                    check_id=self.get_finding_id(),
                    check_name=self.check_name,
                    severity=self.get_severity(),
                    status=Status.FAILED,
                    description=self.get_description(),
                    finding=(
                        f"Key pair '{kp_name}' ({kp_id}) is NOT used by any "
                        f"running/stopped instances. Consider deleting or rotating."
                    ),
                    remediation=self.get_remediation(),
                    resource_id=kp_id,
                    region=self.region,
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

