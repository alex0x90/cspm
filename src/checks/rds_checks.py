"""
RDS Security Checks Module

Implements 5 security checks for Amazon RDS:
1. Publicly Accessible Database
2. Unencrypted Database Storage
3. Database Not in VPC
4. Automated Backups Disabled
5. Outdated Database Engine Version
"""

from typing import List

from botocore.exceptions import ClientError

from src.checks.base_check import BaseCheck
from src.checks.constants import LATEST_ENGINE_VERSIONS
from src.models.findings import Finding, Severity, Status


# ------------------------------------------------------------------
# RDS-001: Publicly Accessible Database
# ------------------------------------------------------------------

class RDSPublicAccessCheck(BaseCheck):
    """Check for RDS instances that are publicly accessible."""

    check_name = "RDS Publicly Accessible Database"
    service = "rds"
    severity = Severity.HIGH
    finding_id = "RDS-001"
    description = (
        "Checks whether RDS instances have the PubliclyAccessible flag "
        "set to True, exposing the database to the internet."
    )
    impact = (
        "A publicly accessible RDS instance is exposed to the internet, increasing the risk "
        "of brute-force attacks, unauthorized access, and data breaches. Attackers can directly "
        "target the database endpoint without needing to compromise other network layers."
    )
    remediation = [
        "1. Open the RDS console and select the affected DB instance.",
        "2. Click 'Modify'.",
        "3. Under 'Connectivity', set 'Publicly accessible' to 'No'.",
        "4. Click 'Continue' and apply changes (may require a brief outage).",
        "5. Ensure the DB is in a private subnet within your VPC.",
        "6. Use a bastion host or VPN for administrative access.",
        "7. Review security groups to ensure no 0.0.0.0/0 inbound rules.",
    ]

    def check(self) -> List[Finding]:
        findings = []
        paginator = self.client.get_paginator("describe_db_instances")

        instances_found = False
        for page in paginator.paginate():
            for instance in page.get("DBInstances", []):
                instances_found = True
                db_id = instance["DBInstanceIdentifier"]
                publicly_accessible = instance.get("PubliclyAccessible", False)

                if publicly_accessible:
                    endpoint = instance.get("Endpoint", {}).get("Address", "N/A")
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"RDS instance '{db_id}' is publicly accessible (endpoint: {endpoint}).",
                        resource_id=db_id,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"RDS instance '{db_id}' is not publicly accessible.",
                        resource_id=db_id,
                    ))

        if not instances_found:
            findings.append(self._make_finding(
                Status.PASSED, "No RDS instances found in this region.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# RDS-002: Storage Encryption
# ------------------------------------------------------------------

class RDSEncryptionCheck(BaseCheck):
    """Check for RDS instances without storage encryption."""

    check_name = "RDS Storage Encryption"
    service = "rds"
    severity = Severity.HIGH
    finding_id = "RDS-002"
    description = (
        "Checks whether RDS instances have storage encryption enabled "
        "to protect data at rest."
    )
    impact = (
        "Without storage encryption, data at rest on the RDS instance is vulnerable to "
        "unauthorized access if the underlying storage is compromised. This violates "
        "compliance requirements such as PCI-DSS, HIPAA, and GDPR."
    )
    remediation = [
        "1. Note: Encryption cannot be enabled on an existing unencrypted RDS instance directly.",
        "2. Create a snapshot of the unencrypted DB instance.",
        "3. Copy the snapshot and enable encryption (select a KMS key).",
        "4. Restore a new DB instance from the encrypted snapshot.",
        "5. Update application connection strings to point to the new encrypted instance.",
        "6. Verify the application works, then delete the old unencrypted instance.",
        "7. Enable encryption by default for new instances in your CloudFormation/Terraform templates.",
    ]

    def check(self) -> List[Finding]:
        findings = []
        paginator = self.client.get_paginator("describe_db_instances")

        instances_found = False
        for page in paginator.paginate():
            for instance in page.get("DBInstances", []):
                instances_found = True
                db_id = instance["DBInstanceIdentifier"]
                encrypted = instance.get("StorageEncrypted", False)

                if encrypted:
                    kms_key = instance.get("KmsKeyId", "Default")
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"RDS instance '{db_id}' has storage encryption enabled (KMS key: {kms_key}).",
                        resource_id=db_id,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"RDS instance '{db_id}' does not have storage encryption enabled.",
                        resource_id=db_id,
                    ))

        if not instances_found:
            findings.append(self._make_finding(
                Status.PASSED, "No RDS instances found in this region.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# RDS-003: VPC Configuration
# ------------------------------------------------------------------

class RDSVPCCheck(BaseCheck):
    """Check for RDS instances not deployed within a VPC."""

    check_name = "RDS VPC Configuration"
    service = "rds"
    severity = Severity.HIGH
    finding_id = "RDS-003"
    description = (
        "Checks whether RDS instances are deployed within a VPC for "
        "proper network isolation and security."
    )
    impact = (
        "An RDS instance not deployed in a VPC lacks network-level isolation, making it "
        "accessible from EC2-Classic shared network. This prevents proper security group "
        "controls and subnet-based access restrictions."
    )
    remediation = [
        "1. Create a VPC with private subnets across multiple Availability Zones.",
        "2. Create a DB subnet group using the private subnets.",
        "3. Create a snapshot of the existing DB instance.",
        "4. Restore the snapshot into the VPC using the new DB subnet group.",
        "5. Update security groups to restrict inbound access to only application subnets.",
        "6. Update application connection endpoints.",
        "7. Test connectivity and delete the old non-VPC instance.",
    ]

    def check(self) -> List[Finding]:
        findings = []
        paginator = self.client.get_paginator("describe_db_instances")

        instances_found = False
        for page in paginator.paginate():
            for instance in page.get("DBInstances", []):
                instances_found = True
                db_id = instance["DBInstanceIdentifier"]
                subnet_group = instance.get("DBSubnetGroup")

                if subnet_group:
                    vpc_id = subnet_group.get("VpcId", "Unknown")
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"RDS instance '{db_id}' is deployed in VPC '{vpc_id}'.",
                        resource_id=db_id,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"RDS instance '{db_id}' is not deployed within a VPC (EC2-Classic).",
                        resource_id=db_id,
                    ))

        if not instances_found:
            findings.append(self._make_finding(
                Status.PASSED, "No RDS instances found in this region.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# RDS-004: Automated Backups
# ------------------------------------------------------------------

class RDSBackupCheck(BaseCheck):
    """Check for RDS instances with automated backups disabled."""

    check_name = "RDS Automated Backups"
    service = "rds"
    severity = Severity.MEDIUM
    finding_id = "RDS-004"
    description = (
        "Checks whether RDS instances have automated backups enabled "
        "with a retention period greater than 0 days."
    )
    impact = (
        "Without automated backups, data loss from accidental deletion, corruption, or "
        "infrastructure failure is permanent. Point-in-time recovery is unavailable, "
        "significantly increasing disaster recovery time and risk."
    )
    remediation = [
        "1. Open the RDS console and select the DB instance.",
        "2. Click 'Modify'.",
        "3. Set 'Backup retention period' to at least 7 days (AWS maximum is 35 days).",
        "4. Configure a backup window during low-traffic periods.",
        "5. Enable 'Copy tags to snapshots' for easier management.",
        "6. Consider enabling cross-region backup replication for disaster recovery.",
        "7. Test restore procedures regularly to ensure backups are valid.",
    ]

    def check(self) -> List[Finding]:
        findings = []
        paginator = self.client.get_paginator("describe_db_instances")

        instances_found = False
        for page in paginator.paginate():
            for instance in page.get("DBInstances", []):
                instances_found = True
                db_id = instance["DBInstanceIdentifier"]
                retention = instance.get("BackupRetentionPeriod", 0)

                if retention > 0:
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"RDS instance '{db_id}' has automated backups enabled (retention: {retention} days).",
                        resource_id=db_id,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"RDS instance '{db_id}' has automated backups disabled (retention period: 0 days).",
                        resource_id=db_id,
                    ))

        if not instances_found:
            findings.append(self._make_finding(
                Status.PASSED, "No RDS instances found in this region.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# RDS-005: Engine Version
# ------------------------------------------------------------------

class RDSEngineVersionCheck(BaseCheck):
    """Check for RDS instances running outdated engine versions."""

    check_name = "RDS Engine Version"
    service = "rds"
    severity = Severity.MEDIUM
    finding_id = "RDS-005"
    description = (
        "Checks whether RDS instances are running outdated or deprecated "
        "database engine versions that may contain known vulnerabilities."
    )
    impact = (
        "Running an outdated database engine version exposes the instance to known "
        "vulnerabilities that have been patched in newer releases. This increases the risk "
        "of exploitation and may also result in loss of vendor support."
    )
    remediation = [
        "1. Check the current engine version in the RDS console.",
        "2. Review AWS documentation for the latest supported major version.",
        "3. Test the upgrade in a non-production environment first.",
        "4. Create a manual snapshot before upgrading.",
        "5. Apply minor version upgrade: Modify instance > 'DB engine version' > select latest.",
        "6. For major version upgrades, plan a maintenance window and test application compatibility.",
        "7. Enable 'Auto minor version upgrade' to automatically apply future patches.",
    ]

    def _is_version_outdated(self, engine, version):
        """Check if the engine version is outdated by comparing major versions."""
        engine_lower = engine.lower()
        latest = LATEST_ENGINE_VERSIONS.get(engine_lower)
        if not latest:
            return False, "Unknown engine"

        try:
            current_major = version.split(".")[0]
            latest_major = latest.split(".")[0]
            if int(current_major) < int(latest_major):
                return True, f"Current: {version}, Latest major: {latest}"
        except (ValueError, IndexError):
            return False, "Unable to parse version"

        return False, f"Current: {version}, Latest major: {latest}"

    def check(self) -> List[Finding]:
        findings = []
        paginator = self.client.get_paginator("describe_db_instances")

        instances_found = False
        for page in paginator.paginate():
            for instance in page.get("DBInstances", []):
                instances_found = True
                db_id = instance["DBInstanceIdentifier"]
                engine = instance.get("Engine", "unknown")
                version = instance.get("EngineVersion", "unknown")
                auto_minor = instance.get("AutoMinorVersionUpgrade", False)

                outdated, version_info = self._is_version_outdated(engine, version)

                if outdated:
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"RDS instance '{db_id}' is running an outdated engine version. "
                        f"Engine: {engine}, {version_info}. "
                        f"Auto minor version upgrade: {'Enabled' if auto_minor else 'Disabled'}.",
                        resource_id=db_id,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"RDS instance '{db_id}' engine version is current. "
                        f"Engine: {engine}, {version_info}. "
                        f"Auto minor version upgrade: {'Enabled' if auto_minor else 'Disabled'}.",
                        resource_id=db_id,
                    ))

        if not instances_found:
            findings.append(self._make_finding(
                Status.PASSED, "No RDS instances found in this region.", resource_id="N/A",
            ))

        return findings


# Registry of all RDS checks for easy discovery
RDS_CHECKS = [
    RDSPublicAccessCheck,
    RDSEncryptionCheck,
    RDSVPCCheck,
    RDSBackupCheck,
    RDSEngineVersionCheck,
]
