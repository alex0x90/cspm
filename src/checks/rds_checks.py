"""
RDS Security Checks Module

Implements 5 security checks for Amazon RDS:
1. Publicly Accessible Database
2. Unencrypted Database Storage
3. Database Not in VPC
4. Automated Backups Disabled
5. Outdated Database Engine Version
"""

import sys
from typing import List

from botocore.exceptions import ClientError

from src.checks.base_check import BaseCheck
from src.models.findings import Finding, Severity, Status

sys.path.insert(0, __file__.rsplit("/src/", 1)[0])
from config.aws_config import LATEST_ENGINE_VERSIONS


class RDSPublicAccessCheck(BaseCheck):
    """Check for RDS instances that are publicly accessible."""

    @property
    def check_name(self) -> str:
        return "RDS Publicly Accessible Database"

    @property
    def service(self) -> str:
        return "rds"

    def get_severity(self) -> str:
        return Severity.HIGH

    def get_description(self) -> str:
        return (
            "Checks whether RDS instances have the PubliclyAccessible flag "
            "set to True, exposing the database to the internet."
        )

    def get_remediation(self) -> str:
        return (
            "1. Open the RDS console and select the affected DB instance.\n"
            "2. Click 'Modify'.\n"
            "3. Under 'Connectivity', set 'Publicly accessible' to 'No'.\n"
            "4. Click 'Continue' and apply changes (may require a brief outage).\n"
            "5. Ensure the DB is in a private subnet within your VPC.\n"
            "6. Use a bastion host or VPN for administrative access.\n"
            "7. Review security groups to ensure no 0.0.0.0/0 inbound rules."
        )

    def get_finding_id(self) -> str:
        return "RDS-001"

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
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=f"RDS instance '{db_id}' is publicly accessible (endpoint: {endpoint}).",
                        remediation=self.get_remediation(),
                        resource_id=db_id,
                        region=self.region,
                    ))
                else:
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=f"RDS instance '{db_id}' is not publicly accessible.",
                        resource_id=db_id,
                        region=self.region,
                    ))

        if not instances_found:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No RDS instances found in this region.",
                resource_id="N/A",
                region=self.region,
            ))

        return findings


class RDSEncryptionCheck(BaseCheck):
    """Check for RDS instances without storage encryption."""

    @property
    def check_name(self) -> str:
        return "RDS Storage Encryption"

    @property
    def service(self) -> str:
        return "rds"

    def get_severity(self) -> str:
        return Severity.HIGH

    def get_description(self) -> str:
        return (
            "Checks whether RDS instances have storage encryption enabled "
            "to protect data at rest."
        )

    def get_remediation(self) -> str:
        return (
            "1. Note: Encryption cannot be enabled on an existing unencrypted RDS instance directly.\n"
            "2. Create a snapshot of the unencrypted DB instance.\n"
            "3. Copy the snapshot and enable encryption (select a KMS key).\n"
            "4. Restore a new DB instance from the encrypted snapshot.\n"
            "5. Update application connection strings to point to the new encrypted instance.\n"
            "6. Verify the application works, then delete the old unencrypted instance.\n"
            "7. Enable encryption by default for new instances in your CloudFormation/Terraform templates."
        )

    def get_finding_id(self) -> str:
        return "RDS-002"

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
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=f"RDS instance '{db_id}' has storage encryption enabled (KMS key: {kms_key}).",
                        resource_id=db_id,
                        region=self.region,
                    ))
                else:
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=f"RDS instance '{db_id}' does not have storage encryption enabled.",
                        remediation=self.get_remediation(),
                        resource_id=db_id,
                        region=self.region,
                    ))

        if not instances_found:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No RDS instances found in this region.",
                resource_id="N/A",
                region=self.region,
            ))

        return findings


class RDSVPCCheck(BaseCheck):
    """Check for RDS instances not deployed within a VPC."""

    @property
    def check_name(self) -> str:
        return "RDS VPC Configuration"

    @property
    def service(self) -> str:
        return "rds"

    def get_severity(self) -> str:
        return Severity.HIGH

    def get_description(self) -> str:
        return (
            "Checks whether RDS instances are deployed within a VPC for "
            "proper network isolation and security."
        )

    def get_remediation(self) -> str:
        return (
            "1. Create a VPC with private subnets across multiple Availability Zones.\n"
            "2. Create a DB subnet group using the private subnets.\n"
            "3. Create a snapshot of the existing DB instance.\n"
            "4. Restore the snapshot into the VPC using the new DB subnet group.\n"
            "5. Update security groups to restrict inbound access to only application subnets.\n"
            "6. Update application connection endpoints.\n"
            "7. Test connectivity and delete the old non-VPC instance."
        )

    def get_finding_id(self) -> str:
        return "RDS-003"

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
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=f"RDS instance '{db_id}' is deployed in VPC '{vpc_id}'.",
                        resource_id=db_id,
                        region=self.region,
                    ))
                else:
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=f"RDS instance '{db_id}' is not deployed within a VPC (EC2-Classic).",
                        remediation=self.get_remediation(),
                        resource_id=db_id,
                        region=self.region,
                    ))

        if not instances_found:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No RDS instances found in this region.",
                resource_id="N/A",
                region=self.region,
            ))

        return findings


class RDSBackupCheck(BaseCheck):
    """Check for RDS instances with automated backups disabled."""

    @property
    def check_name(self) -> str:
        return "RDS Automated Backups"

    @property
    def service(self) -> str:
        return "rds"

    def get_severity(self) -> str:
        return Severity.MEDIUM

    def get_description(self) -> str:
        return (
            "Checks whether RDS instances have automated backups enabled "
            "with a retention period greater than 0 days."
        )

    def get_remediation(self) -> str:
        return (
            "1. Open the RDS console and select the DB instance.\n"
            "2. Click 'Modify'.\n"
            "3. Set 'Backup retention period' to at least 7 days (AWS maximum is 35 days).\n"
            "4. Configure a backup window during low-traffic periods.\n"
            "5. Enable 'Copy tags to snapshots' for easier management.\n"
            "6. Consider enabling cross-region backup replication for disaster recovery.\n"
            "7. Test restore procedures regularly to ensure backups are valid."
        )

    def get_finding_id(self) -> str:
        return "RDS-004"

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
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=f"RDS instance '{db_id}' has automated backups enabled (retention: {retention} days).",
                        resource_id=db_id,
                        region=self.region,
                    ))
                else:
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=f"RDS instance '{db_id}' has automated backups disabled (retention period: 0 days).",
                        remediation=self.get_remediation(),
                        resource_id=db_id,
                        region=self.region,
                    ))

        if not instances_found:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No RDS instances found in this region.",
                resource_id="N/A",
                region=self.region,
            ))

        return findings


class RDSEngineVersionCheck(BaseCheck):
    """Check for RDS instances running outdated engine versions."""

    @property
    def check_name(self) -> str:
        return "RDS Engine Version"

    @property
    def service(self) -> str:
        return "rds"

    def get_severity(self) -> str:
        return Severity.MEDIUM

    def get_description(self) -> str:
        return (
            "Checks whether RDS instances are running outdated or deprecated "
            "database engine versions that may contain known vulnerabilities."
        )

    def get_remediation(self) -> str:
        return (
            "1. Check the current engine version in the RDS console.\n"
            "2. Review AWS documentation for the latest supported major version.\n"
            "3. Test the upgrade in a non-production environment first.\n"
            "4. Create a manual snapshot before upgrading.\n"
            "5. Apply minor version upgrade: Modify instance > 'DB engine version' > select latest.\n"
            "6. For major version upgrades, plan a maintenance window and test application compatibility.\n"
            "7. Enable 'Auto minor version upgrade' to automatically apply future patches."
        )

    def get_finding_id(self) -> str:
        return "RDS-005"

    def _is_version_outdated(self, engine, version):
        """
        Check if the engine version is outdated by comparing the major version
        against known latest versions.
        """
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
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=(
                            f"RDS instance '{db_id}' is running an outdated engine version. "
                            f"Engine: {engine}, {version_info}. "
                            f"Auto minor version upgrade: {'Enabled' if auto_minor else 'Disabled'}."
                        ),
                        remediation=self.get_remediation(),
                        resource_id=db_id,
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
                            f"RDS instance '{db_id}' engine version is current. "
                            f"Engine: {engine}, {version_info}. "
                            f"Auto minor version upgrade: {'Enabled' if auto_minor else 'Disabled'}."
                        ),
                        resource_id=db_id,
                        region=self.region,
                    ))

        if not instances_found:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No RDS instances found in this region.",
                resource_id="N/A",
                region=self.region,
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

