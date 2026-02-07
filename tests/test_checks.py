"""
Unit Tests for AWS Security Misconfiguration Detection System

Tests use unittest.mock to mock Boto3 responses, so no real
AWS credentials or resources are needed.
"""

import json
import unittest
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from src.models.findings import Finding, ScanReport, Severity, Status
from src.checks.s3_checks import (
    S3PublicAccessCheck,
    S3EncryptionCheck,
    S3VersioningCheck,
    S3PublicAccessBlockCheck,
    S3LoggingCheck,
)
from src.checks.rds_checks import (
    RDSPublicAccessCheck,
    RDSEncryptionCheck,
    RDSVPCCheck,
    RDSBackupCheck,
    RDSEngineVersionCheck,
)
from src.checks.ec2_checks import (
    EC2OpenPortsCheck,
    EC2UnencryptedEBSCheck,
    EC2PublicIPCheck,
    EC2IAMRoleCheck,
    EC2KeyPairCheck,
)
from src.utils.formatter import format_json, format_text
from src.utils.error_handler import handle_aws_error, is_permission_error, should_retry


# =====================================================================
# Helper to create mock ClientError
# =====================================================================

def make_client_error(code, message="Test error"):
    """Create a mock botocore ClientError."""
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "TestOperation",
    )


# =====================================================================
# S3 Check Tests
# =====================================================================

class TestS3PublicAccessCheck(unittest.TestCase):
    """Tests for S3PublicAccessCheck."""

    def setUp(self):
        self.client = MagicMock()
        self.check = S3PublicAccessCheck(client=self.client, region="us-east-1")

    def test_no_buckets(self):
        self.client.list_buckets.return_value = {"Buckets": []}
        findings = self.check.execute()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, Status.PASSED)

    def test_bucket_not_public(self):
        self.client.list_buckets.return_value = {"Buckets": [{"Name": "my-bucket"}]}
        self.client.get_bucket_policy.side_effect = make_client_error("NoSuchBucketPolicy")
        self.client.get_bucket_acl.return_value = {
            "Grants": [
                {"Grantee": {"Type": "CanonicalUser"}, "Permission": "FULL_CONTROL"}
            ]
        }
        findings = self.check.execute()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, Status.PASSED)
        self.assertEqual(findings[0].resource_id, "my-bucket")

    def test_bucket_public_via_policy(self):
        self.client.list_buckets.return_value = {"Buckets": [{"Name": "public-bucket"}]}
        self.client.get_bucket_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [
                    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}
                ]
            })
        }
        self.client.get_bucket_acl.return_value = {"Grants": []}
        findings = self.check.execute()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, Status.FAILED)
        self.assertIn("bucket policy", findings[0].finding)

    def test_bucket_public_via_acl(self):
        self.client.list_buckets.return_value = {"Buckets": [{"Name": "acl-bucket"}]}
        self.client.get_bucket_policy.side_effect = make_client_error("NoSuchBucketPolicy")
        self.client.get_bucket_acl.return_value = {
            "Grants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                    },
                    "Permission": "READ",
                }
            ]
        }
        findings = self.check.execute()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, Status.FAILED)
        self.assertIn("ACL", findings[0].finding)


class TestS3EncryptionCheck(unittest.TestCase):
    """Tests for S3EncryptionCheck."""

    def setUp(self):
        self.client = MagicMock()
        self.check = S3EncryptionCheck(client=self.client, region="us-east-1")

    def test_bucket_encrypted(self):
        self.client.list_buckets.return_value = {"Buckets": [{"Name": "enc-bucket"}]}
        self.client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            }
        }
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.PASSED)

    def test_bucket_not_encrypted(self):
        self.client.list_buckets.return_value = {"Buckets": [{"Name": "noenc-bucket"}]}
        self.client.get_bucket_encryption.side_effect = make_client_error(
            "ServerSideEncryptionConfigurationNotFoundError"
        )
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)


class TestS3VersioningCheck(unittest.TestCase):
    """Tests for S3VersioningCheck."""

    def setUp(self):
        self.client = MagicMock()
        self.check = S3VersioningCheck(client=self.client, region="us-east-1")

    def test_versioning_enabled(self):
        self.client.list_buckets.return_value = {"Buckets": [{"Name": "v-bucket"}]}
        self.client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.PASSED)

    def test_versioning_disabled(self):
        self.client.list_buckets.return_value = {"Buckets": [{"Name": "v-bucket"}]}
        self.client.get_bucket_versioning.return_value = {}
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)


class TestS3PublicAccessBlockCheck(unittest.TestCase):
    """Tests for S3PublicAccessBlockCheck."""

    def setUp(self):
        self.client = MagicMock()
        self.check = S3PublicAccessBlockCheck(client=self.client, region="us-east-1")

    def test_all_blocked(self):
        self.client.list_buckets.return_value = {"Buckets": [{"Name": "blocked-bucket"}]}
        self.client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.PASSED)

    def test_partial_blocked(self):
        self.client.list_buckets.return_value = {"Buckets": [{"Name": "partial-bucket"}]}
        self.client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": False,
            }
        }
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)

    def test_no_config(self):
        self.client.list_buckets.return_value = {"Buckets": [{"Name": "no-pab-bucket"}]}
        self.client.get_public_access_block.side_effect = make_client_error(
            "NoSuchPublicAccessBlockConfiguration"
        )
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)


class TestS3LoggingCheck(unittest.TestCase):
    """Tests for S3LoggingCheck."""

    def setUp(self):
        self.client = MagicMock()
        self.check = S3LoggingCheck(client=self.client, region="us-east-1")

    def test_logging_enabled(self):
        self.client.list_buckets.return_value = {"Buckets": [{"Name": "log-bucket"}]}
        self.client.get_bucket_logging.return_value = {
            "LoggingEnabled": {"TargetBucket": "log-target"}
        }
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.PASSED)

    def test_logging_disabled(self):
        self.client.list_buckets.return_value = {"Buckets": [{"Name": "nolog-bucket"}]}
        self.client.get_bucket_logging.return_value = {}
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)


# =====================================================================
# RDS Check Tests
# =====================================================================

class TestRDSPublicAccessCheck(unittest.TestCase):
    """Tests for RDSPublicAccessCheck."""

    def setUp(self):
        self.client = MagicMock()
        self.check = RDSPublicAccessCheck(client=self.client, region="us-east-1")

    def _mock_paginator(self, instances):
        paginator = MagicMock()
        paginator.paginate.return_value = [{"DBInstances": instances}]
        self.client.get_paginator.return_value = paginator

    def test_no_instances(self):
        self._mock_paginator([])
        findings = self.check.execute()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, Status.PASSED)

    def test_publicly_accessible(self):
        self._mock_paginator([{
            "DBInstanceIdentifier": "test-db",
            "PubliclyAccessible": True,
            "Endpoint": {"Address": "test-db.abc.us-east-1.rds.amazonaws.com"},
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)

    def test_not_publicly_accessible(self):
        self._mock_paginator([{
            "DBInstanceIdentifier": "private-db",
            "PubliclyAccessible": False,
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.PASSED)


class TestRDSEncryptionCheck(unittest.TestCase):
    """Tests for RDSEncryptionCheck."""

    def setUp(self):
        self.client = MagicMock()
        self.check = RDSEncryptionCheck(client=self.client, region="us-east-1")

    def _mock_paginator(self, instances):
        paginator = MagicMock()
        paginator.paginate.return_value = [{"DBInstances": instances}]
        self.client.get_paginator.return_value = paginator

    def test_encrypted(self):
        self._mock_paginator([{
            "DBInstanceIdentifier": "enc-db",
            "StorageEncrypted": True,
            "KmsKeyId": "arn:aws:kms:us-east-1:123:key/abc",
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.PASSED)

    def test_not_encrypted(self):
        self._mock_paginator([{
            "DBInstanceIdentifier": "noenc-db",
            "StorageEncrypted": False,
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)


class TestRDSBackupCheck(unittest.TestCase):
    """Tests for RDSBackupCheck."""

    def setUp(self):
        self.client = MagicMock()
        self.check = RDSBackupCheck(client=self.client, region="us-east-1")

    def _mock_paginator(self, instances):
        paginator = MagicMock()
        paginator.paginate.return_value = [{"DBInstances": instances}]
        self.client.get_paginator.return_value = paginator

    def test_backups_enabled(self):
        self._mock_paginator([{
            "DBInstanceIdentifier": "backup-db",
            "BackupRetentionPeriod": 7,
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.PASSED)

    def test_backups_disabled(self):
        self._mock_paginator([{
            "DBInstanceIdentifier": "nobackup-db",
            "BackupRetentionPeriod": 0,
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)


class TestRDSEngineVersionCheck(unittest.TestCase):
    """Tests for RDSEngineVersionCheck."""

    def setUp(self):
        self.client = MagicMock()
        self.check = RDSEngineVersionCheck(client=self.client, region="us-east-1")

    def _mock_paginator(self, instances):
        paginator = MagicMock()
        paginator.paginate.return_value = [{"DBInstances": instances}]
        self.client.get_paginator.return_value = paginator

    def test_current_version(self):
        self._mock_paginator([{
            "DBInstanceIdentifier": "current-db",
            "Engine": "mysql",
            "EngineVersion": "8.0.35",
            "AutoMinorVersionUpgrade": True,
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.PASSED)

    def test_outdated_version(self):
        self._mock_paginator([{
            "DBInstanceIdentifier": "old-db",
            "Engine": "mysql",
            "EngineVersion": "5.7.44",
            "AutoMinorVersionUpgrade": False,
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)


# =====================================================================
# EC2 Check Tests
# =====================================================================

class TestEC2OpenPortsCheck(unittest.TestCase):
    """Tests for EC2OpenPortsCheck."""

    def setUp(self):
        self.client = MagicMock()
        self.check = EC2OpenPortsCheck(client=self.client, region="us-east-1")

    def _mock_paginator(self, security_groups):
        paginator = MagicMock()
        paginator.paginate.return_value = [{"SecurityGroups": security_groups}]
        self.client.get_paginator.return_value = paginator

    def test_no_open_ports(self):
        self._mock_paginator([{
            "GroupId": "sg-123",
            "GroupName": "safe-sg",
            "VpcId": "vpc-abc",
            "IpPermissions": [
                {
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    "Ipv6Ranges": [],
                }
            ],
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.PASSED)

    def test_ssh_open_to_world(self):
        self._mock_paginator([{
            "GroupId": "sg-456",
            "GroupName": "open-sg",
            "VpcId": "vpc-abc",
            "IpPermissions": [
                {
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }
            ],
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)
        self.assertIn("22 (SSH)", findings[0].finding)

    def test_multiple_sensitive_ports_open(self):
        self._mock_paginator([{
            "GroupId": "sg-789",
            "GroupName": "very-open-sg",
            "VpcId": "vpc-abc",
            "IpPermissions": [
                {
                    "FromPort": 0,
                    "ToPort": 65535,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }
            ],
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)
        self.assertIn("SSH", findings[0].finding)
        self.assertIn("RDP", findings[0].finding)


class TestEC2UnencryptedEBSCheck(unittest.TestCase):
    """Tests for EC2UnencryptedEBSCheck."""

    def setUp(self):
        self.client = MagicMock()
        self.check = EC2UnencryptedEBSCheck(client=self.client, region="us-east-1")

    def _mock_paginator(self, volumes):
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Volumes": volumes}]
        self.client.get_paginator.return_value = paginator

    def test_encrypted_volume(self):
        self._mock_paginator([{
            "VolumeId": "vol-enc",
            "Encrypted": True,
            "State": "in-use",
            "Attachments": [{"InstanceId": "i-123"}],
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.PASSED)

    def test_unencrypted_volume(self):
        self._mock_paginator([{
            "VolumeId": "vol-noenc",
            "Encrypted": False,
            "State": "in-use",
            "Attachments": [{"InstanceId": "i-456"}],
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)


class TestEC2PublicIPCheck(unittest.TestCase):
    """Tests for EC2PublicIPCheck."""

    def setUp(self):
        self.client = MagicMock()
        self.check = EC2PublicIPCheck(client=self.client, region="us-east-1")

    def _mock_paginator(self, instances):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "Reservations": [{"Instances": instances}]
        }]
        self.client.get_paginator.return_value = paginator

    def test_no_public_ip(self):
        self._mock_paginator([{
            "InstanceId": "i-private",
            "State": {"Name": "running"},
            "Tags": [{"Key": "Name", "Value": "private-instance"}],
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.PASSED)

    def test_has_public_ip(self):
        self._mock_paginator([{
            "InstanceId": "i-public",
            "State": {"Name": "running"},
            "PublicIpAddress": "54.1.2.3",
            "PublicDnsName": "ec2-54-1-2-3.compute-1.amazonaws.com",
            "Tags": [{"Key": "Name", "Value": "public-instance"}],
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)
        self.assertIn("54.1.2.3", findings[0].finding)


class TestEC2IAMRoleCheck(unittest.TestCase):
    """Tests for EC2IAMRoleCheck."""

    def setUp(self):
        self.client = MagicMock()
        self.check = EC2IAMRoleCheck(client=self.client, region="us-east-1")

    def _mock_paginator(self, instances):
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "Reservations": [{"Instances": instances}]
        }]
        self.client.get_paginator.return_value = paginator

    def test_has_iam_role(self):
        self._mock_paginator([{
            "InstanceId": "i-roled",
            "State": {"Name": "running"},
            "IamInstanceProfile": {"Arn": "arn:aws:iam::123:instance-profile/role"},
            "Tags": [],
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.PASSED)

    def test_no_iam_role(self):
        self._mock_paginator([{
            "InstanceId": "i-notrole",
            "State": {"Name": "running"},
            "Tags": [],
        }])
        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)


class TestEC2KeyPairCheck(unittest.TestCase):
    """Tests for EC2KeyPairCheck."""

    def setUp(self):
        self.client = MagicMock()
        self.check = EC2KeyPairCheck(client=self.client, region="us-east-1")

    def test_key_in_use(self):
        self.client.describe_key_pairs.return_value = {
            "KeyPairs": [{"KeyName": "my-key", "KeyPairId": "key-123"}]
        }
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "Reservations": [{"Instances": [{"KeyName": "my-key"}]}]
        }]
        self.client.get_paginator.return_value = paginator

        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.PASSED)

    def test_unused_key(self):
        self.client.describe_key_pairs.return_value = {
            "KeyPairs": [{"KeyName": "unused-key", "KeyPairId": "key-456"}]
        }
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Reservations": []}]
        self.client.get_paginator.return_value = paginator

        findings = self.check.execute()
        self.assertEqual(findings[0].status, Status.FAILED)


# =====================================================================
# Error Handler Tests
# =====================================================================

class TestErrorHandler(unittest.TestCase):
    """Tests for error_handler module."""

    def test_permission_error(self):
        error = make_client_error("AccessDenied", "Not allowed")
        result = handle_aws_error(error)
        self.assertEqual(result["error_type"], "PERMISSION")
        self.assertFalse(result["retryable"])
        self.assertTrue(is_permission_error(error))

    def test_throttling_error(self):
        error = make_client_error("Throttling", "Rate exceeded")
        result = handle_aws_error(error)
        self.assertEqual(result["error_type"], "TRANSIENT")
        self.assertTrue(result["retryable"])
        self.assertTrue(should_retry(error))

    def test_not_found_error(self):
        error = make_client_error("NoSuchBucket", "Bucket not found")
        result = handle_aws_error(error)
        self.assertEqual(result["error_type"], "NOT_FOUND")
        self.assertFalse(result["retryable"])

    def test_generic_client_error(self):
        error = make_client_error("SomeOtherError", "Something happened")
        result = handle_aws_error(error)
        self.assertEqual(result["error_type"], "CLIENT_ERROR")


# =====================================================================
# Findings Model Tests
# =====================================================================

class TestFindingsModel(unittest.TestCase):
    """Tests for Finding and ScanReport models."""

    def test_finding_to_dict(self):
        finding = Finding(
            check_id="TEST-001",
            check_name="Test Check",
            severity=Severity.HIGH,
            status=Status.FAILED,
            description="Test description",
            finding="Test finding",
            remediation="Fix it",
            resource_id="resource-123",
            region="us-east-1",
        )
        d = finding.to_dict()
        self.assertEqual(d["check_id"], "TEST-001")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["status"], "FAILED")

    def test_scan_report_summary(self):
        report = ScanReport(
            services=["s3"],
            region="us-east-1",
            findings=[
                Finding(check_id="1", check_name="A", severity="HIGH", status=Status.PASSED, description=""),
                Finding(check_id="2", check_name="B", severity="HIGH", status=Status.FAILED, description=""),
                Finding(check_id="3", check_name="C", severity="HIGH", status=Status.ERROR, description=""),
            ],
        )
        summary = report.get_summary()
        self.assertEqual(summary["total_checks"], 3)
        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["errors"], 1)


# =====================================================================
# Formatter Tests
# =====================================================================

class TestFormatter(unittest.TestCase):
    """Tests for output formatters."""

    def _make_report(self):
        return ScanReport(
            services=["s3"],
            region="us-east-1",
            account_id="123456789012",
            account_arn="arn:aws:iam::123456789012:user/test",
            findings=[
                Finding(
                    check_id="S3-001",
                    check_name="S3 Public Access",
                    severity=Severity.HIGH,
                    status=Status.FAILED,
                    description="Check public access",
                    finding="Bucket is public",
                    remediation="Block public access",
                    resource_id="my-bucket",
                    region="us-east-1",
                ),
                Finding(
                    check_id="S3-002",
                    check_name="S3 Encryption",
                    severity=Severity.HIGH,
                    status=Status.PASSED,
                    description="Check encryption",
                    resource_id="my-bucket",
                    region="us-east-1",
                ),
            ],
        )

    def test_format_json(self):
        report = self._make_report()
        output = format_json(report)
        parsed = json.loads(output)
        self.assertIn("summary", parsed)
        self.assertIn("findings", parsed)
        self.assertEqual(parsed["summary"]["total_checks"], 2)
        self.assertEqual(parsed["summary"]["failed"], 1)
        self.assertEqual(len(parsed["findings"]), 2)

    def test_format_text(self):
        report = self._make_report()
        output = format_text(report)
        self.assertIn("AWS Security Misconfiguration Detection Report", output)
        self.assertIn("S3 Public Access", output)
        self.assertIn("FAILED", output)
        self.assertIn("Block public access", output)


# =====================================================================
# Base Check Error Handling Test
# =====================================================================

class TestBaseCheckErrorHandling(unittest.TestCase):
    """Test that base check execute() handles errors gracefully."""

    def test_execute_catches_exception(self):
        client = MagicMock()
        client.list_buckets.side_effect = make_client_error("AccessDenied", "Not authorized")
        check = S3PublicAccessCheck(client=client, region="us-east-1")
        findings = check.execute()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, Status.ERROR)
        self.assertIn("Permission denied", findings[0].error_message)


if __name__ == "__main__":
    unittest.main()

