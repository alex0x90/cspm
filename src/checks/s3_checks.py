"""
S3 Security Checks Module

Implements 5 security checks for Amazon S3:
1. Public Bucket Access (via policies and ACLs)
2. Bucket Encryption
3. Bucket Versioning
4. Public Access Block
5. Bucket Logging
"""

import json
from typing import List

from botocore.exceptions import ClientError

from src.checks.base_check import BaseCheck
from src.models.findings import Finding, Severity, Status


class S3PublicAccessCheck(BaseCheck):
    """Check for S3 buckets with public access via policies or ACLs."""

    @property
    def check_name(self) -> str:
        return "S3 Public Bucket Access"

    @property
    def service(self) -> str:
        return "s3"

    def get_severity(self) -> str:
        return Severity.HIGH

    def get_description(self) -> str:
        return (
            "Checks whether S3 buckets have public read or write access "
            "granted through bucket policies or Access Control Lists (ACLs)."
        )

    def get_remediation(self) -> str:
        return (
            "1. Navigate to the S3 console and select the affected bucket.\n"
            "2. Go to the 'Permissions' tab.\n"
            "3. Review and remove any bucket policy statements with "
            "'Principal': '*' or 'Principal': {'AWS': '*'}.\n"
            "4. Under 'Access Control List', ensure no grants are given to "
            "'Everyone' or 'Authenticated Users'.\n"
            "5. Enable S3 Block Public Access at the bucket level.\n"
            "6. Use AWS Config rule 's3-bucket-public-read-prohibited' and "
            "'s3-bucket-public-write-prohibited' to monitor."
        )

    def get_finding_id(self) -> str:
        return "S3-001"

    def _is_policy_public(self, bucket_name):
        """Check if a bucket policy grants public access."""
        try:
            policy_response = self.client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response["Policy"])
            for statement in policy.get("Statement", []):
                principal = statement.get("Principal", "")
                effect = statement.get("Effect", "")
                if effect == "Allow" and (
                    principal == "*" or
                    (isinstance(principal, dict) and principal.get("AWS") == "*")
                ):
                    return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return False
            raise
        return False

    def _is_acl_public(self, bucket_name):
        """Check if a bucket ACL grants public access."""
        acl_response = self.client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl_response.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if uri in (
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            ):
                return True
        return False

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.client.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                policy_public = self._is_policy_public(bucket_name)
                acl_public = self._is_acl_public(bucket_name)

                if policy_public or acl_public:
                    sources = []
                    if policy_public:
                        sources.append("bucket policy")
                    if acl_public:
                        sources.append("ACL")
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' has public access via: {', '.join(sources)}.",
                        remediation=self.get_remediation(),
                        resource_id=bucket_name,
                        region=self.region,
                    ))
                else:
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' does not have public access.",
                        resource_id=bucket_name,
                        region=self.region,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                findings.append(Finding(
                    check_id=self.get_finding_id(),
                    check_name=self.check_name,
                    severity=self.get_severity(),
                    status=Status.ERROR,
                    description=self.get_description(),
                    resource_id=bucket_name,
                    region=self.region,
                    error_message=f"Error checking bucket '{bucket_name}': {error_code} - {e.response['Error']['Message']}",
                ))

        if not buckets:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No S3 buckets found in the account.",
                resource_id="N/A",
                region=self.region,
            ))

        return findings


class S3EncryptionCheck(BaseCheck):
    """Check for S3 buckets without default encryption enabled."""

    @property
    def check_name(self) -> str:
        return "S3 Bucket Encryption"

    @property
    def service(self) -> str:
        return "s3"

    def get_severity(self) -> str:
        return Severity.HIGH

    def get_description(self) -> str:
        return (
            "Checks whether S3 buckets have default server-side encryption "
            "enabled to protect data at rest."
        )

    def get_remediation(self) -> str:
        return (
            "1. Open the S3 console and select the bucket.\n"
            "2. Go to 'Properties' > 'Default encryption'.\n"
            "3. Enable default encryption with either SSE-S3 (AES-256) or SSE-KMS.\n"
            "4. For SSE-KMS, select or create a KMS key with appropriate key policies.\n"
            "5. Apply a bucket policy that denies s3:PutObject requests without encryption headers.\n"
            "6. Re-encrypt existing unencrypted objects using S3 Batch Operations."
        )

    def get_finding_id(self) -> str:
        return "S3-002"

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.client.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                encryption = self.client.get_bucket_encryption(Bucket=bucket_name)
                rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    sse_algorithm = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "Unknown")
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' has default encryption enabled ({sse_algorithm}).",
                        resource_id=bucket_name,
                        region=self.region,
                    ))
                else:
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' does not have default encryption enabled.",
                        remediation=self.get_remediation(),
                        resource_id=bucket_name,
                        region=self.region,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' does not have default encryption enabled.",
                        remediation=self.get_remediation(),
                        resource_id=bucket_name,
                        region=self.region,
                    ))
                else:
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.ERROR,
                        description=self.get_description(),
                        resource_id=bucket_name,
                        region=self.region,
                        error_message=f"Error checking bucket '{bucket_name}': {error_code}",
                    ))

        if not buckets:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No S3 buckets found in the account.",
                resource_id="N/A",
                region=self.region,
            ))

        return findings


class S3VersioningCheck(BaseCheck):
    """Check for S3 buckets without versioning enabled."""

    @property
    def check_name(self) -> str:
        return "S3 Bucket Versioning"

    @property
    def service(self) -> str:
        return "s3"

    def get_severity(self) -> str:
        return Severity.MEDIUM

    def get_description(self) -> str:
        return (
            "Checks whether S3 buckets have versioning enabled to protect "
            "against accidental deletion or overwrites."
        )

    def get_remediation(self) -> str:
        return (
            "1. Open the S3 console and select the bucket.\n"
            "2. Go to 'Properties' > 'Bucket Versioning'.\n"
            "3. Click 'Edit' and enable versioning.\n"
            "4. Configure lifecycle rules to manage version retention and storage costs.\n"
            "5. Enable MFA Delete for additional protection against unauthorized deletions.\n"
            "6. Note: Versioning cannot be disabled once enabled, only suspended."
        )

    def get_finding_id(self) -> str:
        return "S3-003"

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.client.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                versioning = self.client.get_bucket_versioning(Bucket=bucket_name)
                status = versioning.get("Status", "Disabled")

                if status == "Enabled":
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' has versioning enabled.",
                        resource_id=bucket_name,
                        region=self.region,
                    ))
                else:
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' does not have versioning enabled (Status: {status}).",
                        remediation=self.get_remediation(),
                        resource_id=bucket_name,
                        region=self.region,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                findings.append(Finding(
                    check_id=self.get_finding_id(),
                    check_name=self.check_name,
                    severity=self.get_severity(),
                    status=Status.ERROR,
                    description=self.get_description(),
                    resource_id=bucket_name,
                    region=self.region,
                    error_message=f"Error checking bucket '{bucket_name}': {error_code}",
                ))

        if not buckets:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No S3 buckets found in the account.",
                resource_id="N/A",
                region=self.region,
            ))

        return findings


class S3PublicAccessBlockCheck(BaseCheck):
    """Check for S3 buckets without Public Access Block enabled."""

    @property
    def check_name(self) -> str:
        return "S3 Public Access Block"

    @property
    def service(self) -> str:
        return "s3"

    def get_severity(self) -> str:
        return Severity.HIGH

    def get_description(self) -> str:
        return (
            "Checks whether S3 buckets have the Block Public Access feature "
            "enabled to prevent accidental public exposure."
        )

    def get_remediation(self) -> str:
        return (
            "1. Open the S3 console > select the bucket > 'Permissions' tab.\n"
            "2. Under 'Block public access', click 'Edit'.\n"
            "3. Enable all four settings:\n"
            "   - Block public access granted through new ACLs\n"
            "   - Block public access granted through any ACLs\n"
            "   - Block public and cross-account access through any public bucket policies\n"
            "   - Block public and cross-account access through new public bucket policies\n"
            "4. Also enable Block Public Access at the AWS account level via S3 settings.\n"
            "5. Use AWS Config rule 's3-account-level-public-access-blocks' to enforce."
        )

    def get_finding_id(self) -> str:
        return "S3-004"

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.client.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                pab = self.client.get_public_access_block(Bucket=bucket_name)
                config = pab.get("PublicAccessBlockConfiguration", {})

                all_blocked = all([
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ])

                if all_blocked:
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' has all Public Access Block settings enabled.",
                        resource_id=bucket_name,
                        region=self.region,
                    ))
                else:
                    disabled = []
                    if not config.get("BlockPublicAcls", False):
                        disabled.append("BlockPublicAcls")
                    if not config.get("IgnorePublicAcls", False):
                        disabled.append("IgnorePublicAcls")
                    if not config.get("BlockPublicPolicy", False):
                        disabled.append("BlockPublicPolicy")
                    if not config.get("RestrictPublicBuckets", False):
                        disabled.append("RestrictPublicBuckets")

                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' has disabled Public Access Block settings: {', '.join(disabled)}.",
                        remediation=self.get_remediation(),
                        resource_id=bucket_name,
                        region=self.region,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "NoSuchPublicAccessBlockConfiguration":
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' has no Public Access Block configuration.",
                        remediation=self.get_remediation(),
                        resource_id=bucket_name,
                        region=self.region,
                    ))
                else:
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.ERROR,
                        description=self.get_description(),
                        resource_id=bucket_name,
                        region=self.region,
                        error_message=f"Error checking bucket '{bucket_name}': {error_code}",
                    ))

        if not buckets:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No S3 buckets found in the account.",
                resource_id="N/A",
                region=self.region,
            ))

        return findings


class S3LoggingCheck(BaseCheck):
    """Check for S3 buckets without server access logging enabled."""

    @property
    def check_name(self) -> str:
        return "S3 Bucket Logging"

    @property
    def service(self) -> str:
        return "s3"

    def get_severity(self) -> str:
        return Severity.MEDIUM

    def get_description(self) -> str:
        return (
            "Checks whether S3 buckets have server access logging enabled "
            "to track requests for security auditing."
        )

    def get_remediation(self) -> str:
        return (
            "1. Create a dedicated logging bucket (e.g., 'my-bucket-logs') in the same region.\n"
            "2. Grant the S3 log delivery group write permission to the logging bucket.\n"
            "3. Open the source bucket > 'Properties' > 'Server access logging'.\n"
            "4. Enable logging and specify the target logging bucket and prefix.\n"
            "5. Alternatively, enable AWS CloudTrail data events for S3 for more detailed "
            "API-level logging.\n"
            "6. Set up lifecycle policies on the logging bucket to manage log retention."
        )

    def get_finding_id(self) -> str:
        return "S3-005"

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.client.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                logging_config = self.client.get_bucket_logging(Bucket=bucket_name)
                logging_enabled = logging_config.get("LoggingEnabled")

                if logging_enabled:
                    target_bucket = logging_enabled.get("TargetBucket", "Unknown")
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' has logging enabled (target: {target_bucket}).",
                        resource_id=bucket_name,
                        region=self.region,
                    ))
                else:
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' does not have server access logging enabled.",
                        remediation=self.get_remediation(),
                        resource_id=bucket_name,
                        region=self.region,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                findings.append(Finding(
                    check_id=self.get_finding_id(),
                    check_name=self.check_name,
                    severity=self.get_severity(),
                    status=Status.ERROR,
                    description=self.get_description(),
                    resource_id=bucket_name,
                    region=self.region,
                    error_message=f"Error checking bucket '{bucket_name}': {error_code}",
                ))

        if not buckets:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.PASSED,
                description=self.get_description(),
                finding="No S3 buckets found in the account.",
                resource_id="N/A",
                region=self.region,
            ))

        return findings


# Registry of all S3 checks for easy discovery
S3_CHECKS = [
    S3PublicAccessCheck,
    S3EncryptionCheck,
    S3VersioningCheck,
    S3PublicAccessBlockCheck,
    S3LoggingCheck,
]

