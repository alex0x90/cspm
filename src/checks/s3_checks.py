"""
S3 Security Checks Module

Implements 9 security checks for Amazon S3:
1. Public Bucket Access (via policies and ACLs)
2. Bucket Encryption (at rest — distinguishes SSE-S3 vs SSE-KMS)
3. Bucket Versioning (includes MFA Delete status)
4. Public Access Block (bucket-level)
5. Bucket Logging
6. Encryption in Transit (HTTPS enforcement via aws:SecureTransport)
7. MFA Delete
8. Object Lock
9. Account-Level Public Access Block
"""

import json
from typing import List

from botocore.exceptions import ClientError

from src.checks.base_check import BaseCheck
from src.models.findings import Finding, Severity, Status
from src.utils.aws_client import get_client


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
    """Check for S3 buckets without default encryption enabled.
    Distinguishes between SSE-S3 (AWS managed) and SSE-KMS (Customer managed)
    to highlight stronger encryption options."""

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
            "enabled to protect data at rest. SSE-KMS provides stronger "
            "protection with customer-managed keys and audit trails via CloudTrail."
        )

    def get_remediation(self) -> str:
        return (
            "1. Open the S3 console and select the bucket.\n"
            "2. Go to 'Properties' > 'Default encryption'.\n"
            "3. Enable default encryption with SSE-KMS for stronger protection.\n"
            "4. For SSE-KMS, select or create a Customer Managed Key with appropriate key policies.\n"
            "5. Enable Bucket Key to reduce KMS request costs.\n"
            "6. Apply a bucket policy that denies s3:PutObject requests without encryption headers.\n"
            "7. Re-encrypt existing unencrypted objects using S3 Batch Operations."
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
                    default_enc = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                    sse_algorithm = default_enc.get("SSEAlgorithm", "Unknown")
                    kms_key_id = default_enc.get("KMSMasterKeyID", "")
                    bucket_key = rules[0].get("BucketKeyEnabled", False)

                    if sse_algorithm == "aws:kms" or sse_algorithm == "aws:kms:dsse":
                        detail = f"SSE-KMS (Key: {kms_key_id})" if kms_key_id else "SSE-KMS (AWS managed key)"
                        if bucket_key:
                            detail += " with Bucket Key enabled"
                        findings.append(Finding(
                            check_id=self.get_finding_id(),
                            check_name=self.check_name,
                            severity=self.get_severity(),
                            status=Status.PASSED,
                            description=self.get_description(),
                            finding=f"Bucket '{bucket_name}' has strong encryption enabled ({detail}).",
                            resource_id=bucket_name,
                            region=self.region,
                        ))
                    elif sse_algorithm == "AES256":
                        findings.append(Finding(
                            check_id=self.get_finding_id(),
                            check_name=self.check_name,
                            severity=self.get_severity(),
                            status=Status.PASSED,
                            description=self.get_description(),
                            finding=(
                                f"Bucket '{bucket_name}' has default encryption enabled (SSE-S3). "
                                "Consider upgrading to SSE-KMS for customer-managed key control and audit trails."
                            ),
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
    """Check for S3 buckets without versioning enabled.
    Also reports MFA Delete status for versioned buckets."""

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
            "against accidental deletion or overwrites. Also checks if MFA Delete "
            "is enabled to protect versioning from being disabled by compromised credentials."
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
                mfa_delete = versioning.get("MFADelete", "Disabled")

                if status == "Enabled":
                    mfa_note = ""
                    if mfa_delete != "Enabled":
                        mfa_note = " Warning: MFA Delete is not enabled — versioning could be suspended by compromised credentials."
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' has versioning enabled (MFA Delete: {mfa_delete}).{mfa_note}",
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


class S3TransitEncryptionCheck(BaseCheck):
    """Check for S3 buckets that do not enforce HTTPS (encryption in transit).
    Per AWS best practices, buckets should have a policy denying requests
    where aws:SecureTransport is false."""

    @property
    def check_name(self) -> str:
        return "S3 Encryption in Transit (HTTPS)"

    @property
    def service(self) -> str:
        return "s3"

    def get_severity(self) -> str:
        return Severity.HIGH

    def get_description(self) -> str:
        return (
            "Checks whether S3 buckets enforce HTTPS-only access by having a "
            "bucket policy that denies requests when aws:SecureTransport is false."
        )

    def get_remediation(self) -> str:
        return (
            "1. Open the S3 console and select the bucket.\n"
            "2. Go to the 'Permissions' tab > 'Bucket Policy'.\n"
            "3. Add a policy statement that denies all S3 actions when "
            "aws:SecureTransport is false:\n"
            '   {"Effect":"Deny","Principal":"*","Action":"s3:*",'
            '"Resource":["arn:aws:s3:::BUCKET","arn:aws:s3:::BUCKET/*"],'
            '"Condition":{"Bool":{"aws:SecureTransport":"false"}}}\n'
            "4. This ensures all data in transit is encrypted via TLS/HTTPS."
        )

    def get_finding_id(self) -> str:
        return "S3-006"

    def _policy_enforces_https(self, bucket_name):
        """Check if the bucket policy contains a Deny statement for non-HTTPS.
        Handles both string 'false' and boolean false for aws:SecureTransport."""
        try:
            policy_response = self.client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response["Policy"])
            for statement in policy.get("Statement", []):
                effect = statement.get("Effect", "")
                condition = statement.get("Condition", {})
                bool_condition = condition.get("Bool", {})
                secure_transport = bool_condition.get("aws:SecureTransport", "")
                # AWS policies use string "false", but handle boolean false too
                if effect == "Deny" and str(secure_transport).lower() == "false":
                    return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return False
            raise
        return False

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.client.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                if self._policy_enforces_https(bucket_name):
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' enforces HTTPS via bucket policy (aws:SecureTransport).",
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
                        finding=f"Bucket '{bucket_name}' does not enforce HTTPS-only access. Data in transit may be unencrypted.",
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


class S3MFADeleteCheck(BaseCheck):
    """Check for S3 buckets that have versioning enabled but MFA Delete disabled.
    MFA Delete protects versioning from being suspended by compromised credentials."""

    @property
    def check_name(self) -> str:
        return "S3 MFA Delete"

    @property
    def service(self) -> str:
        return "s3"

    def get_severity(self) -> str:
        return Severity.MEDIUM

    def get_description(self) -> str:
        return (
            "Checks whether S3 buckets with versioning enabled also have MFA Delete "
            "enabled. MFA Delete requires multi-factor authentication to change the "
            "versioning state or permanently delete object versions, protecting against "
            "ransomware and compromised credentials."
        )

    def get_remediation(self) -> str:
        return (
            "1. MFA Delete can only be enabled via the AWS CLI or API (not the console).\n"
            "2. Use the root account credentials with an MFA device configured.\n"
            "3. Run: aws s3api put-bucket-versioning --bucket BUCKET_NAME "
            "--versioning-configuration Status=Enabled,MFADelete=Enabled "
            "--mfa 'arn:aws:iam::ACCOUNT:mfa/DEVICE TOTP_CODE'\n"
            "4. Ensure your root account has an MFA device configured.\n"
            "5. Note: Only the bucket owner (root account) can enable MFA Delete."
        )

    def get_finding_id(self) -> str:
        return "S3-007"

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.client.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                versioning = self.client.get_bucket_versioning(Bucket=bucket_name)
                versioning_status = versioning.get("Status", "Disabled")
                mfa_delete = versioning.get("MFADelete", "Disabled")

                if versioning_status != "Enabled":
                    # Skip — versioning disabled is already reported by S3-003
                    continue
                elif mfa_delete == "Enabled":
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' has MFA Delete enabled.",
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
                        finding=(
                            f"Bucket '{bucket_name}' has versioning enabled but MFA Delete "
                            "is not enabled. Versioning could be suspended by compromised credentials."
                        ),
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


class S3ObjectLockCheck(BaseCheck):
    """Check for S3 buckets without Object Lock enabled.
    Object Lock provides WORM (Write Once Read Many) immutability protection
    against deletion even by root account."""

    @property
    def check_name(self) -> str:
        return "S3 Object Lock"

    @property
    def service(self) -> str:
        return "s3"

    def get_severity(self) -> str:
        return Severity.MEDIUM

    def get_description(self) -> str:
        return (
            "Checks whether S3 buckets have Object Lock enabled. Object Lock "
            "provides immutability protection using a WORM model, preventing "
            "objects from being deleted or overwritten even by the root account. "
            "Supports Governance Mode (time-limited) and Compliance Mode (indefinite)."
        )

    def get_remediation(self) -> str:
        return (
            "1. Object Lock can only be enabled at bucket creation time.\n"
            "2. Create a new bucket with Object Lock enabled.\n"
            "3. Configure a default retention period and mode:\n"
            "   - Governance Mode: Protects for a set retention period.\n"
            "   - Compliance Mode: Protects indefinitely (cannot be overridden).\n"
            "4. Migrate existing objects to the new bucket using S3 Batch Operations.\n"
            "5. Object Lock requires versioning to be enabled (automatically enabled)."
        )

    def get_finding_id(self) -> str:
        return "S3-008"

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.client.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                lock_config = self.client.get_object_lock_configuration(Bucket=bucket_name)
                lock = lock_config.get("ObjectLockConfiguration", {})
                lock_enabled = lock.get("ObjectLockEnabled", "")

                if lock_enabled == "Enabled":
                    rule = lock.get("Rule", {})
                    retention = rule.get("DefaultRetention", {})
                    mode = retention.get("Mode", "Not configured")
                    days = retention.get("Days", "")
                    years = retention.get("Years", "")
                    period = f"{days} days" if days else f"{years} years" if years else "no default period"

                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.PASSED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' has Object Lock enabled (Mode: {mode}, Retention: {period}).",
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
                        finding=f"Bucket '{bucket_name}' does not have Object Lock enabled.",
                        remediation=self.get_remediation(),
                        resource_id=bucket_name,
                        region=self.region,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                # Handle both error code variants for Object Lock not configured
                if error_code in (
                    "ObjectLockConfigurationNotFoundError",
                    "ObjectLockConfigurationNotFound",
                ):
                    findings.append(Finding(
                        check_id=self.get_finding_id(),
                        check_name=self.check_name,
                        severity=self.get_severity(),
                        status=Status.FAILED,
                        description=self.get_description(),
                        finding=f"Bucket '{bucket_name}' does not have Object Lock enabled.",
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


class S3AccountPublicAccessBlockCheck(BaseCheck):
    """Check for S3 Account-Level Public Access Block.
    This is separate from bucket-level and acts as a safety net
    across all buckets in the account."""

    @property
    def check_name(self) -> str:
        return "S3 Account-Level Public Access Block"

    @property
    def service(self) -> str:
        return "s3"

    def get_severity(self) -> str:
        return Severity.HIGH

    def get_description(self) -> str:
        return (
            "Checks whether S3 Account-Level Public Access Block is enabled. "
            "This provides a safety net across all buckets in the account, preventing "
            "accidental public exposure even if individual bucket settings are misconfigured."
        )

    def get_remediation(self) -> str:
        return (
            "1. Open the S3 console > 'Block Public Access settings for this account'.\n"
            "2. Click 'Edit' and enable all four settings:\n"
            "   - Block public access granted through new ACLs\n"
            "   - Block public access granted through any ACLs\n"
            "   - Block public access through new public bucket or access point policies\n"
            "   - Block public and cross-account access through any public bucket or access point policies\n"
            "3. Or use CLI: aws s3control put-public-access-block --account-id ACCOUNT_ID "
            "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
        )

    def get_finding_id(self) -> str:
        return "S3-009"

    def check(self) -> List[Finding]:
        findings = []
        try:
            # Account-level public access block requires s3control + account ID from STS
            sts = get_client("sts", region=self.region)
            account_id = sts.get_caller_identity()["Account"]

            s3control = get_client("s3control", region=self.region)
            pab = s3control.get_public_access_block(AccountId=account_id)
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
                    finding=f"Account '{account_id}' has all Account-Level Public Access Block settings enabled.",
                    resource_id=account_id,
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
                    finding=f"Account '{account_id}' has disabled Account-Level Public Access Block settings: {', '.join(disabled)}.",
                    remediation=self.get_remediation(),
                    resource_id=account_id,
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
                    finding="Account-Level Public Access Block is not configured.",
                    remediation=self.get_remediation(),
                    resource_id="Account",
                    region=self.region,
                ))
            else:
                findings.append(Finding(
                    check_id=self.get_finding_id(),
                    check_name=self.check_name,
                    severity=self.get_severity(),
                    status=Status.ERROR,
                    description=self.get_description(),
                    resource_id="Account",
                    region=self.region,
                    error_message=f"Error checking account-level public access block: {error_code}",
                ))
        except Exception as e:
            findings.append(Finding(
                check_id=self.get_finding_id(),
                check_name=self.check_name,
                severity=self.get_severity(),
                status=Status.ERROR,
                description=self.get_description(),
                resource_id="Account",
                region=self.region,
                error_message=f"Error checking account-level public access block: {str(e)}",
            ))

        return findings


# Registry of all S3 checks for easy discovery
S3_CHECKS = [
    S3PublicAccessCheck,
    S3EncryptionCheck,
    S3VersioningCheck,
    S3PublicAccessBlockCheck,
    S3LoggingCheck,
    S3TransitEncryptionCheck,
    S3MFADeleteCheck,
    S3ObjectLockCheck,
    S3AccountPublicAccessBlockCheck,
]

