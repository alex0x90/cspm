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


# ------------------------------------------------------------------
# S3-001: Public Bucket Access
# ------------------------------------------------------------------

class S3PublicAccessCheck(BaseCheck):
    """Check for S3 buckets with public access via policies or ACLs."""

    check_name = "S3 Public Bucket Access"
    service = "s3"
    severity = Severity.HIGH
    finding_id = "S3-001"
    description = (
        "Checks whether S3 buckets have public read or write access "
        "granted through bucket policies or Access Control Lists (ACLs)."
    )
    impact = (
        "Publicly accessible S3 buckets can lead to unauthorized data access, "
        "data exfiltration, data tampering, or hosting of malicious content. "
        "Attackers can read sensitive files (PII, credentials, backups) or write "
        "malicious objects. This is one of the most common causes of cloud data breaches."
    )
    remediation = [
        "1. Navigate to the S3 console and select the affected bucket.",
        "2. Go to the 'Permissions' tab.",
        "3. Review and remove any bucket policy statements with 'Principal': '*' or 'Principal': {'AWS': '*'}.",
        "4. Under 'Access Control List', ensure no grants are given to 'Everyone' or 'Authenticated Users'.",
        "5. Enable S3 Block Public Access at the bucket level.",
        "6. Use AWS Config rule 's3-bucket-public-read-prohibited' and 's3-bucket-public-write-prohibited' to monitor.",
    ]

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
        buckets = self.context.get("buckets", self.client.list_buckets().get("Buckets", []))

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
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"Bucket '{bucket_name}' has public access via: {', '.join(sources)}.",
                        resource_id=bucket_name,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"Bucket '{bucket_name}' does not have public access.",
                        resource_id=bucket_name,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                findings.append(self._make_finding(
                    Status.ERROR,
                    resource_id=bucket_name,
                    error_message=f"Error checking bucket '{bucket_name}': {error_code} - {e.response['Error']['Message']}",
                ))

        if not buckets:
            findings.append(self._make_finding(
                Status.PASSED, "No S3 buckets found in the account.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# S3-002: Bucket Encryption
# ------------------------------------------------------------------

class S3EncryptionCheck(BaseCheck):
    """Check for S3 buckets without default encryption enabled.
    Distinguishes between SSE-S3 (AWS managed) and SSE-KMS (Customer managed)."""

    check_name = "S3 Bucket Encryption"
    service = "s3"
    severity = Severity.HIGH
    finding_id = "S3-002"
    description = (
        "Checks whether S3 buckets have default server-side encryption "
        "enabled to protect data at rest. SSE-KMS provides stronger "
        "protection with customer-managed keys and audit trails via CloudTrail."
    )
    impact = (
        "Without server-side encryption (or with only SSE-S3), data at rest lacks "
        "customer-controlled key management and detailed audit trails. SSE-KMS provides "
        "envelope encryption with CloudTrail logging of every key usage, enabling detection "
        "of unauthorized access. Without it, compromised storage could expose plaintext data "
        "with no visibility into who accessed it."
    )
    remediation = [
        "1. Open the S3 console and select the bucket.",
        "2. Go to 'Properties' > 'Default encryption'.",
        "3. Enable default encryption with SSE-KMS for stronger protection.",
        "4. For SSE-KMS, select or create a Customer Managed Key with appropriate key policies.",
        "5. Enable Bucket Key to reduce KMS request costs.",
        "6. Apply a bucket policy that denies s3:PutObject requests without encryption headers.",
        "7. Re-encrypt existing unencrypted objects using S3 Batch Operations.",
    ]

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.context.get("buckets", self.client.list_buckets().get("Buckets", []))

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

                    if sse_algorithm in ("aws:kms", "aws:kms:dsse"):
                        detail = f"SSE-KMS (Key: {kms_key_id})" if kms_key_id else "SSE-KMS (AWS managed key)"
                        if bucket_key:
                            detail += " with Bucket Key enabled"
                        findings.append(self._make_finding(
                            Status.PASSED,
                            f"Bucket '{bucket_name}' has strong encryption enabled ({detail}).",
                            resource_id=bucket_name,
                        ))
                    elif sse_algorithm == "AES256":
                        findings.append(self._make_finding(
                            Status.PASSED,
                            f"Bucket '{bucket_name}' has default encryption enabled (SSE-S3). "
                            "Consider upgrading to SSE-KMS for customer-managed key control and audit trails.",
                            resource_id=bucket_name,
                        ))
                    else:
                        findings.append(self._make_finding(
                            Status.PASSED,
                            f"Bucket '{bucket_name}' has default encryption enabled ({sse_algorithm}).",
                            resource_id=bucket_name,
                        ))
                else:
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"Bucket '{bucket_name}' does not have default encryption enabled.",
                        resource_id=bucket_name,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"Bucket '{bucket_name}' does not have default encryption enabled.",
                        resource_id=bucket_name,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.ERROR,
                        resource_id=bucket_name,
                        error_message=f"Error checking bucket '{bucket_name}': {error_code}",
                    ))

        if not buckets:
            findings.append(self._make_finding(
                Status.PASSED, "No S3 buckets found in the account.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# S3-003: Bucket Versioning
# ------------------------------------------------------------------

class S3VersioningCheck(BaseCheck):
    """Check for S3 buckets without versioning enabled.
    Also reports MFA Delete status for versioned buckets."""

    check_name = "S3 Bucket Versioning"
    service = "s3"
    severity = Severity.MEDIUM
    finding_id = "S3-003"
    description = (
        "Checks whether S3 buckets have versioning enabled to protect "
        "against accidental deletion or overwrites. Also checks if MFA Delete "
        "is enabled to protect versioning from being disabled by compromised credentials."
    )
    impact = (
        "Without versioning, accidental or malicious deletion of objects is permanent "
        "and unrecoverable. Versioning protects against ransomware attacks (where attackers "
        "overwrite files with encrypted copies), application bugs that corrupt data, and "
        "human errors. It also enables point-in-time recovery of any object."
    )
    remediation = [
        "1. Open the S3 console and select the bucket.",
        "2. Go to 'Properties' > 'Bucket Versioning'.",
        "3. Click 'Edit' and enable versioning.",
        "4. Configure lifecycle rules to manage version retention and storage costs.",
        "5. Enable MFA Delete for additional protection against unauthorized deletions.",
        "6. Note: Versioning cannot be disabled once enabled, only suspended.",
    ]

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.context.get("buckets", self.client.list_buckets().get("Buckets", []))

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
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"Bucket '{bucket_name}' has versioning enabled (MFA Delete: {mfa_delete}).{mfa_note}",
                        resource_id=bucket_name,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"Bucket '{bucket_name}' does not have versioning enabled (Status: {status}).",
                        resource_id=bucket_name,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                findings.append(self._make_finding(
                    Status.ERROR,
                    resource_id=bucket_name,
                    error_message=f"Error checking bucket '{bucket_name}': {error_code}",
                ))

        if not buckets:
            findings.append(self._make_finding(
                Status.PASSED, "No S3 buckets found in the account.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# S3-004: Public Access Block (bucket-level)
# ------------------------------------------------------------------

class S3PublicAccessBlockCheck(BaseCheck):
    """Check for S3 buckets without all Public Access Block settings enabled."""

    check_name = "S3 Bucket Public Access Block"
    service = "s3"
    severity = Severity.HIGH
    finding_id = "S3-004"
    description = (
        "Checks whether S3 buckets have all four Public Access Block settings "
        "enabled (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, "
        "RestrictPublicBuckets) to prevent accidental public exposure."
    )
    impact = (
        "Without all four Block Public Access settings enabled, S3 buckets are vulnerable "
        "to accidental or intentional public exposure through misconfigured policies or ACLs. "
        "Even a single disabled setting can create a path for unauthorized public access. "
        "Block Public Access is the most effective preventive control against S3 data leaks."
    )
    remediation = [
        "1. Open the S3 console and select the bucket.",
        "2. Go to the 'Permissions' tab > 'Block public access'.",
        "3. Click 'Edit' and enable all four settings:",
        "   - Block public access granted through new ACLs",
        "   - Block public access granted through any ACLs",
        "   - Block public access through new public bucket or access point policies",
        "   - Block public and cross-account access through any public bucket or access point policies",
        "4. Click 'Save changes'.",
    ]

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.context.get("buckets", self.client.list_buckets().get("Buckets", []))

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
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"Bucket '{bucket_name}' has all Public Access Block settings enabled.",
                        resource_id=bucket_name,
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

                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"Bucket '{bucket_name}' has disabled Public Access Block settings: {', '.join(disabled)}.",
                        resource_id=bucket_name,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "NoSuchPublicAccessBlockConfiguration":
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"Bucket '{bucket_name}' has no Public Access Block configuration.",
                        resource_id=bucket_name,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.ERROR,
                        resource_id=bucket_name,
                        error_message=f"Error checking bucket '{bucket_name}': {error_code}",
                    ))

        if not buckets:
            findings.append(self._make_finding(
                Status.PASSED, "No S3 buckets found in the account.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# S3-005: Bucket Logging
# ------------------------------------------------------------------

class S3LoggingCheck(BaseCheck):
    """Check for S3 buckets without server access logging enabled."""

    check_name = "S3 Bucket Logging"
    service = "s3"
    severity = Severity.MEDIUM
    finding_id = "S3-005"
    description = (
        "Checks whether S3 buckets have server access logging enabled "
        "to track requests for security auditing."
    )
    impact = (
        "Without server access logging, there is no record of who accessed the bucket, "
        "what operations were performed, or when. This makes it impossible to detect "
        "unauthorized access, investigate security incidents, or meet compliance audit "
        "requirements (PCI DSS, HIPAA, SOC 2). Attackers can exfiltrate data undetected."
    )
    remediation = [
        "1. Create a dedicated logging bucket (e.g., 'my-bucket-logs') in the same region.",
        "2. Grant the S3 log delivery group write permission to the logging bucket.",
        "3. Open the source bucket > 'Properties' > 'Server access logging'.",
        "4. Enable logging and specify the target logging bucket and prefix.",
        "5. Alternatively, enable AWS CloudTrail data events for S3 for more detailed API-level logging.",
        "6. Set up lifecycle policies on the logging bucket to manage log retention.",
    ]

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.context.get("buckets", self.client.list_buckets().get("Buckets", []))

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                logging_config = self.client.get_bucket_logging(Bucket=bucket_name)
                logging_enabled = logging_config.get("LoggingEnabled")

                if logging_enabled:
                    target_bucket = logging_enabled.get("TargetBucket", "Unknown")
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"Bucket '{bucket_name}' has logging enabled (target: {target_bucket}).",
                        resource_id=bucket_name,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"Bucket '{bucket_name}' does not have server access logging enabled.",
                        resource_id=bucket_name,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                findings.append(self._make_finding(
                    Status.ERROR,
                    resource_id=bucket_name,
                    error_message=f"Error checking bucket '{bucket_name}': {error_code}",
                ))

        if not buckets:
            findings.append(self._make_finding(
                Status.PASSED, "No S3 buckets found in the account.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# S3-006: Encryption in Transit (HTTPS)
# ------------------------------------------------------------------

class S3TransitEncryptionCheck(BaseCheck):
    """Check for S3 buckets that do not enforce HTTPS (encryption in transit)."""

    check_name = "S3 Encryption in Transit (HTTPS)"
    service = "s3"
    severity = Severity.HIGH
    finding_id = "S3-006"
    description = (
        "Checks whether S3 buckets enforce HTTPS-only access by having a "
        "bucket policy that denies requests when aws:SecureTransport is false."
    )
    impact = (
        "Without enforced HTTPS, data transferred to/from S3 can be intercepted via "
        "man-in-the-middle (MITM) attacks on unencrypted HTTP connections. Attackers on "
        "the same network can capture sensitive data (credentials, PII, application data) "
        "in plaintext. This violates encryption-in-transit requirements of PCI DSS, HIPAA, "
        "and most security frameworks."
    )
    remediation = [
        "1. Open the S3 console and select the bucket.",
        "2. Go to the 'Permissions' tab > 'Bucket Policy'.",
        "3. Add a policy statement that denies all S3 actions when aws:SecureTransport is false:",
        '   {"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::BUCKET","arn:aws:s3:::BUCKET/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}',
        "4. This ensures all data in transit is encrypted via TLS/HTTPS.",
    ]

    def _policy_enforces_https(self, bucket_name):
        """Check if the bucket policy contains a Deny statement for non-HTTPS."""
        try:
            policy_response = self.client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response["Policy"])
            for statement in policy.get("Statement", []):
                effect = statement.get("Effect", "")
                condition = statement.get("Condition", {})
                bool_condition = condition.get("Bool", {})
                secure_transport = bool_condition.get("aws:SecureTransport", "")
                if effect == "Deny" and str(secure_transport).lower() == "false":
                    return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return False
            raise
        return False

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.context.get("buckets", self.client.list_buckets().get("Buckets", []))

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                if self._policy_enforces_https(bucket_name):
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"Bucket '{bucket_name}' enforces HTTPS via bucket policy (aws:SecureTransport).",
                        resource_id=bucket_name,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"Bucket '{bucket_name}' does not enforce HTTPS-only access. Data in transit may be unencrypted.",
                        resource_id=bucket_name,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                findings.append(self._make_finding(
                    Status.ERROR,
                    resource_id=bucket_name,
                    error_message=f"Error checking bucket '{bucket_name}': {error_code}",
                ))

        if not buckets:
            findings.append(self._make_finding(
                Status.PASSED, "No S3 buckets found in the account.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# S3-007: MFA Delete
# ------------------------------------------------------------------

class S3MFADeleteCheck(BaseCheck):
    """Check for S3 buckets with versioning enabled but MFA Delete disabled."""

    check_name = "S3 MFA Delete"
    service = "s3"
    severity = Severity.MEDIUM
    finding_id = "S3-007"
    description = (
        "Checks whether S3 buckets with versioning enabled also have MFA Delete "
        "enabled. MFA Delete requires multi-factor authentication to change the "
        "versioning state or permanently delete object versions, protecting against "
        "ransomware and compromised credentials."
    )
    impact = (
        "Without MFA Delete, an attacker who compromises IAM credentials can suspend "
        "versioning and permanently delete all object versions, making data unrecoverable. "
        "This is a key ransomware attack vector — attackers disable versioning, encrypt "
        "files with their own KMS key, and demand payment. MFA Delete requires physical "
        "MFA device access to change versioning state."
    )
    remediation = [
        "1. MFA Delete can only be enabled via the AWS CLI or API (not the console).",
        "2. Use the root account credentials with an MFA device configured.",
        "3. Run: aws s3api put-bucket-versioning --bucket BUCKET_NAME "
        "--versioning-configuration Status=Enabled,MFADelete=Enabled "
        "--mfa 'arn:aws:iam::ACCOUNT:mfa/DEVICE TOTP_CODE'",
        "4. Ensure your root account has an MFA device configured.",
        "5. Note: Only the bucket owner (root account) can enable MFA Delete.",
    ]

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.context.get("buckets", self.client.list_buckets().get("Buckets", []))

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                versioning = self.client.get_bucket_versioning(Bucket=bucket_name)
                versioning_status = versioning.get("Status", "Disabled")
                mfa_delete = versioning.get("MFADelete", "Disabled")

                if versioning_status != "Enabled":
                    continue  # Versioning disabled is already reported by S3-003
                elif mfa_delete == "Enabled":
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"Bucket '{bucket_name}' has MFA Delete enabled.",
                        resource_id=bucket_name,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"Bucket '{bucket_name}' has versioning enabled but MFA Delete "
                        "is not enabled. Versioning could be suspended by compromised credentials.",
                        resource_id=bucket_name,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                findings.append(self._make_finding(
                    Status.ERROR,
                    resource_id=bucket_name,
                    error_message=f"Error checking bucket '{bucket_name}': {error_code}",
                ))

        if not buckets:
            findings.append(self._make_finding(
                Status.PASSED, "No S3 buckets found in the account.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# S3-008: Object Lock
# ------------------------------------------------------------------

class S3ObjectLockCheck(BaseCheck):
    """Check for S3 buckets without Object Lock enabled."""

    check_name = "S3 Object Lock"
    service = "s3"
    severity = Severity.MEDIUM
    finding_id = "S3-008"
    description = (
        "Checks whether S3 buckets have Object Lock enabled. Object Lock "
        "provides immutability protection using a WORM model, preventing "
        "objects from being deleted or overwritten even by the root account. "
        "Supports Governance Mode (time-limited) and Compliance Mode (indefinite)."
    )
    impact = (
        "Without Object Lock, even a compromised root account or bucket owner can delete "
        "or overwrite objects. Object Lock provides immutability (WORM) that protects "
        "against ransomware, insider threats, and accidental deletion. In Compliance Mode, "
        "no one — including AWS — can delete protected objects before the retention period expires. "
        "Required for regulatory compliance in financial services and healthcare."
    )
    remediation = [
        "1. Object Lock can only be enabled at bucket creation time.",
        "2. Create a new bucket with Object Lock enabled.",
        "3. Configure a default retention period and mode:",
        "   - Governance Mode: Protects for a set retention period.",
        "   - Compliance Mode: Protects indefinitely (cannot be overridden).",
        "4. Migrate existing objects to the new bucket using S3 Batch Operations.",
        "5. Object Lock requires versioning to be enabled (automatically enabled).",
    ]

    def check(self) -> List[Finding]:
        findings = []
        buckets = self.context.get("buckets", self.client.list_buckets().get("Buckets", []))

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

                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"Bucket '{bucket_name}' has Object Lock enabled (Mode: {mode}, Retention: {period}).",
                        resource_id=bucket_name,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"Bucket '{bucket_name}' does not have Object Lock enabled.",
                        resource_id=bucket_name,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code in ("ObjectLockConfigurationNotFoundError", "ObjectLockConfigurationNotFound"):
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"Bucket '{bucket_name}' does not have Object Lock enabled.",
                        resource_id=bucket_name,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.ERROR,
                        resource_id=bucket_name,
                        error_message=f"Error checking bucket '{bucket_name}': {error_code}",
                    ))

        if not buckets:
            findings.append(self._make_finding(
                Status.PASSED, "No S3 buckets found in the account.", resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# S3-009: Account-Level Public Access Block
# ------------------------------------------------------------------

class S3AccountPublicAccessBlockCheck(BaseCheck):
    """Check for S3 Account-Level Public Access Block."""

    check_name = "S3 Account-Level Public Access Block"
    service = "s3"
    severity = Severity.HIGH
    finding_id = "S3-009"
    description = (
        "Checks whether S3 Account-Level Public Access Block is enabled. "
        "This provides a safety net across all buckets in the account, preventing "
        "accidental public exposure even if individual bucket settings are misconfigured."
    )
    impact = (
        "Without account-level Block Public Access, any new or existing bucket in the account "
        "can be made public through a misconfigured policy or ACL. This is a defense-in-depth "
        "control — even if individual bucket settings are correct today, a future misconfiguration "
        "could expose data. Account-level blocking overrides all bucket-level settings, preventing "
        "accidental public exposure across the entire account."
    )
    remediation = [
        "1. Open the S3 console > 'Block Public Access settings for this account'.",
        "2. Click 'Edit' and enable all four settings:",
        "   - Block public access granted through new ACLs",
        "   - Block public access granted through any ACLs",
        "   - Block public access through new public bucket or access point policies",
        "   - Block public and cross-account access through any public bucket or access point policies",
        "3. Or use CLI: aws s3control put-public-access-block --account-id ACCOUNT_ID "
        "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
        "BlockPublicPolicy=true,RestrictPublicBuckets=true",
    ]

    def check(self) -> List[Finding]:
        findings = []
        try:
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
                findings.append(self._make_finding(
                    Status.PASSED,
                    f"Account '{account_id}' has all Account-Level Public Access Block settings enabled.",
                    resource_id=account_id,
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

                findings.append(self._make_finding(
                    Status.FAILED,
                    f"Account '{account_id}' has disabled Account-Level Public Access Block settings: {', '.join(disabled)}.",
                    resource_id=account_id,
                ))
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoSuchPublicAccessBlockConfiguration":
                findings.append(self._make_finding(
                    Status.FAILED,
                    "Account-Level Public Access Block is not configured.",
                    resource_id="Account",
                ))
            else:
                findings.append(self._make_finding(
                    Status.ERROR,
                    resource_id="Account",
                    error_message=f"Error checking account-level public access block: {error_code}",
                ))
        except Exception as e:
            findings.append(self._make_finding(
                Status.ERROR,
                resource_id="Account",
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
