"""
S3 Security Checks Module

Implements 5 security checks for Amazon S3:
1. Public Bucket Access (via policies and ACLs)
2. Bucket Encryption (at rest — distinguishes SSE-S3 vs SSE-KMS)
3. Public Access Block (bucket-level)
4. Encryption in Transit (HTTPS enforcement via aws:SecureTransport)
5. Account-Level Public Access Block
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
# S3-003: Public Access Block (bucket-level)
# ------------------------------------------------------------------

class S3PublicAccessBlockCheck(BaseCheck):
    """Check for S3 buckets without all Public Access Block settings enabled."""

    check_name = "S3 Bucket Public Access Block"
    service = "s3"
    severity = Severity.HIGH
    finding_id = "S3-003"
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
# S3-004: Encryption in Transit (HTTPS)
# ------------------------------------------------------------------

class S3TransitEncryptionCheck(BaseCheck):
    """Check for S3 buckets that do not enforce HTTPS (encryption in transit)."""

    check_name = "S3 Encryption in Transit (HTTPS)"
    service = "s3"
    severity = Severity.HIGH
    finding_id = "S3-004"
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
# S3-005: Account-Level Public Access Block
# ------------------------------------------------------------------

class S3AccountPublicAccessBlockCheck(BaseCheck):
    """Check for S3 Account-Level Public Access Block."""

    check_name = "S3 Account-Level Public Access Block"
    service = "s3"
    severity = Severity.HIGH
    finding_id = "S3-005"
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


# Registry of all S3 checks (all HIGH severity)
S3_CHECKS = [
    S3PublicAccessCheck,              # S3-001  HIGH
    S3EncryptionCheck,                # S3-002  HIGH
    S3PublicAccessBlockCheck,         # S3-003  HIGH
    S3TransitEncryptionCheck,         # S3-004  HIGH
    S3AccountPublicAccessBlockCheck,  # S3-005  HIGH
]
