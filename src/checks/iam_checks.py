"""
IAM Security Checks Module

Implements 5 security checks for AWS IAM:
1. Root Account Access Keys
2. MFA Not Enabled for IAM Users
3. Overly Permissive IAM Policies
4. Weak or Missing Password Policy
5. Stale Access Keys (>90 days)
"""

import json
from datetime import datetime, timezone
from typing import List

from botocore.exceptions import ClientError

from src.checks.base_check import BaseCheck
from src.models.findings import Finding, Severity, Status


# Minimum password policy requirements
MIN_PASSWORD_LENGTH = 14
MAX_PASSWORD_AGE_DAYS = 90
MAX_ACCESS_KEY_AGE_DAYS = 90


# ------------------------------------------------------------------
# IAM-001: Root Account Access Keys
# ------------------------------------------------------------------

class IAMRootAccessKeysCheck(BaseCheck):
    """Check if the root account has active access keys."""

    check_name = "IAM Root Account Access Keys"
    service = "iam"
    severity = Severity.HIGH
    finding_id = "IAM-001"
    description = (
        "Checks whether the AWS root account has active access keys. "
        "Root access keys provide unrestricted access to the entire account."
    )
    impact = (
        "Compromised root access keys give an attacker full, unrestricted control "
        "over the entire AWS account — including billing, IAM, and all services. "
        "Root credentials cannot be limited by IAM policies or SCPs."
    )
    remediation = [
        "1. Log in to the AWS Console as the root user.",
        "2. Go to 'My Security Credentials' > 'Access keys'.",
        "3. Delete all active root access keys.",
        "4. Create an IAM user with AdministratorAccess for admin tasks.",
        "5. Enable MFA on the root account with a hardware MFA device.",
        "6. Only use root for tasks that specifically require it.",
    ]

    def check(self) -> List[Finding]:
        summary = self.client.get_account_summary()
        summary_map = summary.get("SummaryMap", {})
        root_keys = summary_map.get("AccountAccessKeysPresent", 0)

        if root_keys > 0:
            return [self._make_finding(
                Status.FAILED,
                f"Root account has {root_keys} active access key(s). "
                f"Root access keys should be deleted immediately.",
                resource_id="root",
            )]
        else:
            return [self._make_finding(
                Status.PASSED,
                "Root account does not have active access keys.",
                resource_id="root",
            )]


# ------------------------------------------------------------------
# IAM-002: MFA Not Enabled for IAM Users
# ------------------------------------------------------------------

class IAMMFACheck(BaseCheck):
    """Check if MFA is enabled for all IAM users and the root account."""

    check_name = "IAM MFA Enabled"
    service = "iam"
    severity = Severity.HIGH
    finding_id = "IAM-002"
    description = (
        "Checks whether MFA is enabled for all IAM users and the root account. "
        "MFA provides an additional layer of security beyond passwords."
    )
    impact = (
        "Without MFA, a compromised password or access key provides full access to "
        "the user's permissions. Credential stuffing, phishing, and keylogging attacks "
        "succeed without a second authentication factor."
    )
    remediation = [
        "1. Open the IAM console > 'Users' > select the user.",
        "2. Go to 'Security credentials' > 'Multi-factor authentication (MFA)'.",
        "3. Click 'Assign MFA device' and configure a virtual or hardware MFA.",
        "4. For the root account, use a hardware MFA device.",
        "5. Enforce MFA via IAM policy requiring aws:MultiFactorAuthPresent.",
        "6. Use AWS Config rule 'iam-user-mfa-enabled' to monitor.",
    ]

    def check(self) -> List[Finding]:
        findings = []

        # Check root account MFA
        summary = self.client.get_account_summary()
        summary_map = summary.get("SummaryMap", {})
        root_mfa = summary_map.get("AccountMFAEnabled", 0)

        if root_mfa == 0:
            findings.append(self._make_finding(
                Status.FAILED,
                "Root account does NOT have MFA enabled. This is critical.",
                resource_id="root",
            ))
        else:
            findings.append(self._make_finding(
                Status.PASSED,
                "Root account has MFA enabled.",
                resource_id="root",
            ))

        # Check each IAM user
        users = self.context.get("users")
        if users is None:
            paginator = self.client.get_paginator("list_users")
            users = []
            for page in paginator.paginate():
                users.extend(page.get("Users", []))

        for user in users:
            username = user["UserName"]
            mfa_devices = self.client.list_mfa_devices(UserName=username)
            has_mfa = len(mfa_devices.get("MFADevices", [])) > 0

            if has_mfa:
                findings.append(self._make_finding(
                    Status.PASSED,
                    f"IAM user '{username}' has MFA enabled.",
                    resource_id=username,
                ))
            else:
                findings.append(self._make_finding(
                    Status.FAILED,
                    f"IAM user '{username}' does NOT have MFA enabled.",
                    resource_id=username,
                ))

        return findings


# ------------------------------------------------------------------
# IAM-003: Overly Permissive Policies
# ------------------------------------------------------------------

class IAMOverlyPermissivePoliciesCheck(BaseCheck):
    """Check for customer-managed policies with full admin access (*:*)."""

    check_name = "IAM Overly Permissive Policies"
    service = "iam"
    severity = Severity.HIGH
    finding_id = "IAM-003"
    description = (
        "Checks whether any attached customer-managed IAM policies grant "
        "full admin access ('Action': '*' with 'Resource': '*')."
    )
    impact = (
        "Policies with full admin access violate least privilege. A compromised "
        "identity can perform any action on any resource, including deleting "
        "resources, exfiltrating data, and modifying IAM."
    )
    remediation = [
        "1. Open the IAM console > 'Policies' > filter 'Customer managed'.",
        "2. Review each policy's JSON for 'Action': '*' with 'Resource': '*'.",
        "3. Replace wildcard permissions with specific actions.",
        "4. Use IAM Access Analyzer to generate least-privilege policies.",
        "5. Implement permission boundaries to set maximum permissions.",
        "6. Use AWS Config rule 'iam-policy-no-statements-with-admin-access'.",
    ]

    @staticmethod
    def _is_admin_statement(statement):
        """Check if a policy statement grants full admin access."""
        if statement.get("Effect") != "Allow":
            return False

        action = statement.get("Action", "")
        resource = statement.get("Resource", "")

        # Normalize to lists
        actions = action if isinstance(action, list) else [action]
        resources = resource if isinstance(resource, list) else [resource]

        return "*" in actions and "*" in resources

    def check(self) -> List[Finding]:
        findings = []
        paginator = self.client.get_paginator("list_policies")

        policies_found = False
        for page in paginator.paginate(Scope="Local", OnlyAttached=True):
            for policy in page.get("Policies", []):
                policies_found = True
                policy_arn = policy["Arn"]
                policy_name = policy["PolicyName"]
                default_version = policy.get("DefaultVersionId", "v1")

                # Get the policy document
                version = self.client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=default_version,
                )
                document = version.get("PolicyVersion", {}).get("Document", {})

                # Document may be URL-encoded JSON string or dict
                if isinstance(document, str):
                    document = json.loads(document)

                statements = document.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                has_admin = any(self._is_admin_statement(s) for s in statements)

                if has_admin:
                    attachment_count = policy.get("AttachmentCount", 0)
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"Policy '{policy_name}' ({policy_arn}) grants full admin access "
                        f"('*:*') and is attached to {attachment_count} entity(ies).",
                        resource_id=policy_arn,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"Policy '{policy_name}' does not grant full admin access.",
                        resource_id=policy_arn,
                    ))

        if not policies_found:
            findings.append(self._make_finding(
                Status.PASSED,
                "No attached customer-managed policies found.",
                resource_id="N/A",
            ))

        return findings


# ------------------------------------------------------------------
# IAM-004: Password Policy
# ------------------------------------------------------------------

class IAMPasswordPolicyCheck(BaseCheck):
    """Check if the account password policy meets security requirements."""

    check_name = "IAM Password Policy"
    service = "iam"
    severity = Severity.MEDIUM
    finding_id = "IAM-004"
    description = (
        "Checks whether the account password policy enforces minimum length "
        f"({MIN_PASSWORD_LENGTH}+), complexity, and rotation requirements."
    )
    impact = (
        "A weak or missing password policy allows users to set short, simple passwords "
        "that are vulnerable to brute-force and credential stuffing attacks. Without "
        "expiration, compromised passwords remain valid indefinitely."
    )
    remediation = [
        "1. Open the IAM console > 'Account settings' > 'Password policy'.",
        f"2. Set minimum password length to {MIN_PASSWORD_LENGTH} characters.",
        "3. Require uppercase, lowercase, numbers, and symbols.",
        f"4. Enable password expiration ({MAX_PASSWORD_AGE_DAYS} days maximum).",
        "5. Remember last 24 passwords to prevent reuse.",
        "6. Use AWS Config rule 'iam-password-policy' to monitor.",
    ]

    def check(self) -> List[Finding]:
        try:
            policy = self.client.get_account_password_policy()
            pp = policy.get("PasswordPolicy", {})
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return [self._make_finding(
                    Status.FAILED,
                    "No custom password policy is configured. "
                    "The account is using the default AWS password policy.",
                    resource_id="Account",
                )]
            raise

        issues = []

        min_length = pp.get("MinimumPasswordLength", 0)
        if min_length < MIN_PASSWORD_LENGTH:
            issues.append(f"minimum length is {min_length} (should be {MIN_PASSWORD_LENGTH}+)")

        if not pp.get("RequireUppercaseCharacters", False):
            issues.append("uppercase letters not required")

        if not pp.get("RequireLowercaseCharacters", False):
            issues.append("lowercase letters not required")

        if not pp.get("RequireNumbers", False):
            issues.append("numbers not required")

        if not pp.get("RequireSymbols", False):
            issues.append("symbols not required")

        max_age = pp.get("MaxPasswordAge", 0)
        if max_age == 0 or max_age > MAX_PASSWORD_AGE_DAYS:
            issues.append(
                f"password expiration is {'disabled' if max_age == 0 else f'{max_age} days'} "
                f"(should be {MAX_PASSWORD_AGE_DAYS} days or less)"
            )

        if issues:
            return [self._make_finding(
                Status.FAILED,
                f"Password policy is weak: {'; '.join(issues)}.",
                resource_id="Account",
            )]
        else:
            return [self._make_finding(
                Status.PASSED,
                "Password policy meets all security requirements.",
                resource_id="Account",
            )]


# ------------------------------------------------------------------
# IAM-005: Stale Access Keys
# ------------------------------------------------------------------

class IAMStaleAccessKeysCheck(BaseCheck):
    """Check for active access keys older than 90 days."""

    check_name = "IAM Stale Access Keys"
    service = "iam"
    severity = Severity.MEDIUM
    finding_id = "IAM-005"
    description = (
        f"Checks whether any IAM users have active access keys that have not "
        f"been rotated in over {MAX_ACCESS_KEY_AGE_DAYS} days."
    )
    impact = (
        "Long-lived access keys have a higher chance of being leaked or compromised. "
        "The longer a key exists, the more likely it has been copied to insecure locations "
        "such as scripts, config files, and shared drives."
    )
    remediation = [
        "1. Run: aws iam list-access-keys --user-name USERNAME.",
        "2. Create a new access key for the user.",
        "3. Update all applications and services to use the new key.",
        "4. Deactivate the old key and verify no impact.",
        "5. Delete the old key after confirming.",
        f"6. Implement a key rotation policy (maximum {MAX_ACCESS_KEY_AGE_DAYS} days).",
        "7. Use AWS Config rule 'access-keys-rotated' to enforce.",
    ]

    def check(self) -> List[Finding]:
        findings = []

        users = self.context.get("users")
        if users is None:
            paginator = self.client.get_paginator("list_users")
            users = []
            for page in paginator.paginate():
                users.extend(page.get("Users", []))

        if not users:
            findings.append(self._make_finding(
                Status.PASSED,
                "No IAM users found.",
                resource_id="N/A",
            ))
            return findings

        now = datetime.now(timezone.utc)

        for user in users:
            username = user["UserName"]
            keys_response = self.client.list_access_keys(UserName=username)
            access_keys = keys_response.get("AccessKeyMetadata", [])

            for key in access_keys:
                key_id = key["AccessKeyId"]
                status = key["Status"]
                create_date = key["CreateDate"]

                if status != "Active":
                    continue

                age_days = (now - create_date).days

                if age_days > MAX_ACCESS_KEY_AGE_DAYS:
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"User '{username}' has access key '{key_id}' that is "
                        f"{age_days} days old (limit: {MAX_ACCESS_KEY_AGE_DAYS} days).",
                        resource_id=key_id,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"User '{username}' access key '{key_id}' is {age_days} days old.",
                        resource_id=key_id,
                    ))

            # If user has no active keys, that's fine — not flagged
            if not any(k["Status"] == "Active" for k in access_keys):
                findings.append(self._make_finding(
                    Status.PASSED,
                    f"User '{username}' has no active access keys.",
                    resource_id=username,
                ))

        return findings


# Registry of all IAM checks — ordered HIGH → MEDIUM
IAM_CHECKS = [
    IAMRootAccessKeysCheck,         # IAM-001  HIGH
    IAMMFACheck,                    # IAM-002  HIGH
    IAMOverlyPermissivePoliciesCheck,  # IAM-003  HIGH
    IAMPasswordPolicyCheck,         # IAM-004  MEDIUM
    IAMStaleAccessKeysCheck,        # IAM-005  MEDIUM
]
