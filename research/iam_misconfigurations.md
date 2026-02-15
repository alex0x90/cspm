# AWS IAM — Security Misconfiguration Analysis

## Service Overview
- Identity and Access Management service controlling authentication and authorization across all AWS services
- Key features: users, groups, roles, policies, MFA, password policies, access keys, credential reports
- Assets: identities, credentials, permission boundaries, cross-account trust relationships
- Attack surface: overly permissive policies, stale credentials, missing MFA, weak password requirements, root account misuse

---

## HIGH Severity

### Root Account Access Keys (IAM-001)
- **Description**: The AWS root account has active access keys. The root account has unrestricted access to all resources and cannot be limited by IAM policies.
- **Risk**: If root access keys are compromised, an attacker gains full, unrestricted control over the entire AWS account — including billing, IAM, and all services. Root keys cannot be restricted by IAM policies or SCPs.
- **Attack Scenario**: An attacker obtains root access keys from a leaked `.env` file or a compromised developer workstation. They create a new IAM admin user for persistence, disable CloudTrail, delete all security configurations, and exfiltrate data from every service in the account.
- **Remediation**:
  1. Log in to the AWS Management Console as the root user.
  2. Go to "My Security Credentials" > "Access keys".
  3. Delete all active root access keys.
  4. Create an IAM user with AdministratorAccess for day-to-day admin tasks.
  5. Enable MFA on the root account using a hardware MFA device.
  6. Only use root for tasks that require it (e.g., changing account settings, closing the account).
  7. Use AWS Organizations SCPs to restrict root actions in member accounts.
- **Likelihood**: High

---

### MFA Not Enabled for IAM Users (IAM-002)
- **Description**: IAM users (including the root account) do not have Multi-Factor Authentication (MFA) enabled, relying solely on passwords or access keys for authentication.
- **Risk**: Without MFA, a compromised password or access key provides full access to the user's permissions. Credential stuffing, phishing, and keylogging attacks succeed without a second factor.
- **Attack Scenario**: An attacker uses credential stuffing with passwords leaked from a third-party breach. They find that an IAM user reused their password and has no MFA configured. The attacker logs into the AWS Console with full access to the user's permissions, creates new access keys, and exfiltrates data.
- **Remediation**:
  1. Open the IAM console > "Users" > select the user.
  2. Go to "Security credentials" tab > "Multi-factor authentication (MFA)".
  3. Click "Assign MFA device" and choose a type:
     - Virtual MFA (e.g., Google Authenticator, Authy) — recommended minimum.
     - Hardware TOTP token — recommended for privileged users.
     - FIDO2 security key — strongest option.
  4. For the root account, use a hardware MFA device stored in a secure location.
  5. Enforce MFA via an IAM policy that denies all actions unless `aws:MultiFactorAuthPresent` is true.
  6. Use AWS Config rule `iam-user-mfa-enabled` to monitor compliance.
- **Likelihood**: High

---

### Overly Permissive IAM Policies (IAM-003)
- **Description**: Customer-managed IAM policies that are attached to users, groups, or roles contain `"Action": "*"` with `"Resource": "*"` (full admin access), violating the principle of least privilege.
- **Risk**: Any identity with this policy has unrestricted access to every AWS service and resource. A compromised identity can perform any action, including deleting resources, exfiltrating data, and modifying IAM.
- **Attack Scenario**: An attacker compromises an IAM role attached to a Lambda function that has `*:*` permissions. They use the role to enumerate all S3 buckets, download sensitive data, create a new admin IAM user for persistence, and disable CloudTrail to cover their tracks.
- **Remediation**:
  1. Open the IAM console > "Policies" > filter by "Customer managed".
  2. Review each attached policy's JSON for `"Action": "*"` combined with `"Resource": "*"`.
  3. Replace wildcard permissions with specific actions required by the workload.
  4. Use IAM Access Analyzer to generate least-privilege policies based on actual usage.
  5. Implement permission boundaries to set maximum permissions.
  6. Use AWS Config rule `iam-policy-no-statements-with-admin-access` to detect violations.
  7. Review policies regularly (quarterly minimum).
- **Likelihood**: High

---

## MEDIUM Severity

### Weak or Missing Password Policy (IAM-004)
- **Description**: The AWS account does not have a custom password policy, or the password policy does not enforce minimum length (14+), complexity requirements, or regular rotation.
- **Risk**: Weak passwords are vulnerable to brute-force and credential stuffing attacks. Without expiration, compromised passwords remain valid indefinitely.
- **Attack Scenario**: An attacker launches a brute-force attack against the AWS Console login for IAM users. The default password policy allows short, simple passwords. They successfully guess a user's 8-character password and gain access to the account.
- **Remediation**:
  1. Open the IAM console > "Account settings" > "Password policy".
  2. Click "Edit" and configure:
     - Minimum password length: 14 characters.
     - Require at least one uppercase letter.
     - Require at least one lowercase letter.
     - Require at least one number.
     - Require at least one non-alphanumeric character.
     - Enable password expiration (90 days maximum).
     - Remember last 24 passwords to prevent reuse.
  3. Notify all IAM users to update their passwords to comply with the new policy.
  4. Use AWS Config rule `iam-password-policy` to monitor compliance.
- **Likelihood**: Medium

---

### Stale Access Keys (IAM-005)
- **Description**: IAM users have active access keys that have not been rotated in over 90 days, increasing the window of opportunity if keys are compromised.
- **Risk**: Long-lived access keys have a higher chance of being leaked or compromised. The longer a key exists, the more likely it has been copied to insecure locations (scripts, config files, shared drives).
- **Attack Scenario**: A developer's access key, created 18 months ago, is embedded in a CI/CD pipeline configuration file. The repository is accidentally made public. An attacker finds the key and uses it to access AWS resources. Because the key was never rotated, it is still active and fully functional.
- **Remediation**:
  1. Run: `aws iam list-access-keys --user-name USERNAME` to see key ages.
  2. Create a new access key: `aws iam create-access-key --user-name USERNAME`.
  3. Update all applications and services to use the new key.
  4. Deactivate the old key: `aws iam update-access-key --access-key-id OLD_KEY --status Inactive`.
  5. After confirming no impact, delete the old key: `aws iam delete-access-key --access-key-id OLD_KEY`.
  6. Implement a key rotation policy (maximum 90 days).
  7. Use AWS Config rule `access-keys-rotated` with `maxAccessKeyAge: 90` to enforce.
- **Likelihood**: High
