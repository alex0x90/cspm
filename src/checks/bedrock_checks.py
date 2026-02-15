"""
Bedrock Security Checks Module

Implements 5 security checks for Amazon Bedrock:
1. Model Invocation Logging Disabled
2. No Guardrails Configured
3. Overly Permissive Model Access
4. Custom Model Encryption Without Customer-Managed Keys
5. No VPC Endpoint for Bedrock API
"""

from typing import List

from botocore.exceptions import ClientError

from src.checks.base_check import BaseCheck
from src.models.findings import Finding, Severity, Status
from src.utils.aws_client import get_client


# ------------------------------------------------------------------
# BDR-001: Model Invocation Logging Disabled
# ------------------------------------------------------------------

class BedrockInvocationLoggingCheck(BaseCheck):
    """Check if Bedrock model invocation logging is enabled."""

    check_name = "Bedrock Model Invocation Logging"
    service = "bedrock"
    severity = Severity.HIGH
    finding_id = "BDR-001"
    description = (
        "Checks whether Amazon Bedrock model invocation logging is enabled. "
        "Logging captures all requests, responses, and metadata for audit and security."
    )
    impact = (
        "Without invocation logging, there is no audit trail of model requests and "
        "responses. Prompt injection attacks, data exfiltration via model outputs, and "
        "abuse of model access cannot be detected or investigated."
    )
    remediation = [
        "1. Open the Bedrock console > 'Settings' > 'Model invocation logging'.",
        "2. Enable logging and configure CloudWatch Logs and/or S3 as destinations.",
        "3. Enable logging for all data types (text, image, embedding, video).",
        "4. Attach a bucket policy granting bedrock.amazonaws.com s3:PutObject permission.",
        "5. Configure CloudWatch alarms on invocation patterns for anomaly detection.",
        "6. Use PutModelInvocationLoggingConfiguration API for infrastructure-as-code.",
    ]

    def check(self) -> List[Finding]:
        response = self.client.get_model_invocation_logging_configuration()
        config = response.get("loggingConfig")

        if not config:
            return [self._make_finding(
                Status.FAILED,
                "Model invocation logging is not configured. "
                "No audit trail of model requests and responses.",
                resource_id="Account",
            )]

        # Check if at least one destination is configured
        has_cloudwatch = bool(config.get("cloudWatchConfig", {}).get("logGroupName"))
        has_s3 = bool(config.get("s3Config", {}).get("bucketName"))

        if not has_cloudwatch and not has_s3:
            return [self._make_finding(
                Status.FAILED,
                "Model invocation logging is configured but no destination "
                "(CloudWatch or S3) is set. Logs are not being delivered.",
                resource_id="Account",
            )]

        # Check data delivery flags
        disabled_types = []
        if not config.get("textDataDeliveryEnabled", False):
            disabled_types.append("text")
        if not config.get("imageDataDeliveryEnabled", False):
            disabled_types.append("image")

        destinations = []
        if has_cloudwatch:
            destinations.append(f"CloudWatch ({config['cloudWatchConfig']['logGroupName']})")
        if has_s3:
            destinations.append(f"S3 ({config['s3Config']['bucketName']})")

        detail = f"Destinations: {', '.join(destinations)}."
        if disabled_types:
            detail += f" Warning: {', '.join(disabled_types)} data delivery is disabled."

        return [self._make_finding(
            Status.PASSED,
            f"Model invocation logging is enabled. {detail}",
            resource_id="Account",
        )]


# ------------------------------------------------------------------
# BDR-002: No Guardrails Configured
# ------------------------------------------------------------------

class BedrockGuardrailsCheck(BaseCheck):
    """Check if Bedrock guardrails are configured."""

    check_name = "Bedrock Guardrails"
    service = "bedrock"
    severity = Severity.HIGH
    finding_id = "BDR-002"
    description = (
        "Checks whether Amazon Bedrock guardrails are configured to inspect "
        "prompts and responses for harmful content, PII, and policy violations."
    )
    impact = (
        "Without guardrails, models can be manipulated via prompt injection to "
        "generate harmful or policy-violating content. Sensitive data (PII, credentials) "
        "can leak through model responses with no automated detection or blocking."
    )
    remediation = [
        "1. Open the Bedrock console > 'Guardrails' > 'Create guardrail'.",
        "2. Configure content filters for harmful categories (hate, violence, sexual).",
        "3. Add denied topic filters for sensitive business topics.",
        "4. Enable PII detection and redaction (SSN, email, phone, credit card).",
        "5. Apply the guardrail to all inference calls using guardrailIdentifier.",
        "6. Monitor guardrail interventions via CloudWatch metrics.",
    ]

    def check(self) -> List[Finding]:
        # Paginate through all guardrails
        guardrails = []
        next_token = None

        while True:
            kwargs = {"maxResults": 100}
            if next_token:
                kwargs["nextToken"] = next_token

            response = self.client.list_guardrails(**kwargs)
            guardrails.extend(response.get("guardrails", []))
            next_token = response.get("nextToken")
            if not next_token:
                break

        if not guardrails:
            return [self._make_finding(
                Status.FAILED,
                "No Bedrock guardrails are configured in this account/region. "
                "Model invocations have no content filtering or PII protection.",
                resource_id="Account",
            )]

        ready_guardrails = [g for g in guardrails if g.get("status") == "READY"]

        if not ready_guardrails:
            names = ", ".join(g.get("name", g.get("id", "?")) for g in guardrails)
            return [self._make_finding(
                Status.FAILED,
                f"Found {len(guardrails)} guardrail(s) but none are in READY status: {names}.",
                resource_id="Account",
            )]

        names = ", ".join(g.get("name", g.get("id", "?")) for g in ready_guardrails)
        return [self._make_finding(
            Status.PASSED,
            f"Found {len(ready_guardrails)} active guardrail(s): {names}.",
            resource_id="Account",
        )]


# ------------------------------------------------------------------
# BDR-003: Overly Permissive Model Access
# ------------------------------------------------------------------

class BedrockModelAccessCheck(BaseCheck):
    """Check for IAM policies granting overly broad Bedrock model access."""

    check_name = "Bedrock Model Access Permissions"
    service = "bedrock"
    severity = Severity.HIGH
    finding_id = "BDR-003"
    description = (
        "Checks whether any attached customer-managed IAM policies grant "
        "unrestricted Bedrock model access ('bedrock:*' or 'bedrock:InvokeModel' "
        "with Resource '*')."
    )
    impact = (
        "Unrestricted model access allows any authorized identity to invoke any "
        "model without restriction. This increases costs, enables data extraction "
        "from knowledge bases, and expands the blast radius of compromised credentials."
    )
    remediation = [
        "1. Review IAM policies for bedrock:InvokeModel with Resource: '*'.",
        "2. Restrict model access to specific model ARNs.",
        "3. Use IAM condition keys to limit access by model provider.",
        "4. Create separate roles for different use cases (dev vs prod).",
        "5. Use IAM Access Analyzer to identify overly permissive Bedrock policies.",
        "6. Implement permission boundaries to cap maximum Bedrock permissions.",
    ]

    @staticmethod
    def _has_broad_bedrock_access(statement):
        """Check if a policy statement grants broad Bedrock access."""
        if statement.get("Effect") != "Allow":
            return False

        action = statement.get("Action", "")
        resource = statement.get("Resource", "")

        actions = action if isinstance(action, list) else [action]
        resources = resource if isinstance(resource, list) else [resource]

        has_broad_action = any(
            a in ("*", "bedrock:*", "bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream")
            for a in actions
        )
        has_broad_resource = "*" in resources

        return has_broad_action and has_broad_resource

    def check(self) -> List[Finding]:
        import json

        findings = []
        iam = get_client("iam", region=self.region)
        paginator = iam.get_paginator("list_policies")

        overly_permissive = []

        for page in paginator.paginate(Scope="Local", OnlyAttached=True):
            for policy in page.get("Policies", []):
                policy_arn = policy["Arn"]
                policy_name = policy["PolicyName"]
                default_version = policy.get("DefaultVersionId", "v1")

                version = iam.get_policy_version(
                    PolicyArn=policy_arn, VersionId=default_version,
                )
                document = version.get("PolicyVersion", {}).get("Document", {})
                if isinstance(document, str):
                    document = json.loads(document)

                statements = document.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                if any(self._has_broad_bedrock_access(s) for s in statements):
                    overly_permissive.append(policy_name)

        if overly_permissive:
            findings.append(self._make_finding(
                Status.FAILED,
                f"Found {len(overly_permissive)} policy(ies) granting broad Bedrock access: "
                f"{', '.join(overly_permissive)}.",
                resource_id="Account",
            ))
        else:
            findings.append(self._make_finding(
                Status.PASSED,
                "No attached customer-managed policies grant unrestricted Bedrock model access.",
                resource_id="Account",
            ))

        return findings


# ------------------------------------------------------------------
# BDR-004: Custom Model Encryption Without CMK
# ------------------------------------------------------------------

class BedrockCustomModelEncryptionCheck(BaseCheck):
    """Check if custom models are encrypted with customer-managed KMS keys."""

    check_name = "Bedrock Custom Model Encryption"
    service = "bedrock"
    severity = Severity.MEDIUM
    finding_id = "BDR-004"
    description = (
        "Checks whether Bedrock custom models (fine-tuned or continued "
        "pre-training) are encrypted with customer-managed KMS keys (CMKs) "
        "instead of AWS-managed keys."
    )
    impact = (
        "AWS-managed keys do not provide CloudTrail audit logs for key usage. "
        "No ability to implement custom key rotation policies, revoke access, "
        "or meet compliance requirements mandating customer-managed encryption."
    )
    remediation = [
        "1. When creating custom model jobs, specify a customer-managed KMS key.",
        "2. Create a KMS key with a restrictive key policy.",
        "3. Enable automatic key rotation on the KMS key.",
        "4. Review existing custom models and re-create with CMK encryption.",
        "5. Monitor key usage via CloudTrail for anomalous access patterns.",
    ]

    def check(self) -> List[Finding]:
        findings = []

        # List all custom models
        custom_models = []
        next_token = None

        while True:
            kwargs = {"maxResults": 100}
            if next_token:
                kwargs["nextToken"] = next_token
            response = self.client.list_custom_models(**kwargs)
            custom_models.extend(response.get("modelSummaries", []))
            next_token = response.get("nextToken")
            if not next_token:
                break

        if not custom_models:
            findings.append(self._make_finding(
                Status.PASSED,
                "No custom models found. Check is not applicable.",
                resource_id="N/A",
            ))
            return findings

        for model in custom_models:
            model_name = model.get("modelName", "unknown")
            model_arn = model.get("modelArn", model_name)

            try:
                detail = self.client.get_custom_model(modelIdentifier=model_name)
                kms_key = detail.get("modelKmsKeyArn")

                if kms_key:
                    findings.append(self._make_finding(
                        Status.PASSED,
                        f"Custom model '{model_name}' is encrypted with "
                        f"customer-managed KMS key: {kms_key}.",
                        resource_id=model_arn,
                    ))
                else:
                    findings.append(self._make_finding(
                        Status.FAILED,
                        f"Custom model '{model_name}' is encrypted with AWS-managed key "
                        f"instead of a customer-managed KMS key.",
                        resource_id=model_arn,
                    ))
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                findings.append(self._make_finding(
                    Status.ERROR,
                    resource_id=model_arn,
                    error_message=f"Error checking model '{model_name}': {error_code}",
                ))

        return findings


# ------------------------------------------------------------------
# BDR-005: No VPC Endpoint for Bedrock API
# ------------------------------------------------------------------

class BedrockVPCEndpointCheck(BaseCheck):
    """Check if a VPC endpoint exists for Bedrock runtime API."""

    check_name = "Bedrock VPC Endpoint"
    service = "bedrock"
    severity = Severity.MEDIUM
    finding_id = "BDR-005"
    description = (
        "Checks whether a VPC interface endpoint (AWS PrivateLink) exists for "
        "the Bedrock runtime API, keeping API traffic off the public internet."
    )
    impact = (
        "Without a VPC endpoint, all Bedrock API traffic (prompts, responses, model data) "
        "traverses the public internet. This increases exposure to network-level attacks "
        "and violates security architectures requiring private connectivity."
    )
    remediation = [
        "1. Open the VPC console > 'Endpoints' > 'Create Endpoint'.",
        "2. Select 'AWS services' and search for com.amazonaws.REGION.bedrock-runtime.",
        "3. Select the VPC and subnets where Bedrock clients run.",
        "4. Attach a security group allowing HTTPS (443) from client subnets.",
        "5. Optionally create an endpoint for com.amazonaws.REGION.bedrock (control plane).",
        "6. Apply a VPC endpoint policy to restrict allowed models and actions.",
    ]

    def check(self) -> List[Finding]:
        ec2 = get_client("ec2", region=self.region)

        bedrock_service = f"com.amazonaws.{self.region}.bedrock-runtime"

        response = ec2.describe_vpc_endpoints(
            Filters=[
                {"Name": "service-name", "Values": [bedrock_service]},
                {"Name": "vpc-endpoint-state", "Values": ["available", "pending"]},
            ]
        )

        endpoints = response.get("VpcEndpoints", [])

        if endpoints:
            vpcs = ", ".join(ep.get("VpcId", "?") for ep in endpoints)
            return [self._make_finding(
                Status.PASSED,
                f"Found {len(endpoints)} VPC endpoint(s) for Bedrock runtime "
                f"({bedrock_service}) in VPC(s): {vpcs}.",
                resource_id=bedrock_service,
            )]
        else:
            return [self._make_finding(
                Status.FAILED,
                f"No VPC endpoint found for Bedrock runtime ({bedrock_service}). "
                f"API traffic is routed over the public internet.",
                resource_id=bedrock_service,
            )]


# Registry of all Bedrock checks — ordered HIGH → MEDIUM
BEDROCK_CHECKS = [
    BedrockInvocationLoggingCheck,      # BDR-001  HIGH
    BedrockGuardrailsCheck,             # BDR-002  HIGH
    BedrockModelAccessCheck,            # BDR-003  HIGH
    BedrockCustomModelEncryptionCheck,  # BDR-004  MEDIUM
    BedrockVPCEndpointCheck,            # BDR-005  MEDIUM
]
