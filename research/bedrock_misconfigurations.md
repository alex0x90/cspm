# Amazon Bedrock — Security Misconfiguration Analysis

## Service Overview
- Fully managed generative AI service for building applications with foundation models (FMs)
- Key features: model invocation, custom models, guardrails, agents, knowledge bases, model evaluation
- Assets: prompts, responses, fine-tuned models, agent configurations, knowledge base data, API keys
- Attack surface: missing invocation logging, absent guardrails, overly permissive model access, unencrypted data, no VPC isolation

---

## HIGH Severity

### Model Invocation Logging Disabled (BDR-001)
- **Description**: Amazon Bedrock model invocation logging is disabled by default. Without enabling it, no record of model requests, responses, or metadata is captured for the account.
- **Risk**: Without invocation logging, there is no visibility into what prompts are being sent, what responses are generated, or who is invoking models. Impossible to detect prompt injection attacks, data exfiltration via model responses, abuse of model access, or compliance violations.
- **Attack Scenario**: An attacker with compromised IAM credentials invokes a Bedrock model to extract sensitive information from a knowledge base or generate harmful content. Without invocation logging, the organization has no audit trail of the queries, no way to detect the abuse, and cannot perform forensic analysis or incident response.
- **Remediation**:
  1. Open the Amazon Bedrock console > "Settings" > "Model invocation logging".
  2. Enable logging and configure destinations:
     - CloudWatch Logs: specify a log group for real-time monitoring and alerting.
     - S3: specify a bucket (same region) for long-term storage and analysis.
  3. Enable logging for all data types (text, image, embedding, video).
  4. Attach a bucket policy granting `bedrock.amazonaws.com` the `s3:PutObject` permission.
  5. Configure CloudWatch alarms on invocation patterns for anomaly detection.
  6. Use the `PutModelInvocationLoggingConfiguration` API for infrastructure-as-code.
- **Likelihood**: High

---

### No Guardrails Configured (BDR-002)
- **Description**: Amazon Bedrock guardrails are not configured for model invocations. Guardrails inspect prompts and responses for harmful content, PII, denied topics, and policy violations — providing a critical safety layer for generative AI.
- **Risk**: Without guardrails, models can be manipulated via prompt injection to generate harmful, biased, or policy-violating content. Sensitive data (PII, credentials) can leak through model responses. No content filtering means no protection against abuse.
- **Attack Scenario**: An attacker uses prompt injection techniques to bypass application-level controls and extract PII from a Bedrock knowledge base. The model responds with customer names, email addresses, and phone numbers. Without guardrails, there is no automated detection or blocking of PII in responses, and the data is exfiltrated.
- **Remediation**:
  1. Open the Bedrock console > "Guardrails" > "Create guardrail".
  2. Configure content filters for harmful categories (hate, violence, sexual, misconduct).
  3. Add denied topic filters for sensitive business topics.
  4. Enable PII detection and redaction (SSN, email, phone, credit card, etc.).
  5. Configure word filters for profanity and custom blocked terms.
  6. Apply the guardrail to all Bedrock inference calls using the `guardrailIdentifier` and `guardrailVersion` parameters.
  7. Monitor guardrail interventions via CloudWatch metrics.
- **Likelihood**: High

---

### Overly Permissive Model Access (BDR-003)
- **Description**: IAM policies granting `bedrock:InvokeModel` or `bedrock:*` with `Resource: "*"` allow identities to invoke any foundation model or custom model without restriction, violating the principle of least privilege.
- **Risk**: Unrestricted model access allows any authorized identity to invoke expensive or powerful models they don't need. This increases costs, enables data extraction from knowledge bases, and expands the blast radius of compromised credentials.
- **Attack Scenario**: A developer's IAM role has `bedrock:*` permissions. An attacker compromises the role and invokes high-cost models (e.g., Anthropic Claude, Meta Llama) at scale, running up significant charges. They also invoke models connected to internal knowledge bases, extracting proprietary business data and customer information.
- **Remediation**:
  1. Review IAM policies for `bedrock:InvokeModel` with `Resource: "*"`.
  2. Restrict model access to specific model ARNs:
     `arn:aws:bedrock:REGION::foundation-model/MODEL_ID`
  3. Use IAM condition keys to limit access by model provider or inference profile.
  4. Create separate roles for different use cases (development vs. production).
  5. Use IAM Access Analyzer to identify overly permissive Bedrock policies.
  6. Implement permission boundaries to cap maximum Bedrock permissions.
- **Likelihood**: High

---

## MEDIUM Severity

### Custom Model Encryption Without Customer-Managed Keys (BDR-004)
- **Description**: Custom models (fine-tuned or continued pre-training) and their associated data are encrypted with AWS-managed keys instead of customer-managed KMS keys (CMKs), reducing control over key management and audit trails.
- **Risk**: AWS-managed keys do not provide CloudTrail audit logs for key usage, making it impossible to track who accessed the encryption keys. No ability to implement key rotation policies, revoke access, or meet strict compliance requirements (HIPAA, PCI-DSS, FedRAMP) that mandate customer-managed encryption.
- **Attack Scenario**: A security audit reveals that fine-tuned Bedrock models contain proprietary training data. Because AWS-managed keys are used, there is no CloudTrail record of key usage to verify who accessed the model artifacts. The organization cannot demonstrate compliance with data protection regulations and fails the audit.
- **Remediation**:
  1. When creating custom model jobs, specify a customer-managed KMS key.
  2. Create a KMS key with a restrictive key policy limiting access to authorized roles.
  3. Enable automatic key rotation on the KMS key.
  4. For agent sessions, configure customer-managed keys for session encryption.
  5. Review existing custom models and re-create with CMK encryption if needed.
  6. Monitor key usage via CloudTrail for anomalous access patterns.
- **Likelihood**: Medium

---

### No VPC Endpoint for Bedrock API (BDR-005)
- **Description**: Amazon Bedrock API calls are routed over the public internet instead of through a VPC interface endpoint (AWS PrivateLink), exposing API traffic to potential interception.
- **Risk**: Without a VPC endpoint, all Bedrock API traffic (including prompts, responses, and model data) traverses the public internet. This increases exposure to network-level attacks and violates security architectures that require private connectivity for sensitive workloads.
- **Attack Scenario**: An application in a private VPC sends sensitive prompts to Bedrock over the public internet via a NAT Gateway. An attacker with access to the network path performs traffic analysis, identifying patterns in API calls and metadata. In a more targeted attack, DNS hijacking redirects Bedrock API calls to a malicious endpoint that captures prompts containing confidential business data.
- **Remediation**:
  1. Open the VPC console > "Endpoints" > "Create Endpoint".
  2. Select "AWS services" and search for `com.amazonaws.REGION.bedrock-runtime`.
  3. Select the VPC and subnets where Bedrock clients run.
  4. Attach a security group allowing HTTPS (443) from client subnets.
  5. Optionally create an endpoint for `com.amazonaws.REGION.bedrock` (control plane).
  6. Apply a VPC endpoint policy to restrict which models and actions are allowed.
  7. Update route tables and DNS settings (enable private DNS).
- **Likelihood**: Medium
