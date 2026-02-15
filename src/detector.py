"""
Security Detector Module

Orchestrates all security checks across AWS services,
collects findings, and produces scan reports.
"""

from datetime import datetime
from typing import List, Optional

from src.models.findings import Finding, ScanReport
from src.utils.aws_client import get_client, validate_credentials
from src.checks.s3_checks import S3_CHECKS
from src.checks.rds_checks import RDS_CHECKS
from src.checks.ec2_checks import EC2_CHECKS
from src.checks.iam_checks import IAM_CHECKS
from src.checks.bedrock_checks import BEDROCK_CHECKS


# Map service names to their check registries and required boto3 client names
SERVICE_REGISTRY = {
    "s3": {
        "checks": S3_CHECKS,
        "client_service": "s3",
    },
    "rds": {
        "checks": RDS_CHECKS,
        "client_service": "rds",
    },
    "ec2": {
        "checks": EC2_CHECKS,
        "client_service": "ec2",
    },
    "iam": {
        "checks": IAM_CHECKS,
        "client_service": "iam",
    },
    "bedrock": {
        "checks": BEDROCK_CHECKS,
        "client_service": "bedrock",
    },
}


class SecurityDetector:
    """
    Orchestrates security checks across AWS services.

    Usage:
        detector = SecurityDetector(services=["s3", "ec2"], region="us-east-1")
        report = detector.run_all_checks()
    """

    def __init__(self, services: List[str], region: str, profile: Optional[str] = None):
        """
        Initialize the detector.

        Args:
            services: List of AWS service names to check (e.g., ["s3", "rds", "ec2"]).
            region: AWS region to scan.
            profile: AWS profile name (optional).
        """
        self.services = [s.lower() for s in services]
        self.region = region
        self.profile = profile
        self.findings: List[Finding] = []
        self.identity = None

        # Validate requested services
        for svc in self.services:
            if svc not in SERVICE_REGISTRY:
                raise ValueError(
                    f"Unknown service '{svc}'. Supported services: {', '.join(SERVICE_REGISTRY.keys())}"
                )

    def validate(self):
        """Validate AWS credentials and store identity info."""
        self.identity = validate_credentials(
            profile=self.profile, region=self.region
        )
        return self.identity

    def get_checks_info(self):
        """
        Return metadata for all checks that will be run, grouped by service.
        Reads class-level attributes directly — no instantiation needed.

        Returns:
            dict: {service_name: [(finding_id, check_name, severity, description), ...]}
        """
        info = {}
        for service_name in self.services:
            service_config = SERVICE_REGISTRY[service_name]
            checks_list = []
            for check_class in service_config["checks"]:
                checks_list.append((
                    check_class.finding_id,
                    check_class.check_name,
                    check_class.severity,
                    check_class.description,
                ))
            info[service_name] = checks_list
        return info

    def _build_report(self) -> ScanReport:
        """Build a ScanReport from the current findings and identity."""
        return ScanReport(
            scan_date=datetime.utcnow().isoformat(),
            services=self.services,
            region=self.region,
            findings=self.findings,
            account_id=self.identity.get("account", "N/A") if self.identity else "N/A",
            account_arn=self.identity.get("arn", "N/A") if self.identity else "N/A",
        )

    def run_all_checks(self) -> ScanReport:
        """
        Execute all registered checks for the configured services.

        Returns:
            ScanReport: A complete scan report with all findings.
        """
        self.findings = []

        for service_name in self.services:
            service_config = SERVICE_REGISTRY[service_name]
            client = get_client(
                service_config["client_service"],
                profile=self.profile,
                region=self.region,
            )

            # Pre-fetch shared data to avoid redundant API calls
            context = {}
            if service_name == "s3":
                context["buckets"] = client.list_buckets().get("Buckets", [])
            elif service_name == "iam":
                users = []
                paginator = client.get_paginator("list_users")
                for page in paginator.paginate():
                    users.extend(page.get("Users", []))
                context["users"] = users

            for check_class in service_config["checks"]:
                check_instance = check_class(client=client, region=self.region, context=context)
                results = check_instance.execute()
                self.findings.extend(results)

        return self._build_report()

    def run_specific_check(self, check_id: str) -> ScanReport:
        """
        Run a specific check by its finding ID.

        Args:
            check_id: The check ID to run (e.g., "S3-001", "EC2-003").

        Returns:
            ScanReport: A scan report containing results from the specific check.
        """
        self.findings = []

        for service_name in self.services:
            service_config = SERVICE_REGISTRY[service_name]

            for check_class in service_config["checks"]:
                if check_class.finding_id == check_id.upper():
                    client = get_client(
                        service_config["client_service"],
                        profile=self.profile,
                        region=self.region,
                    )
                    # Pre-fetch shared data
                    context = {}
                    if service_name == "s3":
                        context["buckets"] = client.list_buckets().get("Buckets", [])
                    elif service_name == "iam":
                        users = []
                        paginator = client.get_paginator("list_users")
                        for page in paginator.paginate():
                            users.extend(page.get("Users", []))
                        context["users"] = users

                    check_instance = check_class(client=client, region=self.region, context=context)
                    results = check_instance.execute()
                    self.findings.extend(results)

        return self._build_report()
