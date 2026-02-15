"""
Base Check Module

Abstract base class that all security checks inherit from.
Provides the template method pattern for executing checks
with consistent error handling and a helper for building findings.

Subclasses define check metadata as class-level attributes and
implement check() for the actual security logic.
"""

from abc import ABC, abstractmethod
from typing import List

from src.models.findings import Finding, Status
from src.utils.error_handler import handle_aws_error


class BaseCheck(ABC):
    """
    Abstract base class for all security checks.

    Subclasses must define these class attributes:
        check_name  (str):       Human-readable name of the check.
        service     (str):       AWS service being checked (e.g., 's3').
        severity    (str):       Severity level (Severity.HIGH / MEDIUM / LOW).
        finding_id  (str):       Unique identifier (e.g., 'S3-001').
        description (str):       What this check verifies.
        impact      (str):       Security impact if not addressed.
        remediation (List[str]): Step-by-step remediation guidance.

    Subclasses must implement:
        check() -> List[Finding]: Perform the actual security check.
    """

    # Sentinel values — subclasses must override all of these.
    check_name: str = NotImplemented
    service: str = NotImplemented
    severity: str = NotImplemented
    finding_id: str = NotImplemented
    description: str = NotImplemented
    impact: str = NotImplemented
    remediation: List[str] = NotImplemented

    def __init__(self, client, region="", context=None):
        """
        Initialize the check with an AWS client.

        Args:
            client: A boto3 client for the relevant AWS service.
            region: The AWS region being checked.
            context: Optional shared data dict (e.g., pre-fetched bucket list).
        """
        self.client = client
        self.region = region
        self.context = context or {}

    # ------------------------------------------------------------------
    # Finding helpers — eliminates boilerplate in every check class
    # ------------------------------------------------------------------

    def _make_finding(self, status, issue="", resource_id="", error_message=""):
        """
        Build a Finding with common fields auto-populated from class metadata.

        Remediation and impact are included automatically for FAILED findings.
        Impact is also included for ERROR findings.
        """
        return Finding(
            check_id=self.finding_id,
            check_name=self.check_name,
            severity=self.severity,
            status=status,
            description=self.description,
            issue=issue,
            remediation=self.remediation if status == Status.FAILED else [],
            impact=self.impact if status in (Status.FAILED, Status.ERROR) else "",
            resource_id=resource_id,
            region=self.region,
            error_message=error_message,
        )

    # ------------------------------------------------------------------
    # Abstract check method
    # ------------------------------------------------------------------

    @abstractmethod
    def check(self) -> List[Finding]:
        """
        Perform the security check.

        Returns:
            List[Finding]: A list of Finding objects, one per resource checked.
        """
        pass

    # ------------------------------------------------------------------
    # Template method with error handling
    # ------------------------------------------------------------------

    def execute(self) -> List[Finding]:
        """
        Template method that executes the check with error handling.

        Calls check() and catches any exceptions, converting them
        to ERROR findings using the error handler.

        Returns:
            List[Finding]: A list of Finding objects.
        """
        try:
            return self.check()
        except Exception as e:
            error_info = handle_aws_error(e)
            return [self._make_finding(
                Status.ERROR,
                resource_id="N/A",
                error_message=error_info["message"],
            )]
