"""
Base Check Module

Abstract base class that all security checks inherit from.
Provides the template method pattern for executing checks
with consistent error handling.
"""

from abc import ABC, abstractmethod
from typing import List

from src.models.findings import Finding, Status
from src.utils.error_handler import handle_aws_error


class BaseCheck(ABC):
    """
    Abstract base class for all security checks.

    Subclasses must implement:
        - check(): Perform the actual security check.
        - get_severity(): Return the severity level (HIGH/MEDIUM/LOW).
        - get_description(): Return a description of what is being checked.
        - get_remediation(): Return step-by-step remediation guidance.
        - get_finding_id(): Return a unique identifier for this check type.

    Attributes:
        check_name: Human-readable name of the check.
        service: AWS service being checked (e.g., 's3', 'rds', 'ec2').
        region: AWS region being checked.
    """

    def __init__(self, client, region=""):
        """
        Initialize the check with an AWS client.

        Args:
            client: A boto3 client for the relevant AWS service.
            region: The AWS region being checked.
        """
        self.client = client
        self.region = region

    @property
    @abstractmethod
    def check_name(self) -> str:
        """Human-readable name of the check."""
        pass

    @property
    @abstractmethod
    def service(self) -> str:
        """AWS service being checked."""
        pass

    @abstractmethod
    def get_severity(self) -> str:
        """Return the severity level: HIGH, MEDIUM, or LOW."""
        pass

    @abstractmethod
    def get_description(self) -> str:
        """Return a description of what this check verifies."""
        pass

    @abstractmethod
    def get_remediation(self) -> str:
        """Return step-by-step remediation guidance."""
        pass

    @abstractmethod
    def get_finding_id(self) -> str:
        """Return a unique identifier for this check type."""
        pass

    def get_impact(self) -> str:
        """Return a description of the security impact if this check fails.
        Override in subclasses to provide check-specific impact statements."""
        return ""

    @abstractmethod
    def check(self) -> List[Finding]:
        """
        Perform the security check.

        Returns:
            List[Finding]: A list of Finding objects, one per resource checked.
        """
        pass

    def execute(self) -> List[Finding]:
        """
        Template method that executes the check with error handling.

        Calls check() and catches any exceptions, converting them
        to ERROR findings using the error handler. Automatically
        injects impact into all returned findings.

        Returns:
            List[Finding]: A list of Finding objects.
        """
        try:
            findings = self.check()
            # Auto-inject impact into all findings from this check
            impact = self.get_impact()
            if impact:
                for finding in findings:
                    if not finding.impact:
                        finding.impact = impact
            return findings
        except Exception as e:
            error_info = handle_aws_error(e)
            return [
                Finding(
                    check_id=self.get_finding_id(),
                    check_name=self.check_name,
                    severity=self.get_severity(),
                    status=Status.ERROR,
                    description=self.get_description(),
                    finding="",
                    remediation="",
                    impact=self.get_impact(),
                    resource_id="N/A",
                    region=self.region,
                    error_message=error_info["message"],
                )
            ]

