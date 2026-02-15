"""
Findings Data Models

Data structures for representing security check results,
individual findings, and scan reports.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import List


class Severity(str, Enum):
    """Severity levels for findings."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Status(str, Enum):
    """Status values for check results."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"


@dataclass
class Finding:
    """
    Represents a single security check result.

    Attributes:
        check_id: Unique identifier for the check.
        check_name: Human-readable name of the check.
        severity: HIGH, MEDIUM, or LOW.
        status: PASSED, FAILED, or ERROR.
        description: What was checked.
        issue: What was found (details of the misconfiguration).
        remediation: Step-by-step remediation guidance (list of steps).
        impact: Potential security impact if not addressed.
        resource_id: AWS resource identifier (if applicable).
        region: AWS region (if applicable).
        error_message: Error details (if ERROR status).
    """
    check_id: str
    check_name: str
    severity: str
    status: str
    description: str
    issue: str = ""
    remediation: List[str] = field(default_factory=list)
    impact: str = ""
    resource_id: str = ""
    region: str = ""
    error_message: str = ""

    def to_dict(self):
        """Convert finding to a dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class ScanReport:
    """
    Represents a complete scan report containing all findings
    and summary metadata.

    Attributes:
        scan_date: Timestamp of the scan.
        services: List of AWS services scanned.
        region: AWS region scanned.
        findings: List of Finding objects.
        account_id: AWS account ID.
        account_arn: AWS account ARN.
    """
    scan_date: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    services: List[str] = field(default_factory=list)
    region: str = ""
    findings: List[Finding] = field(default_factory=list)
    account_id: str = ""
    account_arn: str = ""

    @property
    def total_checks(self) -> int:
        """Total number of checks performed."""
        return len(self.findings)

    @property
    def passed_count(self) -> int:
        """Number of checks that passed."""
        return sum(1 for f in self.findings if f.status == Status.PASSED)

    @property
    def failed_count(self) -> int:
        """Number of checks that failed (misconfigurations found)."""
        return sum(1 for f in self.findings if f.status == Status.FAILED)

    @property
    def error_count(self) -> int:
        """Number of checks that encountered errors."""
        return sum(1 for f in self.findings if f.status == Status.ERROR)

    def get_summary(self) -> dict:
        """Generate summary statistics."""
        return {
            "total_checks": self.total_checks,
            "passed": self.passed_count,
            "failed": self.failed_count,
            "errors": self.error_count,
        }

    def to_dict(self) -> dict:
        """Convert the entire scan report to a dictionary for JSON serialization."""
        return {
            "scan_date": self.scan_date,
            "services": self.services,
            "region": self.region,
            "account_id": self.account_id,
            "account_arn": self.account_arn,
            "summary": self.get_summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
