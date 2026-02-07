"""
Output Formatter Module

Formats scan reports into JSON or plain text for display and file export.
"""

import json
from src.models.findings import ScanReport, Status


def format_json(report: ScanReport, indent: int = 2) -> str:
    """
    Serialize a ScanReport to a JSON string.

    Args:
        report: The ScanReport to format.
        indent: JSON indentation level.

    Returns:
        str: JSON-formatted string.
    """
    return json.dumps(report.to_dict(), indent=indent, default=str)


def format_text(report: ScanReport) -> str:
    """
    Format a ScanReport as a human-readable plain text report.

    Args:
        report: The ScanReport to format.

    Returns:
        str: Plain text report string.
    """
    separator = "=" * 59
    thin_sep = "-" * 59
    lines = []

    # Header
    lines.append(separator)
    lines.append("  AWS Security Misconfiguration Detection Report")
    lines.append(separator)
    lines.append(f"  Service(s): {', '.join(s.upper() for s in report.services)}")
    lines.append(f"  Scan Date:  {report.scan_date}")
    lines.append(f"  Region:     {report.region}")
    lines.append(f"  Account:    {report.account_id}")
    lines.append(separator)

    # Summary
    summary = report.get_summary()
    lines.append("  FINDINGS SUMMARY")
    lines.append(separator)
    lines.append(f"  Total Checks: {summary['total_checks']}")
    lines.append(f"  Passed:       {summary['passed']}")
    lines.append(f"  Failed:       {summary['failed']}")
    lines.append(f"  Errors:       {summary['errors']}")
    lines.append(separator)

    # Detailed findings (only show FAILED and ERROR)
    failed_findings = [f for f in report.findings if f.status in (Status.FAILED, Status.ERROR)]

    if failed_findings:
        lines.append("  DETAILED FINDINGS")
        lines.append(separator)

        for finding in failed_findings:
            severity_badge = f"[{finding.severity}]"
            lines.append("")
            lines.append(f"  {severity_badge} {finding.check_name}")
            lines.append(f"  {thin_sep}")
            lines.append(f"  Status:      {finding.status}")
            lines.append(f"  Check ID:    {finding.check_id}")
            lines.append(f"  Resource:    {finding.resource_id}")
            lines.append(f"  Description: {finding.description}")

            if finding.status == Status.FAILED:
                lines.append(f"  Finding:     {finding.finding}")
                if finding.remediation:
                    lines.append(f"  Remediation:")
                    for rem_line in finding.remediation.split("\n"):
                        lines.append(f"    {rem_line}")
            elif finding.status == Status.ERROR:
                lines.append(f"  Error:       {finding.error_message}")

            lines.append(f"  {thin_sep}")
    else:
        lines.append("")
        lines.append("  No misconfigurations or errors found. All checks passed!")
        lines.append("")

    lines.append(separator)
    return "\n".join(lines)


def export_to_file(content: str, filepath: str) -> None:
    """
    Write formatted content to a file.

    Args:
        content: The formatted report content.
        filepath: The output file path.
    """
    with open(filepath, "w") as f:
        f.write(content)

