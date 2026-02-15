"""
AWS Security Misconfiguration Detection System - Entry Point

CLI interface for running security checks against AWS services.

Usage:
    python -m src.main --service all --region us-east-1
    python -m src.main --service s3 --region us-east-1 --output json --output-file report.json
    python -m src.main --service ec2 --region us-west-2 --check EC2-001
"""

import sys
import os
import argparse
import json
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Reports folder path
REPORTS_DIR = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), "reports")

from config.aws_config import DEFAULT_REGION
from src.detector import SecurityDetector
from src.models.findings import Status


SUPPORTED_SERVICES = ["s3", "rds", "ec2", "iam", "all"]


def parse_args(argv=None):
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="AWS Security Misconfiguration Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m src.main --service all --region us-east-1\n"
            "  python -m src.main --service s3 --region us-east-1 --output json\n"
            "  python -m src.main --service ec2 --region us-west-2 --check EC2-001\n"
            "  python -m src.main --service all --region us-east-1 --output-file report.json\n"
        ),
    )

    parser.add_argument(
        "--service",
        type=str,
        default="all",
        choices=SUPPORTED_SERVICES,
        help="AWS service to check: s3, rds, ec2, or all (default: all)",
    )

    parser.add_argument(
        "--region",
        type=str,
        default=DEFAULT_REGION,
        help=f"AWS region to scan (default: {DEFAULT_REGION} from .env)",
    )

    parser.add_argument(
        "--check",
        type=str,
        default=None,
        help="Run a specific check by ID (e.g., S3-001, EC2-003). Default: run all checks.",
    )

    parser.add_argument(
        "--output",
        type=str,
        default="json",
        choices=["json", "text"],
        help="Output format: json or text (default: json)",
    )

    parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Export results to a file (e.g., report.json)",
    )

    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="AWS CLI profile to use (optional)",
    )

    return parser.parse_args(argv)


def main(argv=None):
    """Main entry point."""
    args = parse_args(argv)

    # Determine services to scan
    if args.service == "all":
        services = ["s3", "rds", "ec2", "iam"]
    else:
        services = [args.service]

    print(f"AWS Security Misconfiguration Detection System")
    print(f"Scanning services: {', '.join(s.upper() for s in services)}")
    print(f"Region: {args.region}")
    print()

    # Initialize detector
    try:
        detector = SecurityDetector(
            services=services,
            region=args.region,
            profile=args.profile,
        )
    except ValueError as e:
        print(f"ERROR: {e}")
        return 2

    # Validate credentials
    print("Validating AWS credentials...")
    try:
        identity = detector.validate()
        print(f"Authenticated as: {identity['arn']}")
        print(f"Account ID: {identity['account']}")
        print()
    except Exception:
        print("Failed to validate AWS credentials. Exiting.")
        return 2

    # Show what misconfigurations we are scanning for
    checks_info = detector.get_checks_info()
    print("Scanning for the following misconfigurations:")
    print("=" * 60)
    for svc, checks_list in checks_info.items():
        print(f"\n  {svc.upper()}:")
        for check_id, check_name, severity, description in checks_list:
            print(f"    {check_id} - {check_name} [{severity}]")
    print()
    print("=" * 60)

    # Run the scan
    print("\nSearching for misconfigurations...\n")

    try:
        if args.check:
            report = detector.run_specific_check(args.check)
        else:
            report = detector.run_all_checks()
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during scanning: {e}")
        return 2

    # Only show misconfigurations that were found
    failed_findings = [f for f in report.findings if f.status in (Status.FAILED, Status.ERROR)]
    summary = report.get_summary()

    if failed_findings:
        print(f"Found {len(failed_findings)} misconfiguration(s):\n")
        print("=" * 60)
        for finding in failed_findings:
            print()
            print(f"  [{finding.severity}] {finding.check_id} - {finding.check_name}")
            print(f"  Resource: {finding.resource_id}")
            print(f"  Issue:    {finding.issue}")
            if finding.status == Status.ERROR:
                print(f"  Error:    {finding.error_message}")
            print()
            print("-" * 60)

        # Generate JSON report for misconfigurations with remediation
        misconfig_report = {
            "scan_date": report.scan_date,
            "account_id": report.account_id,
            "region": report.region,
            "total_misconfigurations": len(failed_findings),
            "misconfigurations": [],
        }
        for finding in failed_findings:
            misconfig_report["misconfigurations"].append({
                "check_id": finding.check_id,
                "check_name": finding.check_name,
                "severity": finding.severity,
                "resource_id": finding.resource_id,
                "description": finding.description,
                "issue": finding.issue,
                "impact": finding.impact,
                "remediation": finding.remediation,
            })

        # Write JSON report to reports folder
        os.makedirs(REPORTS_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        service_label = args.service if args.service != "all" else "all"
        report_filename = f"report_{service_label}_{timestamp}.json"
        report_path = os.path.join(REPORTS_DIR, report_filename)

        try:
            with open(report_path, "w") as f:
                json.dump(misconfig_report, f, indent=2)
            print(f"\nJSON report saved to: {report_path}")
        except IOError as e:
            print(f"\nERROR: Could not write report: {e}")
            return 2
    else:
        print("No misconfigurations found. All checks passed!\n")

    # Exit code based on findings
    if summary["errors"] > 0:
        return 2
    elif summary["failed"] > 0:
        return 1
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())
