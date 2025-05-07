"""
sraverify - Security Reference Architecture Verification Tool

This package provides both a command-line interface and a Python library for verifying
AWS Security Reference Architecture implementations.

Example usage as a library:

    from sraverify import SRAVerify

    # Create an instance with optional AWS profile and regions
    sra = SRAVerify(profile='my-profile', regions=['us-east-1', 'us-west-2'])

    # Get available checks and services
    checks = sra.get_available_checks()
    services = sra.get_available_services()

    # Run checks with various filters
    findings = sra.run_checks(
        account_type='application',  # or 'audit', 'log-archive', 'management', 'all'
        service='GuardDuty',        # optional service filter
        check_id='SRA-GD-1',       # optional specific check
        audit_accounts=['123456789012'],  # optional audit account IDs
        log_archive_accounts=['987654321098']  # optional log archive account IDs
    )

    # Process findings
    for finding in findings:
        print(f"{finding['CheckId']}: {finding['Status']} - {finding['Title']}")
"""

__version__ = "0.1.0"

from sraverify.main import SRAVerify

__all__ = ['SRAVerify']