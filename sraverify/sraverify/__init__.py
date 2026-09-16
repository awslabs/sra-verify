"""
sraverify - Security Reference Architecture Verification Tool

This package provides both a command-line interface and a Python library for verifying
AWS Security Reference Architecture implementations.

Example usage as a library:

    from sraverify import SRAVerify
    from sraverify.core.enums import Status

    # Create an instance with optional AWS profile and regions
    sra = SRAVerify(profile='my-profile', regions=['us-east-1', 'us-west-2'])

    # Get available checks and services. Neither issues an AWS API call.
    checks = sra.get_available_checks()
    services = sra.get_available_services()

    # Run checks with various filters
    findings = sra.run_checks(
        account_type='application',  # or 'audit', 'log-archive', 'management', 'all'
        service='GuardDuty',        # optional service filter
        check_id='SRA-GUARDDUTY-01',  # optional specific check
        audit_accounts=['123456789012'],  # optional audit account IDs
        log_archive_accounts=['987654321098']  # optional log archive account IDs
    )

    # Process findings. run_checks returns a list of Finding dataclasses, not
    # dicts, so fields are read as attributes and status is a Status member.
    for finding in findings:
        print(f"{finding.check_id}: {finding.status.value} - {finding.title}")

An unknown check_id raises UnknownCheckError and a filter combination matching
no checks raises NoChecksSelectedError (both from sraverify.core.errors), so a
usage error cannot masquerade as a clean scan that found nothing.

See sraverify/README.md for the check-authoring contract and the full library
surface.
"""

__version__ = "0.2.1"

from sraverify.main import SRAVerify

__all__ = ['SRAVerify']