"""
sraverify - Security Reference Architecture Verification Tool

This package provides both a command-line interface (``sraverify.cli``, run as
``sraverify`` or ``python -m sraverify``) and a Python library
(``sraverify.scanner``) for verifying AWS Security Reference Architecture
implementations.

The library configures no logging. Records go to the ``sraverify`` logger, which
carries only a ``NullHandler``; configure logging in your application to see them.

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

# The single source of the package version. pyproject.toml's [tool.hatch.version]
# reads this line as text, so keep it a plain string literal assignment.
__version__ = "0.2.8"

from sraverify.scanner import SRAVerify

__all__ = ['SRAVerify']