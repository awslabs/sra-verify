"""
SRA Verify command-line interface.

The ``sraverify`` console script and ``python -m sraverify`` both land in
:func:`main`. This module owns everything that belongs to the process rather
than to the library: argument parsing, logging configuration, the banner, the
output path, the summary on stdout, and the exit status. The scan itself is
``sraverify.scanner.SRAVerify``.
"""
import argparse
import datetime
import logging
import os
import sys
from typing import List, Optional, Sequence

from sraverify.core.enums import AccountType, Status
from sraverify.core.errors import (
    NoChecksSelectedError,
    PartitionUndeterminedError,
    UnknownCheckError,
)
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
from sraverify.scanner import SRAVerify
from sraverify.utils.banner import print_banner
from sraverify.utils.outputs import write_csv_output

#: Output path used when ``--output`` is omitted. Named rather than repeated
#: because the CLI compares against it to decide whether to inject a timestamp
#: (Requirement 9.12): an operator who supplies this exact path explicitly gets
#: a timestamp too, which is the pre-change behavior and is deliberately kept.
DEFAULT_OUTPUT = 'sraverify_findings.csv'

#: Record format for the CLI's stderr handler.
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

#: Third-party loggers held at WARNING: at DEBUG they log every request, which
#: would bury the one-line ``aws_call_failed`` records ``--debug`` exists for.
_QUIET_LOGGERS = ("boto3", "botocore", "urllib3")

#: The stderr handler this module installed on the ``sraverify`` logger, kept
#: so a second ``main()`` in the same process replaces it rather than stacking
#: a duplicate that would emit every record twice.
_cli_handler: Optional[logging.Handler] = None


def configure_logging(debug: bool = False) -> None:
    """Send diagnostics to stderr at the CLI's levels. CLI-only.

    The library installs nothing but a ``NullHandler``, so without this call a
    scan logs nowhere. Here the ``sraverify`` logger gets its own stderr
    handler at ``ERROR`` (``DEBUG`` with ``--debug``) and stops propagating, so
    its level does not depend on the root logger's. The root logger gets a
    stderr handler through ``basicConfig`` for boto3/botocore/urllib3, which
    are held at ``WARNING``.

    ``ERROR`` rather than ``INFO`` by default because ``logger.error`` is
    reserved for something that produced an ERROR row in the report
    (``test_no_error_level_records_without_error_rows``), so a clean scan
    prints nothing on stderr. The package makes no ``logger.info`` calls, so
    the default suppresses only ``WARNING`` -- almost entirely "no client
    available for region X", which already reaches the report as a
    ``NoClient`` ERROR row. The banner, progress bar and summary are written to
    stdout directly and are unaffected.

    Nothing here ever writes to stdout: the MCP server's JSON-RPC stream and
    the separability of report from diagnostics both depend on it.

    Idempotent: calling it again replaces the handler it installed before.

    Args:
        debug: ``True`` for ``DEBUG`` on the ``sraverify`` logger, which
            surfaces warnings and the per-failure ``aws_call_failed`` records.
    """
    global _cli_handler

    # A no-op when the root already has handlers (an embedding application,
    # or pytest), which is the behavior wanted: never replace someone else's.
    logging.basicConfig(stream=sys.stderr, format=LOG_FORMAT, level=logging.WARNING)
    for name in _QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)

    if _cli_handler is not None:
        logger.removeHandler(_cli_handler)
    _cli_handler = logging.StreamHandler(sys.stderr)
    _cli_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(_cli_handler)
    logger.propagate = False
    logger.setLevel(logging.DEBUG if debug else logging.ERROR)
    logger.debug("Debug logging enabled")


def print_summary(findings: List[Finding], output_file: str) -> None:
    """Report the per-status tallies on standard output.

    Reached only once the report has been written, so its appearance is the
    operator's signal that a usable CSV exists at ``output_file`` (Requirement
    9.14 suppresses it on a write failure).

    ``f.status`` is a :class:`Status` member and is compared against the enum, not
    against a string literal. A ``Finding`` is a frozen dataclass with no ``get``,
    so a dict-style read here would raise rather than silently tally zero.

    Args:
        findings: The findings just written, in output order.
        output_file: The resolved path they were written to, echoed so the
            operator does not have to reconstruct the injected timestamp.
    """
    pass_count = sum(1 for f in findings if f.status is Status.PASS)
    fail_count = sum(1 for f in findings if f.status is Status.FAIL)
    error_count = sum(1 for f in findings if f.status is Status.ERROR)

    logger.debug("Scan complete")
    print("\n-> Scan complete!")
    print(f"  · Total findings: {len(findings)}")
    print(f"  · Pass: {pass_count}")
    print(f"  · Fail: {fail_count}")
    print(f"  · Error: {error_count}")
    print(f"  · Output: {output_file}")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command line arguments.

    Args:
        argv: Arguments excluding the program name. ``None`` reads
            ``sys.argv[1:]``, which is what the console script does.
    """
    parser = argparse.ArgumentParser(description='SRA Verify - Security Rule Assessment Verification Tool')
    parser.add_argument('--profile', type=str, help='AWS profile to use')
    parser.add_argument('--role', type=str, help='ARN of IAM role to assume')
    parser.add_argument('--regions', type=str,
                        help='Comma-separated list of AWS regions to check. The first value '
                             'also selects the AWS partition. Required unless the session has '
                             'a Region (AWS_DEFAULT_REGION, or region = in the profile; '
                             'boto3 does not read AWS_REGION by itself).')
    parser.add_argument('--output', type=str, default=DEFAULT_OUTPUT,
                        help=f'Output file name (default: {DEFAULT_OUTPUT})')
    parser.add_argument('--check', type=str, help='Run a specific check (e.g., SRA-GUARDDUTY-01)')
    parser.add_argument('--service', type=str, help='Run checks for a specific service (e.g., GuardDuty)')
    # Choices derived from the enum plus the literal 'all', so the CLI holds no
    # second list of account-type strings to drift from AccountType (9.10). The
    # help text is generated from the same source for the same reason. Note the
    # values are the members' ``.value`` strings, not the members: argparse
    # compares the supplied string against the choices, and while StrEnum
    # members would compare equal, they render as ``AccountType.APPLICATION``
    # in the usage message.
    account_type_choices = [t.value for t in AccountType] + ['all']
    parser.add_argument('--account-type', type=str,
                        choices=account_type_choices,
                        default='all',
                        help='Type of accounts to run checks against: '
                             f'{", ".join(account_type_choices)} (default: all)')
    parser.add_argument('--audit-account', type=str, metavar='ACCOUNTID1,ACCOUNTID2',
                        help='AWS accounts used for Audit/Security Tooling, use comma separated values')
    parser.add_argument('--log-archive-account', type=str, metavar='ACCOUNTID1,ACCOUNTID2',
                        help='AWS accounts used for Logging, use comma separated values')
    parser.add_argument('--list-checks', action='store_true', help='List available checks')
    parser.add_argument('--list-services', action='store_true', help='List available services')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    # Bounded boto3 Client_Config knobs forwarded into the per-scan
    # ScanContext. Defaults match the ScanContext defaults (10s connect,
    # 30s read, 3 retry attempts, 50 pool connections); when these flags
    # are omitted the ScanContext defaults take effect.
    parser.add_argument('--connect-timeout', type=float, default=None,
                        help='boto3 connect timeout in seconds (default: 10)')
    parser.add_argument('--read-timeout', type=float, default=None,
                        help='boto3 read timeout in seconds (default: 30)')
    parser.add_argument('--max-attempts', type=int, default=None,
                        help='boto3 retry max_attempts (default: 3)')
    parser.add_argument('--max-pool-connections', type=int, default=None,
                        help='boto3 max_pool_connections (default: 50)')

    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return its exit status.

    The console script wraps this as ``sys.exit(main())``, and ``__main__.py``
    does the same, so returning rather than exiting keeps the function callable
    from tests and from other Python code. argparse's own usage errors still
    raise ``SystemExit(2)`` from ``parse_args``.

    Args:
        argv: Arguments excluding the program name; ``None`` reads ``sys.argv``.

    Returns:
        0 when a report was written, regardless of FAIL and ERROR rows; 1 when
        the scan ran but the report could not be written; 2 for a usage error
        (an unknown --check, an empty filter combination, or a scan Region
        that cannot be determined), with no file created.
    """
    args = parse_args(argv)

    # First, so every record from here on -- including session setup inside
    # SRAVerify -- goes to stderr at the requested level.
    configure_logging(args.debug)

    regions = [r.strip() for r in args.regions.split(',')] if args.regions else None
    try:
        sra = SRAVerify(
            profile=args.profile,
            role_arn=args.role,
            regions=regions,
            connect_timeout=args.connect_timeout,
            read_timeout=args.read_timeout,
            max_attempts=args.max_attempts,
            max_pool_connections=args.max_pool_connections,
        )
    except PartitionUndeterminedError as exc:
        # Only reachable with --role: get_session refuses to send AssumeRole to
        # an unknown partition. No output path has been resolved yet, so no
        # file can exist.
        logger.error(str(exc))
        return 2

    if args.list_checks:
        checks = sra.get_available_checks(args.account_type)
        print("Available checks:")
        for check_id, info in checks.items():
            print(f"  {check_id}: {info['name']} ({info['service']}) [{info['account_type']}]")
        return 0

    if args.list_services:
        services = sra.get_available_services()
        print("Available services:")
        for service in services:
            print(f"  {service}")
        return 0

    # Parse audit accounts if provided
    audit_accounts = None
    if args.audit_account:
        audit_accounts = [a.strip() for a in args.audit_account.split(',')]
        logger.debug(f"Using audit accounts: {', '.join(audit_accounts)}")

    # Parse log archive accounts if provided
    log_archive_accounts = None
    if args.log_archive_account:
        log_archive_accounts = [a.strip() for a in args.log_archive_account.split(',')]
        logger.debug(f"Using log archive accounts: {', '.join(log_archive_accounts)}")

    # Resolved BEFORE the scan so the error paths below know the path -- the
    # exit-2 path has to promise no file was created there, and the exit-1 path
    # has to name it. A timestamp is injected ONLY when --output was left at
    # its default, so an explicit --output is never rewritten (9.12).
    # ``splitext`` rather than string surgery so the stamp lands before the
    # extension: sraverify_findings_20250909_074500.csv.
    output_file = args.output
    if output_file == DEFAULT_OUTPUT:
        stem, ext = os.path.splitext(DEFAULT_OUTPUT)
        stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"{stem}_{stamp}{ext}"

    # One guarded block spanning the banner and the scan, because BOTH resolve
    # the filters: the banner's check count calls ``select_checks`` directly,
    # and ``run_checks`` calls it again. A mistyped --check would otherwise
    # traceback out of the banner before ever reaching the handler below. Exit
    # 2 is the argparse convention for a usage error, which is also what
    # argparse itself returns for a bad --account-type, so the CLI is
    # internally consistent (9.7).
    try:
        # First: refuse a scan whose partition cannot be determined, ahead of
        # the banner's check count and its STS call. When both the partition
        # and the filters are bad, the partition error is the one reported.
        scan_region = sra.resolve_scan_region()

        # Display banner with session information
        print_banner(
            profile=args.profile or 'default',
            region=scan_region,
            session=sra.session,
            regions=regions,
            account_type=args.account_type,
            # Derived from the selected mapping, so the banner reports the
            # checks that are about to run rather than the whole account-type
            # inventory, and constructs no check to count them.
            checks_count=len(sra.select_checks(args.account_type, args.service, args.check)),
            output_file=output_file,
            role=args.role
        )

        findings = sra.run_checks(
            account_type=args.account_type,
            service=args.service,
            check_id=args.check,
            audit_accounts=audit_accounts,
            log_archive_accounts=log_archive_accounts,
            show_progress=True
        )
    except (UnknownCheckError, NoChecksSelectedError, PartitionUndeterminedError) as exc:
        # Usage error. UnknownCheckError composes a sentence carrying the
        # unmatched ID and its near-miss suggestions; NoChecksSelectedError
        # renders the three filter values through __str__ while keeping them as
        # its args for a library caller; PartitionUndeterminedError names
        # --regions and AWS_DEFAULT_REGION. Either way ``str(exc)`` holds everything
        # 9.7 requires be logged, and the phrasing belongs to the exception rather
        # than to the CLI so a library caller sees the same text.
        logger.error(str(exc))
        # No file is created at output_file: nothing has touched it yet, and
        # write_csv_output is not reached. This replaces the pre-change
        # "log, return [], write a header-only CSV, exit 0", which was
        # indistinguishable from a clean scan and, in the CodeBuild fan-out,
        # silently under-reported a whole account (9.14).
        return 2

    logger.debug(f"Writing findings to {output_file}")
    try:
        write_csv_output(findings, output_file)
    except OSError as exc:
        # The scan itself succeeded and the write failed -- often transient (a
        # full disk, a stale working directory), so it is worth retrying, which
        # is why it is status 1 and not the 2 reserved for arguments that will
        # not work on a second run. No summary is printed: the summary is the
        # operator's evidence that a usable report exists (9.14).
        logger.error(f"Could not write {output_file}: {exc}")
        return 1

    print_summary(findings, output_file)

    # 0 even with FAIL and ERROR rows present (9.13). This is load-bearing and
    # the instinct runs the other way: the buildspec fans sraverify out across
    # every ACTIVE account with GNU parallel, and a non-zero exit from one
    # member account would abort or degrade the fan-out. A FAIL is not a tool
    # failure -- it is the tool working. A non-zero status means only "this
    # invocation produced no usable report", which is exactly the signal the
    # pandas consolidation step needs to tell a missing CSV from an empty one.
    return 0


if __name__ == "__main__":
    sys.exit(main())
