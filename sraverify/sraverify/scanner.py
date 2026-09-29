"""
SRA Verify library interface: the ``SRAVerify`` scan orchestrator.

This module is the library half of the package and is what
``from sraverify import SRAVerify`` resolves to. It selects checks, runs them
against a per-scan ``ScanContext``, and returns findings. It configures no
logging handlers and writes nothing to stdout; both belong to the host
application. The command-line interface lives in ``sraverify.cli``.
"""
import difflib
from boto3 import Session
from typing import Dict, List, Any, Optional

from sraverify.core.check import SecurityCheck
from sraverify.core.errors import NoChecksSelectedError, UnknownCheckError
from sraverify.core.enums import Status
from sraverify.core.finding import GLOBAL_REGION, Finding
from sraverify.core.registry import all_checks
from sraverify.core.session import get_session
from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext
from sraverify.utils.progress import ScanProgress

# Imported purely for its side effect: importing the services package walks
# every service subpackage and every ``sra_*`` check module, and each check
# class body fires ``SecurityCheck.__init_subclass__``, which registers it.
# The catalog is therefore reached only through ``all_checks()`` and there is
# no ``ALL_CHECKS`` dict here to maintain. This import looks removable and is
# not: drop it and the registry is empty, so every scan selects nothing.
import sraverify.services  # noqa: F401

#: Similarity floor, on difflib's 0-to-1 scale, for a registry key to be worth
#: offering as a near miss for an unmatched --check value.
SUGGESTION_CUTOFF = 0.6

#: At most this many suggestions accompany an UnknownCheckError.
SUGGESTION_LIMIT = 3


def _near_misses(check_id: str, registry) -> List[str]:
    """Registry keys similar enough to ``check_id`` to be worth suggesting.

    Ordered most similar first, with ties broken by ascending check ID.
    ``difflib.get_close_matches`` is not used directly: it selects with
    ``heapq.nlargest`` over ``(ratio, key)`` tuples, so equally-similar keys
    come back in *descending* key order -- ``SRA-GUARDDUTY-02`` before
    ``SRA-GUARDDUTY-01``. Computing the ratios here keeps difflib's scoring
    and its cheap ``quick_ratio`` short-circuits while making the tie order
    ascending and reproducible.

    Args:
        check_id: The unmatched value supplied on the command line.
        registry: The catalog mapping to search, read for its keys only.

    Returns:
        Up to ``SUGGESTION_LIMIT`` check IDs, possibly empty when nothing
        reaches ``SUGGESTION_CUTOFF``.
    """
    matcher = difflib.SequenceMatcher()
    matcher.set_seq2(check_id)
    scored = []
    for key in registry:
        matcher.set_seq1(key)
        if (matcher.real_quick_ratio() >= SUGGESTION_CUTOFF
                and matcher.quick_ratio() >= SUGGESTION_CUTOFF):
            ratio = matcher.ratio()
            if ratio >= SUGGESTION_CUTOFF:
                # Negated ratio first, so one ascending sort yields descending
                # similarity with ascending check ID inside each tie.
                scored.append((-ratio, key))
    scored.sort()
    return [key for _, key in scored[:SUGGESTION_LIMIT]]


def _synthetic_error(check_class: type[SecurityCheck], exc: Exception,
                     fallback_account: tuple) -> Finding:
    """One ERROR row for a check that raised out of construction, init, or execute.

    Metadata is read from ``check_class.meta`` rather than from an instance
    (Requirement 10.4). ``meta`` is a ``ClassVar`` set at import time by
    ``__init_subclass__``, so it is available even when construction is what
    failed -- which is the case this row exists to report.

    All sixteen fields come from a determinate source (10.3) and none is a
    literal placeholder: eight from ``meta``, ``status`` from the enum,
    ``region`` as ``GLOBAL_REGION``, ``resource_id`` as ``None``,
    ``checked_value`` derived from ``meta.service``, ``actual_value`` from the
    exception, ``remediation`` from ``meta.remediation.text``, and the account
    identity from the value resolved once for the scan. ``Severity`` is the
    check's real severity: the pre-change row carried the string ``"UNKNOWN"``,
    which was never a legal ``Severity`` value, and it carried no
    ``AccountName`` at all, so these rows were unattributable in a fan-out.

    ``remediation`` falls back to the *control's* remediation here, which
    ``SecurityCheck.error()`` deliberately refuses to do. The orchestrator has
    no better option -- it knows only that something broke, not what -- and a
    cell naming the control beats an empty one. The diagnostic signal is
    carried by ``actual_value``, which names the exception **type** as well as
    its message: "An error occurred" is useless in a report, whereas
    "ClientError: AccessDenied ..." is triage-able (10.3).

    Args:
        check_class: The class of the check that raised. Never an instance.
        exc: The exception that escaped construction, ``initialize``, or
            ``execute``.
        fallback_account: The ``(account_id, account_name)`` pair resolved once
            for the scan, both empty strings when identity was unresolvable.

    Returns:
        Exactly one ERROR ``Finding``.
    """
    m = check_class.meta
    account_id, account_name = fallback_account
    return Finding(
        check_id=m.check_id,
        status=Status.ERROR,
        region=GLOBAL_REGION,
        severity=m.severity,
        title=f"{m.check_id} {m.title}",
        description=m.description,
        resource_id=None,
        resource_type=m.resource_type,
        account_id=account_id,
        account_name=account_name,
        checked_value=f"{m.service} Configuration",
        actual_value=f"Error running {m.check_id}: {type(exc).__name__}: {exc}",
        remediation=m.remediation.text,
        service=m.service,
        check_logic=m.check_logic,
        account_type=m.account_type,
    )


class SRAVerify:
    """Main class for SRA Verify functionality."""

    def __init__(self, profile: Optional[str] = None, role_arn: Optional[str] = None,
                 regions: Optional[List[str]] = None, session: Optional[Session] = None,
                 connect_timeout: Optional[float] = None,
                 read_timeout: Optional[float] = None,
                 max_attempts: Optional[int] = None,
                 max_pool_connections: Optional[int] = None):
        """
        Initialize SRA Verify.

        Args:
            profile: AWS profile to use
            role_arn: ARN of IAM role to assume
            regions: List of AWS regions to check
            session: Existing AWS session to use (if provided)
            connect_timeout: Optional override for the boto3 connect timeout (seconds)
                applied to every client built during ``run_checks``. ``None``
                keeps the ``ScanContext`` default (10s).
            read_timeout: Optional override for the boto3 read timeout (seconds)
                applied to every client built during ``run_checks``. ``None``
                keeps the ``ScanContext`` default (30s).
            max_attempts: Optional override for the boto3 retry ``max_attempts``
                applied to every client built during ``run_checks``. ``None``
                keeps the ``ScanContext`` default (3).
            max_pool_connections: Optional override for the boto3
                ``max_pool_connections`` applied to every client built during
                ``run_checks``. ``None`` keeps the ``ScanContext`` default (50).

        Logging is not configured here. The ``sraverify`` logger carries only a
        ``NullHandler``, so the host application decides where records go and
        at what level; the CLI does that in ``sraverify.cli``.
        """
        self.regions = regions
        self.session = session if session else get_session(profile=profile, role_arn=role_arn)
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._max_attempts = max_attempts
        self._max_pool_connections = max_pool_connections
        self.progress = None

    def select_checks(self, account_type: str = 'all', service: Optional[str] = None,
                      check_id: Optional[str] = None) -> Dict[str, type[SecurityCheck]]:
        """
        Resolve scan filters to the checks to run. Instantiates nothing.

        Public so a caller can size or preview a scan before running it -- the
        CLI's banner reports ``len(select_checks(...))`` -- using exactly the
        selection ``run_checks`` will apply.

        Every filter reads ``cls.meta``, a validated class attribute, so
        selection constructs no check and issues no AWS API call. ``--check``
        narrows the intersection rather than replacing it: an ID that
        contradicts a supplied account type or service yields zero matches and
        reaches ``NoChecksSelectedError``.

        Args:
            account_type: Account type filter, or ``'all'`` for no filter.
            service: Service display name filter, matched in full and
                case-insensitively, or ``None`` for no filter.
            check_id: A single check ID, matched exactly and case-sensitively,
                or ``None`` for no filter.

        Returns:
            A non-empty mapping of check ID to check class.

        Raises:
            UnknownCheckError: ``check_id`` is absent from the registry. The
                error carries up to three near-miss registry keys.
            NoChecksSelectedError: The filter combination matched no check.
                The error carries all three filter values as supplied, with
                ``None`` marking a filter that was not supplied.
        """
        registry = all_checks()

        # --check NARROWS the set; it does not replace it. The account-type and
        # service filters below still apply to the single candidate.
        if check_id is not None:
            if check_id not in registry:
                raise UnknownCheckError(check_id, _near_misses(check_id, registry))
            candidates = {check_id: registry[check_id]}
        else:
            candidates = dict(registry)

        if account_type != 'all':
            # ``meta.account_type`` is a ``StrEnum`` member, so comparing it
            # against the plain CLI string is correct without ``.value``.
            candidates = {
                key: cls for key, cls in candidates.items()
                if cls.meta.account_type == account_type
            }

        if service is not None:
            # Full-value comparison, ASCII-lower-cased and therefore
            # locale-independent. ``str.lower()`` rather than ``casefold()``,
            # which folds characters outside A-Z and would let a lookalike
            # match one of the 18 ASCII display names. No prefix or substring
            # match: ``--service Security`` matches nothing. ``strip()``
            # applies to the supplied value only, since whitespace inside
            # ``meta.service`` is already impossible.
            wanted = service.strip().lower()
            candidates = {
                key: cls for key, cls in candidates.items()
                if cls.meta.service.lower() == wanted
            }

        if not candidates:
            raise NoChecksSelectedError(account_type, service, check_id)

        return candidates

    def get_available_checks(self, account_type: str = 'all') -> Dict[str, Dict[str, str]]:
        """
        Get all available checks, optionally filtered by account type.

        Reads ``cls.meta`` and constructs no check instance. Unlike
        ``select_checks``, an empty result is not an error here: listing the checks
        for an account type that has none is a legitimate inventory answer.

        Args:
            account_type: Type of accounts to list checks for ('application', 'audit', 'log-archive', 'management', or 'all')

        Returns:
            Dictionary mapping check IDs to check information
        """
        checks = {}
        for check_id, check_class in all_checks().items():
            meta = check_class.meta
            if account_type == 'all' or meta.account_type == account_type:
                checks[check_id] = {
                    'name': meta.title,
                    'service': meta.service,
                    'account_type': meta.account_type.value,
                    'description': meta.description,
                    'severity': meta.severity.value
                }
        return checks

    def get_available_services(self) -> List[str]:
        """
        Get all available services.

        Reads ``cls.meta`` and constructs no check instance.

        Returns:
            List of service names
        """
        return sorted({
            check_class.meta.service for check_class in all_checks().values()
        })

    def run_checks(self, account_type: str = 'all', service: Optional[str] = None,
                  check_id: Optional[str] = None, audit_accounts: Optional[List[str]] = None,
                  log_archive_accounts: Optional[List[str]] = None,
                  show_progress: bool = False) -> List[Finding]:
        """
        Run security checks.

        Args:
            account_type: Type of accounts to check ('application', 'audit', 'log-archive', 'management', or 'all')
            service: Run checks for a specific service
            check_id: Run a specific check
            audit_accounts: List of AWS accounts used for Audit/Security Tooling
            log_archive_accounts: List of AWS accounts used for Logging
            show_progress: Whether to show progress bar

        Returns:
            A concrete ``list`` of :class:`Finding`, never a generator, an
            iterator, a view, or any other lazy object (Requirement 10.7).
            See the note at the ``return`` below: a lazy return value would
            defer ``finally: del ctx`` until the caller finished consuming it,
            moving the client leak up one layer rather than removing it.

        Raises:
            UnknownCheckError: ``check_id`` names an ID absent from the
                registry.
            NoChecksSelectedError: The filter combination matched no check.
        """
        # Resolve the filters against the registered classes. This raises on a
        # mistyped check ID or an empty filter combination rather than
        # returning an empty list, so a usage error cannot masquerade as a
        # clean scan that found nothing.
        logger.debug(
            f"Selecting checks: account_type={account_type}, "
            f"service={service}, check_id={check_id}"
        )
        checks_to_run = self.select_checks(account_type, service, check_id)

        all_findings: List[Finding] = []

        # Group checks by service for better organization. Read from
        # ``cls.meta``; grouping constructs no instance.
        service_checks: Dict[str, List[Any]] = {}
        for selected_id, check_class in checks_to_run.items():
            service_name = check_class.meta.service
            service_checks.setdefault(service_name, []).append(
                (selected_id, check_class)
            )

        # Set up progress tracking if requested
        if show_progress:
            self.progress = ScanProgress(len(checks_to_run))

        # Construct the per-scan context. It owns the session, region list,
        # audit/log-archive account lists, the bounded ``Client_Config``, the
        # per-scan boto3 client cache, and every cached AWS API response. A
        # fresh context is built per ``run_checks`` call and dropped in the
        # ``finally`` below so its boto3 clients become collectible when the
        # call returns (Requirements 3.1, 3.3).
        ctx = ScanContext(
            session=self.session,
            regions=self.regions,
            audit_accounts=audit_accounts or [],
            log_archive_accounts=log_archive_accounts or [],
            connect_timeout=self._connect_timeout,
            read_timeout=self._read_timeout,
            max_attempts=self._max_attempts,
            max_pool_connections=self._max_pool_connections,
        )

        try:
            # Resolved once, before the loop, so every synthetic ERROR row is
            # attributable to an account. Served from the context's existing
            # cache, so the scan issues no additional AWS call (Requirement
            # 10.10). A failure here is not fatal (10.5): every real finding
            # would fail too, but the ERROR rows should still say which check
            # broke and in which account, so we log and carry empty strings.
            try:
                info = ctx.get_account_info()
                fallback_account = (info["account_id"], info["account_name"])
            except Exception as exc:
                logger.error(f"Could not resolve account identity: {exc}")
                fallback_account = ("", "")

            # Run checks by service
            for service_name, checks in service_checks.items():
                if self.progress:
                    self.progress.update(service_name)
                logger.debug(f"Running {len(checks)} checks for service {service_name}")

                for selected_id, check_class in checks:
                    # One guarded block per check, spanning construction,
                    # initialize, and consumption of execute() (Requirement
                    # 10.1). Construction is inside it because an
                    # abstractmethod violation, a metadata-property failure,
                    # or a rejected ``self.findings`` assignment raises there,
                    # and one broken check must cost one row rather than the
                    # scan.
                    #
                    # ``except Exception``, deliberately NOT
                    # ``except BaseException`` and not a bare ``except``
                    # (10.1). BaseException would catch KeyboardInterrupt and
                    # SystemExit, which are not check failures -- they are the
                    # operator or the runtime asking the process to stop.
                    # Catching them per check would turn a single Ctrl-C into
                    # one synthetic ERROR row per remaining check, producing a
                    # full-looking report from an aborted scan. Letting them
                    # propagate runs ``finally: del ctx`` on the way out (10.9).
                    try:
                        logger.debug(
                            f"Initializing check {selected_id}: "
                            f"{check_class.meta.title}"
                        )
                        check = check_class()
                        # Hand the shared context to the check. Audit and
                        # log-archive account lists flow through ``ctx`` rather
                        # than through direct mutation on the check instance
                        # (Requirement 3.4).
                        check.initialize(ctx)

                        logger.debug(f"Executing check {selected_id}")
                        # This ``list()`` is LOAD-BEARING. Do not "optimize" it
                        # into a lazy ``all_findings.extend(check.execute())``.
                        #
                        # ``execute()`` is a generator in the migrated
                        # catalog, and a generator captures its frame. That
                        # frame references the check instance, which holds
                        # ``self._ctx``. An unconsumed or partially consumed
                        # generator therefore keeps the whole ScanContext --
                        # and every boto3 client it has cached -- reachable
                        # past ``finally: del ctx``, silently defeating the
                        # per-scan isolation the long-running MCP server
                        # depends on. ``list()`` forces and drops the
                        # generator inside this loop iteration, so nothing
                        # survives the guarded block (10.6).
                        #
                        # It also preserves today's semantics exactly (10.8):
                        # a check that raises midway contributes ONE synthetic
                        # ERROR row and nothing else, because the rows it
                        # yielded before failing go with the discarded
                        # generator. Yielding the partial rows as well would
                        # arguably be more informative, and is a deliberate
                        # future decision rather than an oversight -- it is a
                        # behavior change to every check that can fail after
                        # its first yield. And ``len()`` on a generator is a
                        # TypeError, so the debug line below needs the list too.
                        findings = list(check.execute())
                        all_findings.extend(findings)
                        logger.debug(
                            f"Check {selected_id} completed with "
                            f"{len(findings)} findings"
                        )
                    except Exception as exc:
                        logger.error(
                            f"Error running check {selected_id}: {exc}",
                            exc_info=True,
                        )
                        try:
                            # Exactly one ERROR row for this check; every
                            # finding already collected is retained and the
                            # loop continues with the next check (10.2).
                            all_findings.append(
                                _synthetic_error(check_class, exc, fallback_account)
                            )
                        except Exception:
                            # Secondary failure (10.12): the ERROR row itself
                            # could not be built -- e.g. ``meta`` is absent
                            # because __init_subclass__ never completed. Log
                            # and move on, contributing no row. Without this
                            # nesting a failure inside error handling escapes
                            # the per-check guard and ends the scan, which is
                            # the exact failure mode the guard exists to
                            # remove, reintroduced one level in.
                            logger.error(
                                f"Could not build synthetic ERROR row for "
                                f"{selected_id}",
                                exc_info=True,
                            )

                    # Outside the ``except``, so a broken check advances the
                    # indicator exactly once, same as a healthy one (10.2).
                    if self.progress:
                        self.progress.increment()

            if self.progress:
                self.progress.finish()

            # A concrete list (10.7). The per-check ``list()`` above looks
            # like it has already solved the lifetime problem, and it has not:
            # were this a generator, or ``itertools.chain(...)``, or a ``map``,
            # ``finally: del ctx`` would not run until the *caller* finished
            # consuming the result, and the frame holding ``ctx`` would stay
            # alive until then -- the same leak, one layer up.
            return all_findings
        finally:
            # Drop the local reference so the ``ScanContext`` (and the boto3
            # clients it caches) become collectible as soon as ``run_checks``
            # returns. This is the mechanism that gives the long-running MCP
            # server per-scan isolation without an explicit cache-clear step.
            del ctx
