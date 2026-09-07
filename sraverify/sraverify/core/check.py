"""
Base class for security checks.

This module hosts ``SecurityCheck``, the abstract base every concrete service
check inherits from. Per-scan state (the boto3 ``Session``, the region list,
audit/log-archive account lists, and account info) lives on a
:class:`ScanContext` rather than on the check instance itself.
``SecurityCheck`` exposes that state through read-only properties that
delegate to ``self._ctx`` so individual check classes never have to know
they are reading from a context object.

``SecurityCheck.initialize`` accepts a single :class:`ScanContext`
argument. The deprecated 2-argument ``(session, regions=None)`` shim that
existed during the scan-context-refactor migration has been removed; every
internal caller now goes through ``initialize(ctx)``.

The public ``create_finding`` and ``execute`` interfaces are unchanged so
the finding format produced by every concrete check is preserved exactly.
"""
from typing import Any, Dict, List, Optional

import boto3

from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext


class SecurityCheck:
    """Base class for all security checks.

    Per-scan state is owned by an attached :class:`ScanContext`; this class
    exposes that state through read-only properties (``session``, ``regions``,
    ``account_info``, ``account_id``, ``account_name``, ``audit_accounts``,
    ``log_archive_accounts``) that delegate to ``self._ctx``. Direct
    assignment to any of those properties raises ``AttributeError``, which
    enforces Requirement 3.4 (the orchestrator must not mutate per-scan
    state on the check instance directly).

    Subclasses keep ``self._clients`` for their per-region service-level
    client wrappers; the underlying boto3 clients held by those wrappers
    come from ``ctx.get_client(...)`` so the bounded ``Client_Config``
    is applied uniformly.
    """

    def __init__(self, account_type="application", service=None, resource_type=None):
        """
        Initialize security check metadata.

        Per-scan state (session, regions, account info, audit/log-archive
        accounts) is intentionally not set here; it is attached later by
        :meth:`initialize`, which is called by ``SRAVerify.run_checks``
        once per scan.

        Args:
            account_type: Type of account (application, audit, log-archive, management)
            service: AWS service name
            resource_type: AWS resource type for findings
        """
        self.account_type = account_type
        self.service = service
        self.resource_type = resource_type
        self.check_id = None
        self.check_name = None
        self.description = None
        self.rationale = None
        self.remediation = None
        self.severity = "Unknown"
        self.check_logic = None
        self.findings: List[Dict[str, Any]] = []

        # Per-scan state container. Populated by :meth:`initialize` at the
        # start of each scan and dropped along with the rest of the scan
        # state when the scan finishes.
        self._ctx: Optional[ScanContext] = None

        # Per-scan service-level client wrappers (e.g., ``GuardDutyClient``
        # instances keyed by region). Service base classes populate this in
        # their ``_setup_clients`` override; the underlying boto3 clients
        # are obtained from ``ctx.get_client(...)`` so they pick up the
        # bounded ``Client_Config``.
        self._clients: Dict[str, Any] = {}

    def initialize(self, ctx: ScanContext) -> None:
        """
        Attach per-scan state to this check and set up service clients.

        ``ctx`` is the :class:`ScanContext` for the current scan. This is
        the path used by ``SRAVerify.run_checks``; there is no longer a
        ``(session, regions)`` shim.

        Args:
            ctx: The :class:`ScanContext` owning the boto3 session, region
                list, account-ID lists, bounded ``Client_Config``, and the
                per-scan client + response caches.
        """
        logger.debug(f"Initializing {self.__class__.__name__} check")

        self._ctx = ctx

        # Defer to subclass for per-region client wrapper construction.
        # Service base classes obtain their underlying boto3 clients from
        # ``self._ctx.get_client(...)`` so the bounded ``Client_Config``
        # is applied.
        self._setup_clients()

    def _setup_clients(self):
        """
        Set up service-level client wrappers for each region.

        Service base classes override this to populate ``self._clients``
        with their per-region wrapper objects, e.g.,
        ``self._clients[region] = GuardDutyClient(region, ctx=self._ctx)``.
        """
        raise NotImplementedError("Subclasses must implement _setup_clients method")

    def get_client(self, region: str) -> Optional[Any]:
        """
        Get the service-level client wrapper for a specific region.

        Args:
            region: AWS region name.

        Returns:
            The service-level wrapper for the region, or ``None`` if the
            subclass did not register one for that region.
        """
        return self._clients.get(region)

    def create_finding(
        self,
        status: str,
        region: str,
        resource_id: str,
        actual_value: str,
        remediation: str,
        checked_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a standardized finding.

        The key set produced here is the public finding format and is
        preserved exactly by Requirement 8.3.

        Args:
            status: Check status (PASS/FAIL/ERROR).
            region: AWS region.
            resource_id: Resource identifier.
            actual_value: Actual value found.
            remediation: Remediation steps.
            checked_value: Value that was checked (defaults to
                ``"<service> Configuration"``).

        Returns:
            Finding dictionary.

        Note:
            ``account_id`` and ``account_name`` are populated from the
            attached ``ScanContext`` via the read-only properties.
        """
        if checked_value is None:
            checked_value = f"{self.service} Configuration"

        return {
            "CheckId": self.check_id,
            "Status": status,
            "Region": region,
            "Severity": self.severity,
            "Title": f"{self.check_id} {self.check_name}",
            "Description": self.description,
            "ResourceId": resource_id,
            "ResourceType": self.resource_type,
            "AccountId": self.account_id,
            "AccountName": self.account_name,
            "CheckedValue": checked_value,
            "ActualValue": actual_value,
            "Remediation": remediation,
            "Service": self.service,
            "CheckLogic": self.check_logic,
            "AccountType": self.account_type,
        }

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check. Must be implemented by subclasses.

        Returns:
            List of findings.
        """
        raise NotImplementedError("Subclasses must implement execute method")

    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Get findings from the check.

        Returns:
            List of findings.
        """
        return self.findings

    # ------------------------------------------------------------------ #
    # Read-only properties that delegate to the attached ScanContext.
    #
    # All of these have no setter, so direct assignment (e.g.
    # ``check.audit_accounts = [...]``) raises ``AttributeError``. This
    # enforces Requirement 3.4: the orchestrator MUST NOT mutate per-scan
    # state on the check instance; account lists flow exclusively through
    # the ``ScanContext``.
    # ------------------------------------------------------------------ #

    @property
    def session(self) -> boto3.Session:
        """The boto3 ``Session`` for the current scan, from ``self._ctx``."""
        return self._ctx.session

    @property
    def regions(self) -> List[str]:
        """The region list for the current scan.

        When the ``ScanContext`` was constructed with an explicit non-empty
        region list, that list is returned. Otherwise enabled regions are
        lazily resolved via ``ctx.get_enabled_regions()`` (one EC2
        ``DescribeRegions`` call per scan, cached for the rest of the scan)
        which mirrors the pre-refactor ``_get_enabled_regions`` behavior.
        """
        ctx_regions = self._ctx.regions
        if ctx_regions:
            return ctx_regions
        return self._ctx.get_enabled_regions()

    @property
    def account_info(self) -> Dict[str, str]:
        """The ``{"account_id", "account_name"}`` dict for the current scan."""
        return self._ctx.get_account_info()

    @property
    def account_id(self) -> str:
        """The current AWS account ID, sourced from the ``ScanContext``."""
        return self.account_info["account_id"]

    @property
    def account_name(self) -> str:
        """The current AWS account name, sourced from the ``ScanContext``."""
        return self.account_info["account_name"]

    @property
    def audit_accounts(self) -> List[str]:
        """Audit account IDs for the current scan; ``[]`` when none supplied.

        Read-only: assignment raises ``AttributeError`` so account lists
        cannot be mutated on the check instance directly. They flow
        exclusively through the ``ScanContext``.
        """
        return self._ctx.audit_accounts

    @property
    def log_archive_accounts(self) -> List[str]:
        """Log-archive account IDs for the current scan; ``[]`` when none supplied.

        Read-only: assignment raises ``AttributeError`` so account lists
        cannot be mutated on the check instance directly. They flow
        exclusively through the ``ScanContext``.
        """
        return self._ctx.log_archive_accounts

    def get_management_accountId(self, session: Optional[boto3.Session] = None) -> str:
        """
        Get the AWS Organizations management account ID for the current scan.

        Delegates to ``self._ctx.get_management_account_id()``, which issues
        ``organizations:DescribeOrganization`` once per scan and caches the
        result. The ``session`` parameter is preserved for backward
        compatibility with the pre-refactor signature but is ignored; the
        attached ``ScanContext`` owns the session.

        Args:
            session: Ignored. Kept for backward compatibility.

        Returns:
            AWS account ID of the organization's management account.
        """
        if session is not None:
            logger.debug(
                "SecurityCheck.get_management_accountId received an explicit "
                "session argument; this is ignored now that the ScanContext "
                "owns the session."
            )
        return self._ctx.get_management_account_id()
