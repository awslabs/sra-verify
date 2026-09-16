"""
Base class for Audit Manager security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"auditmanager"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

:data:`AuditManagerCheck.NOT_CONFIGURED_ERRORS` declares one pair, and it is the
only entry in the tree that *requires* its message needle to be correct rather
than merely more precise: ``GetOrganizationAdminAccount`` returns
``AccessDeniedException`` both for an account that has not completed Audit Manager
setup and for a caller that lacks the permission.
"""
from typing import ClassVar, Dict, Any
from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.services.auditmanager.client import AuditManagerClient


class AuditManagerCheck(SecurityCheck):
    """Base class for all Audit Manager security checks."""

    #: Namespace string used for ``ScanContext`` cache reads/writes
    #: (Requirement 5.12).
    NAMESPACE = "auditmanager"

    #: The one pair that means "the control is not configured".
    #:
    #: ``GetOrganizationAdminAccount`` answers ``AccessDeniedException`` for two
    #: unrelated conditions, so the **message needle is mandatory**: an account
    #: that has not completed Audit Manager setup, which is the control being
    #: absent, and a genuine permission failure, which is an inability to
    #: determine. Without the needle every denied call in the organization would
    #: become a fabricated finding.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "GetOrganizationAdminAccount": {
            "AccessDeniedException": NotConfigured(
                message="Please complete AWS Audit Manager setup",
                evidence=(
                    "Observed 2026-09-16 in a controlled management account with "
                    "Audit Manager not set up: aws_call_failed "
                    "operation=GetOrganizationAdminAccount "
                    "code=AccessDeniedException message=\"Please complete AWS "
                    "Audit Manager setup from home page to enable this action in "
                    "this account.\" The message states the condition outright -- "
                    "setup has not been completed -- which is what "
                    "SRA-AUDITMANAGER-02 asks about, so it is the control being "
                    "absent and not a permission problem."
                ),
            ),
        },
    }

    def _setup_clients(self):
        """Set up Audit Manager clients for each region.

        The underlying boto3 ``auditmanager`` clients are obtained via
        ``self._ctx.get_client(...)`` inside :class:`AuditManagerClient`,
        so they share the bounded ``Client_Config`` and de-duplicate
        across service base classes that need an Audit Manager client in
        the same region.
        """
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = AuditManagerClient(region, ctx=self._ctx)

    def get_account_status(self, region: str) -> Dict[str, Any]:
        """
        Get account status for a specific region with caching.

        Reads from / writes to the ``ScanContext``'s ``"auditmanager"``
        namespace, so the cache is per-scan rather than process-wide.

        Args:
            region: AWS region name

        Returns:
            Account status response or error information
        """
        cache_key = f"account_status:{self.account_id}:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            return no_client_result(service="Audit Manager", region=region)

        status = client.get_account_status()
        if is_error(status):
            # Never cached: a retry has to be able to re-issue the call.
            return status

        self._ctx._set(self.NAMESPACE, cache_key, status)
        return status

    def get_organization_admin_account(self, region: str) -> Dict[str, Any]:
        """
        Get organization admin account for a specific region with caching.

        Reads from / writes to the ``ScanContext``'s ``"auditmanager"``
        namespace, so the cache is per-scan rather than process-wide.

        Args:
            region: AWS region name

        Returns:
            Organization admin account response or error information
        """
        cache_key = f"org_admin:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            return no_client_result(service="Audit Manager", region=region)

        admin_info = client.get_organization_admin_account()
        if is_error(admin_info):
            # Never cached: a retry has to be able to re-issue the call.
            return admin_info

        self._ctx._set(self.NAMESPACE, cache_key, admin_info)
        return admin_info
