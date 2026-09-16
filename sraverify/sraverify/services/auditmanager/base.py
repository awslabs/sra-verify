"""
Base class for Audit Manager security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"auditmanager"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

:data:`AuditManagerCheck.NOT_CONFIGURED_ERRORS` is empty, and the comment on it
says why: the one candidate code has not been observed against a not-yet-set-up
account, and an undeclared code resolves to an honest ERROR.
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

    #: Empty, and deliberately so, pending confirmation.
    #:
    #: ``GetOrganizationAdminAccount`` answers ``AccessDeniedException`` both for a
    #: genuine permission failure and -- reportedly -- with a "Please complete AWS
    #: Audit Manager setup" message when the account has not been set up. The
    #: second has never been observed against such an account, so it is not
    #: declared: an undeclared code yields an honest ERROR, whereas declaring it
    #: unconfirmed would risk fabricating a FAIL.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}

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
