"""
Base class for Audit Manager security checks.

As of the scan-context-refactor (task 8.12), per-scan cached AWS responses
live on the attached :class:`~sraverify.core.scan_context.ScanContext` under
the ``"auditmanager"`` namespace. The previous class-level
``_account_status_cache`` dict has been removed; reads and writes go
through ``self._ctx._has`` / ``self._ctx._get`` / ``self._ctx._set``,
which keeps the cache scoped to a single ``run_checks`` invocation and
makes it eligible for garbage collection when the scan ends.
"""
from typing import Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.auditmanager.client import AuditManagerClient


class AuditManagerCheck(SecurityCheck):
    """Base class for all Audit Manager security checks."""

    #: Namespace string used for ``ScanContext`` cache reads/writes
    #: (Requirement 5.12).
    NAMESPACE = "auditmanager"

    def __init__(self):
        """Initialize Audit Manager base check."""
        super().__init__(
            account_type="application",
            service="AuditManager",
            resource_type="AWS::AuditManager::Account"
        )

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
            return {"Error": {"Code": "NoClient", "Message": f"No client available for region {region}"}}

        status = client.get_account_status()
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
            return {"Error": {"Code": "NoClient", "Message": f"No client available for region {region}"}}

        admin_info = client.get_organization_admin_account()
        self._ctx._set(self.NAMESPACE, cache_key, admin_info)
        return admin_info
