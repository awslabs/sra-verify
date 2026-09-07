"""
Base class for Account security checks.

Migrated to the per-scan :class:`ScanContext` model in task 8.11 of the
scan-context-refactor spec: the previously class-level ``_contact_cache``
dict has been removed and cached alternate-contact responses now live in
the ``"account"`` namespace on the attached ``ScanContext``
(Requirements 5.11, 5.18).
"""
from typing import Any, Dict

from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.account.client import AccountClient


class AccountCheck(SecurityCheck):
    """Base class for all Account security checks."""

    #: Namespace used for all ``ctx._get`` / ``ctx._set`` / ``ctx._has``
    #: calls made from this base class. Matches Requirement 5.11.
    NAMESPACE = "account"

    def __init__(self):
        """Initialize Account base check."""
        super().__init__(
            account_type="application",
            service="Account",
            resource_type="AWS::Account::AlternateContact"
        )

    def _setup_clients(self):
        """Set up Account client wrappers for each region.

        Each :class:`AccountClient` obtains its underlying boto3 ``account``
        client through ``ctx.get_client(...)`` so the bounded
        ``Client_Config`` is applied and the same boto3 client instance is
        shared across all wrappers in this scan.
        """
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = AccountClient(region, ctx=self._ctx)

    def get_alternate_contact(self, region: str, contact_type: str, account_id: str = None) -> Dict[str, Any]:
        """
        Get alternate contact information with caching.

        The result is cached for the lifetime of the current scan in the
        ``"account"`` namespace on the attached :class:`ScanContext`. The
        cache key is keyed on the calling account, the region, the contact
        type, and the optional target account ID so each unique
        ``(account, region, type, target)`` combination is fetched at most
        once per scan.

        Args:
            region: AWS region name
            contact_type: Type of contact (BILLING, OPERATIONS, or SECURITY)
            account_id: Optional target account ID

        Returns:
            Dictionary containing contact details or empty dict if not available
        """
        cache_key = f"contact:{self.account_id}:{region}:{contact_type}:{account_id or ''}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Account: Using cached {contact_type} contact for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"Account: No Account client available for region {region}")
            return {}

        contact_info = client.get_alternate_contact(contact_type, account_id)
        self._ctx._set(self.NAMESPACE, cache_key, contact_info)
        logger.debug(f"Account: Cached {contact_type} contact for {region}")

        return contact_info
