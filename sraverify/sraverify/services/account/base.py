"""
Base class for Account security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"account"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.
"""
from typing import ClassVar, Any, Dict

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.account.client import AccountClient


class AccountCheck(SecurityCheck):
    """Base class for all Account security checks."""

    #: Namespace used for all ``ctx._get`` / ``ctx._set`` / ``ctx._has``
    #: calls made from this base class. Matches Requirement 5.11.
    NAMESPACE = "account"

    #: The one pair that means "the control is not configured" for Account.
    #:
    #: ``ResourceNotFoundException`` from ``GetAlternateContact`` means no
    #: alternate contact of that type is set, which is precisely what the three
    #: Account checks test for.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "GetAlternateContact": {
            "ResourceNotFoundException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/accounts/latest/reference/"
                    "API_GetAlternateContact.html -- returned when the specified "
                    "alternate contact does not exist for the account. The "
                    "requested resource *is* the contact the check asks about, so "
                    "its absence is the finding."
                ),
            ),
        },
    }

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
            return no_client_result(service="Account", region=region)

        contact_info = client.get_alternate_contact(contact_type, account_id)
        if is_error(contact_info):
            # Never cached: a retry has to be able to re-issue the call.
            return contact_info

        self._ctx._set(self.NAMESPACE, cache_key, contact_info)
        logger.debug(f"Account: Cached {contact_type} contact for {region}")

        return contact_info
