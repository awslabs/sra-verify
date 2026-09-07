"""
Base class for AWS IAM security checks.

As of the scan-context-refactor (task 8.16), IAM's previously class-level
``_users_cache`` has been replaced with calls to the per-scan
:class:`ScanContext` namespaced primitives under the ``"iam"`` namespace.
Cache keys are scoped by ``account_id`` (e.g., ``"users:111111111111"``)
because the per-scan context is per-session but a single SRA Verify run can
in principle span account boundaries via assumed-role sessions.
"""
from typing import Any, Dict, Optional

from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.iam.client import IAM_Client


class IAMCheck(SecurityCheck):
    """Base class for all AWS IAM security checks.

    IAM is a global AWS service, so a single :class:`IAM_Client` is constructed
    per instance (no region) and findings always carry
    ``Region = "us-east-1"``. Cached AWS-API responses live on the per-scan
    :class:`ScanContext` under the ``"iam"`` namespace, keyed by
    ``account_id``, which avoids duplicate ``ListUsers`` API calls when
    multiple IAM checks run in the same SRA Verify invocation.
    """

    # All cached AWS-API responses for IAM are stored under this namespace
    # on the per-scan ``ScanContext``.
    NAMESPACE = "iam"

    # IAM is a global service; all API calls target this endpoint and every
    # finding produced by an IAM check reports this region.
    GLOBAL_REGION: str = "us-east-1"

    def __init__(self):
        """Initialize the IAM base check with SRA-standard metadata."""
        super().__init__(
            account_type="application",
            service="IAM",
            resource_type="AWS::IAM::User",
        )
        self._iam_client: Optional[IAM_Client] = None

    def _setup_clients(self):
        """Set up the IAM client (global service, no per-region clients).

        The underlying boto3 IAM client held by :class:`IAM_Client` is obtained
        from ``self._ctx.get_client('iam', region=None)`` so it is shared
        across every IAM caller in the scan via the per-scan client cache.
        """
        # IAM is a global service: one client constructed without a region.
        self._iam_client = IAM_Client(ctx=self._ctx)
        # Clear the inherited per-region clients dict since IAM does not use it
        # (mirrors the pattern used by OrganizationsCheck).
        self._clients.clear()

    def get_iam_client(self) -> IAM_Client:
        """
        Get the IAM client.

        Returns:
            The :class:`IAM_Client` instance constructed in :meth:`_setup_clients`.
        """
        return self._iam_client

    def list_users(self) -> Dict[str, Any]:
        """
        List IAM users for the current account with caching.

        Looks up ``f"users:{self.account_id}"`` in the ``"iam"`` namespace on
        the attached :class:`ScanContext` first and returns the cached
        response on hit. On miss, delegates to :meth:`IAM_Client.list_users`,
        caches the response (success or error), and returns it.

        Returns:
            Dictionary with a ``Users`` key (success) or an ``Error`` key
            (failure), matching the shape returned by :class:`IAM_Client`.
        """
        cache_key = f"users:{self.account_id}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug("IAM: Using cached list_users response")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug("IAM: Fetching list_users response")
        response = self._iam_client.list_users()

        # Cache both success and error responses so repeated failures don't
        # cascade into additional API calls within the same run.
        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug("IAM: Cached list_users response")

        return response

    def _validate_metadata(self):
        """
        Validate that required metadata attributes are populated.

        Raises:
            ValueError: If ``check_name``, ``description``, or ``check_logic``
                is ``None`` or an empty string. The error message identifies
                the missing attribute and the offending subclass.
        """
        for attr_name in ("check_name", "description", "check_logic"):
            value = getattr(self, attr_name, None)
            if value is None or value == "":
                raise ValueError(
                    f"{attr_name} is missing or empty on {self.__class__.__name__}"
                )
