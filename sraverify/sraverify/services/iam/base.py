"""
Base class for AWS IAM security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"iam"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

Cache keys here are scoped by ``account_id`` (e.g. ``"users:111111111111"``),
unlike every other service. The per-scan context is per-session, but a single run
can in principle span account boundaries via an assumed-role session.
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

    #: Empty, deliberately. An account with no IAM users is a **successful**
    #: ``ListUsers`` returning an empty list, not an error, so every error from
    #: this operation is an inability to determine.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}

    # IAM is a global service; all API calls target this endpoint and every
    # finding produced by an IAM check reports this region.
    GLOBAL_REGION: str = "us-east-1"

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
        if self._iam_client is None:
            logger.warning("IAM: No client available")
            return no_client_result(service="IAM", region="global")

        response = self._iam_client.list_users()

        # Cache both success and error responses so repeated failures don't
        # cascade into additional API calls within the same run.
        if is_error(response):
            # Never cached: a retry has to be able to re-issue the call.
            return response

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
