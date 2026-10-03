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

#: The service principal the IAM delegated administrator is registered under,
#: for centralized root access management.
IAM_SERVICE_PRINCIPAL = "iam.amazonaws.com"


class IAMCheck(SecurityCheck):
    """Base class for all AWS IAM security checks.

    IAM is a global AWS service, so a single :class:`IAM_Client` is constructed
    per instance (no region) and findings always carry
    ``Region = "global"`` (``GLOBAL_REGION``). Cached AWS-API responses live on the per-scan
    :class:`ScanContext` under the ``"iam"`` namespace, keyed by
    ``account_id``, which avoids duplicate ``ListUsers`` API calls when
    multiple IAM checks run in the same SRA Verify invocation.
    """

    # All cached AWS-API responses for IAM are stored under this namespace
    # on the per-scan ``ScanContext``.
    NAMESPACE = "iam"

    #: The ``(operation, code)`` pairs that mean "the control is not configured".
    #:
    #: ``ListUsers`` and ``GetAccountSummary`` declare nothing: no IAM users is a
    #: successful empty list, and the summary documents only ``ServiceFailure``.
    #:
    #: ``ListOrganizationsFeatures`` declares only what has been observed:
    #: ``ServiceAccessNotEnabledException`` (IAM trusted access off), which leaves
    #: centralized root access unavailable and so is the control being absent.
    #: ``AccountNotManagementOrDelegatedAdministratorException`` is deliberately
    #: absent: it means the scan ran from the wrong account, not that root access
    #: management is off. ``OrganizationNotFoundException`` and
    #: ``OrganizationNotInAllFeaturesModeException`` are documented but have not
    #: been observed, and the wire spelling of this operation's codes differs
    #: from the API reference (it carries an ``Exception`` suffix), so they are
    #: left undeclared and read as an honest ERROR.
    #:
    #: The Organizations operations this base's accessors reach
    #: (``ListDelegatedAdministrators``, ``DescribeOrganization``) are classified
    #: by ``OrganizationsProvider.NOT_CONFIGURED_ERRORS``, not here. The provider
    #: declares ``DescribeOrganization`` / ``AWSOrganizationsNotInUseException``,
    #: so ``is_not_configured`` answers ``True`` for it; SRA-IAM-05 still yields
    #: ERROR on that branch because it has no FAIL arm there (moved-verdict
    #: ledger row "stays ERROR").
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "ListOrganizationsFeatures": {
            "ServiceAccessNotEnabledException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/IAM/latest/APIReference/"
                    "API_ListOrganizationsFeatures.html -- ServiceAccessNotEnabled, "
                    "trusted access for IAM is not enabled. Observed 2026-09-29 from "
                    "the test-org management account after disable-aws-service-access "
                    "for iam.amazonaws.com: 'Trusted Access for IAM not enabled by "
                    "organization of input account <account-id>.'"
                ),
            ),
        },
        "GetAccountPasswordPolicy": {
            "NoSuchEntity": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/IAM/latest/APIReference/"
                    "API_GetAccountPasswordPolicy.html -- NoSuchEntity. Observed "
                    "2026-09-29 in three test-org accounts with no custom policy: "
                    "'The Password Policy with domain name <account-id> cannot be "
                    "found.'"
                ),
            ),
        },
    }

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

    def _cached_call(self, thing: str, client_method: str) -> Dict[str, Any]:
        """
        Issue one no-argument client call, caching a success per account.

        Args:
            thing: The cache-key prefix; the key is ``f"{thing}:{account_id}"``.
            client_method: The :class:`IAM_Client` method to call on a miss.

        Returns:
            The client's success dict, or its error result unchanged (never
            cached), or a ``NoClient`` result when no client was built.
        """
        cache_key = f"{thing}:{self.account_id}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"IAM: Using cached {thing} response")
            return self._ctx._get(self.NAMESPACE, cache_key)

        if self._iam_client is None:
            logger.warning("IAM: No client available")
            return no_client_result(service="IAM", region="global")

        logger.debug(f"IAM: Fetching {thing} response")
        response = getattr(self._iam_client, client_method)()
        if is_error(response):
            # Never cached: a retry has to be able to re-issue the call.
            return response

        self._ctx._set(self.NAMESPACE, cache_key, response)
        return response

    def get_organizations_features(self) -> Dict[str, Any]:
        """
        Get the centralized root access features enabled for the organization.

        Returns:
            ``{"EnabledFeatures": [...], "OrganizationId": ...}`` on success, or
            an error result.
        """
        return self._cached_call("organizations_features", "list_organizations_features")

    def get_account_summary(self) -> Dict[str, Any]:
        """
        Get the IAM account summary for the current account.

        Returns:
            ``{"SummaryMap": {...}}`` on success, or an error result.
        """
        return self._cached_call("account_summary", "get_account_summary")

    def get_account_password_policy(self) -> Dict[str, Any]:
        """
        Get the account's custom IAM password policy.

        Returns:
            ``{"PasswordPolicy": {...}}`` on success, or an error result.
        """
        return self._cached_call("password_policy", "get_account_password_policy")

    def get_iam_delegated_administrators(self) -> Dict[str, Any]:
        """
        Get the delegated administrators registered for ``iam.amazonaws.com``.

        Delegates to the scan's Organizations provider, which caches the answer
        once per scan per service principal.

        Returns:
            ``{"DelegatedAdministrators": [...]}`` on success, or an error result.
        """
        return self.organization.delegated_administrators(IAM_SERVICE_PRINCIPAL)

    def get_organization(self) -> Dict[str, Any]:
        """
        Describe the organization the current account belongs to.

        Delegates to ``self.organization.describe()``, the scan's one cached
        ``DescribeOrganization`` answer.

        Returns:
            ``{"Organization": {...}}`` on success, or an error result.
        """
        return self.organization.describe()

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
