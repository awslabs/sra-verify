"""
Base class for Inspector security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"inspector"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

Reshaping happens **after** the error test, in pure helpers over a success dict:
:meth:`account_status_of` flattens ``resourceState`` up to the top level and
:meth:`status_by_account` builds an ``{account_id: status}`` map. Neither is ever
handed an accessor's raw return, so an accessor's result has exactly two shapes
and ``"Error" in result`` is the only test that separates them.

:meth:`batch_get_account_status` issues one call per batch of 10 accounts and
**fails as a whole** if any batch fails. A partial map is indistinguishable from
a complete one, and an account missing from it would read as "not enrolled".

:meth:`caller_is_delegated_admin` handles a third category of error, neither
transport nor not-configured; see its docstring.
"""
from typing import Any, ClassVar, Dict, List, Mapping, Optional

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.inspector.client import InspectorClient


class InspectorCheck(SecurityCheck):
    """Base class for all Inspector security checks."""

    NAMESPACE = "inspector"

    #: The ``(operation, code)`` pairs that mean "the control is not configured"
    #: for Inspector.
    #:
    #: ``ResourceNotFoundException`` from ``GetDelegatedAdminAccount`` is the only
    #: entry: Inspector answers it when no delegated administrator has been
    #: designated, which is the control being absent. Nothing is declared for
    #: ``BatchGetAccountStatus`` -- an account with Inspector switched off is a
    #: *successful* response carrying ``status: DISABLED``, not an error, so a
    #: failure there is always an inability to determine.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "GetDelegatedAdminAccount": {
            "ResourceNotFoundException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/inspector/v2/APIReference/"
                    "API_GetDelegatedAdminAccount.html -- "
                    "ResourceNotFoundException is returned when the requested "
                    "resource does not exist, and the requested resource here is "
                    "the delegated administrator designation itself. Nothing is "
                    "declared for BatchGetAccountStatus on purpose: Inspector "
                    "being disabled for an account is a successful response with "
                    "state.status == DISABLED, so any error from that call is an "
                    "inability to determine rather than a finding."
                ),
            ),
        },
    }

    def _setup_clients(self):
        """Set up Inspector clients for each region.

        Each wrapper obtains its underlying boto3 ``inspector2`` and
        ``organizations`` clients from ``self._ctx.get_client(...)``.
        """
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = InspectorClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[InspectorClient]:
        """
        Get Inspector client for a specific region.

        Args:
            region: AWS region name

        Returns:
            InspectorClient for the region or None if not available
        """
        return self._clients.get(region)

    def _cached_call(
        self, region: str, cache_key: str, method: str, *args: Any
    ) -> Mapping[str, Any]:
        """
        Run one client method for a Region through the accessor shape.

        Args:
            region: AWS region name.
            cache_key: Key within the ``"inspector"`` namespace.
            method: Name of the :class:`InspectorClient` method to call.
            *args: Positional arguments for that method.

        Returns:
            The cached or freshly fetched response dict, or an error result.
        """
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Inspector: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(f"Inspector: No client available for region {region}")
            return no_client_result(service="Inspector", region=region)

        logger.debug(f"Inspector: Fetching {cache_key}")
        result = getattr(client, method)(*args)

        if is_error(result):
            # Never cached: a retry has to be able to re-issue the call.
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    # ----------------------------------------------------------------- #
    # Pure helpers over a success dict, never over an accessor's raw return
    # ----------------------------------------------------------------- #

    @staticmethod
    def caller_is_delegated_admin(error: Mapping[str, str]) -> bool:
        """
        Whether this error means "you are the delegated administrator".

        ``inspector2:GetDelegatedAdminAccount`` refuses to answer when the calling
        account *is* the delegated administrator, with
        ``ValidationException: Invoking account is the delegated admin.`` That is
        not a failure and it is not "not configured" -- it is the answer, stated as
        a refusal. So it belongs in neither the transport path nor
        :data:`NOT_CONFIGURED_ERRORS`: declaring it as "not configured" would turn
        a correctly-configured organization into a FAIL, which is the opposite of
        the truth.

        A check that sees this should read the delegated administrator as its own
        account and carry on. ``SRA-INSPECTOR-07`` is the one that does.

        Args:
            error: An error result's ``Error`` sub-dict.

        Returns:
            ``True`` for exactly that ``(operation, code, message)`` combination.
        """
        return (
            error.get("Operation") == "GetDelegatedAdminAccount"
            and error.get("Code") == "ValidationException"
            and "invoking account is the delegated admin"
            in error.get("Message", "").lower()
        )

    @staticmethod
    def account_status_of(
        response: Mapping[str, Any], account_id: str
    ) -> Dict[str, Any]:
        """
        Flatten one account's entry out of a ``BatchGetAccountStatus`` response.

        Call only after ``"Error" in response`` is False.

        Args:
            response: A successful :meth:`get_account_status` response.
            account_id: The account whose entry to read.

        Returns:
            ``{"accountId", "state", "ec2", "ecr", "lambda", "lambdaCode"}``, or
            ``{}`` when the response carries no entry for that account. Here
            ``{}`` means exactly one thing -- AWS answered and this account is not
            in the result -- because a failure could not have reached this far.
        """
        for status in response.get('accounts', []):
            if status.get('accountId') != account_id:
                continue
            resource_state = status.get('resourceState', {})
            return {
                'accountId': status.get('accountId'),
                'state': status.get('state', {}),
                'ec2': resource_state.get('ec2', {}),
                'ecr': resource_state.get('ecr', {}),
                'lambda': resource_state.get('lambda', {}),
                'lambdaCode': resource_state.get('lambdaCode', {}),
            }
        return {}

    @staticmethod
    def status_by_account(response: Mapping[str, Any]) -> Dict[str, Dict]:
        """
        Index a ``BatchGetAccountStatus`` response by account ID.

        Call only after ``"Error" in response`` is False.

        Args:
            response: A successful :meth:`batch_get_account_status` response.

        Returns:
            ``{account_id: account_entry}``. Complete by construction, because a
            partial batch is now an error result rather than a short map.
        """
        return {
            account['accountId']: account
            for account in response.get('accounts', [])
            if account.get('accountId')
        }

    # ----------------------------------------------------------------- #
    # Accessors
    # ----------------------------------------------------------------- #

    def get_account_status(self, region: str) -> Mapping[str, Any]:
        """
        Get the Inspector account status for the scanned account, with caching.

        Args:
            region: AWS region name

        Returns:
            The ``BatchGetAccountStatus`` response, or an error result. Use
            :meth:`account_status_of` to read this account's entry after the
            error test.
        """
        return self._cached_call(
            region,
            f"account_status:{self.account_id}:{region}",
            "batch_get_account_status",
            [self.account_id],
        )

    def get_delegated_admin(self, region: str) -> Mapping[str, Any]:
        """
        Get the Inspector delegated administrator, with caching.

        Args:
            region: AWS region name

        Returns:
            The ``GetDelegatedAdminAccount`` response, or an error result.
        """
        return self._cached_call(
            region, f"delegated_admin:{region}", "get_delegated_admin_account"
        )

    def get_organization_members(self, region: str) -> Mapping[str, Any]:
        """
        Get accounts in the AWS Organization, with caching.

        The cache key carries no Region because the answer is organization-wide,
        which is the pre-existing behaviour and is correct.

        Args:
            region: AWS region name, used only to select a client.

        Returns:
            ``{"Accounts": [...]}``, or an error result. First page only; see
            ``InspectorClient.list_organization_accounts``.
        """
        return self._cached_call(
            region, "organization_members", "list_organization_accounts"
        )

    def batch_get_account_status(
        self, region: str, account_ids: List[str]
    ) -> Mapping[str, Any]:
        """
        Get the Inspector status for many accounts, with caching.

        ``BatchGetAccountStatus`` accepts at most 10 accounts, so this issues one
        call per batch of 10 and merges the ``accounts`` members.

        **A failing batch fails the whole call**, rather than being skipped. A
        partial map is indistinguishable from a complete one, and an account
        missing from it would read as "not enrolled".

        Args:
            region: AWS region name
            account_ids: Account IDs to query.

        Returns:
            ``{"accounts": [...]}`` merged across batches, or the first batch's
            error result. Use :meth:`status_by_account` to index it after the
            error test.
        """
        cache_key = f"batch_status:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Inspector: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(f"Inspector: No client available for region {region}")
            return no_client_result(service="Inspector", region=region)

        # One batch is the common case, and its response is cached **by identity**:
        # the accessor contract is that a check receives the client's response
        # dict unchanged, so a single-batch call must not rebuild it.
        responses: List[Mapping[str, Any]] = []
        for start in range(0, len(account_ids), 10):
            batch = account_ids[start:start + 10]
            response = client.batch_get_account_status(batch)
            if is_error(response):
                # Not cached, and not partially returned: a short map is
                # indistinguishable from a complete one.
                return response
            responses.append(response)

        if len(responses) == 1:
            result: Mapping[str, Any] = responses[0]
        else:
            accounts: List[Dict[str, Any]] = []
            for response in responses:
                accounts.extend(response.get('accounts', []))
            result = {"accounts": accounts}
        self._ctx._set(self.NAMESPACE, cache_key, result)
        logger.debug(
            f"Inspector: cached batch status for "
            f"{len(result.get('accounts', []))} accounts in {region}"
        )
        return result

    def get_organization_configuration(self, region: str) -> Mapping[str, Any]:
        """
        Get the Inspector organization configuration, with caching.

        Args:
            region: AWS region name

        Returns:
            The ``DescribeOrganizationConfiguration`` response, or an error
            result.
        """
        return self._cached_call(
            region,
            f"organization_configuration:{region}",
            "describe_organization_configuration",
        )
