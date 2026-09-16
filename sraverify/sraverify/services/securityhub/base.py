"""
Base class for Security Hub security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"securityhub"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

Cache keys are scoped to the typed method that wrote them (e.g.
``"enabled_standards:{region}"``), so :meth:`get_administrator_account` and
:meth:`get_organization_admin_accounts` cannot collide. The eight accessors share
one implementation, :meth:`_cached_call`.

:meth:`get_organization` deliberately reads and writes the **shared**
``"organizations"`` namespace under the key ``"organization"``, the same shape
``OrganizationsCheck.get_organization`` uses, so either service populates it for
the other and one scan issues ``DescribeOrganization`` once.
"""
from typing import Any, ClassVar, Mapping, Optional

from sraverify.core.aws_client import AWS_EXCEPTIONS
from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    error_result,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.securityhub.client import SecurityHubClient

#: Evidence for the overloaded ``InvalidAccessException``.
_NOT_SUBSCRIBED_EVIDENCE = (
    "securityhub returns InvalidAccessException both when the account is not "
    "subscribed to Security Hub in the Region -- the control is genuinely absent "
    "-- and for other access problems, so the code alone cannot classify it. The "
    "message 'not subscribed to AWS Security Hub' separates them and is declared "
    "here as a needle. Observed in the 2026-09-12 CodeBuild log; the pair was "
    "already special-cased by hand in SecurityHubClient.get_enabled_standards "
    "and list_enabled_products_for_import before this migration, which is where "
    "the message string comes from. "
    "https://docs.aws.amazon.com/securityhub/1.0/APIReference/CommonErrors.html"
)


class SecurityHubCheck(SecurityCheck):
    """Base class for all SecurityHub security checks."""

    NAMESPACE = "securityhub"

    #: The ``(operation, code)`` pairs that mean "the control is not configured"
    #: for Security Hub.
    #:
    #: One code, six operations, and a message needle on every entry, because
    #: ``InvalidAccessException`` is overloaded. Without the needle this table
    #: would turn every Security Hub permission denial into a fabricated FAIL.
    #:
    #: The two Organizations operations this service also calls --
    #: ``ListDelegatedAdministrators`` and ``ListAccounts`` -- are deliberately
    #: absent. Their errors are Organizations errors: an
    #: ``AWSOrganizationsNotInUseException`` there means no organization exists,
    #: which is a different fact from Security Hub not being subscribed, and a
    #: table keyed only by code could not have told them apart.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "GetEnabledStandards": {
            "InvalidAccessException": NotConfigured(
                evidence=_NOT_SUBSCRIBED_EVIDENCE,
                message="not subscribed to aws security hub",
            ),
        },
        "ListEnabledProductsForImport": {
            "InvalidAccessException": NotConfigured(
                evidence=_NOT_SUBSCRIBED_EVIDENCE,
                message="not subscribed to aws security hub",
            ),
        },
        "GetAdministratorAccount": {
            "InvalidAccessException": NotConfigured(
                evidence=_NOT_SUBSCRIBED_EVIDENCE,
                message="not subscribed to aws security hub",
            ),
        },
        "DescribeOrganizationConfiguration": {
            "InvalidAccessException": NotConfigured(
                evidence=_NOT_SUBSCRIBED_EVIDENCE,
                message="not subscribed to aws security hub",
            ),
        },
        "ListMembers": {
            "InvalidAccessException": NotConfigured(
                evidence=_NOT_SUBSCRIBED_EVIDENCE,
                message="not subscribed to aws security hub",
            ),
            # This entry is why SRA-SECURITYHUB-09 FAILs rather than PASSes in
            # a Region where Security Hub is not enabled: "no member accounts
            # found" is only a pass when the question could be asked.
            "BadRequestException": NotConfigured(
                evidence=(
                    "securityhub:ListMembers answers BadRequestException 'The "
                    "request is rejected since no such resource found.' when no "
                    "hub exists in the Region -- the missing resource is the hub "
                    "itself, so the control is absent rather than undetermined. "
                    "Verified directly on 2026-09-15 in a controlled account: "
                    "DescribeHub returns InvalidAccessException in us-east-2 and "
                    "us-west-1 and succeeds in us-east-1 and us-west-2, and "
                    "ListMembers returns exactly this BadRequestException in the "
                    "same two Regions and succeeds in the other two. The needle is "
                    "required because securityhub also returns BadRequestException "
                    "for an invalid or out-of-range input parameter, which is a "
                    "defect in the caller and must stay an ERROR. "
                    "https://docs.aws.amazon.com/securityhub/1.0/APIReference/"
                    "CommonErrors.html"
                ),
                message="no such resource found",
            ),
        },
        "ListOrganizationAdminAccounts": {
            "InvalidAccessException": NotConfigured(
                evidence=_NOT_SUBSCRIBED_EVIDENCE,
                message="not subscribed to aws security hub",
            ),
        },
    }

    # The shared cross-service cache slot for organizations:DescribeOrganization.
    _ORGANIZATIONS_NAMESPACE = "organizations"
    _ORGANIZATION_CACHE_KEY = "organization"

    def _setup_clients(self):
        """Set up SecurityHub clients for each region.

        Constructs one ``SecurityHubClient`` wrapper per region in
        ``self.regions``. Each wrapper obtains its underlying boto3
        ``securityhub`` and ``organizations`` clients from
        ``self._ctx.get_client(...)``, so the per-scan ``Client_Config`` and
        per-scan boto3 client cache are applied.
        """
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = SecurityHubClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[SecurityHubClient]:
        """
        Get SecurityHub client for a specific region.

        Args:
            region: AWS region name

        Returns:
            SecurityHubClient for the region or None if not available
        """
        return self._clients.get(region)

    def _cached_call(
        self, region: str, cache_key: str, method: str, *args: Any
    ) -> Mapping[str, Any]:
        """
        Run one client method for a Region through the accessor shape.

        The eight public accessors below differ only in cache key and client
        method, so the shape is written once.

        Args:
            region: AWS region name.
            cache_key: Key within the ``"securityhub"`` namespace.
            method: Name of the :class:`SecurityHubClient` method to call.
            *args: Positional arguments for that method.

        Returns:
            The cached or freshly fetched response dict, or an error result.
        """
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"SecurityHub: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(
                f"SecurityHub: No client available for region {region}"
            )
            return no_client_result(service="SecurityHub", region=region)

        logger.debug(f"SecurityHub: Fetching {cache_key}")
        result = getattr(client, method)(*args)

        if is_error(result):
            # Never cached: a retry has to be able to re-issue the call.
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    def get_enabled_standards(self, region: str) -> Mapping[str, Any]:
        """
        Get enabled Security Hub standards for a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"StandardsSubscriptions": [...]}`` on success, or an error result.
            "Security Hub is not subscribed here" arrives as an
            ``InvalidAccessException`` that ``self.is_not_configured(error)``
            recognizes, which distinguishes it from a denied permission.
        """
        return self._cached_call(
            region, f"enabled_standards:{region}", "get_enabled_standards"
        )

    def get_administrator_account(self, region: str) -> Mapping[str, Any]:
        """
        Get the Security Hub administrator account, with caching.

        Args:
            region: AWS region name

        Returns:
            The ``GetAdministratorAccount`` response, or an error result.
        """
        return self._cached_call(
            region, f"administrator_account:{region}", "get_administrator_account"
        )

    def get_organization_configuration(self, region: str) -> Mapping[str, Any]:
        """
        Get the Security Hub organization configuration, with caching.

        Args:
            region: AWS region name

        Returns:
            The ``DescribeOrganizationConfiguration`` response, or an error result.
        """
        return self._cached_call(
            region,
            f"organization_configuration:{region}",
            "describe_organization_configuration",
        )

    def get_enabled_products_for_import(self, region: str) -> Mapping[str, Any]:
        """
        Get enabled product integrations for a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"ProductSubscriptions": [...]}`` on success, or an error result.
        """
        return self._cached_call(
            region,
            f"product_integrations:{region}",
            "list_enabled_products_for_import",
        )

    def get_delegated_administrators(self, region: str) -> Mapping[str, Any]:
        """
        Get the Organizations delegated administrators for Security Hub, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"DelegatedAdministrators": [...]}`` on success, or an error result.
        """
        return self._cached_call(
            region, f"delegated_admin:{region}", "list_delegated_administrators"
        )

    def get_organization_admin_accounts(self, region: str) -> Mapping[str, Any]:
        """
        Get the Security Hub organization admin accounts, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"AdminAccounts": [...]}`` on success, or an error result.
        """
        return self._cached_call(
            region,
            f"organization_admin_accounts:{region}",
            "list_organization_admin_accounts",
        )

    def get_organization_accounts(self, region: str) -> Mapping[str, Any]:
        """
        Get every account in the AWS Organization, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"Accounts": [...]}`` on success, or an error result.
        """
        return self._cached_call(
            region, f"organization_accounts:{region}", "list_organization_accounts"
        )

    def get_security_hub_members(self, region: str) -> Mapping[str, Any]:
        """
        Get Security Hub member accounts, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"Members": [...]}`` on success, or an error result.
        """
        return self._cached_call(
            region, f"securityhub_members:{region}", "list_members"
        )

    def get_organization(self) -> Mapping[str, Any]:
        """Return the AWS Organizations ``DescribeOrganization`` response.

        Reads from and writes to the ``"organizations"`` namespace under the key
        ``"organization"`` -- the same shape
        :meth:`sraverify.services.organizations.base.OrganizationsCheck.get_organization`
        uses -- so a later ``OrganizationsCheck`` call in the same scan picks up
        the value without re-issuing ``organizations:DescribeOrganization``, and
        vice-versa.

        This is the one accessor here that issues its own boto3 call rather than
        going through :class:`SecurityHubClient`, because the response belongs to
        another service and ``SecurityHubClient`` has no method for it. A failure
        is emphatically **not** cached: the namespace is shared, so a cached error
        would be replayed to every later Organizations check as well as every
        later Security Hub one.

        Organizations is a global service, so the client is pinned to
        ``us-east-1`` to match ``OrganizationsClient`` and populate the shared
        slot with a value from the same boto3 instance.

        Returns:
            The ``DescribeOrganization`` response, or an error result.
        """
        if self._ctx._has(
            self._ORGANIZATIONS_NAMESPACE, self._ORGANIZATION_CACHE_KEY
        ):
            logger.debug(
                "SecurityHub: Using cached organization details from "
                "'organizations' namespace"
            )
            return self._ctx._get(
                self._ORGANIZATIONS_NAMESPACE, self._ORGANIZATION_CACHE_KEY
            )

        logger.debug(
            "SecurityHub: Fetching organization details and writing to "
            "shared 'organizations' namespace"
        )
        org_client = self._ctx.get_client('organizations', region='us-east-1')
        try:
            response = org_client.describe_organization()
        except AWS_EXCEPTIONS as e:
            code = getattr(e, "response", {}).get("Error", {}).get(
                "Code"
            ) or type(e).__name__
            message = getattr(e, "response", {}).get("Error", {}).get(
                "Message"
            ) or str(e)
            logger.error(
                f"aws_call_failed operation=DescribeOrganization "
                f"region={self.regions[0] if self.regions else 'global'} "
                f"code={code} message={message!r}"
            )
            # Not cached: the shared namespace makes a cached failure reachable
            # from two services.
            return error_result(
                code=code, message=message, operation="DescribeOrganization"
            )

        self._ctx._set(
            self._ORGANIZATIONS_NAMESPACE, self._ORGANIZATION_CACHE_KEY, response
        )
        logger.debug(
            "SecurityHub: Cached organization details under shared "
            "'organizations' namespace"
        )
        return response
