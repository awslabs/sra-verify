"""
Base class for Macie security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"macie"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

Cache keys are simple service-internal strings (e.g.
``"findings_publication:us-east-1"``) because the context is already per-scan and
per-account. The seven accessors share one implementation, :meth:`_cached_call`.

``macie2`` overloads ``AccessDeniedException`` across "Macie is disabled here" and
"you lack the permission", so :data:`NOT_CONFIGURED_ERRORS` declares it with a
message needle and keyed by operation. Checks call ``self.is_not_configured``;
nothing here judges a code.
"""
from typing import Any, ClassVar, Mapping, Optional

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.macie.client import MacieClient

#: Evidence for the overloaded ``AccessDeniedException``. Recorded once and shared
#: by the four operations that return it, because it is one observed fact about
#: ``macie2`` rather than four.
_MACIE_DISABLED_EVIDENCE = (
    "macie2 has no dedicated 'not enabled' error code. When Macie is disabled in "
    "a Region it answers AccessDeniedException with a message saying so, which is "
    "the same code returned when the caller merely lacks the IAM permission -- so "
    "the message is the only available discriminator and is declared here as a "
    "needle. Observed in the 2026-09-12 CodeBuild log as 'Macie is not enabled "
    "for this account' against accounts where Macie had not been enabled; "
    "https://docs.aws.amazon.com/macie/latest/APIReference/CommonErrors.html"
)

#: Evidence for ``ResourceNotFoundException``, which is unambiguous.
_MACIE_NOT_FOUND_EVIDENCE = (
    "https://docs.aws.amazon.com/macie/latest/APIReference/CommonErrors.html -- "
    "ResourceNotFoundException means the requested resource does not exist. For "
    "these operations the requested resource *is* the configuration under test, so "
    "its absence is the finding rather than an inability to determine it. This is "
    "the pair the bdad609 reference implementation already classified this way on "
    "GetClassificationExportConfiguration."
)


class MacieCheck(SecurityCheck):
    """Base class for all Macie security checks."""

    # All cached AWS-API responses for Macie are stored under this namespace on
    # the per-scan ``ScanContext``.
    NAMESPACE = "macie"

    #: The ``(operation, code)`` pairs that mean "the control is not configured"
    #: for Macie.
    #:
    #: Every entry is a ``macie2`` operation. The Organizations calls this service
    #: also makes -- ``ListDelegatedAdministrators``, ``ListAccounts`` -- are
    #: deliberately absent: their errors are Organizations errors and mean
    #: something different, and a table keyed only by code would have conflated
    #: them.
    #:
    #: ``AccessDeniedException`` carries a message needle on every entry because
    #: ``macie2`` overloads it. Without the needle this table would convert every
    #: permission denial in the member role into a fabricated FAIL -- which is the
    #: precise failure mode the evidence rule exists to prevent, and the reason
    #: ``NotConfigured.evidence`` is a required field.
    #:
    #: ``DescribeOrganizationConfiguration`` gets the needle too, and only for the
    #: "not enabled" message. The "must be the Macie administrator" condition is
    #: deliberately not declared: it means the scan was pointed at a
    #: non-administrator account, which is a fact about the scan, so it stays an
    #: ERROR.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "GetClassificationExportConfiguration": {
            "ResourceNotFoundException": NotConfigured(
                evidence=_MACIE_NOT_FOUND_EVIDENCE,
            ),
            "AccessDeniedException": NotConfigured(
                evidence=_MACIE_DISABLED_EVIDENCE,
                message="macie is not enabled",
            ),
        },
        "GetFindingsPublicationConfiguration": {
            "ResourceNotFoundException": NotConfigured(
                evidence=_MACIE_NOT_FOUND_EVIDENCE,
            ),
            "AccessDeniedException": NotConfigured(
                evidence=_MACIE_DISABLED_EVIDENCE,
                message="macie is not enabled",
            ),
        },
        "DescribeOrganizationConfiguration": {
            "ResourceNotFoundException": NotConfigured(
                evidence=_MACIE_NOT_FOUND_EVIDENCE,
            ),
            "AccessDeniedException": NotConfigured(
                evidence=_MACIE_DISABLED_EVIDENCE,
                message="macie is not enabled",
            ),
        },
        "GetAdministratorAccount": {
            "ResourceNotFoundException": NotConfigured(
                evidence=_MACIE_NOT_FOUND_EVIDENCE,
            ),
            "AccessDeniedException": NotConfigured(
                evidence=_MACIE_DISABLED_EVIDENCE,
                message="macie is not enabled",
            ),
        },
        "ListMembers": {
            "ResourceNotFoundException": NotConfigured(
                evidence=_MACIE_NOT_FOUND_EVIDENCE,
            ),
            "AccessDeniedException": NotConfigured(
                evidence=_MACIE_DISABLED_EVIDENCE,
                message="macie is not enabled",
            ),
        },
    }

    def _setup_clients(self):
        """Set up Macie clients for each region.

        Constructs one ``MacieClient`` wrapper per region in ``self.regions``.
        Each wrapper obtains its underlying boto3 ``macie2``, ``organizations``,
        and ``sts`` clients from ``self._ctx.get_client(...)``, so the per-scan
        ``Client_Config`` and per-scan boto3 client cache are applied.
        """
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = MacieClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[MacieClient]:
        """
        Get Macie client for a specific region.

        Args:
            region: AWS region name

        Returns:
            MacieClient for the region or None if not available
        """
        return self._clients.get(region)

    def _cached_call(
        self, region: str, cache_key: str, method: str, *args: Any
    ) -> Mapping[str, Any]:
        """
        Run one client method for a Region through the accessor shape.

        The seven public accessors below differ only in cache key and client
        method, so the shape is written once here. That is a deliberate contrast
        with the client tier, where the repetition is the point: a client's
        ``except`` clause is what a reader checks when they doubt an error is
        being preserved, whereas this sequence -- hit, no-client, call, error
        guard, store -- has one correct form and seven chances to get it subtly
        wrong.

        Args:
            region: AWS region name.
            cache_key: Key within the ``"macie"`` namespace.
            method: Name of the :class:`MacieClient` method to call.
            *args: Positional arguments for that method.

        Returns:
            The cached or freshly fetched response dict, or an error result.
        """
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Macie: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(f"Macie: No client available for region {region}")
            return no_client_result(service="Macie", region=region)

        logger.debug(f"Macie: Fetching {cache_key}")
        result = getattr(client, method)(*args)

        if is_error(result):
            # Never cached: a retry has to be able to re-issue the call. This is
            # the line that stops one denied Macie call from being replayed to
            # every later Macie check in the Region.
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    def get_findings_publication_configuration(
        self, region: str
    ) -> Mapping[str, Any]:
        """
        Get the findings publication configuration for Macie, with caching.

        Args:
            region: AWS region name

        Returns:
            The ``GetFindingsPublicationConfiguration`` response, or an error
            result.
        """
        return self._cached_call(
            region,
            f"findings_publication:{region}",
            "get_findings_publication_configuration",
        )

    def get_classification_export_configuration(
        self, region: str
    ) -> Mapping[str, Any]:
        """
        Get the classification export configuration for Macie, with caching.

        Args:
            region: AWS region name

        Returns:
            The ``GetClassificationExportConfiguration`` response, or an error
            result.
        """
        return self._cached_call(
            region,
            f"export_configuration:{region}",
            "get_classification_export_configuration",
        )

    def get_macie_delegated_admin(self, region: str) -> Mapping[str, Any]:
        """
        Get the Macie delegated administrator, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"DelegatedAdministrators": [...]}``, or an error result. The list
            is read by the check after the error test.
        """
        return self._cached_call(
            region, f"delegated_admin:{region}", "list_delegated_administrators"
        )

    def get_macie_members(self, region: str) -> Mapping[str, Any]:
        """
        Get Macie members, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"members": [...]}``, or an error result.
        """
        return self._cached_call(region, f"members:{region}", "list_members")

    def get_organization_members(self, region: str) -> Mapping[str, Any]:
        """
        Get AWS Organization accounts, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"Accounts": [...]}``, or an error result.
        """
        return self._cached_call(
            region, f"organization_members:{region}", "list_organization_accounts"
        )

    def get_organization_configuration(self, region: str) -> Mapping[str, Any]:
        """
        Get Macie organization configuration, with caching.

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

    def get_macie_administrator_account(self, region: str) -> Mapping[str, Any]:
        """
        Get the Macie administrator account, with caching.

        Keyed separately from :meth:`get_macie_delegated_admin`; the two are
        different facts about the organization.

        Args:
            region: AWS region name

        Returns:
            The ``GetAdministratorAccount`` response, or an error result.
        """
        return self._cached_call(
            region,
            f"administrator_account:{region}",
            "get_administrator_account",
        )
