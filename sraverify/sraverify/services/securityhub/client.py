"""
Security Hub client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

The "not subscribed to AWS Security Hub" condition travels as
``InvalidAccessException`` with its message intact, and
``SecurityHubCheck.NOT_CONFIGURED_ERRORS`` declares it with a message needle.

Pagination here is an explicit ``NextToken`` loop rather than a paginator.
"""
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext


class SecurityHubClient(AWSClient):
    """Client for interacting with AWS Security Hub service."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize Security Hub client for a specific region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan; the underlying boto3 clients
                are obtained via ``ctx.get_client(...)`` so the per-scan client
                cache and bounded ``Client_Config`` are applied.
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('securityhub', region=region)
        self.org_client = ctx.get_client('organizations', region=region)

    def get_enabled_standards(self) -> Mapping[str, Any]:
        """
        Get all enabled Security Hub standards.

        Returns:
            ``{"StandardsSubscriptions": [...]}`` with every page merged, on
            success, or the error result. "Not subscribed" is an
            ``InvalidAccessException`` whose message says so, declared in the
            discriminator table, and reaches the check like any other error.
        """
        try:
            response = self.client.get_enabled_standards()
            standards = list(response.get('StandardsSubscriptions', []))
            while response.get('NextToken'):
                response = self.client.get_enabled_standards(
                    NextToken=response['NextToken']
                )
                standards.extend(response.get('StandardsSubscriptions', []))
            logger.debug(
                f"SecurityHub: Found {len(standards)} enabled standards in "
                f"{self.region}"
            )
            return {"StandardsSubscriptions": standards}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_organization_admin_accounts(self) -> Mapping[str, Any]:
        """
        List Security Hub organization admin accounts.

        Returns:
            ``{"AdminAccounts": [...]}`` with every page merged, on success, or
            the error result.
        """
        try:
            response = self.client.list_organization_admin_accounts()
            admin_accounts = list(response.get('AdminAccounts', []))
            while response.get('NextToken'):
                response = self.client.list_organization_admin_accounts(
                    NextToken=response['NextToken']
                )
                admin_accounts.extend(response.get('AdminAccounts', []))
            logger.debug(
                f"SecurityHub: Found {len(admin_accounts)} organization admin "
                f"accounts in {self.region}"
            )
            return {"AdminAccounts": admin_accounts}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_administrator_account(self) -> Mapping[str, Any]:
        """
        Get the Security Hub administrator account.

        Returns:
            The ``GetAdministratorAccount`` response on success, or the error
            result.
        """
        try:
            return self.client.get_administrator_account()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_organization_configuration(self) -> Mapping[str, Any]:
        """
        Describe the Security Hub organization configuration.

        Returns:
            The ``DescribeOrganizationConfiguration`` response on success, or the
            error result.
        """
        try:
            return self.client.describe_organization_configuration()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_security_hub_v2(self) -> Mapping[str, Any]:
        """
        Describe the Security Hub V2 resource for this account and Region.

        Returns:
            The ``DescribeSecurityHubV2`` response on success -- ``HubV2Arn`` and
            ``SubscribedAt`` -- or the error result.

            An account without V2 answers ``ResourceNotFoundException: You are
            not subscribed to HubV2`` (observed 2026-09-16), which is a real
            answer and is declared in
            ``SecurityHubCheck.NOT_CONFIGURED_ERRORS``. V2 is independent of
            CSPM: the same probe found V2 enabled in a Region where CSPM was not
            subscribed.
        """
        try:
            return self.client.describe_security_hub_v2()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_finding_aggregators(self) -> Mapping[str, Any]:
        """
        List the finding aggregators visible from this Region.

        Returns:
            ``{"FindingAggregators": [...]}`` with every page merged, on success,
            or the error result.

            The aggregator ARN embeds the home Region, which is the only way to
            learn it without a second call: ``GetFindingAggregator`` needs the ARN
            this call returns. Callable from any subscribed Region, unlike the
            central-configuration operations.
        """
        try:
            aggregators = []
            next_token = None
            while True:
                params: dict[str, Any] = {}
                if next_token:
                    params['NextToken'] = next_token
                response = self.client.list_finding_aggregators(**params)
                aggregators.extend(response.get('FindingAggregators', []))
                next_token = response.get('NextToken')
                if not next_token:
                    break
            return {"FindingAggregators": aggregators}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_configuration_policies(self) -> Mapping[str, Any]:
        """
        List the Security Hub central configuration policies.

        Returns:
            ``{"ConfigurationPolicySummaries": [...]}`` with every page merged,
            on success, or the error result.

            Only the delegated administrator may call this, and only from the
            home Region. From elsewhere it answers ``AccessDeniedException``; the
            two messages differ ("Must be a Security Hub delegated administrator
            with Central Configuration enabled" versus "Central Configuration
            APIs can only be called from the aggregation region"), which is what
            lets the discriminator classify one and not the other.
        """
        try:
            summaries = []
            next_token = None
            while True:
                params: dict[str, Any] = {}
                if next_token:
                    params['NextToken'] = next_token
                response = self.client.list_configuration_policies(**params)
                summaries.extend(response.get('ConfigurationPolicySummaries', []))
                next_token = response.get('NextToken')
                if not next_token:
                    break
            return {"ConfigurationPolicySummaries": summaries}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_configuration_policy(self, identifier: str) -> Mapping[str, Any]:
        """
        Get one Security Hub configuration policy.

        Args:
            identifier: The configuration policy ARN or UUID.

        Returns:
            The ``GetConfigurationPolicy`` response on success, or the error
            result. The summary from ``ListConfigurationPolicies`` carries
            ``ServiceEnabled`` but not the enabled standards, so this second call
            is the only way to read ``EnabledStandardIdentifiers``.
        """
        try:
            return self.client.get_configuration_policy(Identifier=identifier)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_enabled_products_for_import(self) -> Mapping[str, Any]:
        """
        List enabled products for import into Security Hub.

        Returns:
            ``{"ProductSubscriptions": [...]}`` with every page merged, on
            success, or the error result.

            The second half of the ``None`` tri-state, resolved the same way as
            :meth:`get_enabled_standards`.
        """
        try:
            response = self.client.list_enabled_products_for_import()
            products = list(response.get('ProductSubscriptions', []))
            while response.get('NextToken'):
                response = self.client.list_enabled_products_for_import(
                    NextToken=response['NextToken']
                )
                products.extend(response.get('ProductSubscriptions', []))
            logger.debug(
                f"SecurityHub: Found {len(products)} enabled products in "
                f"{self.region}"
            )
            return {"ProductSubscriptions": products}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_delegated_administrators(
        self, service_principal: str = "securityhub.amazonaws.com"
    ) -> Mapping[str, Any]:
        """
        List Organizations delegated administrators for a service principal.

        Args:
            service_principal: Service principal to check for delegated
                administrators.

        Returns:
            ``{"DelegatedAdministrators": [...]}`` with every page merged, on
            success, or the error result.

            This reaches ``organizations``, not ``securityhub``, so its errors are
            Organizations errors and mean something different from Security Hub
            not being subscribed. That is why the discriminator table declares
            nothing for ``ListDelegatedAdministrators``.
        """
        try:
            response = self.org_client.list_delegated_administrators(
                ServicePrincipal=service_principal
            )
            delegated_admins = list(response.get('DelegatedAdministrators', []))
            while response.get('NextToken'):
                response = self.org_client.list_delegated_administrators(
                    ServicePrincipal=service_principal,
                    NextToken=response['NextToken'],
                )
                delegated_admins.extend(
                    response.get('DelegatedAdministrators', [])
                )
            logger.debug(
                f"SecurityHub: Found {len(delegated_admins)} delegated "
                f"administrators for {service_principal}"
            )
            return {"DelegatedAdministrators": delegated_admins}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_members(self) -> Mapping[str, Any]:
        """
        List Security Hub member accounts.

        Returns:
            ``{"Members": [...]}`` with every page merged, on success, or the
            error result.
        """
        try:
            response = self.client.list_members()
            members = list(response.get('Members', []))
            while response.get('NextToken'):
                response = self.client.list_members(
                    NextToken=response['NextToken']
                )
                members.extend(response.get('Members', []))
            logger.debug(
                f"SecurityHub: Found {len(members)} members in {self.region}"
            )
            return {"Members": members}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_organization_accounts(self) -> Mapping[str, Any]:
        """
        List all accounts in the AWS Organization.

        Returns:
            ``{"Accounts": [...]}`` with every page merged, on success, or the
            error result.
        """
        try:
            response = self.org_client.list_accounts()
            accounts = list(response.get('Accounts', []))
            while response.get('NextToken'):
                response = self.org_client.list_accounts(
                    NextToken=response['NextToken']
                )
                accounts.extend(response.get('Accounts', []))
            logger.debug(
                f"SecurityHub: Found {len(accounts)} organization accounts"
            )
            return {"Accounts": accounts}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
