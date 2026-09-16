"""
Macie client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

``macie2`` overloads ``AccessDeniedException``: it is returned both when Macie is
**disabled** in a Region -- the control is genuinely absent -- and when the caller
lacks the API permission, where the control simply could not be evaluated. Only
the message separates them, and that judgement lives in
``MacieCheck.NOT_CONFIGURED_ERRORS``, keyed by ``(operation, code)`` with a
message needle. It is never made here: this tier does not have the operation
context the decision needs.
"""
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class MacieClient(AWSClient):
    """Client for interacting with AWS Macie service."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize Macie client for a specific region.

        Every boto3 client is acquired here rather than inside a method.
        ``ctx.get_client`` is offline and deterministic, so it cannot fail in a
        way that belongs in an error result; acquiring inside a method would put
        a construction defect inside the ``try`` and convert it into a plausible
        AWS failure.

        Args:
            region: AWS region name
            ctx: ScanContext that owns the per-scan boto3 session, the bounded
                ``Client_Config``, and the ``(service, region)`` client cache.
                Underlying boto3 clients are obtained via ``ctx.get_client(...)``
                so they are de-duplicated and share the bounded timeout/retry
                settings (see Requirement 2.12).
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('macie2', region=region)
        self.org_client = ctx.get_client('organizations', region=region)
        # Global service; the wrapper's Region does not apply.
        self.sts_client = ctx.get_client('sts')

    def get_findings_publication_configuration(self) -> Mapping[str, Any]:
        """
        Get the findings publication configuration for Macie.

        Returns:
            The ``GetFindingsPublicationConfiguration`` response on success, or
            the error result.
        """
        try:
            return self.client.get_findings_publication_configuration()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_classification_export_configuration(self) -> Mapping[str, Any]:
        """
        Get the classification export configuration for Macie.

        Returns:
            The ``GetClassificationExportConfiguration`` response on success, or
            the error result.

            One of the two reference implementations from ``bdad609``. It already
            preserved the code and message; what it lacked was ``Operation``,
            without which ``is_error`` rejects the value and
            ``is_not_configured`` has nothing to key on.
        """
        try:
            return self.client.get_classification_export_configuration()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_delegated_administrators(
        self, service_principal: str = "macie.amazonaws.com"
    ) -> Mapping[str, Any]:
        """
        List Organizations delegated administrators for a service principal.

        Args:
            service_principal: Service principal to check for delegated
                administrators.

        Returns:
            ``{"DelegatedAdministrators": [...]}`` on success, or the error
            result.

            Note this reaches ``organizations``, not ``macie2``, so its errors are
            Organizations errors -- ``AWSOrganizationsNotInUseException`` here
            means no organization exists, which is a different fact from Macie
            being disabled.
        """
        try:
            return self.org_client.list_delegated_administrators(
                ServicePrincipal=service_principal
            )
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_members(self) -> Mapping[str, Any]:
        """
        List Macie members.

        Returns:
            ``{"members": [...]}`` with every page merged, on success, or the
            error result.

            Lowercase ``members`` is the ``macie2`` response member name; the
            key is the AWS one and is not normalized.
        """
        try:
            members: list[Any] = []
            for page in self.client.get_paginator('list_members').paginate():
                members.extend(page.get('members', []))
            return {"members": members}
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
            accounts: list[Any] = []
            for page in self.org_client.get_paginator('list_accounts').paginate():
                accounts.extend(page.get('Accounts', []))
            return {"Accounts": accounts}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_organization_configuration(self) -> Mapping[str, Any]:
        """
        Describe the Macie organization configuration.

        Returns:
            The ``DescribeOrganizationConfiguration`` response on success, or the
            error result.

            An ``AccessDeniedException`` whose message says "must be the Macie
            administrator" is **not** declared in the discriminator table: that
            sentence is returned both when Macie is disabled and when Macie is
            enabled but delegated to another account, so it cannot establish
            either on its own. The two checks that read this operation call
            ``GetAdministratorAccount`` first, whose "Macie is not enabled"
            message *is* declared, and classify from that.
        """
        try:
            return self.client.describe_organization_configuration()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_account_id(self) -> Mapping[str, Any]:
        """
        Get the current account ID.

        Returns:
            The ``GetCallerIdentity`` response on success, i.e.
            ``{"Account": ..., "Arn": ..., "UserId": ...}``, or the error result.
            The caller reads ``["Account"]`` after the error test.
        """
        try:
            return self.sts_client.get_caller_identity()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_administrator_account(self) -> Mapping[str, Any]:
        """
        Get the Macie administrator account.

        Returns:
            The ``GetAdministratorAccount`` response on success, or the error
            result.

            ``ResourceNotFoundException`` and ``AccessDeniedException`` with a
            "Macie is not enabled" message both mean the control is absent and
            are declared in ``MacieCheck.NOT_CONFIGURED_ERRORS``. A bare
            ``AccessDeniedException`` with any other message is a permission
            failure and stays an ERROR.
        """
        try:
            return self.client.get_administrator_account()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
