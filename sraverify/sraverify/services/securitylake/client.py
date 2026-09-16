"""
Security Lake client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

``get_delegated_admin`` and ``is_security_lake_enabled`` return whole responses
rather than an extracted value or a ``bool``. A ``bool`` in particular has nowhere
to carry an error, so the base class answers the predicate *after* the error test.

No method here catches a typed ``self.client.exceptions.*`` code. Classifying a
code is the check's decision, against ``SecurityLakeCheck.NOT_CONFIGURED_ERRORS``.
"""
from typing import Any, Mapping, Optional

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext


class SecurityLakeClient(AWSClient):
    """Client for interacting with AWS Security Lake service."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize Security Lake client for a specific region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan; the underlying boto3 clients
                are obtained via ``ctx.get_client(...)`` so the per-scan client
                cache and bounded ``Client_Config`` are applied.
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('securitylake', region=region)
        self.org_client = ctx.get_client('organizations', region=region)
        # Moved out of get_sqs_queue_encryption, which acquired it per call
        # (Requirement 1.11).
        self.sqs_client = ctx.get_client('sqs', region=region)

    def is_security_lake_enabled(self) -> Mapping[str, Any]:
        """
        Return the ``ListDataLakes`` response, from which enablement is read.

        Returns:
            ``{"dataLakes": [...]}`` on success, or the error result. The name is
            historical -- eleven checks and four base helpers reach it -- but it
            answers a response, not a ``bool``, because a ``bool`` has nowhere to
            carry an error. ``SecurityLakeCheck`` answers the bool after testing
            for ``"Error"``.
        """
        try:
            return self.client.list_data_lakes()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_organization_configuration(self) -> Mapping[str, Any]:
        """
        Get the Security Lake organization configuration.

        Returns:
            The ``GetDataLakeOrganizationConfiguration`` response on success, or
            the error result.
        """
        try:
            return self.client.get_data_lake_organization_configuration()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_data_lakes(self) -> Mapping[str, Any]:
        """
        List the Security Lake data lakes.

        Returns:
            ``{"dataLakes": [...]}`` on success, or the error result. The whole
            response, not the extracted list.
        """
        try:
            return self.client.list_data_lakes()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_log_sources(
        self, regions: Optional[list] = None, accounts: Optional[list] = None
    ) -> Mapping[str, Any]:
        """
        List enabled log sources, with pagination.

        Args:
            regions: Regions to filter by.
            accounts: Account IDs to filter by.

        Returns:
            ``{"sources": [...]}`` with every page merged, on success, or the
            error result.
        """
        try:
            params: dict[str, Any] = {}
            if regions:
                params['regions'] = regions
            if accounts:
                params['accounts'] = accounts

            response = self.client.list_log_sources(**params)
            sources = list(response.get("sources", []))
            while response.get('nextToken'):
                params['nextToken'] = response['nextToken']
                response = self.client.list_log_sources(**params)
                sources.extend(response.get("sources", []))
            return {"sources": sources}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_subscribers(self) -> Mapping[str, Any]:
        """
        List Security Lake subscribers, with pagination.

        Returns:
            ``{"subscribers": [...]}`` with every page merged, on success, or the
            error result. An empty ``subscribers`` list is a real answer and stays
            distinguishable from a denied ``ListSubscribers``, which is what
            ``SRA-SECURITYLAKE-16``/``-17`` depend on.
        """
        try:
            response = self.client.list_subscribers()
            subscribers = list(response.get("subscribers", []))
            while response.get('nextToken'):
                response = self.client.list_subscribers(
                    nextToken=response['nextToken']
                )
                subscribers.extend(response.get("subscribers", []))
            return {"subscribers": subscribers}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_delegated_admin(self) -> Mapping[str, Any]:
        """
        Get the Organizations delegated administrator for Security Lake.

        Returns:
            ``{"DelegatedAdministrators": [...]}`` on success, or the error
            result. The caller reads element ``[0]`` after the error test.
        """
        try:
            return self.org_client.list_delegated_administrators(
                ServicePrincipal="securitylake.amazonaws.com"
            )
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_delegated_administrators(
        self, service_principal: str = "securitylake.amazonaws.com"
    ) -> Mapping[str, Any]:
        """
        List Organizations delegated administrators for a service principal.

        Args:
            service_principal: Service principal to check.

        Returns:
            ``{"DelegatedAdministrators": [...]}`` on success, or the error
            result.
        """
        try:
            return self.org_client.list_delegated_administrators(
                ServicePrincipal=service_principal
            )
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_sqs_queue_encryption(self, queue_url: str) -> Mapping[str, Any]:
        """
        Get the SQS queue attributes that carry its encryption setting.

        Args:
            queue_url: The queue URL.

        Returns:
            The ``GetQueueAttributes`` response on success, i.e.
            ``{"Attributes": {...}}``, or the error result. The caller reads
            ``Attributes.KmsMasterKeyId`` after the error test.
        """
        try:
            return self.sqs_client.get_queue_attributes(
                QueueUrl=queue_url, AttributeNames=["KmsMasterKeyId"]
            )
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_organization_accounts(self) -> Mapping[str, Any]:
        """
        List all accounts in the AWS Organization, with pagination.

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
            return {"Accounts": accounts}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_data_lake_sources(
        self, account_id: Optional[str] = None
    ) -> Mapping[str, Any]:
        """
        Get data lake sources, optionally for one account.

        Args:
            account_id: An account ID to filter by. A ``dict`` carrying an ``Id``
                member is also accepted, for the caller that passes an
                Organizations account record straight through.

        Returns:
            ``{"dataLakeSources": [...]}`` on success, or the error result.
        """
        request_body: dict[str, Any] = {}
        if account_id:
            if isinstance(account_id, dict):
                # Left in place: one caller passes an Organizations account record.
                # Note this branch is *outside* the try, because a dict with no
                # 'Id' is a programming defect in the caller, not an AWS outcome.
                if 'Id' not in account_id:
                    raise KeyError(
                        f"get_data_lake_sources: account_id dict has no 'Id': "
                        f"{account_id!r}"
                    )
                account_id = account_id['Id']
            request_body["accounts"] = [account_id]

        try:
            return self.client.get_data_lake_sources(**request_body)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
