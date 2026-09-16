"""
Config client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

Reaches four services -- ``config``, ``organizations``, ``s3`` and ``sts`` -- all
acquired in ``__init__``.

``get_bucket_location`` returns the raw response. The ``None``
``LocationConstraint`` -> ``us-east-1`` mapping the API implies lives in
``ConfigCheck.bucket_region_of`` instead, so a failed call cannot be mistaken for
a bucket that really is in us-east-1.
"""
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class ConfigClient(AWSClient):
    """Client for interacting with AWS Config."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize Config client for a specific region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan; the underlying boto3 clients
                are obtained via ``ctx.get_client(...)`` so the per-scan client
                cache and bounded ``Client_Config`` are applied.
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('config', region=region)
        self.org_client = ctx.get_client('organizations', region=region)
        self.s3_client = ctx.get_client('s3', region=region)
        # Moved out of get_account_id, which acquired it per call.
        self.sts_client = ctx.get_client('sts')

    def get_account_id(self) -> Mapping[str, Any]:
        """
        Get the current account ID.

        Returns:
            The ``GetCallerIdentity`` response on success, or the error result.
        """
        try:
            return self.sts_client.get_caller_identity()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_management_account_id(self) -> Mapping[str, Any]:
        """
        Get the organization's management account.

        Returns:
            The ``DescribeOrganization`` response on success, i.e.
            ``{"Organization": {...}}``, or the error result.

            ``AWSOrganizationsNotInUseException`` means no organization exists,
            which is a real answer and is declared in
            ``ConfigCheck.NOT_CONFIGURED_ERRORS``.
        """
        try:
            return self.org_client.describe_organization()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_configuration_recorders(self) -> Mapping[str, Any]:
        """
        Describe the configuration recorders in this Region.

        Returns:
            ``{"ConfigurationRecorders": [...]}`` on success, or the error result.
        """
        try:
            return self.client.describe_configuration_recorders()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_configuration_recorder_status(self) -> Mapping[str, Any]:
        """
        Describe the configuration recorder status in this Region.

        Returns:
            ``{"ConfigurationRecordersStatus": [...]}`` on success, or the error
            result.
        """
        try:
            return self.client.describe_configuration_recorder_status()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_delivery_channels(self) -> Mapping[str, Any]:
        """
        Describe the delivery channels in this Region.

        Returns:
            ``{"DeliveryChannels": [...]}`` on success, or the error result.
        """
        try:
            return self.client.describe_delivery_channels()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_delivery_channel_status(self) -> Mapping[str, Any]:
        """
        Describe the delivery channel status in this Region.

        Returns:
            ``{"DeliveryChannelsStatus": [...]}`` on success, or the error result.
        """
        try:
            return self.client.describe_delivery_channel_status()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_configuration_aggregators(self) -> Mapping[str, Any]:
        """
        Describe the configuration aggregators in this Region.

        Returns:
            ``{"ConfigurationAggregators": [...]}`` on success, or the error
            result.
        """
        try:
            return self.client.describe_configuration_aggregators()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_configuration_aggregator_sources_status(
        self, aggregator_name: str
    ) -> Mapping[str, Any]:
        """
        Describe an aggregator's source statuses.

        Args:
            aggregator_name: The aggregator name.

        Returns:
            ``{"AggregatedSourceStatusList": [...]}`` on success, or the error
            result.
        """
        try:
            return self.client.describe_configuration_aggregator_sources_status(
                ConfigurationAggregatorName=aggregator_name
            )
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_bucket_location(self, bucket_name: str) -> Mapping[str, Any]:
        """
        Get an S3 bucket's Region.

        Args:
            bucket_name: The bucket name.

        Returns:
            The ``GetBucketLocation`` response on success, i.e.
            ``{"LocationConstraint": ...}``, or the error result.

            The response, not the mapped Region: ``LocationConstraint`` is
            ``None`` for us-east-1, so a caller writing ``location or
            'us-east-1'`` could not tell that from a failure.
            ``ConfigCheck.bucket_region_of`` does the mapping after the error test.
        """
        try:
            return self.s3_client.get_bucket_location(Bucket=bucket_name)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_bucket_policy(self, bucket_name: str) -> Mapping[str, Any]:
        """
        Get an S3 bucket's policy.

        Args:
            bucket_name: The bucket name.

        Returns:
            The ``GetBucketPolicy`` response on success, i.e. ``{"Policy": ...}``,
            or the error result.

            ``NoSuchBucketPolicy`` means the bucket has no policy, which is a real
            answer and is declared in ``ConfigCheck.NOT_CONFIGURED_ERRORS``.
        """
        try:
            return self.s3_client.get_bucket_policy(Bucket=bucket_name)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_delegated_administrators(
        self, service_principal: str = "config.amazonaws.com"
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
