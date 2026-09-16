"""
Shield client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

Reaches five services -- ``shield`` plus ``lambda``, ``wafv2``, ``cloudwatch`` and
``cloudfront`` for the helper methods -- all acquired in ``__init__``.

``list_protections`` reads the **first page** only. Paginating would change which
resources the per-resource fan-out covers, which moves rows, so it is a recorded
deferred correction.

``get_web_acl_for_resource`` is the one place a client legitimately *constructs* an
error result rather than catching one; see its docstring.
"""
from typing import Any, Mapping, Optional

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.aws_errors import error_result
from sraverify.core.scan_context import ScanContext


class ShieldClient(AWSClient):
    """Client for interacting with AWS Shield service."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize Shield client for a specific region.

        Args:
            region: AWS region name. Shield is a global service that is
                typically pinned to ``us-east-1`` for control-plane operations,
                but the existing wrapper passes the caller-supplied region
                through to ``shield`` (and to the auxiliary ``lambda``,
                ``wafv2``, and ``cloudwatch`` clients used by helper methods)
                so that behavior is preserved here.
            ctx: The per-scan ``ScanContext`` that owns the boto3 session,
                ``Client_Config``, and per-scan boto3 client cache. Underlying
                boto3 clients are obtained via ``ctx.get_client(...)`` so the
                bounded timeouts and retry policy are applied and the same
                client instance is reused across all wrappers in this scan.
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('shield', region=region)
        # The four auxiliary clients the helper methods use. Acquired here rather
        # than inside each method: acquisition is offline and deterministic, so a
        # failure is a defect for the orchestrator to report, not an AWS outcome
        # for a method's except clause to convert into an error result.
        self.lambda_client = ctx.get_client('lambda', region=region)
        self.wafv2_client = ctx.get_client('wafv2', region=region)
        self.cloudwatch_client = ctx.get_client('cloudwatch', region=region)
        # CloudFront's control plane is us-east-1 only, which is why this one is
        # not parameterised by the wrapper's Region.
        self.cloudfront_client = ctx.get_client('cloudfront', region='us-east-1')

    def get_subscription_state(self) -> Mapping[str, Any]:
        """
        Get Shield Advanced subscription details.

        Note the crossed name, which is in the tree and not a typo: this calls
        ``DescribeSubscription``, while ``get_subscription_status`` calls
        ``GetSubscriptionState``.

        Returns:
            The ``DescribeSubscription`` response on success, or the error result.
            ``ResourceNotFoundException`` means the account has no Shield Advanced
            subscription, and is declared semantic on the base class.
        """
        try:
            return self.client.describe_subscription()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_subscription_status(self) -> Mapping[str, Any]:
        """
        Get Shield Advanced subscription status (ACTIVE/INACTIVE).

        Returns:
            The ``GetSubscriptionState`` response on success, i.e.
            ``{"SubscriptionState": ...}``, or the error result.
        """
        try:
            return self.client.get_subscription_state()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_protections(self, resource_type: Optional[str] = None) -> Mapping[str, Any]:
        """
        List Shield Advanced protections.

        First page only. Paginating would change which resources the
        per-resource fan-out covers, so it is a recorded deferred correction.

        Args:
            resource_type: Optional resource type filter

        Returns:
            The ``ListProtections`` response on success, or the error result.
        """
        try:
            params = {}
            if resource_type:
                params['InclusionFilters'] = {'ResourceTypes': [resource_type]}

            return self.client.list_protections(**params)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_drt_access(self) -> Mapping[str, Any]:
        """
        Describe Shield Response Team (SRT) access configuration.

        Returns:
            The ``DescribeDRTAccess`` response on success, or the error result.
        """
        try:
            return self.client.describe_drt_access()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_lambda_function(self, function_name: str) -> Mapping[str, Any]:
        """
        Get Lambda function details.

        Args:
            function_name: Name of the Lambda function

        Returns:
            The ``GetFunction`` response on success, or the error result.
            ``ResourceNotFoundException`` means the function does not exist, and is
            declared semantic on the base class.
        """
        try:
            return self.lambda_client.get_function(FunctionName=function_name)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_web_acl_for_resource(self, resource_arn: str) -> Mapping[str, Any]:
        """
        Get the WAF web ACL associated with a resource.

        Branches on the ARN. A CloudFront distribution's association is read from
        ``cloudfront:GetDistributionConfig``, because ``wafv2`` does not serve it;
        everything else goes to ``wafv2:GetWebACLForResource``.

        On the CloudFront branch, a distribution with no ``WebACLId`` produces a
        **synthesized** ``WAFNonexistentItemException`` error result. That is not the
        client classifying an error: AWS answered, the answer is that the
        distribution has no Web ACL, and the synthesis expresses that answer in the
        same shape ``wafv2`` would have used for it -- which is what lets
        ``SRA-SHIELD-12`` read one branch. It carries ``GetDistributionConfig`` as
        its ``Operation``, so the row names the call that produced it.

        Args:
            resource_arn: ARN of the resource

        Returns:
            The ``GetWebACLForResource`` response, a ``{"WebACL": ...}`` dict
            assembled from the distribution config, or the error result.
        """
        try:
            # For CloudFront distributions, use CloudFront API
            if "cloudfront" in resource_arn.lower():
                # Extract distribution ID from ARN: arn:aws:cloudfront::account:distribution/ID
                distribution_id = resource_arn.split("/")[-1]
                response = self.cloudfront_client.get_distribution_config(
                    Id=distribution_id
                )
                web_acl_id = response.get('DistributionConfig', {}).get('WebACLId', '')

                if web_acl_id:
                    return {"WebACL": {"Id": web_acl_id, "Name": f"WebACL-{web_acl_id}"}}
                return error_result(
                    code="WAFNonexistentItemException",
                    message=f"Distribution {distribution_id} has no associated web ACL",
                    operation="GetDistributionConfig",
                )
            # For other resources, use WAFv2 API
            return self.wafv2_client.get_web_acl_for_resource(ResourceArn=resource_arn)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_cloudwatch_alarms_for_resource(self, resource_arn: str) -> Mapping[str, Any]:
        """
        Get CloudWatch alarms for Shield Advanced DDoS metrics for a resource.

        Args:
            resource_arn: ARN of the resource

        Returns:
            ``{"DDoSDetectedAlarms": [...]}`` on success, or the error result.
            An empty list is a real answer: the resource has no DDoSDetected
            alarm.
        """
        try:
            # Look for alarms on DDoSDetected metric for this resource
            response = self.cloudwatch_client.describe_alarms_for_metric(
                MetricName='DDoSDetected',
                Namespace='AWS/DDoSProtection',
                Dimensions=[
                    {
                        'Name': 'ResourceArn',
                        'Value': resource_arn
                    }
                ]
            )
            return {"DDoSDetectedAlarms": response.get('MetricAlarms', [])}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
