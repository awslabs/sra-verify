"""
WAF client, wrapping the 9 boto3 services the WAF checks consult: CloudFront,
ELBv2, WAFv2, API Gateway, AppSync, Cognito, App Runner, EC2 and Amplify.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

``TRANSPORT_ERROR_CODES`` is imported from ``core.aws_errors``, where it is derived
from the exception tuple a client raises through, so the set a check tests against
cannot drift from the one this module produces.

``WAFNonexistentItemException`` from ``GetWebACLForResource`` and
``GetLoggingConfiguration`` is passed through untouched. Both are declared in
``WAFCheck.NOT_CONFIGURED_ERRORS``; substituting a ``None`` for either here would
make the judgement at the tier that cannot see the operation.
"""
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class WAFClient(AWSClient):
    """Client wrapping the nine boto3 services the WAF checks consult."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize a WAFClient for ``region``.

        WAFClient wraps 9 underlying boto3 clients. Each is obtained through
        the per-scan ``ScanContext.get_client(...)`` so the bounded
        ``Client_Config`` is applied and the underlying boto3 clients
        de-duplicate across all WAFClient instances built within a scan.

        CloudFront is a global service and is always pinned to ``us-east-1``;
        the other 8 clients are constructed for the supplied ``region``. The
        CloudFront-scoped Web ACL lookups are handled by ``WAFCheck``, which
        always builds a dedicated ``WAFClient('us-east-1', ctx=...)``.

        Args:
            region: AWS region name for the regional clients (ELBv2, WAFv2,
                API Gateway, AppSync, Cognito, App Runner, EC2, Amplify).
            ctx: The per-scan ``ScanContext`` that owns the boto3 session,
                ``Client_Config``, and per-scan boto3 client cache.
        """
        super().__init__(region, ctx)
        # CloudFront is global; pin to us-east-1.
        self.cloudfront_client = ctx.get_client('cloudfront', region='us-east-1')
        self.elbv2_client = ctx.get_client('elbv2', region=region)
        self.wafv2_client = ctx.get_client('wafv2', region=region)
        self.apigateway_client = ctx.get_client('apigateway', region=region)
        self.appsync_client = ctx.get_client('appsync', region=region)
        self.cognito_idp_client = ctx.get_client('cognito-idp', region=region)
        self.apprunner_client = ctx.get_client('apprunner', region=region)
        self.ec2_client = ctx.get_client('ec2', region=region)
        self.amplify_client = ctx.get_client('amplify', region=region)

    def list_distributions(self) -> Mapping[str, Any]:
        """
        List CloudFront distributions.

        Returns:
            The ``ListDistributions`` response on success, or the error result.
        """
        try:
            return self.cloudfront_client.list_distributions()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_load_balancers(self) -> Mapping[str, Any]:
        """
        Describe the Elastic Load Balancers in this Region.

        Returns:
            The ``DescribeLoadBalancers`` response on success, or the error result.
        """
        try:
            return self.elbv2_client.describe_load_balancers()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_rest_apis(self) -> Mapping[str, Any]:
        """
        Get the API Gateway REST APIs in this Region.

        Returns:
            The ``GetRestApis`` response on success, or the error result.
        """
        try:
            return self.apigateway_client.get_rest_apis()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_stages(self, rest_api_id: str) -> Mapping[str, Any]:
        """
        Get the stages of one API Gateway REST API.

        Returns:
            The ``GetStages`` response on success, or the error result.
        """
        try:
            return self.apigateway_client.get_stages(restApiId=rest_api_id)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_graphql_apis(self) -> Mapping[str, Any]:
        """
        List the AppSync GraphQL APIs in this Region.

        Returns:
            The ``ListGraphqlApis`` response on success, or the error result.
        """
        try:
            return self.appsync_client.list_graphql_apis()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_user_pools(self) -> Mapping[str, Any]:
        """
        List the Cognito user pools in this Region.

        Returns:
            The ``ListUserPools`` response on success, or the error result.
        """
        try:
            return self.cognito_idp_client.list_user_pools(MaxResults=60)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_services(self) -> Mapping[str, Any]:
        """
        List App Runner services in this Region.

        Returns:
            The ``ListServices`` response on success, or the error result.

            App Runner is not available in every Region, and in a Region with no
            App Runner endpoint the hostname does not resolve at all, which
            botocore raises as ``EndpointConnectionError`` -- a ``BotoCoreError``,
            not a ``ClientError``. ``AWS_EXCEPTIONS`` covers both.

            The error result deliberately does not decide whether an unreachable
            endpoint is a finding. ``SRA-WAF-06`` tests Region support up front via
            ``service_available_in_region`` so it can tell "App Runner does not
            exist here" from "App Runner is unreachable from here".
        """
        try:
            return self.apprunner_client.list_services()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_verified_access_instances(self) -> Mapping[str, Any]:
        """
        Describe the Verified Access instances in this Region.

        Returns:
            The ``DescribeVerifiedAccessInstances`` response on success, or the
            error result.
        """
        try:
            return self.ec2_client.describe_verified_access_instances()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_apps(self) -> Mapping[str, Any]:
        """
        List the Amplify apps in this Region.

        Returns:
            The ``ListApps`` response on success, or the error result.
        """
        try:
            return self.amplify_client.list_apps()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_web_acls(self, scope: str = "REGIONAL") -> Mapping[str, Any]:
        """
        List the WAFv2 Web ACLs for a scope.

        Returns:
            The ``ListWebACLs`` response on success, or the error result.
        """
        try:
            return self.wafv2_client.list_web_acls(Scope=scope)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_logging_configuration(self, resource_arn: str) -> Mapping[str, Any]:
        """
        Get the logging configuration of one Web ACL.

        Returns:
            The ``GetLoggingConfiguration`` response on success, or the error
            result. ``WAFNonexistentItemException`` -- the web ACL has no logging
            configuration -- is passed through untouched and declared in
            ``WAFCheck.NOT_CONFIGURED_ERRORS``, so ``SRA-WAF-09`` can tell it from
            a permission failure.
        """
        try:
            return self.wafv2_client.get_logging_configuration(ResourceArn=resource_arn)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_web_acl_for_resource(self, resource_arn: str) -> Mapping[str, Any]:
        """
        Get the Web ACL associated with a resource.

        Returns:
            The ``GetWebACLForResource`` response on success, or the error result.
            ``WAFNonexistentItemException`` -- the resource has no associated web
            ACL -- is passed through untouched and declared in
            ``WAFCheck.NOT_CONFIGURED_ERRORS``, so the five checks that read this
            share one classification instead of each judging the code themselves.
        """
        try:
            return self.wafv2_client.get_web_acl_for_resource(ResourceArn=resource_arn)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
