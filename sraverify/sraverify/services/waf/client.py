"""
WAF client wrapping the 9 underlying boto3 services that WAF checks consult:
CloudFront, ELBv2, WAFv2, API Gateway, AppSync, Cognito, App Runner, EC2, and
Amplify.
"""
from typing import Dict, Any

from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext

# botocore transport failures, as they appear in the ``Code`` field of this
# client's error sentinel. These mean "the call did not reach AWS", which is
# always an undetermined state rather than a negative verdict.
TRANSPORT_ERROR_CODES = frozenset({
    "EndpointConnectionError",
    "ConnectTimeoutError",
    "ReadTimeoutError",
})


class WAFClient:
    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize a WAFClient for ``region``.

        WAFClient wraps 9 underlying boto3 clients. Each is obtained through
        the per-scan ``ScanContext.get_client(...)`` so the bounded
        ``Client_Config`` is applied and the underlying boto3 clients
        de-duplicate across all WAFClient instances built within a scan.

        CloudFront is a global service and is always pinned to ``us-east-1``;
        the other 8 clients are constructed for the supplied ``region``. This
        preserves the pre-refactor region-pinning behavior. The WAF for
        CloudFront global-scope concern is handled at the ``WAFCheck`` base
        class layer (task 8.17), which still constructs a dedicated
        ``WAFClient('us-east-1', ctx=...)`` for the CloudFront-scoped Web ACL
        lookups.

        Args:
            region: AWS region name for the regional clients (ELBv2, WAFv2,
                API Gateway, AppSync, Cognito, App Runner, EC2, Amplify).
            ctx: The per-scan ``ScanContext`` that owns the boto3 session,
                ``Client_Config``, and per-scan boto3 client cache.
        """
        self.region = region
        self.ctx = ctx
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

    def list_distributions(self) -> Dict[str, Any]:
        try:
            return self.cloudfront_client.list_distributions()
        except ClientError as e:
            logger.error(f"Error listing CloudFront distributions: {e}")
            return {"Error": {"Message": str(e)}}

    def describe_load_balancers(self) -> Dict[str, Any]:
        try:
            return self.elbv2_client.describe_load_balancers()
        except ClientError as e:
            logger.error(f"Error describing load balancers in {self.region}: {e}")
            return {"Error": {"Message": str(e)}}

    def get_rest_apis(self) -> Dict[str, Any]:
        try:
            return self.apigateway_client.get_rest_apis()
        except ClientError as e:
            logger.error(f"Error getting REST APIs in {self.region}: {e}")
            return {"Error": {"Message": str(e)}}

    def get_stages(self, rest_api_id: str) -> Dict[str, Any]:
        try:
            return self.apigateway_client.get_stages(restApiId=rest_api_id)
        except ClientError as e:
            logger.error(f"Error getting stages for REST API {rest_api_id} in {self.region}: {e}")
            return {"Error": {"Message": str(e)}}

    def list_graphql_apis(self) -> Dict[str, Any]:
        try:
            return self.appsync_client.list_graphql_apis()
        except ClientError as e:
            logger.error(f"Error listing GraphQL APIs in {self.region}: {e}")
            return {"Error": {"Message": str(e)}}

    def list_user_pools(self) -> Dict[str, Any]:
        try:
            return self.cognito_idp_client.list_user_pools(MaxResults=60)
        except ClientError as e:
            logger.error(f"Error listing user pools in {self.region}: {e}")
            return {"Error": {"Message": str(e)}}

    def list_services(self) -> Dict[str, Any]:
        """
        List App Runner services in this Region.

        Returns the raw API response on success, or the error sentinel
        ``{"Error": {"Code": ..., "Message": ...}}``.

        Transport failures are caught explicitly alongside ``ClientError``.
        App Runner is not available in every Region, and in a Region with no
        App Runner endpoint the hostname does not resolve at all, which
        botocore raises as ``EndpointConnectionError`` — a ``BotoCoreError``,
        not a ``ClientError``. Left uncaught it escapes ``execute()`` and the
        orchestrator collapses the entire check into one synthetic ERROR row,
        discarding the rows already yielded for the Regions that did work.

        The sentinel deliberately does not decide whether an unreachable
        endpoint is a finding. ``SRA-WAF-06`` tests Region support up front
        via ``WAFCheck.region_supports_service`` so it can tell "App Runner
        does not exist here" from "App Runner is unreachable from here".
        """
        try:
            return self.apprunner_client.list_services()
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            logger.error(
                f"Error listing App Runner services in {self.region}: "
                f"{error_code}: {error_message}"
            )
            return {"Error": {"Code": error_code, "Message": error_message}}
        except (EndpointConnectionError, ConnectTimeoutError, ReadTimeoutError) as e:
            logger.error(
                f"Network error listing App Runner services in {self.region}: "
                f"{type(e).__name__}: {e}"
            )
            return {"Error": {"Code": type(e).__name__, "Message": str(e)}}
        except Exception as e:
            logger.error(
                f"Unexpected error listing App Runner services in {self.region}: "
                f"{type(e).__name__}: {e}"
            )
            return {"Error": {"Code": type(e).__name__, "Message": str(e)}}

    def describe_verified_access_instances(self) -> Dict[str, Any]:
        try:
            return self.ec2_client.describe_verified_access_instances()
        except ClientError as e:
            logger.error(f"Error describing Verified Access instances in {self.region}: {e}")
            return {"Error": {"Message": str(e)}}

    def list_apps(self) -> Dict[str, Any]:
        try:
            return self.amplify_client.list_apps()
        except ClientError as e:
            logger.error(f"Error listing Amplify apps in {self.region}: {e}")
            return {"Error": {"Message": str(e)}}

    def list_web_acls(self, scope: str = "REGIONAL") -> Dict[str, Any]:
        try:
            return self.wafv2_client.list_web_acls(Scope=scope)
        except ClientError as e:
            logger.error(f"Error listing Web ACLs in {self.region}: {e}")
            return {"Error": {"Message": str(e)}}

    def get_logging_configuration(self, resource_arn: str) -> Dict[str, Any]:
        try:
            return self.wafv2_client.get_logging_configuration(ResourceArn=resource_arn)
        except ClientError as e:
            if e.response['Error']['Code'] == 'WAFNonexistentItemException':
                return {"LoggingConfiguration": None}
            logger.error(f"Error getting logging configuration for {resource_arn}: {e}")
            return {"Error": {"Message": str(e)}}

    def get_web_acl_for_resource(self, resource_arn: str) -> Dict[str, Any]:
        try:
            return self.wafv2_client.get_web_acl_for_resource(ResourceArn=resource_arn)
        except ClientError as e:
            if e.response['Error']['Code'] == 'WAFNonexistentItemException':
                return {"WebACL": None}
            elif e.response['Error']['Code'] == 'AccessDeniedException':
                logger.error(f"Access denied getting web ACL for resource {resource_arn}: {e}")
                return {"Error": {"Code": "AccessDeniedException", "Message": str(e)}}
            logger.error(f"Error getting web ACL for resource {resource_arn}: {e}")
            return {"Error": {"Message": str(e)}}
