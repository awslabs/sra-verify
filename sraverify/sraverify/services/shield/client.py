"""
Shield client for interacting with AWS Shield service.
"""
from typing import Dict, Optional, Any
from botocore.exceptions import ClientError
from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext


class ShieldClient:
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
        self.region = region
        self.ctx = ctx
        self.client = ctx.get_client('shield', region=region)

    def get_subscription_state(self) -> Dict[str, Any]:
        """
        Get Shield Advanced subscription state.

        Returns:
            Dictionary containing subscription details or error information
        """
        try:
            return self.client.describe_subscription()
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)
            logger.debug(f"Error getting Shield subscription in {self.region}: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }

    def get_subscription_status(self) -> Dict[str, Any]:
        """
        Get Shield Advanced subscription status (ACTIVE/INACTIVE).

        Returns:
            Dictionary containing subscription state or error information
        """
        try:
            return self.client.get_subscription_state()
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)
            logger.debug(f"Error getting Shield subscription state in {self.region}: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }

    def list_protections(self, resource_type: Optional[str] = None) -> Dict[str, Any]:
        """
        List Shield Advanced protections.

        Args:
            resource_type: Optional resource type filter

        Returns:
            Dictionary containing protections list or error information
        """
        try:
            params = {}
            if resource_type:
                params['InclusionFilters'] = {'ResourceTypes': [resource_type]}

            return self.client.list_protections(**params)
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)
            logger.debug(f"Error listing Shield protections in {self.region}: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }

    def describe_drt_access(self) -> Dict[str, Any]:
        """
        Describe Shield Response Team (SRT) access configuration.

        Returns:
            Dictionary containing DRT access details or error information
        """
        try:
            return self.client.describe_drt_access()
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)
            logger.debug(f"Error describing DRT access in {self.region}: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }

    def get_lambda_function(self, function_name: str) -> Dict[str, Any]:
        """
        Get Lambda function details.

        Args:
            function_name: Name of the Lambda function

        Returns:
            Dictionary containing function details or error information
        """
        try:
            lambda_client = self.ctx.get_client('lambda', region=self.region)
            return lambda_client.get_function(FunctionName=function_name)
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)
            logger.debug(f"Error getting Lambda function {function_name} in {self.region}: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }

    def get_web_acl_for_resource(self, resource_arn: str) -> Dict[str, Any]:
        """
        Get WAF web ACL associated with a resource.

        Args:
            resource_arn: ARN of the resource

        Returns:
            Dictionary containing web ACL details or error information
        """
        try:
            # For CloudFront distributions, use CloudFront API
            if "cloudfront" in resource_arn.lower():
                # Extract distribution ID from ARN: arn:aws:cloudfront::account:distribution/ID
                distribution_id = resource_arn.split("/")[-1]
                cloudfront_client = self.ctx.get_client('cloudfront', region='us-east-1')
                response = cloudfront_client.get_distribution_config(Id=distribution_id)
                web_acl_id = response.get('DistributionConfig', {}).get('WebACLId', '')

                if web_acl_id:
                    return {"WebACL": {"Id": web_acl_id, "Name": f"WebACL-{web_acl_id}"}}
                else:
                    return {"Error": {"Code": "WAFNonexistentItemException", "Message": "No web ACL associated"}}
            else:
                # For other resources, use WAFv2 API
                wafv2_client = self.ctx.get_client('wafv2', region=self.region)
                return wafv2_client.get_web_acl_for_resource(ResourceArn=resource_arn)
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)
            logger.debug(f"Error getting web ACL for resource {resource_arn} in {self.region}: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }

    def get_cloudwatch_alarms_for_resource(self, resource_arn: str) -> Dict[str, Any]:
        """
        Get CloudWatch alarms for Shield Advanced DDoS metrics for a resource.

        Args:
            resource_arn: ARN of the resource

        Returns:
            Dictionary containing alarm details or error information
        """
        try:
            cloudwatch_client = self.ctx.get_client('cloudwatch', region=self.region)

            # Look for alarms on DDoSDetected metric for this resource
            response = cloudwatch_client.describe_alarms_for_metric(
                MetricName='DDoSDetected',
                Namespace='AWS/DDoSProtection',
                Dimensions=[
                    {
                        'Name': 'ResourceArn',
                        'Value': resource_arn
                    }
                ]
            )

            ddos_alarms = response.get('MetricAlarms', [])

            return {
                "DDoSDetectedAlarms": ddos_alarms
            }

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)
            logger.debug(f"Error getting CloudWatch alarms for resource {resource_arn} in {self.region}: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }
