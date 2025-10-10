from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger

class WAFClient:
    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        self.region = region
        self.session = session or boto3.Session()
        self.cloudfront_client = self.session.client('cloudfront', region_name='us-east-1')  # CloudFront is global
        self.elbv2_client = self.session.client('elbv2', region_name=region)
        self.wafv2_client = self.session.client('wafv2', region_name=region)
        self.apigateway_client = self.session.client('apigateway', region_name=region)
        self.appsync_client = self.session.client('appsync', region_name=region)
        self.cognito_idp_client = self.session.client('cognito-idp', region_name=region)
        self.apprunner_client = self.session.client('apprunner', region_name=region)
        self.ec2_client = self.session.client('ec2', region_name=region)
        self.amplify_client = self.session.client('amplify', region_name=region)

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
        try:
            return self.apprunner_client.list_services()
        except ClientError as e:
            logger.error(f"Error listing App Runner services in {self.region}: {e}")
            return {"Error": {"Message": str(e)}}

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
            logger.error(f"Error getting web ACL for resource {resource_arn}: {e}")
            return {"Error": {"Message": str(e)}}
