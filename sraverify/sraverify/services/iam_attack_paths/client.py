"""
IAM Attack Path client for interacting with AWS IAM service.

Provides paginated access to GetAccountAuthorizationDetails and
helper methods for IAM attack path analysis.
"""
from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger


class IAMAttackPathClient:
    """Client for IAM attack path data retrieval."""

    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        """
        Initialize IAM Attack Path client.

        Args:
            region: AWS region name (us-east-1 for IAM global)
            session: AWS session to use (if None, a new session will be created)
        """
        self.region = region
        self.session = session or boto3.Session()
        self.iam_client = self.session.client('iam', region_name=region)
        self.lambda_client = self.session.client('lambda', region_name=region)

    def get_account_authorization_details(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get complete account authorization details with pagination.

        Returns all users, roles, groups, and policies in a single
        consolidated response. This is the single source of truth
        for privilege graph construction.

        Returns:
            Dictionary with keys: users, roles, groups, policies
        """
        result: Dict[str, List[Dict[str, Any]]] = {
            'users': [],
            'roles': [],
            'groups': [],
            'policies': [],
        }

        try:
            logger.debug("IAMAttackPath: Fetching account authorization details")
            paginator = self.iam_client.get_paginator(
                'get_account_authorization_details'
            )

            for page in paginator.paginate(
                Filter=['User', 'Role', 'Group', 'LocalManagedPolicy', 'AWSManagedPolicy']
            ):
                result['users'].extend(page.get('UserDetailList', []))
                result['roles'].extend(page.get('RoleDetailList', []))
                result['groups'].extend(page.get('GroupDetailList', []))
                result['policies'].extend(page.get('Policies', []))

            logger.debug(
                f"IAMAttackPath: Retrieved {len(result['users'])} users, "
                f"{len(result['roles'])} roles, {len(result['groups'])} groups, "
                f"{len(result['policies'])} policies"
            )
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            logger.error(
                f"IAMAttackPath: Error fetching authorization details: "
                f"{error_code} - {e}"
            )

        return result

    def get_role_trust_policy(self, role_name: str) -> Optional[Dict[str, Any]]:
        """
        Get a role's trust policy (assume role policy document).

        Args:
            role_name: Name of the IAM role

        Returns:
            Trust policy document or None if unavailable
        """
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            return response['Role'].get('AssumeRolePolicyDocument')
        except ClientError as e:
            logger.error(
                f"IAMAttackPath: Error getting trust policy for {role_name}: {e}"
            )
            return None

    def list_lambda_functions(self, region: str) -> List[Dict[str, Any]]:
        """
        List Lambda functions and their execution roles.

        Used for Lambda code injection checks (SRA-IAP-8).

        Args:
            region: AWS region to list functions in

        Returns:
            List of Lambda function configurations
        """
        functions: List[Dict[str, Any]] = []

        try:
            lambda_client = self.session.client('lambda', region_name=region)
            paginator = lambda_client.get_paginator('list_functions')

            for page in paginator.paginate():
                functions.extend(page.get('Functions', []))

            logger.debug(
                f"IAMAttackPath: Found {len(functions)} Lambda functions in {region}"
            )
        except ClientError as e:
            logger.error(
                f"IAMAttackPath: Error listing Lambda functions in {region}: {e}"
            )

        return functions
