from typing import Dict, Optional, Any, List
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger

class SecurityIncidentResponseClient:
    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        self.region = region
        self.session = session or boto3.Session()
        self.org_client = self.session.client('organizations', region_name=region)
        self.sir_client = self.session.client('security-ir', region_name=region)
        self.iam_client = self.session.client('iam', region_name=region)

    def list_delegated_administrators(self, service_principal: str = "security-ir.amazonaws.com") -> Dict[str, Any]:
        """List delegated administrators for Security Incident Response service."""
        try:
            response = self.org_client.list_delegated_administrators(
                ServicePrincipal=service_principal
            )
            return response
        except ClientError as e:
            logger.error(f"Error listing delegated administrators in {self.region}: {e}")
            return {"Error": {"Code": e.response['Error']['Code'], "Message": e.response['Error']['Message']}}

    def list_memberships(self) -> Dict[str, Any]:
        """List Security Incident Response memberships."""
        try:
            response = self.sir_client.list_memberships()
            return response
        except ClientError as e:
            logger.error(f"Error listing memberships in {self.region}: {e}")
            return {"Error": {"Code": e.response['Error']['Code'], "Message": e.response['Error']['Message']}}

    def get_membership(self, membership_id: str) -> Dict[str, Any]:
        """Get Security Incident Response membership details."""
        try:
            response = self.sir_client.get_membership(membershipId=membership_id)
            return response
        except ClientError as e:
            logger.error(f"Error getting membership {membership_id} in {self.region}: {e}")
            return {"Error": {"Code": e.response['Error']['Code'], "Message": e.response['Error']['Message']}}

    def batch_get_member_account_details(self, membership_id: str, account_ids: List[str]) -> Dict[str, Any]:
        """Get member account details for multiple accounts."""
        try:
            response = self.sir_client.batch_get_member_account_details(
                membershipId=membership_id,
                accountIds=account_ids
            )
            return response
        except ClientError as e:
            logger.error(f"Error getting member account details for membership {membership_id} in {self.region}: {e}")
            return {"Error": {"Code": e.response['Error']['Code'], "Message": e.response['Error']['Message']}}

    def list_accounts(self) -> Dict[str, Any]:
        """List all accounts in the organization."""
        try:
            response = self.org_client.list_accounts()
            return response
        except ClientError as e:
            logger.error(f"Error listing organization accounts in {self.region}: {e}")
            return {"Error": {"Code": e.response['Error']['Code'], "Message": e.response['Error']['Message']}}

    def get_role(self, role_name: str) -> Dict[str, Any]:
        """Get IAM role details."""
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            return response
        except ClientError as e:
            logger.error(f"Error getting role {role_name}: {e}")
            return {"Error": {"Code": e.response['Error']['Code'], "Message": e.response['Error']['Message']}}
