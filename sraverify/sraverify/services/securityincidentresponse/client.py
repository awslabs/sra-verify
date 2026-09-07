from typing import Dict, Any, List
from botocore.exceptions import ClientError
from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext

class SecurityIncidentResponseClient:
    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize the Security Incident Response client wrapper for a region.

        Args:
            region: AWS region name
            ctx: Per-scan ``ScanContext`` providing the cached, bounded boto3
                clients used by this wrapper
        """
        self.region = region
        self.ctx = ctx
        self.org_client = ctx.get_client('organizations', region=region)
        self.sir_client = ctx.get_client('security-ir', region=region)
        self.iam_client = ctx.get_client('iam', region=region)

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
