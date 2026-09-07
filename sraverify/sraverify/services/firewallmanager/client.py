from typing import Dict, Any
from botocore.exceptions import ClientError
from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext


class FirewallManagerClient:
    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize Firewall Manager client for a specific region.

        Args:
            region: AWS region name. The Firewall Manager admin APIs are
                global and only respond in ``us-east-1``; regional policy
                APIs accept any enabled region.
            ctx: Per-scan ``ScanContext`` whose bounded ``Client_Config`` and
                cached ``(service, region)`` boto3 clients back this wrapper.
        """
        self.region = region
        self.ctx = ctx
        self.client = ctx.get_client('fms', region=region)

    def get_admin_account(self) -> Dict[str, Any]:
        try:
            return self.client.get_admin_account()
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'ResourceNotFoundException':
                return {"Error": {"Message": "No Firewall Manager administrator account configured"}}
            logger.error(f"Error getting Firewall Manager admin account: {e}")
            return {"Error": {"Message": str(e)}}

    def list_policies(self) -> Dict[str, Any]:
        try:
            policies = []
            next_token = None
            while True:
                if next_token:
                    response = self.client.list_policies(NextToken=next_token, MaxResults=100)
                else:
                    response = self.client.list_policies(MaxResults=100)

                policies.extend(response.get('PolicyList', []))
                next_token = response.get('NextToken')
                if not next_token:
                    break

            return {"PolicyList": policies}
        except ClientError as e:
            logger.error(f"Error listing Firewall Manager policies in {self.region}: {e}")
            return {"Error": {"Message": str(e)}}
