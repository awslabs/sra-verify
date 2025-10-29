from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger

class FirewallManagerClient:
    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        self.region = region
        self.session = session or boto3.Session()
        self.client = self.session.client('fms', region_name=region)

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
