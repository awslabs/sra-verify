"""
S3 client for interacting with AWS S3 service.
"""
from typing import Any, Dict

from botocore.exceptions import ClientError

from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext


class S3Client:
    """Client for interacting with AWS S3 service."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize S3 client for a specific region.

        Args:
            region: AWS region name
            ctx: The per-scan ``ScanContext`` that owns the boto3 session,
                ``Client_Config``, and per-scan boto3 client cache. Underlying
                boto3 clients are obtained via ``ctx.get_client(...)`` so the
                bounded timeouts and retry policy are applied and the same
                client instance is reused across all wrappers in this scan.
        """
        self.region = region
        self.ctx = ctx
        self.client = ctx.get_client('s3', region=region)
        self.s3control_client = ctx.get_client('s3control', region=region)

    def get_public_access_block(self, account_id: str) -> Dict[str, Any]:
        """
        Get the public access block configuration for an account.

        Args:
            account_id: AWS account ID

        Returns:
            Public access block configuration
        """
        try:
            logger.debug(f"Getting public access block configuration for account {account_id} in {self.region}")
            response = self.s3control_client.get_public_access_block(
                AccountId=account_id
            )
            return response.get('PublicAccessBlockConfiguration', {})
        except ClientError as e:
            if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                # Silently handle the case where no configuration exists
                # This is a common case and not an error condition
                logger.debug(f"No public access block configuration found for account {account_id} in {self.region}")
                return {}
            logger.error(f"Error getting public access block configuration for account {account_id} in {self.region}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error getting public access block configuration for account {account_id} in {self.region}: {e}")
            return {}
