"""
IAM client for interacting with AWS IAM service.
"""
from typing import Any, Dict

from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext


class IAM_Client:
    """Client for interacting with AWS IAM service.

    IAM is a global AWS service, so the underlying boto3 client is requested
    from the :class:`ScanContext` without a region. The context's per-scan
    client cache stores it under the ``"__global__"`` cache-key sentinel so it
    is shared across every caller in the scan.
    """

    def __init__(self, ctx: ScanContext):
        """
        Initialize IAM client.

        Args:
            ctx: Per-scan :class:`ScanContext` that owns the boto3 session,
                bounded ``Client_Config``, and the per-scan client cache.
        """
        self.ctx = ctx
        # IAM is a global service; request the client without a region so the
        # context caches it under the "__global__" sentinel.
        self.client = ctx.get_client('iam', region=None)

    def list_users(self) -> Dict[str, Any]:
        """
        List all IAM users in the account with pagination support.

        Returns:
            Dictionary with ``Users`` key containing the list of IAM users
            accumulated across every response page, or an ``Error`` key with
            ``Code``/``Message`` fields if the API call failed. Exceptions are
            never re-raised; failures are always returned as a structured dict.
        """
        try:
            users = []
            paginator = self.client.get_paginator('list_users')
            for page in paginator.paginate():
                users.extend(page.get('Users', []))
            return {"Users": users}
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            logger.warning(f"Error listing IAM users: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }
        except (EndpointConnectionError, ReadTimeoutError, ConnectTimeoutError) as e:
            logger.warning(f"Network error listing IAM users: {e}")
            return {
                "Error": {
                    "Code": e.__class__.__name__,
                    "Message": str(e)
                }
            }
        except Exception as e:
            logger.warning(f"Unexpected error listing IAM users: {e}")
            return {
                "Error": {
                    "Code": "UnknownError",
                    "Message": str(e)
                }
            }
