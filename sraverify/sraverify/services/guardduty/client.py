"""
GuardDuty client for interacting with AWS GuardDuty service.
"""
from typing import Dict, Any
from botocore.exceptions import ClientError
from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext


class GuardDutyClient:
    """Client for interacting with AWS GuardDuty service."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize GuardDuty client for a specific region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan; the underlying boto3 client
                is obtained via ``ctx.get_client('guardduty', region=region)``
                so that the per-scan client cache and bounded ``Client_Config``
                are applied (see Requirement 2.12).
        """
        self.region = region
        self.ctx = ctx
        self.client = ctx.get_client('guardduty', region=region)

    def get_detector_id(self):
        """
        Get the detector ID for the current region.

        Returns:
            Detector ID if GuardDuty is enabled, None otherwise
        """
        try:
            response = self.client.list_detectors()
            detector_ids = response.get('DetectorIds', [])
            if detector_ids:
                return detector_ids[0]
            logger.debug(f"No detector found in {self.region}")
            return None
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)
            logger.error(f"Error getting detector ID in {self.region}: {error_message}")
            # Return a special error indicator instead of None
            return f"ERROR:{error_code}:{error_message}"

    def get_detector_details(self, detector_id: str) -> Dict[str, Any]:
        """
        Get details for a specific detector.

        Args:
            detector_id: GuardDuty detector ID

        Returns:
            Dictionary containing detector details
        """
        try:
            return self.client.get_detector(DetectorId=detector_id)
        except ClientError as e:
            logger.error(f"Error getting detector details for {detector_id} in {self.region}: {e}")
            return {}

    def describe_organization_configuration(self, detector_id: str) -> Dict[str, Any]:
        """
        Get organization configuration for a specific detector.

        Args:
            detector_id: GuardDuty detector ID

        Returns:
            Dictionary containing organization configuration details or error information
        """
        try:
            return self.client.describe_organization_configuration(DetectorId=detector_id)
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)
            logger.error(f"Error getting organization configuration for {detector_id} in {self.region}: {error_message}")

            # Return a dictionary with error information
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }

    def list_organization_admin_accounts(self) -> Dict[str, Any]:
        """
        List organization admin accounts for GuardDuty.

        Returns:
            Dictionary containing organization admin accounts details or error information
        """
        try:
            return self.client.list_organization_admin_accounts()
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)
            logger.error(f"Error listing organization admin accounts for GuardDuty in {self.region}: {error_message}")

            # Return a dictionary with error information
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }
