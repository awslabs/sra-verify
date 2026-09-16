"""
GuardDuty client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.
"""
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class GuardDutyClient(AWSClient):
    """Client for interacting with AWS GuardDuty service."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize GuardDuty client for a specific region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan; the underlying boto3 client
                is obtained via ``ctx.get_client('guardduty', region=region)``
                so that the per-scan client cache and bounded ``Client_Config``
                are applied.
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('guardduty', region=region)

    def get_detector_id(self) -> Mapping[str, Any]:
        """
        List the detector IDs in this Region.

        Returns:
            ``{"DetectorIds": [...]}`` on success, or the error result.

            The whole response, not the first ID. Extraction happens after the
            error test -- ``GuardDutyCheck.detector_id_of`` does it -- because a
            method that returned the ID itself would have to encode "no detector"
            and "the call failed" in the same ``None``, which is exactly the
            defect this replaces.
        """
        try:
            return self.client.list_detectors()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_detector_details(self, detector_id: str) -> Mapping[str, Any]:
        """
        Get details for a specific detector.

        Args:
            detector_id: GuardDuty detector ID

        Returns:
            The ``GetDetector`` response on success, or the error result.
        """
        try:
            return self.client.get_detector(DetectorId=detector_id)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_organization_configuration(
        self, detector_id: str
    ) -> Mapping[str, Any]:
        """
        Get organization configuration for a specific detector.

        Args:
            detector_id: GuardDuty detector ID

        Returns:
            The ``DescribeOrganizationConfiguration`` response on success, or the
            error result.

            ``BadRequestException`` from *this* operation means no delegated
            administrator has been enabled -- the control is absent -- and
            ``GuardDutyCheck.NOT_CONFIGURED_ERRORS`` declares it so. The same code
            from ``ListOrganizationAdminAccounts`` means something else entirely,
            which is why the table is keyed by operation and why this client makes
            no judgement about either.
        """
        try:
            return self.client.describe_organization_configuration(
                DetectorId=detector_id
            )
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_organization_admin_accounts(self) -> Mapping[str, Any]:
        """
        List organization admin accounts for GuardDuty.

        Returns:
            The ``ListOrganizationAdminAccounts`` response on success, or the
            error result.
        """
        try:
            return self.client.list_organization_admin_accounts()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
