"""
EC2 client, for the account-level default EBS encryption setting and the
VPC and flow-log inventories.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

Reaches ``ec2`` and ``sts``, both acquired in ``__init__``.
"""
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class EC2Client(AWSClient):
    """Client for interacting with AWS EC2."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize EC2 client for a specific region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan; the underlying boto3 clients
                are obtained via ``ctx.get_client(...)`` so the per-scan client
                cache and bounded ``Client_Config`` are applied.
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('ec2', region=region)
        # Moved out of get_account_id, which acquired it per call.
        self.sts_client = ctx.get_client('sts')

    def get_ebs_encryption_by_default(self) -> Mapping[str, Any]:
        """
        Get the account's default EBS encryption setting for this Region.

        Returns:
            The ``GetEbsEncryptionByDefault`` response on success, i.e.
            ``{"EbsEncryptionByDefault": bool}``, or the error result.
        """
        try:
            return self.client.get_ebs_encryption_by_default()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_vpcs(self) -> Mapping[str, Any]:
        """
        List every VPC visible to the account in this Region.

        The result includes VPCs shared into the account through AWS RAM; the
        check filters on ``OwnerId``.

        Returns:
            ``{"Vpcs": [...]}`` with every page merged, on success, or the error
            result.
        """
        try:
            vpcs = []
            for page in self.client.get_paginator('describe_vpcs').paginate():
                vpcs.extend(page.get('Vpcs', []))
            return {"Vpcs": vpcs}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_flow_logs(self) -> Mapping[str, Any]:
        """
        List every flow log in this Region.

        Deliberately unfiltered: a ``resource-id`` filter naming a nonexistent
        VPC answers an empty list rather than an error, so the check lists all
        flow logs once and matches them to VPCs by ``ResourceId``.

        Returns:
            ``{"FlowLogs": [...]}`` with every page merged, on success, or the
            error result.
        """
        try:
            flow_logs = []
            for page in self.client.get_paginator('describe_flow_logs').paginate():
                flow_logs.extend(page.get('FlowLogs', []))
            return {"FlowLogs": flow_logs}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_account_id(self) -> Mapping[str, Any]:
        """
        Get the current account ID.

        Returns:
            The ``GetCallerIdentity`` response on success, or the error result.
        """
        try:
            return self.sts_client.get_caller_identity()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
