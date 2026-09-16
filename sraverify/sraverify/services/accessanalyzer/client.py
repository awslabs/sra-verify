"""
IAM Access Analyzer client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.
"""
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class AccessAnalyzerClient(AWSClient):
    """Client for interacting with AWS IAM Access Analyzer."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize Access Analyzer client for a specific region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan; the underlying boto3 clients
                are obtained via ``ctx.get_client(...)`` so the per-scan client
                cache and bounded ``Client_Config`` are applied.
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('accessanalyzer', region=region)
        self.org_client = ctx.get_client('organizations', region=region)

    def list_analyzers(self) -> Mapping[str, Any]:
        """
        List the analyzers in this Region, with pagination.

        Returns:
            ``{"analyzers": [...]}`` with every page merged, on success, or the
            error result.
        """
        try:
            analyzers: list[Any] = []
            for page in self.client.get_paginator('list_analyzers').paginate():
                analyzers.extend(page.get('analyzers', []))
            return {"analyzers": analyzers}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_analyzer_details(self, analyzer_arn: str) -> Mapping[str, Any]:
        """
        Get details for one analyzer.

        Args:
            analyzer_arn: The analyzer ARN.

        Returns:
            The ``GetAnalyzer`` response on success, or the error result.
        """
        try:
            return self.client.get_analyzer(analyzerArn=analyzer_arn)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_delegated_admin(self) -> Mapping[str, Any]:
        """
        Get the Organizations delegated administrator for Access Analyzer.

        Returns:
            ``{"DelegatedAdministrators": [...]}`` on success, or the error
            result. The caller reads element ``[0]`` after the error test.
        """
        try:
            return self.org_client.list_delegated_administrators(
                ServicePrincipal="access-analyzer.amazonaws.com"
            )
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
