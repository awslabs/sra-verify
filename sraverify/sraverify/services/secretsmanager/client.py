"""
Secrets Manager client: the secret inventory and the per-secret description.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over.
"""
from collections.abc import Mapping as MappingABC
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class SecretsManagerClient(AWSClient):
    """Client for interacting with AWS Secrets Manager."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize the Secrets Manager client wrapper for a region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('secretsmanager', region=region)

    def list_secrets(self) -> Mapping[str, Any]:
        """
        List the secrets in this Region, every page merged.

        Returns:
            ``{"SecretList": [...]}`` on success, with ``"InvalidPages"`` set to
            the number of pages that were not a mapping holding a list, or the
            error result. A page that ends in an error fails the whole listing.
        """
        try:
            secrets: list[Any] = []
            invalid = 0
            for page in self.client.get_paginator('list_secrets').paginate():
                entries = page.get('SecretList', []) if isinstance(page, MappingABC) else None
                if isinstance(entries, list):
                    secrets.extend(entries)
                else:
                    invalid += 1
            result: dict[str, Any] = {"SecretList": secrets}
            if invalid:
                result["InvalidPages"] = invalid
            return result
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_secret(self, secret_arn: str) -> Mapping[str, Any]:
        """
        Describe one secret by ARN.

        Args:
            secret_arn: The secret ARN.

        Returns:
            The ``DescribeSecret`` response, or the error result.
        """
        try:
            return self.client.describe_secret(SecretId=secret_arn)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
