"""
Secrets Manager client: the secret inventory and the per-secret description.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over.
"""
from collections.abc import Mapping as MappingABC
from typing import Any, Mapping

from botocore.exceptions import PaginationError

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class SecretsManagerClient(AWSClient):
    """Client for interacting with AWS Secrets Manager."""

    def __init__(self, region: str, ctx: ScanContext):
        super().__init__(region, ctx)
        self.client = ctx.get_client('secretsmanager', region=region)

    def list_secrets(self) -> Mapping[str, Any]:
        """
        List the secrets in this Region, every page merged.

        A page that is not a mapping with a list ``SecretList`` raises botocore's
        ``PaginationError``, so the whole listing becomes one error result and no
        partial inventory is returned.
        """
        try:
            secrets: list[Any] = []
            for page in self.client.get_paginator('list_secrets').paginate():
                entries = page.get('SecretList', []) if isinstance(page, MappingABC) else None
                if not isinstance(entries, list):
                    raise PaginationError(message="ListSecrets returned a malformed page")
                secrets.extend(entries)
            return {"SecretList": secrets}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_secret(self, secret_arn: str) -> Mapping[str, Any]:
        try:
            return self.client.describe_secret(SecretId=secret_arn)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
