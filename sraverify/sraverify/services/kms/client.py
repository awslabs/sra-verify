from collections.abc import Mapping
from typing import Any

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class KMSClient(AWSClient):
    def __init__(self, region: str, ctx: ScanContext) -> None:
        super().__init__(region, ctx)
        self.client = ctx.get_client("kms", region=region)

    def list_keys(self) -> Mapping[str, Any]:
        try:
            keys = []
            for page in self.client.get_paginator("list_keys").paginate():
                entries = page.get("Keys")
                marker = page.get("NextMarker")
                truncated = page.get("Truncated", False)
                if not isinstance(entries, list) or type(truncated) is not bool:
                    return {}
                if truncated and (not isinstance(marker, str) or not marker.strip()):
                    return {}
                if not truncated and marker is not None:
                    return {}
                keys.extend(entries)
            return {"Keys": keys}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_key(self, key_arn: str) -> Mapping[str, Any]:
        try:
            return self.client.describe_key(KeyId=key_arn)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_key_rotation_status(self, key_arn: str) -> Mapping[str, Any]:
        try:
            return self.client.get_key_rotation_status(KeyId=key_arn)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
