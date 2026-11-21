from collections.abc import Callable, Mapping
from typing import Any, ClassVar

from sraverify.core.aws_errors import NotConfiguredTable, is_error, no_client_result
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.kms.client import KMSClient


class KMSCheck(SecurityCheck):
    NAMESPACE = "kms"
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}

    def _setup_clients(self) -> None:
        self._clients.clear()
        for region in self.regions:
            self._clients[region] = KMSClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> KMSClient | None:
        return self._clients.get(region)

    def _cached_call(
        self, region: str, cache_key: str, query: Callable[[KMSClient], Mapping[str, Any]]
    ) -> Mapping[str, Any]:
        if self._ctx._has(self.NAMESPACE, cache_key):
            return self._ctx._get(self.NAMESPACE, cache_key)
        client = self.get_client(region)
        if client is None:
            logger.warning(f"KMS: No client available for region {region}")
            return no_client_result(service="KMS", region=region)
        result = query(client)
        if not is_error(result) and result and "Error" not in result:
            self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    def get_keys(self, region: str) -> Mapping[str, Any]:
        return self._cached_call(region, f"keys:{region}", lambda client: client.list_keys())

    def get_key(self, region: str, key_arn: str) -> Mapping[str, Any]:
        return self._cached_call(region, f"key:{region}:{key_arn}", lambda client: client.describe_key(key_arn))

    def get_rotation_status(self, region: str, key_arn: str) -> Mapping[str, Any]:
        return self._cached_call(
            region, f"rotation:{region}:{key_arn}", lambda client: client.get_key_rotation_status(key_arn)
        )
