"""
Base class for Secrets Manager security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"secretsmanager"`` namespace. Every accessor returns the client's response dict
unchanged, or an error result, and none caches a failure.
"""
from typing import Any, ClassVar, Mapping, Optional

from sraverify.core.aws_errors import (
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.secretsmanager.client import SecretsManagerClient


class SecretsManagerCheck(SecurityCheck):
    """Base class for all Secrets Manager security checks."""

    NAMESPACE = "secretsmanager"

    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}

    def _setup_clients(self):
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = SecretsManagerClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[SecretsManagerClient]:
        return self._clients.get(region)

    def get_secrets(self, region: str) -> Mapping[str, Any]:
        return self._cached(
            region, f"secrets:{region}", lambda client: client.list_secrets()
        )

    def get_secret(self, region: str, secret_arn: str) -> Mapping[str, Any]:
        return self._cached(
            region,
            f"secret:{region}:{secret_arn}",
            lambda client: client.describe_secret(secret_arn),
        )

    def _cached(self, region: str, cache_key: str, call) -> Mapping[str, Any]:
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"SecretsManager: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(f"SecretsManager: No client available for region {region}")
            return no_client_result(service="Secrets Manager", region=region)

        result = call(client)
        if is_error(result):
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result
