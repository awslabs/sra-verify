"""
Base class for AWS Config security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"config"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

Two shapes here are deliberate exceptions to the accessor pattern:

* :meth:`get_configuration_recorders` **caches nothing**. It is the only accessor
  in the tree that calls its client on every invocation.
* :meth:`get_delegated_administrators` **loops over two service principals** --
  ``config.amazonaws.com`` and ``config-multiaccountsetup.amazonaws.com`` --
  caching one slot per principal and merging the results. A single call therefore
  writes the cache more than once, which is why it is classified as derived rather
  than as a plain accessor.

:meth:`bucket_region_of` is a pure helper over a success dict, not an accessor. It
maps a ``None`` ``LocationConstraint`` to ``"us-east-1"``, which is what the API
means -- doing that inside the client would make a failed call indistinguishable
from a bucket that really is in us-east-1.
"""
from typing import Any, ClassVar, Dict, List, Mapping, Optional

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.config.client import ConfigClient


class ConfigCheck(SecurityCheck):
    """Base class for all AWS Config security checks."""

    NAMESPACE = "config"

    #: Both service principals Config can be delegated under. Checked together
    #: because an organization may have either or both registered.
    CONFIG_SERVICE_PRINCIPALS: ClassVar[tuple] = (
        "config.amazonaws.com",
        "config-multiaccountsetup.amazonaws.com",
    )

    #: The ``(operation, code)`` pairs that mean "the control is not configured".
    #:
    #: Both entries are about a resource whose *absence is the finding*: no
    #: organization, or a bucket with no policy. Nothing is declared for the
    #: ``describe_*`` operations, because Config having no recorder or no delivery
    #: channel is a **successful** response with an empty list, not an error -- so
    #: any error from those is an inability to determine.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "DescribeOrganization": {
            "AWSOrganizationsNotInUseException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/organizations/latest/APIReference/"
                    "API_DescribeOrganization.html -- "
                    "AWSOrganizationsNotInUseException is returned when the "
                    "account is not a member of an organization, which is the "
                    "control being absent rather than an inability to determine. "
                    "This is the pair product.md names as the canonical example of "
                    "a semantic AWS code."
                ),
            ),
        },
        "GetBucketPolicy": {
            "NoSuchBucketPolicy": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/AmazonS3/latest/API/"
                    "API_GetBucketPolicy.html -- NoSuchBucketPolicy means the "
                    "bucket has no policy attached, which is exactly what a check "
                    "asking whether the Config delivery bucket restricts access is "
                    "testing for. The sibling AccessDenied is deliberately not "
                    "declared: it means the role may not read the policy."
                ),
            ),
        },
    }

    def _setup_clients(self):
        """Set up Config clients for each region.

        Each wrapper obtains its underlying boto3 ``config``, ``organizations``,
        ``s3`` and ``sts`` clients from ``self._ctx.get_client(...)``.
        """
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = ConfigClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[ConfigClient]:
        """
        Get Config client for a specific region.

        Args:
            region: AWS region name

        Returns:
            ConfigClient for the region or None if not available
        """
        return self._clients.get(region)

    @staticmethod
    def bucket_region_of(response: Mapping[str, Any]) -> str:
        """
        Read a bucket's Region out of a successful ``GetBucketLocation`` response.

        Call only after ``"Error" in response`` is False. That ordering is the
        whole point: ``LocationConstraint`` is ``None`` for us-east-1, so this
        mapping is only sound once a failure has been ruled out.

        Args:
            response: A successful :meth:`get_bucket_location` response.

        Returns:
            The bucket's Region, with ``None`` resolved to ``"us-east-1"``.
        """
        return response.get('LocationConstraint') or 'us-east-1'

    def _cached_call(
        self, region: str, cache_key: str, method: str, *args: Any
    ) -> Mapping[str, Any]:
        """
        Run one client method for a Region through the accessor shape.

        Args:
            region: AWS region name.
            cache_key: Key within the ``"config"`` namespace.
            method: Name of the :class:`ConfigClient` method to call.
            *args: Positional arguments for that method.

        Returns:
            The cached or freshly fetched response dict, or an error result.
        """
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Config: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(f"Config: No client available for region {region}")
            return no_client_result(service="Config", region=region)

        logger.debug(f"Config: Fetching {cache_key}")
        result = getattr(client, method)(*args)

        if is_error(result):
            # Never cached: a retry has to be able to re-issue the call.
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    def get_configuration_recorders(self, region: str) -> Mapping[str, Any]:
        """
        Get the configuration recorders in a Region.

        **Uncached, deliberately.** This is the one accessor in the tree that
        re-issues its call every time.

        Args:
            region: AWS region name

        Returns:
            ``{"ConfigurationRecorders": [...]}``, or an error result.
        """
        client = self.get_client(region)
        if client is None:
            logger.warning(f"Config: No client available for region {region}")
            return no_client_result(service="Config", region=region)
        return client.describe_configuration_recorders()

    def get_configuration_recorder_status(self, region: str) -> Mapping[str, Any]:
        """
        Get the configuration recorder status in a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"ConfigurationRecordersStatus": [...]}``, or an error result.
        """
        return self._cached_call(
            region,
            f"recorder_status:{region}",
            "describe_configuration_recorder_status",
        )

    def get_delivery_channels(self, region: str) -> Mapping[str, Any]:
        """
        Get the delivery channels in a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"DeliveryChannels": [...]}``, or an error result.
        """
        return self._cached_call(
            region, f"delivery_channels:{region}", "describe_delivery_channels"
        )

    def get_delivery_channel_status(self, region: str) -> Mapping[str, Any]:
        """
        Get the delivery channel status in a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"DeliveryChannelsStatus": [...]}``, or an error result.
        """
        return self._cached_call(
            region,
            f"delivery_channel_status:{region}",
            "describe_delivery_channel_status",
        )

    def get_configuration_aggregators(self, region: str) -> Mapping[str, Any]:
        """
        Get the configuration aggregators in a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"ConfigurationAggregators": [...]}``, or an error result.
        """
        return self._cached_call(
            region,
            f"configuration_aggregators:{region}",
            "describe_configuration_aggregators",
        )

    def get_delegated_administrators(
        self, service_principal: Optional[str] = None
    ) -> Mapping[str, Any]:
        """
        Get Config delegated administrators, merged across service principals.

        Config can be delegated under either ``config.amazonaws.com`` or
        ``config-multiaccountsetup.amazonaws.com``, so both are consulted unless
        one is named. Each principal's response is cached in its own slot.

        **The first failure wins.** A merged list assembled from one successful
        principal and one denied one would be indistinguishable from a complete
        answer, and the checks that compare a delegated administrator against
        ``--audit-account`` would draw a confident conclusion from half the data.

        Args:
            service_principal: A single principal to check, or ``None`` for both.

        Returns:
            ``{"DelegatedAdministrators": [...]}`` merged across principals, or the
            first error result encountered.
        """
        if not self.regions:
            logger.warning("Config: No regions specified")
            return no_client_result(service="Config", region="global")

        account_id = self.account_id
        principals = (
            [service_principal] if service_principal
            else list(self.CONFIG_SERVICE_PRINCIPALS)
        )
        region = self.regions[0]
        merged: List[Dict[str, Any]] = []

        for principal in principals:
            cache_key = f"delegated_admin:{account_id}:{principal}"
            if self._ctx._has(self.NAMESPACE, cache_key):
                logger.debug(f"Config: Using cached {cache_key}")
                merged.extend(
                    self._ctx._get(self.NAMESPACE, cache_key).get(
                        'DelegatedAdministrators', []
                    )
                )
                continue

            client = self.get_client(region)
            if client is None:
                logger.warning(f"Config: No client available for region {region}")
                return no_client_result(service="Config", region=region)

            result = client.list_delegated_administrators(principal)
            if is_error(result):
                # Not cached, and not merged around: a partial answer here would
                # be read as a complete one.
                return result

            self._ctx._set(self.NAMESPACE, cache_key, result)
            merged.extend(result.get('DelegatedAdministrators', []))

        return {"DelegatedAdministrators": merged}
