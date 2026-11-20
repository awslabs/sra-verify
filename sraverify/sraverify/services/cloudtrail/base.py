"""
Base class for CloudTrail security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"cloudtrail"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

"""
from typing import Any, ClassVar, Dict, List, Mapping, Optional

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
    error_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.cloudtrail.client import CloudTrailClient


class CloudTrailCheck(SecurityCheck):
    """Base class for all CloudTrail security checks."""

    NAMESPACE = "cloudtrail"

    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "GetObjectLockConfiguration": {
            "ObjectLockConfigurationNotFoundError": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/code-library/latest/ug/"
                    "s3_example_s3_Scenario_ObjectLock_section.html -- "
                    "The S3 SDK example identifies this error as an absent "
                    "Object Lock configuration."
                ),
            ),
        },
        "GetTrailStatus": {
            "TrailNotFoundException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/"
                    "API_GetTrailStatus.html -- TrailNotFoundException is returned "
                    "when the trail named in the request does not exist. A check "
                    "asking whether a trail is logging is asking about that trail, "
                    "so its absence is the control being absent. Nothing is "
                    "declared for DescribeTrails because 'no trails' is a "
                    "successful empty trailList there, not an error."
                ),
            ),
        },
        "GetEventSelectors": {
            "TrailNotFoundException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/"
                    "API_GetEventSelectors.html -- TrailNotFoundException is "
                    "returned when the trail named in the request does not exist, "
                    "the same reasoning as GetTrailStatus above: the trail whose "
                    "selectors are being read is the resource in question, so its "
                    "absence is the control being absent. Verified 2026-09-16 that "
                    "the full owner ARN avoids the other route to this code -- a "
                    "bare trail name resolves against the calling account."
                ),
            ),
        },
    }

    def _setup_clients(self):
        """Set up CloudTrail clients for each region.

        Each wrapper obtains its underlying boto3 ``cloudtrail`` and ``sts``
        clients from ``self._ctx.get_client(...)``.
        """
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = CloudTrailClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[CloudTrailClient]:
        """
        Get CloudTrail client for a specific region.

        Args:
            region: AWS region name

        Returns:
            CloudTrailClient for the region or None if not available
        """
        return self._clients.get(region)

    @staticmethod
    def parse_delivery_time(value: Any) -> Optional["datetime"]:
        """
        Parse one of ``GetTrailStatus``'s delivery timestamps.

        Exists so no ``except`` clause appears inside a check's ``execute()``.
        Three checks -- ``_08``, ``_09``, ``_10`` -- compare a delivery time
        against a 24-hour window, and each wrapped the parse in
        ``except (ValueError, TypeError)``. That handler was not catching an AWS
        failure at all; it was catching a malformed timestamp. The contract still
        forbids it in ``execute()``, because the orchestrator is the only tier
        that may handle exceptions, so the parse moves here and answers ``None``
        instead of raising.

        Args:
            value: A ``LatestDeliveryTime``-style member: boto3 usually hands back
                a ``datetime``, but a string is accepted and parsed.

        Returns:
            The parsed ``datetime``, or ``None`` when the value is absent or
            unparseable. ``None`` is a shape problem in AWS's response, not a
            verdict, and the caller reports it as such.
        """
        from datetime import datetime as _dt

        if value is None:
            return None
        if not isinstance(value, str):
            return value if hasattr(value, "tzinfo") else None
        try:
            return _dt.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None

    def describe_trails(
        self, include_shadow_trails: bool = True, *, region: Optional[str] = None
    ) -> Mapping[str, Any]:
        """
        Get every visible CloudTrail trail, with caching.

        Args:
            include_shadow_trails: Include shadow trails in the response.

        Returns:
            ``{"trailList": [...]}`` on success, or an error result. Test for
            ``"Error"`` before iterating -- every check here does, and one that
            forgot would raise.
        """
        cache_key = f"describe_trails:{include_shadow_trails}"
        if region is not None:
            cache_key += f":{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"CloudTrail: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        if not self.regions:
            logger.warning("CloudTrail: No regions specified")
            return no_client_result(service="CloudTrail", region="global")

        region = region or self.regions[0]
        client = self.get_client(region)
        if client is None:
            logger.warning(f"CloudTrail: No client available for region {region}")
            return no_client_result(service="CloudTrail", region=region)

        result = client.describe_trails(
            include_shadow_trails=include_shadow_trails
        )
        if is_error(result):
            # Never cached: a retry has to be able to re-issue the call.
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    def get_organization_trails(self) -> Mapping[str, Any]:
        """
        Get the organization trails.

        Filters :meth:`describe_trails`; issues no call of its own.

        Returns:
            ``{"trailList": [...]}`` holding only organization trails, or
            :meth:`describe_trails`'s error result unchanged. Passing the error
            through rather than returning an empty list is the point: "no
            organization trail exists" and "we could not list trails" must stay
            distinguishable.
        """
        response = self.describe_trails()
        if is_error(response):
            return response

        org_trails = [
            trail for trail in response.get('trailList', [])
            if trail.get('IsOrganizationTrail', False)
        ]
        logger.debug(f"CloudTrail: Found {len(org_trails)} organization trails")
        return {"trailList": org_trails}

    def get_trail_status(self, region: str, trail_arn: str) -> Mapping[str, Any]:
        """
        Get a trail's status, with caching.

        Args:
            region: AWS region name
            trail_arn: The trail ARN.

        Returns:
            The ``GetTrailStatus`` response, or an error result.
        """
        cache_key = f"trail_status:{trail_arn}:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"CloudTrail: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(f"CloudTrail: No client available for region {region}")
            return no_client_result(service="CloudTrail", region=region)

        result = client.get_trail_status(trail_arn)
        if is_error(result):
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    def get_event_selectors(self, region: str, trail_arn: str) -> Mapping[str, Any]:
        """
        Get a trail's event selectors, with caching.

        Args:
            region: AWS region name. Pass the trail's ``HomeRegion``.
            trail_arn: The trail ARN, not a bare name.

        Returns:
            The ``GetEventSelectors`` response, or an error result.
        """
        cache_key = f"event_selectors:{trail_arn}:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"CloudTrail: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(f"CloudTrail: No client available for region {region}")
            return no_client_result(service="CloudTrail", region=region)

        result = client.get_event_selectors(trail_arn)
        if is_error(result):
            # Never cached: a retry has to be able to re-issue the call.
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    def get_delegated_administrators(self) -> Mapping[str, Any]:
        """
        Get the Organizations delegated administrators for CloudTrail.

        Delegates to the scan's Organizations provider, which caches the answer
        once per scan per service principal.

        Returns:
            ``{"DelegatedAdministrators": [...]}``, or an error result.
        """
        return self.organization.delegated_administrators("cloudtrail.amazonaws.com")

    def _list_owned_buckets(self) -> Mapping[str, Any]:
        from sraverify.services.s3.client import S3Client

        key = "owned_buckets"
        if self._ctx._has("s3", key):
            return self._ctx._get("s3", key)
        result = S3Client(self.regions[0], ctx=self._ctx).list_owned_buckets()
        if not is_error(result) and isinstance(result.get("Buckets"), list):
            self._ctx._set("s3", key, result)
        return result

    def _get_object_lock_configuration(self, region: str, bucket: str) -> Mapping[str, Any]:
        from sraverify.services.s3.client import S3Client

        key = f"object_lock:{region}:{bucket}:{self.account_id}"
        if self._ctx._has("s3", key):
            return self._ctx._get("s3", key)
        from botocore.exceptions import InvalidRegionError
        from botocore.utils import validate_region_name

        try:
            validate_region_name(region)
        except InvalidRegionError as exc:
            return error_result(
                code="InvalidRegion", message=str(exc),
                operation="GetObjectLockConfiguration",
            )
        result = S3Client(region, ctx=self._ctx).get_object_lock_configuration(
            bucket, self.account_id
        )
        if not is_error(result):
            self._ctx._set("s3", key, result)
        return result
