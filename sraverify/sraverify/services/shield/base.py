"""
Base class for Shield security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"shield"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

Shield is a global service and every concrete Shield check passes ``"us-east-1"``
to the accessors below. ``_setup_clients`` still builds one wrapper per Region in
``self.regions``, so this class does not need to know which Region the checks will
pin to.

Three accessors -- :meth:`get_lambda_function`, :meth:`get_web_acl_for_resource`
and :meth:`get_cloudwatch_alarms_for_resource` -- are **uncached**, because each is
parameterized on a resource ARN or a function name. They still owe the no-client
error result and the never-cache-a-failure guarantee.
"""
from typing import Any, ClassVar, Dict, Optional

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.services.shield.client import ShieldClient
from sraverify.core.logging import logger


class ShieldCheck(SecurityCheck):
    """Base class for all Shield security checks."""

    #: Namespace string used for ``ScanContext`` cache reads/writes
    #: (Requirement 5.10).
    NAMESPACE = "shield"

    #: The pairs that mean "the control is not configured".
    #:
    #: All fourteen Shield checks already reached this conclusion by hand, with an
    #: inline ``error_code == "ResourceNotFoundException"`` compare repeated
    #: fourteen times. Declaring it once is what stops those fourteen copies
    #: drifting, and what keeps the judgement keyed by *operation* -- the same code
    #: means "no Shield Advanced subscription" through DescribeSubscription and
    #: "that Lambda function does not exist" through GetFunction, and both are the
    #: control being absent, but they are separate facts and are declared
    #: separately.
    #:
    #: ``ListProtections`` and ``DescribeDRTAccess`` are declared for the same code
    #: on the strength of a live observation, and the first draft of this table
    #: omitted them on the reasoning that "no protections" arrives as a successful
    #: response with an empty ``Protections`` list. That reasoning is right about an
    #: account that *has* a subscription and wrong about one that does not: in an
    #: unsubscribed account both calls fail outright with
    #: ``ResourceNotFoundException: The subscription does not exist.`` A live
    #: organization scan caught the omission: ten checks moved FAIL to ERROR
    #: against records that were plainly semantic.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "DescribeSubscription": {
            "ResourceNotFoundException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/"
                    "API_DescribeSubscription.html -- ResourceNotFoundException is "
                    "returned when the account has no Shield Advanced "
                    "subscription, which is exactly what these checks test for. "
                    "All fourteen Shield checks already classified it this way "
                    "with an inline code compare before this table existed."
                ),
            ),
        },
        "GetSubscriptionState": {
            "ResourceNotFoundException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/"
                    "API_GetSubscriptionState.html -- same absent-subscription "
                    "condition as DescribeSubscription, reached through the "
                    "status call the checks use to decide ACTIVE versus INACTIVE."
                ),
            ),
        },
        "ListProtections": {
            "ResourceNotFoundException": NotConfigured(
                evidence=(
                    "Observed 2026-09-16 in a controlled account with no "
                    "Shield Advanced subscription: "
                    "aws_call_failed operation=ListProtections region=us-east-1 "
                    "code=ResourceNotFoundException message=\"The subscription "
                    "does not exist.\" -- byte-identical to the message "
                    "DescribeSubscription returns for the same condition, so this "
                    "is the absent subscription and not an absent protection. Nine "
                    "checks read this call and all nine reported it as a FAIL by "
                    "hand before this table existed."
                ),
            ),
        },
        "DescribeDRTAccess": {
            "ResourceNotFoundException": NotConfigured(
                evidence=(
                    "Observed 2026-09-16 in the same unsubscribed account: "
                    "aws_call_failed operation=DescribeDRTAccess region=us-east-1 "
                    "code=ResourceNotFoundException message=\"The subscription "
                    "does not exist.\" -- the same absent-subscription condition. "
                    "SRA-SHIELD-08 asks whether the Shield Response Team has "
                    "access, and without a subscription it cannot, so the control "
                    "is absent rather than undetermined."
                ),
            ),
        },
        "GetFunction": {
            "ResourceNotFoundException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/lambda/latest/api/"
                    "API_GetFunction.html -- ResourceNotFoundException is returned "
                    "when the named function does not exist. SRA-SHIELD-13 asks "
                    "whether a Shield response Lambda exists, so its absence is "
                    "the control being absent rather than an inability to look."
                ),
            ),
        },
        "GetWebACLForResource": {
            "WAFNonexistentItemException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/waf/latest/APIReference/"
                    "API_GetWebACLForResource.html -- WAFNonexistentItemException "
                    "means the resource has no associated web ACL. The client's "
                    "CloudFront branch synthesizes the same code for a "
                    "distribution whose WebACLId is empty, so one declaration "
                    "covers both paths of SRA-SHIELD-12."
                ),
            ),
        },
    }

    def _setup_clients(self):
        """Set up Shield clients for each region.

        The underlying boto3 ``shield`` clients (and the auxiliary
        ``lambda``/``wafv2``/``cloudwatch``/``cloudfront`` clients used by
        helper methods) are obtained via ``self._ctx.get_client(...)``
        inside :class:`ShieldClient`, so they share the bounded
        ``Client_Config`` and de-duplicate across service base classes
        that need the same client in the same region.
        """
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = ShieldClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[ShieldClient]:
        """
        Get Shield client for a specific region.

        Args:
            region: AWS region name

        Returns:
            ShieldClient for the region or None if not available
        """
        return self._clients.get(region)

    def get_subscription_state(self, region: str) -> Dict[str, Any]:
        """
        Get Shield Advanced subscription state with caching.

        Reads from / writes to the ``ScanContext``'s ``"shield"`` namespace,
        so the cache is per-scan rather than process-wide.

        Args:
            region: AWS region name

        Returns:
            The ``DescribeSubscription`` response on success, or an error result.
        """
        cache_key = f"subscription_state:{region}"

        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Shield: Using cached subscription state for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return no_client_result(service="Shield", region=region)

        logger.debug(f"Shield: Fetching subscription state for {region}")
        subscription = client.get_subscription_state()

        if is_error(subscription):
            # Never cached: a retry has to be able to re-issue the call.
            return subscription

        self._ctx._set(self.NAMESPACE, cache_key, subscription)
        logger.debug(f"Shield: Cached subscription state for {region}")

        return subscription

    def get_subscription_status(self, region: str) -> Dict[str, Any]:
        """
        Get Shield Advanced subscription status (ACTIVE/INACTIVE) with caching.

        Reads from / writes to the ``ScanContext``'s ``"shield"`` namespace,
        so the cache is per-scan rather than process-wide.

        Args:
            region: AWS region name

        Returns:
            The ``GetSubscriptionState`` response on success, or an error result.
        """
        cache_key = f"subscription_status:{region}"

        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Shield: Using cached subscription status for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return no_client_result(service="Shield", region=region)

        logger.debug(f"Shield: Fetching subscription status for {region}")
        status = client.get_subscription_status()

        if is_error(status):
            # Never cached: a retry has to be able to re-issue the call.
            return status

        self._ctx._set(self.NAMESPACE, cache_key, status)
        logger.debug(f"Shield: Cached subscription status for {region}")

        return status

    def list_protections(self, region: str, resource_type: str = None) -> Dict[str, Any]:
        """
        List Shield Advanced protections with caching.

        Reads from / writes to the ``ScanContext``'s ``"shield"`` namespace,
        so the cache is per-scan rather than process-wide.

        Args:
            region: AWS region name
            resource_type: Optional resource type filter

        Returns:
            The ``ListProtections`` response on success, or an error result.
        """
        cache_key = f"protections:{region}:{resource_type or 'all'}"

        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Shield: Using cached protections for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return no_client_result(service="Shield", region=region)

        logger.debug(f"Shield: Listing protections for {region}")
        protections = client.list_protections(resource_type)

        if is_error(protections):
            # Never cached: a retry has to be able to re-issue the call.
            return protections

        self._ctx._set(self.NAMESPACE, cache_key, protections)
        logger.debug(f"Shield: Cached protections for {region}")

        return protections

    def describe_drt_access(self, region: str) -> Dict[str, Any]:
        """
        Describe Shield Response Team (SRT) access configuration with caching.

        Reads from / writes to the ``ScanContext``'s ``"shield"`` namespace,
        so the cache is per-scan rather than process-wide.

        Args:
            region: AWS region name

        Returns:
            The ``DescribeDRTAccess`` response on success, or an error result.
        """
        cache_key = f"drt_access:{region}"

        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Shield: Using cached DRT access for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return no_client_result(service="Shield", region=region)

        logger.debug(f"Shield: Describing DRT access for {region}")
        drt_access = client.describe_drt_access()

        if is_error(drt_access):
            # Never cached: a retry has to be able to re-issue the call.
            return drt_access

        self._ctx._set(self.NAMESPACE, cache_key, drt_access)
        logger.debug(f"Shield: Cached DRT access for {region}")

        return drt_access

    def get_lambda_function(self, region: str, function_name: str) -> Dict[str, Any]:
        """
        Get Lambda function details.

        This helper is intentionally uncached: the underlying boto3 client
        is reused per-scan via the ``ScanContext``, but the response itself
        varies per ``function_name`` and is not worth caching at this layer.

        Args:
            region: AWS region name
            function_name: Name of the Lambda function

        Returns:
            The ``GetFunction`` response on success, or an error result.
        """
        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return no_client_result(service="Shield", region=region)

        logger.debug(f"Shield: Getting Lambda function {function_name} for {region}")
        return client.get_lambda_function(function_name)

    def get_web_acl_for_resource(self, region: str, resource_arn: str) -> Dict[str, Any]:
        """
        Get WAF web ACL associated with a resource.

        This helper is intentionally uncached: the underlying boto3 client
        is reused per-scan via the ``ScanContext``, but the response itself
        varies per ``resource_arn`` and is not worth caching at this layer.

        Args:
            region: AWS region name
            resource_arn: ARN of the resource

        Returns:
            The web ACL association on success, or an error result.
        """
        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return no_client_result(service="Shield", region=region)

        logger.debug(f"Shield: Getting web ACL for resource {resource_arn} in {region}")
        return client.get_web_acl_for_resource(resource_arn)

    def get_cloudwatch_alarms_for_resource(self, region: str, resource_arn: str) -> Dict[str, Any]:
        """
        Get CloudWatch alarms for Shield Advanced DDoS metrics for a resource.

        This helper is intentionally uncached: the underlying boto3 client
        is reused per-scan via the ``ScanContext``, but the response itself
        varies per ``resource_arn`` and is not worth caching at this layer.

        Args:
            region: AWS region name
            resource_arn: ARN of the resource

        Returns:
            ``{"DDoSDetectedAlarms": [...]}`` on success, or an error result.
        """
        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return no_client_result(service="Shield", region=region)

        logger.debug(f"Shield: Getting CloudWatch alarms for resource {resource_arn} in {region}")
        return client.get_cloudwatch_alarms_for_resource(resource_arn)
