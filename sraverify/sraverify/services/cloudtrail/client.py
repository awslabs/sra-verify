"""
CloudTrail client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

Reaches ``cloudtrail``, ``organizations`` and ``sts``. All three boto3 clients are
acquired in ``__init__``.
"""
from typing import Any, List, Mapping, Optional

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class CloudTrailClient(AWSClient):
    """Client for interacting with AWS CloudTrail."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize CloudTrail client for a specific region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan; the underlying boto3 clients
                are obtained via ``ctx.get_client(...)`` so the per-scan client
                cache and bounded ``Client_Config`` are applied.
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('cloudtrail', region=region)
        self.org_client = ctx.get_client('organizations', region=region)
        # Moved out of get_account_id, which acquired it per call.
        self.sts_client = ctx.get_client('sts')

    def describe_trails(
        self,
        trail_name_list: Optional[List[str]] = None,
        include_shadow_trails: bool = True,
    ) -> Mapping[str, Any]:
        """
        Describe the trails visible from this Region.

        Args:
            trail_name_list: Trail names or ARNs to describe. ``None`` means all.
            include_shadow_trails: Whether to include shadow trails.

        Returns:
            ``{"trailList": [...]}`` on success, or the error result.

            The whole response, not the extracted list. All 13 CloudTrail checks
            iterate this, so each must test for ``"Error"`` before doing so --
            handing them an error result unguarded raises rather than
            mis-reporting, which is loud but still loses every other Region's rows
            for that check.
        """
        try:
            params: dict[str, Any] = {
                "includeShadowTrails": include_shadow_trails
            }
            if trail_name_list is not None:
                params["trailNameList"] = trail_name_list
            return self.client.describe_trails(**params)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_trail_status(self, trail_arn: str) -> Mapping[str, Any]:
        """
        Get a trail's status.

        Args:
            trail_arn: The trail ARN.

        Returns:
            The ``GetTrailStatus`` response on success, or the error result.
        """
        try:
            return self.client.get_trail_status(Name=trail_arn)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_event_selectors(self, trail_arn: str) -> Mapping[str, Any]:
        """
        Get a trail's event selectors.

        Args:
            trail_arn: The trail ARN. Pass the full owner ARN, never a bare name:
                a name resolves against the *calling* account, so an organization
                trail owned by the management account answers
                ``TrailNotFoundException`` when asked for by name from anywhere
                else.

        Returns:
            The ``GetEventSelectors`` response on success, or the error result.

            A trail carries either ``EventSelectors`` (basic) or
            ``AdvancedEventSelectors``, never both, and the whole response is
            returned so the caller can tell which.
        """
        try:
            return self.client.get_event_selectors(TrailName=trail_arn)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_delegated_administrators(
        self, service_principal: str = "cloudtrail.amazonaws.com"
    ) -> Mapping[str, Any]:
        """
        List Organizations delegated administrators for a service principal.

        Args:
            service_principal: Service principal to check.

        Returns:
            ``{"DelegatedAdministrators": [...]}`` on success, or the error
            result.
        """
        try:
            return self.org_client.list_delegated_administrators(
                ServicePrincipal=service_principal
            )
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
