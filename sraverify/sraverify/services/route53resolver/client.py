"""
Route 53 Resolver client, for query logging configuration associations and the
VPC inventory they are matched against.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

Reaches ``route53resolver`` and ``ec2``, both acquired in ``__init__``.
"""
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class Route53ResolverClient(AWSClient):
    """Client for interacting with Amazon Route 53 Resolver."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize the Route 53 Resolver client wrapper for a region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan; the underlying boto3 clients
                are obtained via ``ctx.get_client(...)`` so the per-scan client
                cache and bounded ``Client_Config`` are applied.
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('route53resolver', region=region)
        # The VPC inventory this service's associations are matched against. A second
        # binding rather than an import of EC2Check: no base inherits another base.
        self.ec2_client = ctx.get_client('ec2', region=region)

    def list_resolver_query_log_config_associations(self) -> Mapping[str, Any]:
        """
        List every Resolver query logging configuration association in this Region.

        Returns:
            ``{"ResolverQueryLogConfigAssociations": [...]}`` with every page
            merged, on success, or the error result.
        """
        try:
            associations = []
            paginator = self.client.get_paginator(
                'list_resolver_query_log_config_associations'
            )
            for page in paginator.paginate():
                associations.extend(page.get('ResolverQueryLogConfigAssociations', []))
            return {"ResolverQueryLogConfigAssociations": associations}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_vpcs(self) -> Mapping[str, Any]:
        """
        List every VPC visible to the account in this Region.

        The result includes VPCs shared into the account through AWS RAM; the
        check filters on ``OwnerId``.

        Returns:
            ``{"Vpcs": [...]}`` with every page merged, on success, or the error
            result.
        """
        try:
            vpcs = []
            for page in self.ec2_client.get_paginator('describe_vpcs').paginate():
                vpcs.extend(page.get('Vpcs', []))
            return {"Vpcs": vpcs}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
