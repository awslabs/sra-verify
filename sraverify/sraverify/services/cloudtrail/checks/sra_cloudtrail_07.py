"""
SRA-CLOUDTRAIL-07: Organization CloudTrail Active Logging.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck


class SRA_CLOUDTRAIL_07(CloudTrailCheck):
    """Check if organization trails are actively publishing events."""

    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-07",
        title="Organization trail is actively publishing events",
        description=(
            "This check verifies that your organization trail is running and actively logging events. "
            "If a trail is modified to stop logging, accidently or by malicious user, you will not have "
            "visibility into any API activity across your AWS environment."
        ),
        check_logic=(
            "Check if organization trails have IsLogging set to true in their status."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="CloudTrail",
        resource_type="AWS::CloudTrail::Trail",
        remediation=Remediation(
            text="Start logging on the organization trail.",
            cli=(
                "aws cloudtrail start-logging --name <trail-name> --region <home-region>"
            ),
            console=(
                "CloudTrail console, Trails, select the organization trail, and choose "
                "Start logging."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per organization trail, or one Finding when none exist.
        """
        # Get organization trails
        org_trails = self.get_organization_trails()

        if not org_trails:
            yield self.failed(
                region="global",
                resource_id=f"organization/{self.account_id}",
                checked_value="IsLogging: true",
                actual_value="No organization trails found",
                remediation=(
                    "Create an organization trail in the management account using the AWS CLI command: "
                    f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{self.account_id} "
                    f"--is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'} && "
                    f"aws cloudtrail start-logging --name org-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                ),
            )
            return

        # Check each organization trail for active logging
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            home_region = trail.get('HomeRegion', 'Unknown')

            # Get trail status to check if logging is enabled
            trail_status = self.get_trail_status(home_region, trail_arn)
            is_logging = trail_status.get('IsLogging', False)

            if is_logging:
                # Trail is actively logging
                yield self.passed(
                    region="global",
                    resource_id=trail_arn,
                    checked_value="IsLogging: true",
                    actual_value=f"Organization trail '{trail_name}' is actively logging events",
                )
            else:
                # Trail is not actively logging
                yield self.failed(
                    region="global",
                    resource_id=trail_arn,
                    checked_value="IsLogging: true",
                    actual_value=f"Organization trail '{trail_name}' is not actively logging events",
                    remediation=(
                        f"Start logging for the organization trail '{trail_name}' using the AWS CLI command: "
                        f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                    ),
                )
