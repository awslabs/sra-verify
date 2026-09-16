"""
SRA-CLOUDTRAIL-01: Organization CloudTrail Configuration.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck


class SRA_CLOUDTRAIL_01(CloudTrailCheck):
    """Check if an Organization trail is configured for the AWS Organization."""

    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-01",
        title="An Organization trail is configured for the AWS Organization",
        description=(
            "This check verifies that an organization trail is configured for your AWS Organization. "
            "It is important to have uniform logging strategy for your AWS environment. Organization trail "
            "logs all events for all AWS accounts in that organization and delivers logs to a single S3 bucket, "
            "CloudWatch Logs and Event Bridge. Organization trails are automatically applied to all member accounts "
            "in the organization. Member accounts can see the organization trail, but can't modify or delete it. "
            "Organization trail should be configured for all AWS regions even if you are not operating out of any region."
        ),
        check_logic=(
            "Check if at least one trail has IsOrganizationTrail set to true."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="CloudTrail",
        resource_type="AWS::CloudTrail::Trail",
        remediation=Remediation(
            text=(
                "Create a multi-region organization trail in the AWS Organizations "
                "management account."
            ),
            cli=(
                "aws cloudtrail create-trail --name org-trail --is-organization-trail "
                "--s3-bucket-name <bucket-name> --is-multi-region-trail --region <region>"
            ),
            console=(
                "CloudTrail console in the management account, Trails, Create trail, "
                "and select Enable for all accounts in my organization."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per organization trail, or one Finding when none exist.
        """
        # Get all trails using the base class method
        # This will use the cache if available or make API calls if needed
        trails_response = self.describe_trails()

        if "Error" in trails_response:
            error = trails_response['Error']
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    actual_value="No CloudTrail trail exists for this account, so no organization trail is configured",
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        all_trails = trails_response.get('trailList', [])

        # Filter for organization trails
        org_trails = [
            trail for trail in all_trails
            if trail.get('IsOrganizationTrail', False)
        ]

        if not org_trails:
            yield self.failed(
                region="global",
                resource_id=f"organization/{self.account_id}",
                checked_value="IsOrganizationTrail: true",
                actual_value="No organization trails found",
                remediation=(
                    "Create an organization trail in the management account using the AWS CLI command: "
                    f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{self.account_id} "
                    f"--is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                ),
            )
            return

        # If we have organization trails, create a PASS finding for each one
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')

            yield self.passed(
                region="global",
                resource_id=trail_arn,
                checked_value="IsOrganizationTrail: true",
                actual_value=f"Organization trail '{trail_name}' is configured",
            )
