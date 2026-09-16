"""
SRA-CLOUDTRAIL-04: Organization CloudTrail Multi-Region Configuration.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck


class SRA_CLOUDTRAIL_04(CloudTrailCheck):
    """Check if organization trails are configured as multi-region trails."""

    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-04",
        title="Organization Trail is a multi-region trail",
        description=(
            "This check verifies whether the Organization trail is configured as a multi-region trail. "
            "This helps with visibility across your entire AWS environment, even for AWS Regions where "
            "you are not operating to ensure you detect any malicious and/or unauthorized activities."
        ),
        check_logic=(
            "Check if organization trails have IsMultiRegionTrail set to true."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.MANAGEMENT,
        service="CloudTrail",
        resource_type="AWS::CloudTrail::Trail",
        remediation=Remediation(
            text=(
                "Convert the organization trail to a multi-region trail so that events "
                "from every AWS Region are captured."
            ),
            cli=(
                "aws cloudtrail update-trail --name <trail-name> "
                "--is-multi-region-trail --region <home-region>"
            ),
            console=(
                "CloudTrail console, Trails, select the organization trail, Edit "
                "General details, and set Apply trail to all Regions to Yes."
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
        org_response = self.get_organization_trails()

        if "Error" in org_response:
            error = org_response['Error']
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

        org_trails = org_response.get('trailList', [])

        if not org_trails:
            yield self.failed(
                region="global",
                resource_id=f"organization/{self.account_id}",
                checked_value="IsMultiRegionTrail: true",
                actual_value="No organization trails found",
                remediation=(
                    "Create a multi-region organization trail in the management account using the AWS CLI command: "
                    f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{self.account_id} "
                    f"--is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                ),
            )
            return

        # Check each organization trail for multi-region configuration
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            is_multi_region_trail = trail.get('IsMultiRegionTrail', False)
            home_region = trail.get('HomeRegion', 'Unknown')

            if is_multi_region_trail:
                # Trail is a multi-region trail
                yield self.passed(
                    region="global",
                    resource_id=trail_arn,
                    checked_value="IsMultiRegionTrail: true",
                    actual_value=f"Organization trail '{trail_name}' is configured as a multi-region trail",
                )
            else:
                # Trail is not a multi-region trail
                yield self.failed(
                    region="global",
                    resource_id=trail_arn,
                    checked_value="IsMultiRegionTrail: true",
                    actual_value=f"Organization trail '{trail_name}' is not configured as a multi-region trail",
                    remediation=(
                        f"Update the organization trail '{trail_name}' to be a multi-region trail using the AWS CLI command: "
                        f"aws cloudtrail update-trail --name {trail_name} --is-multi-region-trail --region {home_region}"
                    ),
                )
