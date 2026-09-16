"""
SRA-CLOUDTRAIL-06: Organization CloudTrail Global Service Events.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck


class SRA_CLOUDTRAIL_06(CloudTrailCheck):
    """Check if organization trails are configured to publish events from global services."""

    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-06",
        title="Organization trail is configured to publish events from global services",
        description=(
            "This check verifies that your organization trail is configured to publish event from AWS global services. "
            "The organization trail should capture events from global services such as AWS IAM, AWS STS and Amazon CloudFront. "
            "Trails created using CloudTrail console by default have global service event configured but if you are creating "
            "trail with AWS CLI, AWS SDKs, or CloudTrail API you have to specify to included global services events."
        ),
        check_logic=(
            "Check if organization trails have IncludeGlobalServiceEvents set to true."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.MANAGEMENT,
        service="CloudTrail",
        resource_type="AWS::CloudTrail::Trail",
        remediation=Remediation(
            text=(
                "Enable global service events on the organization trail so that IAM, "
                "STS and CloudFront activity is captured."
            ),
            cli=(
                "aws cloudtrail update-trail --name <trail-name> "
                "--include-global-service-events --region <home-region>"
            ),
            console=(
                "CloudTrail console, Trails, select the organization trail, Edit "
                "General details, and set Include global service events to Yes."
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
                checked_value="IncludeGlobalServiceEvents: true",
                actual_value="No organization trails found",
                remediation=(
                    "Create an organization trail with global service events in the management account using the AWS CLI command: "
                    f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{self.account_id} "
                    f"--include-global-service-events --is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                ),
            )
            return

        # Check each organization trail for global service events
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            include_global_service_events = trail.get('IncludeGlobalServiceEvents', False)
            home_region = trail.get('HomeRegion', 'Unknown')

            if include_global_service_events:
                # Trail includes global service events
                yield self.passed(
                    region="global",
                    resource_id=trail_arn,
                    checked_value="IncludeGlobalServiceEvents: true",
                    actual_value=f"Organization trail '{trail_name}' is configured to publish events from global services",
                )
            else:
                # Trail does not include global service events
                yield self.failed(
                    region="global",
                    resource_id=trail_arn,
                    checked_value="IncludeGlobalServiceEvents: true",
                    actual_value=f"Organization trail '{trail_name}' is not configured to publish events from global services",
                    remediation=(
                        f"Update the organization trail '{trail_name}' to include global service events using the AWS CLI command: "
                        f"aws cloudtrail update-trail --name {trail_name} --include-global-service-events --region {home_region}"
                    ),
                )
