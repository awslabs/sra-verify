"""
SRA-CLOUDTRAIL-03: Organization CloudTrail Log File Validation.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck


class SRA_CLOUDTRAIL_03(CloudTrailCheck):
    """Check if organization trails have log file validation enabled."""

    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-03",
        title="Organization trail has Log File validation enabled",
        description=(
            "This check verifies that your organization trail has log file validation enabled. "
            "Validated log files are especially valuable in security and forensic investigations. "
            "CloudTrail log file integrity validation uses industry standard algorithms: SHA-256 for "
            "hashing and SHA-256 with RSA for digital signing. This makes it computationally unfeasible "
            "to modify, delete or forge CloudTrail log files without detection."
        ),
        check_logic=(
            "Check if organization trails have LogFileValidationEnabled set to true."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.MANAGEMENT,
        service="CloudTrail",
        resource_type="AWS::CloudTrail::Trail",
        remediation=Remediation(
            text=(
                "Enable log file integrity validation on the organization trail so that "
                "tampering with delivered log files is detectable."
            ),
            cli=(
                "aws cloudtrail update-trail --name <trail-name> "
                "--enable-log-file-validation --region <home-region>"
            ),
            console=(
                "CloudTrail console, Trails, select the organization trail, Edit "
                "Additional settings, and set Log file validation to Enabled."
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
                checked_value="LogFileValidationEnabled: true",
                actual_value="No organization trails found",
                remediation=(
                    "Create an organization trail with log file validation in the management account using the AWS CLI command: "
                    f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{self.account_id} "
                    f"--enable-log-file-validation --is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                ),
            )
            return

        # Check each organization trail for log file validation
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            log_file_validation_enabled = trail.get('LogFileValidationEnabled', False)
            home_region = trail.get('HomeRegion', 'Unknown')

            if log_file_validation_enabled:
                # Trail has log file validation enabled
                yield self.passed(
                    region="global",
                    resource_id=trail_arn,
                    checked_value="LogFileValidationEnabled: true",
                    actual_value=f"Organization trail '{trail_name}' has log file validation enabled",
                )
            else:
                # Trail does not have log file validation enabled
                yield self.failed(
                    region="global",
                    resource_id=trail_arn,
                    checked_value="LogFileValidationEnabled: true",
                    actual_value=f"Organization trail '{trail_name}' does not have log file validation enabled",
                    remediation=(
                        f"Update the organization trail '{trail_name}' to enable log file validation using the AWS CLI command: "
                        f"aws cloudtrail update-trail --name {trail_name} --enable-log-file-validation --region {home_region}"
                    ),
                )
