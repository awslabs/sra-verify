"""
SRA-CLOUDTRAIL-12: CloudTrail Delegated Administrator Configuration.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck


class SRA_CLOUDTRAIL_12(CloudTrailCheck):
    """Check if CloudTrail service administration is delegated out of AWS Organization management account."""

    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-12",
        title="Delegated Administrator set for CloudTrail",
        description=(
            "This check verifies whether CloudTrail service administration is delegated out of AWS Organization "
            "management account. The delegated administrator has permissions to create and manage analyzers "
            "with the AWS organization as the zone of trust."
        ),
        check_logic=(
            "Check if there is at least one delegated administrator for CloudTrail service."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.MANAGEMENT,
        service="CloudTrail",
        resource_type="AWS::CloudTrail::Trail",
        remediation=Remediation(
            text=(
                "Register a delegated administrator for the cloudtrail.amazonaws.com "
                "service principal from the AWS Organizations management account."
            ),
            cli=(
                "aws organizations register-delegated-administrator "
                "--account-id <account-id> --service-principal cloudtrail.amazonaws.com"
            ),
            console=(
                "CloudTrail console in the management account, Settings, and set the "
                "delegated administrator account."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per delegated administrator, or one Finding when none exist.
        """
        # Get delegated administrators for CloudTrail
        # This will use the cache if available or make API calls if needed
        delegated_admins = self.get_delegated_administrators()

        if not delegated_admins:
            yield self.failed(
                region="global",
                resource_id=f"organization/{self.account_id}",
                checked_value="At least one delegated administrator for CloudTrail",
                actual_value="No delegated administrator configured for CloudTrail",
                remediation=(
                    "Register a delegated administrator for CloudTrail using the AWS CLI command: "
                    "aws organizations register-delegated-administrator "
                    "--account-id ACCOUNT_ID --service-principal cloudtrail.amazonaws.com"
                ),
            )
            return

        # If we have delegated administrators, create a PASS finding for each one
        for admin in delegated_admins:
            admin_id = admin.get('Id', 'Unknown')
            admin_name = admin.get('Name', 'Unknown')

            # Create a resource ID that includes the delegated admin info
            resource_id = f"cloudtrail arn has delegated administrator set to {admin_id}"

            yield self.passed(
                region="global",
                resource_id=resource_id,
                checked_value="At least one delegated administrator for CloudTrail",
                actual_value=f"CloudTrail has delegated administrator: {admin_id} ({admin_name})",
            )
