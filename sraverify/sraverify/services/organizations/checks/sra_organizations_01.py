"""
Check if AWS Organizations is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.organizations.base import OrganizationsCheck


class SRA_ORGANIZATIONS_01(OrganizationsCheck):
    """Check if AWS Organizations is enabled."""

    meta = CheckMeta(
        check_id="SRA-ORGANIZATIONS-01",
        title="AWS Organizations is enabled",
        description=(
            "This check verifies that AWS Organizations is enabled for the account. "
            "AWS Organizations enables central management and governance of multiple AWS accounts, "
            "providing consolidated billing, account management, and policy-based controls."
        ),
        check_logic=(
            "Call DescribeOrganization API to confirm an organization exists. "
            "Check passes if an organization is found, fails if no organization exists."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="Organizations",
        resource_type="AWS::Organizations::Organization",
        remediation=Remediation(
            text=(
                "Create an AWS Organization from this account so that accounts, "
                "billing, and policy-based controls are centrally managed."
            ),
            cli="aws organizations create-organization --feature-set ALL",
            console=(
                "AWS Organizations console, Create an organization, "
                "Create organization."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the organization.
        """
        # Organizations is a global service, use "global" as region
        region = "global"

        # Get organization details
        response = self.get_organization()

        # Check for errors
        if "Error" in response:
            error = response["Error"]
            error_code = response["Error"].get("Code", "")
            error_message = response["Error"].get("Message", "Unknown error")

            # AWSOrganizationsNotInUseException means no organization exists
            if self.is_not_configured(error):
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No organization exists",
                    remediation=(
                        "Create an AWS Organization by navigating to AWS Organizations in the console "
                        "and clicking 'Create organization', or use the AWS CLI command: "
                        "aws organizations create-organization"
                    ),
                    checked_value="AWS Organizations enabled",
                )
            else:
                # Other errors (permissions, service errors)
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation="Check IAM permissions for Organizations API access",
                    checked_value="AWS Organizations enabled",
                )
            return

        # Organization exists - extract details
        organization = response.get("Organization", {})
        org_id = organization.get("Id", "Unknown")

        yield self.passed(
            region=region,
            resource_id=org_id,
            actual_value=f"Organization exists: {org_id}",
            checked_value="AWS Organizations enabled",
        )
