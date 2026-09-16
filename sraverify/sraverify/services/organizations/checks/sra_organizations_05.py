"""
Check if organization has all features enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.organizations.base import OrganizationsCheck


class SRA_ORGANIZATIONS_05(OrganizationsCheck):
    """Check if organization has all features enabled."""

    meta = CheckMeta(
        check_id="SRA-ORGANIZATIONS-05",
        title="Organization has all features enabled",
        description=(
            "This check verifies that the organization has all features enabled. "
            "All features mode enables full governance capabilities including Service Control Policies (SCPs), "
            "tag policies, backup policies, and AI services opt-out policies. Organizations with only "
            "consolidated billing have limited governance capabilities."
        ),
        check_logic=(
            "Call DescribeOrganization API to retrieve organization details. "
            "Check passes if FeatureSet equals 'ALL', fails if FeatureSet equals 'CONSOLIDATED_BILLING'."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="Organizations",
        resource_type="AWS::Organizations::Organization",
        remediation=Remediation(
            text=(
                "Enable all features on the organization so that Service Control "
                "Policies, tag policies, backup policies, and AI services opt-out "
                "policies become available. All member accounts must accept the "
                "invitation to enable all features."
            ),
            cli="aws organizations enable-all-features",
            console=(
                "AWS Organizations console, Settings, "
                "Enable all features, Begin process for enabling all features."
            ),
        ),
        additional_urls=(
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the organization feature set.
        """
        # Organizations is a global service, use "global" as region
        region = "global"

        # Get organization details
        response = self.get_organization()

        # Check for errors
        if "Error" in response:
            error = response["Error"]
            if self.is_not_configured(error):
                # A declared semantic pair: AWS answered and the control is
                # absent. For Organizations that means either no organization
                # exists, or the policy type is not enabled.
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        f"AWS Organizations reports the control absent: "
                        f"{error['Code']}"
                    ),
                    checked_value="Organization FeatureSet",
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                    checked_value="Organization FeatureSet",
                )
            return

        # Extract organization details
        organization = response.get("Organization", {})
        org_id = organization.get("Id", "Unknown")
        feature_set = organization.get("FeatureSet", "Unknown")

        if feature_set == "ALL":
            yield self.passed(
                region=region,
                resource_id=org_id,
                actual_value=f"FeatureSet: {feature_set}",
                checked_value="Organization FeatureSet",
            )
        elif feature_set == "CONSOLIDATED_BILLING":
            yield self.failed(
                region=region,
                resource_id=org_id,
                actual_value=f"FeatureSet: {feature_set}",
                remediation=(
                    "Enable all features in AWS Organizations to gain full governance capabilities. "
                    "Navigate to AWS Organizations in the console and enable all features. "
                    "Note: This requires consent from all member accounts. "
                    "See: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html"
                ),
                checked_value="Organization FeatureSet",
            )
        else:
            yield self.error(
                region=region,
                resource_id=org_id,
                actual_value=f"Unknown FeatureSet: {feature_set}",
                remediation="Verify organization configuration",
                checked_value="Organization FeatureSet",
            )
