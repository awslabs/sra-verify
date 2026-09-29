"""
Check that centralized root credentials management is enabled (SRA-IAM-02).
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import GLOBAL_REGION, Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.iam.base import IAMCheck

#: The ListOrganizationsFeatures value this check requires.
_FEATURE = "RootCredentialsManagement"


class SRA_IAM_02(IAMCheck):
    """Centralized root credentials management is enabled for member accounts."""

    meta = CheckMeta(
        check_id="SRA-IAM-02",
        title="Centralized root credentials management is enabled for member accounts",
        description=(
            "This check verifies that the organization has enabled root credentials "
            "management, one of the two features of centralized root access for member "
            "accounts. With it enabled, the management account and the IAM delegated "
            "administrator can audit and delete the root user credentials of any member "
            "account, and new member accounts are created without root user "
            "credentials. AWS SRA recommends enforcing centralized management of root "
            "access so that member account root credentials cannot be recovered or used "
            "at scale."
        ),
        check_logic=(
            "Call IAM ListOrganizationsFeatures from the management account. PASS if "
            "EnabledFeatures contains RootCredentialsManagement. FAIL if it does not, or "
            "if IAM trusted access, the organization, or all features is not enabled. "
            "Any other error is an ERROR. One global row."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="IAM",
        resource_type="AWS::Organizations::Organization",
        remediation=Remediation(
            text=(
                "Enable trusted access for IAM in AWS Organizations, then enable root "
                "credentials management from the management account."
            ),
            cli=(
                "aws organizations enable-aws-service-access --service-principal iam.amazonaws.com\n"
                "aws iam enable-organizations-root-credentials-management"
            ),
            console=(
                "IAM console in the management account, Root access management, Enable, "
                "select Root credentials management, Enable."
            ),
        ),
        sra_sections=("Management account", "AWS Identity and Access Management"),
        additional_urls=(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html",
            "https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListOrganizationsFeatures.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One global Finding for the organization.
        """
        response = self.get_organizations_features()

        if "Error" in response:
            error = response["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region=GLOBAL_REGION,
                    resource_id=self.account_id,
                    actual_value=(
                        "Centralized root access is unavailable: "
                        f"{error['Code']}: {error['Message']}"
                    ),
                )
            else:
                yield self.error(
                    region=GLOBAL_REGION,
                    resource_id=self.account_id,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        organization_id = response.get("OrganizationId") or self.account_id
        # Sorted so the cell is identical across runs.
        features = sorted(response.get("EnabledFeatures") or [])
        enabled = ", ".join(features) if features else "none"

        if _FEATURE in features:
            yield self.passed(
                region=GLOBAL_REGION,
                resource_id=organization_id,
                actual_value=f"{_FEATURE} is enabled (enabled features: {enabled})",
            )
        else:
            yield self.failed(
                region=GLOBAL_REGION,
                resource_id=organization_id,
                actual_value=f"{_FEATURE} is not enabled (enabled features: {enabled})",
            )
