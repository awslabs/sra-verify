"""
Check that privileged root actions in member accounts are enabled (SRA-IAM-03).
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import GLOBAL_REGION, Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.iam.base import IAMCheck

#: The ListOrganizationsFeatures value this check requires.
_FEATURE = "RootSessions"


class SRA_IAM_03(IAMCheck):
    """Privileged root actions in member accounts are enabled for central use."""

    meta = CheckMeta(
        check_id="SRA-IAM-03",
        title="Privileged root actions in member accounts are enabled for central use",
        description=(
            "This check verifies that the organization has enabled privileged root "
            "actions in member accounts, the second feature of centralized root access. "
            "It lets the management account and the IAM delegated administrator start "
            "a short-lived, task-scoped root session in a member account with "
            "sts:AssumeRoot, so tasks that need root, such as unlocking a misconfigured "
            "S3 bucket or SQS queue policy, deleting root credentials, or allowing "
            "password recovery, are performed centrally rather than by signing in as the "
            "member account root user. AWS SRA recommends enforcing these privileged "
            "root tasks from the delegated administrator."
        ),
        check_logic=(
            "Call IAM ListOrganizationsFeatures from the management account. PASS if "
            "EnabledFeatures contains RootSessions. FAIL if it does not, or if IAM "
            "trusted access, the organization, or all features is not enabled. Any other "
            "error is an ERROR. One global row."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="IAM",
        resource_type="AWS::Organizations::Organization",
        remediation=Remediation(
            text=(
                "Enable trusted access for IAM in AWS Organizations, then enable "
                "privileged root actions in member accounts from the management account."
            ),
            cli=(
                "aws organizations enable-aws-service-access --service-principal iam.amazonaws.com\n"
                "aws iam enable-organizations-root-sessions"
            ),
            console=(
                "IAM console in the management account, Root access management, Enable, "
                "select Privileged root actions in member accounts, Enable."
            ),
        ),
        sra_sections=("Management account", "AWS Identity and Access Management"),
        additional_urls=(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user-privileged-task.html",
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
