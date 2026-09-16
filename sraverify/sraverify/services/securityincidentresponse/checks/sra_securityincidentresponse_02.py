"""
Check if the Security Incident Response membership is active.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityincidentresponse.base import SecurityIncidentResponseCheck


class SRA_SECURITYINCIDENTRESPONSE_02(SecurityIncidentResponseCheck):
    """Check if the Security Incident Response membership is active."""

    meta = CheckMeta(
        check_id="SRA-SECURITYINCIDENTRESPONSE-02",
        title="Security Incident Response membership active",
        description="Verifies that Security Incident Response membership is active",
        check_logic="Lists memberships and verifies status is Active",
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="SecurityIncidentResponse",
        resource_type="AWS::Organizations::DelegatedAdministrator",
        remediation=Remediation(
            text=(
                "Create an AWS Security Incident Response membership in the delegated "
                "administrator account and complete onboarding so the membership "
                "reaches the Active status."
            ),
            console=(
                "AWS Security Incident Response console, Get started, create a "
                "membership, then complete the onboarding steps until Membership "
                "status shows Active."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per membership, plus a summary Finding when no
            membership is active.
        """
        # Report against the region that actually holds the membership, so this
        # check and checks 03/04 agree on the region in their findings.
        region = self.discover_sir_region()

        response = self.list_memberships()

        if "Error" in response:
            error = response["Error"]
            if self.is_not_configured(error):
                # AWS reported the membership absent, which is the same finding as
                # the empty items list below.
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No Security Incident Response membership exists",
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation="Check IAM permissions for Security Incident Response API access"
                )
            return

        memberships = response.get("items", [])

        if not memberships:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="No Security Incident Response memberships found",
                remediation="Create a Security Incident Response membership through the AWS console or API"
            )
        else:
            active_found = False
            for membership in memberships:
                membership_id = membership.get("membershipId")
                status = membership.get("membershipStatus")

                if status == "Active":
                    active_found = True
                    yield self.passed(
                        region=region,
                        resource_id=membership_id,
                        actual_value=f"Membership {membership_id} is Active"
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=membership_id,
                        actual_value=f"Membership {membership_id} status is {status}",
                        remediation="Activate the Security Incident Response membership through the AWS console"
                    )

            if not active_found:
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No active Security Incident Response memberships found",
                    remediation="Activate an existing membership or create a new active membership"
                )
