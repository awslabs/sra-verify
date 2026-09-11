"""
Check if Security Incident Response proactive response (Triage) is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityincidentresponse.base import SecurityIncidentResponseCheck


class SRA_SECURITYINCIDENTRESPONSE_03(SecurityIncidentResponseCheck):
    """Check if Security Incident Response proactive response (Triage) is enabled."""

    meta = CheckMeta(
        check_id="SRA-SECURITYINCIDENTRESPONSE-03",
        title="Security Incident Response proactive response enabled",
        description=(
            "Verifies that Security Incident Response proactive response (Triage) "
            "feature is enabled"
        ),
        check_logic=(
            "Lists memberships and checks if Triage opt-in feature is enabled"
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="SecurityIncidentResponse",
        resource_type="AWS::Organizations::DelegatedAdministrator",
        remediation=Remediation(
            text=(
                "Opt in to the proactive response (Triage) feature on the AWS "
                "Security Incident Response membership."
            ),
            console=(
                "AWS Security Incident Response console, Settings, membership "
                "settings, enable Proactive response (Triage)."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per membership.
        """
        # Discover the region where Security Incident Response is configured
        region = self.discover_sir_region()

        # First get list of memberships
        memberships_response = self.list_memberships()

        if "Error" in memberships_response:
            yield self.error(
                region=region,
                resource_id=None,
                actual_value=memberships_response["Error"].get("Message", "Unknown error"),
                remediation="Check IAM permissions for Security Incident Response API access"
            )
            return

        memberships = memberships_response.get("items", [])

        if not memberships:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="No Security Incident Response memberships found",
                remediation="Create a Security Incident Response membership first"
            )
            return

        # Check each membership for proactive response
        for membership in memberships:
            membership_id = membership.get("membershipId")

            # Get detailed membership info
            membership_details = self.get_membership(membership_id)

            if "Error" in membership_details:
                yield self.error(
                    region=region,
                    resource_id=membership_id,
                    actual_value=membership_details["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Security Incident Response GetMembership API access"
                )
                continue

            # Check opt-in features for Triage
            opt_in_features = membership_details.get("optInFeatures", [])
            triage_enabled = False

            for feature in opt_in_features:
                if feature.get("featureName") == "Triage" and feature.get("isEnabled"):
                    triage_enabled = True
                    break

            if triage_enabled:
                yield self.passed(
                    region=region,
                    resource_id=membership_id,
                    actual_value="Proactive response (Triage) is enabled"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=membership_id,
                    actual_value="Proactive response (Triage) is not enabled",
                    remediation="Enable proactive response in the Security Incident Response console under membership settings"
                )
