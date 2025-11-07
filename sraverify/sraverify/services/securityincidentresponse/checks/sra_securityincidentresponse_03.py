from typing import Dict, List, Any
from sraverify.services.securityincidentresponse.base import SecurityIncidentResponseCheck

class SRA_SECURITYINCIDENTRESPONSE_03(SecurityIncidentResponseCheck):
    def __init__(self):
        super().__init__()
        self.account_type = "audit"
        self.check_id = "SRA-SECURITYINCIDENTRESPONSE-03"
        self.check_name = "Security Incident Response proactive response enabled"
        self.description = "Verifies that Security Incident Response proactive response (Triage) feature is enabled"
        self.severity = "MEDIUM"
        self.check_logic = "Lists memberships and checks if Triage opt-in feature is enabled"

    def execute(self) -> List[Dict[str, Any]]:
        # Discover the region where Security Incident Response is configured
        region = self.discover_sir_region()

        # First get list of memberships
        memberships_response = self.list_memberships()

        if "Error" in memberships_response:
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value=memberships_response["Error"].get("Message", "Unknown error"),
                remediation="Check IAM permissions for Security Incident Response API access"
            ))
            return self.findings

        memberships = memberships_response.get("items", [])

        if not memberships:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="No Security Incident Response memberships found",
                remediation="Create a Security Incident Response membership first"
            ))
            return self.findings

        # Check each membership for proactive response
        for membership in memberships:
            membership_id = membership.get("membershipId")

            # Get detailed membership info
            membership_details = self.get_membership(membership_id)

            if "Error" in membership_details:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=membership_id,
                    actual_value=membership_details["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Security Incident Response GetMembership API access"
                ))
                continue

            # Check opt-in features for Triage
            opt_in_features = membership_details.get("optInFeatures", [])
            triage_enabled = False

            for feature in opt_in_features:
                if feature.get("featureName") == "Triage" and feature.get("isEnabled"):
                    triage_enabled = True
                    break

            if triage_enabled:
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id=membership_id,
                    actual_value="Proactive response (Triage) is enabled",
                    remediation="No remediation needed"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=membership_id,
                    actual_value="Proactive response (Triage) is not enabled",
                    remediation="Enable proactive response in the Security Incident Response console under membership settings"
                ))

        return self.findings
