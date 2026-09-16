"""
Check if Firewall Manager manages Route 53 DNS Firewall policies.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.firewallmanager.base import FirewallManagerCheck


class SRA_FIREWALLMANAGER_07(FirewallManagerCheck):
    """Check if Firewall Manager manages Route 53 DNS Firewall policies."""

    meta = CheckMeta(
        check_id="SRA-FIREWALLMANAGER-07",
        title="Firewall Manager manages Route 53 DNS Firewall policies",
        description=(
            "Verifies that AWS Firewall Manager has Route 53 DNS Firewall policies "
            "configured in each region"
        ),
        check_logic=(
            "Calls list_policies() per region and checks for policies with "
            "SecurityServiceType of DNS_FIREWALL"
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="FirewallManager",
        resource_type="AWS::FMS::Policy",
        remediation=Remediation(
            text=(
                "Create an AWS Firewall Manager Amazon Route 53 Resolver DNS Firewall "
                "policy in every enabled Region so that DNS Firewall rule groups are "
                "associated centrally with in-scope VPCs."
            ),
            cli="aws fms put-policy --policy file://dns-firewall-policy.json --region <region>",
            console=(
                "AWS Firewall Manager console, Security policies, Create policy, "
                "Amazon Route 53 Resolver DNS Firewall. Repeat per Region."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        for region in self.regions:
            policies_response = self.list_policies(region)

            if "Error" in policies_response:
                error = policies_response["Error"]
                # Inside the per-Region loop, so one undetermined Region costs one
                # row rather than the whole check's output.
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=None,
                        actual_value="No Route 53 DNS Firewall policies configured",
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
                    )
                continue

            policies = policies_response.get("PolicyList", [])
            dns_policies = [
                p for p in policies
                if p.get("SecurityServiceType") == "DNS_FIREWALL"
            ]

            if not dns_policies:
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No Route 53 DNS Firewall policies configured",
                    remediation="Create Firewall Manager Route 53 DNS Firewall policies: https://docs.aws.amazon.com/waf/latest/developerguide/dns-firewall-policies.html"
                )
            else:
                policy_names = [p.get("PolicyName", "Unknown") for p in dns_policies]
                yield self.passed(
                    region=region,
                    resource_id=",".join([p.get("PolicyId", "") for p in dns_policies]),
                    actual_value=f"{len(dns_policies)} Route 53 DNS Firewall policy(ies) configured: {', '.join(policy_names)}"
                )
