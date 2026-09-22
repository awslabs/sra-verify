"""
SRA-SECURITYHUB-14: Security Hub V2 is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_14(SecurityHubCheck):
    """Check if Security Hub is enabled in its V2 form."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-14",
        title="Security Hub V2 is enabled",
        description=(
            "This check verifies that Security Hub is enabled in its V2 form in each Region, "
            "not only as Security Hub CSPM. Security Hub V2 is a separate resource with its own "
            "enablement operation and hosts the AI inventory, exposure findings and cross-service "
            "correlation. All other Security Hub checks read the CSPM surface, so an account "
            "passes every one of them with V2 never enabled."
        ),
        check_logic=(
            "Call securityhub:DescribeSecurityHubV2 in each Region. Check passes if the "
            "response carries a HubV2Arn. Fails on ResourceNotFoundException with the message "
            "'You are not subscribed to HubV2'."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::HubV2",
        remediation=Remediation(
            text="Enable Security Hub V2 in every Region where Security Hub CSPM is enabled.",
            cli="aws securityhub enable-security-hub-v2 --region <region>",
            console=(
                "Security Hub console, Get started with Security Hub, Enable Security Hub. "
                "Repeat per Region, or enable for the organization from the delegated "
                "administrator."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Hub"),
        additional_urls=(
            "https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DescribeSecurityHubV2.html",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-enable.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        checked_value = "Security Hub V2 is enabled"

        if not self._clients:
            yield self.failed(
                region="global",
                resource_id="securityhub:global",
                checked_value=checked_value,
                actual_value="Security Hub not available in any region",
                remediation="Enable Security Hub V2 in at least one region",
            )
            return

        for region in self.regions:
            v2_response = self.get_security_hub_v2(region)

            # V2 is independent of CSPM -- it was observed enabled in a Region
            # where CSPM was not subscribed -- so this branch reports only on V2.
            if "Error" in v2_response:
                error = v2_response["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"securityhub:hubv2/{self.account_id}",
                        checked_value=checked_value,
                        actual_value=(
                            f"Security Hub V2 is not enabled in region {region}"
                        ),
                        remediation=(
                            f"Enable Security Hub V2 in {region}: "
                            f"aws securityhub enable-security-hub-v2 --region {region}"
                        ),
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"securityhub:hubv2/{self.account_id}",
                        checked_value=checked_value,
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            hub_v2_arn = v2_response.get('HubV2Arn')

            if hub_v2_arn:
                subscribed_at = v2_response.get('SubscribedAt', 'unknown date')
                yield self.passed(
                    region=region,
                    resource_id=hub_v2_arn,
                    checked_value=checked_value,
                    actual_value=(
                        f"Security Hub V2 is enabled in region {region} "
                        f"(subscribed {subscribed_at})"
                    ),
                )
            else:
                # DescribeSecurityHubV2 succeeded and named no hub. AWS answered,
                # and the answer carries no V2 resource.
                yield self.failed(
                    region=region,
                    resource_id=f"securityhub:hubv2/{self.account_id}",
                    checked_value=checked_value,
                    actual_value=(
                        f"DescribeSecurityHubV2 returned no HubV2Arn in region "
                        f"{region}"
                    ),
                    remediation=(
                        f"Enable Security Hub V2 in {region}: "
                        f"aws securityhub enable-security-hub-v2 --region {region}"
                    ),
                )
