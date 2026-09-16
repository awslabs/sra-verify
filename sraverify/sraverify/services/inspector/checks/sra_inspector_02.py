"""
SRA-INSPECTOR-02: Inspector EC2 Vulnerability Scanning.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.inspector.base import InspectorCheck


class SRA_INSPECTOR_02(InspectorCheck):
    """Check if Inspector EC2 vulnerability scanning is enabled for the account."""

    meta = CheckMeta(
        check_id="SRA-INSPECTOR-02",
        title="Inspector EC2 vulnerability scanning is enabled",
        description=(
            "This check verifies whether Inspector EC2 vulnerability scanning feature is enabled. "
            "Inspector automatically discovers EC2 instances and scans for software vulnerability."
        ),
        check_logic=(
            "Check runs inspector2 batch-get-account-status. Check PASS if response ec2 status = ENABLED"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Inspector",
        resource_type="AWS::Inspector::Assessment",
        remediation=Remediation(
            text=(
                "Enable the Amazon Inspector EC2 scan type for the account in every "
                "enabled Region."
            ),
            cli=(
                "aws inspector2 enable --account-ids <account-id> "
                "--resource-types EC2 --region <region>"
            ),
            console=(
                "Inspector console, Settings, General settings, Scan types, "
                "enable Amazon EC2 scanning. Repeat per Region."
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
            # Get account status using the base class method with caching
            status_response = self.get_account_status(region)

            if "Error" in status_response:
                error = status_response['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"inspector2/{self.account_id}/ec2",
                        actual_value=f"Inspector account status could not be read in {region}",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"inspector2/{self.account_id}/ec2",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            account_status = self.account_status_of(
                status_response, self.account_id
            )

            # Check if EC2 scanning is enabled
            ec2_status = account_status.get('ec2', {}).get('status')

            if not account_status or ec2_status != 'ENABLED':
                yield self.failed(
                    region=region,
                    resource_id=f"inspector2/{self.account_id}/ec2",
                    checked_value="Inspector EC2 scanning: ENABLED",
                    actual_value=f"Inspector EC2 scanning: {ec2_status if ec2_status else 'NOT_ENABLED'}",
                    remediation=(
                        "Enable Amazon Inspector EC2 scanning for your account using the AWS Console or CLI command: "
                        f"aws inspector2 enable --account-ids {self.account_id} --resource-types EC2 --region {region}"
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=f"inspector2/{self.account_id}/ec2",
                    checked_value="Inspector EC2 scanning: ENABLED",
                    actual_value=f"Inspector EC2 scanning: {ec2_status}",
                )
