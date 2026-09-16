"""
SRA-INSPECTOR-01: Inspector Service Status.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.inspector.base import InspectorCheck


class SRA_INSPECTOR_01(InspectorCheck):
    """Check if Inspector service is enabled for the account."""

    meta = CheckMeta(
        check_id="SRA-INSPECTOR-01",
        title="Inspector service is enabled",
        description=(
            "This check verifies whether Inspector service status for the account is enabled. "
            "Amazon Inspector is a vulnerability management service that continuously scans your AWS "
            "workloads for software vulnerabilities and unintended network exposure."
        ),
        check_logic=(
            "Check runs inspector2 batch-get-account-status. Check PASS if response state status = Enabled"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Inspector",
        resource_type="AWS::Inspector::Assessment",
        remediation=Remediation(
            text=(
                "Enable Amazon Inspector for the account in every enabled Region, "
                "covering all supported resource types."
            ),
            cli=(
                "aws inspector2 enable --account-ids <account-id> "
                "--resource-types EC2 ECR LAMBDA LAMBDA_CODE --region <region>"
            ),
            console=(
                "Inspector console, Activate Inspector, then confirm the scan types "
                "under Settings, General settings. Repeat per Region."
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
                        resource_id=f"inspector2/{self.account_id}",
                        actual_value=f"Inspector account status could not be read in {region}",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"inspector2/{self.account_id}",
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

            # Check if state status is enabled
            state_status = account_status.get('state', {}).get('status')

            if not account_status or state_status != 'ENABLED':
                yield self.failed(
                    region=region,
                    resource_id=f"inspector2/{self.account_id}",
                    checked_value="Inspector state status: ENABLED",
                    actual_value=f"Inspector state status: {state_status if state_status else 'NOT_ENABLED'}",
                    remediation=(
                        "Enable Amazon Inspector for your account using the AWS Console or CLI command: "
                        f"aws inspector2 enable --account-ids {self.account_id} --resource-types EC2 ECR LAMBDA LAMBDA_CODE --region {region}"
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=f"inspector2/{self.account_id}",
                    checked_value="Inspector state status: ENABLED",
                    actual_value=f"Inspector state status: {state_status}",
                )
