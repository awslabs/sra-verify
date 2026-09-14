"""
SRA-INSPECTOR-04: Inspector Lambda Function and Layers Vulnerability Scanning.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.inspector.base import InspectorCheck


class SRA_INSPECTOR_04(InspectorCheck):
    """Check if Inspector Lambda function and layers vulnerability scanning is enabled for the account."""

    meta = CheckMeta(
        check_id="SRA-INSPECTOR-04",
        title="Inspector Lambda function and layers vulnerability scanning is enabled",
        description=(
            "This check verifies whether Inspector Lambda function and layers for package and code vulnerability. "
            "Amazon Inspector monitors each Lambda function throughout its lifetime until it's either deleted or excluded from scanning."
        ),
        check_logic=(
            "Check runs inspector2 batch-get-account-status. Check PASS if lambda status = ENABLED AND lambdaCode status = ENABLED"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Inspector",
        resource_type="AWS::Inspector::Assessment",
        remediation=Remediation(
            text=(
                "Enable both the Amazon Inspector Lambda standard scanning and Lambda "
                "code scanning types for the account in every enabled Region."
            ),
            cli=(
                "aws inspector2 enable --account-ids <account-id> "
                "--resource-types LAMBDA LAMBDA_CODE --region <region>"
            ),
            console=(
                "Inspector console, Settings, General settings, Scan types, enable "
                "AWS Lambda standard scanning and Lambda code scanning. Repeat per Region."
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
            account_status = self.get_account_status(region)

            # Check if Lambda and LambdaCode scanning are enabled
            lambda_status = account_status.get('lambda', {}).get('status')
            lambda_code_status = account_status.get('lambdaCode', {}).get('status')

            if not account_status or lambda_status != 'ENABLED' or lambda_code_status != 'ENABLED':
                yield self.failed(
                    region=region,
                    resource_id=f"inspector2/{self.account_id}/lambda",
                    checked_value="Inspector Lambda scanning: ENABLED, LambdaCode scanning: ENABLED",
                    actual_value=f"Inspector Lambda scanning: {lambda_status if lambda_status else 'NOT_ENABLED'}, "
                                 f"LambdaCode scanning: {lambda_code_status if lambda_code_status else 'NOT_ENABLED'}",
                    remediation=(
                        "Enable Amazon Inspector Lambda and LambdaCode scanning for your account using the AWS Console or CLI command: "
                        f"aws inspector2 enable --account-ids {self.account_id} --resource-types LAMBDA LAMBDA_CODE --region {region}"
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=f"inspector2/{self.account_id}/lambda",
                    checked_value="Inspector Lambda scanning: ENABLED, LambdaCode scanning: ENABLED",
                    actual_value=f"Inspector Lambda scanning: {lambda_status}, LambdaCode scanning: {lambda_code_status}",
                )
