"""
SRA-SECURITYHUB-01: Security Hub check.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_01(SecurityHubCheck):
    """Check if Security Hub enabled account level standards exist."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-01",
        title="Security Hub enabled account level standards exist",
        description=(
            "This check verifies whether a list of enabled Security Hub standards for the current AWS account exists."
        ),
        check_logic=(
            "Check evaluates if there are any standards enabled in the AWS account and AWS region. "
            "Check PASS if there are any standards enabled."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::Hub",
        remediation=Remediation(
            text=(
                "Enable Security Hub in every enabled Region and subscribe the account "
                "to at least one security standard."
            ),
            cli=(
                "aws securityhub enable-security-hub --region <region>\n"
                "aws securityhub batch-enable-standards --standards-subscription-requests "
                "'StandardsArn=arn:aws:securityhub:<region>::standards/"
                "aws-foundational-security-best-practices/v/1.0.0' --region <region>"
            ),
            console=(
                "Security Hub console, Settings, Standards, enable the required "
                "standards. Repeat per Region."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        # If no regions have Security Hub available, return a single failure
        if not self._clients:
            yield self.failed(
                region="global",
                resource_id="securityhub:global",
                checked_value="Security Hub is enabled",
                actual_value="Security Hub not available in any region",
                remediation="Enable Security Hub in at least one region",
            )
            return

        # Check each region where Security Hub is available
        for region in self.regions:
            # Get enabled standards for the current account in this region
            standards_response = self.get_enabled_standards(region)

            # "Security Hub is not subscribed here" is an InvalidAccessException
            # the discriminator recognizes; every other failure is an ERROR.
            if "Error" in standards_response:
                error = standards_response["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"securityhub:service/{self.account_id}",
                        checked_value="Security Hub is enabled",
                        actual_value=f"Security Hub is not enabled in region {region}",
                        remediation=(
                            "Enable Security Hub in this region. In the AWS console, navigate to Security Hub and enable the service. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securityhub enable-security-hub --region {region}"
                        ),
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"securityhub:service/{self.account_id}",
                        checked_value="Security Hub is enabled",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            enabled_standards = standards_response.get('StandardsSubscriptions', [])

            # Extract standard names for better reporting
            standard_names = []
            for standard in enabled_standards:
                standard_arn = standard.get('StandardsArn', '')
                # Extract the standard name from the ARN
                if '/standards/' in standard_arn:
                    standard_name = standard_arn.split('/standards/')[1]
                    standard_names.append(standard_name)
                else:
                    standard_names.append(standard_arn)

            # Format the list of standards for reporting
            standards_list = ', '.join(standard_names) if standard_names else "None"

            if not enabled_standards:
                yield self.failed(
                    region=region,
                    resource_id=f"securityhub:standards/{self.account_id}",
                    checked_value="Security Hub standards are enabled",
                    actual_value=f"Account {self.account_id} region {region} has no Security Hub standards enabled",
                    remediation=(
                        "Enable Security Hub standards for this account. In the Security Hub console, "
                        "navigate to Settings > Standards and enable the required standards. "
                        "Alternatively, use the AWS CLI command: "
                        f"aws securityhub batch-enable-standards --standards-subscription-requests 'StandardsArn=arn:aws:securityhub:{region}::standards/aws-foundational-security-best-practices/v/1.0.0' --region {region}"
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=f"securityhub:standards/{self.account_id}",
                    checked_value="Security Hub standards are enabled",
                    actual_value=f"Account {self.account_id} region {region} has the following standards enabled: {standards_list}",
                )
