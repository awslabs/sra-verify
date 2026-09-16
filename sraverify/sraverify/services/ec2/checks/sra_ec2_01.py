"""
SRA-EC2-01: AWS account level EBS encryption by default is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.ec2.base import EC2Check


class SRA_EC2_01(EC2Check):
    """Check if AWS account level EBS encryption by default is enabled."""

    meta = CheckMeta(
        check_id="SRA-EC2-01",
        title="AWS account level EBS encryption by default is enabled",
        description=(
            "This check verifies that the AWS account level configuration to encrypt EBS volumes by default "
            "is enabled in the AWS Region. This enforces, at AWS account level, the encryption of the new EBS "
            "volumes and snapshot copies that you create. You can use AWS managed keys or a customer managed KMS key."
        ),
        check_logic="Check Pass if 'EbsEncryptionByDefault' = true.",
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="EC2",
        resource_type="AWS::EC2::Volume",
        remediation=Remediation(
            text=(
                "Enable EBS encryption by default at the account level in every enabled "
                "Region, so that new EBS volumes and snapshot copies are encrypted with "
                "an AWS managed key or a customer managed KMS key."
            ),
            cli=(
                "aws ec2 enable-ebs-encryption-by-default --region <region>"
            ),
            console=(
                "EC2 console, Account attributes, Data protection and privacy, Manage "
                "EBS encryption, select Enable, Update EBS encryption. Repeat per Region."
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
            # Get EBS encryption by default status using the base class method with caching
            encryption_response = self.get_ebs_encryption_by_default(region)

            if "Error" in encryption_response:
                # ec2's NOT_CONFIGURED_ERRORS is empty:
                # GetEbsEncryptionByDefault answers a boolean, so encryption being
                # off is a successful response, not an error. Every error here is
                # an inability to determine.
                error = encryption_response['Error']
                yield self.error(
                    region=region,
                    resource_id=f"ec2:{self.account_id}:{region}",
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
                continue

            encryption_status = encryption_response

            # Check if the API call was successful
            if not encryption_status:
                yield self.error(
                    region=region,
                    resource_id=f"account/{self.account_id}/region/{region}",
                    checked_value="EbsEncryptionByDefault: true",
                    actual_value="Failed to retrieve EBS encryption by default status",
                    remediation="Ensure you have the necessary permissions to call the EC2 GetEbsEncryptionByDefault API"
                )
                continue

            # Check if EBS encryption by default is enabled
            is_encryption_enabled = encryption_status.get('EbsEncryptionByDefault', False)

            if is_encryption_enabled:
                yield self.passed(
                    region=region,
                    resource_id=f"account/{self.account_id}/region/{region}",
                    checked_value="EbsEncryptionByDefault: true",
                    actual_value=f"EBS encryption by default is enabled in region {region}"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"account/{self.account_id}/region/{region}",
                    checked_value="EbsEncryptionByDefault: true",
                    actual_value=f"EBS encryption by default is not enabled in region {region}",
                    remediation=(
                        f"Enable EBS encryption by default in region {region} using the AWS CLI command: "
                        f"aws ec2 enable-ebs-encryption-by-default --region {region}"
                    )
                )
