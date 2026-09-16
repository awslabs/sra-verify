"""
SRA-MACIE-04: Checks that findings are being exported to S3 in the log archive account are encrypted at rest.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.macie.base import MacieCheck


class SRA_MACIE_04(MacieCheck):
    """Check if Macie findings exported to S3 are encrypted at rest using KMS."""

    meta = CheckMeta(
        check_id="SRA-MACIE-04",
        # Retitled: the pre-migration title opened with a forbidden token and
        # read as a subordinate clause with no main verb. The trailing "with a
        # KMS key" is load-bearing -- it is what keeps this title distinct from
        # SRA-MACIE-03's, which is otherwise almost the same sentence.
        title="Macie findings exported to S3 in the log archive account are encrypted at rest with a KMS key",
        description=(
            "This check verifies whether all Macie findings that are being exported to a S3 bucket within the Log Archive account "
            "are encrypted using KMS key. Macie findings are sensitive in natures and should be encrypted to prevent from unauthorized disclosure."
        ),
        check_logic=(
            "Check validates using get-classification-export-configuration that kms key exists. "
            "PASS if KMS ARN returned."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Macie",
        resource_type="AWS::Macie::Session",
        remediation=Remediation(
            text=(
                "Set a KMS key on the Macie classification export configuration so "
                "exported findings are encrypted at rest, in every enabled Region."
            ),
            cli=(
                "aws macie2 put-classification-export-configuration "
                "--s3-destination bucketName=<bucket>,kmsKeyArn=<kms-key-arn> "
                "--region <region>"
            ),
            console=(
                "Macie console, Settings, Discovery results, Repository for "
                "sensitive data discovery results, choose an AWS KMS key. "
                "Repeat per Region."
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
            # Get classification export configuration using the base class method with caching
            export_config = self.get_classification_export_configuration(region)

            # The API call failed. Macie disabled in the Region is a FAIL, since
            # AWS answered and the control is absent. Anything else is an ERROR:
            # the control could not be evaluated.
            if "Error" in export_config:
                error = export_config["Error"]
                error_code = error.get("Code", "Unknown")
                error_message = error.get("Message", "Unknown error")
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="KMS encryption for S3 bucket",
                        actual_value=f"Macie is not enabled in region {region}, so no KMS-encrypted findings export is configured ({error_code})",
                        remediation=(
                            f"Enable Macie in {region}, then configure a KMS-encrypted findings export destination: "
                            f"aws macie2 enable-macie --region {region}"
                        )
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="KMS encryption for S3 bucket",
                        actual_value=(
                            f"{error['Operation']} failed: {error_code}: "
                            f"{error_message}"
                        ),
                        remediation=self._remediation_for(error)
                    )
                continue

            # Check if export configuration exists
            configuration = export_config.get('configuration', {})
            if not configuration:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="KMS encryption for S3 bucket",
                    actual_value="Macie findings export configuration not found",
                    remediation=(
                        f"Configure Macie to export findings to a S3 bucket with KMS encryption in region {region} using the AWS CLI command: "
                        f"aws macie2 put-classification-export-configuration --s3-destination bucketName=your-bucket-name,kmsKeyArn=arn:aws:kms:{region}:{self.account_id}:key/your-key-id --region {region}"
                    )
                )
                continue

            # Check if S3 destination exists
            s3_destination = configuration.get('s3Destination', {})
            if not s3_destination:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="KMS encryption for S3 bucket",
                    actual_value="S3 destination not found in Macie findings export configuration",
                    remediation=(
                        f"Configure Macie to export findings to a S3 bucket with KMS encryption in region {region} using the AWS CLI command: "
                        f"aws macie2 put-classification-export-configuration --s3-destination bucketName=your-bucket-name,kmsKeyArn=arn:aws:kms:{region}:{self.account_id}:key/your-key-id --region {region}"
                    )
                )
                continue

            # Get bucket name and KMS key ARN
            bucket_name = s3_destination.get('bucketName', '')
            kms_key_arn = s3_destination.get('kmsKeyArn', '')

            # Check if KMS key ARN exists
            if kms_key_arn:
                yield self.passed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="KMS encryption for S3 bucket",
                    actual_value=f"Macie findings exported to S3 bucket '{bucket_name}' are encrypted using KMS key '{kms_key_arn}' in region {region}"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="KMS encryption for S3 bucket",
                    actual_value=f"Macie findings exported to S3 bucket '{bucket_name}' are not encrypted using KMS in region {region}",
                    remediation=(
                        f"Configure Macie to export findings to a S3 bucket with KMS encryption in region {region} using the AWS CLI command: "
                        f"aws macie2 put-classification-export-configuration --s3-destination bucketName={bucket_name},kmsKeyArn=arn:aws:kms:{region}:{self.account_id}:key/your-key-id --region {region}"
                    )
                )
