"""
SRA-MACIE-03: Macie findings exported to a S3 bucket in Log Archive account are encrypted at rest.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.macie.base import MacieCheck


class SRA_MACIE_03(MacieCheck):
    """Check if Macie findings are exported to a S3 bucket in Log Archive account."""

    meta = CheckMeta(
        check_id="SRA-MACIE-03",
        title="Macie findings exported to a S3 bucket in Log Archive account are encrypted at rest",
        description=(
            "This check verifies whether all Macie findings are being exported to a S3 bucket within the Log Archive account. "
            "Log Archive account is the central repository of all AWS Organization logs."
        ),
        check_logic=(
            "Check validates using get-classification-export-configuration if Macie is set to export findings to S3 AND "
            "if the S3 bucket is in the log archive account validated by EITHER the bucket name containing OR the KMS key "
            "arn containing the --log-archive account ID. If bucket account can't be validated to --log-archive FAIL with value of bucket."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="Macie",
        resource_type="AWS::Macie::Session",
        remediation=Remediation(
            text=(
                "Configure Macie to export classification findings to a S3 bucket owned "
                "by the Log Archive account, in every enabled Region."
            ),
            cli=(
                "aws macie2 put-classification-export-configuration "
                "--s3-destination bucketName=<log-archive-bucket>,"
                "kmsKeyArn=<kms-key-arn> --region <region>"
            ),
            console=(
                "Macie console, Settings, Discovery results, Repository for "
                "sensitive data discovery results, select the Log Archive bucket. "
                "Repeat per Region."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region, or one Finding describing why the Macie
            findings export destination could not be determined.
        """
        # Check if log archive accounts are provided.
        log_archive_accounts = self.log_archive_accounts

        if not log_archive_accounts:
            # Missing required input is not a regional condition, report once.
            yield self.error(
                region="global",
                resource_id=f"macie2/{self.account_id}",
                checked_value="S3 bucket in Log Archive account",
                actual_value="Log Archive account ID not provided",
                remediation="Provide the Log Archive account IDs using --log-archive-account flag"
            )
            return

        for region in self.regions:
            # Get classification export configuration using the base class method with caching
            export_config = self.get_classification_export_configuration(region)

            # No client wrapper for this Region: the control was not evaluated.
            if not export_config:
                yield self.error(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="S3 bucket in Log Archive account",
                    actual_value=f"No Macie client available for region {region}",
                    remediation=f"Confirm that Macie is available in {region} and that the Region is reachable from the scanning environment"
                )
                continue

            # The API call failed. Macie disabled in the Region is a FAIL, since
            # AWS answered and the control is absent. Anything else is an ERROR:
            # the control could not be evaluated.
            if "Error" in export_config:
                error = export_config["Error"]
                error_code = error.get("Code", "Unknown")
                error_message = error.get("Message", "Unknown error")
                if self.is_macie_disabled_error(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="S3 bucket in Log Archive account",
                        actual_value=f"Macie is not enabled in region {region}, so findings are not exported to the Log Archive account ({error_code})",
                        remediation=(
                            f"Enable Macie in {region}, then configure it to export findings to a S3 bucket in the Log Archive account "
                            f"{log_archive_accounts[0]}: aws macie2 enable-macie --region {region}"
                        )
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="S3 bucket in Log Archive account",
                        actual_value=f"Could not determine the Macie findings export destination in {region}: {error_code}: {error_message}",
                        remediation="Grant the member role macie2:GetClassificationExportConfiguration so the findings export destination can be read"
                    )
                continue

            # Check if export configuration exists
            configuration = export_config.get('configuration', {})
            if not configuration:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="S3 bucket in Log Archive account",
                    actual_value="Macie findings export configuration not found",
                    remediation=(
                        f"Configure Macie to export findings to a S3 bucket in the Log Archive account in region {region} using the AWS CLI command: "
                        f"aws macie2 put-classification-export-configuration --s3-destination bucketName=macie-findings-{log_archive_accounts[0]},kmsKeyArn=arn:aws:kms:{region}:{log_archive_accounts[0]}:key/your-key-id --region {region}"
                    )
                )
                continue

            # Check if S3 destination exists
            s3_destination = configuration.get('s3Destination', {})
            if not s3_destination:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="S3 bucket in Log Archive account",
                    actual_value="S3 destination not found in Macie findings export configuration",
                    remediation=(
                        f"Configure Macie to export findings to a S3 bucket in the Log Archive account in region {region} using the AWS CLI command: "
                        f"aws macie2 put-classification-export-configuration --s3-destination bucketName=macie-findings-{log_archive_accounts[0]},kmsKeyArn=arn:aws:kms:{region}:{log_archive_accounts[0]}:key/your-key-id --region {region}"
                    )
                )
                continue

            # Get bucket name and KMS key ARN
            bucket_name = s3_destination.get('bucketName', '')
            kms_key_arn = s3_destination.get('kmsKeyArn', '')

            # Check if bucket name or KMS key ARN contains log archive account ID
            is_in_log_archive = False
            log_archive_account_found = None

            for log_archive_account in log_archive_accounts:
                if log_archive_account in bucket_name or log_archive_account in kms_key_arn:
                    is_in_log_archive = True
                    log_archive_account_found = log_archive_account
                    break

            if is_in_log_archive:
                yield self.passed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="S3 bucket in Log Archive account",
                    actual_value=f"Macie findings are exported to S3 bucket '{bucket_name}' in Log Archive account {log_archive_account_found} in region {region}"
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"macie2/{self.account_id}/{region}",
                    checked_value="S3 bucket in Log Archive account",
                    actual_value=f"Macie findings are exported to S3 bucket '{bucket_name}' which is not in any of the specified Log Archive accounts {', '.join(log_archive_accounts)} in region {region}",
                    remediation=(
                        f"Configure Macie to export findings to a S3 bucket in the Log Archive account in region {region} using the AWS CLI command: "
                        f"aws macie2 put-classification-export-configuration --s3-destination bucketName=macie-findings-{log_archive_accounts[0]},kmsKeyArn=arn:aws:kms:{region}:{log_archive_accounts[0]}:key/your-key-id --region {region}"
                    )
                )
