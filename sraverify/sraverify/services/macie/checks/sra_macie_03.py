"""
SRA-MACIE-03: Macie findings exported to a S3 bucket in Log Archive account are encrypted at rest.
"""
from typing import List, Dict, Any
from sraverify.services.macie.base import MacieCheck
from sraverify.core.logging import logger


class SRA_MACIE_03(MacieCheck):
    """Check if Macie findings are exported to a S3 bucket in Log Archive account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-MACIE-03"
        self.check_name = "Macie findings exported to a S3 bucket in Log Archive account are encrypted at rest"
        self.description = (
            "This check verifies whether all Macie findings are being exported to a S3 bucket within the Log Archive account. "
            "Log Archive account is the central repository of all AWS Organization logs."
        )
        self.severity = "HIGH"
        self.account_type = "application"
        self.check_logic = (
            "Check validates using get-classification-export-configuration if Macie is set to export findings to S3 AND "
            "if the S3 bucket is in the log archive account validated by EITHER the bucket name containing OR the KMS key "
            "arn containing the --log-archive account ID. If bucket account can't be validated to --log-archive FAIL with value of bucket."
        )
        self.resource_type = "AWS::Macie::Session"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        
        # Check if log archive accounts are provided
        log_archive_accounts = []
        if hasattr(self, '_log_archive_accounts') and self._log_archive_accounts:
            log_archive_accounts = self._log_archive_accounts
        
        if not log_archive_accounts:
            for region in self.regions:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="S3 bucket in Log Archive account",
                        actual_value="Log Archive account ID not provided",
                        remediation="Provide the Log Archive account IDs using --log-archive-account flag"
                    )
                )
            return findings
        
        for region in self.regions:
            # Get classification export configuration using the base class method with caching
            export_config = self.get_classification_export_configuration(region)
            
            # Check if the API call was successful
            if not export_config:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="S3 bucket in Log Archive account",
                        actual_value="Failed to retrieve Macie classification export configuration",
                        remediation="Ensure Macie is enabled and you have the necessary permissions to call the Macie GetClassificationExportConfiguration API"
                    )
                )
                continue
            
            # Check if export configuration exists
            configuration = export_config.get('configuration', {})
            if not configuration:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="S3 bucket in Log Archive account",
                        actual_value="Macie findings export configuration not found",
                        remediation=(
                            f"Configure Macie to export findings to a S3 bucket in the Log Archive account in region {region} using the AWS CLI command: "
                            f"aws macie2 put-classification-export-configuration --s3-destination bucketName=macie-findings-{log_archive_accounts[0]},kmsKeyArn=arn:aws:kms:{region}:{log_archive_accounts[0]}:key/your-key-id --region {region}"
                        )
                    )
                )
                continue
            
            # Check if S3 destination exists
            s3_destination = configuration.get('s3Destination', {})
            if not s3_destination:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="S3 bucket in Log Archive account",
                        actual_value="S3 destination not found in Macie findings export configuration",
                        remediation=(
                            f"Configure Macie to export findings to a S3 bucket in the Log Archive account in region {region} using the AWS CLI command: "
                            f"aws macie2 put-classification-export-configuration --s3-destination bucketName=macie-findings-{log_archive_accounts[0]},kmsKeyArn=arn:aws:kms:{region}:{log_archive_accounts[0]}:key/your-key-id --region {region}"
                        )
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
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="S3 bucket in Log Archive account",
                        actual_value=f"Macie findings are exported to S3 bucket '{bucket_name}' in Log Archive account {log_archive_account_found} in region {region}",
                        remediation="No remediation needed"
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=f"macie2/{self.account_id}/{region}",
                        checked_value="S3 bucket in Log Archive account",
                        actual_value=f"Macie findings are exported to S3 bucket '{bucket_name}' which is not in any of the specified Log Archive accounts {', '.join(log_archive_accounts)} in region {region}",
                        remediation=(
                            f"Configure Macie to export findings to a S3 bucket in the Log Archive account in region {region} using the AWS CLI command: "
                            f"aws macie2 put-classification-export-configuration --s3-destination bucketName=macie-findings-{log_archive_accounts[0]},kmsKeyArn=arn:aws:kms:{region}:{log_archive_accounts[0]}:key/your-key-id --region {region}"
                        )
                    )
                )
        
        return findings
