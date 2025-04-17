"""
SRA-MACIE-04: Checks that findings are being exported to S3 in the log archive account are encrypted at rest.
"""
from typing import List, Dict, Any
from sraverify.services.macie.base import MacieCheck
from sraverify.core.logging import logger


class SRA_MACIE_04(MacieCheck):
    """Check if Macie findings exported to S3 are encrypted at rest using KMS."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-MACIE-04"
        self.check_name = "Checks that findings are being exported to S3 in the log archive account are encrypted at rest"
        self.description = (
            "This check verifies whether all Macie findings that are being exported to a S3 bucket within the Log Archive account "
            "are encrypted using KMS key. Macie findings are sensitive in natures and should be encrypted to prevent from unauthorized disclosure."
        )
        self.severity = "HIGH"
        self.account_type = "application"
        self.check_logic = "Check validates using get-classification-export-configuration that kms key exists. PASS if KMS ARN returned."
        self.resource_type = "AWS::Macie::Session"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        for region in self.regions:
            # Get classification export configuration using the base class method with caching
            export_config = self.get_classification_export_configuration(region)
            
            # Check if the API call was successful
            if not export_config:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="KMS encryption for S3 bucket",
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
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="KMS encryption for S3 bucket",
                        actual_value="Macie findings export configuration not found",
                        remediation=(
                            f"Configure Macie to export findings to a S3 bucket with KMS encryption in region {region} using the AWS CLI command: "
                            f"aws macie2 put-classification-export-configuration --s3-destination bucketName=your-bucket-name,kmsKeyArn=arn:aws:kms:{region}:{account_id}:key/your-key-id --region {region}"
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
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="KMS encryption for S3 bucket",
                        actual_value="S3 destination not found in Macie findings export configuration",
                        remediation=(
                            f"Configure Macie to export findings to a S3 bucket with KMS encryption in region {region} using the AWS CLI command: "
                            f"aws macie2 put-classification-export-configuration --s3-destination bucketName=your-bucket-name,kmsKeyArn=arn:aws:kms:{region}:{account_id}:key/your-key-id --region {region}"
                        )
                    )
                )
                continue
            
            # Get bucket name and KMS key ARN
            bucket_name = s3_destination.get('bucketName', '')
            kms_key_arn = s3_destination.get('kmsKeyArn', '')
            
            # Check if KMS key ARN exists
            if kms_key_arn:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="KMS encryption for S3 bucket",
                        actual_value=f"Macie findings exported to S3 bucket '{bucket_name}' are encrypted using KMS key '{kms_key_arn}' in region {region}",
                        remediation="No remediation needed"
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="KMS encryption for S3 bucket",
                        actual_value=f"Macie findings exported to S3 bucket '{bucket_name}' are not encrypted using KMS in region {region}",
                        remediation=(
                            f"Configure Macie to export findings to a S3 bucket with KMS encryption in region {region} using the AWS CLI command: "
                            f"aws macie2 put-classification-export-configuration --s3-destination bucketName={bucket_name},kmsKeyArn=arn:aws:kms:{region}:{account_id}:key/your-key-id --region {region}"
                        )
                    )
                )
        
        return findings
