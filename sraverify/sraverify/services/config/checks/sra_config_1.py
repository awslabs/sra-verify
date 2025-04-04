"""
SRA-CONFIG-1: AWS Config Recorder Configured.
"""
from typing import List, Dict, Any
from sraverify.services.config.base import ConfigCheck
from sraverify.core.logging import logger


class SRA_CONFIG_1(ConfigCheck):
    """Check if AWS Config recorder is configured in each region."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CONFIG-1"
        self.check_name = "AWS Config recorder is configured in this region"
        self.account_type = "account"  # This check applies to all account types
        self.severity = "HIGH"
        self.description = (
            "This check verifies that a configuration recorder exists in the AWS Region. "
            "AWS Config uses the configuration recorder to detect changes in your resource configurations "
            "and capture these changes as configuration items. You must create a configuration recorder "
            "in every AWS Region for AWS Config can track your resource configurations in the region."
        )
        self.check_logic = (
            "Checks if AWS Config recorder exists in each region using describe-configuration-recorder-status API."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        if not self.regions:
            findings.append(
                self.create_finding(
                    status="ERROR",
                    region="global",
                    account_id=account_id,
                    resource_id="config:global",
                    actual_value="No regions specified for check",
                    remediation="Specify at least one region when running the check"
                )
            )
            return findings
        
        # Check each region for configuration recorder
        for region in self.regions:
            # Get configuration recorders for the region
            recorders = self.get_configuration_recorders(region)
            
            # Get configuration recorder status for the region
            recorder_statuses = self.get_configuration_recorder_status(region)
            
            if not recorders:
                # No configuration recorder found in this region
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"arn:aws:config:{region}:{account_id}:configurationRecorder/default",
                        actual_value="No configuration recorder found in this region",
                        remediation=(
                            f"1. Check if the AWS Config service-linked role exists: aws iam get-role --role-name AWSServiceRoleForConfig. "
                            f"2. If the role doesn't exist, create it: aws iam create-service-linked-role --aws-service-name config.amazonaws.com. "
                            f"3. Create a configuration recorder in {region}: aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=arn:aws:iam::{account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig --recording-group allSupported=true,includeGlobalResourceTypes=true --region {region}"
                        )
                    )
                )
            else:
                # Configuration recorder exists, check if it's enabled
                recorder_name = recorders[0].get('name', 'default')
                recorder_role_arn = recorders[0].get('roleARN', '')
                
                # Construct the Config Recorder ARN
                recorder_arn = f"arn:aws:config:{region}:{account_id}:configurationRecorder/{recorder_name}"
                
                # Find the status for this recorder
                recorder_status = next((status for status in recorder_statuses if status.get('name') == recorder_name), None)
                
                if recorder_status and recorder_status.get('recording', False):
                    # Configuration recorder exists and is recording
                    findings.append(
                        self.create_finding(
                            status="PASS",
                            region=region,
                            account_id=account_id,
                            resource_id=recorder_arn,
                            actual_value=f"Configuration recorder '{recorder_name}' exists and is recording",
                            remediation=""
                        )
                    )
                elif recorder_status:
                    # Configuration recorder exists but is not recording
                    findings.append(
                        self.create_finding(
                            status="FAIL",
                            region=region,
                            account_id=account_id,
                            resource_id=recorder_arn,
                            actual_value=f"Configuration recorder '{recorder_name}' exists but is not recording",
                            remediation=(
                                f"Start the configuration recorder in {region} using the AWS CLI command: "
                                f"aws configservice start-configuration-recorder --configuration-recorder-name {recorder_name} --region {region}"
                            )
                        )
                    )
                else:
                    # Configuration recorder exists but no status found
                    findings.append(
                        self.create_finding(
                            status="FAIL",
                            region=region,
                            account_id=account_id,
                            resource_id=recorder_arn,
                            actual_value=f"Configuration recorder '{recorder_name}' exists but status could not be determined",
                            remediation=(
                                f"Check the configuration recorder status in {region} and ensure it's properly configured"
                            )
                        )
                    )
        
        return findings
