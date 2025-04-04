"""
SRA-CONFIG-2: AWS Config Recorder Running.
"""
from typing import List, Dict, Any
from sraverify.services.config.base import ConfigCheck
from sraverify.core.logging import logger


class SRA_CONFIG_2(ConfigCheck):
    """Check if AWS Config recorder is running."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CONFIG-2"
        self.check_name = "AWS Config recorder is running"
        self.account_type = "account"  # This check applies to all account types
        self.severity = "HIGH"
        self.description = (
            "This check verifies that configuration recorder is running. AWS Config configuration "
            "recorder must be started and running to record resource configurations. If you set up "
            "AWS Config by using the console or the AWS CLI, AWS Config automatically creates and "
            "then starts the configuration recorder for you. Users with right permission have the "
            "ability to stop configuration recorder."
        )
        self.check_logic = (
            "Checks if AWS Config recorder is running by verifying the lastStatus is SUCCESS."
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
        
        # Check each region for configuration recorder status
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
                            f"First create a configuration recorder in {region} using: aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=arn:aws:iam::{account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig --recording-group allSupported=true,includeGlobalResourceTypes=true --region {region}. "
                            f"Then start the recorder with: aws configservice start-configuration-recorder --configuration-recorder-name default --region {region}"
                        )
                    )
                )
                continue
            
            # Configuration recorder exists, check if it's running
            recorder_name = recorders[0].get('name', 'default')
            
            # Find the status for this recorder
            recorder_status = next((status for status in recorder_statuses if status.get('name') == recorder_name), None)
            
            # Get the full ARN from the status if available
            recorder_arn = None
            if recorder_status and 'arn' in recorder_status:
                recorder_arn = recorder_status.get('arn')
            else:
                # Construct the Config Recorder ARN if not available in status
                recorder_arn = f"arn:aws:config:{region}:{account_id}:configurationRecorder/{recorder_name}"
            
            if not recorder_status:
                # No status found for this recorder
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
                continue
            
            # Check if the recorder is recording
            is_recording = recorder_status.get('recording', False)
            last_status = recorder_status.get('lastStatus', 'UNKNOWN')
            last_error_code = recorder_status.get('lastErrorCode', '')
            last_error_message = recorder_status.get('lastErrorMessage', '')
            
            if is_recording and last_status == "SUCCESS":
                # Configuration recorder is running successfully
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=recorder_arn,
                        actual_value=f"Configuration recorder '{recorder_name}' is running with lastStatus: SUCCESS",
                        remediation=""
                    )
                )
            elif is_recording:
                # Configuration recorder is recording but not in SUCCESS state
                error_info = f"lastStatus: {last_status}"
                if last_error_code:
                    error_info += f", errorCode: {last_error_code}"
                if last_error_message:
                    error_info += f", errorMessage: {last_error_message}"
                
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=recorder_arn,
                        actual_value=f"Configuration recorder '{recorder_name}' is recording but has issues: {error_info}",
                        remediation=(
                            f"Check the AWS Config logs and permissions in {region}. "
                            f"Ensure the Config service role has the necessary permissions to record resources."
                        )
                    )
                )
            else:
                # Configuration recorder is not recording
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=recorder_arn,
                        actual_value=f"Configuration recorder '{recorder_name}' is not recording",
                        remediation=(
                            f"Start the configuration recorder in {region} using the AWS CLI command: "
                            f"aws configservice start-configuration-recorder --configuration-recorder-name {recorder_name} --region {region}"
                        )
                    )
                )
        
        return findings
