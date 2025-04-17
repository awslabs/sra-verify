"""
Check if GuardDuty S3 data events are configured for auto-enablement.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck
from sraverify.core.logging import logger


class SRA_GUARDDUTY_20(GuardDutyCheck):
    """Check if GuardDuty S3 data events are configured for auto-enablement."""

    def __init__(self):
        """Initialize GuardDuty S3 data events auto-enablement check."""
        super().__init__()
        self.check_id = "SRA-GUARDDUTY-20"
        self.check_name = "GuardDuty S3 data events auto-enablement configured"
        self.description = ("This check verifies whether S3 data events are configured for auto-enablement "
                           "in GuardDuty for all member accounts. S3 data events provide visibility into "
                           "object-level API operations, enhancing threat detection for S3 buckets.")
        self.severity = "HIGH"
        self.check_logic = "Check if S3_DATA_EVENTS feature is configured with AutoEnable set to ALL."
        self.account_type = "audit"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Check all regions
        for region in self.regions:
            detector_id = self.get_detector_id(region)
            
            # Handle regions where we can't access GuardDuty
            if not detector_id:
                findings.append(self.create_finding(
                    status="ERROR", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}", 
                    actual_value="Unable to access GuardDuty in this region", 
                    remediation="Check permissions or if GuardDuty is supported in this region"
                ))
                continue
                
            # Get organization configuration for GuardDuty
            org_config = self.get_organization_configuration(region)
            
            # Check if there was an error in the response
            if "Error" in org_config:
                error_code = org_config["Error"].get("Code", "Unknown")
                error_message = org_config["Error"].get("Message", "Unknown error")
                
                # Handle BadRequestException specifically for non-management accounts
                if error_code == "BadRequestException" and "not the master account" in error_message:
                    findings.append(self.create_finding(
                        status="ERROR", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"This check must be run from the organization management account", 
                        remediation="Run this check from the AWS Organizations management account"
                    ))
                else:
                    findings.append(self.create_finding(
                        status="ERROR", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"Error accessing GuardDuty organization configuration: {error_code}", 
                        remediation="Check permissions and AWS Organizations configuration"
                    ))
                continue
            
            # Check if S3 data events are configured for auto-enablement
            # Look for S3_DATA_EVENTS in Features
            s3_data_events_found = False
            s3_data_events_auto_enable = "NOT_CONFIGURED"
            features = org_config.get('Features', [])
            
            for feature in features:
                if feature.get('Name') == 'S3_DATA_EVENTS':
                    s3_data_events_found = True
                    s3_data_events_auto_enable = feature.get('AutoEnable', 'NONE')
                    break
            
            if s3_data_events_found and s3_data_events_auto_enable == 'ALL':
                findings.append(self.create_finding(
                    status="PASS", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value="GuardDuty S3 data events are configured for auto-enablement for all accounts (AutoEnable=ALL)", 
                    remediation=""
                ))
            elif s3_data_events_found:
                findings.append(self.create_finding(
                    status="FAIL", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value=f"GuardDuty S3 data events are configured with AutoEnable={s3_data_events_auto_enable}, but should be ALL", 
                    remediation=f"Configure S3 data events auto-enablement for all accounts in {region} by setting AutoEnable to ALL"
                ))
            else:
                findings.append(self.create_finding(
                    status="FAIL", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value=f"GuardDuty S3 data events feature is not configured", 
                    remediation=f"Enable S3 data events feature and configure auto-enablement for all accounts in {region}"
                ))
        
        return findings
