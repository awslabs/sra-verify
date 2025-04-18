"""
Check if GuardDuty EBS Malware Protection is configured for auto-enablement.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck
from sraverify.core.logging import logger


class SRA_GUARDDUTY_21(GuardDutyCheck):
    """Check if GuardDuty EBS Malware Protection is configured for auto-enablement."""

    def __init__(self):
        """Initialize GuardDuty EBS Malware Protection auto-enablement check."""
        super().__init__()
        self.check_id = "SRA-GUARDDUTY-21"
        self.check_name = "GuardDuty EBS Malware Protection auto-enablement configured"
        self.description = ("This check verifies whether EBS Malware Protection is configured for auto-enablement "
                           "in GuardDuty for all member accounts. EBS Malware Protection scans EBS volumes for "
                           "malware when GuardDuty detects a potential threat, helping to identify and remediate "
                           "malware infections in your AWS environment.")
        self.severity = "HIGH"
        self.check_logic = "Check if EBS_MALWARE_PROTECTION feature is configured with AutoEnable set to ALL."
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
                if error_code == "BadRequestException":
                    findings.append(self.create_finding(
                        status="FAIL", 
                        region=region, 
                        account_id=account_id,
                        resource_id=f"guardduty:{region}:{detector_id}", 
                        actual_value=f"{error_code} {error_message}", 
                        remediation="Verify that GuardDuty is the delegated admin in this Region and run the check again."
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
            
            # Check if EBS Malware Protection is configured for auto-enablement
            # Look for EBS_MALWARE_PROTECTION in Features
            ebs_malware_protection_found = False
            ebs_malware_protection_auto_enable = "NOT_CONFIGURED"
            features = org_config.get('Features', [])
            
            for feature in features:
                if feature.get('Name') == 'EBS_MALWARE_PROTECTION':
                    ebs_malware_protection_found = True
                    ebs_malware_protection_auto_enable = feature.get('AutoEnable', 'NONE')
                    break
            
            if ebs_malware_protection_found and ebs_malware_protection_auto_enable == 'ALL':
                findings.append(self.create_finding(
                    status="PASS", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value="GuardDuty EBS Malware Protection is configured for auto-enablement for all accounts (AutoEnable=ALL)", 
                    remediation=""
                ))
            elif ebs_malware_protection_found:
                findings.append(self.create_finding(
                    status="FAIL", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value=f"GuardDuty EBS Malware Protection is configured with AutoEnable={ebs_malware_protection_auto_enable}, but should be ALL", 
                    remediation=f"Configure EBS Malware Protection auto-enablement for all accounts in {region} by setting AutoEnable to ALL"
                ))
            else:
                findings.append(self.create_finding(
                    status="FAIL", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value=f"GuardDuty EBS Malware Protection feature is not configured", 
                    remediation=f"Enable EBS Malware Protection feature and configure auto-enablement for all accounts in {region}"
                ))
        
        return findings
