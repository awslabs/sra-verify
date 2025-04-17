"""
Check if GuardDuty Runtime Monitoring is configured for auto-enablement.
"""
from typing import Dict, List, Any
from sraverify.services.guardduty.base import GuardDutyCheck
from sraverify.core.logging import logger


class SRA_GUARDDUTY_23(GuardDutyCheck):
    """Check if GuardDuty Runtime Monitoring is configured for auto-enablement."""

    def __init__(self):
        """Initialize GuardDuty Runtime Monitoring auto-enablement check."""
        super().__init__()
        self.check_id = "SRA-GUARDDUTY-23"
        self.check_name = "GuardDuty Runtime Monitoring auto-enablement configured"
        self.description = ("This check verifies whether Runtime Monitoring and its components (ECS Fargate Agent Management, "
                           "EC2 Agent Management, and EKS Addon Management) are configured for auto-enablement "
                           "in GuardDuty for all member accounts. Runtime Monitoring provides threat detection for "
                           "runtime behavior of resources, helping to identify malicious activities.")
        self.severity = "HIGH"
        self.check_logic = "Check if RUNTIME_MONITORING feature and its components are configured with AutoEnable set to ALL."
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
            
            # Check if Runtime Monitoring is configured for auto-enablement
            # Look for RUNTIME_MONITORING in Features
            runtime_monitoring_found = False
            runtime_monitoring_auto_enable = "NOT_CONFIGURED"
            additional_config = {}
            features = org_config.get('Features', [])
            
            for feature in features:
                if feature.get('Name') == 'RUNTIME_MONITORING':
                    runtime_monitoring_found = True
                    runtime_monitoring_auto_enable = feature.get('AutoEnable', 'NONE')
                    
                    # Check additional configuration for the three components
                    additional_configuration = feature.get('AdditionalConfiguration', [])
                    for config in additional_configuration:
                        config_name = config.get('Name')
                        config_auto_enable = config.get('AutoEnable', 'NONE')
                        additional_config[config_name] = config_auto_enable
                    
                    break
            
            # Check if all required components are properly configured
            required_components = {
                'ECS_FARGATE_AGENT_MANAGEMENT': 'ALL',
                'EC2_AGENT_MANAGEMENT': 'ALL',
                'EKS_ADDON_MANAGEMENT': 'ALL'
            }
            
            missing_components = []
            misconfigured_components = []
            
            for component, expected_value in required_components.items():
                if component not in additional_config:
                    missing_components.append(component)
                elif additional_config[component] != expected_value:
                    misconfigured_components.append(f"{component}={additional_config[component]}")
            
            # Determine the status based on the findings
            if runtime_monitoring_found and runtime_monitoring_auto_enable == 'ALL' and not missing_components and not misconfigured_components:
                findings.append(self.create_finding(
                    status="PASS", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value="GuardDuty Runtime Monitoring and all its components are configured for auto-enablement for all accounts (AutoEnable=ALL)", 
                    remediation=""
                ))
            elif not runtime_monitoring_found:
                findings.append(self.create_finding(
                    status="FAIL", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value=f"GuardDuty Runtime Monitoring feature is not configured", 
                    remediation=f"Enable Runtime Monitoring feature and configure auto-enablement for all accounts in {region}"
                ))
            elif runtime_monitoring_auto_enable != 'ALL':
                findings.append(self.create_finding(
                    status="FAIL", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value=f"GuardDuty Runtime Monitoring is configured with AutoEnable={runtime_monitoring_auto_enable}, but should be ALL", 
                    remediation=f"Configure Runtime Monitoring auto-enablement for all accounts in {region} by setting AutoEnable to ALL"
                ))
            elif missing_components:
                findings.append(self.create_finding(
                    status="FAIL", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value=f"GuardDuty Runtime Monitoring is missing the following components: {', '.join(missing_components)}", 
                    remediation=f"Configure all required Runtime Monitoring components in {region}"
                ))
            elif misconfigured_components:
                findings.append(self.create_finding(
                    status="FAIL", 
                    region=region, 
                    account_id=account_id,
                    resource_id=f"guardduty:{region}:{detector_id}", 
                    actual_value=f"GuardDuty Runtime Monitoring has misconfigured components: {', '.join(misconfigured_components)}", 
                    remediation=f"Set AutoEnable to ALL for all Runtime Monitoring components in {region}"
                ))
        
        return findings
