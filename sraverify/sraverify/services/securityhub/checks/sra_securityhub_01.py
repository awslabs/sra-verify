"""
SRA-SECURITYHUB-01: Security Hub check.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SECURITYHUB_01(SecurityHubCheck):
    """Check if Security Hub enabled account level standards exist."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SECURITYHUB-01"
        self.check_name = "Security Hub enabled account level standards exist"
        self.account_type = "application"  # This check is for application accounts
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether a list of enabled Security Hub standards for the current AWS account exists."
        )
        self.check_logic = (
            "Check evaluates if there are any standards enabled in the AWS account and AWS region. "
            "Check PASS if there are any standards enabled."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        
        # If no regions have Security Hub available, return a single failure
        if not self._clients:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id="securityhub:global",
                    checked_value="Security Hub is enabled",
                    actual_value="Security Hub not available in any region",
                    remediation="Enable Security Hub in at least one region"
                )
            )
            return findings
        
        # Check each region where Security Hub is available
        for region in self.regions:
            # Get enabled standards for the current account in this region
            enabled_standards = self.get_enabled_standards(region)
            
            # If None is returned, Security Hub is not enabled
            if enabled_standards is None:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=f"securityhub:service/{self.account_id}",
                        checked_value="Security Hub is enabled",
                        actual_value=f"Security Hub is not enabled in region {region}",
                        remediation=(
                            "Enable Security Hub in this region. In the AWS console, navigate to Security Hub and enable the service. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securityhub enable-security-hub --region {region}"
                        )
                    )
                )
                continue
            
            # Extract standard names for better reporting
            standard_names = []
            for standard in enabled_standards:
                standard_arn = standard.get('StandardsArn', '')
                # Extract the standard name from the ARN
                if '/standards/' in standard_arn:
                    standard_name = standard_arn.split('/standards/')[1]
                    standard_names.append(standard_name)
                else:
                    standard_names.append(standard_arn)
            
            # Format the list of standards for reporting
            standards_list = ', '.join(standard_names) if standard_names else "None"
            
            if not enabled_standards:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=f"securityhub:standards/{self.account_id}",
                        checked_value="Security Hub standards are enabled",
                        actual_value=f"Account {self.account_id} region {region} has no Security Hub standards enabled",
                        remediation=(
                            "Enable Security Hub standards for this account. In the Security Hub console, "
                            "navigate to Settings > Standards and enable the required standards. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securityhub batch-enable-standards --standards-subscription-requests 'StandardsArn=arn:aws:securityhub:{region}::standards/aws-foundational-security-best-practices/v/1.0.0' --region {region}"
                        )
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=f"securityhub:standards/{self.account_id}",
                        checked_value="Security Hub standards are enabled",
                        actual_value=f"Account {self.account_id} region {region} has the following standards enabled: {standards_list}",
                        remediation="No remediation needed"
                    )
                )
        
        return findings
