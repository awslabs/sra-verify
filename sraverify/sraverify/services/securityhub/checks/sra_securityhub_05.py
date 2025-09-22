"""
SRA-SECURITYHUB-05: Security Hub check.
"""
from typing import List, Dict, Any
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.core.logging import logger


class SRA_SECURITYHUB_05(SecurityHubCheck):
    """Check if Security Hub has integrations with findings generating products."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-SECURITYHUB-05"
        self.check_name = "Security Hub integration with findings generating products"
        self.account_type = "audit"  # This check is for the audit account
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies whether Security Hub has expected integration with AWS services "
            "and third party products to ingest security findings."
        )
        self.check_logic = (
            "Check looks in audit account to evaluate see what types of findings are being ingested. "
            "PASS if there are any products listed."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        
        # Check each region separately
        for region in self.regions:
            # Get enabled products for import in this specific region
            enabled_products = self.get_enabled_products_for_import(region)
            
            resource_id = f"securityhub:integrations/{self.account_id}"
            
            # Check if Security Hub is not enabled (None response)
            if enabled_products is None:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Hub enabled with product integrations",
                        actual_value=f"Security Hub is not enabled in region {region}",
                        remediation=(
                            f"Enable Security Hub in region {region} first. "
                            "Use the AWS CLI command: "
                            f"aws securityhub enable-security-hub --region {region}, "
                            "then configure product integrations."
                        )
                    )
                )
            elif not enabled_products:
                # Security Hub is enabled but no products configured
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="List of products that are enabled in Security Hub",
                        actual_value=f"Security Hub has no enabled security integrations in region {region}",
                        remediation=(
                            "Enable integrations with security findings generating products. In the Security Hub console, "
                            "navigate to Integrations and enable relevant AWS services like GuardDuty, Inspector, Macie, etc. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securityhub enable-import-findings-for-product --product-arn [PRODUCT_ARN] --region {region}"
                        )
                    )
                )
            else:
                # Security Hub is enabled with products
                product_names = []
                for product_arn in enabled_products:
                    # Extract the product name from the ARN
                    if '/product-subscription/' in product_arn:
                        product_name = product_arn.split('/product-subscription/')[1]
                        product_names.append(product_name)
                    else:
                        product_names.append(product_arn)
                
                products_list = ', '.join(product_names) if product_names else "None"
                
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="List of products that are enabled in Security Hub",
                        actual_value=f"Security Hub has enabled security integrations in region {region}: {products_list}",
                        remediation="No remediation needed"
                    )
                )
        
        return findings
