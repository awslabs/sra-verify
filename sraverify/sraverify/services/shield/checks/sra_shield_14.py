"""
Check if Shield Advanced protected resources have automatic application layer DDoS mitigation enabled.
"""
from typing import Dict, List, Any
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_14(ShieldCheck):
    """Check if Shield Advanced protected resources have automatic application layer DDoS mitigation enabled."""

    def __init__(self):
        """Initialize Shield Advanced automatic mitigation check."""
        super().__init__()
        self.check_id = "SRA-SHIELD-14"
        self.check_name = "Shield Advanced protected resources have automatic application layer DDoS mitigation enabled"
        self.description = ("This check verifies that Shield Advanced protected application layer resources "
                           "(CloudFront distributions and Application Load Balancers) have automatic "
                           "application layer DDoS mitigation enabled with Block action for effective protection.")
        self.severity = "HIGH"
        self.check_logic = ("List Shield protections and check ApplicationLayerAutomaticResponseConfiguration "
                           "status and action for application layer resources.")

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """
        # Shield is a global service, check only in us-east-1
        region = "us-east-1"
        protections = self.list_protections(region)

        if "Error" in protections:
            error_code = protections["Error"].get("Code", "")
            if error_code == "ResourceNotFoundException":
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value="Shield Advanced subscription not found",
                    remediation="Enable Shield Advanced subscription to protect resources"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=protections["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Shield API access"
                ))
        elif protections.get("Protections"):
            # Filter for application layer resources (CloudFront and ALB)
            app_layer_protections = [
                p for p in protections["Protections"]
                if ("cloudfront" in p.get("ResourceArn", "").lower() or
                    "elasticloadbalancing" in p.get("ResourceArn", "").lower())
            ]

            if not app_layer_protections:
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="shield:automatic-mitigation",
                    actual_value="No application layer protected resources found",
                    remediation=""
                ))
                return self.findings

            # Check each application layer resource for automatic mitigation
            for protection in app_layer_protections:
                resource_arn = protection.get("ResourceArn", "")
                
                # Check if ApplicationLayerAutomaticResponseConfiguration exists in the protection
                auto_response_config = protection.get("ApplicationLayerAutomaticResponseConfiguration")
                
                if auto_response_config and auto_response_config.get("Status") == "ENABLED":
                    if "Block" in auto_response_config.get("Action", {}):
                        self.findings.append(self.create_finding(
                            status="PASS",
                            region=region,
                            resource_id=resource_arn,
                            actual_value="Automatic mitigation enabled with Block action",
                            remediation=""
                        ))
                    else:
                        self.findings.append(self.create_finding(
                            status="FAIL",
                            region=region,
                            resource_id=resource_arn,
                            actual_value="Automatic mitigation enabled but using Count action",
                            remediation="Change automatic mitigation action from Count to Block for effective protection"
                        ))
                else:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_arn,
                        actual_value="Automatic application layer DDoS mitigation not enabled",
                        remediation="Enable automatic application layer DDoS mitigation with Block action in Shield Advanced console"
                    ))
        else:
            self.findings.append(self.create_finding(
                status="PASS",
                region=region,
                resource_id=None,
                actual_value="No Shield Advanced protections found",
                remediation=""
            ))

        return self.findings
