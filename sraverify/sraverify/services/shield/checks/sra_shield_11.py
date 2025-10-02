"""
Check if Shield engagement Lambda function is configured.
"""
from typing import Dict, List, Any
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_11(ShieldCheck):
    """Check if Shield engagement Lambda function is configured."""

    def __init__(self):
        """Initialize Shield engagement Lambda function check."""
        super().__init__()
        self.check_id = "SRA-SHIELD-11"
        self.check_name = "Shield engagement Lambda function is configured"
        self.description = ("This check verifies that a Lambda function named "
                            "'AWS_Shield_Engagement_Lambda' exists to automate support case creation during DDoS events.")
        self.severity = "MEDIUM"
        self.check_logic = "Check for existence of Lambda function named 'AWS_Shield_Engagement_Lambda' in us-east-1."

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """
        # Check for Lambda function in us-east-1
        region = "us-east-1"
        function_name = "AWS_Shield_Engagement_Lambda"

        lambda_function = self.get_lambda_function(region, function_name)

        if "Error" in lambda_function:
            error_code = lambda_function["Error"].get("Code", "")
            if error_code == "ResourceNotFoundException":
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value="Shield engagement Lambda function not found",
                    remediation=f"Create Lambda function named '{function_name}' to automate support case creation during DDoS events"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=lambda_function["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Lambda API access"
                ))
        elif lambda_function.get("Configuration"):
            function_arn = lambda_function["Configuration"].get("FunctionArn", "")
            runtime = lambda_function["Configuration"].get("Runtime", "")
            self.findings.append(self.create_finding(
                status="PASS",
                region=region,
                resource_id=function_arn,
                actual_value=f"Shield engagement Lambda function exists (Runtime: {runtime})",
                remediation=""
            ))
        else:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="Shield engagement Lambda function not found",
                remediation=f"Create Lambda function named '{function_name}' to automate support case creation during DDoS events"
            ))

        return self.findings
