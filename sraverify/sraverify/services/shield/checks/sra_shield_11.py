"""
Check if Shield engagement Lambda function is configured.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_11(ShieldCheck):
    """Check if Shield engagement Lambda function is configured."""

    meta = CheckMeta(
        check_id="SRA-SHIELD-11",
        title="Shield engagement Lambda function is configured",
        description=(
            "This check verifies that a Lambda function named "
            "'AWS_Shield_Engagement_Lambda' exists to automate support case creation during DDoS events."
        ),
        check_logic=(
            "Check for existence of Lambda function named 'AWS_Shield_Engagement_Lambda' in us-east-1."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="Shield",
        resource_type="AWS::Shield::Subscription",
        remediation=Remediation(
            text=(
                "Create a Lambda function named 'AWS_Shield_Engagement_Lambda' in "
                "us-east-1 to automate support case creation during DDoS events."
            ),
            cli=(
                "aws lambda create-function --function-name AWS_Shield_Engagement_Lambda "
                "--runtime python3.11 --role <execution-role-arn> "
                "--handler index.handler --zip-file fileb://function.zip "
                "--region us-east-1"
            ),
            console=(
                "Lambda console in us-east-1, Create function, name it "
                "AWS_Shield_Engagement_Lambda, grant it permission to open AWS "
                "Support cases."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the Shield engagement Lambda function.
        """
        # Check for Lambda function in us-east-1
        region = "us-east-1"
        function_name = "AWS_Shield_Engagement_Lambda"

        lambda_function = self.get_lambda_function(region, function_name)

        if "Error" in lambda_function:
            error_code = lambda_function["Error"].get("Code", "")
            if error_code == "ResourceNotFoundException":
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="Shield engagement Lambda function not found",
                    remediation=f"Create Lambda function named '{function_name}' to automate support case creation during DDoS events"
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=lambda_function["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Lambda API access"
                )
        elif lambda_function.get("Configuration"):
            function_arn = lambda_function["Configuration"].get("FunctionArn", "")
            runtime = lambda_function["Configuration"].get("Runtime", "")
            yield self.passed(
                region=region,
                resource_id=function_arn,
                actual_value=f"Shield engagement Lambda function exists (Runtime: {runtime})"
            )
        else:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="Shield engagement Lambda function not found",
                remediation=f"Create Lambda function named '{function_name}' to automate support case creation during DDoS events"
            )
