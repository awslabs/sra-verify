"""
Check if CloudWatch alarms exist for Shield Advanced protected CloudFront and Route53 resources.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_13(ShieldCheck):
    """Check if CloudWatch alarms exist for Shield Advanced protected CloudFront and Route53 resources."""

    meta = CheckMeta(
        check_id="SRA-SHIELD-13",
        title=(
            "CloudWatch alarms exist for Shield Advanced protected CloudFront and "
            "Route53 resources"
        ),
        description=(
            "This check verifies that CloudWatch alarms are configured for "
            "Shield Advanced protected CloudFront distributions and Route53 hosted zones "
            "to monitor DDoS detection metrics (DDoSDetected)."
        ),
        check_logic=(
            "List Shield protections for CloudFront and Route53 resources, "
            "then check if CloudWatch alarms exist for DDoSDetected metric."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="Shield",
        resource_type="AWS::Shield::Subscription",
        remediation=Remediation(
            text=(
                "Create a CloudWatch alarm on the DDoSDetected metric for each "
                "protected CloudFront distribution and Route53 hosted zone."
            ),
            cli=(
                "aws cloudwatch put-metric-alarm --alarm-name <alarm-name> "
                "--namespace AWS/DDoSProtection --metric-name DDoSDetected "
                "--dimensions Name=ResourceArn,Value=<resource-arn> "
                "--statistic Sum --period 60 --evaluation-periods 1 "
                "--threshold 1 --comparison-operator GreaterThanOrEqualToThreshold "
                "--region us-east-1"
            ),
            console=(
                "CloudWatch console in us-east-1, Alarms, Create alarm, "
                "AWS/DDoSProtection namespace, DDoSDetected metric, "
                "select the protected resource ARN."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per protected CloudFront or Route53 resource.
        """
        # Shield metrics for CloudFront and Route53 are reported in us-east-1
        region = "us-east-1"
        protections = self.list_protections(region)

        if "Error" in protections:
            error_code = protections["Error"].get("Code", "")
            if error_code == "ResourceNotFoundException":
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="Shield Advanced subscription not found",
                    remediation="Enable Shield Advanced subscription to protect resources"
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=protections["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Shield API access"
                )
        elif protections.get("Protections"):
            # Filter for CloudFront and Route53 resources
            cf_r53_protections = [
                p for p in protections["Protections"]
                if ("cloudfront" in p.get("ResourceArn", "").lower() or
                    "route53" in p.get("ResourceArn", "").lower())
            ]

            if not cf_r53_protections:
                yield self.passed(
                    region=region,
                    resource_id="shield:cloudwatch-alarms",
                    actual_value="No CloudFront or Route53 protected resources found"
                )
                return

            # Check each resource for CloudWatch alarms
            for protection in cf_r53_protections:
                resource_arn = protection.get("ResourceArn", "")
                protection_name = protection.get("Name", "Unknown")

                # Check for DDoSDetected alarm
                alarms = self.get_cloudwatch_alarms_for_resource(region, resource_arn)

                if "Error" in alarms:
                    yield self.error(
                        region=region,
                        resource_id=resource_arn,
                        actual_value=alarms["Error"].get("Message", "Unknown error"),
                        remediation="Check IAM permissions for CloudWatch API access"
                    )
                elif alarms.get("DDoSDetectedAlarms"):
                    alarm_names = [alarm["AlarmName"] for alarm in alarms["DDoSDetectedAlarms"]]
                    yield self.passed(
                        region=region,
                        resource_id=resource_arn,
                        actual_value=f"DDoSDetected alarms configured: {', '.join(alarm_names)}"
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=resource_arn,
                        actual_value="No DDoSDetected CloudWatch alarms configured",
                        remediation="Create CloudWatch alarm for DDoSDetected metric to monitor DDoS events"
                    )
        else:
            yield self.passed(
                region=region,
                resource_id=None,
                actual_value="No Shield Advanced protections found"
            )
