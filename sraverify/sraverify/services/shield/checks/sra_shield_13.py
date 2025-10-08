"""
Check if CloudWatch alarms exist for Shield Advanced protected CloudFront and Route53 resources.
"""
from typing import Dict, List, Any
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_13(ShieldCheck):
    """Check if CloudWatch alarms exist for Shield Advanced protected CloudFront and Route53 resources."""

    def __init__(self):
        """Initialize Shield Advanced CloudWatch alarms check."""
        super().__init__()
        self.check_id = "SRA-SHIELD-13"
        self.check_name = "CloudWatch alarms exist for Shield Advanced protected CloudFront and Route53 resources"
        self.description = ("This check verifies that CloudWatch alarms are configured for "
                           "Shield Advanced protected CloudFront distributions and Route53 hosted zones "
                           "to monitor DDoS detection metrics (DDoSDetected).")
        self.severity = "MEDIUM"
        self.check_logic = ("List Shield protections for CloudFront and Route53 resources, "
                           "then check if CloudWatch alarms exist for DDoSDetected metric.")

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """
        # Shield metrics for CloudFront and Route53 are reported in us-east-1
        region = "us-east-1"
        protections = self.list_protections(region)

        if "Error" in protections:
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value=protections["Error"].get("Message", "Unknown error"),
                remediation="Check IAM permissions for Shield API access"
            ))
        elif protections.get("Protections"):
            # Filter for CloudFront and Route53 resources
            cf_r53_protections = [
                p for p in protections["Protections"]
                if ("cloudfront" in p.get("ResourceArn", "").lower() or
                    "route53" in p.get("ResourceArn", "").lower())
            ]

            if not cf_r53_protections:
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id="shield:cloudwatch-alarms",
                    actual_value="No CloudFront or Route53 protected resources found",
                    remediation=""
                ))
                return self.findings

            # Check each resource for CloudWatch alarms
            for protection in cf_r53_protections:
                resource_arn = protection.get("ResourceArn", "")
                protection_name = protection.get("Name", "Unknown")

                # Check for DDoSDetected alarm
                alarms = self.get_cloudwatch_alarms_for_resource(region, resource_arn)

                if "Error" in alarms:
                    self.findings.append(self.create_finding(
                        status="ERROR",
                        region=region,
                        resource_id=resource_arn,
                        actual_value=alarms["Error"].get("Message", "Unknown error"),
                        remediation="Check IAM permissions for CloudWatch API access"
                    ))
                elif alarms.get("DDoSDetectedAlarms"):
                    alarm_names = [alarm["AlarmName"] for alarm in alarms["DDoSDetectedAlarms"]]
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_arn,
                        actual_value=f"DDoSDetected alarms configured: {', '.join(alarm_names)}",
                        remediation=""
                    ))
                else:
                    self.findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_arn,
                        actual_value="No DDoSDetected CloudWatch alarms configured",
                        remediation="Create CloudWatch alarm for DDoSDetected metric to monitor DDoS events"
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
