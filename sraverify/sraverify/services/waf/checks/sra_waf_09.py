"""
Check if WAF Web ACLs have logging enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.waf.base import WAFCheck


class SRA_WAF_09(WAFCheck):
    """Check if WAF Web ACLs have logging enabled."""

    meta = CheckMeta(
        check_id="SRA-WAF-09",
        title="WAF Web ACLs should have logging enabled",
        description=(
            "Ensures that all WAF Web ACLs have logging enabled to capture traffic "
            "analysis data"
        ),
        check_logic=(
            "Lists all WAF Web ACLs and verifies each has logging configuration "
            "enabled"
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="WAF",
        resource_type="AWS::WAFv2::WebACL",
        remediation=Remediation(
            text=(
                "Enable logging on every WAF Web ACL and point it at a CloudWatch "
                "Logs log group, an S3 bucket, or a Kinesis Data Firehose delivery "
                "stream so that request-level traffic can be analyzed."
            ),
            cli=(
                "aws wafv2 put-logging-configuration "
                "--logging-configuration "
                "ResourceArn=<web-acl-arn>,LogDestinationConfigs=<log-destination-arn> "
                "--region <region>"
            ),
            console=(
                "AWS WAF console, Web ACLs, select the web ACL, Logging and "
                "metrics, Logging, Enable, select a logging destination."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per WAF Web ACL.
        """
        # Check both regional and global (CloudFront) Web ACLs
        scopes = [("REGIONAL", self.regions), ("CLOUDFRONT", ["us-east-1"])]

        for scope, regions in scopes:
            for region in regions:
                web_acls_response = self.get_web_acls(region, scope)

                if "Error" in web_acls_response:
                    error = web_acls_response["Error"]
                    yield self.error(
                        region=region,
                        resource_id=None,
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                    continue

                web_acls = web_acls_response.get("WebACLs", [])

                if not web_acls:
                    yield self.passed(
                        region=region,
                        resource_id=f"No {scope} Web ACLs",
                        actual_value=f"No {scope} WAF Web ACLs found"
                    )
                    continue

                for web_acl in web_acls:
                    web_acl_arn = web_acl.get("ARN")
                    web_acl_name = web_acl.get("Name")
                    web_acl_id = web_acl.get("Id")

                    logging_response = self.get_logging_configuration(region, web_acl_arn)

                    if "Error" in logging_response:
                        error = logging_response["Error"]
                        # WAFNonexistentItemException is the declared "no logging
                        # configuration exists" answer, and the only code that is;
                        # every other code is an inability to determine.
                        if self.is_not_configured(error):
                            yield self.failed(
                                region=region,
                                resource_id=web_acl_name or web_acl_id,
                                actual_value="No logging configuration found",
                                remediation="Enable logging for this WAF Web ACL using CloudWatch Logs, S3, or Kinesis Data Firehose"
                            )
                        else:
                            yield self.error(
                                region=region,
                                resource_id=web_acl_name or web_acl_id,
                                actual_value=(
                                    f"{error['Operation']} failed: {error['Code']}: "
                                    f"{error['Message']}"
                                ),
                                remediation=self._remediation_for(error),
                            )
                        continue

                    logging_config = logging_response.get("LoggingConfiguration")

                    if logging_config:
                        log_destinations = logging_config.get("LogDestinationConfigs", [])
                        if log_destinations:
                            destinations_str = ", ".join(log_destinations)
                            yield self.passed(
                                region=region,
                                resource_id=web_acl_name or web_acl_id,
                                actual_value=f"Logging enabled to: {destinations_str}"
                            )
                        else:
                            yield self.failed(
                                region=region,
                                resource_id=web_acl_name or web_acl_id,
                                actual_value="Logging configuration exists but no destinations configured",
                                remediation="Configure logging destinations for this WAF Web ACL using CloudWatch Logs, S3, or Kinesis Data Firehose"
                            )
                    else:
                        yield self.failed(
                            region=region,
                            resource_id=web_acl_name or web_acl_id,
                            actual_value="No logging configuration found",
                            remediation="Enable logging for this WAF Web ACL using CloudWatch Logs, S3, or Kinesis Data Firehose"
                        )
