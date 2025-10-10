from typing import Dict, List, Any
from sraverify.services.waf.base import WAFCheck

class SRA_WAF_09(WAFCheck):
    def __init__(self):
        super().__init__()
        self.resource_type = "AWS::WAFv2::WebACL"
        self.check_id = "SRA-WAF-09"
        self.check_name = "WAF Web ACLs should have logging enabled"
        self.description = "Ensures that all WAF Web ACLs have logging enabled to capture traffic analysis data"
        self.severity = "MEDIUM"
        self.check_logic = "Lists all WAF Web ACLs and verifies each has logging configuration enabled"

    def execute(self) -> List[Dict[str, Any]]:
        # Check both regional and global (CloudFront) Web ACLs
        scopes = [("REGIONAL", self.regions), ("CLOUDFRONT", ["us-east-1"])]
        
        for scope, regions in scopes:
            for region in regions:
                web_acls_response = self.get_web_acls(region, scope)

                if "Error" in web_acls_response:
                    self.findings.append(self.create_finding(
                        status="ERROR",
                        region=region,
                        resource_id=None,
                        actual_value=web_acls_response["Error"].get("Message", "Unknown error"),
                        remediation="Check IAM permissions for WAF API access"
                    ))
                    continue

                web_acls = web_acls_response.get("WebACLs", [])

                if not web_acls:
                    self.findings.append(self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=f"No {scope} Web ACLs",
                        actual_value=f"No {scope} WAF Web ACLs found",
                        remediation="No action needed"
                    ))
                    continue

                for web_acl in web_acls:
                    web_acl_arn = web_acl.get("ARN")
                    web_acl_name = web_acl.get("Name")
                    web_acl_id = web_acl.get("Id")
                    
                    client = self.get_client(region)
                    if not client:
                        continue

                    logging_response = client.get_logging_configuration(web_acl_arn)

                    if "Error" in logging_response:
                        self.findings.append(self.create_finding(
                            status="ERROR",
                            region=region,
                            resource_id=web_acl_name or web_acl_id,
                            actual_value=logging_response["Error"].get("Message", "Unknown error"),
                            remediation="Check IAM permissions for WAF logging configuration access"
                        ))
                        continue

                    logging_config = logging_response.get("LoggingConfiguration")

                    if logging_config:
                        log_destinations = logging_config.get("LogDestinationConfigs", [])
                        if log_destinations:
                            destinations_str = ", ".join(log_destinations)
                            self.findings.append(self.create_finding(
                                status="PASS",
                                region=region,
                                resource_id=web_acl_name or web_acl_id,
                                actual_value=f"Logging enabled to: {destinations_str}",
                                remediation="No action needed"
                            ))
                        else:
                            self.findings.append(self.create_finding(
                                status="FAIL",
                                region=region,
                                resource_id=web_acl_name or web_acl_id,
                                actual_value="Logging configuration exists but no destinations configured",
                                remediation="Configure logging destinations for this WAF Web ACL using CloudWatch Logs, S3, or Kinesis Data Firehose"
                            ))
                    else:
                        self.findings.append(self.create_finding(
                            status="FAIL",
                            region=region,
                            resource_id=web_acl_name or web_acl_id,
                            actual_value="No logging configuration found",
                            remediation="Enable logging for this WAF Web ACL using CloudWatch Logs, S3, or Kinesis Data Firehose"
                        ))

        return self.findings
