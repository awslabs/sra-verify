"""
Check if Verified Access instances are associated with AWS WAF.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.waf.base import WAFCheck


class SRA_WAF_07(WAFCheck):
    """Check if Verified Access instances are associated with AWS WAF."""

    meta = CheckMeta(
        check_id="SRA-WAF-07",
        title="Verified Access instances should be associated with AWS WAF",
        description=(
            "Ensures that all Verified Access instances are protected by AWS WAF "
            "web ACLs to filter malicious traffic"
        ),
        check_logic=(
            "Lists all Verified Access instances and verifies each has a WAF web "
            "ACL associated"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="WAF",
        resource_type="AWS::EC2::VerifiedAccessInstance",
        remediation=Remediation(
            text=(
                "Associate a regional WAF Web ACL with every Verified Access "
                "instance so that malicious requests are filtered before they "
                "reach the applications behind it."
            ),
            cli=(
                "aws wafv2 associate-web-acl "
                "--web-acl-arn arn:aws:wafv2:<region>:<account-id>:regional/webacl/<name>/<id> "
                "--resource-arn arn:aws:ec2:<region>:<account-id>:verified-access-instance/<instance-id> "
                "--region <region>"
            ),
            console=(
                "Amazon VPC console, Verified Access instances, select the "
                "instance, Web application firewall, Associate a web ACL."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Verified Access instance.
        """
        for region in self.regions:
            instances_response = self.get_verified_access_instances(region)

            if "Error" in instances_response:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=instances_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for EC2 and WAF API access"
                )
                continue

            instances = instances_response.get("VerifiedAccessInstances", [])

            if not instances:
                yield self.passed(
                    region=region,
                    resource_id="No Verified Access instances",
                    actual_value="No Verified Access instances found"
                )
                continue

            for instance in instances:
                instance_id = instance.get("VerifiedAccessInstanceId")
                description = instance.get("Description", "")

                # Construct the Verified Access instance ARN for WAF association check
                # Format: arn:partition:ec2:region:account-id:verified-access-instance/instance-id
                instance_arn = f"arn:aws:ec2:{region}:{self.account_id}:verified-access-instance/{instance_id}"

                client = self.get_client(region)
                if not client:
                    continue

                web_acl_response = client.get_web_acl_for_resource(instance_arn)

                if "Error" in web_acl_response:
                    error_code = web_acl_response["Error"].get("Code")
                    if error_code == "AccessDeniedException":
                        yield self.error(
                            region=region,
                            resource_id=instance_id,
                            actual_value=web_acl_response["Error"].get("Message", "Access denied"),
                            remediation="Check IAM permissions for wafv2:GetWebACLForResource and ec2:GetVerifiedAccessInstanceWebAcl"
                        )
                    else:
                        yield self.failed(
                            region=region,
                            resource_id=instance_id,
                            actual_value="No WAF Web ACL associated",
                            remediation="Associate a WAF Web ACL with this Verified Access instance using the AWS Console, CLI, or API"
                        )
                    continue

                web_acl = web_acl_response.get("WebACL")

                if web_acl:
                    web_acl_name = web_acl.get("Name", "Unknown")
                    yield self.passed(
                        region=region,
                        resource_id=instance_id,
                        actual_value=f"WAF Web ACL associated: {web_acl_name}"
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=instance_id,
                        actual_value="No WAF Web ACL associated",
                        remediation="Associate a WAF Web ACL with this Verified Access instance using the AWS Console, CLI, or API"
                    )
