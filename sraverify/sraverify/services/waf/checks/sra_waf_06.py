"""
Check if App Runner services are associated with AWS WAF.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.waf.base import WAFCheck


class SRA_WAF_06(WAFCheck):
    """Check if App Runner services are associated with AWS WAF."""

    meta = CheckMeta(
        check_id="SRA-WAF-06",
        title="App Runner services should be associated with AWS WAF",
        description=(
            "Ensures that all App Runner services are protected by AWS WAF web "
            "ACLs to filter malicious traffic"
        ),
        check_logic=(
            "Lists all App Runner services and verifies each has a WAF web ACL "
            "associated"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="WAF",
        resource_type="AWS::AppRunner::Service",
        remediation=Remediation(
            text=(
                "Associate a regional WAF Web ACL with every App Runner service so "
                "that malicious requests are filtered before they reach the "
                "container."
            ),
            cli=(
                "aws wafv2 associate-web-acl "
                "--web-acl-arn arn:aws:wafv2:<region>:<account-id>:regional/webacl/<name>/<id> "
                "--resource-arn <app-runner-service-arn> --region <region>"
            ),
            console=(
                "AWS App Runner console, select the service, Configuration, "
                "AWS WAF, Edit, associate a web ACL."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per App Runner service.
        """
        for region in self.regions:
            services_response = self.get_apprunner_services(region)

            if "Error" in services_response:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=services_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for App Runner and WAF API access"
                )
                continue

            services = services_response.get("ServiceSummaryList", [])

            if not services:
                yield self.passed(
                    region=region,
                    resource_id="No App Runner services",
                    actual_value="No App Runner services found"
                )
                continue

            for service in services:
                service_arn = service.get("ServiceArn")
                service_name = service.get("ServiceName")
                service_id = service.get("ServiceId")

                client = self.get_client(region)
                if not client:
                    continue

                web_acl_response = client.get_web_acl_for_resource(service_arn)

                if "Error" in web_acl_response:
                    error_code = web_acl_response["Error"].get("Code")
                    if error_code == "AccessDeniedException":
                        yield self.error(
                            region=region,
                            resource_id=service_name or service_id,
                            actual_value=web_acl_response["Error"].get("Message", "Access denied"),
                            remediation="Check IAM permissions for wafv2:GetWebACLForResource and apprunner:DescribeWebAclForService"
                        )
                    else:
                        yield self.failed(
                            region=region,
                            resource_id=service_name or service_id,
                            actual_value="No WAF Web ACL associated",
                            remediation="Associate a WAF Web ACL with this App Runner service using the AWS Console, CLI, or API"
                        )
                    continue

                web_acl = web_acl_response.get("WebACL")

                if web_acl:
                    web_acl_name = web_acl.get("Name", "Unknown")
                    yield self.passed(
                        region=region,
                        resource_id=service_name or service_id,
                        actual_value=f"WAF Web ACL associated: {web_acl_name}"
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=service_name or service_id,
                        actual_value="No WAF Web ACL associated",
                        remediation="Associate a WAF Web ACL with this App Runner service using the AWS Console, CLI, or API"
                    )
