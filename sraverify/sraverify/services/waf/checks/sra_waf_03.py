"""
Check if API Gateway REST APIs are associated with AWS WAF.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.waf.base import WAFCheck


class SRA_WAF_03(WAFCheck):
    """Check if API Gateway REST APIs are associated with AWS WAF."""

    meta = CheckMeta(
        check_id="SRA-WAF-03",
        title="API Gateway REST APIs should be associated with AWS WAF",
        description=(
            "Ensures that all API Gateway REST APIs are protected by AWS WAF "
            "web ACLs to filter malicious traffic"
        ),
        check_logic=(
            "Lists all API Gateway REST APIs and verifies each has a WAF web "
            "ACL associated"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="WAF",
        resource_type="AWS::ApiGateway::RestApi",
        remediation=Remediation(
            text=(
                "Associate a regional WAF Web ACL with every deployed API Gateway "
                "REST API stage so that malicious requests are filtered before "
                "they reach the integration."
            ),
            cli=(
                "aws wafv2 associate-web-acl "
                "--web-acl-arn arn:aws:wafv2:<region>:<account-id>:regional/webacl/<name>/<id> "
                "--resource-arn arn:aws:apigateway:<region>::/restapis/<api-id>/stages/<stage-name> "
                "--region <region>"
            ),
            console=(
                "API Gateway console, select the REST API, Stages, select the "
                "stage, Web application firewall, Edit, associate a web ACL."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per API Gateway REST API stage.
        """
        for region in self.regions:
            rest_apis_response = self.get_rest_apis(region)

            if "Error" in rest_apis_response:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=rest_apis_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for API Gateway and WAF API access"
                )
                continue

            rest_apis = rest_apis_response.get("items", [])

            if not rest_apis:
                yield self.passed(
                    region=region,
                    resource_id="No REST APIs",
                    actual_value="No API Gateway REST APIs found"
                )
                continue

            for api in rest_apis:
                api_id = api.get("id")
                api_name = api.get("name")

                # Get all stages for this API
                stages_response = self.get_stages(region, api_id)

                if "Error" in stages_response:
                    yield self.error(
                        region=region,
                        resource_id=api_name or api_id,
                        actual_value=stages_response["Error"].get("Message", "Unknown error"),
                        remediation="Check IAM permissions for API Gateway access"
                    )
                    continue

                stages = stages_response.get("item", [])

                if not stages:
                    yield self.failed(
                        region=region,
                        resource_id=api_name or api_id,
                        actual_value="No stages deployed",
                        remediation="Deploy the API to a stage and associate a WAF Web ACL"
                    )
                    continue

                # Check each stage for WAF association
                for stage in stages:
                    stage_name = stage.get("stageName")
                    resource_id = f"{api_name or api_id}/{stage_name}"

                    # Construct the API Gateway stage ARN for WAF association check
                    api_arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stage_name}"

                    client = self.get_client(region)
                    if not client:
                        continue

                    web_acl_response = client.get_web_acl_for_resource(api_arn)

                    if "Error" in web_acl_response:
                        error_code = web_acl_response["Error"].get("Code")
                        if error_code == "AccessDeniedException":
                            yield self.error(
                                region=region,
                                resource_id=resource_id,
                                actual_value=web_acl_response["Error"].get("Message", "Access denied"),
                                remediation="Check IAM permissions for wafv2:GetWebACLForResource"
                            )
                        else:
                            yield self.failed(
                                region=region,
                                resource_id=resource_id,
                                actual_value="No WAF Web ACL associated",
                                remediation="Associate a WAF Web ACL with this API Gateway stage using the AWS Console, CLI, or API"
                            )
                        continue

                    web_acl = web_acl_response.get("WebACL")

                    if web_acl:
                        web_acl_name = web_acl.get("Name", "Unknown")
                        yield self.passed(
                            region=region,
                            resource_id=resource_id,
                            actual_value=f"WAF Web ACL associated: {web_acl_name}"
                        )
                    else:
                        yield self.failed(
                            region=region,
                            resource_id=resource_id,
                            actual_value="No WAF Web ACL associated",
                            remediation="Associate a WAF Web ACL with this API Gateway stage using the AWS Console, CLI, or API"
                        )
