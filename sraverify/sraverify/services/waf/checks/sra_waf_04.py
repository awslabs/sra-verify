"""
Check if AppSync GraphQL APIs are associated with AWS WAF.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.waf.base import WAFCheck


class SRA_WAF_04(WAFCheck):
    """Check if AppSync GraphQL APIs are associated with AWS WAF."""

    meta = CheckMeta(
        check_id="SRA-WAF-04",
        title="AppSync GraphQL APIs should be associated with AWS WAF",
        description=(
            "Ensures that all AppSync GraphQL APIs are protected by AWS WAF "
            "web ACLs to filter malicious traffic"
        ),
        check_logic=(
            "Lists all AppSync GraphQL APIs and verifies each has a WAF web ACL "
            "associated"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="WAF",
        resource_type="AWS::AppSync::GraphQLApi",
        remediation=Remediation(
            text=(
                "Associate a regional WAF Web ACL with every AppSync GraphQL API "
                "so that malicious queries are filtered before they reach the "
                "resolvers."
            ),
            cli=(
                "aws wafv2 associate-web-acl "
                "--web-acl-arn arn:aws:wafv2:<region>:<account-id>:regional/webacl/<name>/<id> "
                "--resource-arn arn:aws:appsync:<region>:<account-id>:apis/<api-id> "
                "--region <region>"
            ),
            console=(
                "AWS AppSync console, select the API, Settings, "
                "Web application firewall, associate a web ACL."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per AppSync GraphQL API.
        """
        for region in self.regions:
            graphql_apis_response = self.get_graphql_apis(region)

            if "Error" in graphql_apis_response:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=graphql_apis_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for AppSync and WAF API access"
                )
                continue

            graphql_apis = graphql_apis_response.get("graphqlApis", [])

            if not graphql_apis:
                yield self.passed(
                    region=region,
                    resource_id="No GraphQL APIs",
                    actual_value="No AppSync GraphQL APIs found"
                )
                continue

            for api in graphql_apis:
                api_arn = api.get("arn")
                api_name = api.get("name")
                api_id = api.get("apiId")

                # Check if WAF is already associated (wafWebAclArn field)
                waf_web_acl_arn = api.get("wafWebAclArn")

                if waf_web_acl_arn:
                    yield self.passed(
                        region=region,
                        resource_id=api_name or api_id,
                        actual_value=f"WAF Web ACL associated: {waf_web_acl_arn}"
                    )
                else:
                    # Double-check using WAF API
                    client = self.get_client(region)
                    if not client:
                        continue

                    web_acl_response = client.get_web_acl_for_resource(api_arn)

                    if "Error" in web_acl_response:
                        yield self.failed(
                            region=region,
                            resource_id=api_name or api_id,
                            actual_value="No WAF Web ACL associated",
                            remediation="Associate a WAF Web ACL with this AppSync GraphQL API using the AWS Console, CLI, or API"
                        )
                        continue

                    web_acl = web_acl_response.get("WebACL")

                    if web_acl:
                        web_acl_name = web_acl.get("Name", "Unknown")
                        yield self.passed(
                            region=region,
                            resource_id=api_name or api_id,
                            actual_value=f"WAF Web ACL associated: {web_acl_name}"
                        )
                    else:
                        yield self.failed(
                            region=region,
                            resource_id=api_name or api_id,
                            actual_value="No WAF Web ACL associated",
                            remediation="Associate a WAF Web ACL with this AppSync GraphQL API using the AWS Console, CLI, or API"
                        )
