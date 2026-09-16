"""
Check if AppSync GraphQL APIs are associated with AWS WAF.
"""
from collections.abc import Iterable

from sraverify.core.availability import service_available_in_region
from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
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
            # AppSync has an endpoint in 31 of the 34 commercial Regions. Where it has none
            # there can be no GraphQL API left unprotected, so there is nothing to
            # report: emit no row at all. A FAIL would assert a
            # misconfiguration that cannot exist, and an ERROR would claim we
            # were unable to look when in fact there was nothing to look at.
            # This fact cannot be changed by an AWS call, so the guard precedes
            # the call.
            if not service_available_in_region("appsync", region):
                logger.debug(
                    f"WAF: AppSync has no endpoint in {region}; "
                    f"{self.check_id} reports nothing for this Region"
                )
                continue

            graphql_apis_response = self.get_graphql_apis(region)

            if "Error" in graphql_apis_response:
                error = graphql_apis_response["Error"]
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
                    web_acl_response = self.get_web_acl_for_resource(region, api_arn)

                    if "Error" in web_acl_response:
                        error = web_acl_response["Error"]
                        # WAFNonexistentItemException is the declared "this resource
                        # has no associated Web ACL" answer, and the only code that
                        # is; every other code is an inability to determine.
                        if self.is_not_configured(error):
                            yield self.failed(
                                region=region,
                                resource_id=api_name or api_id,
                                actual_value="No WAF Web ACL associated",
                                remediation="Associate a WAF Web ACL with this AppSync GraphQL API using the AWS Console, CLI, or API"
                            )
                        else:
                            yield self.error(
                                region=region,
                                resource_id=api_name or api_id,
                                actual_value=(
                                    f"{error['Operation']} failed: {error['Code']}: "
                                    f"{error['Message']}"
                                ),
                                remediation=self._remediation_for(error),
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
