"""
Check if Cognito user pools are associated with AWS WAF.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.waf.base import WAFCheck


class SRA_WAF_05(WAFCheck):
    """Check if Cognito user pools are associated with AWS WAF."""

    meta = CheckMeta(
        check_id="SRA-WAF-05",
        title="Cognito user pools should be associated with AWS WAF",
        description=(
            "Ensures that all Cognito user pools are protected by AWS WAF web "
            "ACLs to filter malicious traffic"
        ),
        check_logic=(
            "Lists all Cognito user pools and verifies each has a WAF web ACL "
            "associated"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="WAF",
        resource_type="AWS::Cognito::UserPool",
        remediation=Remediation(
            text=(
                "Associate a regional WAF Web ACL with every Cognito user pool so "
                "that credential-stuffing and other malicious requests against "
                "the hosted UI and user pool API are filtered."
            ),
            cli=(
                "aws wafv2 associate-web-acl "
                "--web-acl-arn arn:aws:wafv2:<region>:<account-id>:regional/webacl/<name>/<id> "
                "--resource-arn arn:aws:cognito-idp:<region>:<account-id>:userpool/<user-pool-id> "
                "--region <region>"
            ),
            console=(
                "Amazon Cognito console, select the user pool, "
                "Sign-in experience or Properties, AWS WAF, "
                "Add web ACL, select the web ACL."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Cognito user pool.
        """
        for region in self.regions:
            user_pools_response = self.get_user_pools(region)

            if "Error" in user_pools_response:
                error = user_pools_response["Error"]
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

            user_pools = user_pools_response.get("UserPools", [])

            if not user_pools:
                yield self.passed(
                    region=region,
                    resource_id="No user pools",
                    actual_value="No Cognito user pools found"
                )
                continue

            for pool in user_pools:
                pool_id = pool.get("Id")
                pool_name = pool.get("Name")

                # Construct the Cognito user pool ARN for WAF association check
                # Format: arn:partition:cognito-idp:region:account-id:userpool/user-pool-id
                pool_arn = f"arn:aws:cognito-idp:{region}:{self.account_id}:userpool/{pool_id}"

                web_acl_response = self.get_web_acl_for_resource(region, pool_arn)

                if "Error" in web_acl_response:
                    error = web_acl_response["Error"]
                    # WAFNonexistentItemException is the declared "this resource
                    # has no associated Web ACL" answer, and the only code that
                    # is; every other code is an inability to determine.
                    if self.is_not_configured(error):
                        yield self.failed(
                            region=region,
                            resource_id=pool_name or pool_id,
                            actual_value="No WAF Web ACL associated",
                            remediation="Associate a WAF Web ACL with this Cognito user pool using the AWS Console, CLI, or API"
                        )
                    else:
                        yield self.error(
                            region=region,
                            resource_id=pool_name or pool_id,
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
                        resource_id=pool_name or pool_id,
                        actual_value=f"WAF Web ACL associated: {web_acl_name}"
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=pool_name or pool_id,
                        actual_value="No WAF Web ACL associated",
                        remediation="Associate a WAF Web ACL with this Cognito user pool using the AWS Console, CLI, or API"
                    )
