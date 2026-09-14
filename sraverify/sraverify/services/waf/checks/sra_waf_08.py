"""
Check if Amplify applications are associated with AWS WAF.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.waf.base import WAFCheck


class SRA_WAF_08(WAFCheck):
    """Check if Amplify applications are associated with AWS WAF."""

    meta = CheckMeta(
        check_id="SRA-WAF-08",
        title="Amplify applications should be associated with AWS WAF",
        description=(
            "Ensures that all Amplify applications are protected by AWS WAF web "
            "ACLs to filter malicious traffic"
        ),
        check_logic=(
            "Lists all Amplify applications and verifies each has a WAF web ACL "
            "associated"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="WAF",
        resource_type="AWS::Amplify::App",
        remediation=Remediation(
            text=(
                "Associate a WAF Web ACL with every Amplify application and confirm "
                "the firewall status is ENABLED so that malicious requests are "
                "filtered."
            ),
            cli=(
                "aws wafv2 associate-web-acl "
                "--web-acl-arn arn:aws:wafv2:<region>:<account-id>:regional/webacl/<name>/<id> "
                "--resource-arn arn:aws:amplify:<region>:<account-id>:apps/<app-id> "
                "--region <region>"
            ),
            console=(
                "AWS Amplify console, select the app, Hosting, Firewall, "
                "Enable firewall, associate a web ACL."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Amplify application.
        """
        for region in self.regions:
            apps_response = self.get_amplify_apps(region)

            if "Error" in apps_response:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=apps_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Amplify and WAF API access"
                )
                continue

            apps = apps_response.get("apps", [])

            if not apps:
                yield self.passed(
                    region=region,
                    resource_id="No Amplify apps",
                    actual_value="No Amplify applications found"
                )
                continue

            for app in apps:
                app_id = app.get("appId")
                app_name = app.get("name")
                waf_config = app.get("wafConfiguration", {})

                # Check WAF configuration from the app response
                waf_status = waf_config.get("wafStatus")
                web_acl_arn = waf_config.get("webAclArn")

                if waf_status == "ENABLED" and web_acl_arn:
                    yield self.passed(
                        region=region,
                        resource_id=app_name or app_id,
                        actual_value=f"WAF Web ACL associated: {web_acl_arn}"
                    )
                else:
                    yield self.failed(
                        region=region,
                        resource_id=app_name or app_id,
                        actual_value="No WAF Web ACL associated",
                        remediation="Associate a WAF Web ACL with this Amplify application using the AWS Console, CLI, or API"
                    )
