"""
Check if App Runner services are associated with AWS WAF.
"""
from collections.abc import Iterable

from sraverify.core.availability import service_available_in_region
from sraverify.core.aws_errors import TRANSPORT_ERROR_CODES
from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
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
            # App Runner does not exist in every Region. Where it has no
            # endpoint there can be no App Runner service left unprotected, so
            # there is nothing to report: emit no row at all. A FAIL would
            # assert a misconfiguration that cannot exist, and an ERROR would
            # claim we were unable to look when in fact there was nothing to
            # look at. This fact cannot be changed by an AWS call, so the guard
            # precedes the call.
            # Called directly rather than through a WAFCheck delegate. The
            # delegate was the original implementation, lifted to core/ so every
            # service could reach it and left behind only so the WAF checks did
            # not have to change in the same commit; this is the one call site.
            if not service_available_in_region("apprunner", region):
                logger.debug(
                    f"WAF: App Runner has no endpoint in {region}; "
                    f"SRA-WAF-06 reports nothing for this Region"
                )
                continue

            services_response = self.get_apprunner_services(region)

            # App Runner is supported here but the call still failed, so the
            # control could not be evaluated. A transport failure and a denied
            # permission need different advice.
            if "Error" in services_response:
                error = services_response["Error"]
                # App Runner is supported here but the call still failed, so the
                # control could not be evaluated. This check keeps its own wording
                # for the transport case rather than deferring to
                # _remediation_for: it is the one check that has already
                # established the endpoint *should* exist in this Region, and a
                # helper that knows only the code cannot say that.
                if error["Code"] in TRANSPORT_ERROR_CODES:
                    remediation = (
                        f"App Runner is available in {region} but its endpoint could not be "
                        f"reached. Check network egress and DNS resolution from the scanning "
                        f"environment, then re-run."
                    )
                else:
                    remediation = self._remediation_for(error)
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=remediation
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

                web_acl_response = self.get_web_acl_for_resource(region, service_arn)

                if "Error" in web_acl_response:
                    error = web_acl_response["Error"]
                    # WAFNonexistentItemException is the declared "this resource
                    # has no associated Web ACL" answer, and the only code that
                    # is; every other code is an inability to determine.
                    if self.is_not_configured(error):
                        yield self.failed(
                            region=region,
                            resource_id=service_name or service_id,
                            actual_value="No WAF Web ACL associated",
                            remediation="Associate a WAF Web ACL with this App Runner service using the AWS Console, CLI, or API"
                        )
                    else:
                        yield self.error(
                            region=region,
                            resource_id=service_name or service_id,
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
