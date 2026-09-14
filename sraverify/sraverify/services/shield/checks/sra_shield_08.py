"""
Check if Shield Response Team (SRT) access is configured.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_08(ShieldCheck):
    """Check if Shield Response Team (SRT) access is configured."""

    meta = CheckMeta(
        check_id="SRA-SHIELD-08",
        title="Shield Response Team (SRT) access is configured",
        description=(
            "This check verifies that AWS Shield Response Team (SRT) "
            "access is configured with an appropriate IAM role."
        ),
        check_logic=(
            "Describe DRT access configuration. Check fails if no role ARN is configured."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="Shield",
        resource_type="AWS::Shield::Subscription",
        remediation=Remediation(
            text=(
                "Configure Shield Response Team access by associating an IAM role "
                "using the AssociateDRTRole API."
            ),
            cli=(
                "aws shield associate-drt-role --role-arn <srt-access-role-arn> "
                "--region us-east-1"
            ),
            console=(
                "AWS WAF & Shield console, AWS Shield, Overview, "
                "Configure SRT access, grant the SRT permission to access the account."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the SRT access configuration.
        """
        # Shield is a global service, check only in us-east-1
        region = "us-east-1"
        drt_access = self.describe_drt_access(region)

        if "Error" in drt_access:
            error_code = drt_access["Error"].get("Code", "")
            if error_code == "ResourceNotFoundException":
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="SRT access not configured",
                    remediation="Configure Shield Response Team access by associating an IAM role using AssociateDRTRole API"
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=drt_access["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Shield API access"
                )
        elif drt_access.get("RoleArn"):
            role_arn = drt_access["RoleArn"]
            bucket_count = len(drt_access.get("LogBucketList", []))
            yield self.passed(
                region=region,
                resource_id="shield:srt-access",
                actual_value=f"SRT access configured with role: {role_arn}, {bucket_count} log bucket(s)"
            )
        else:
            yield self.failed(
                region=region,
                resource_id=None,
                actual_value="SRT access not configured",
                remediation="Configure Shield Response Team access by associating an IAM role using AssociateDRTRole API"
            )
