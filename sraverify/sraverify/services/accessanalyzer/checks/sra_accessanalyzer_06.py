"""
Check if an IAM Access Analyzer internal access analyzer with account zone of trust exists in every Region.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.accessanalyzer.base import AccessAnalyzerCheck

#: ``AnalyzerSummary.type`` of an internal access analyzer whose zone of trust is
#: the account. ``ListAnalyzers`` without a ``type`` filter returns every type,
#: observed live, so the shared ``get_analyzers`` accessor already carries it.
ANALYZER_TYPE = "ACCOUNT_INTERNAL_ACCESS"


class SRA_ACCESSANALYZER_06(AccessAnalyzerCheck):
    """Check if an internal access analyzer with account zone of trust exists in every Region."""

    meta = CheckMeta(
        check_id="SRA-ACCESSANALYZER-06",
        title=(
            "IAM Access Analyzer internal access analyzer is configured with "
            "account zone of trust in every Region"
        ),
        description=(
            "This check verifies that an IAM Access Analyzer internal access analyzer "
            "with the AWS account as its zone of trust is active in every Region. An "
            "internal access analyzer identifies which IAM users and roles inside the "
            "zone of trust can reach the critical resources it monitors, such as S3 "
            "buckets, DynamoDB tables and RDS snapshots. Analyzers are Regional, so a "
            "Region without one has no internal access findings."
        ),
        check_logic=(
            "List analyzers in each Region. Passes when an analyzer of type "
            "ACCOUNT_INTERNAL_ACCESS has status ACTIVE. Fails when none exists or none "
            "is ACTIVE. The monitored resource selection is not evaluated."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="IAM Access Analyzer",
        resource_type="AWS::AccessAnalyzer::Analyzer",
        remediation=Remediation(
            text=(
                "Create an IAM Access Analyzer internal access analyzer with the "
                "current account as the zone of trust in every enabled Region, and "
                "select the critical resources it should monitor."
            ),
            cli=(
                "aws accessanalyzer create-analyzer "
                "--analyzer-name account-internal-access "
                "--type ACCOUNT_INTERNAL_ACCESS "
                "--configuration '{\"internalAccess\":{\"analysisRule\":{\"inclusions\":"
                "[{\"resourceTypes\":[\"AWS::S3::Bucket\",\"AWS::DynamoDB::Table\"]}]}}}' "
                "--region <region>"
            ),
            console=(
                "IAM console, Access analyzer, Analyzer settings, Create analyzer, "
                "Resource analysis - Internal access, choose Current account as the "
                "zone of trust, add the resources to analyze, Create analyzer. "
                "Repeat per Region."
            ),
        ),
        sra_sections=("Security Tooling account", "IAM Access Analyzer"),
        additional_urls=(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-create-internal.html",
            "https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/checklist.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """Execute the check.

        Yields:
            One Finding per Region.
        """
        for region in self._clients:
            resource_id = f"access-analyzer/{self.account_id}/{region}"
            response = self.get_analyzers(region)

            if "Error" in response:
                error = response["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=resource_id,
                        actual_value=(
                            "No internal access analyzer with account zone of trust "
                            "in this Region"
                        ),
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=resource_id,
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            matching = sorted(
                (a for a in response.get("analyzers", []) if a.get("type") == ANALYZER_TYPE),
                key=lambda a: a.get("name", ""),
            )
            active = [a for a in matching if a.get("status") == "ACTIVE"]

            if active:
                yield self.passed(
                    region=region,
                    resource_id=active[0]["arn"],
                    actual_value=(
                        "Internal access analyzer with account zone of trust is "
                        f"ACTIVE: {', '.join(a['name'] for a in active)}"
                    ),
                )
            elif matching:
                states = ", ".join(f"{a['name']} ({a.get('status')})" for a in matching)
                yield self.failed(
                    region=region,
                    resource_id=matching[0]["arn"],
                    actual_value=(
                        "Internal access analyzer with account zone of trust exists "
                        f"but is not ACTIVE: {states}"
                    ),
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    actual_value=(
                        "No internal access analyzer with account zone of trust "
                        "in this Region"
                    ),
                    remediation=(
                        "Create an internal access analyzer with account zone of trust "
                        f"in {region}: aws accessanalyzer create-analyzer "
                        "--analyzer-name account-internal-access --type "
                        "ACCOUNT_INTERNAL_ACCESS --configuration "
                        "'{\"internalAccess\":{\"analysisRule\":{\"inclusions\":"
                        "[{\"resourceTypes\":[\"AWS::S3::Bucket\",\"AWS::DynamoDB::Table\"]}]}}}' "
                        f"--region {region}"
                    ),
                )
