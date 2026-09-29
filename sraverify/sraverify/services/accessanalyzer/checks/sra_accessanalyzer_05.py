"""
Check if an IAM Access Analyzer internal access analyzer with organization zone of trust exists in every Region.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.accessanalyzer.base import AccessAnalyzerCheck

#: ``AnalyzerSummary.type`` of an internal access analyzer whose zone of trust is
#: the organization. ``ListAnalyzers`` without a ``type`` filter returns every
#: type, observed live, so the shared ``get_analyzers`` accessor already carries it.
ANALYZER_TYPE = "ORGANIZATION_INTERNAL_ACCESS"


class SRA_ACCESSANALYZER_05(AccessAnalyzerCheck):
    """Check if an internal access analyzer with organization zone of trust exists in every Region."""

    meta = CheckMeta(
        check_id="SRA-ACCESSANALYZER-05",
        title=(
            "IAM Access Analyzer internal access analyzer is configured with "
            "organization zone of trust in every Region"
        ),
        description=(
            "This check verifies that an IAM Access Analyzer internal access analyzer "
            "with the AWS organization as its zone of trust is active in every Region "
            "of the audit account, which is the IAM Access Analyzer delegated "
            "administrator. An internal access analyzer identifies which IAM users and "
            "roles in the organization can reach the critical resources it monitors, "
            "such as S3 buckets, DynamoDB tables and RDS snapshots. Analyzers are "
            "Regional, so a Region without one has no internal access findings."
        ),
        check_logic=(
            "List analyzers in each Region of the audit account. Passes when an "
            "analyzer of type ORGANIZATION_INTERNAL_ACCESS has status ACTIVE. Fails "
            "when none exists or none is ACTIVE. The monitored resource selection is "
            "not evaluated."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="IAM Access Analyzer",
        resource_type="AWS::AccessAnalyzer::Analyzer",
        remediation=Remediation(
            text=(
                "From the audit account, create an IAM Access Analyzer internal access "
                "analyzer with the organization as the zone of trust in every enabled "
                "Region, and select the accounts and critical resources it should "
                "monitor."
            ),
            cli=(
                "aws accessanalyzer create-analyzer "
                "--analyzer-name org-internal-access "
                "--type ORGANIZATION_INTERNAL_ACCESS "
                "--configuration '{\"internalAccess\":{\"analysisRule\":{\"inclusions\":"
                "[{\"accountIds\":[\"<account-id>\"],"
                "\"resourceTypes\":[\"AWS::S3::Bucket\",\"AWS::DynamoDB::Table\"]}]}}}' "
                "--region <region>"
            ),
            console=(
                "IAM console in the audit account, Access analyzer, Analyzer settings, "
                "Create analyzer, Resource analysis - Internal access, choose Entire "
                "organization as the zone of trust, add the resources to analyze, "
                "Submit. Repeat per Region."
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
                            "No internal access analyzer with organization zone of "
                            "trust in this Region"
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
                        "Internal access analyzer with organization zone of trust is "
                        f"ACTIVE: {', '.join(a['name'] for a in active)}"
                    ),
                )
            elif matching:
                states = ", ".join(f"{a['name']} ({a.get('status')})" for a in matching)
                yield self.failed(
                    region=region,
                    resource_id=matching[0]["arn"],
                    actual_value=(
                        "Internal access analyzer with organization zone of trust "
                        f"exists but is not ACTIVE: {states}"
                    ),
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    actual_value=(
                        "No internal access analyzer with organization zone of trust "
                        "in this Region"
                    ),
                    remediation=(
                        "From the audit account, create an internal access analyzer "
                        f"with organization zone of trust in {region}: aws "
                        "accessanalyzer create-analyzer --analyzer-name "
                        "org-internal-access --type ORGANIZATION_INTERNAL_ACCESS "
                        "--configuration '{\"internalAccess\":{\"analysisRule\":"
                        "{\"inclusions\":[{\"accountIds\":[\"<account-id>\"],"
                        "\"resourceTypes\":[\"AWS::S3::Bucket\",\"AWS::DynamoDB::Table\"]}]}}}' "
                        f"--region {region}"
                    ),
                )
