"""
Check if an IAM Access Analyzer unused access analyzer exists for the organization.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.accessanalyzer.base import AccessAnalyzerCheck

#: ``AnalyzerSummary.type`` of an unused access analyzer scoped to the organization.
#: ``ListAnalyzers`` without a ``type`` filter returns every type, observed live,
#: so the shared ``get_analyzers`` accessor already carries it.
ANALYZER_TYPE = "ORGANIZATION_UNUSED_ACCESS"


class SRA_ACCESSANALYZER_08(AccessAnalyzerCheck):
    """Check if an unused access analyzer exists for the organization."""

    meta = CheckMeta(
        check_id="SRA-ACCESSANALYZER-08",
        title="IAM Access Analyzer unused access analyzer exists for the organization",
        description=(
            "This check verifies that an IAM Access Analyzer unused access analyzer "
            "with the AWS organization as its zone of trust is active in the audit "
            "account, which is the IAM Access Analyzer delegated administrator. An "
            "unused access analyzer reports unused IAM roles, unused access keys and "
            "passwords, and unused permissions across every member account. IAM roles "
            "and users are global, so one analyzer in any Region covers the "
            "organization."
        ),
        check_logic=(
            "List analyzers in every scanned Region of the audit account. Passes when "
            "any Region holds an ACTIVE analyzer of type ORGANIZATION_UNUSED_ACCESS. "
            "Fails when every Region answered and none is ACTIVE. One row for the "
            "account."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="IAM Access Analyzer",
        resource_type="AWS::AccessAnalyzer::Analyzer",
        remediation=Remediation(
            text=(
                "From the audit account, create an IAM Access Analyzer unused access "
                "analyzer with the organization as the zone of trust in one Region."
            ),
            cli=(
                "aws accessanalyzer create-analyzer "
                "--analyzer-name org-unused-access "
                "--type ORGANIZATION_UNUSED_ACCESS "
                "--configuration '{\"unusedAccess\":{\"unusedAccessAge\":90}}' "
                "--region <region>"
            ),
            console=(
                "IAM console in the audit account, Access analyzer, Analyzer settings, "
                "Create analyzer, Unused access analysis, choose Current organization "
                "as the zone of trust, Create analyzer."
            ),
        ),
        sra_sections=("Security Tooling account", "IAM Access Analyzer"),
        additional_urls=(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-create-unused.html",
            "https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/checklist.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """Execute the check.

        Yields:
            One global Finding for the account, or one ERROR per Region that could
            not be read when no answering Region holds an active analyzer.
        """
        resource_id = f"access-analyzer/{self.account_id}"
        if not self._clients:
            yield self.error(
                region="global",
                resource_id=resource_id,
                actual_value="No Regions were scanned, so no analyzer could be listed",
                remediation="Re-run with --regions naming at least one enabled Region",
            )
            return

        active, inactive, undetermined = [], [], []
        for region in self._clients:
            response = self.get_analyzers(region)
            if "Error" in response:
                undetermined.append((region, response["Error"]))
                continue
            for analyzer in response.get("analyzers", []):
                if analyzer.get("type") != ANALYZER_TYPE:
                    continue
                bucket = active if analyzer.get("status") == "ACTIVE" else inactive
                bucket.append((region, analyzer))

        if active:
            # An active analyzer anywhere settles the control, whatever the other
            # Regions said: the analyzer covers the whole organization.
            described = "; ".join(
                f"{a['name']} in {region}"
                for region, a in sorted(active, key=lambda x: (x[0], x[1]["name"]))
            )
            first = min(active, key=lambda x: (x[0], x[1]["name"]))[1]
            yield self.passed(
                region="global",
                resource_id=first["arn"],
                actual_value=(
                    f"Unused access analyzer for the organization is ACTIVE: {described}"
                ),
            )
            return

        if undetermined:
            # Absence cannot be asserted while a Region is unread; each unread
            # Region gets its own ERROR row instead of a FAIL.
            for region, error in undetermined:
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"{resource_id}/{region}",
                        actual_value=(
                            "No unused access analyzer for the organization in this Region"
                        ),
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"{resource_id}/{region}",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
            return

        scanned = ", ".join(self._clients)
        if inactive:
            states = "; ".join(
                f"{a['name']} in {region} ({a.get('status')})"
                for region, a in sorted(inactive, key=lambda x: (x[0], x[1]["name"]))
            )
            yield self.failed(
                region="global",
                resource_id=resource_id,
                actual_value=(
                    f"Unused access analyzer for the organization is not ACTIVE: {states}"
                ),
            )
        else:
            yield self.failed(
                region="global",
                resource_id=resource_id,
                actual_value=(
                    "No unused access analyzer for the organization in any scanned "
                    f"Region ({scanned})"
                ),
            )
