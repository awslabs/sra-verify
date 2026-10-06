"""
SRA-CLOUDTRAIL-15: Organization trail logs all management events.
"""
from collections.abc import Iterable
from typing import Any, Optional

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck

#: The advanced-selector operators that can narrow ``eventSource``.
_SOURCE_OPERATORS = (
    "Equals", "NotEquals", "StartsWith", "NotStartsWith", "EndsWith", "NotEndsWith",
)


def _as_list(value: Any) -> list:
    """``value`` when it is a list, else an empty list."""
    return value if isinstance(value, list) else []


class SRA_CLOUDTRAIL_15(CloudTrailCheck):
    """Check if the organization trail logs all management events."""

    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-15",
        title="Organization trail logs all management events",
        description=(
            "This check verifies that every organization trail records all management "
            "events, read and write, from every event source. Management events are the "
            "control-plane history an incident responder needs in every account; a trail "
            "that records only read or only write events, excludes management events, or "
            "excludes event sources such as AWS KMS leaves gaps in that history. This is a "
            "step of the Security Incident Response configuration validation procedure."
        ),
        check_logic=(
            "For each organization trail call cloudtrail:GetEventSelectors in its HomeRegion. "
            "Advanced selectors are evaluated when present, else basic selectors. Passes if "
            "one selector includes management events with ReadWriteType All and no excluded "
            "sources, or one advanced selector has eventCategory Management with no readOnly "
            "or eventSource field."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="CloudTrail",
        resource_type="AWS::CloudTrail::Trail",
        remediation=Remediation(
            text=(
                "Restore full management-event logging on the organization trail with aws "
                "cloudtrail put-event-selectors. The call replaces every existing selector on "
                "the trail, so include the trail's data-event selectors in the same call."
            ),
            cli=(
                "aws cloudtrail put-event-selectors --trail-name <trail-arn> "
                "--region <home-region> --event-selectors "
                "'[{\"ReadWriteType\":\"All\",\"IncludeManagementEvents\":true,"
                "\"ExcludeManagementEventSources\":[]}]'\n"
                "aws cloudtrail put-event-selectors --trail-name <trail-arn> "
                "--region <home-region> --advanced-event-selectors "
                "'[{\"Name\":\"Management events\",\"FieldSelectors\":"
                "[{\"Field\":\"eventCategory\",\"Equals\":[\"Management\"]}]}]'"
            ),
            console=(
                "CloudTrail console in the management account, Trails, select the "
                "organization trail, Management events, Edit, select Read and Write, clear "
                "every excluded event source, Save changes."
            ),
        ),
        sra_sections=("Management account", "AWS CloudTrail"),
        additional_urls=(
            "https://docs.aws.amazon.com/security-ir/latest/userguide/config-validation.md",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html",
        ),
    )

    @staticmethod
    def management_event_gap(response: Any) -> Optional[str]:
        """
        Decide whether a ``GetEventSelectors`` response covers all management events.

        The evaluated list is ``AdvancedEventSelectors`` when it is non-empty, else
        ``EventSelectors``; the other list is never consulted. Coverage is decided
        per selector, never by a union across selectors. Never raises; non-dict
        elements are ignored.

        Args:
            response: A successful ``GetEventSelectors`` response.

        Returns:
            ``None`` when some selector of the evaluated list covers every read
            and write management event from every source, otherwise the reason.
        """
        if not isinstance(response, dict):
            response = {}
        advanced = [
            s for s in _as_list(response.get("AdvancedEventSelectors")) if isinstance(s, dict)
        ]
        if _as_list(response.get("AdvancedEventSelectors")):
            return SRA_CLOUDTRAIL_15._advanced_gap(advanced)
        basic = [s for s in _as_list(response.get("EventSelectors")) if isinstance(s, dict)]
        return SRA_CLOUDTRAIL_15._basic_gap(basic)

    @staticmethod
    def _basic_gap(selectors: list) -> Optional[str]:
        """The reason basic ``EventSelectors`` fall short, or ``None``."""
        if any(
            s.get("IncludeManagementEvents") is True
            and s.get("ReadWriteType") == "All"
            and not s.get("ExcludeManagementEventSources")
            for s in selectors
        ):
            return None

        including = [s for s in selectors if s.get("IncludeManagementEvents") is True]
        if not including:
            return "Management events are not included"

        all_rw = [s for s in including if s.get("ReadWriteType") == "All"]
        if not all_rw:
            kinds = sorted({str(s.get("ReadWriteType")) for s in including})
            if len(kinds) == 1:
                return f"Only {kinds[0]} management events are recorded"
            return (
                "Read and write management events are split across selectors "
                f"({', '.join(kinds)}); no single selector records both"
            )

        excluded: set[str] = set()
        for s in all_rw:
            value = s.get("ExcludeManagementEventSources")
            if isinstance(value, list):
                excluded.update(str(v) for v in value)
            elif value:
                excluded.add(str(value))
        return (
            "Management events from these sources are excluded: "
            f"{', '.join(sorted(excluded))}"
        )

    @staticmethod
    def _fields(selector: dict) -> dict:
        """A selector's ``FieldSelectors`` grouped by ``Field``."""
        grouped: dict = {}
        for fs in _as_list(selector.get("FieldSelectors")):
            if isinstance(fs, dict) and isinstance(fs.get("Field"), str):
                grouped.setdefault(fs["Field"], []).append(fs)
        return grouped

    @staticmethod
    def _advanced_gap(selectors: list) -> Optional[str]:
        """The reason ``AdvancedEventSelectors`` fall short, or ``None``."""
        management = []
        for s in selectors:
            fields = SRA_CLOUDTRAIL_15._fields(s)
            if any(
                "Management" in _as_list(fs.get("Equals"))
                for fs in fields.get("eventCategory", [])
            ):
                management.append(fields)

        if any("readOnly" not in f and "eventSource" not in f for f in management):
            return None
        if not management:
            return "Management events are not included"

        if all("readOnly" in f for f in management):
            values = sorted(
                {
                    v
                    for f in management
                    for fs in f["readOnly"]
                    for v in _as_list(fs.get("Equals"))
                    if isinstance(v, str)
                }
            )
            if not values:
                return "Management events are filtered by readOnly"
            if len(values) == 1:
                if values[0] == "true":
                    return "Only read-only management events are recorded"
                if values[0] == "false":
                    return "Only write management events are recorded"
                return f"Only readOnly = {values[0]} management events are recorded"
            return (
                "Read and write management events are split across advanced selectors "
                f"(readOnly = {', '.join(values)}); no single selector records both"
            )

        # Some management selector has no readOnly field, so it fails only on an
        # eventSource field. Describe those fields.
        described = sorted(
            {
                f"{op} {v}"
                for f in management
                if "readOnly" not in f
                for fs in f.get("eventSource", [])
                for op in _SOURCE_OPERATORS
                for v in _as_list(fs.get(op))
            }
        )
        return (
            "Management event sources are restricted: "
            f"{', '.join(described) if described else 'eventSource field present'}"
        )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per usable organization trail, or one Finding keyed
            ``organization/<account_id>`` when there is none or the trail list
            could not be read.
        """
        org_rid = f"organization/{self.account_id}"
        trails_response = self.get_organization_trails()

        if "Error" in trails_response:
            error = trails_response["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=org_rid,
                    actual_value=(
                        "No CloudTrail trail exists for this account, so no "
                        "organization trail logs management events"
                    ),
                    remediation=(
                        "Create an organization trail in the management account that "
                        "logs all management events"
                    ),
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=org_rid,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        usable = [
            t for t in trails_response.get("trailList") or []
            if isinstance(t, dict)
            and isinstance(t.get("TrailARN"), str) and t["TrailARN"]
            and isinstance(t.get("HomeRegion"), str) and t["HomeRegion"]
        ]

        if not usable:
            yield self.failed(
                region="global",
                resource_id=org_rid,
                actual_value="No organization trail found, so management events are not logged org-wide",
                remediation=(
                    "Create an organization trail in the management account that logs "
                    "all management events"
                ),
            )
            return

        for trail in usable:
            trail_arn = trail["TrailARN"]
            selectors_response = self.get_event_selectors(trail["HomeRegion"], trail_arn)

            # Inside the per-trail loop: one undetermined trail costs one row.
            if "Error" in selectors_response:
                error = selectors_response["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region="global",
                        resource_id=trail_arn,
                        actual_value=f"Trail {trail_arn} does not exist",
                    )
                else:
                    yield self.error(
                        region="global",
                        resource_id=trail_arn,
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            gap = self.management_event_gap(selectors_response)
            if gap is None:
                yield self.passed(
                    region="global",
                    resource_id=trail_arn,
                    actual_value=(
                        "Organization trail logs all read and write management events "
                        "from every event source"
                    ),
                )
            else:
                yield self.failed(region="global", resource_id=trail_arn, actual_value=gap)
