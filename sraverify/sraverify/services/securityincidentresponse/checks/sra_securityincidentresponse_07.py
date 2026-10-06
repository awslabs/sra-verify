"""
SRA-SECURITYINCIDENTRESPONSE-07: Security Incident Response proactive response
EventBridge rules are enabled.
"""
import json
from collections.abc import Iterable
from typing import Any

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityincidentresponse.base import SecurityIncidentResponseCheck

#: The ``ManagedBy`` value on the rules Security Incident Response triage creates.
#: Rules are identified by this alone, never by name: a customer rule named
#: ``SIRGuardDutyRule`` must not count, and a renamed managed rule must.
SIR_MANAGED_BY = "triage.security-ir.amazonaws.com"

_REMEDIATION = (
    "Confirm this account is covered by the Security Incident Response membership with "
    "proactive response (triage) enabled. In the management account, create the triage "
    "service linked role manually: aws iam create-service-linked-role --aws-service-name "
    "triage.security-ir.amazonaws.com"
)


class SRA_SECURITYINCIDENTRESPONSE_07(SecurityIncidentResponseCheck):
    """Check if the SIR proactive response EventBridge rules exist and are enabled."""

    meta = CheckMeta(
        check_id="SRA-SECURITYINCIDENTRESPONSE-07",
        title="Security Incident Response proactive response EventBridge rules are enabled",
        description=(
            "This check verifies that the EventBridge rules Security Incident Response "
            "triage uses to receive GuardDuty and Security Hub findings exist on the "
            "default event bus and are enabled in every Region. Without them proactive "
            "response is silently blind in that account and Region. This is a step of the "
            "Security Incident Response configuration validation procedure."
        ),
        check_logic=(
            "For each Region list default event bus rules with events:ListRules and select "
            "rules ManagedBy triage.security-ir.amazonaws.com. Passes if a GuardDuty-sourced "
            "and a Security Hub-sourced managed rule exist and every one is ENABLED."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="SecurityIncidentResponse",
        resource_type="AWS::Events::Rule",
        remediation=Remediation(
            text=_REMEDIATION,
            cli="aws iam create-service-linked-role --aws-service-name triage.security-ir.amazonaws.com",
            console=(
                "AWS Security Incident Response console in the delegated administrator "
                "account, Membership, confirm the account is covered and proactive response "
                "is enabled."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Incident Response"),
        additional_urls=(
            "https://docs.aws.amazon.com/security-ir/latest/userguide/config-validation.md",
            "https://docs.aws.amazon.com/security-ir/latest/userguide/setup-monitoring-and-investigation-workflows.html",
        ),
    )

    @staticmethod
    def event_sources(rule: Any) -> frozenset[str]:
        """
        The ``source`` values of a rule's ``EventPattern``.

        Never raises. An absent or invalid JSON pattern, a pattern that is not an
        object, or a ``source`` that is neither a string nor a list of strings
        yields an empty set, so the rule counts as neither type.

        Args:
            rule: One element of a ``ListRules`` response.

        Returns:
            The source strings named by the pattern.
        """
        if not isinstance(rule, dict):
            return frozenset()
        try:
            pattern = json.loads(rule.get("EventPattern"))
        except (TypeError, ValueError):
            return frozenset()
        if not isinstance(pattern, dict):
            return frozenset()
        source = pattern.get("source")
        if isinstance(source, str):
            return frozenset((source,))
        if isinstance(source, list):
            return frozenset(s for s in source if isinstance(s, str))
        return frozenset()

    @staticmethod
    def rule_name(rule: Any) -> str:
        """A rule's name, or ``<unnamed>`` when it is missing or not a string."""
        name = rule.get("Name") if isinstance(rule, dict) else None
        return name if isinstance(name, str) and name else "<unnamed>"

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            Exactly one Finding per Region, keyed ``events:<region>:<account_id>``.
        """
        for region in self.regions:
            rid = f"events:{region}:{self.account_id}"
            rules = self.get_event_rules(region)

            if "Error" in rules:
                error = rules["Error"]
                if self.is_not_configured(error):
                    # Nothing is declared for ListRules today; the arm keeps the
                    # standard two-arm shape so a future declaration needs no edit.
                    yield self.failed(
                        region=region,
                        resource_id=rid,
                        actual_value="EventBridge reports no default event bus in this Region",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=rid,
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            managed = sorted(
                (
                    r for r in rules.get("Rules") or []
                    if isinstance(r, dict) and r.get("ManagedBy") == SIR_MANAGED_BY
                ),
                key=self.rule_name,
            )
            gd = [r for r in managed if "aws.guardduty" in self.event_sources(r)]
            sh = [r for r in managed if "aws.securityhub" in self.event_sources(r)]
            missing = [
                label for label, group in (("GuardDuty", gd), ("Security Hub", sh))
                if not group
            ]
            disabled = sorted(
                {
                    (self.rule_name(r), str(r.get("State")))
                    for r in gd + sh
                    if r.get("State") != "ENABLED"
                }
            )
            disabled_text = ", ".join(f"{name} ({state})" for name, state in disabled)

            if missing:
                actual = (
                    f"No SIR-managed EventBridge rule for {' and '.join(missing)} findings"
                )
                if disabled:
                    actual += f"; not ENABLED: {disabled_text}"
                yield self.failed(region=region, resource_id=rid, actual_value=actual)
            elif disabled:
                yield self.failed(
                    region=region,
                    resource_id=rid,
                    actual_value=f"SIR-managed rules not ENABLED: {disabled_text}",
                )
            else:
                matched = sorted(
                    {(self.rule_name(r), "GuardDuty") for r in gd}
                    | {(self.rule_name(r), "Security Hub") for r in sh}
                )
                yield self.passed(
                    region=region,
                    resource_id=rid,
                    actual_value=(
                        "SIR-managed rules ENABLED: "
                        + ", ".join(f"{name} ({kind})" for name, kind in matched)
                    ),
                )
