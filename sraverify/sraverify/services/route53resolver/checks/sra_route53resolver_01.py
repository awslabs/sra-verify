"""
SRA-ROUTE53RESOLVER-01: Route 53 Resolver query logging is enabled for every VPC.
"""
from collections.abc import Iterable
from typing import Any

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.route53resolver.base import Route53ResolverCheck

#: The ``ResolverQueryLogConfigAssociationStatus`` value of a working association
#: (the others are CREATING, DELETING, FAILED and ACTION_NEEDED). A named
#: constant, not an inline literal: this is an association status, not an
#: Organizations account status, and test_accounts.py's guard against comparing
#: an account's Status to "ACTIVE" by hand matches the inline spelling.
ASSOCIATION_ACTIVE = "ACTIVE"


class SRA_ROUTE53RESOLVER_01(Route53ResolverCheck):
    """Check if every VPC owned by the account has active Resolver query logging."""

    meta = CheckMeta(
        check_id="SRA-ROUTE53RESOLVER-01",
        title="Route 53 Resolver query logging is enabled for every VPC",
        description=(
            "This check verifies that every VPC the account owns, including the default "
            "VPC, has an active Route 53 Resolver query logging association in every Region, "
            "so that DNS evidence exists when an incident responder traces an incident. A "
            "query logging configuration shared from another account through AWS RAM counts. "
            "This is a step of the Security Incident Response configuration validation "
            "procedure."
        ),
        check_logic=(
            "For each Region list VPCs owned by the account and Resolver query log config "
            "associations. Passes per VPC with an ACTIVE association. A Region with no owned "
            "VPC passes once."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="Route 53 Resolver",
        resource_type="AWS::EC2::VPC",
        remediation=Remediation(
            text=(
                "Create a Resolver query logging configuration, ideally shared from the Log "
                "Archive account, and associate it with every VPC."
            ),
            cli=(
                "aws route53resolver create-resolver-query-log-config --name <name> "
                "--destination-arn <arn> --region <region>\n"
                "aws route53resolver associate-resolver-query-log-config "
                "--resolver-query-log-config-id <id> --resource-id <vpc-id> --region <region>"
            ),
            console=(
                "Route 53 console, Resolver, Query logging, Configure query logging, choose "
                "the destination, Add VPC. Repeat per Region."
            ),
        ),
        sra_sections=("Application account", "Amazon Route 53 Resolver DNS query logging"),
        additional_urls=(
            "https://docs.aws.amazon.com/security-ir/latest/userguide/config-validation.md",
            "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html",
        ),
    )

    @staticmethod
    def owned_vpcs(vpcs: Any, account_id: str) -> list[dict]:
        """
        Owned VPCs with a usable ``VpcId``, sorted by ``VpcId``.

        A copy of the same helper on SRA-EC2-02: no check imports across
        service packages.

        Args:
            vpcs: A successful ``DescribeVpcs`` result.
            account_id: The scanned account ID.

        Returns:
            The VPCs whose ``OwnerId`` is ``account_id``. VPCs shared in through
            AWS RAM are excluded; they are evaluated in the owning account.
        """
        return sorted(
            (
                v for v in vpcs.get("Vpcs") or []
                if isinstance(v, dict) and v.get("OwnerId") == account_id
                and isinstance(v.get("VpcId"), str) and v["VpcId"]
            ),
            key=lambda v: v["VpcId"],
        )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per owned VPC per Region, or one Region-level Finding when
            the Region has no owned VPC or its VPCs could not be listed.
        """
        for region in self.regions:
            region_rid = f"route53resolver:{region}:{self.account_id}"

            vpcs = self.get_vpcs(region)
            if "Error" in vpcs:
                # route53resolver's NOT_CONFIGURED_ERRORS is empty, and a failed
                # VPC listing has no VPC to name: one Region row.
                error = vpcs["Error"]
                yield self.error(
                    region=region,
                    resource_id=region_rid,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
                continue

            owned = self.owned_vpcs(vpcs, self.account_id)
            if not owned:
                yield self.passed(
                    region=region,
                    resource_id=region_rid,
                    actual_value="No VPC owned by this account in this Region",
                )
                continue

            assocs = self.get_query_log_config_associations(region)
            if "Error" in assocs:
                # One row per VPC, not one for the Region: a failed listing must
                # not drop VPCs from the report.
                error = assocs["Error"]
                for vpc in owned:
                    yield self.error(
                        region=region,
                        resource_id=vpc["VpcId"],
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            # Ownership of the query logging configuration is not consulted: a
            # configuration shared through RAM is a legitimate SRA pattern.
            active: dict[str, list[str]] = {}
            for a in assocs.get("ResolverQueryLogConfigAssociations") or []:
                if not isinstance(a, dict):
                    continue
                rid = a.get("ResourceId")
                if a.get("Status") == ASSOCIATION_ACTIVE and isinstance(rid, str) and rid:
                    active.setdefault(rid, []).append(str(a.get("ResolverQueryLogConfigId")))

            for vpc in owned:
                vpc_id = vpc["VpcId"]
                config_ids = sorted(set(active.get(vpc_id, [])))
                if config_ids:
                    yield self.passed(
                        region=region,
                        resource_id=vpc_id,
                        actual_value=(
                            "Active Resolver query logging association with "
                            + ", ".join(config_ids)
                        ),
                    )
                else:
                    suffix = " (default VPC)" if vpc.get("IsDefault") is True else ""
                    yield self.failed(
                        region=region,
                        resource_id=vpc_id,
                        actual_value=f"No active Resolver query logging association{suffix}",
                        remediation=(
                            f"Associate a Resolver query logging configuration with {vpc_id}: "
                            f"aws route53resolver associate-resolver-query-log-config "
                            f"--resolver-query-log-config-id <id> --resource-id {vpc_id} "
                            f"--region {region} (create one first with aws route53resolver "
                            f"create-resolver-query-log-config --name <name> "
                            f"--destination-arn <arn>)"
                        ),
                    )
