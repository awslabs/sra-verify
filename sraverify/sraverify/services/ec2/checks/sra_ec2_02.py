"""
SRA-EC2-02: VPC Flow Logs are enabled for every VPC.
"""
from collections.abc import Iterable
from typing import Any

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.ec2.base import EC2Check


class SRA_EC2_02(EC2Check):
    """Check if every VPC owned by the account has an active VPC-level flow log."""

    meta = CheckMeta(
        check_id="SRA-EC2-02",
        title="VPC Flow Logs are enabled for every VPC",
        description=(
            "This check verifies that every VPC the account owns, including the default "
            "VPC, has an active VPC-level flow log in every Region, so that network evidence "
            "exists for any workload an incident responder may need to investigate. Subnet "
            "and network interface flow logs do not satisfy the control. This is a step of "
            "the Security Incident Response configuration validation procedure."
        ),
        check_logic=(
            "For each Region list VPCs owned by the account and all flow logs. Passes per VPC "
            "with an ACTIVE flow log whose ResourceId is the VPC. A Region with no owned VPC "
            "passes once."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="EC2",
        resource_type="AWS::EC2::VPC",
        remediation=Remediation(
            text=(
                "Create a VPC-level flow log for every VPC, delivered to the Log Archive "
                "account."
            ),
            cli=(
                "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> "
                "--traffic-type ALL --log-destination-type s3 --log-destination <bucket-arn> "
                "--region <region>"
            ),
            console=(
                "VPC console, Your VPCs, select the VPC, Flow logs, Create flow log, Filter "
                "All, destination the Log Archive bucket. Repeat per VPC and Region."
            ),
        ),
        sra_sections=("Application account", "Amazon VPC Flow Logs"),
        additional_urls=(
            "https://docs.aws.amazon.com/security-ir/latest/userguide/config-validation.md",
            "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
        ),
    )

    @staticmethod
    def owned_vpcs(vpcs: Any, account_id: str) -> list[dict]:
        """
        Owned VPCs with a usable ``VpcId``, sorted by ``VpcId``.

        A copy of the same helper lives on SRA-ROUTE53RESOLVER-01: no check
        imports across service packages.

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
            region_rid = f"ec2:{region}:{self.account_id}"

            vpcs = self.get_vpcs(region)
            if "Error" in vpcs:
                # ec2's NOT_CONFIGURED_ERRORS is empty, and a failed VPC listing
                # has no VPC to name: one Region row.
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

            flow_logs = self.get_flow_logs(region)
            if "Error" in flow_logs:
                # One row per VPC, not one for the Region: a failed listing must
                # not drop VPCs from the report.
                error = flow_logs["Error"]
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

            active: dict[str, list[tuple[str, str]]] = {}
            for fl in flow_logs.get("FlowLogs") or []:
                if not isinstance(fl, dict):
                    continue
                rid = fl.get("ResourceId")
                # Subnet (subnet-) and ENI (eni-) flow logs never count.
                if (
                    fl.get("FlowLogStatus") == "ACTIVE"
                    and isinstance(rid, str)
                    and rid.startswith("vpc-")
                ):
                    active.setdefault(rid, []).append(
                        (str(fl.get("FlowLogId")), str(fl.get("TrafficType")))
                    )

            for vpc in owned:
                vpc_id = vpc["VpcId"]
                hits = sorted(active.get(vpc_id, []))
                if hits:
                    yield self.passed(
                        region=region,
                        resource_id=vpc_id,
                        actual_value="Active flow log " + ", ".join(
                            f"{fl_id} (traffic type {traffic})" for fl_id, traffic in hits
                        ),
                    )
                else:
                    suffix = " (default VPC)" if vpc.get("IsDefault") is True else ""
                    yield self.failed(
                        region=region,
                        resource_id=vpc_id,
                        actual_value=f"No active VPC-level flow log{suffix}",
                        remediation=(
                            f"Create a VPC flow log for {vpc_id}: aws ec2 create-flow-logs "
                            f"--resource-type VPC --resource-ids {vpc_id} --traffic-type ALL "
                            f"--log-destination-type s3 --log-destination <bucket-arn> "
                            f"--region {region}"
                        ),
                    )
