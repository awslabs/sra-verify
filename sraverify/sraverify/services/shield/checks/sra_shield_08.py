"""
Check if Shield Response Team (SRT) access is configured.
"""
from typing import Dict, List, Any
from sraverify.services.shield.base import ShieldCheck


class SRA_SHIELD_08(ShieldCheck):
    """Check if Shield Response Team (SRT) access is configured."""

    def __init__(self):
        """Initialize Shield Response Team access check."""
        super().__init__()
        self.check_id = "SRA-SHIELD-08"
        self.check_name = "Shield Response Team (SRT) access is configured"
        self.description = ("This check verifies that AWS Shield Response Team (SRT) "
                            "access is configured with an appropriate IAM role.")
        self.severity = "MEDIUM"
        self.check_logic = "Describe DRT access configuration. Check fails if no role ARN is configured."

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """
        # Shield is a global service, check only in us-east-1
        region = "us-east-1"
        drt_access = self.describe_drt_access(region)

        if "Error" in drt_access:
            error_code = drt_access["Error"].get("Code", "")
            if error_code == "ResourceNotFoundException":
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value="SRT access not configured",
                    remediation="Configure Shield Response Team access by associating an IAM role using AssociateDRTRole API"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=drt_access["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Shield API access"
                ))
        elif drt_access.get("RoleArn"):
            role_arn = drt_access["RoleArn"]
            bucket_count = len(drt_access.get("LogBucketList", []))
            self.findings.append(self.create_finding(
                status="PASS",
                region=region,
                resource_id="shield:srt-access",
                actual_value=f"SRT access configured with role: {role_arn}, {bucket_count} log bucket(s)",
                remediation=""
            ))
        else:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="SRT access not configured",
                remediation="Configure Shield Response Team access by associating an IAM role using AssociateDRTRole API"
            ))

        return self.findings
