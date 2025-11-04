"""Check if Amazon Security Lake is enabled."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger



class SRA_SECURITYLAKE_01(SecurityLakeCheck):
    """Check if Amazon Security Lake is enabled."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.check_id = "SRA-SECURITYLAKE-01"
        self.check_name = "Security Lake is enabled"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake is enabled in this region. "
            "Amazon Security Lake is a fully managed security data lake service that you "
            "can use to automatically centralize security data from AWS environments, "
            "SaaS providers, on premises, cloud sources, and third-party sources into a "
            "purpose-built data lake that's stored in your AWS account. The data lake is "
            "backed by Amazon S3 buckets, and you retain ownership over your data. You "
            "must enable security lake in every AWS account and AWS region to collect "
            "security logs and event from your entire AWS environment."
        )
        self.check_logic = (
            "Checks if Security Lake is enabled in each region by calling list_data_lakes API. "
            "The check passes if data lakes are found in the region, indicating Security Lake is enabled. "
            "The check fails if no data lakes are found, indicating Security Lake is not enabled."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            # Construct a proper ARN-like resource ID
            resource_id = f"arn:aws:securitylake:{region}:{self.account_id}:datalake/default"

            # Get data lakes for the region
            client = self.get_client(region)
            data_lakes = client.list_data_lakes() if client else []

            # Handle both list and dictionary responses
            if isinstance(data_lakes, dict):
                data_lakes = data_lakes.get('dataLakes', [])

            # Check if any data lakes are configured in the region
            if data_lakes:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Lake Enabled",
                        actual_value=f"Security Lake is enabled in {region}",
                        remediation="No remediation needed"
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Lake Enabled",
                        actual_value=f"Security Lake is not enabled in {region}",
                        remediation=(
                        "Enable Security Lake in this region. In the Security Lake console, "
                        "navigate to Settings and enable Security Lake. Alternatively, use the AWS CLI command: "
                        f"aws securitylake enable-security-lake --region {region}"
                        )
                    )
                )

        return self.findings
