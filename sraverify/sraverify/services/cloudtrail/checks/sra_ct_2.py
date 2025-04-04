"""
SRA-CT-2: Organization CloudTrail KMS Encryption.
"""
from typing import List, Dict, Any
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.core.logging import logger


class SRA_CT_2(CloudTrailCheck):
    """Check if organization trails are encrypted with KMS."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CT-2"
        self.check_name = "Organization trail is encrypted with KMS"
        self.account_type = "management"
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies that your organization trail is encrypted with a KMS key. "
            "Log files delivered by CloudTrail to your bucket should be encrypted by using SSE-KMS. "
            "This is selected by default in the console but can be altered by users. With SSE-KMS "
            "you create and manage the KMS key yourself with the ability to manage permissions on "
            "who can use the key. For a user to read log files they must have read permissions to "
            "the bucket and have permissions that allows decrypt permission on the key applied by "
            "the KMS key policy."
        )
        self.check_logic = (
            "Check if organization trails have KmsKeyId configured."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Get organization trails
        org_trails = self.get_organization_trails()
        
        if not org_trails:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    account_id=account_id,
                    resource_id=f"organization/{account_id}",
                    checked_value="KmsKeyId: not empty",
                    actual_value="No organization trails found",
                    remediation=(
                        "Create an organization trail with KMS encryption in the management account using the AWS CLI command: "
                        f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{account_id} "
                        f"--kms-key-id arn:aws:kms:{self.regions[0] if self.regions else 'us-east-1'}:{account_id}:key/YOUR_KMS_KEY_ID "
                        f"--is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                    )
                )
            )
            return findings
        
        # Check each organization trail for KMS encryption
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            kms_key_id = trail.get('KmsKeyId', '')
            home_region = trail.get('HomeRegion', 'Unknown')
            
            if kms_key_id:
                # Trail is encrypted with KMS
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region="global",
                        account_id=account_id,
                        resource_id=trail_arn,
                        checked_value="KmsKeyId: not empty",
                        actual_value=f"Organization trail '{trail_name}' is encrypted with KMS key: {kms_key_id}",
                        remediation=""
                    )
                )
            else:
                # Trail is not encrypted with KMS
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        account_id=account_id,
                        resource_id=trail_arn,
                        checked_value="KmsKeyId: not empty",
                        actual_value=f"Organization trail '{trail_name}' is not encrypted with KMS",
                        remediation=(
                            f"Update the organization trail '{trail_name}' to use KMS encryption using the AWS CLI command: "
                            f"aws cloudtrail update-trail --name {trail_name} "
                            f"--kms-key-id arn:aws:kms:{home_region}:{account_id}:key/YOUR_KMS_KEY_ID "
                            f"--region {home_region}"
                        )
                    )
                )
        
        return findings
