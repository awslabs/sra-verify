"""
Base class for security checks.
"""
from typing import List, Optional, Dict, Any
import boto3
from sraverify.core.logging import logger


class SecurityCheck:
    """Base class for all security checks."""
    
    def __init__(self, account_type="application", service=None, resource_type=None):
        """
        Initialize security check.
        
        Args:
            account_type: Type of account (application, audit, log-archive, management)
            service: AWS service name
            resource_type: AWS resource type for findings
        """
        self.account_type = account_type
        self.service = service
        self.resource_type = resource_type
        self.check_id = None
        self.check_name = None
        self.description = None
        self.rationale = None
        self.remediation = None
        self.severity = "Unknown"
        self.check_logic = None
        self.findings = []
        self.regions = []
        self.session = None
        self._clients = {}
        
    def initialize(self, session: boto3.Session, regions: Optional[List[str]] = None):
        """
        Initialize check with AWS session and optional regions.
        
        Args:
            session: AWS session to use for the check
            regions: List of AWS regions to check. If not provided, enabled regions will be detected.
        """
        logger.debug(f"Initializing {self.__class__.__name__} check")
        self.session = session
        # All account types need regions, so we'll get them regardless of account type
        self.regions = regions if regions else self._get_enabled_regions()
        logger.debug(f"Check will run in regions: {', '.join(self.regions)}")
        self._setup_clients()

    def _get_enabled_regions(self) -> List[str]:
        """
        Get all enabled regions in the AWS account.
        
        Returns:
            List of enabled region names
        """
        try:
            logger.debug("Getting enabled AWS regions")
            session = boto3.Session()
            ec2_client = session.client('ec2', region_name='us-east-1')
            response = ec2_client.describe_regions(AllRegions=False)
            regions = [region['RegionName'] for region in response['Regions']]
            logger.debug(f"Found {len(regions)} enabled regions")
            return regions
        except Exception as e:
            logger.error(f"Failed to get enabled regions: {str(e)}")
            raise Exception(f"Failed to get enabled regions: {str(e)}")
    
    def _setup_clients(self):
        """
        Set up clients for each region. Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement _setup_clients method")
    
    def get_client(self, region: str) -> Optional[Any]:
        """
        Get client for a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            Client for the region or None if not available
        """
        return self._clients.get(region)
    
    def create_finding(self, status: str, region: str, account_id: str,
                      resource_id: str, actual_value: str,
                      remediation: str, checked_value: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a standardized finding.
        
        Args:
            status: Check status (PASS/FAIL/ERROR)
            region: AWS region
            account_id: AWS account ID
            resource_id: Resource identifier
            actual_value: Actual value found
            remediation: Remediation steps
            checked_value: Value that was checked (defaults to service name + " Configuration")
            
        Returns:
            Finding dictionary
        """
        if checked_value is None:
            checked_value = f"{self.service} Configuration"
            
        return {
            "CheckId": self.check_id,
            "Status": status,
            "Region": region,
            "Severity": self.severity,
            "Title": f"{self.check_id} {self.check_name}",
            "Description": self.description,
            "ResourceId": resource_id,
            "ResourceType": self.resource_type,
            "AccountId": account_id,
            "CheckedValue": checked_value,
            "ActualValue": actual_value,
            "Remediation": remediation,
            "Service": self.service,
            "CheckLogic": self.check_logic,
            "AccountType": self.account_type
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check. Must be implemented by subclasses.
        
        Returns:
            List of findings
        """
        raise NotImplementedError("Subclasses must implement execute method")
    
    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Get findings from the check.
        
        Returns:
            List of findings
        """
        return self.findings

    def get_session_accountId(self, session: boto3.Session) -> str:
        """
        Get AWS account ID from the session.

        Args:
            session: AWS session

        Returns:
            AWS account ID
        """
        try:
            logger.debug("Getting AWS account ID from session")
            sts_client = session.client("sts")
            response = sts_client.get_caller_identity()
            account_id = response["Account"]
            logger.debug(f"Account ID: {account_id}")
            return account_id
        except Exception as e:
            logger.error(f"Failed to get AWS account ID: {str(e)}")
            raise Exception(f"Failed to get AWS account ID: {str(e)}")
        
    def get_management_accountId(self, session: boto3.Session) -> str:
        """
        Get AWS management account ID from the session.

        Args:
            session: AWS session

        Returns:
            AWS management account ID
        """
        try:
            logger.debug("Getting AWS management account ID")
            org_client = session.client("organizations")
            response = org_client.describe_organization()
            management_account_id = response["Organization"]["MasterAccountId"]
            logger.debug(f"Management account ID: {management_account_id}")
            return management_account_id
        except Exception as e:
            logger.error(f"Failed to get AWS management account ID: {str(e)}")
            raise Exception(f"Failed to get AWS management account ID: {str(e)}")
