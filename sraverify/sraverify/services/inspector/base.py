"""
Base class for Inspector security checks.
"""
from typing import List, Optional, Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.inspector.client import InspectorClient
from sraverify.core.logging import logger


class InspectorCheck(SecurityCheck):
    """Base class for all Inspector security checks."""
    
    # Class-level caches shared across all instances
    _inspector_account_status = {}
    _inspector_batch_account_status = {}  # SRA-INSPECTOR-7
    _inspector_delegated_admin = {}
    _inspector_org_config = {}
    _organization_members = {}
    
    def __init__(self):
        """Initialize Inspector base check."""
        super().__init__(
            account_type="application",  # Default, can be overridden in subclasses
            service="Inspector",
            resource_type="AWS::Inspector::Assessment"
        )
    
    def _setup_clients(self):
        """Set up Inspector clients for each region."""
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = InspectorClient(region, session=self.session)
    
    def get_client(self, region: str) -> Optional[InspectorClient]:
        """
        Get Inspector client for a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            InspectorClient for the region or None if not available
        """
        return self._clients.get(region)
    
    def get_account_status(self, region: str) -> Dict[str, Any]:
        """
        Get Inspector account status with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing account status
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return {}
        
        # Check cache first
        cache_key = f"{account_id}:{region}"
        if cache_key in self.__class__._inspector_account_status:
            logger.debug(f"Using cached Inspector account status for {cache_key}")
            return self.__class__._inspector_account_status[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Inspector client available for region {region}")
            return {}
        
        # Get account status from client
        response = client.batch_get_account_status(account_ids=[account_id])
        
        # Extract the account status for the current account
        account_status = {}
        for status in response.get('accounts', []):
            if status.get('accountId') == account_id:
                # Restructure the account status to make it easier to access
                account_status = {
                    'accountId': status.get('accountId'),
                    'state': status.get('state', {}),
                    # Extract resource states to top level for easier access in checks
                    'ec2': status.get('resourceState', {}).get('ec2', {}),
                    'ecr': status.get('resourceState', {}).get('ecr', {}),
                    'lambda': status.get('resourceState', {}).get('lambda', {}),
                    'lambdaCode': status.get('resourceState', {}).get('lambdaCode', {})
                }
                break
        
        # Cache the result
        self.__class__._inspector_account_status[cache_key] = account_status
        logger.debug(f"Cached Inspector account status for {cache_key}")
        
        return account_status
    
    def get_delegated_admin(self, region: str) -> Dict[str, Any]:
        """
        Get Inspector delegated admin with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing delegated admin information
        """
        # Check cache first
        cache_key = f"{self.session.region_name}:{region}"
        if cache_key in self.__class__._inspector_delegated_admin:
            logger.debug(f"Using cached Inspector delegated admin for {cache_key}")
            return self.__class__._inspector_delegated_admin[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Inspector client available for region {region}")
            return {}
        
        # Get delegated admin from client
        response = client.get_delegated_admin_account()
        
        # Cache the result
        self.__class__._inspector_delegated_admin[cache_key] = response
        logger.debug(f"Cached Inspector delegated admin for {cache_key}")
        
        return response
    
    def get_organization_members(self, region: str) -> List[Dict[str, Any]]:
        """
        Get all AWS Organization member accounts with caching.
        
        Args:
            region: AWS region name (not used for Organizations API call)
            
        Returns:
            List of organization member accounts
        """
        # Use the current session region for Organizations API call
        current_region = self.session.region_name
        
        # Check cache first
        cache_key = f"{current_region}:organizations"
        if cache_key in self.__class__._organization_members:
            logger.debug(f"Using cached organization members for {cache_key}")
            return self.__class__._organization_members[cache_key]
        
        # Use the client for the current region
        client = self.get_client(current_region)
        if not client:
            logger.warning(f"No Inspector client available for region {current_region}")
            return []
        
        # Get organization members from client
        accounts = client.list_organization_accounts()
        
        # Cache the result
        self.__class__._organization_members[cache_key] = accounts
        logger.debug(f"Cached {len(accounts)} organization members for {cache_key} (using current region)")
        
        return accounts
        
    def batch_get_account_status(self, region: str, account_ids: List[str]) -> Dict[str, Dict]:
        """
        Get Inspector account status for multiple accounts with caching.
        
        Args:
            region: AWS region name
            account_ids: List of account IDs to check
            
        Returns:
            Dictionary mapping account IDs to their status
        """
        # Check cache first
        cache_key = f"{self.session.region_name}:{region}:batch_status"
        if cache_key in self.__class__._inspector_batch_account_status:
            logger.debug(f"Using cached Inspector batch account status for {cache_key}")
            return self.__class__._inspector_batch_account_status[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Inspector client available for region {region}")
            return {}
        
        # Process accounts in batches of 10 (API limit)
        result = {}
        for i in range(0, len(account_ids), 10):
            batch = account_ids[i:i+10]
            try:
                response = client.batch_get_account_status(batch)
                for account in response.get('accounts', []):
                    acc_id = account.get('accountId')
                    if acc_id:
                        result[acc_id] = account
            except Exception as e:
                logger.debug(f"Error getting batch account status in {region}: {e}")
        
        # Cache the result
        self.__class__._inspector_batch_account_status[cache_key] = result
        logger.debug(f"Cached Inspector batch account status for {len(result)} accounts in {region}")
        
        return result
        
    def get_organization_configuration(self, region: str) -> Dict[str, Any]:
        """
        Get Inspector organization configuration with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing organization configuration
        """
        # Check cache first
        cache_key = f"{self.session.region_name}:{region}"
        if cache_key in self.__class__._inspector_org_config:
            logger.debug(f"Using cached Inspector organization configuration for {cache_key}")
            return self.__class__._inspector_org_config[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Inspector client available for region {region}")
            return {}
        
        # Get organization configuration from client
        response = client.describe_organization_configuration()
        
        # Cache the result
        self.__class__._inspector_org_config[cache_key] = response
        logger.debug(f"Cached Inspector organization configuration for {cache_key}")
        
        return response
