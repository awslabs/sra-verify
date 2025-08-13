"""
Base class for Macie security checks.
"""
from typing import List, Optional, Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.macie.client import MacieClient
from sraverify.core.logging import logger


class MacieCheck(SecurityCheck):
    """Base class for all Macie security checks."""
    
    # Class-level caches shared across all instances
    _findings_publication_cache = {}
    _export_configuration_cache = {}
    _macie_delegated_admin_cache = {}
    _macie_members_cache = {}
    _org_members_cache = {}
    _auto_enable_cache = {}
    
    def __init__(self):
        """Initialize Macie base check."""
        super().__init__(
            account_type="application",  # Default, can be overridden in subclasses
            service="Macie",
            resource_type="AWS::Macie::Session"
        )
    
    def _setup_clients(self):
        """Set up Macie clients for each region."""
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = MacieClient(region, session=self.session)
    
    def get_client(self, region: str) -> Optional[MacieClient]:
        """
        Get Macie client for a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            MacieClient for the region or None if not available
        """
        return self._clients.get(region)
    
    def get_findings_publication_configuration(self, region: str) -> Dict[str, Any]:
        """
        Get the findings publication configuration for Macie with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing findings publication configuration
        """
        # Check cache first
        account_id = self.account_id
        cache_key = f"{account_id}:{region}"
        
        if cache_key in self.__class__._findings_publication_cache:
            logger.debug(f"Using cached Macie findings publication configuration for {region}")
            return self.__class__._findings_publication_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Macie client available for region {region}")
            return {}
        
        # Get findings publication configuration from client
        config = client.get_findings_publication_configuration()
        
        # Cache the result
        self.__class__._findings_publication_cache[cache_key] = config
        logger.debug(f"Cached Macie findings publication configuration for {region}")
        
        return config
    
    def get_classification_export_configuration(self, region: str) -> Dict[str, Any]:
        """
        Get the classification export configuration for Macie with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing classification export configuration
        """
        # Check cache first
        account_id = self.account_id
        cache_key = f"{account_id}:{region}"
        
        if cache_key in self.__class__._export_configuration_cache:
            logger.debug(f"Using cached Macie classification export configuration for {region}")
            return self.__class__._export_configuration_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Macie client available for region {region}")
            return {}
        
        # Get classification export configuration from client
        config = client.get_classification_export_configuration()
        
        # Cache the result
        self.__class__._export_configuration_cache[cache_key] = config
        logger.debug(f"Cached Macie classification export configuration for {region}")
        
        return config
    
    def get_macie_delegated_admin(self, region: str) -> List[Dict[str, Any]]:
        """
        Get the Macie delegated administrator with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            List of delegated administrators
        """
        # Check cache first
        account_id = self.account_id
        cache_key = f"{account_id}:{region}"
        
        if cache_key in self.__class__._macie_delegated_admin_cache:
            logger.debug(f"Using cached Macie delegated administrator for {region}")
            return self.__class__._macie_delegated_admin_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Macie client available for region {region}")
            return []
        
        # Get delegated administrator from client
        delegated_admin = client.list_delegated_administrators()
        
        # Cache the result
        self.__class__._macie_delegated_admin_cache[cache_key] = delegated_admin
        logger.debug(f"Cached Macie delegated administrator for {region}")
        
        return delegated_admin
    
    def get_macie_members(self, region: str) -> List[Dict[str, Any]]:
        """
        Get Macie members with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            List of Macie members
        """
        # Check cache first
        account_id = self.account_id
        cache_key = f"{account_id}:{region}"
        
        if cache_key in self.__class__._macie_members_cache:
            logger.debug(f"Using cached Macie members for {region}")
            return self.__class__._macie_members_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Macie client available for region {region}")
            return []
        
        # Get members from client
        members = client.list_members()
        
        # Cache the result
        self.__class__._macie_members_cache[cache_key] = members
        logger.debug(f"Cached {len(members)} Macie members for {region}")
        
        return members
    
    def get_organization_members(self, region: str) -> List[Dict[str, Any]]:
        """
        Get AWS Organization members with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            List of AWS Organization members
        """
        # Check cache first
        account_id = self.account_id
        cache_key = f"{account_id}:{region}"
        
        if cache_key in self.__class__._org_members_cache:
            logger.debug(f"Using cached AWS Organization members for {region}")
            return self.__class__._org_members_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Macie client available for region {region}")
            return []
        
        # Get organization members from client
        members = client.list_organization_accounts()
        
        # Cache the result
        self.__class__._org_members_cache[cache_key] = members
        logger.debug(f"Cached {len(members)} AWS Organization members for {region}")
        
        return members
    
    def get_organization_configuration(self, region: str) -> Dict[str, Any]:
        """
        Get Macie organization configuration with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing Macie organization configuration
        """
        # Check cache first
        account_id = self.account_id
        cache_key = f"{account_id}:{region}"
        
        if cache_key in self.__class__._auto_enable_cache:
            logger.debug(f"Using cached Macie organization configuration for {region}")
            return self.__class__._auto_enable_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Macie client available for region {region}")
            return {}
        
        # Get organization configuration from client
        config = client.describe_organization_configuration()
        
        # Cache the result
        self.__class__._auto_enable_cache[cache_key] = config
        logger.debug(f"Cached Macie organization configuration for {region}")
        
        return config
    def get_macie_administrator_account(self, region: str) -> Dict[str, Any]:
        """
        Get the Macie administrator account with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing Macie administrator account information
        """
        # Check cache first
        account_id = self.account_id
        cache_key = f"{account_id}:{region}"
        
        if cache_key in self.__class__._macie_delegated_admin_cache:
            logger.debug(f"Using cached Macie administrator account for {region}")
            return self.__class__._macie_delegated_admin_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Macie client available for region {region}")
            return {}
        
        # Get administrator account from client
        admin_account = client.get_administrator_account()
        
        # Cache the result
        self.__class__._macie_delegated_admin_cache[cache_key] = admin_account
        logger.debug(f"Cached Macie administrator account for {region}")
        
        return admin_account
