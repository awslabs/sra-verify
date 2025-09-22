"""
Base class for SecurityHub security checks.
"""
from typing import List, Optional, Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.securityhub.client import SecurityHubClient
from sraverify.core.logging import logger


class SecurityHubCheck(SecurityCheck):
    """Base class for all SecurityHub security checks."""
    
    # Class-level caches shared across all instances
    _enabled_standards_cache = {}
    _admin_account_cache = {}
    _organization_configuration_cache = {}
    _product_integrations_cache = {}
    _delegated_admin_cache = {}
    _organization_accounts_cache = {}
    _securityhub_members_cache = {}
    
    def __init__(self):
        """Initialize SecurityHub base check."""
        super().__init__(
            account_type="audit",  # Default to audit, can be overridden in child classes
            service="SecurityHub",
            resource_type="AWS::SecurityHub::Hub"
        )
    
    def _setup_clients(self):
        """Set up SecurityHub clients for each region."""
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = SecurityHubClient(region, session=self.session)
    
    def get_client(self, region: str) -> Optional[SecurityHubClient]:
        """
        Get SecurityHub client for a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            SecurityHubClient for the region or None if not available
        """
        return self._clients.get(region)
    
    def get_enabled_standards(self, region: str) -> List[Dict[str, Any]]:
        """
        Get enabled Security Hub standards for a region with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            List of enabled standards or None if Security Hub is not enabled
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return []
        
        # Check cache first
        cache_key = f"{account_id}:{region}"
        if cache_key in self.__class__._enabled_standards_cache:
            logger.debug(f"Using cached enabled standards for {cache_key}")
            return self.__class__._enabled_standards_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return []
        
        try:
            # Get enabled standards from client
            standards = client.get_enabled_standards()
            
            # If standards is None (Security Hub not enabled), don't try to cache it
            if standards is None:
                logger.debug(f"Security Hub is not enabled in region {region}")
                return None
            
            # Cache the results
            self.__class__._enabled_standards_cache[cache_key] = standards
            logger.debug(f"Cached {len(standards)} enabled standards for {cache_key}")
            
            return standards
        except Exception as e:
            # Check if this is the "not subscribed to AWS Security Hub" error
            if hasattr(e, 'response') and isinstance(e.response, dict):
                error = e.response.get('Error', {})
                if error.get('Code') == 'InvalidAccessException' and 'not subscribed to AWS Security Hub' in error.get('Message', ''):
                    # Return None specifically for this error to indicate Security Hub is not enabled
                    # Don't log this as an error since it's an expected condition we want to check for
                    logger.debug(f"Security Hub is not enabled in region {region}")
                    return None
            
            # For other errors, log a warning instead of an error to avoid cluttering the build logs
            logger.warning(f"Error getting enabled standards in {region}: {e}")
            return []
    
    def get_administrator_account(self, region: str) -> Dict[str, Any]:
        """
        Get Security Hub administrator account with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Administrator account information
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return {}
        
        # Check cache first
        cache_key = f"{account_id}:{region}"
        if cache_key in self.__class__._admin_account_cache:
            logger.debug(f"Using cached administrator account for {cache_key}")
            return self.__class__._admin_account_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return {}
        
        # Get administrator account from client
        admin_account = client.get_administrator_account()
        
        # Cache the results
        self.__class__._admin_account_cache[cache_key] = admin_account
        logger.debug(f"Cached administrator account for {cache_key}")
        
        return admin_account
    
    def get_organization_configuration(self, region: str) -> Dict[str, Any]:
        """
        Get Security Hub organization configuration with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Organization configuration
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return {}
        
        # Check cache first
        cache_key = f"{account_id}:{region}"
        if cache_key in self.__class__._organization_configuration_cache:
            logger.debug(f"Using cached organization configuration for {cache_key}")
            return self.__class__._organization_configuration_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return {}
        
        # Get organization configuration from client
        org_config = client.describe_organization_configuration()
        
        # Cache the results
        self.__class__._organization_configuration_cache[cache_key] = org_config
        logger.debug(f"Cached organization configuration for {cache_key}")
        
        return org_config
    
    def get_enabled_products_for_import(self, region: str) -> Optional[List[str]]:
        """
        Get enabled products for import with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            List of enabled product ARNs, or None if Security Hub is not enabled
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return []
        
        # Check cache first
        cache_key = f"{account_id}:{region}"
        if cache_key in self.__class__._product_integrations_cache:
            logger.debug(f"Using cached product integrations for {cache_key}")
            return self.__class__._product_integrations_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return []
        
        # Get enabled products from client
        products = client.list_enabled_products_for_import()
        
        # Only cache if we got a valid response (not None)
        if products is not None:
            self.__class__._product_integrations_cache[cache_key] = products
            logger.debug(f"Cached {len(products)} product integrations for {cache_key}")
        
        return products
    
    def get_delegated_administrators(self, region: str) -> List[Dict[str, Any]]:
        """
        Get SecurityHub delegated administrators with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            List of delegated administrators
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return []
        
        # Check cache first
        cache_key = f"{account_id}:{region}"
        if cache_key in self.__class__._delegated_admin_cache:
            logger.debug(f"Using cached delegated administrators for {cache_key}")
            return self.__class__._delegated_admin_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return []
        
        # Get delegated administrators from client
        delegated_admins = client.list_delegated_administrators()
        
        # Cache the results
        self.__class__._delegated_admin_cache[cache_key] = delegated_admins
        logger.debug(f"Cached {len(delegated_admins)} delegated administrators for {cache_key}")
        
        return delegated_admins
    
    def get_organization_admin_accounts(self, region: str) -> List[Dict[str, Any]]:
        """
        Get Security Hub organization admin accounts with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            List of organization admin accounts
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return []
        
        # Check cache first
        cache_key = f"{account_id}:{region}"
        if cache_key in self.__class__._admin_account_cache:
            logger.debug(f"Using cached organization admin accounts for {cache_key}")
            return self.__class__._admin_account_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return []
        
        # Get organization admin accounts from client
        admin_accounts = client.list_organization_admin_accounts()
        
        # Cache the results
        self.__class__._admin_account_cache[cache_key] = admin_accounts
        logger.debug(f"Cached {len(admin_accounts)} organization admin accounts for {cache_key}")
        
        return admin_accounts
    
    def get_organization_accounts(self, region: str) -> List[Dict[str, Any]]:
        """
        Get all organization accounts with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            List of organization accounts
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return []
        
        # Check cache first
        cache_key = f"{account_id}:{region}"
        if cache_key in self.__class__._organization_accounts_cache:
            logger.debug(f"Using cached organization accounts for {cache_key}")
            return self.__class__._organization_accounts_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return []
        
        # Get organization accounts from client
        accounts = client.list_organization_accounts()
        
        # Cache the results
        self.__class__._organization_accounts_cache[cache_key] = accounts
        logger.debug(f"Cached {len(accounts)} organization accounts for {cache_key}")
        
        return accounts
    
    def get_security_hub_members(self, region: str) -> List[Dict[str, Any]]:
        """
        Get Security Hub member accounts with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            List of Security Hub member accounts
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return []
        
        # Check cache first
        cache_key = f"{account_id}:{region}"
        if cache_key in self.__class__._securityhub_members_cache:
            logger.debug(f"Using cached Security Hub members for {cache_key}")
            return self.__class__._securityhub_members_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return []
        
        # Get Security Hub members from client
        members = client.list_members()
        
        # Cache the results
        self.__class__._securityhub_members_cache[cache_key] = members
        logger.debug(f"Cached {len(members)} Security Hub members for {cache_key}")
        
        return members
