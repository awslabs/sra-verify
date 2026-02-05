"""
Base class for AWS Organizations security checks.
"""
from typing import List, Optional, Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.organizations.client import OrganizationsClient
from sraverify.core.logging import logger


class OrganizationsCheck(SecurityCheck):
    """Base class for all AWS Organizations security checks."""
    
    # Class-level caches shared across all instances
    _organization_cache = {}
    _roots_cache = {}
    _ous_cache = {}
    _policies_cache = {}
    _accounts_cache = {}
    
    def __init__(self, resource_type: str = "AWS::Organizations::Organization"):
        """
        Initialize Organizations base check.
        
        Args:
            resource_type: AWS resource type for findings (default: Organization)
        """
        super().__init__(
            account_type="management",
            service="Organizations",
            resource_type=resource_type
        )
        self._org_client = None
    
    def _setup_clients(self):
        """Set up Organizations client (global service, no per-region clients needed)."""
        # Organizations is a global service, we only need one client
        self._org_client = OrganizationsClient(session=self.session)
        # Clear existing regional clients dict since Organizations doesn't use them
        self._clients.clear()

    def get_org_client(self) -> OrganizationsClient:
        """
        Get the Organizations client.
        
        Returns:
            OrganizationsClient instance
        """
        return self._org_client
    
    def get_organization(self) -> Dict[str, Any]:
        """
        Get organization details with caching.
        
        Returns:
            Dictionary containing organization details or Error key if failed.
        """
        # Check class-level cache
        cache_key = f"{self.account_id}:organization"
        if cache_key in OrganizationsCheck._organization_cache:
            logger.debug("Organizations: Using cached organization details")
            return OrganizationsCheck._organization_cache[cache_key]
        
        # Get organization details
        logger.debug("Organizations: Fetching organization details")
        response = self._org_client.describe_organization()
        
        # Cache the response
        OrganizationsCheck._organization_cache[cache_key] = response
        logger.debug("Organizations: Cached organization details")
        
        return response
    
    def get_roots(self) -> Dict[str, Any]:
        """
        Get organization roots with caching.
        
        Returns:
            Dictionary with Roots key containing list of roots,
            or Error key if failed.
        """
        # Check class-level cache
        cache_key = f"{self.account_id}:roots"
        if cache_key in OrganizationsCheck._roots_cache:
            logger.debug("Organizations: Using cached roots")
            return OrganizationsCheck._roots_cache[cache_key]
        
        # Get roots
        logger.debug("Organizations: Fetching organization roots")
        response = self._org_client.list_roots()
        
        # Cache the response
        OrganizationsCheck._roots_cache[cache_key] = response
        logger.debug("Organizations: Cached roots")
        
        return response
    
    def get_ous_for_parent(self, parent_id: str) -> Dict[str, Any]:
        """
        Get organizational units for a parent with caching.
        
        Args:
            parent_id: The ID of the parent root or OU
            
        Returns:
            Dictionary with OrganizationalUnits key containing list of OUs,
            or Error key if failed.
        """
        # Check class-level cache
        cache_key = f"{self.account_id}:{parent_id}:ous"
        if cache_key in OrganizationsCheck._ous_cache:
            logger.debug(f"Organizations: Using cached OUs for parent {parent_id}")
            return OrganizationsCheck._ous_cache[cache_key]
        
        # Get OUs
        logger.debug(f"Organizations: Fetching OUs for parent {parent_id}")
        response = self._org_client.list_organizational_units_for_parent(parent_id)
        
        # Cache the response
        OrganizationsCheck._ous_cache[cache_key] = response
        logger.debug(f"Organizations: Cached OUs for parent {parent_id}")
        
        return response
    
    def list_policies(self, policy_type: str = "SERVICE_CONTROL_POLICY") -> Dict[str, Any]:
        """
        List policies by type with caching.
        
        Args:
            policy_type: Type of policy to list (default: SERVICE_CONTROL_POLICY)
            
        Returns:
            Dictionary with Policies key containing list of policies,
            or Error key if failed.
        """
        # Check class-level cache
        cache_key = f"{self.account_id}:{policy_type}:policies"
        if cache_key in OrganizationsCheck._policies_cache:
            logger.debug(f"Organizations: Using cached policies of type {policy_type}")
            return OrganizationsCheck._policies_cache[cache_key]
        
        # Get policies
        logger.debug(f"Organizations: Fetching policies of type {policy_type}")
        response = self._org_client.list_policies(policy_type)
        
        # Cache the response
        OrganizationsCheck._policies_cache[cache_key] = response
        logger.debug(f"Organizations: Cached policies of type {policy_type}")
        
        return response

    def get_accounts_for_parent(self, parent_id: str) -> Dict[str, Any]:
        """
        Get accounts for a parent (root or OU) with caching.
        
        Args:
            parent_id: The ID of the parent root or OU
            
        Returns:
            Dictionary with Accounts key containing list of accounts,
            or Error key if failed.
        """
        # Check class-level cache
        cache_key = f"{self.account_id}:{parent_id}:accounts"
        if cache_key in OrganizationsCheck._accounts_cache:
            logger.debug(f"Organizations: Using cached accounts for parent {parent_id}")
            return OrganizationsCheck._accounts_cache[cache_key]
        
        # Get accounts
        logger.debug(f"Organizations: Fetching accounts for parent {parent_id}")
        response = self._org_client.list_accounts_for_parent(parent_id)
        
        # Cache the response
        OrganizationsCheck._accounts_cache[cache_key] = response
        logger.debug(f"Organizations: Cached accounts for parent {parent_id}")
        
        return response
