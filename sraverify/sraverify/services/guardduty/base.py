"""
Base class for GuardDuty security checks.
"""
from typing import List, Optional, Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.guardduty.client import GuardDutyClient
from sraverify.core.logging import logger


class GuardDutyCheck(SecurityCheck):
    """Base class for all GuardDuty security checks."""
    
    # Class-level caches shared across all instances
    _detector_details_cache = {}
    _detector_ids_cache = {}
    _org_config_cache = {}
    _admin_accounts_cache = {}
    
    def __init__(self):
        """Initialize GuardDuty base check."""
        super().__init__(
            account_type="application",
            service="GuardDuty",
            resource_type="AWS::GuardDuty::Detector"
        )
    
    def _setup_clients(self):
        """Set up GuardDuty clients for each region."""
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = GuardDutyClient(region, session=self.session)
    
    def get_detector_id(self, region: str) -> Optional[str]:
        """
        Get detector ID for a specific region with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Detector ID if available, None otherwise
        """
        # Check class-level cache
        cache_key = f"{self.session.region_name}:{region}"
        if cache_key in GuardDutyCheck._detector_ids_cache:
            logger.debug(f"GuardDuty: Using cached detector ID for {region}")
            return GuardDutyCheck._detector_ids_cache[cache_key]
        
        # Get client
        client = self.get_client(region)
        if not client:
            logger.warning(f"GuardDuty: No GuardDuty client available for region {region}")
            return None
        
        # Get detector ID
        logger.debug(f"GuardDuty: Fetching detector ID for {region}")
        detector_id = client.get_detector_id()
        
        # Check if detector_id contains an error
        if detector_id and isinstance(detector_id, str) and detector_id.startswith("ERROR:"):
            _, error_code, error_message = detector_id.split(":", 2)
            logger.warning(f"GuardDuty: Error accessing GuardDuty in {region}: {error_code}")
            GuardDutyCheck._detector_ids_cache[cache_key] = None
            return None
        
        # Cache the detector ID
        if detector_id:
            logger.debug(f"GuardDuty: Found detector ID {detector_id} for {region}")
            GuardDutyCheck._detector_ids_cache[cache_key] = detector_id
        else:
            logger.debug(f"GuardDuty: No detector ID found for {region}")
        
        return detector_id
    
    def get_detector_details(self, region: str) -> Dict[str, Any]:
        """
        Get detector details for a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing detector details or empty dict if not available
        """
        # Check if we already have cached details in the class-level cache
        cache_key = f"{self.session.region_name}:{region}"  # Include session region to avoid conflicts
        if cache_key in GuardDutyCheck._detector_details_cache:
            logger.debug(f"GuardDuty: Using cached detector details for {region}")
            return GuardDutyCheck._detector_details_cache[cache_key]
        
        # Get detector ID
        detector_id = self.get_detector_id(region)
        if not detector_id:
            logger.debug(f"GuardDuty: No detector ID found for region {region}")
            return {}
        
        # Get client
        client = self.get_client(region)
        if not client:
            logger.warning(f"GuardDuty: No GuardDuty client available for region {region}")
            return {}
        
        # Get detector details
        logger.debug(f"GuardDuty: Getting detector details for {detector_id} in {region}")
        details = client.get_detector_details(detector_id)
        
        # Cache the details in the class-level cache
        GuardDutyCheck._detector_details_cache[cache_key] = details
        logger.debug(f"GuardDuty: Cached detector details for {region}")
        
        return details
    
    def get_organization_configuration(self, region: str) -> Dict[str, Any]:
        """
        Get organization configuration for a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing organization configuration details or empty dict if not available
        """
        # Check if we already have cached org config in the class-level cache
        cache_key = f"{self.session.region_name}:{region}"
        if cache_key in GuardDutyCheck._org_config_cache:
            logger.debug(f"GuardDuty: Using cached organization configuration for {region}")
            return GuardDutyCheck._org_config_cache[cache_key]
        
        # Get detector ID
        detector_id = self.get_detector_id(region)
        if not detector_id:
            logger.debug(f"GuardDuty: No detector ID found for region {region}")
            return {}
        
        # Get client
        client = self.get_client(region)
        if not client:
            logger.warning(f"GuardDuty: No GuardDuty client available for region {region}")
            return {}
        
        # Get organization configuration
        logger.debug(f"GuardDuty: Getting organization configuration for {detector_id} in {region}")
        org_config = client.describe_organization_configuration(detector_id)
        
        # Cache the org config in the class-level cache
        GuardDutyCheck._org_config_cache[cache_key] = org_config
        logger.debug(f"GuardDuty: Cached organization configuration for {region}")
        
        return org_config
    
    def list_organization_admin_accounts(self, region: str) -> Dict[str, Any]:
        """
        List organization admin accounts for GuardDuty.
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing organization admin accounts details or empty dict if not available
        """
        # Check if we already have cached admin accounts in the class-level cache
        cache_key = f"{self.session.region_name}:{region}"
        if cache_key in GuardDutyCheck._admin_accounts_cache:
            logger.debug(f"GuardDuty: Using cached organization admin accounts for {region}")
            return GuardDutyCheck._admin_accounts_cache[cache_key]
        
        # Get client
        client = self.get_client(region)
        if not client:
            logger.warning(f"GuardDuty: No GuardDuty client available for region {region}")
            return {}
        
        # List organization admin accounts
        logger.debug(f"GuardDuty: Listing organization admin accounts in {region}")
        admin_accounts = client.list_organization_admin_accounts()
        
        # Cache the admin accounts in the class-level cache
        GuardDutyCheck._admin_accounts_cache[cache_key] = admin_accounts
        logger.debug(f"GuardDuty: Cached organization admin accounts for {region}")
        
        return admin_accounts
    
    def get_enabled_regions(self) -> List[str]:
        """
        Get list of regions where GuardDuty is enabled.
        
        Returns:
            List of region names where GuardDuty is enabled
        """
        # If no detector IDs have been discovered yet, try to discover them
        if not any(k.endswith(f":{region}") for k in GuardDutyCheck._detector_ids_cache.keys() 
                  for region in self.regions):
            logger.debug("GuardDuty: No detector IDs cached, discovering them now")
            for region in self.regions:
                self.get_detector_id(region)
        
        # Get regions from the class-level cache that match the current session
        prefix = f"{self.session.region_name}:"
        enabled_regions = [
            key.split(":")[-1] for key in GuardDutyCheck._detector_ids_cache.keys()
            if key.startswith(prefix) and GuardDutyCheck._detector_ids_cache[key] is not None
        ]
        
        return enabled_regions
