"""
Base class for CloudTrail security checks.
"""
from typing import List, Optional, Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.cloudtrail.client import CloudTrailClient
from sraverify.core.logging import logger


class CloudTrailCheck(SecurityCheck):
    """Base class for all CloudTrail security checks."""
    
    # Class-level caches shared across all instances - only keeping the ones specified
    _describe_trails_cache = {}
    _trail_status_cache = {}
    _delegated_admin_account_id_cache = {}
    
    def __init__(self):
        """Initialize CloudTrail base check."""
        super().__init__(
            account_type="management",
            service="CloudTrail",
            resource_type="AWS::CloudTrail::Trail"
        )
    
    def _setup_clients(self):
        """Set up CloudTrail clients for each region."""
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = CloudTrailClient(region, session=self.session)
    
    def get_client(self, region: str) -> Optional[CloudTrailClient]:
        """
        Get CloudTrail client for a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            CloudTrailClient for the region or None if not available
        """
        return self._clients.get(region)
    
    def describe_trails(self, include_shadow_trails: bool = True) -> List[Dict[str, Any]]:
        """
        Get all CloudTrail trails across all regions using the client with caching.
        
        Args:
            include_shadow_trails: Include shadow trails in the response
            
        Returns:
            List of all trails
        """
        if not self.regions:
            logger.warning("No regions specified")
            return []
        
        # Use session region name as part of cache key
        cache_key = f"describe_trails:{self.session.region_name}:{include_shadow_trails}"
        if cache_key in self.__class__._describe_trails_cache:
            logger.debug(f"Using cached trails for {cache_key}")
            return self.__class__._describe_trails_cache[cache_key]
        
        # Use any region to get all trails
        client = self.get_client(self.regions[0])
        if not client:
            logger.warning("No CloudTrail client available")
            return []
        
        # Get all trails using the client
        trails = client.describe_trails(include_shadow_trails=include_shadow_trails)
        
        # Cache the results
        self.__class__._describe_trails_cache[cache_key] = trails
        logger.debug(f"Cached {len(trails)} trails for {cache_key}")
        
        return trails
    
    def get_organization_trails(self) -> List[Dict[str, Any]]:
        """
        Get all organization CloudTrail trails.
        
        Returns:
            List of organization trails
        """
        # Get all trails first
        all_trails = self.describe_trails()
        
        # Filter for organization trails
        org_trails = [
            trail for trail in all_trails 
            if trail.get('IsOrganizationTrail', False)
        ]
        
        logger.debug(f"Found {len(org_trails)} organization trails")
        return org_trails
    
    def get_trail_status(self, region: str, trail_arn: str) -> Dict[str, Any]:
        """
        Get status of a specific CloudTrail trail using the client with caching.
        
        Args:
            region: AWS region name
            trail_arn: ARN of the trail
            
        Returns:
            Dictionary containing trail status
        """
        # Check cache first
        cache_key = f"{trail_arn}:{region}"
        if cache_key in self.__class__._trail_status_cache:
            logger.debug(f"Using cached trail status for {trail_arn} in {region}")
            return self.__class__._trail_status_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No CloudTrail client available for region {region}")
            return {}
        
        # Get trail status from client
        status = client.get_trail_status(trail_arn)
        
        # Cache the result
        self.__class__._trail_status_cache[cache_key] = status
        logger.debug(f"Cached trail status for {trail_arn} in {region}")
        
        return status
    
    def get_delegated_administrators(self) -> List[Dict[str, Any]]:
        """
        Get CloudTrail delegated administrators with caching.
        
        Returns:
            List of delegated administrators
        """
        if not self.regions:
            logger.warning("No regions specified")
            return []
        
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return []
        
        # Check cache first
        cache_key = f"{account_id}:{self.session.region_name}"
        if cache_key in self.__class__._delegated_admin_account_id_cache:
            logger.debug(f"Using cached delegated administrators for {cache_key}")
            return self.__class__._delegated_admin_account_id_cache[cache_key]
        
        # Use any region to get delegated administrators
        client = self.get_client(self.regions[0])
        if not client:
            logger.warning("No CloudTrail client available")
            return []
        
        # Get delegated administrators from client
        delegated_admins = client.list_delegated_administrators()
        
        # Cache the results
        self.__class__._delegated_admin_account_id_cache[cache_key] = delegated_admins
        logger.debug(f"Cached {len(delegated_admins)} delegated administrators for {cache_key}")
        
        return delegated_admins
