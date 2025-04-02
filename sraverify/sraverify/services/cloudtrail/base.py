"""
Base class for CloudTrail security checks.
"""
from typing import List, Optional, Dict, Any
import boto3
from sraverify.core.check import SecurityCheck
from sraverify.services.cloudtrail.client import CloudTrailClient
from sraverify.core.logging import logger


class CloudTrailCheck(SecurityCheck):
    """Base class for all CloudTrail security checks."""
    
    # Class-level cache shared across all instances
    _trails_cache = {}
    
    def __init__(self):
        """Initialize CloudTrail base check."""
        super().__init__(
            check_type="account",
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
    
    def get_trails(self, region: str, trail_name_list: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Get CloudTrail trails in a specific region with caching.
        
        Args:
            region: AWS region name
            trail_name_list: List of trail names to describe (if None, all trails are described)
            
        Returns:
            List of trail descriptions or empty list if not available
        """
        # Create a cache key that includes the region and trail names (if specified)
        cache_key = f"{self.session.region_name}:{region}"
        if trail_name_list:
            cache_key += f":{','.join(sorted(trail_name_list))}"
        
        # Check if we already have cached trails
        if cache_key in CloudTrailCheck._trails_cache:
            logger.debug(f"Using cached trails for {region}")
            return CloudTrailCheck._trails_cache[cache_key]     
        
        # Get client
        client = self.get_client(region)
        if not client:
            logger.warning(f"No CloudTrail client available for region {region}")
            return []
        
        try:
            # Get trails
            trails = client.describe_trails(trail_name_list)
            
            # Cache the trails
            CloudTrailCheck._trails_cache[cache_key] = trails
            
            return trails
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error describing trails in {region}: {error_msg}")
            # Return a special value to indicate an error
            return {"error": True, "message": error_msg}
