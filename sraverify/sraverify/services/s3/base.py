"""
Base class for S3 security checks.
"""
from typing import List, Optional, Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.s3.client import S3Client
from sraverify.core.logging import logger


class S3Check(SecurityCheck):
    """Base class for all S3 security checks."""
    
    # Class-level cache shared across all instances
    _public_access_cache = {}
    
    def __init__(self):
        """Initialize S3 base check."""
        super().__init__(
            account_type="application",
            service="S3",
            resource_type="AWS::S3::AccountPublicAccessBlock"
        )
    
    def _setup_clients(self):
        """Set up S3 clients for each region."""
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = S3Client(region, session=self.session)
    
    def get_public_access(self) -> Dict[str, Any]:
        """
        Get the public access block configuration for the account with caching.
        
        Returns:
            Public access block configuration
        """
        if not self.regions:
            logger.warning("No regions specified")
            return {}
        
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return {}
        
        # Use session region name as part of cache key
        cache_key = f"public_access:{account_id}:{self.session.region_name}"
        if cache_key in self.__class__._public_access_cache:
            logger.debug(f"Using cached public access block configuration for {cache_key}")
            return self.__class__._public_access_cache[cache_key]
        
        # Use any region to get public access block configuration
        # S3 is a global service, but we need to use a regional endpoint
        client = self._clients.get(self.regions[0])
        if not client:
            logger.warning("No S3 client available")
            return {}
        
        # Get public access block configuration from client
        public_access_config = client.get_public_access_block(account_id)
        
        # Cache the results
        self.__class__._public_access_cache[cache_key] = public_access_config
        logger.debug(f"Cached public access block configuration for {cache_key}")
        
        return public_access_config
