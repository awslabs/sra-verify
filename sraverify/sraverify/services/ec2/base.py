"""
Base class for EC2 security checks.
"""
from typing import Dict, Optional, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.ec2.client import EC2Client
from sraverify.core.logging import logger


class EC2Check(SecurityCheck):
    """Base class for all EC2 security checks."""
    
    # Class-level caches shared across all instances
    _ebs_encryption_default_cache = {}
    
    def __init__(self):
        """Initialize EC2 base check."""
        super().__init__(
            account_type="application",
            service="EC2",
            resource_type="AWS::EC2::Instance"
        )
    
    def _setup_clients(self):
        """Set up EC2 clients for each region."""
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = EC2Client(region, session=self.session)
    
    def get_client(self, region: str) -> Optional[EC2Client]:
        """
        Get EC2 client for a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            EC2Client for the region or None if not available
        """
        return self._clients.get(region)
    
    def get_ebs_encryption_by_default(self, region: str) -> Dict[str, Any]:
        """
        Get the EBS encryption by default status for the account in the region with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing EBS encryption by default status
        """
        # Check cache first
        account_id = self.get_session_accountId(self.session)
        cache_key = f"{account_id}:{region}"
        
        if cache_key in self.__class__._ebs_encryption_default_cache:
            logger.debug(f"Using cached EBS encryption by default status for {region}")
            return self.__class__._ebs_encryption_default_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"No EC2 client available for region {region}")
            return {}
        
        # Get EBS encryption by default status from client
        encryption_status = client.get_ebs_encryption_by_default()
        
        # Cache the result
        self.__class__._ebs_encryption_default_cache[cache_key] = encryption_status
        logger.debug(f"Cached EBS encryption by default status for {region}")
        
        return encryption_status
