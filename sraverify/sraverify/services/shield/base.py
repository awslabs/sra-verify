"""
Base class for Shield security checks.
"""
from typing import Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.shield.client import ShieldClient
from sraverify.core.logging import logger


class ShieldCheck(SecurityCheck):
    """Base class for all Shield security checks."""
    
    # Class-level cache shared across all instances
    _subscription_cache = {}
    
    def __init__(self):
        """Initialize Shield base check."""
        super().__init__(
            account_type="application",
            service="Shield",
            resource_type="AWS::Shield::Subscription"
        )
    
    def _setup_clients(self):
        """Set up Shield clients for each region."""
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = ShieldClient(region, session=self.session)
    
    def get_subscription_state(self, region: str) -> Dict[str, Any]:
        """
        Get Shield Advanced subscription state with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing subscription details or empty dict if not available
        """
        cache_key = f"{self.session.region_name}:{region}"
        if cache_key in ShieldCheck._subscription_cache:
            logger.debug(f"Shield: Using cached subscription state for {region}")
            return ShieldCheck._subscription_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return {}
        
        logger.debug(f"Shield: Fetching subscription state for {region}")
        subscription = client.get_subscription_state()
        
        ShieldCheck._subscription_cache[cache_key] = subscription
        logger.debug(f"Shield: Cached subscription state for {region}")
        
        return subscription
    
    def get_subscription_status(self, region: str) -> Dict[str, Any]:
        """
        Get Shield Advanced subscription status (ACTIVE/INACTIVE) with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing subscription status or empty dict if not available
        """
        cache_key = f"status:{self.session.region_name}:{region}"
        if cache_key in ShieldCheck._subscription_cache:
            logger.debug(f"Shield: Using cached subscription status for {region}")
            return ShieldCheck._subscription_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return {}
        
        logger.debug(f"Shield: Fetching subscription status for {region}")
        status = client.get_subscription_status()
        
        ShieldCheck._subscription_cache[cache_key] = status
        logger.debug(f"Shield: Cached subscription status for {region}")
        
        return status
    
    def list_protections(self, region: str, resource_type: str = None) -> Dict[str, Any]:
        """
        List Shield Advanced protections with caching.
        
        Args:
            region: AWS region name
            resource_type: Optional resource type filter
            
        Returns:
            Dictionary containing protections list or empty dict if not available
        """
        cache_key = f"protections:{self.session.region_name}:{region}:{resource_type or 'all'}"
        if cache_key in ShieldCheck._subscription_cache:
            logger.debug(f"Shield: Using cached protections for {region}")
            return ShieldCheck._subscription_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return {}
        
        logger.debug(f"Shield: Listing protections for {region}")
        protections = client.list_protections(resource_type)
        
        ShieldCheck._subscription_cache[cache_key] = protections
        logger.debug(f"Shield: Cached protections for {region}")
        
        return protections
    
    def describe_drt_access(self, region: str) -> Dict[str, Any]:
        """
        Describe Shield Response Team (SRT) access configuration with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing DRT access details or empty dict if not available
        """
        cache_key = f"drt_access:{self.session.region_name}:{region}"
        if cache_key in ShieldCheck._subscription_cache:
            logger.debug(f"Shield: Using cached DRT access for {region}")
            return ShieldCheck._subscription_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return {}
        
        logger.debug(f"Shield: Describing DRT access for {region}")
        drt_access = client.describe_drt_access()
        
        ShieldCheck._subscription_cache[cache_key] = drt_access
        logger.debug(f"Shield: Cached DRT access for {region}")
        
        return drt_access
    
    def get_lambda_function(self, region: str, function_name: str) -> Dict[str, Any]:
        """
        Get Lambda function details.
        
        Args:
            region: AWS region name
            function_name: Name of the Lambda function
            
        Returns:
            Dictionary containing function details or empty dict if not available
        """
        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return {}
        
        logger.debug(f"Shield: Getting Lambda function {function_name} for {region}")
        return client.get_lambda_function(function_name)
    
    def get_web_acl_for_resource(self, region: str, resource_arn: str) -> Dict[str, Any]:
        """
        Get WAF web ACL associated with a resource.
        
        Args:
            region: AWS region name
            resource_arn: ARN of the resource
            
        Returns:
            Dictionary containing web ACL details or empty dict if not available
        """
        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return {}
        
        logger.debug(f"Shield: Getting web ACL for resource {resource_arn} in {region}")
        return client.get_web_acl_for_resource(resource_arn)
