"""
Base class for IAM Access Analyzer security checks.
"""
from typing import List, Optional, Dict, Any
import boto3
from sraverify.core.check import SecurityCheck
from sraverify.services.accessanalyzer.client import AccessAnalyzerClient
from sraverify.core.logging import logger


class AccessAnalyzerCheck(SecurityCheck):
    """Base class for all IAM Access Analyzer security checks."""
    
    # Class-level caches shared across all instances
    _delegated_admin_cache = {}
    _analyzer_cache = {}
    
    def __init__(self):
        """Initialize IAM Access Analyzer base check."""
        super().__init__(
            account_type="application",
            service="IAM Access Analyzer",
            resource_type="AWS::AccessAnalyzer::Analyzer"
        )
    
    def _setup_clients(self):
        """Set up AccessAnalyzer clients for enabled regions."""
        # Clear existing clients
        self._clients.clear()
        
        if not hasattr(self, 'session') or not self.session:
            logger.debug("No session available, skipping client setup")
            return
            
        # For organization checks, we need to check all specified regions
        for region in self.regions:
            try:
                client = AccessAnalyzerClient(region, self.session)
                if client.is_access_analyzer_available():
                    self._clients[region] = client
                    logger.debug(f"Access Analyzer client set up for region {region}")
                else:
                    logger.debug(f"Access Analyzer not available in region {region}")
            except Exception as e:
                # Skip regions where client creation fails
                logger.warning(f"Failed to create Access Analyzer client for region {region}: {e}")
                continue
    
    def get_client(self, region: str) -> Optional[AccessAnalyzerClient]:
        """
        Get Access Analyzer client for a region.
        
        Args:
            region: AWS region name
            
        Returns:
            AccessAnalyzerClient for the region or None if not available
        """
        return self._clients.get(region)
    
    def get_analyzers(self, region: str) -> List[Dict[str, Any]]:
        """
        Get analyzers for a specific region with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            List of analyzers in the region
        """
        # Check class-level cache
        cache_key = f"{self.session.region_name}:{region}"
        if cache_key in AccessAnalyzerCheck._analyzer_cache:
            logger.debug(f"Using cached analyzers for {region}")
            return AccessAnalyzerCheck._analyzer_cache[cache_key]
        
        # Get client
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Access Analyzer client available for region {region}")
            return []
        
        # Get analyzers
        logger.debug(f"Fetching analyzers for {region}")
        analyzers = client.list_analyzers()
        
        # Cache the analyzers
        AccessAnalyzerCheck._analyzer_cache[cache_key] = analyzers
        logger.debug(f"Cached {len(analyzers)} analyzers for {region}")
        
        return analyzers
        
    def get_delegated_admin(self) -> Dict[str, Any]:
        """
        Get the delegated administrator for IAM Access Analyzer with caching.
        
        Returns:
            Dictionary containing delegated administrator details or empty dict if none
        """
        account_id = self.account_id
        
        # Check class-level cache
        if account_id in AccessAnalyzerCheck._delegated_admin_cache:
            logger.debug(f"Using cached delegated admin for account {account_id}")
            return AccessAnalyzerCheck._delegated_admin_cache[account_id]
        
        # If not in cache, get it from the client
        # Use the first available region to make the API call
        if not self._clients:
            logger.warning("No Access Analyzer clients available")
            return {}
        
        # Use the first available region's client
        region = next(iter(self._clients))
        client = self._clients[region]
        
        # Get delegated admin from client
        delegated_admin = client.get_delegated_admin()
        
        # Cache the result
        AccessAnalyzerCheck._delegated_admin_cache[account_id] = delegated_admin
        
        return delegated_admin
