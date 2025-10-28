"""
Base class for Audit Manager security checks.
"""
from typing import Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.auditmanager.client import AuditManagerClient


class AuditManagerCheck(SecurityCheck):
    """Base class for all Audit Manager security checks."""
    
    # Class-level cache shared across all instances
    _account_status_cache = {}
    
    def __init__(self):
        """Initialize Audit Manager base check."""
        super().__init__(
            account_type="application",
            service="AuditManager",
            resource_type="AWS::AuditManager::Account"
        )
    
    def _setup_clients(self):
        """Set up Audit Manager clients for each region."""
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = AuditManagerClient(region, session=self.session)
    
    def get_account_status(self, region: str) -> Dict[str, Any]:
        """
        Get account status for a specific region with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Account status response or error information
        """
        cache_key = f"{self.account_id}:{region}"
        if cache_key in AuditManagerCheck._account_status_cache:
            return AuditManagerCheck._account_status_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            return {"Error": {"Code": "NoClient", "Message": f"No client available for region {region}"}}
        
        status = client.get_account_status()
        AuditManagerCheck._account_status_cache[cache_key] = status
        return status
    
    def get_organization_admin_account(self, region: str) -> Dict[str, Any]:
        """
        Get organization admin account for a specific region with caching.
        
        Args:
            region: AWS region name
            
        Returns:
            Organization admin account response or error information
        """
        cache_key = f"org_admin:{region}"
        if cache_key in AuditManagerCheck._account_status_cache:
            return AuditManagerCheck._account_status_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            return {"Error": {"Code": "NoClient", "Message": f"No client available for region {region}"}}
        
        admin_info = client.get_organization_admin_account()
        AuditManagerCheck._account_status_cache[cache_key] = admin_info
        return admin_info
