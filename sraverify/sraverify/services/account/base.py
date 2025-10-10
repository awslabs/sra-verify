"""
Base class for Account security checks.
"""
from typing import Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.account.client import AccountClient
from sraverify.core.logging import logger


class AccountCheck(SecurityCheck):
    """Base class for all Account security checks."""
    
    # Class-level cache shared across all instances
    _contact_cache = {}
    
    def __init__(self):
        """Initialize Account base check."""
        super().__init__(
            account_type="application",
            service="Account",
            resource_type="AWS::Account::AlternateContact"
        )
    
    def _setup_clients(self):
        """Set up Account clients for each region."""
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = AccountClient(region, session=self.session)
    
    def get_alternate_contact(self, region: str, contact_type: str, account_id: str = None) -> Dict[str, Any]:
        """
        Get alternate contact information with caching.
        
        Args:
            region: AWS region name
            contact_type: Type of contact (BILLING, OPERATIONS, or SECURITY)
            account_id: Optional account ID
            
        Returns:
            Dictionary containing contact details or empty dict if not available
        """
        cache_key = f"{self.account_id}:{region}:{contact_type}"
        if cache_key in AccountCheck._contact_cache:
            logger.debug(f"Account: Using cached {contact_type} contact for {region}")
            return AccountCheck._contact_cache[cache_key]
        
        client = self.get_client(region)
        if not client:
            logger.warning(f"Account: No Account client available for region {region}")
            return {}
        
        contact_info = client.get_alternate_contact(contact_type, account_id)
        AccountCheck._contact_cache[cache_key] = contact_info
        
        return contact_info
