from typing import Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.securityincidentresponse.client import SecurityIncidentResponseClient
from sraverify.core.logging import logger

class SecurityIncidentResponseCheck(SecurityCheck):
    def __init__(self):
        super().__init__(
            account_type="management",
            service="SecurityIncidentResponse",
            resource_type="AWS::Organizations::DelegatedAdministrator"
        )

    def _setup_clients(self):
        self._clients.clear()
        # Use first region specified, or us-east-1 as fallback
        region = self.regions[0] if self.regions else "us-east-1"
        self._clients[region] = SecurityIncidentResponseClient(region, session=self.session)

    def get_delegated_administrators(self) -> Dict[str, Any]:
        """Get delegated administrators for Security Incident Response."""
        region = self.regions[0] if self.regions else "us-east-1"
        client = self.get_client(region)
        if not client:
            return {}
        return client.list_delegated_administrators()

    def list_memberships(self) -> Dict[str, Any]:
        """List Security Incident Response memberships."""
        region = self.regions[0] if self.regions else "us-east-1"
        client = self.get_client(region)
        if not client:
            return {}
        return client.list_memberships()

    def get_membership(self, membership_id: str) -> Dict[str, Any]:
        """Get Security Incident Response membership details."""
        region = self.regions[0] if self.regions else "us-east-1"
        client = self.get_client(region)
        if not client:
            return {}
        return client.get_membership(membership_id)

    def batch_get_member_account_details(self, membership_id: str, account_ids: list) -> Dict[str, Any]:
        """Get member account details for multiple accounts."""
        # Discover the correct region for Security Incident Response
        sir_region = self._discover_sir_region_for_batch()
        client = self.get_client(sir_region)
        if not client:
            # Create client for discovered region if it doesn't exist
            self._clients[sir_region] = SecurityIncidentResponseClient(sir_region, session=self.session)
            client = self.get_client(sir_region)
        return client.batch_get_member_account_details(membership_id, account_ids)

    def _discover_sir_region_for_batch(self) -> str:
        """Discover the region where Security Incident Response is configured for batch operations."""
        regions_to_try = self.regions if self.regions else ["us-east-1"]
        
        for region in regions_to_try:
            try:
                temp_client = SecurityIncidentResponseClient(region, session=self.session)
                response = temp_client.list_memberships()
                
                if "Error" not in response:
                    memberships = response.get("items", [])
                    if memberships:
                        return memberships[0].get("region", region)
            except Exception:
                continue
        
        return self.regions[0] if self.regions else "us-east-1"

    def get_organization_accounts(self) -> list:
        """Get all accounts in the organization."""
        region = self.regions[0] if self.regions else "us-east-1"
        client = self.get_client(region)
        if not client:
            return []

        response = client.list_accounts()
        if "Error" in response:
            return []

        return response.get("Accounts", [])

    def get_role(self, role_name: str) -> Dict[str, Any]:
        """Get IAM role details."""
        region = self.regions[0] if self.regions else "us-east-1"
        client = self.get_client(region)
        if not client:
            return {}
        return client.get_role(role_name)

    def discover_sir_region(self) -> str:
        """Discover the region where Security Incident Response is configured."""
        # Try each region until we find one with memberships
        regions_to_try = self.regions

        for region in regions_to_try:
            try:
                # Create a temporary client for this region
                temp_client = SecurityIncidentResponseClient(region, session=self.session)
                response = temp_client.list_memberships()

                if "Error" not in response:
                    memberships = response.get("items", [])
                    if memberships:
                        # Return the region from the first membership
                        return memberships[0].get("region", region)
            except Exception:
                continue

        # Fallback to first region or us-east-1
        return self.regions[0] if self.regions else "us-east-1"
