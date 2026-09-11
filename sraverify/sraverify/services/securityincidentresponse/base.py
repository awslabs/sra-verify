from typing import Dict, Any, Tuple
from sraverify.core.check import SecurityCheck
from sraverify.services.securityincidentresponse.client import SecurityIncidentResponseClient
from sraverify.core.logging import logger

# Namespace and key for the per-scan cache of the membership discovery result.
# Shared by every SecurityIncidentResponse check in a scan so the region sweep
# runs once rather than once per check and once per batch API call.
_CACHE_NAMESPACE = "securityincidentresponse"
_MEMBERSHIP_DISCOVERY_KEY = "membership_discovery"


class SecurityIncidentResponseCheck(SecurityCheck):
    def _setup_clients(self):
        self._clients.clear()
        # Use first region specified, or us-east-1 as fallback
        region = self.regions[0] if self.regions else "us-east-1"
        self._clients[region] = SecurityIncidentResponseClient(region, ctx=self._ctx)

    def _default_region(self) -> str:
        """Region used for calls that are not pinned to the membership's region."""
        return self.regions[0] if self.regions else "us-east-1"

    def _sir_client(self, region: str) -> SecurityIncidentResponseClient:
        """Return the client wrapper for a region, creating it if absent."""
        client = self.get_client(region)
        if not client:
            self._clients[region] = SecurityIncidentResponseClient(region, ctx=self._ctx)
            client = self.get_client(region)
        return client

    def get_delegated_administrators(self) -> Dict[str, Any]:
        """Get delegated administrators for Security Incident Response."""
        region = self.regions[0] if self.regions else "us-east-1"
        client = self.get_client(region)
        if not client:
            return {}
        return client.list_delegated_administrators()

    def list_memberships(self) -> Dict[str, Any]:
        """
        List Security Incident Response memberships.

        A Security Incident Response membership lives in a single home region
        chosen at onboarding, and ``ListMemberships`` in any other region
        returns an empty ``items`` list rather than an error. Querying only
        ``regions[0]`` therefore reported "no memberships" for every
        organization whose membership is not in that region. This returns the
        response from the region that actually holds the membership.

        Returns:
            The ``ListMemberships`` response from the membership's home region.
            When no region holds a membership, the response from
            ``_default_region()`` is returned so a genuine API failure there
            still surfaces as ``{"Error": ...}``.
        """
        return self._discover_memberships()[1]

    def get_membership(self, membership_id: str) -> Dict[str, Any]:
        """Get Security Incident Response membership details."""
        return self._sir_client(self.discover_sir_region()).get_membership(membership_id)

    def batch_get_member_account_details(self, membership_id: str, account_ids: list) -> Dict[str, Any]:
        """Get member account details for multiple accounts."""
        client = self._sir_client(self.discover_sir_region())
        return client.batch_get_member_account_details(membership_id, account_ids)

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
        """
        Discover the region where Security Incident Response is configured.

        Returns:
            The home region of the first membership found, or
            ``_default_region()`` when no region holds a membership.
        """
        return self._discover_memberships()[0]

    def _discover_memberships(self) -> Tuple[str, Dict[str, Any]]:
        """
        Find the region holding the membership and its ``ListMemberships`` response.

        Sweeps the scan's regions once and caches the outcome on the
        ``ScanContext``, so every check in the scan shares one sweep instead of
        repeating it per check and per batch call.

        Returns:
            ``(region, list_memberships_response)``. Both callers of this method
            take one element each, which keeps the region and the membership
            list that produced it consistent -- previously they were resolved by
            two separate sweeps and could disagree.
        """
        cached = self._ctx._get(_CACHE_NAMESPACE, _MEMBERSHIP_DISCOVERY_KEY)
        if cached is not None:
            return cached

        default_region = self._default_region()
        default_response: Dict[str, Any] = {}
        result: Tuple[str, Dict[str, Any]] | None = None

        for region in self.regions or [default_region]:
            try:
                response = self._sir_client(region).list_memberships()
            except Exception as exc:
                # BotoCoreError, UnknownServiceError and friends are not
                # converted by the client wrapper, which only handles
                # ClientError. Skip the region rather than abort the scan.
                logger.debug(f"Unable to list Security Incident Response memberships in {region}: {exc}")
                continue

            if region == default_region:
                default_response = response

            if "Error" in response:
                continue

            memberships = response.get("items", [])
            if memberships:
                home_region = memberships[0].get("region") or region
                logger.debug(
                    f"Security Incident Response membership found in {home_region} "
                    f"(discovered via {region})"
                )
                result = (home_region, response)
                break

        if result is None:
            result = (default_region, default_response)

        self._ctx._set(_CACHE_NAMESPACE, _MEMBERSHIP_DISCOVERY_KEY, result)
        return result
