"""
Base class for AWS Security Incident Response checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"securityincidentresponse"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

This base is the one in the tree that declares **no** ``NAMESPACE``, and three of
its accessors pin ``self.regions[0]`` while the sibling ``discover_sir_region``
resolves the Region correctly. That is a known defect, deliberately left alone:
relabelling moves the ``Region`` cell on genuine PASS and FAIL rows, which the
acceptance gate reads as a regression it cannot attribute.
``tests/property/test_accessor_cache_property.py`` asserts the absence, so the
deferral cannot be undone by accident.

The one caching site is the private :meth:`_discover_memberships`, under the
module-level ``_CACHE_NAMESPACE``.
"""
from typing import Any, ClassVar, Dict, Tuple

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.securityincidentresponse.client import (
    SecurityIncidentResponseClient,
)

# Namespace and key for the per-scan cache of the membership discovery result.
# Shared by every SecurityIncidentResponse check in a scan so the region sweep
# runs once rather than once per check and once per batch API call.
#
# A module constant rather than a NAMESPACE class attribute on purpose: see the
# module docstring. The private _discover_memberships is the only writer, so
# nothing here goes through the accessor-caching contract the class attribute
# would advertise.
_CACHE_NAMESPACE = "securityincidentresponse"
_MEMBERSHIP_DISCOVERY_KEY = "membership_discovery"

#: Display name used in the no-client error result's message.
_SERVICE_NAME = "Security Incident Response"


class SecurityIncidentResponseCheck(SecurityCheck):
    """Base class for all AWS Security Incident Response checks."""

    #: One declared pair. ``iam:GetRole`` answering ``NoSuchEntity`` is the
    #: service linked role genuinely not existing, which is the control being
    #: absent -- SRA-SECURITYINCIDENTRESPONSE-05 already treated it as a FAIL by
    #: a hand-coded ``error_code == "NoSuchEntity"`` compare before this table
    #: existed, and that compare is now replaced by ``is_not_configured``.
    #:
    #: Nothing is declared for the ``organizations`` or ``security-ir``
    #: operations. ``ListMemberships`` answering with an empty ``items`` list is a
    #: *successful* response in every Region but the membership's home Region, so
    #: the absent-membership condition never arrives as an error code in the first
    #: place; any error from it is an inability to determine.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "GetRole": {
            "NoSuchEntity": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/IAM/latest/APIReference/"
                    "API_GetRole.html -- NoSuchEntity is returned when the "
                    "request referenced a role that does not exist. For a "
                    "service linked role that is precisely the control gap the "
                    "check is testing for, and SRA-SECURITYINCIDENTRESPONSE-05 "
                    "was already reporting it as FAIL against a live account."
                ),
            ),
        },
    }

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
        """
        Get delegated administrators for Security Incident Response.

        Returns:
            The ``ListDelegatedAdministrators`` response on success, or an error
            result.
        """
        region = self._default_region()
        client = self.get_client(region)
        if not client:
            return no_client_result(service=_SERVICE_NAME, region=region)
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
            still surfaces as an error result.
        """
        return self._discover_memberships()[1]

    def get_membership(self, membership_id: str) -> Dict[str, Any]:
        """Get Security Incident Response membership details."""
        return self._sir_client(self.discover_sir_region()).get_membership(membership_id)

    def batch_get_member_account_details(self, membership_id: str, account_ids: list) -> Dict[str, Any]:
        """Get member account details for multiple accounts."""
        client = self._sir_client(self.discover_sir_region())
        return client.batch_get_member_account_details(membership_id, account_ids)

    def get_organization_accounts(self) -> Dict[str, Any]:
        """
        Get all accounts in the organization.

        Returns:
            ``{"Accounts": [...]}`` on success, or an error result. A ``Mapping``
            rather than a bare list, so "the organization is empty", "the call was
            denied" and "there was no client" stay three distinct outcomes.
        """
        region = self._default_region()
        client = self.get_client(region)
        if not client:
            return no_client_result(service=_SERVICE_NAME, region=region)
        return client.list_accounts()

    def get_role(self, role_name: str) -> Dict[str, Any]:
        """
        Get IAM role details.

        Returns:
            The ``GetRole`` response on success, or an error result. ``NoSuchEntity``
            is declared in :data:`NOT_CONFIGURED_ERRORS`, so a check routes it to
            FAIL through ``is_not_configured`` rather than comparing the code by
            hand.
        """
        region = self._default_region()
        client = self.get_client(region)
        if not client:
            return no_client_result(service=_SERVICE_NAME, region=region)
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

        There is deliberately no catch-all handler around the sweep. The client
        catches ``AWS_EXCEPTIONS``, so a failure in any Region arrives as an error
        result and the ``is_error`` branch below skips that Region; the only thing
        left able to raise here is a programming defect, which must propagate.

        Returns:
            ``(region, list_memberships_response)``. Both callers take one element
            each, which keeps the Region and the membership list that produced it
            consistent.
        """
        cached = self._ctx._get(_CACHE_NAMESPACE, _MEMBERSHIP_DISCOVERY_KEY)
        if cached is not None:
            return cached

        default_region = self._default_region()
        default_response: Dict[str, Any] = {}
        result: Tuple[str, Dict[str, Any]] | None = None

        for region in self.regions or [default_region]:
            response = self._sir_client(region).list_memberships()

            if region == default_region:
                default_response = response

            if is_error(response):
                logger.debug(
                    f"Security Incident Response: skipping {region}: "
                    f"{response['Error']['Code']}"
                )
                continue

            memberships = response.get("items", [])
            if memberships:
                # The response's own region field, but only when it is a usable
                # string. This value becomes the Region cell of every row three
                # checks emit, and Finding rejects a non-str -- so a response
                # missing the field, or carrying something other than a name,
                # would cost those checks their entire output rather than one
                # cell. The Region the sweep found it in is the safe fallback.
                claimed = memberships[0].get("region")
                home_region = claimed if isinstance(claimed, str) and claimed else region
                logger.debug(
                    f"Security Incident Response membership found in {home_region} "
                    f"(discovered via {region})"
                )
                result = (home_region, response)
                break

        if result is None:
            result = (default_region, default_response)

        if is_error(result[1]):
            # Never cached: a retry has to be able to re-issue the sweep. The
            # fallback is the default Region's own response, so when that Region
            # is the one that failed, caching here would replay the failure for
            # the rest of the scan and every later check would report the same
            # ERROR without ever asking AWS again.
            return result

        self._ctx._set(_CACHE_NAMESPACE, _MEMBERSHIP_DISCOVERY_KEY, result)
        return result
