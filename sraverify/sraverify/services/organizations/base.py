"""
Base class for AWS Organizations security checks.

Every accessor delegates to the scan's Organizations provider
(``self.organization``, ``core/organization.py``), which owns the
``"organizations"`` namespace on the attached :class:`ScanContext`: it caches each
answer once per scan, returns a failure unchanged, and never caches one. This base
binds no client and reads no cache slot by key.
"""
import json
from typing import ClassVar, Any, Dict

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger


class OrganizationsCheck(SecurityCheck):
    """Base class for all AWS Organizations security checks.

    Organizations data is per-scan, cross-service state, so it lives on the
    context's :class:`~sraverify.core.organization.OrganizationsProvider`. The
    accessors here keep their names and signatures and delegate to it, so the
    checks' call sites are unchanged.
    """

    # Every base declares its namespace. The ``organizations`` namespace is
    # written and read only by the Organizations provider; this base issues no
    # ``_has`` / ``_get`` / ``_set`` call of its own.
    NAMESPACE = "organizations"

    #: The ``(operation, code)`` pairs that mean "the control is not configured".
    #:
    #: Only ``ListPolicies`` is declared here. Every other operation these
    #: accessors reach is in ``OrganizationsProvider.OWNED_OPERATIONS`` and is
    #: classified by the provider's table (``DescribeOrganization`` and
    #: ``DescribeEffectivePolicy`` moved there). ``ListPolicies`` stays because
    #: ``fms:ListPolicies`` shares the name, and the provider's table, keyed by
    #: operation, would be consulted for every Firewall Manager check too.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "ListPolicies": {
            "PolicyTypeNotEnabledException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/organizations/latest/APIReference/"
                    "API_ListPolicies.html -- returned when the requested policy "
                    "type is not enabled for the organization, which is exactly "
                    "what a check asking whether SCPs are enabled is testing for."
                ),
            ),
        },
    }

    def _setup_clients(self):
        """Bind nothing: every accessor delegates to ``self.organization``."""
        self._clients.clear()

    def get_organization(self) -> Dict[str, Any]:
        """
        Get organization details.

        Delegates to ``self.organization.describe()``.

        Returns:
            The ``DescribeOrganization`` response, or an error result.
        """
        return self.organization.describe()

    def get_roots(self) -> Dict[str, Any]:
        """
        Get the organization roots.

        Delegates to ``self.organization.roots()``.

        Returns:
            ``{"Roots": [...]}``, or an error result.
        """
        return self.organization.roots()

    def get_ous_for_parent(self, parent_id: str) -> Dict[str, Any]:
        """
        Get the organizational units directly under a parent.

        Delegates to ``self.organization.ous_for_parent()``.

        Args:
            parent_id: The ID of the parent root or OU

        Returns:
            ``{"OrganizationalUnits": [...]}``, or an error result.
        """
        return self.organization.ous_for_parent(parent_id)

    def list_policies(self, policy_type: str = "SERVICE_CONTROL_POLICY") -> Dict[str, Any]:
        """
        List the organization policies of one type.

        Delegates to ``self.organization.policies()``.

        Args:
            policy_type: Type of policy to list (default: SERVICE_CONTROL_POLICY)

        Returns:
            ``{"Policies": [...]}``, or an error result.
        """
        return self.organization.policies(policy_type)

    def get_accounts_for_parent(self, parent_id: str) -> Dict[str, Any]:
        """
        Get the accounts directly under a parent (root or OU).

        Delegates to ``self.organization.accounts_for_parent()``.

        Args:
            parent_id: The ID of the parent root or OU

        Returns:
            ``{"Accounts": [...]}``, or an error result.
        """
        return self.organization.accounts_for_parent(parent_id)

    def get_effective_policy(
        self, policy_type: str, target_id: str
    ) -> Dict[str, Any]:
        """
        Get the effective management policy for one account.

        Delegates to ``self.organization.effective_policy()``.

        Args:
            policy_type: A management policy type, e.g. ``"BEDROCK_POLICY"``.
            target_id: An account ID. A root or OU is not a supported target.

        Returns:
            The ``DescribeEffectivePolicy`` response, or an error result.
        """
        return self.organization.effective_policy(policy_type, target_id)

    @staticmethod
    def guardrail_identifiers_of(response: Dict[str, Any]) -> tuple:
        """
        Collect the Guardrail identifiers named by an effective Bedrock policy.

        ``EffectivePolicy.PolicyContent`` is a JSON *string*, and the Guardrails
        sit at ``bedrock.guardrail_inference.<region>.<config>.identifier``. The
        parse lives here rather than in the check because ``execute()`` may not
        contain a ``try``, and malformed or unexpected content has to resolve to
        "named no Guardrail" rather than raising.

        Args:
            response: A successful ``DescribeEffectivePolicy`` response.

        Returns:
            The identifiers, sorted and de-duplicated, so the reported cell is
            deterministic across runs.
        """
        content = (response.get("EffectivePolicy") or {}).get("PolicyContent")
        if not isinstance(content, str):
            return ()

        try:
            document = json.loads(content)
        except (ValueError, TypeError):
            logger.debug(
                "Organizations: effective Bedrock policy content is not valid JSON"
            )
            return ()

        if not isinstance(document, dict):
            return ()

        identifiers = set()
        guardrail_inference = (document.get("bedrock") or {}).get(
            "guardrail_inference"
        )
        if not isinstance(guardrail_inference, dict):
            return ()

        # Keyed by Region, then by an opaque configuration name.
        for per_region in guardrail_inference.values():
            if not isinstance(per_region, dict):
                continue
            for config in per_region.values():
                if not isinstance(config, dict):
                    continue
                identifier = config.get("identifier")
                if isinstance(identifier, str) and identifier.strip():
                    identifiers.add(identifier.strip())

        return tuple(sorted(identifiers))
