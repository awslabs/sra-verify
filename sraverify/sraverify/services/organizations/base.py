"""
Base class for AWS Organizations security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"organizations"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

Organizations is a global service, so a single :class:`OrganizationsClient` --
pinned to ``us-east-1`` inside the client itself -- is constructed per check
instance and ``self._clients`` is cleared. Cache keys carry no account prefix
because the context is already scoped to one account scan.
"""
import json
from typing import ClassVar, Any, Dict

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.organizations.client import OrganizationsClient


class OrganizationsCheck(SecurityCheck):
    """Base class for all AWS Organizations security checks.

    Organizations is a global AWS service, so a single
    :class:`OrganizationsClient` (pinned to ``us-east-1`` inside the client
    itself) is constructed per check instance. All cached AWS-API responses
    live on the per-scan :class:`ScanContext` under the ``"organizations"``
    namespace; nothing is stored at class or instance level.
    """

    # All cached AWS-API responses for Organizations are stored under this
    # namespace on the per-scan ``ScanContext``. Cache keys are simple
    # service-internal strings (e.g., ``"ous:{parent_id}"``) since the
    # ``ScanContext`` itself is per-scan and per-account, so there is no
    # need to disambiguate by account anymore.
    NAMESPACE = "organizations"

    #: The ``(operation, code)`` pairs that mean "the control is not configured".
    #:
    #: These two are the canonical semantic codes the product principles cite.
    #: Nothing is declared for ``ListRoots``, ``ListOrganizationalUnitsForParent``
    #: or ``ListAccountsForParent``: an empty result from those is a *successful*
    #: response, so any error is an inability to determine.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "DescribeOrganization": {
            "AWSOrganizationsNotInUseException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/organizations/latest/APIReference/"
                    "API_DescribeOrganization.html -- returned when the account is "
                    "not a member of an organization. product.md names this as the "
                    "canonical semantic code, and several checks already treated it "
                    "as a FAIL by hand before this table existed."
                ),
            ),
        },
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
        "DescribeEffectivePolicy": {
            "EffectivePolicyNotFoundException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/organizations/latest/APIReference/"
                    "API_DescribeEffectivePolicy.html -- returned when no policy of "
                    "the requested type is in effect for the target. Observed "
                    "2026-09-16 in organization o-svvpsun36e for every active "
                    "account as 'EffectivePolicyNotFoundException: The specified "
                    "policy type is not enabled. Enable that policy type on your "
                    "organization root and then retry.' -- AWS answered, and the "
                    "answer is that no policy reaches the account. "
                    "InvalidInputException (an unsupported root or OU target) is "
                    "deliberately NOT declared: that is a defect in the caller, not "
                    "a fact about the organization."
                ),
            ),
        },
    }

    def _setup_clients(self):
        """Set up Organizations client (global service, no per-region clients needed).

        The underlying boto3 client held by :class:`OrganizationsClient` is
        obtained from ``self._ctx.get_client(...)`` so it picks up the
        per-scan bounded ``Client_Config`` and the ``(service, region)``
        client cache.
        """
        # Organizations is a global service: one client pinned to us-east-1
        # inside the wrapper is enough.
        self._org_client = OrganizationsClient(ctx=self._ctx)
        # Clear inherited per-region clients dict since Organizations
        # doesn't use it.
        self._clients.clear()

    def get_org_client(self) -> OrganizationsClient:
        """
        Get the Organizations client.

        Returns:
            OrganizationsClient instance
        """
        return self._org_client

    def get_organization(self) -> Dict[str, Any]:
        """
        Get organization details with caching.

        Returns:
            Dictionary containing organization details or Error key if failed.
        """
        cache_key = "organization"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug("Organizations: Using cached organization details")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug("Organizations: Fetching organization details")
        if self._org_client is None:
            logger.warning("Organizations: No client available")
            return no_client_result(service="Organizations", region="global")

        response = self._org_client.describe_organization()

        if is_error(response):
            # Never cached: a retry has to be able to re-issue the call.
            return response

        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug("Organizations: Cached organization details")

        return response

    def get_roots(self) -> Dict[str, Any]:
        """
        Get organization roots with caching.

        Returns:
            Dictionary with Roots key containing list of roots,
            or Error key if failed.
        """
        cache_key = "roots"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug("Organizations: Using cached roots")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug("Organizations: Fetching organization roots")
        if self._org_client is None:
            logger.warning("Organizations: No client available")
            return no_client_result(service="Organizations", region="global")

        response = self._org_client.list_roots()

        if is_error(response):
            # Never cached: a retry has to be able to re-issue the call.
            return response

        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug("Organizations: Cached roots")

        return response

    def get_ous_for_parent(self, parent_id: str) -> Dict[str, Any]:
        """
        Get organizational units for a parent with caching.

        Args:
            parent_id: The ID of the parent root or OU

        Returns:
            Dictionary with OrganizationalUnits key containing list of OUs,
            or Error key if failed.
        """
        cache_key = f"ous:{parent_id}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Organizations: Using cached OUs for parent {parent_id}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug(f"Organizations: Fetching OUs for parent {parent_id}")
        if self._org_client is None:
            logger.warning("Organizations: No client available")
            return no_client_result(service="Organizations", region="global")

        response = self._org_client.list_organizational_units_for_parent(parent_id)

        if is_error(response):
            # Never cached: a retry has to be able to re-issue the call.
            return response

        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug(f"Organizations: Cached OUs for parent {parent_id}")

        return response

    def list_policies(self, policy_type: str = "SERVICE_CONTROL_POLICY") -> Dict[str, Any]:
        """
        List policies by type with caching.

        Args:
            policy_type: Type of policy to list (default: SERVICE_CONTROL_POLICY)

        Returns:
            Dictionary with Policies key containing list of policies,
            or Error key if failed.
        """
        cache_key = f"policies:{policy_type}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Organizations: Using cached policies of type {policy_type}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug(f"Organizations: Fetching policies of type {policy_type}")
        if self._org_client is None:
            logger.warning("Organizations: No client available")
            return no_client_result(service="Organizations", region="global")

        response = self._org_client.list_policies(policy_type)

        if is_error(response):
            # Never cached: a retry has to be able to re-issue the call.
            return response

        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug(f"Organizations: Cached policies of type {policy_type}")

        return response

    def get_accounts_for_parent(self, parent_id: str) -> Dict[str, Any]:
        """
        Get accounts for a parent (root or OU) with caching.

        Args:
            parent_id: The ID of the parent root or OU

        Returns:
            Dictionary with Accounts key containing list of accounts,
            or Error key if failed.
        """
        cache_key = f"accounts:{parent_id}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Organizations: Using cached accounts for parent {parent_id}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug(f"Organizations: Fetching accounts for parent {parent_id}")
        if self._org_client is None:
            logger.warning("Organizations: No client available")
            return no_client_result(service="Organizations", region="global")

        response = self._org_client.list_accounts_for_parent(parent_id)

        if is_error(response):
            # Never cached: a retry has to be able to re-issue the call.
            return response

        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug(f"Organizations: Cached accounts for parent {parent_id}")

        return response

    def get_accounts(self) -> Dict[str, Any]:
        """
        Get every account in the organization, with caching.

        Returns:
            Dictionary with Accounts key containing every account,
            or Error key if failed.
        """
        cache_key = "all_accounts"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug("Organizations: Using cached organization accounts")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug("Organizations: Fetching organization accounts")
        if self._org_client is None:
            logger.warning("Organizations: No client available")
            return no_client_result(service="Organizations", region="global")

        response = self._org_client.list_accounts()

        if is_error(response):
            # Never cached: a retry has to be able to re-issue the call.
            return response

        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug("Organizations: Cached organization accounts")

        return response

    def get_effective_policy(
        self, policy_type: str, target_id: str
    ) -> Dict[str, Any]:
        """
        Get the effective management policy for one account, with caching.

        Args:
            policy_type: A management policy type, e.g. ``"BEDROCK_POLICY"``.
            target_id: An account ID. A root or OU is not a supported target.

        Returns:
            Dictionary with EffectivePolicy key, or Error key if failed.
        """
        cache_key = f"effective_policy:{policy_type}:{target_id}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Organizations: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug(
            f"Organizations: Fetching effective {policy_type} for {target_id}"
        )
        if self._org_client is None:
            logger.warning("Organizations: No client available")
            return no_client_result(service="Organizations", region="global")

        response = self._org_client.describe_effective_policy(policy_type, target_id)

        if is_error(response):
            # Never cached: a retry has to be able to re-issue the call.
            return response

        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug(f"Organizations: Cached {cache_key}")

        return response

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
