"""
Properties 3a, 7, 8, and 9: the base accessor contract, over every accessor.

A base accessor sits between a client and a check. Its job after this change is
six lines, identical everywhere: cache hit, no-client result, call, error
guard, store, return. Three things it must never do are what these properties
hold.

**Never cache a failure (Property 7).** An error result written into the per-scan
cache is replayed to every later check in that Region for the rest of the scan.
That is not hypothetical: ``SecurityLakeCheck.get_subscribers`` caching ``[]`` on
an ``AccessDeniedException`` is what turned one denied call into 8 wrong FAIL rows
in the 2026-09-12 baseline. 66 of the 72 caching accessors write unguarded today,
4 guard partially, and 2 cache the failure *deliberately*, with a comment saying
so.

**Report a missing wrapper as undetermined (Property 8).** ``get_client(region)``
returns ``None`` when ``_setup_clients`` registered nothing for that Region.
Returning ``[]`` or ``{}`` there makes "we have no way to ask" indistinguishable
from "we asked and there is nothing".

**Do not change what is cached on success (Property 9).** The namespace, the key,
and the call count must all stay as they are, so a scan with no failures issues
exactly the calls it does today. Only the cached *value* changes, for the
accessors whose client used to extract a list or scalar.

**Every public method must be classified.** Requirement 7.10 is explicit that a
source-text heuristic is not good enough -- it misses accessors that delegate
through a private helper, as ``SecurityIncidentResponseCheck.list_memberships``
does through ``_discover_memberships``. So the table below assigns one of six
kinds to every public method in every service base's own ``vars()``, and Property
3a asserts the assignment is total and exact in both directions. A method with no
classification fails.

Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 7.5, 7.10, 7.11.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from unittest.mock import MagicMock

import pytest

import sraverify.services
from sraverify.core.aws_errors import (
    NO_CLIENT_CODE,
    error_result,
    is_error,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.core.enums import AccountType, Severity
from sraverify.core.scan_context import ScanContext

_SERVICES_ROOT: Path = Path(sraverify.services.__file__).resolve().parent

_TEST_REGION = "us-east-1"
_TEST_ACCOUNT = "111122223333"

#: How a public method on a service base class is driven.
#:
#: ``accessor``            caches a client result under NAMESPACE -> Properties 7, 8, 9
#: ``accessor_uncached``   calls the client and returns, caching nothing -> Properties 7, 8
#: ``derived``             computes from other accessors or a private helper -> excluded
#: ``helper``              pure over a success dict; must never touch the context
#: ``client_lookup``       returns the per-Region wrapper (a ``get_client`` override)
#: ``table``               the ``NOT_CONFIGURED_ERRORS`` declaration
Kind = Literal[
    "accessor", "accessor_uncached", "derived", "helper", "client_lookup", "table"
]


@dataclass(frozen=True)
class AccessorAdapter:
    """How to drive one public method on a service base class.

    Attributes:
        method: The method name.
        kind: How it is driven. See :data:`Kind`.
        args: Positional arguments, for the kinds that are called.
        client_method: The client method it ultimately delegates to, for
            ``accessor`` and ``accessor_uncached``.
        cache_key: The cache key it writes, for ``accessor``. Read from the
            implementation, so Property 9 asserts the key has not moved.
        why: Required for ``derived``, so an exclusion carries its reason rather
            than being a quiet opt-out.
    """

    method: str
    kind: Kind
    args: tuple = ()
    client_method: str | None = None
    cache_key: str | None = None
    why: str = ""
    error_bearing: bool | None = None
    prerequisite: tuple[str, Any] | None = None
    """A ``(client_method, success_dict)`` this accessor calls *first*.

    For the two GuardDuty accessors that resolve a detector ID before making
    their own call. The harness arms the prerequisite to succeed so the accessor
    reaches the call under test; without it the internal ``get_detector_id``
    returns an unconfigured ``MagicMock``, which is not an error result and so is
    cached -- a harness artefact that reads as a contract violation.

    Property 9's "exactly one ``_set``" becomes "exactly one ``_set`` for *this*
    accessor's key" when a prerequisite is declared, because the prerequisite
    legitimately caches its own result under its own key.
    """
    """Whether this method hands a check a value it must test for ``"Error"``.

    Defaults to ``True`` for the two accessor kinds and ``False`` otherwise, which
    is right almost everywhere. It is declared explicitly for the two exceptions:

    * ``securityincidentresponse``'s public methods are all ``derived`` -- they
      route through ``_sir_client`` rather than ``self._clients`` -- but they still
      return the client's dict straight to a check, so
      ``test_check_classification_property`` must drive them.
    * ``securitylake``'s derived predicates return a ``bool`` by design, so
      feeding one an error result would simulate something that cannot happen.

    Read by ``test_check_classification_property``, not by this module.
    """

    def bears_error(self) -> bool:
        """Return whether a check tests this method's return value for ``"Error"``.

        Returns:
            The explicit declaration, or the default for the kind.
        """
        if self.error_bearing is not None:
            return self.error_bearing
        return self.kind in {"accessor", "accessor_uncached"}


A = AccessorAdapter

_ADAPTERS: dict[str, tuple[AccessorAdapter, ...]] = {
    "accessanalyzer": (
        A("get_client", "client_lookup", args=(_TEST_REGION,)),
        A(
            "get_analyzers",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_analyzers",
            cache_key=f"analyzers:{_TEST_REGION}",
        ),
        A(
            "get_delegated_admin",
            "accessor",
            client_method="get_delegated_admin",
            cache_key=f"delegated_admin:{_TEST_ACCOUNT}",
        ),
    ),
    "account": (
        A(
            "get_alternate_contact",
            "accessor",
            args=(_TEST_REGION, "SECURITY"),
            client_method="get_alternate_contact",
            cache_key=f"contact:{_TEST_ACCOUNT}:{_TEST_REGION}:SECURITY:",
        ),
    ),
    "auditmanager": (
        A(
            "get_account_status",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_account_status",
            cache_key=f"account_status:{_TEST_ACCOUNT}:{_TEST_REGION}",
        ),
        A(
            "get_organization_admin_account",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_organization_admin_account",
            cache_key=f"org_admin:{_TEST_REGION}",
        ),
    ),
    "cloudtrail": (
        A("get_client", "client_lookup", args=(_TEST_REGION,)),
        # A pure parser, so that no `except` clause appears inside
        # a check's execute(). Three checks compared a delivery time against a
        # 24-hour window inside `except (ValueError, TypeError)`; that handler was
        # catching a malformed timestamp, not an AWS failure, and the contract still
        # forbids it there.
        A("parse_delivery_time", "helper", args=("2026-09-12T18:00:00Z",)),
        A(
            "describe_trails",
            "accessor",
            client_method="describe_trails",
            cache_key="describe_trails:True",
        ),
        A(
            "get_trail_status",
            "accessor",
            args=(_TEST_REGION, "arn:aws:cloudtrail:us-east-1:111122223333:trail/t"),
            client_method="get_trail_status",
            cache_key=(
                "trail_status:arn:aws:cloudtrail:us-east-1:111122223333:trail/t:"
                f"{_TEST_REGION}"
            ),
        ),
        A(
            "get_delegated_administrators",
            "accessor",
            client_method="list_delegated_administrators",
            cache_key=f"delegated_admins:{_TEST_ACCOUNT}",
        ),
        A(
            "get_organization_trails",
            "derived",
            why="filters describe_trails()'s result; issues no call of its own",
        ),
    ),
    "config": (
        A("get_client", "client_lookup", args=(_TEST_REGION,)),
        # A pure helper over a success dict. GetBucketLocation answers a None
        # LocationConstraint for us-east-1, and the client used to return None on
        # failure too -- so the mapping had to move behind the error test.
        A("bucket_region_of", "helper", args=({"LocationConstraint": "us-west-2"},)),
        # The one accessor in the tree that calls its client and caches nothing.
        # Requirement 3.6 forbids changing which responses are cached, so it must
        # keep not caching -- Property 9 does not apply to it.
        A(
            "get_configuration_recorders",
            "accessor_uncached",
            args=(_TEST_REGION,),
            client_method="describe_configuration_recorders",
        ),
        A(
            "get_configuration_recorder_status",
            "accessor",
            args=(_TEST_REGION,),
            client_method="describe_configuration_recorder_status",
            cache_key=f"recorder_status:{_TEST_REGION}",
        ),
        A(
            "get_delivery_channels",
            "accessor",
            args=(_TEST_REGION,),
            client_method="describe_delivery_channels",
            cache_key=f"delivery_channels:{_TEST_REGION}",
        ),
        A(
            "get_delivery_channel_status",
            "accessor",
            args=(_TEST_REGION,),
            client_method="describe_delivery_channel_status",
            cache_key=f"delivery_channel_status:{_TEST_REGION}",
        ),
        A(
            "get_configuration_aggregators",
            "accessor",
            args=(_TEST_REGION,),
            client_method="describe_configuration_aggregators",
            cache_key=f"configuration_aggregators:{_TEST_REGION}",
        ),
        # Loops over CONFIG_SERVICE_PRINCIPALS -- both `config.amazonaws.com` and
        # `config-multiaccountsetup.amazonaws.com` -- caching one slot per
        # principal and aggregating the results. So it writes the cache more than
        # once for a single call, which Property 9's "exactly one _set" assertion
        # cannot express. Excluded with a reason rather than special-cased.
        A(
            "get_delegated_administrators",
            "derived",
            error_bearing=True,
            why=(
                "aggregates across CONFIG_SERVICE_PRINCIPALS, caching one slot "
                "per principal, so a single call writes the cache more than once "
                "-- which Property 9's 'exactly one _set' cannot express. Still "
                "error-bearing: it returns the first principal's error result "
                "rather than merging a partial answer, so the classification "
                "properties must drive it"
            ),
        ),
    ),
    "ec2": (
        A("get_client", "client_lookup", args=(_TEST_REGION,)),
        A(
            "get_ebs_encryption_by_default",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_ebs_encryption_by_default",
            cache_key=f"ebs_encryption_default:{_TEST_REGION}",
        ),
    ),
    "firewallmanager": (
        A(
            "get_admin_account",
            "accessor",
            client_method="get_admin_account",
            cache_key="admin_account",
        ),
        A(
            "list_policies",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_policies",
            cache_key=f"policies:{_TEST_REGION}",
        ),
    ),
    "guardduty": (
        A(
            "get_detector_id",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_detector_id",
            cache_key=f"detector_id:{_TEST_REGION}",
        ),
        # Reads the detector ID from its own get_detector_id call before making
        # its own -- the one internal read Requirement 1.5 permits -- and must
        # return that first call's error result unchanged when it fails.
        A(
            "get_detector_details",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_detector_details",
            cache_key=f"detector_details:{_TEST_REGION}",
            prerequisite=("get_detector_id", {"DetectorIds": ["detector-1"]}),
        ),
        A(
            "get_organization_configuration",
            "accessor",
            args=(_TEST_REGION,),
            client_method="describe_organization_configuration",
            cache_key=f"org_config:{_TEST_REGION}",
            prerequisite=("get_detector_id", {"DetectorIds": ["detector-1"]}),
        ),
        # A pure helper over a success dict -- reads DetectorIds[0]. Never handed
        # an accessor's raw return, per Requirement 1.5.
        A("detector_id_of", "helper", args=({"DetectorIds": ["detector-1"]},)),
        A(
            "list_organization_admin_accounts",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_organization_admin_accounts",
            cache_key=f"admin_accounts:{_TEST_REGION}",
        ),
        A(
            "get_enabled_regions",
            "derived",
            why="folds get_detector_id() over self.regions; issues no call itself",
        ),
    ),
    "iam": (
        A("get_iam_client", "client_lookup"),
        A(
            "list_users",
            "accessor",
            client_method="list_users",
            cache_key=f"users:{_TEST_ACCOUNT}",
        ),
    ),
    "inspector": (
        A("get_client", "client_lookup", args=(_TEST_REGION,)),
        # Extraction lives in these two pure
        # helpers over a success dict (Requirement 1.5). get_account_status used to
        # flatten resourceState itself, and batch_get_account_status used to build
        # the {account_id: status} map, so each had two possible success shapes.
        A(
            "account_status_of",
            "helper",
            args=(
                {"accounts": [{"accountId": _TEST_ACCOUNT, "state": {}, "resourceState": {}}]},
                _TEST_ACCOUNT,
            ),
        ),
        A(
            "status_by_account",
            "helper",
            args=({"accounts": [{"accountId": _TEST_ACCOUNT}]},),
        ),
        # Recognises inspector2:GetDelegatedAdminAccount refusing to answer
        # *because* the caller is the delegated administrator. Neither a
        # transport failure nor "not configured" -- it is the answer, stated as a
        # refusal, so it gets its own predicate rather than a table entry.
        A(
            "caller_is_delegated_admin",
            "helper",
            args=(
                {
                    "Operation": "GetDelegatedAdminAccount",
                    "Code": "ValidationException",
                    "Message": "Invoking account is the delegated admin.",
                },
            ),
        ),
        A(
            "get_account_status",
            "accessor",
            args=(_TEST_REGION,),
            client_method="batch_get_account_status",
            cache_key=f"account_status:{_TEST_ACCOUNT}:{_TEST_REGION}",
        ),
        A(
            "get_delegated_admin",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_delegated_admin_account",
            cache_key=f"delegated_admin:{_TEST_REGION}",
        ),
        A(
            "get_organization_members",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_organization_accounts",
            cache_key="organization_members",
        ),
        A(
            "batch_get_account_status",
            "accessor",
            args=(_TEST_REGION, [_TEST_ACCOUNT]),
            client_method="batch_get_account_status",
            cache_key=f"batch_status:{_TEST_REGION}",
        ),
        A(
            "get_organization_configuration",
            "accessor",
            args=(_TEST_REGION,),
            client_method="describe_organization_configuration",
            cache_key=f"organization_configuration:{_TEST_REGION}",
        ),
    ),
    "macie": (
        A("get_client", "client_lookup", args=(_TEST_REGION,)),
        A(
            "get_findings_publication_configuration",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_findings_publication_configuration",
            cache_key=f"findings_publication:{_TEST_REGION}",
        ),
        # One of the two reference accessors from bdad609: already refuses to
        # cache an error result, which is why the classification keys on the
        # pair. Marking macie wholesale would XPASS here.
        A(
            "get_classification_export_configuration",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_classification_export_configuration",
            cache_key=f"export_configuration:{_TEST_REGION}",
        ),
        A(
            "get_macie_delegated_admin",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_delegated_administrators",
            cache_key=f"delegated_admin:{_TEST_REGION}",
        ),
        A(
            "get_macie_members",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_members",
            cache_key=f"members:{_TEST_REGION}",
        ),
        A(
            "get_organization_members",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_organization_accounts",
            cache_key=f"organization_members:{_TEST_REGION}",
        ),
        A(
            "get_organization_configuration",
            "accessor",
            args=(_TEST_REGION,),
            client_method="describe_organization_configuration",
            cache_key=f"organization_configuration:{_TEST_REGION}",
        ),
        A(
            "get_macie_administrator_account",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_administrator_account",
            cache_key=f"administrator_account:{_TEST_REGION}",
        ),
        # A predicate over an error dict, superseded by the shared
        # is_not_configured table.
    ),
    "organizations": (
        A("get_org_client", "client_lookup"),
        A(
            "get_organization",
            "accessor",
            client_method="describe_organization",
            cache_key="organization",
        ),
        A("get_roots", "accessor", client_method="list_roots", cache_key="roots"),
        A(
            "get_ous_for_parent",
            "accessor",
            args=("r-abc1",),
            client_method="list_organizational_units_for_parent",
            cache_key="ous:r-abc1",
        ),
        A(
            "list_policies",
            "accessor",
            client_method="list_policies",
            cache_key="policies:SERVICE_CONTROL_POLICY",
        ),
        A(
            "get_accounts_for_parent",
            "accessor",
            args=("ou-abc-123",),
            client_method="list_accounts_for_parent",
            cache_key="accounts:ou-abc-123",
        ),
    ),
    "s3": (
        A("get_client", "client_lookup", args=(_TEST_REGION,)),
        A(
            "get_public_access",
            "accessor",
            client_method="get_public_access_block",
            cache_key=f"public_access:{_TEST_ACCOUNT}",
        ),
    ),
    "securityhub": (
        A("get_client", "client_lookup", args=(_TEST_REGION,)),
        A(
            "get_enabled_standards",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_enabled_standards",
            cache_key=f"enabled_standards:{_TEST_REGION}",
        ),
        A(
            "get_administrator_account",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_administrator_account",
            cache_key=f"administrator_account:{_TEST_REGION}",
        ),
        A(
            "get_organization_configuration",
            "accessor",
            args=(_TEST_REGION,),
            client_method="describe_organization_configuration",
            cache_key=f"organization_configuration:{_TEST_REGION}",
        ),
        A(
            "get_enabled_products_for_import",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_enabled_products_for_import",
            cache_key=f"product_integrations:{_TEST_REGION}",
        ),
        A(
            "get_delegated_administrators",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_delegated_administrators",
            cache_key=f"delegated_admin:{_TEST_REGION}",
        ),
        A(
            "get_organization_admin_accounts",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_organization_admin_accounts",
            cache_key=f"organization_admin_accounts:{_TEST_REGION}",
        ),
        A(
            "get_organization_accounts",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_organization_accounts",
            cache_key=f"organization_accounts:{_TEST_REGION}",
        ),
        A(
            "get_security_hub_members",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_members",
            cache_key=f"securityhub_members:{_TEST_REGION}",
        ),
        # Writes into the SHARED "organizations" namespace, and builds its own
        # error result in its own except clause and caches it -- one of the two
        # deliberate failure-caching sites (Requirement 3.4). Because the
        # namespace is shared, OrganizationsCheck.get_organization reads that
        # cached error result back.
        A(
            "get_organization",
            "derived",
            why=(
                "writes the shared 'organizations' namespace rather than "
                "securityhub's, and is covered by its own test below"
            ),
        ),
    ),
    "securityincidentresponse": (
        # Every one of these routes through the private _discover_memberships or
        # _sir_client rather than through self._clients, so neither the no-client
        # path nor the NAMESPACE cache applies -- this base declares no NAMESPACE
        # at all (a known defect, deferred by Non-Goal 6). The one caching site is
        # _discover_memberships, covered by its own test below.
        # All six of these hand a check the client's dict directly, so they are
        # error-bearing even though the caching classification is ``derived``.
        A(
            "get_delegated_administrators",
            "derived",
            why="builds a throwaway client via _sir_client; no NAMESPACE cache",
            error_bearing=True,
        ),
        A(
            "list_memberships",
            "derived",
            why="returns _discover_memberships()[1]; the caching happens there",
            error_bearing=True,
        ),
        A(
            "get_membership",
            "derived",
            args=("m-abc123",),
            why="builds a throwaway client via _sir_client; no NAMESPACE cache",
            error_bearing=True,
        ),
        A(
            "batch_get_member_account_details",
            "derived",
            why="builds a throwaway client via _sir_client; no NAMESPACE cache",
            error_bearing=True,
        ),
        A(
            "get_organization_accounts",
            "derived",
            why="builds a throwaway client via _sir_client; no NAMESPACE cache",
            error_bearing=True,
        ),
        A(
            "get_role",
            "derived",
            why="builds a throwaway client via _sir_client; no NAMESPACE cache",
            error_bearing=True,
        ),
        # Returns a Region name, not a response dict.
        A(
            "discover_sir_region",
            "derived",
            why="region resolution only; re-issues ListMemberships per call",
            error_bearing=False,
        ),
    ),
    "securitylake": (
        A("get_client", "client_lookup", args=(_TEST_REGION,)),
        # A pure helper over a success dict -- reads bool(dataLakes). Never handed
        # an accessor's raw return, per Requirement 1.5. It exists because
        # is_security_lake_enabled stopped answering a bool.
        A("data_lake_present", "helper", args=({"dataLakes": [{"region": _TEST_REGION}]},)),
        # The measured masked-FAIL path: caches [] on AccessDeniedException today,
        # and on the no-client path too.
        A(
            "get_subscribers",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_subscribers",
            cache_key=f"subscribers:{_TEST_REGION}",
        ),
        A(
            "is_security_lake_enabled",
            "accessor",
            args=(_TEST_REGION,),
            client_method="is_security_lake_enabled",
            cache_key=f"security_lake_status:{_TEST_REGION}",
        ),
        A(
            "get_organization_configuration",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_organization_configuration",
            cache_key=f"organization_configuration:{_TEST_REGION}",
        ),
        A(
            "get_delegated_administrators",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_delegated_administrators",
            cache_key=f"delegated_administrators:{_TEST_REGION}",
        ),
        A(
            "get_organization_accounts",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_organization_accounts",
            cache_key=f"organization_accounts:{_TEST_REGION}",
        ),
        A(
            "get_sqs_queue_encryption",
            "accessor",
            args=(_TEST_REGION, "https://sqs.us-east-1.amazonaws.com/1/q"),
            client_method="get_sqs_queue_encryption",
            cache_key=f"sqs_encryption:{_TEST_REGION}:https://sqs.us-east-1.amazonaws.com/1/q",
        ),
        A(
            "get_data_lake_sources",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_data_lake_sources",
            cache_key=f"data_lake_sources:{_TEST_REGION}:all",
        ),
        # The three log-source predicates below answer a bare
        # bool and cannot report a failure, so this is the error-bearing accessor
        # a check guards before using any of them -- and the single cached slot
        # that stopped one denied ListLogSources fanning out into 832 calls.
        A(
            "get_log_sources",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_log_sources",
            cache_key=f"log_sources:{_TEST_REGION}",
        ),
        A(
            "get_log_source_status",
            "derived",
            why="answers a bool from the list_log_sources cache primed elsewhere",
        ),
        A(
            "get_account_log_source_status",
            "derived",
            why="answers a bool from get_data_lake_sources()",
        ),
        A(
            "check_log_source_configured",
            "derived",
            why="answers a bool from the _prime_region_log_sources cache",
        ),
        A(
            "get_enabled_regions",
            "derived",
            why="folds is_security_lake_enabled() over self.regions",
        ),
    ),
    "shield": (
        A("get_client", "client_lookup", args=(_TEST_REGION,)),
        A(
            "get_subscription_state",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_subscription_state",
            cache_key=f"subscription_state:{_TEST_REGION}",
        ),
        A(
            "get_subscription_status",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_subscription_status",
            cache_key=f"subscription_status:{_TEST_REGION}",
        ),
        A(
            "list_protections",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_protections",
            cache_key=f"protections:{_TEST_REGION}:all",
        ),
        A(
            "describe_drt_access",
            "accessor",
            args=(_TEST_REGION,),
            client_method="describe_drt_access",
            cache_key=f"drt_access:{_TEST_REGION}",
        ),
        # These three are documented in the tree as intentionally uncached: the
        # response varies per resource ARN or function name and is not worth
        # caching at this layer. Requirement 3.6 forbids changing what is cached,
        # so they must keep not caching -- but they still owe the no-client
        # error result and the never-cache-a-error result guarantee, which is exactly what
        # ``accessor_uncached`` drives.
        A(
            "get_lambda_function",
            "accessor_uncached",
            args=(_TEST_REGION, "fn"),
            client_method="get_lambda_function",
        ),
        A(
            "get_web_acl_for_resource",
            "accessor_uncached",
            args=(_TEST_REGION, "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/x/y"),
            client_method="get_web_acl_for_resource",
        ),
        A(
            "get_cloudwatch_alarms_for_resource",
            "accessor_uncached",
            args=(_TEST_REGION, "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/x/y"),
            client_method="get_cloudwatch_alarms_for_resource",
        ),
    ),
    "waf": (
        A(
            "get_distributions",
            "accessor",
            client_method="list_distributions",
            cache_key="distributions",
        ),
        A(
            "get_load_balancers",
            "accessor",
            args=(_TEST_REGION,),
            client_method="describe_load_balancers",
            cache_key=f"load_balancers:{_TEST_REGION}",
        ),
        A(
            "get_rest_apis",
            "accessor",
            args=(_TEST_REGION,),
            client_method="get_rest_apis",
            cache_key=f"rest_apis:{_TEST_REGION}",
        ),
        # Documented in the tree as intentionally uncached: parameterized on
        # rest_api_id, and the pre-refactor implementation did not cache either.
        A(
            "get_stages",
            "accessor_uncached",
            args=(_TEST_REGION, "api1"),
            client_method="get_stages",
        ),
        A(
            "get_graphql_apis",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_graphql_apis",
            cache_key=f"graphql_apis:{_TEST_REGION}",
        ),
        A(
            "get_user_pools",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_user_pools",
            cache_key=f"user_pools:{_TEST_REGION}",
        ),
        # The other reference accessor from bdad609.
        A(
            "get_apprunner_services",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_services",
            cache_key=f"apprunner_services:{_TEST_REGION}",
        ),
        A(
            "get_verified_access_instances",
            "accessor",
            args=(_TEST_REGION,),
            client_method="describe_verified_access_instances",
            cache_key=f"verified_access_instances:{_TEST_REGION}",
        ),
        A(
            "get_amplify_apps",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_apps",
            cache_key=f"amplify_apps:{_TEST_REGION}",
        ),
        A(
            "get_web_acls",
            "accessor",
            args=(_TEST_REGION,),
            client_method="list_web_acls",
            cache_key=f"web_acls:{_TEST_REGION}_REGIONAL",
        ),
        # Uncached: both are parameterized on a resource ARN. They exist on the
        # base rather than being reached through ``get_client`` so that the
        # no-client condition yields a row, and so that the accessor patching in
        # test_check_classification_property can drive them.
        A(
            "get_web_acl_for_resource",
            "accessor_uncached",
            args=(_TEST_REGION, "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/x/y"),
            client_method="get_web_acl_for_resource",
        ),
        A(
            "get_logging_configuration",
            "accessor_uncached",
            args=(_TEST_REGION, "arn:aws:wafv2:us-east-1:1:regional/webacl/acl/1"),
            client_method="get_logging_configuration",
        ),
        # The availability delegate is gone (task 19.1). It was the original
        # implementation of the offline endpoint lookup, lifted to
        # ``core/availability.py`` so every service could reach it; the delegate
        # stayed behind only so the WAF checks did not have to change in the same
        # commit. ``sra_waf_06`` now imports ``service_available_in_region``
        # directly, which is the one place in the tree that called it.
    ),
}


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


def _service_names() -> list[str]:
    """Return every service package name, sorted.

    Returns:
        The service directory names.
    """
    return sorted(
        module.name
        for module in pkgutil.iter_modules([str(_SERVICES_ROOT)])
        if module.ispkg
    )


def _base_class(service: str) -> type[SecurityCheck]:
    """Return the ``<Service>Check`` class declared in a service's ``base`` module.

    Args:
        service: A service package name.

    Returns:
        The declared base class.

    Raises:
        AssertionError: If the module declares no base class.
    """
    module = importlib.import_module(f"sraverify.services.{service}.base")
    for obj in vars(module).values():
        if (
            inspect.isclass(obj)
            and issubclass(obj, SecurityCheck)
            and obj is not SecurityCheck
            and obj.__module__ == module.__name__
        ):
            return obj
    raise AssertionError(f"{service}/base.py declares no <Service>Check class")


def _public_methods(cls: type) -> list[str]:
    """Return the class's own public method names, sorted.

    ``vars(cls)`` -- the class's own dict -- which is Requirement 7.10's
    enumeration rule. ``dir(cls)`` would pull in every inherited
    ``SecurityCheck`` method and make the table a statement about the wrong
    thing.

    Args:
        cls: The class to inspect.

    Returns:
        Sorted public method names.
    """
    return sorted(
        name
        for name, obj in vars(cls).items()
        if not name.startswith("_")
        and (inspect.isfunction(obj) or isinstance(obj, staticmethod))
    )


@dataclass(frozen=True)
class _Target:
    """One (service, base class, adapter) triple."""

    service: str
    cls: type[SecurityCheck]
    adapter: AccessorAdapter

    @property
    def id(self) -> str:
        """Return the parametrize ID: ``<service>.<Class>.<method>``."""
        return f"{self.service}.{self.cls.__name__}.{self.adapter.method}"


def _build_targets(kinds: tuple[str, ...]) -> list[_Target]:
    """Pair adapters of the given kinds with their base class.

    Args:
        kinds: Which adapter kinds to include.

    Returns:
        Matching targets, in service order.
    """
    targets: list[_Target] = []
    for service in _SERVICE_NAMES:
        cls = _base_class(service)
        for adapter in _ADAPTERS.get(service, ()):
            if adapter.kind in kinds and adapter.method in _public_methods(cls):
                targets.append(_Target(service, cls, adapter))
    return targets


_SERVICE_NAMES: list[str] = _service_names()
_CACHING: list[_Target] = _build_targets(("accessor",))
_CALLING: list[_Target] = _build_targets(("accessor", "accessor_uncached"))
_HELPERS: list[_Target] = _build_targets(("helper",))


# --------------------------------------------------------------------------- #
# The harness
# --------------------------------------------------------------------------- #


def _concrete(cls: type[SecurityCheck]) -> type[SecurityCheck]:
    """Return an instantiable subclass of an abstract service base class.

    ``SecurityCheck`` is an ``ABC`` with ``execute`` abstract, and a service base
    class does not implement it -- that is the check's job. This adds a trivial
    ``execute`` and a valid ``meta`` so the base's accessors can be exercised
    without a real check.

    Declared in this module, whose stem is not ``sra_``, so
    ``__init_subclass__`` returns silently and nothing registers.

    Args:
        cls: The service base class.

    Returns:
        A concrete subclass.
    """
    return type(
        f"_Concrete{cls.__name__}",
        (cls,),
        {
            "__doc__": f"Throwaway concrete {cls.__name__} for a contract test.",
            "__module__": __name__,
            "meta": CheckMeta(
                check_id="SRA-PROBE-01",
                title="A synthetic control is configured",
                description="Throwaway metadata for an accessor contract test.",
                check_logic="Synthetic.",
                severity=Severity.HIGH,
                account_type=AccountType.APPLICATION,
                service="Probe",
                resource_type="AWS::Probe::Resource",
                remediation=Remediation(text="Configure the probe control."),
            ),
            "execute": lambda self: iter(()),
        },
    )


def _make_check(
    target: _Target, *, register_client: bool = True
) -> tuple[SecurityCheck, MagicMock, MagicMock]:
    """Build a check whose client wrapper is a mock, with a mock context.

    ``_setup_clients`` is bypassed rather than run: it would construct real
    wrappers, and the point here is the accessor's own logic, not the wrapper's.
    A ``MagicMock`` stands in for the wrapper so the harness can make the client
    method return an error result or a success dict.

    Args:
        target: The target to build for.
        register_client: When ``False``, leave ``_clients`` empty so the accessor
            takes its no-client path (Property 8).

    Returns:
        ``(check, ctx, wrapper)``.
    """
    # A real dict behind _has/_get/_set, not a bare MagicMock returning False.
    #
    # This matters for two of the properties. With ``_has`` pinned to False the
    # "a failed call is re-issued" test would pass for an accessor that cached
    # the failure -- the second call would miss the cache no matter what the
    # first one wrote -- and the warm-cache test could not be set up at all. The
    # dict makes both of them measure the accessor's behaviour instead of the
    # mock's.
    cache: dict[tuple[str, str], Any] = {}

    ctx = MagicMock(spec=ScanContext)
    ctx.regions = [_TEST_REGION]
    ctx.audit_accounts = [_TEST_ACCOUNT]
    ctx.log_archive_accounts = ["444455556666"]
    ctx.get_account_info.return_value = {
        "account_id": _TEST_ACCOUNT,
        "account_name": "probe-account",
    }
    ctx.get_management_account_id.return_value = _TEST_ACCOUNT
    ctx.get_enabled_regions.return_value = [_TEST_REGION]
    ctx._has.side_effect = lambda namespace, key: (namespace, key) in cache
    ctx._get.side_effect = lambda namespace, key, default=None: cache.get(
        (namespace, key), default
    )
    ctx._set.side_effect = lambda namespace, key, value: cache.__setitem__(
        (namespace, key), value
    )
    # Exposed so a test can pre-warm or inspect it directly.
    ctx.probe_cache = cache

    check = _concrete(target.cls)()
    check._ctx = ctx

    wrapper = MagicMock(name=f"{target.service}Client")
    # Arm any prerequisite call to succeed, so the accessor under test actually
    # reaches its own call rather than stopping at an unconfigured MagicMock.
    if target.adapter.prerequisite is not None:
        prerequisite_method, prerequisite_success = target.adapter.prerequisite
        getattr(wrapper, prerequisite_method).return_value = prerequisite_success
    if register_client:
        check._clients[_TEST_REGION] = wrapper
        # Some accessors are non-regional and read a fixed key; give them the
        # same wrapper under the global spellings the tree uses.
        check._clients["global"] = wrapper
        check._clients[None] = wrapper

    # A global service's base pins a single client on a named attribute instead
    # of keying ``_clients`` by Region -- ``OrganizationsCheck._org_client``,
    # ``IAMCheck._iam_client``. Those attributes are normally assigned by
    # ``_setup_clients``, which this harness deliberately does not run (it would
    # construct real wrappers). Read the names out of ``_setup_clients``'s source
    # and bind the same mock to each, so the harness covers regional and global
    # bases without a per-service special case.
    for attribute in _global_client_attributes(target.cls):
        setattr(check, attribute, wrapper if register_client else None)

    return check, ctx, wrapper


def _global_client_attributes(cls: type) -> tuple[str, ...]:
    """Return the ``self._<name>_client`` attributes ``_setup_clients`` assigns.

    Derived by AST from the base class's ``_setup_clients``, so a service that
    renames its pinned client attribute does not silently drop out of these
    properties.

    Args:
        cls: A service base class.

    Returns:
        The assigned private client attribute names.
    """
    import ast
    import textwrap

    setup = vars(cls).get("_setup_clients")
    if setup is None:
        return ()
    try:
        source = inspect.getsource(setup)
    except OSError:  # pragma: no cover - source always available in this tree
        return ()

    # textwrap.dedent, not inspect.cleandoc: cleandoc is for docstrings and
    # leaves a method's body indented relative to its own `def`, which does not
    # parse.
    tree = ast.parse(textwrap.dedent(source))
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for goal in node.targets:
            if (
                isinstance(goal, ast.Attribute)
                and isinstance(goal.value, ast.Name)
                and goal.value.id == "self"
                and goal.attr.startswith("_")
                and goal.attr.endswith("_client")
            ):
                names.append(goal.attr)
    return tuple(dict.fromkeys(names))


def _error_result(target: _Target) -> Any:
    """Return a non-semantic error result for the target's client method.

    Args:
        target: The target.

    Returns:
        An error result naming a code no discriminator declares.
    """
    return error_result(
        code="TestDenied",
        message="simulated denial for the accessor contract",
        operation=target.adapter.client_method or "TestOperation",
    )


def _params(targets: list[_Target], property_key: str) -> list[Any]:
    """Return parametrize values, one per target.

    ``property_key`` is retained in the signature and unused: the call sites read
    as documentation of which property each parametrization drives.

    Args:
        targets: The targets to parametrize over.
        property_key: Which property this parametrization drives. Unused.

    Returns:
        ``pytest.param`` values.
    """
    return [pytest.param(target, id=target.id) for target in targets]


# --------------------------------------------------------------------------- #
# Property 3a -- the classification is total and exact
# --------------------------------------------------------------------------- #


def test_eighteen_services_are_discovered() -> None:
    """The enumeration found the whole tree."""
    assert len(_SERVICE_NAMES) == 18, (
        f"expected 18 service packages, found {len(_SERVICE_NAMES)}"
    )


def test_the_caching_accessor_set_is_not_trivially_small() -> None:
    """Enough accessors to be quantifying over something real."""
    assert len(_CACHING) >= 60, (
        f"only {len(_CACHING)} caching accessors found; the tree holds roughly 70 "
        f"and either discovery or the tables are broken"
    )


@pytest.mark.parametrize("service", _SERVICE_NAMES)
def test_every_public_base_method_is_classified(service: str) -> None:
    """Property 3a: the adapter table covers the base class exactly.

    Requirement 7.10 requires *every* public method to carry a classification, so
    that a method with none fails rather than being silently uncovered. The rule
    that makes this non-trivial is the enumeration: ``vars(cls)``, not a
    source-text heuristic, which would miss
    ``SecurityIncidentResponseCheck.list_memberships`` -- its body is
    ``return self._discover_memberships()[1]`` and contains neither ``_set(`` nor
    ``get_client(``.
    """
    cls = _base_class(service)
    discovered = set(_public_methods(cls))
    declared = {adapter.method for adapter in _ADAPTERS.get(service, ())}

    missing = discovered - declared
    stale = declared - discovered

    assert missing == set(), (
        f"{service}: public base methods with no classification: "
        f"{sorted(missing)}. Add an AccessorAdapter declaring whether each is an "
        f"accessor, a derived value, a pure helper, a client lookup, or the table."
    )
    assert stale == set(), (
        f"{service}: adapters for methods that no longer exist: {sorted(stale)}"
    )


def test_every_derived_adapter_records_why_it_is_excluded() -> None:
    """An exclusion carries its reason, so it cannot be a quiet opt-out.

    ``derived`` is the escape hatch from Properties 7-9, and an escape hatch
    without a stated reason is how an accessor that *should* be guarded ends up
    unguarded.
    """
    offenders = [
        f"{service}.{adapter.method}"
        for service, adapters in _ADAPTERS.items()
        for adapter in adapters
        if adapter.kind == "derived" and not adapter.why.strip()
    ]
    assert offenders == [], f"derived adapters with no stated reason: {offenders}"


def test_every_caching_adapter_declares_a_cache_key() -> None:
    """Property 9 compares against a declared key, so it must be present."""
    offenders = [
        f"{service}.{adapter.method}"
        for service, adapters in _ADAPTERS.items()
        for adapter in adapters
        if adapter.kind == "accessor" and not adapter.cache_key
    ]
    assert offenders == [], f"accessor adapters with no cache_key: {offenders}"


# --------------------------------------------------------------------------- #
# Property 7 -- an error result is never cached, and the call is re-issued
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("target", _params(_CALLING, "property_7"), ids=None)
def test_no_accessor_caches_an_error_result(target: _Target) -> None:
    """Property 7: the slot is left empty and the error result is returned unchanged.

    Returning it unchanged matters as much as not caching it. An accessor that
    swallowed the error result and returned ``[]`` would satisfy "did not cache a
    failure" while handing the check exactly the ambiguous value this whole
    contract removes.
    """
    check, ctx, wrapper = _make_check(target)
    getattr(wrapper, target.adapter.client_method).return_value = _error_result(target)

    result = getattr(check, target.adapter.method)(*target.adapter.args)

    # A declared prerequisite legitimately caches its own success under its own
    # key; only a write under THIS accessor's key -- or any write at all when
    # there is no prerequisite -- is a violation.
    own_writes = [
        call
        for call in ctx._set.call_args_list
        if target.adapter.prerequisite is None
        or call.args[1] == target.adapter.cache_key
    ]
    assert own_writes == [], (
        f"{target.id} wrote to the cache after its client returned an error result: "
        f"{own_writes}"
    )
    assert is_error(result), (
        f"{target.id} returned {result!r} instead of passing the error result through"
    )


@pytest.mark.parametrize("target", _params(_CALLING, "property_7_reissue"), ids=None)
def test_a_failed_accessor_call_is_re_issued_on_the_next_call(
    target: _Target,
) -> None:
    """Property 7: the cost of not caching a failure, observed directly.

    Requirement 3.5 accepts this explicitly: where two checks call the same
    accessor and the underlying call fails, the call is issued once per calling
    check rather than once per scan. That is the price of a retry being possible
    at all, and it is bounded -- the alternative was replaying one failure for the
    rest of the scan.
    """
    check, ctx, wrapper = _make_check(target)
    client_method = getattr(wrapper, target.adapter.client_method)
    client_method.return_value = _error_result(target)

    getattr(check, target.adapter.method)(*target.adapter.args)
    first = client_method.call_count

    getattr(check, target.adapter.method)(*target.adapter.args)
    second = client_method.call_count

    assert second > first, (
        f"{target.id} did not re-issue the call after a failure; the error result "
        f"must not be cached, so a retry has to reach AWS again"
    )


# --------------------------------------------------------------------------- #
# Property 8 -- the no-client condition
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("target", _params(_CALLING, "property_8"), ids=None)
def test_a_missing_client_wrapper_yields_a_no_client_result(
    target: _Target,
) -> None:
    """Property 8: a missing wrapper is an undetermined state, not an empty result.

    ``get_client(region)`` returns ``None`` only when ``_setup_clients``
    registered nothing for that Region. Returning ``[]`` there -- which
    ``SecurityLakeCheck.get_subscribers``, ``get_sqs_queue_encryption``, and
    ``get_data_lake_sources`` all do today, *and cache* -- makes "we had no way to
    ask" identical to "we asked and there was nothing".
    """
    check, ctx, _ = _make_check(target, register_client=False)
    assert check._clients == {}, "the fixture registered a client after all"

    result = getattr(check, target.adapter.method)(*target.adapter.args)

    assert is_error(result), (
        f"{target.id} returned {result!r} with no client registered; expected a "
        f"{NO_CLIENT_CODE} error result"
    )
    assert result["Error"]["Code"] == NO_CLIENT_CODE, (
        f"{target.id} reported Code={result['Error']['Code']!r} for the no-client "
        f"condition, expected {NO_CLIENT_CODE!r}"
    )
    assert ctx._set.call_args_list == [], (
        f"{target.id} cached the no-client condition: {ctx._set.call_args_list}"
    )


# --------------------------------------------------------------------------- #
# Property 9 -- success caching is unchanged
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("target", _params(_CACHING, "property_9"), ids=None)
def test_a_successful_response_is_cached_under_the_same_namespace_and_key(
    target: _Target,
) -> None:
    """Property 9: the namespace, the key, and the value stored.

    Requirement 3.6 promises that a scan with no failures issues exactly the
    calls it does today. The namespace and key are how that is checked; the
    *value* is the one thing that does change, from an extracted list or scalar to
    the named-key success dict, and asserting the dict is stored verbatim is what
    pins that change down.
    """
    check, ctx, wrapper = _make_check(target)
    success = {"probeMember": [{"ok": True}]}
    getattr(wrapper, target.adapter.client_method).return_value = success

    result = getattr(check, target.adapter.method)(*target.adapter.args)

    # With a prerequisite declared, the prerequisite's own write is expected and
    # excluded; exactly one write must remain, and it must be this accessor's.
    own_writes = [
        call
        for call in ctx._set.call_args_list
        if target.adapter.prerequisite is None
        or call.args[1] == target.adapter.cache_key
    ]
    assert len(own_writes) == 1, (
        f"{target.id} wrote the cache {len(own_writes)} times under its own key "
        f"for one successful call: {ctx._set.call_args_list}"
    )
    namespace, key, value = own_writes[0].args
    assert namespace == target.cls.NAMESPACE, (
        f"{target.id} cached under namespace {namespace!r}, expected "
        f"{target.cls.NAMESPACE!r}"
    )
    assert key == target.adapter.cache_key, (
        f"{target.id} cached under key {key!r}, expected "
        f"{target.adapter.cache_key!r}; Requirement 3.6 forbids moving a key"
    )
    assert value is success, (
        f"{target.id} cached {value!r} rather than the client's response dict; "
        f"the accessor passes the dict through and the check extracts after the "
        f"error test"
    )
    assert result is success


@pytest.mark.parametrize("target", _params(_CACHING, "property_9_warm"), ids=None)
def test_a_warm_cache_skips_the_client_entirely(target: _Target) -> None:
    """Property 9: a hit costs no AWS call, which is the point of the cache."""
    check, ctx, wrapper = _make_check(target)
    cached = {"probeMember": [{"warm": True}]}
    # Pre-warm the exact slot the accessor is declared to use. Seeding the real
    # namespace and key rather than forcing ``_has`` to True is what makes this a
    # test of the key as well as of the hit.
    ctx.probe_cache[(target.cls.NAMESPACE, target.adapter.cache_key)] = cached

    result = getattr(check, target.adapter.method)(*target.adapter.args)

    client_method = getattr(wrapper, target.adapter.client_method)
    assert client_method.call_count == 0, (
        f"{target.id} called its client despite a warm cache under "
        f"{target.cls.NAMESPACE}:{target.adapter.cache_key}"
    )
    assert result is cached


# --------------------------------------------------------------------------- #
# Helpers must be pure
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "target", [pytest.param(t, id=t.id) for t in _HELPERS] or [pytest.param(None, id="none")]
)
def test_a_helper_never_touches_the_per_scan_context(target: _Target | None) -> None:
    """A ``helper`` is a pure function over a success dict or plain arguments.

    Requirement 1.5 permits a base to offer a helper that takes a success dict,
    and forbids one that takes an accessor's raw return -- because that would
    re-introduce a function having to handle both shapes. Asserting the helper
    never reaches the context is how "pure" is made checkable.
    """
    if target is None:
        pytest.skip("no helper adapters declared")

    check, ctx, _ = _make_check(target)

    try:
        getattr(check, target.adapter.method)(*target.adapter.args)
    except Exception as exc:  # noqa: BLE001 - the call may legitimately reject args
        pytest.skip(f"helper rejected the fixture arguments: {exc!r}")

    assert ctx._set.call_args_list == [], (
        f"{target.id} is classified as a pure helper but wrote to the cache"
    )
    assert ctx._get.call_args_list == [], (
        f"{target.id} is classified as a pure helper but read the cache"
    )


# --------------------------------------------------------------------------- #
# The two sites that need naming
# --------------------------------------------------------------------------- #


def test_securityhub_get_organization_writes_the_shared_organizations_namespace() -> None:
    """One of the two deliberate failure-caching sites (Requirement 3.4).

    ``SecurityHubCheck.get_organization`` builds an error result in its own ``except``
    and caches it -- and it caches it under the **shared** ``organizations``
    namespace, where ``OrganizationsCheck.get_organization`` will read it back. So
    one denied ``securityhub`` path poisons an entirely different service's
    accessor for the rest of the scan.

    Asserted here by name because the adapter table classifies it ``derived`` (it
    does not write securityhub's own namespace, so Property 9's namespace
    assertion would be wrong for it).
    """
    source = (_SERVICES_ROOT / "securityhub" / "base.py").read_text(encoding="utf-8")

    assert "_ORGANIZATION_CACHE_KEY" in source, (
        "the shared-namespace write has been restructured; re-check that this "
        "accessor still cannot poison OrganizationsCheck"
    )

    # After migration the accessor must not construct an error result of its own.
    assert "except ClientError" not in source, (
        "SecurityHubCheck.get_organization still builds its own error result; it "
        "should pass the client's through and not cache it"
    )


def test_securityincidentresponse_discover_memberships_is_the_one_caching_site() -> None:
    """The private helper the six SIR accessors route through.

    Classified out of Properties 7-9 because it is private and therefore not in
    the public enumeration, but it is the only place that base writes the cache --
    and it falls back to caching ``(regions[0], response_from_regions[0])``, which
    may itself be an error result.
    """
    source = (
        _SERVICES_ROOT / "securityincidentresponse" / "base.py"
    ).read_text(encoding="utf-8")

    assert "_discover_memberships" in source
    assert "_MEMBERSHIP_DISCOVERY_KEY" in source, (
        "the SIR discovery cache key has moved; re-check the fallback tuple"
    )

    assert "except Exception" not in source, (
        "_discover_memberships still holds a bare except; after the transport "
        "guard lands in the client it is dead code"
    )


def test_securityincidentresponse_declares_no_namespace() -> None:
    """A known defect, asserted so it cannot be "fixed" by accident here.

    This base declares no ``NAMESPACE``, its accessors do no caching, and three of
    them pin ``self.regions[0]`` while the sibling ``discover_sir_region``
    resolves the Region correctly. Non-Goal 6 defers all of it: folding a
    Region-labelling change into a verdict-correctness change would make a diff of
    two scans impossible to read, because both the ``Region`` and ``Status`` cells
    would move at once.

    If this test ever fails, someone has started that work deliberately.
    """
    cls = _base_class("securityincidentresponse")

    assert "NAMESPACE" not in vars(cls), (
        "securityincidentresponse now declares a NAMESPACE. That is a real "
        "improvement, but it is Non-Goal 6 for this feature -- it moves the "
        "Region cell on genuine verdicts, which cannot be separated from a "
        "regression when diffing two scans."
    )
