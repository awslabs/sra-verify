"""
Property-based test harness for the service-base-class migration (task 7.1).

This module implements **Property 8: Migrated service base classes have no
cache attrs and route through ctx**, which validates Requirements 5.1 through
5.18 of the scan-context-refactor spec.

For each of the 17 service base classes (``GuardDutyCheck``, ``CloudTrailCheck``,
``AccessAnalyzerCheck``, ``ConfigCheck``, ``SecurityHubCheck``, ``S3Check``,
``InspectorCheck``, ``EC2Check``, ``MacieCheck``, ``ShieldCheck``,
``AccountCheck``, ``AuditManagerCheck``, ``FirewallManagerCheck``,
``SecurityLakeCheck``, ``OrganizationsCheck``, ``IAMCheck``, ``WAFCheck``),
this harness asserts three structural invariants that must hold *after* the
class has been migrated to use the per-scan ``ScanContext``:

  (a) None of the documented removed cache attribute names exists as a class
      attribute on the migrated class.
  (b) None of the documented removed cache attribute names exists as an
      instance attribute on a default-constructed instance (this is the
      relevant assertion for ``WAFCheck``, which today initialises 9
      instance-level cache dicts in ``__init__``).
  (c) Calling a representative typed method on the migrated class -- with a
      mocked ``ScanContext`` and a mocked service-level client wrapper --
      results in at least one ``ctx._set`` call whose ``namespace`` argument
      equals the documented namespace string for that service.

The harness is intentionally created up front, before any of the 17 service
base classes has been migrated, so that each migration in tasks 8.1 - 8.17
runs against this test as its acceptance check. Until a service is migrated
its row is marked ``xfail``, which keeps the harness landing in CI without
blocking on un-migrated services. As each task 8.x lands, drop the
corresponding ``xfail`` marker so the row participates as a hard
correctness check.

Feature: scan-context-refactor, Property 8: Migrated service base classes
have no cache attrs and route through ctx.

**Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 5.10,
5.11, 5.12, 5.13, 5.14, 5.15, 5.16, 5.17, 5.18**
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, List, Tuple
from unittest.mock import MagicMock

import pytest

from sraverify.core.scan_context import ScanContext
from sraverify.services.accessanalyzer.base import AccessAnalyzerCheck
from sraverify.services.account.base import AccountCheck
from sraverify.services.auditmanager.base import AuditManagerCheck
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.services.config.base import ConfigCheck
from sraverify.services.ec2.base import EC2Check
from sraverify.services.firewallmanager.base import FirewallManagerCheck
from sraverify.services.guardduty.base import GuardDutyCheck
from sraverify.services.iam.base import IAMCheck
from sraverify.services.inspector.base import InspectorCheck
from sraverify.services.macie.base import MacieCheck
from sraverify.services.organizations.base import OrganizationsCheck
from sraverify.services.s3.base import S3Check
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.services.shield.base import ShieldCheck
from sraverify.services.waf.base import WAFCheck


# --------------------------------------------------------------------------- #
# ScanContext mock factory
# --------------------------------------------------------------------------- #
#
# Every (c) test starts from a fresh ``ScanContext`` mock built here. The mock
# is shaped to look enough like a real ``ScanContext`` that a migrated service
# base class running through one of its typed methods can:
#   - read ``ctx.regions`` (a single-region list keeps loops short),
#   - call ``ctx._has`` and have it return ``False`` so the typed method
#     takes the cache-miss path that performs the write we want to observe,
#   - call ``ctx._get`` (returns the supplied ``default`` when given one,
#     otherwise ``None``),
#   - call ``ctx._set`` (the call we are asserting on),
#   - call ``ctx.get_account_info`` / ``get_management_account_id`` /
#     ``get_enabled_regions`` / ``get_client`` and receive plausible values.


def _make_mock_ctx(region: str = "us-east-1") -> MagicMock:
    """Build a ``MagicMock`` shaped like a fresh ``ScanContext``.

    The mock is used by the (c) sub-test to drive a migrated service's
    canonical typed method without touching real AWS. The defaults are chosen
    so the cache-miss path is taken on every call:

      - ``_has`` returns ``False`` -> typed method falls through to the AWS /
        cache-write branch.
      - ``_get`` returns the supplied ``default`` (or ``None``) -> typed
        method does not believe a previous write exists.
      - ``regions``, ``audit_accounts``, ``log_archive_accounts`` are concrete
        lists so service base classes that iterate them don't blow up.
      - ``get_account_info`` returns a dict the way the real API does so
        ``check.account_id`` resolves cleanly when service base classes use
        it as part of a cache key.
    """
    ctx = MagicMock(spec=ScanContext)
    ctx.regions = [region]
    ctx.audit_accounts = []
    ctx.log_archive_accounts = []
    ctx.session = MagicMock(name="boto3_session")
    ctx.session.region_name = region
    ctx.client_config = MagicMock(name="client_config")

    # Cache primitives: always miss so the typed method writes through to
    # ``_set`` (the call we are asserting on).
    ctx._has.return_value = False

    def _get_default(namespace, key, default=None):  # noqa: ARG001 - mock signature
        return default

    ctx._get.side_effect = _get_default

    # Lazy typed accessors: return realistic stand-ins. Service base classes
    # that resolve ``self.account_id`` / ``self.account_name`` on the way to
    # writing a cache key go through these.
    ctx.get_account_info.return_value = {
        "account_id": "111111111111",
        "account_name": "test-account",
    }
    ctx.get_management_account_id.return_value = "111111111111"
    ctx.get_enabled_regions.return_value = [region]

    # Boto3 client cache: whatever a service base class asks for, hand back a
    # ``MagicMock`` so the call doesn't raise. Service-level *wrapper* mocks
    # are installed by the per-row ``invoke`` callable; this fallback exists
    # only to keep paths that go through ``ctx.get_client`` directly safe.
    ctx.get_client.return_value = MagicMock(name="boto3_client")

    return ctx


# --------------------------------------------------------------------------- #
# Per-service "invoke canonical method" callables
# --------------------------------------------------------------------------- #
#
# Each migrated service's typed methods read different inputs and call
# different methods on their service-level wrapper. To keep the parameterized
# test simple, we put a small per-service "invoke" function in the row table
# that:
#   1. Installs a ``MagicMock`` wrapper into ``check._clients[<region>]`` so
#      ``check.get_client(region)`` returns it when the typed method asks.
#   2. Configures the wrapper's relevant return values so the typed method
#      reaches its cache-write branch (rather than short-circuiting on an
#      empty / error response and never calling ``ctx._set``).
#   3. Calls the typed method with arguments that hit the documented cache
#      key shape for that service.
#
# Each function takes the already-initialised ``check`` (with mock ``ctx``
# attached) and returns nothing; the assertion on ``ctx._set`` happens in the
# generic test body.


_REGION = "us-east-1"


def _invoke_guardduty(check: GuardDutyCheck) -> None:
    wrapper = MagicMock(name="GuardDutyClient")
    wrapper.get_detector_id.return_value = "detector-abc"
    check._clients[_REGION] = wrapper
    check.get_detector_id(_REGION)


def _invoke_cloudtrail(check: CloudTrailCheck) -> None:
    wrapper = MagicMock(name="CloudTrailClient")
    wrapper.describe_trails.return_value = [{"Name": "trail-1"}]
    check._clients[_REGION] = wrapper
    check.describe_trails()


def _invoke_accessanalyzer(check: AccessAnalyzerCheck) -> None:
    wrapper = MagicMock(name="AccessAnalyzerClient")
    wrapper.list_analyzers.return_value = [{"name": "analyzer-1"}]
    check._clients[_REGION] = wrapper
    check.get_analyzers(_REGION)


def _invoke_config(check: ConfigCheck) -> None:
    wrapper = MagicMock(name="ConfigClient")
    wrapper.describe_configuration_recorder_status.return_value = [
        {"name": "recorder-1", "recording": True}
    ]
    check._clients[_REGION] = wrapper
    check.get_configuration_recorder_status(_REGION)


def _invoke_securityhub(check: SecurityHubCheck) -> None:
    wrapper = MagicMock(name="SecurityHubClient")
    wrapper.get_enabled_standards.return_value = [
        {"StandardsArn": "arn:aws:securityhub:::standards/aws-foundational"}
    ]
    check._clients[_REGION] = wrapper
    check.get_enabled_standards(_REGION)


def _invoke_s3(check: S3Check) -> None:
    wrapper = MagicMock(name="S3Client")
    wrapper.get_public_access_block_configuration.return_value = {
        "BlockPublicAcls": True
    }
    check._clients[_REGION] = wrapper
    check.get_public_access()


def _invoke_inspector(check: InspectorCheck) -> None:
    wrapper = MagicMock(name="InspectorClient")
    wrapper.batch_get_account_status.return_value = {
        "accounts": [
            {
                "accountId": "111111111111",
                "state": {"status": "ENABLED"},
                "resourceState": {
                    "ec2": {"status": "ENABLED"},
                    "ecr": {"status": "ENABLED"},
                    "lambda": {"status": "ENABLED"},
                    "lambdaCode": {"status": "ENABLED"},
                },
            }
        ]
    }
    check._clients[_REGION] = wrapper
    check.get_account_status(_REGION)


def _invoke_ec2(check: EC2Check) -> None:
    wrapper = MagicMock(name="EC2Client")
    wrapper.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": True}
    check._clients[_REGION] = wrapper
    check.get_ebs_encryption_by_default(_REGION)


def _invoke_macie(check: MacieCheck) -> None:
    wrapper = MagicMock(name="MacieClient")
    wrapper.get_findings_publication_configuration.return_value = {
        "publishPolicyFindings": True
    }
    check._clients[_REGION] = wrapper
    check.get_findings_publication_configuration(_REGION)


def _invoke_shield(check: ShieldCheck) -> None:
    wrapper = MagicMock(name="ShieldClient")
    wrapper.get_subscription_state.return_value = {"SubscriptionState": "ACTIVE"}
    check._clients[_REGION] = wrapper
    check.get_subscription_state(_REGION)


def _invoke_account(check: AccountCheck) -> None:
    wrapper = MagicMock(name="AccountClient")
    wrapper.get_alternate_contact.return_value = {
        "Name": "Sec Ops",
        "EmailAddress": "ops@example.com",
    }
    check._clients[_REGION] = wrapper
    check.get_alternate_contact(_REGION, "SECURITY")


def _invoke_auditmanager(check: AuditManagerCheck) -> None:
    wrapper = MagicMock(name="AuditManagerClient")
    wrapper.get_account_status.return_value = {"status": "ACTIVE"}
    check._clients[_REGION] = wrapper
    check.get_account_status(_REGION)


def _invoke_firewallmanager(check: FirewallManagerCheck) -> None:
    wrapper = MagicMock(name="FirewallManagerClient")
    wrapper.get_admin_account.return_value = {"AdminAccount": "111111111111"}
    # FirewallManager pins admin APIs to us-east-1 in its _setup_clients;
    # match that here so the typed method finds its wrapper.
    check._clients["us-east-1"] = wrapper
    check.get_admin_account()


def _invoke_securitylake(check: SecurityLakeCheck) -> None:
    wrapper = MagicMock(name="SecurityLakeClient")
    wrapper.list_subscribers.return_value = [{"subscriberId": "sub-1"}]
    check._clients[_REGION] = wrapper
    check.get_subscribers(_REGION)


def _invoke_organizations(check: OrganizationsCheck) -> None:
    # Organizations is a global service: the migrated base class will hold a
    # single client (likely on ``check._org_client`` or via
    # ``ctx.get_client('organizations')``). We populate both surfaces so the
    # typed method finds its client whichever shape it ends up using.
    org_client = MagicMock(name="OrganizationsClient")
    org_client.describe_organization.return_value = {
        "Organization": {
            "Id": "o-abc",
            "MasterAccountId": "111111111111",
        }
    }
    check._org_client = org_client
    # If the migrated implementation uses ctx.get_client instead, the mock
    # ctx already returns a MagicMock that will accept any method call.
    check.get_organization()


def _invoke_iam(check: IAMCheck) -> None:
    iam_client = MagicMock(name="IAMClient")
    iam_client.list_users.return_value = {"Users": [{"UserName": "u1"}]}
    check._iam_client = iam_client
    check.list_users()


def _invoke_waf(check: WAFCheck) -> None:
    wrapper = MagicMock(name="WAFClient")
    wrapper.describe_load_balancers.return_value = {
        "LoadBalancers": [{"LoadBalancerArn": "arn:aws:elb:..."}]
    }
    check._clients[_REGION] = wrapper
    check.get_load_balancers(_REGION)


# --------------------------------------------------------------------------- #
# MIGRATED_SERVICES table - the canonical definition of "what migration means"
# --------------------------------------------------------------------------- #
#
# Each row binds together:
#   - the service base class,
#   - the namespace string the migrated implementation must use when calling
#     ``ctx._set(namespace, ...)``,
#   - the cache attribute names that must be removed from the class
#     (``removed_class_attrs``) and from a default-constructed instance
#     (``removed_instance_attrs`` -- empty for everything except ``WAFCheck``,
#     where ``__init__`` currently assigns 9 instance-level cache dicts),
#   - a small ``invoke`` callable that drives one canonical typed method end
#     to end so the ``ctx._set`` assertion in (c) has something to check.
#
# Until a service migrates, its row is marked ``xfail``: assertions (a) and
# (b) will fail (the class still holds its cache dicts) and assertion (c)
# will fail (the un-migrated typed method writes to its own ``_*_cache``
# rather than calling ``ctx._set``). Once the corresponding task 8.x lands,
# drop the ``xfail`` marker so the row becomes a hard correctness check.


@dataclass(frozen=True)
class ServiceRow:
    """One row of the migrated-services table.

    Attributes:
        cls: The service base class under test.
        namespace: The namespace string the migrated class must use in
            ``ctx._set(...)`` calls (Requirements 5.1 - 5.17).
        removed_class_attrs: Cache attribute names that must NOT exist as
            class attributes on the migrated class (Requirement 5.18).
        removed_instance_attrs: Cache attribute names that must NOT exist
            as instance attributes on a default-constructed instance.
            Non-empty only for ``WAFCheck`` per Requirement 5.17.
        invoke_canonical: Callable that takes a check instance with a mock
            ``ctx`` already attached, sets up a service-level wrapper mock,
            and invokes one representative typed method that should call
            ``ctx._set(<namespace>, ...)`` exactly once.
        task_id: The ``8.x`` task that lands this migration (used in the
            ``xfail`` reason and in the test id).
    """

    cls: type
    namespace: str
    removed_class_attrs: Tuple[str, ...]
    removed_instance_attrs: Tuple[str, ...]
    invoke_canonical: Callable[[Any], None] = field(repr=False)
    task_id: str

    @property
    def display_name(self) -> str:
        return self.cls.__name__


MIGRATED_SERVICES: List[ServiceRow] = [
    # Requirement 5.1: GuardDutyCheck -> "guardduty"
    ServiceRow(
        cls=GuardDutyCheck,
        namespace="guardduty",
        removed_class_attrs=(
            "_detector_details_cache",
            "_detector_ids_cache",
            "_org_config_cache",
            "_admin_accounts_cache",
        ),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_guardduty,
        task_id="8.1",
    ),
    # Requirement 5.2: CloudTrailCheck -> "cloudtrail"
    ServiceRow(
        cls=CloudTrailCheck,
        namespace="cloudtrail",
        removed_class_attrs=(
            "_describe_trails_cache",
            "_trail_status_cache",
            "_delegated_admin_account_id_cache",
        ),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_cloudtrail,
        task_id="8.2",
    ),
    # Requirement 5.3: AccessAnalyzerCheck -> "accessanalyzer"
    ServiceRow(
        cls=AccessAnalyzerCheck,
        namespace="accessanalyzer",
        removed_class_attrs=(
            "_delegated_admin_cache",
            "_analyzer_cache",
        ),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_accessanalyzer,
        task_id="8.3",
    ),
    # Requirement 5.4: ConfigCheck -> "config"
    ServiceRow(
        cls=ConfigCheck,
        namespace="config",
        removed_class_attrs=(
            "_config_recorder_status_cache",
            "_config_delivery_channel_status_cache",
            "_config_organization_aggregator",
            "_config_delivery_channel_cache",
            "_config_delegated_admin_cache",
        ),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_config,
        task_id="8.4",
    ),
    # Requirement 5.5: SecurityHubCheck -> "securityhub"
    ServiceRow(
        cls=SecurityHubCheck,
        namespace="securityhub",
        removed_class_attrs=(
            "_enabled_standards_cache",
            "_admin_account_cache",
            "_organization_configuration_cache",
            "_product_integrations_cache",
            "_delegated_admin_cache",
            "_organization_accounts_cache",
            "_securityhub_members_cache",
        ),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_securityhub,
        task_id="8.5",
    ),
    # Requirement 5.6: S3Check -> "s3"
    ServiceRow(
        cls=S3Check,
        namespace="s3",
        removed_class_attrs=("_public_access_cache",),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_s3,
        task_id="8.6",
    ),
    # Requirement 5.7: InspectorCheck -> "inspector"
    ServiceRow(
        cls=InspectorCheck,
        namespace="inspector",
        removed_class_attrs=(
            "_inspector_account_status",
            "_inspector_batch_account_status",
            "_inspector_delegated_admin",
            "_inspector_org_config",
            "_organization_members",
        ),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_inspector,
        task_id="8.7",
    ),
    # Requirement 5.8: EC2Check -> "ec2"
    ServiceRow(
        cls=EC2Check,
        namespace="ec2",
        removed_class_attrs=("_ebs_encryption_default_cache",),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_ec2,
        task_id="8.8",
    ),
    # Requirement 5.9: MacieCheck -> "macie"
    ServiceRow(
        cls=MacieCheck,
        namespace="macie",
        removed_class_attrs=(
            "_findings_publication_cache",
            "_export_configuration_cache",
            "_macie_delegated_admin_cache",
            "_macie_members_cache",
            "_org_members_cache",
            "_auto_enable_cache",
        ),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_macie,
        task_id="8.9",
    ),
    # Requirement 5.10: ShieldCheck -> "shield"
    ServiceRow(
        cls=ShieldCheck,
        namespace="shield",
        removed_class_attrs=("_subscription_cache",),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_shield,
        task_id="8.10",
    ),
    # Requirement 5.11: AccountCheck -> "account"
    ServiceRow(
        cls=AccountCheck,
        namespace="account",
        removed_class_attrs=("_contact_cache",),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_account,
        task_id="8.11",
    ),
    # Requirement 5.12: AuditManagerCheck -> "auditmanager"
    ServiceRow(
        cls=AuditManagerCheck,
        namespace="auditmanager",
        removed_class_attrs=("_account_status_cache",),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_auditmanager,
        task_id="8.12",
    ),
    # Requirement 5.13: FirewallManagerCheck -> "firewallmanager"
    ServiceRow(
        cls=FirewallManagerCheck,
        namespace="firewallmanager",
        removed_class_attrs=(
            "_admin_account_cache",
            "_policies_cache",
        ),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_firewallmanager,
        task_id="8.13",
    ),
    # Requirement 5.14: SecurityLakeCheck -> "securitylake"
    ServiceRow(
        cls=SecurityLakeCheck,
        namespace="securitylake",
        removed_class_attrs=(
            "_subscribers_cache",
            "_security_lake_status_cache",
            "_organization_configuration_cache",
            "_delegated_admin_cache",
            "_organization_accounts_cache",
            "_log_sources_cache",
            "_sqs_encryption_cache",
        ),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_securitylake,
        task_id="8.14",
    ),
    # Requirement 5.15: OrganizationsCheck -> "organizations"
    ServiceRow(
        cls=OrganizationsCheck,
        namespace="organizations",
        removed_class_attrs=(
            "_organization_cache",
            "_roots_cache",
            "_ous_cache",
            "_policies_cache",
            "_accounts_cache",
        ),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_organizations,
        task_id="8.15",
    ),
    # Requirement 5.16: IAMCheck -> "iam"
    ServiceRow(
        cls=IAMCheck,
        namespace="iam",
        removed_class_attrs=("_users_cache",),
        removed_instance_attrs=(),
        invoke_canonical=_invoke_iam,
        task_id="8.16",
    ),
    # Requirement 5.17: WAFCheck -> "waf"
    # WAF is the only service whose caches live on the *instance* (assigned
    # in ``__init__``) rather than the class, so its row is the only one
    # with a non-empty ``removed_instance_attrs`` list.
    ServiceRow(
        cls=WAFCheck,
        namespace="waf",
        removed_class_attrs=(
            "_distributions_cache",
            "_load_balancers_cache",
            "_rest_apis_cache",
            "_graphql_apis_cache",
            "_user_pools_cache",
            "_apprunner_services_cache",
            "_verified_access_instances_cache",
            "_amplify_apps_cache",
            "_web_acls_cache",
        ),
        removed_instance_attrs=(
            "_distributions_cache",
            "_load_balancers_cache",
            "_rest_apis_cache",
            "_graphql_apis_cache",
            "_user_pools_cache",
            "_apprunner_services_cache",
            "_verified_access_instances_cache",
            "_amplify_apps_cache",
            "_web_acls_cache",
        ),
        invoke_canonical=_invoke_waf,
        task_id="8.17",
    ),
]


# --------------------------------------------------------------------------- #
# Pytest parameter list with per-row xfail markers
# --------------------------------------------------------------------------- #
#
# Wrap each row in ``pytest.param`` so we can attach a ``pytest.mark.xfail``
# marker keyed on the corresponding ``8.x`` task. This keeps the harness
# importable and runnable today (with un-migrated rows xfailing) while making
# each service migration's "flip xfail off" diff a one-line change.


# Task IDs whose migrations have landed and whose rows should participate as
# hard correctness checks (no ``xfail`` marker). As each 8.x task lands, add
# its task id here and the corresponding row stops being expected to fail.
MIGRATED_TASK_IDS: set = {"8.1", "8.2", "8.3", "8.4", "8.5", "8.6", "8.7", "8.8", "8.9", "8.10", "8.11", "8.12", "8.13", "8.14", "8.15", "8.16", "8.17"}


def _service_params() -> List[Any]:
    """Return the parameter list for the (a)/(b)/(c) tests, with xfail markers.

    Each row is wrapped in ``pytest.param``. Rows whose ``task_id`` is in
    ``MIGRATED_TASK_IDS`` participate as hard correctness checks; every other
    row is tagged with an ``xfail`` marker referencing the ``8.x`` task that
    will land its migration.
    """
    params = []
    for row in MIGRATED_SERVICES:
        if row.task_id in MIGRATED_TASK_IDS:
            params.append(pytest.param(row, id=row.display_name))
        else:
            params.append(
                pytest.param(
                    row,
                    id=row.display_name,
                    marks=pytest.mark.xfail(
                        reason=(
                            f"awaits task {row.task_id} migration of "
                            f"{row.display_name} to ScanContext namespace "
                            f"{row.namespace!r}"
                        ),
                        strict=False,
                    ),
                )
            )
    return params


SERVICE_PARAMS = _service_params()


# --------------------------------------------------------------------------- #
# (a) No class-level cache attributes
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("row", SERVICE_PARAMS)
def test_no_class_level_cache_attrs(row: ServiceRow) -> None:
    """Property 8 (a): the migrated class must not carry the documented cache attrs.

    For every name in ``row.removed_class_attrs``, ``getattr(row.cls, name,
    None)`` must be ``None`` (or the attribute simply not exist). The
    ``getattr(..., None)`` shape lets us distinguish "attribute removed" from
    "attribute still present and explicitly set to ``None``".

    Validates: Requirements 5.1 - 5.17 (per-service removal), 5.18 (the
    cumulative "no class-level or instance-level cache dict variables on any
    migrated service base class" rule).
    """
    leftover = [
        name for name in row.removed_class_attrs if name in vars(row.cls)
    ]
    assert leftover == [], (
        f"{row.display_name} still has class-level cache attribute(s) "
        f"{leftover!r}; migration to ScanContext namespace "
        f"{row.namespace!r} must remove them (Requirement 5.18)."
    )


# --------------------------------------------------------------------------- #
# (b) No instance-level cache attributes on a fresh instance
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("row", SERVICE_PARAMS)
def test_no_instance_level_cache_attrs(row: ServiceRow) -> None:
    """Property 8 (b): a default-constructed instance must not carry the documented cache attrs.

    Today's ``WAFCheck.__init__`` assigns 9 instance-level cache dicts;
    migration (task 8.17) drops them. For all other services the
    ``removed_instance_attrs`` tuple is empty so this assertion is a no-op
    that still keeps a row in the parameterised test for symmetry.

    Validates: Requirement 5.17 (the WAF instance-level cache dicts must be
    removed from ``__init__``).
    """
    instance = row.cls()
    leftover = [
        name for name in row.removed_instance_attrs if name in vars(instance)
    ]
    assert leftover == [], (
        f"{row.display_name}() instance still has instance-level cache "
        f"attribute(s) {leftover!r}; migration to ScanContext namespace "
        f"{row.namespace!r} must remove the assignments from __init__ "
        f"(Requirement 5.17)."
    )


# --------------------------------------------------------------------------- #
# (c) Canonical typed method routes through ``ctx._set``
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("row", SERVICE_PARAMS)
def test_canonical_method_routes_through_ctx_set(row: ServiceRow) -> None:
    """Property 8 (c): a canonical typed method writes via ``ctx._set(<namespace>, ...)``.

    Builds a fresh check instance, attaches a ``MagicMock`` ``ScanContext``,
    and runs one representative typed method per service. Each typed method
    is expected to take its cache-miss branch (because ``ctx._has`` is mocked
    to return ``False``) and end with a ``ctx._set(<namespace>, <key>,
    <value>)`` call that records the AWS response under the documented
    namespace.

    The assertion is "at least one ``_set`` call whose first positional
    argument equals ``row.namespace``". We deliberately do not assert on the
    cache key or value: those are service-internal and the design's "Cache
    key conventions" section describes them as service-owned, so the harness
    only validates the namespace.

    Validates: Requirements 5.1 - 5.17 (per-service namespace), 6.1 (the
    namespaced primitives are how cached data is written), and indirectly
    Requirement 6.3 (no individual check class is involved here -- only the
    service base class is).
    """
    check = row.cls()
    mock_ctx = _make_mock_ctx(region=_REGION)
    check._ctx = mock_ctx
    # Service base classes may populate ``self._clients`` lazily in
    # ``_setup_clients``. The per-row ``invoke`` callable installs the
    # specific wrapper(s) it needs, so we deliberately do *not* call
    # ``check._setup_clients()`` here -- that path constructs real service
    # clients which require a real session.

    row.invoke_canonical(check)

    # Pull every ``_set`` call's first positional argument (the namespace).
    set_namespaces = [call.args[0] for call in mock_ctx._set.call_args_list if call.args]
    assert row.namespace in set_namespaces, (
        f"{row.display_name} did not call ctx._set with namespace "
        f"{row.namespace!r} during {row.invoke_canonical.__name__}; "
        f"observed _set calls: {mock_ctx._set.call_args_list!r}"
    )
