"""
Properties 1, 2, 3, 3a, 4, and 6: the client contract, over every client method.

Every ``<Service>Client`` method must return a dict on every non-raising path --
a named-key success dict, or ``{"Error": {"Code", "Message", "Operation"}}`` --
and must let a programming defect propagate. This module holds that for all 92
methods across the 18 clients, enumerated by reflection so a method added later
is covered without a second edit.

**This module is what makes plain ``try``/``except`` safe to repeat.** Each client
method writes its own two-clause handler by hand rather than going through a
shared guard -- a deliberate choice, so a reader of ``client.py`` sees the error
handling at the call site. The cost is 92 copies of the same idiom, and the
historical failure mode of 92 copies is drift: some catching only
``ClientError``, some using ``str(e)``, some returning ``[]``. Properties 1-4
close that by *running* every method through every failure kind, and the static
Property 6 tests read each ``except`` clause and require it to be exactly
``except AWS_EXCEPTIONS as e: return self.aws_error(e)``. A method that drifts in
either direction fails here, not in a scan.

**Why adapters, and why not placeholders.** A first instinct is to call every
method with ``"arg"`` for each parameter and have every boto3 call return ``{}``.
That cannot work against this tree: ``ShieldClient.get_web_acl_for_resource``
branches on whether the ARN contains ``cloudfront``,
``ConfigClient.get_bucket_location`` maps a ``None`` member to ``us-east-1``,
``InspectorClient.batch_get_account_status`` takes a list, several methods index a
required response member, and eight methods paginate. Placeholder inputs would
fail for *harness* reasons, and a harness failure is indistinguishable from a
contract violation -- worse, it can produce an error result and read as a pass.

So each method has an adapter declaring how to drive it. The adapter table is
fixture data, not the enumeration: Property 3a asserts the adapter set equals the
reflected set **in both directions**, so a new method without an adapter fails and
an adapter for a deleted method fails.

**Why the mock is keyed by boto3 service id.** Every client acquires its
underlying boto3 clients through ``ctx.get_client('<service id>', ...)`` --
``WAFClient`` holds nine, ``ShieldClient`` five. Keying the mocks by service id
rather than by attribute name means the harness works unchanged across the
migration: Requirement 1.11 moves eight acquisitions from a method body into
``__init__``, which changes *where* the call happens but not which service id it
asks for.

Validates: Requirements 1.1-1.12, 2.1, 2.2, 2.3, 2.6, 5.9, 7.1, 7.2, 7.3, 7.4,
7.4a, 7.10, 7.11.
"""
from __future__ import annotations

import ast
import importlib
import inspect
import logging
import pkgutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Mapping
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
)

import sraverify.services
from sraverify.core.aws_errors import UNKNOWN_OPERATION, is_error
from sraverify.core.scan_context import ScanContext

_SERVICES_ROOT: Path = Path(sraverify.services.__file__).resolve().parent

_TEST_REGION = "us-east-1"
_TEST_ACCOUNT = "111122223333"


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


def _service_names() -> list[str]:
    """Return every service package name under ``services/``, sorted.

    Returns:
        e.g. ``["accessanalyzer", "account", ...]``.
    """
    return sorted(
        module.name
        for module in pkgutil.iter_modules([str(_SERVICES_ROOT)])
        if module.ispkg
    )


def _client_classes(service: str) -> list[type]:
    """Return the ``*Client`` classes declared in a service's ``client`` module.

    Filtered to classes whose ``__module__`` is that module, so an imported name
    is not mistaken for a declaration. The name test is a suffix rather than
    ``f"{Service}Client"`` because ``iam`` declares ``IAM_Client``.

    Args:
        service: A service package name.

    Returns:
        The declared client classes.
    """
    module = importlib.import_module(f"sraverify.services.{service}.client")
    return [
        obj
        for name, obj in vars(module).items()
        if inspect.isclass(obj)
        and name.endswith("Client")
        and obj.__module__ == module.__name__
    ]


def _public_methods(cls: type) -> list[str]:
    """Return the class's own public method names, sorted.

    ``vars(cls)`` rather than ``dir(cls)``: the class's own dict, so nothing
    inherited is counted and the adapter table stays a statement about this
    class.

    Args:
        cls: The class to inspect.

    Returns:
        Sorted method names not beginning with an underscore.
    """
    return sorted(
        name
        for name, obj in vars(cls).items()
        if not name.startswith("_")
        and (inspect.isfunction(obj) or isinstance(obj, staticmethod))
    )


# --------------------------------------------------------------------------- #
# The adapter
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ClientAdapter:
    """How to drive one client method, and what to expect back.

    Attributes:
        method: The wrapper method name.
        boto_service: The boto3 service id the method's call goes to, as passed
            to ``ctx.get_client``. Keyed by service id rather than by attribute
            name so the harness survives Requirement 1.11 moving an acquisition
            from a method body into ``__init__``.
        boto_method: The boto3 method the wrapper calls.
        operation: The AWS operation name this method's call reaches. The harness
            sets it on the ``ClientError`` it raises, then asserts the error result
            carried it back -- so what is checked is that the client propagates
            botocore's ``operation_name`` rather than substituting anything of
            its own. On the ``BotoCoreError`` paths the expected value is
            ``UNKNOWN_OPERATION`` instead, because nothing was sent.
        args: Positional arguments to call the wrapper with. Real values, because
            several methods branch on them.
        success: The boto3 response to return on the success path. A ``tuple``
            means paginator pages, configured through
            ``get_paginator(...).paginate()``.
        paginated: Whether the method reaches the API through a paginator.
    """

    method: str
    boto_service: str
    boto_method: str
    operation: str
    args: tuple = ()
    success: Any = field(default_factory=dict)
    paginated: bool = False


# --------------------------------------------------------------------------- #
# The tables -- one per service, all 18, written against the current signatures.
#
# ``success`` is the boto3 response the method *reads*, which the migration does
# not change: it changes what the wrapper returns, not what AWS sends.
# --------------------------------------------------------------------------- #

_ACCESSANALYZER = (
    ClientAdapter(
        method="get_analyzer_details",
        boto_service="accessanalyzer",
        boto_method="get_analyzer",
        operation="GetAnalyzer",
        args=(f"arn:aws:access-analyzer:us-east-1:{_TEST_ACCOUNT}:analyzer/org",),
        success={"analyzer": {"name": "org", "type": "ORGANIZATION"}},
    ),
    ClientAdapter(
        method="get_delegated_admin",
        boto_service="organizations",
        boto_method="list_delegated_administrators",
        operation="ListDelegatedAdministrators",
        success={"DelegatedAdministrators": [{"Id": _TEST_ACCOUNT}]},
    ),
    # Requirement 1.7's probe was here: a bare bool on the success path, so it had
    # nowhere to carry an error result and its failure path was always erasing.
    # **Deleted**, not converted -- accessanalyzer has an endpoint in
    # 34 of 34 Regions, so the probe could never legitimately answer no. Its only
    # effects were an API call per Region and turning a transport blip into a
    # silent skip of that Region.
    ClientAdapter(
        method="list_analyzers",
        boto_service="accessanalyzer",
        boto_method="list_analyzers",
        operation="ListAnalyzers",
        success=({"analyzers": [{"name": "org", "type": "ORGANIZATION"}]},),
        paginated=True,
    ),
)

_ACCOUNT = (
    ClientAdapter(
        method="get_alternate_contact",
        boto_service="account",
        boto_method="get_alternate_contact",
        operation="GetAlternateContact",
        args=("SECURITY",),
        success={
            "AlternateContact": {
                "EmailAddress": "security@example.com",
                "Name": "Security",
            }
        },
    ),
)

_AUDITMANAGER = (
    ClientAdapter(
        method="get_account_status",
        boto_service="auditmanager",
        boto_method="get_account_status",
        operation="GetAccountStatus",
        success={"status": "ACTIVE"},
    ),
    ClientAdapter(
        method="get_organization_admin_account",
        boto_service="auditmanager",
        boto_method="get_organization_admin_account",
        operation="GetOrganizationAdminAccount",
        success={"adminAccountId": _TEST_ACCOUNT, "organizationId": "o-abc123"},
    ),
)

_CLOUDTRAIL = (
    ClientAdapter(
        method="describe_trails",
        boto_service="cloudtrail",
        boto_method="describe_trails",
        operation="DescribeTrails",
        success={"trailList": [{"Name": "org-trail", "IsMultiRegionTrail": True}]},
    ),
    # Requirement 1.11: acquires sts inside the method body today; moves to
    # __init__. The harness is unaffected either way because both
    # acquire through ctx.get_client("sts", ...).
    ClientAdapter(
        method="get_account_id",
        boto_service="sts",
        boto_method="get_caller_identity",
        operation="GetCallerIdentity",
        success={"Account": _TEST_ACCOUNT},
    ),
    ClientAdapter(
        method="get_trail_status",
        boto_service="cloudtrail",
        boto_method="get_trail_status",
        operation="GetTrailStatus",
        args=(f"arn:aws:cloudtrail:us-east-1:{_TEST_ACCOUNT}:trail/org-trail",),
        success={"IsLogging": True, "LatestDeliveryTime": "2026-09-12T18:00:00Z"},
    ),
    ClientAdapter(
        method="list_delegated_administrators",
        boto_service="organizations",
        boto_method="list_delegated_administrators",
        operation="ListDelegatedAdministrators",
        success={"DelegatedAdministrators": [{"Id": _TEST_ACCOUNT, "Name": "audit"}]},
    ),
)

_CONFIG = (
    ClientAdapter(
        method="describe_configuration_aggregator_sources_status",
        boto_service="config",
        boto_method="describe_configuration_aggregator_sources_status",
        operation="DescribeConfigurationAggregatorSourcesStatus",
        args=("org-aggregator",),
        success={"AggregatedSourceStatusList": [{"SourceId": _TEST_ACCOUNT}]},
    ),
    ClientAdapter(
        method="describe_configuration_aggregators",
        boto_service="config",
        boto_method="describe_configuration_aggregators",
        operation="DescribeConfigurationAggregators",
        success={
            "ConfigurationAggregators": [
                {"ConfigurationAggregatorName": "org-aggregator"}
            ]
        },
    ),
    ClientAdapter(
        method="describe_configuration_recorder_status",
        boto_service="config",
        boto_method="describe_configuration_recorder_status",
        operation="DescribeConfigurationRecorderStatus",
        success={"ConfigurationRecordersStatus": [{"recording": True}]},
    ),
    ClientAdapter(
        method="describe_configuration_recorders",
        boto_service="config",
        boto_method="describe_configuration_recorders",
        operation="DescribeConfigurationRecorders",
        success={"ConfigurationRecorders": [{"name": "default"}]},
    ),
    ClientAdapter(
        method="describe_delivery_channel_status",
        boto_service="config",
        boto_method="describe_delivery_channel_status",
        operation="DescribeDeliveryChannelStatus",
        success={"DeliveryChannelsStatus": [{"name": "default"}]},
    ),
    ClientAdapter(
        method="describe_delivery_channels",
        boto_service="config",
        boto_method="describe_delivery_channels",
        operation="DescribeDeliveryChannels",
        success={"DeliveryChannels": [{"name": "default", "s3BucketName": "b"}]},
    ),
    ClientAdapter(
        method="get_account_id",
        boto_service="sts",
        boto_method="get_caller_identity",
        operation="GetCallerIdentity",
        success={"Account": _TEST_ACCOUNT},
    ),
    # us-east-1 answers a None LocationConstraint, which the method maps to
    # "us-east-1". A placeholder response would miss that branch entirely.
    ClientAdapter(
        method="get_bucket_location",
        boto_service="s3",
        boto_method="get_bucket_location",
        operation="GetBucketLocation",
        args=("config-bucket",),
        success={"LocationConstraint": "us-west-2"},
    ),
    ClientAdapter(
        method="get_bucket_policy",
        boto_service="s3",
        boto_method="get_bucket_policy",
        operation="GetBucketPolicy",
        args=("config-bucket",),
        success={"Policy": '{"Version":"2012-10-17","Statement":[]}'},
    ),
    ClientAdapter(
        method="get_management_account_id",
        boto_service="organizations",
        boto_method="describe_organization",
        operation="DescribeOrganization",
        success={"Organization": {"MasterAccountId": _TEST_ACCOUNT}},
    ),
    ClientAdapter(
        method="list_delegated_administrators",
        boto_service="organizations",
        boto_method="list_delegated_administrators",
        operation="ListDelegatedAdministrators",
        success={"DelegatedAdministrators": [{"Id": _TEST_ACCOUNT, "Name": "audit"}]},
    ),
)

_EC2 = (
    ClientAdapter(
        method="get_account_id",
        boto_service="sts",
        boto_method="get_caller_identity",
        operation="GetCallerIdentity",
        success={"Account": _TEST_ACCOUNT},
    ),
    ClientAdapter(
        method="get_ebs_encryption_by_default",
        boto_service="ec2",
        boto_method="get_ebs_encryption_by_default",
        operation="GetEbsEncryptionByDefault",
        success={"EbsEncryptionByDefault": True},
    ),
)

_FIREWALLMANAGER = (
    ClientAdapter(
        method="get_admin_account",
        boto_service="fms",
        boto_method="get_admin_account",
        operation="GetAdminAccount",
        success={"AdminAccount": _TEST_ACCOUNT, "RoleStatus": "READY"},
    ),
    # Declared non-paginated when this table was written, because the
    # pre-migration method hand-rolled its own NextToken loop over
    # ``list_policies(MaxResults=100)``. ``fms`` does publish a ``list_policies``
    # paginator, and the migrated method uses it -- the merged result is identical
    # and the loop is eight fewer lines to get wrong -- so the harness has to
    # attach its raise to ``paginate()`` rather than to the boto method.
    ClientAdapter(
        method="list_policies",
        boto_service="fms",
        boto_method="list_policies",
        operation="ListPolicies",
        success=({"PolicyList": [{"PolicyName": "waf-policy"}]},),
        paginated=True,
    ),
)

_GUARDDUTY = (
    ClientAdapter(
        method="describe_organization_configuration",
        boto_service="guardduty",
        boto_method="describe_organization_configuration",
        operation="DescribeOrganizationConfiguration",
        args=("detector-1",),
        success={"AutoEnableOrganizationMembers": "ALL", "MemberAccountLimitReached": False},
    ),
    ClientAdapter(
        method="get_detector_details",
        boto_service="guardduty",
        boto_method="get_detector",
        operation="GetDetector",
        args=("detector-1",),
        success={"Status": "ENABLED", "FindingPublishingFrequency": "SIX_HOURS"},
    ),
    # The third error result shape in the tree: this returns the *string*
    # "ERROR:{code}:{message}" on failure, which its caller parses by prefix and
    # then cached as None. It returns {"DetectorIds": [...]}.
    ClientAdapter(
        method="get_detector_id",
        boto_service="guardduty",
        boto_method="list_detectors",
        operation="ListDetectors",
        success={"DetectorIds": ["detector-1"]},
    ),
    ClientAdapter(
        method="list_organization_admin_accounts",
        boto_service="guardduty",
        boto_method="list_organization_admin_accounts",
        operation="ListOrganizationAdminAccounts",
        success={"AdminAccounts": [{"AdminAccountId": _TEST_ACCOUNT}]},
    ),
)

_IAM = (
    ClientAdapter(
        method="list_users",
        boto_service="iam",
        boto_method="list_users",
        operation="ListUsers",
        success=({"Users": [{"UserName": "alice", "Arn": "arn:aws:iam::1:user/alice"}]},),
        paginated=True,
    ),
)

_INSPECTOR = (
    ClientAdapter(
        method="batch_get_account_status",
        boto_service="inspector2",
        boto_method="batch_get_account_status",
        operation="BatchGetAccountStatus",
        args=([_TEST_ACCOUNT],),
        success={
            "accounts": [
                {
                    "accountId": _TEST_ACCOUNT,
                    "state": {"status": "ENABLED"},
                    "resourceState": {"ec2": {"status": "ENABLED"}},
                }
            ]
        },
    ),
    ClientAdapter(
        method="describe_organization_configuration",
        boto_service="inspector2",
        boto_method="describe_organization_configuration",
        operation="DescribeOrganizationConfiguration",
        success={"autoEnable": {"ec2": True, "ecr": True}, "maxAccountLimitReached": False},
    ),
    ClientAdapter(
        method="get_delegated_admin_account",
        boto_service="inspector2",
        boto_method="get_delegated_admin_account",
        operation="GetDelegatedAdminAccount",
        success={"delegatedAdmin": {"accountId": _TEST_ACCOUNT, "relationshipStatus": "ENABLED"}},
    ),
    # First page only (Requirement 1.13): <=20 accounts. Recorded as a deferred
    # correction, not fixed here -- adding pagination changes the success path's
    # call count and could surface accounts the first page omitted, which would
    # move verdicts and break the gate's no-PASS-changes promise.
    ClientAdapter(
        method="list_organization_accounts",
        boto_service="organizations",
        boto_method="list_accounts",
        operation="ListAccounts",
        success={"Accounts": [{"Id": _TEST_ACCOUNT, "Status": "ACTIVE"}]},
    ),
)

_MACIE = (
    ClientAdapter(
        method="describe_organization_configuration",
        boto_service="macie2",
        boto_method="describe_organization_configuration",
        operation="DescribeOrganizationConfiguration",
        success={"autoEnable": True, "maxAccountLimitReached": False},
    ),
    ClientAdapter(
        method="get_account_id",
        boto_service="sts",
        boto_method="get_caller_identity",
        operation="GetCallerIdentity",
        success={"Account": _TEST_ACCOUNT},
    ),
    ClientAdapter(
        method="get_administrator_account",
        boto_service="macie2",
        boto_method="get_administrator_account",
        operation="GetAdministratorAccount",
        success={"administrator": {"accountId": _TEST_ACCOUNT, "relationshipStatus": "Enabled"}},
    ),
    # One of the two reference implementations from commit bdad609. It already
    # returns a Code+Message error result -- but no Operation, so the strict is_error
    # does not recognize it, which is why it is routed through ``aws_error``.
    ClientAdapter(
        method="get_classification_export_configuration",
        boto_service="macie2",
        boto_method="get_classification_export_configuration",
        operation="GetClassificationExportConfiguration",
        success={"configuration": {"s3Destination": {"bucketName": "macie-findings"}}},
    ),
    ClientAdapter(
        method="get_findings_publication_configuration",
        boto_service="macie2",
        boto_method="get_findings_publication_configuration",
        operation="GetFindingsPublicationConfiguration",
        success={"securityHubConfiguration": {"publishPolicyFindings": True}},
    ),
    ClientAdapter(
        method="list_delegated_administrators",
        boto_service="organizations",
        boto_method="list_delegated_administrators",
        operation="ListDelegatedAdministrators",
        success={"DelegatedAdministrators": [{"Id": _TEST_ACCOUNT, "Name": "audit"}]},
    ),
    ClientAdapter(
        method="list_members",
        boto_service="macie2",
        boto_method="list_members",
        operation="ListMembers",
        success=({"members": [{"accountId": _TEST_ACCOUNT, "relationshipStatus": "Enabled"}]},),
        paginated=True,
    ),
    ClientAdapter(
        method="list_organization_accounts",
        boto_service="organizations",
        boto_method="list_accounts",
        operation="ListAccounts",
        success=({"Accounts": [{"Id": _TEST_ACCOUNT, "Status": "ACTIVE"}]},),
        paginated=True,
    ),
)

_ORGANIZATIONS = (
    ClientAdapter(
        method="describe_organization",
        boto_service="organizations",
        boto_method="describe_organization",
        operation="DescribeOrganization",
        success={"Organization": {"Id": "o-abc123", "MasterAccountId": _TEST_ACCOUNT}},
    ),
    ClientAdapter(
        method="list_accounts_for_parent",
        boto_service="organizations",
        boto_method="list_accounts_for_parent",
        operation="ListAccountsForParent",
        args=("ou-abc-123",),
        success=({"Accounts": [{"Id": _TEST_ACCOUNT, "Status": "ACTIVE"}]},),
        paginated=True,
    ),
    ClientAdapter(
        method="list_organizational_units_for_parent",
        boto_service="organizations",
        boto_method="list_organizational_units_for_parent",
        operation="ListOrganizationalUnitsForParent",
        args=("r-abc1",),
        success=({"OrganizationalUnits": [{"Id": "ou-abc-123", "Name": "Security"}]},),
        paginated=True,
    ),
    ClientAdapter(
        method="list_policies",
        boto_service="organizations",
        boto_method="list_policies",
        operation="ListPolicies",
        success=({"Policies": [{"Id": "p-abc123", "Name": "FullAWSAccess"}]},),
        paginated=True,
    ),
    ClientAdapter(
        method="list_roots",
        boto_service="organizations",
        boto_method="list_roots",
        operation="ListRoots",
        success=({"Roots": [{"Id": "r-abc1", "Name": "Root"}]},),
        paginated=True,
    ),
)

_S3 = (
    # Maps BOTH NoSuchPublicAccessBlockConfiguration and AccessDenied to {}
    # today, which is why SRA-S3-01..04 say "No public access block
    # configuration found" either way. A masked FAIL with no CSV tell.
    ClientAdapter(
        method="get_public_access_block",
        boto_service="s3control",
        boto_method="get_public_access_block",
        operation="GetPublicAccessBlock",
        args=(_TEST_ACCOUNT,),
        success={
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
    ),
)

_SECURITYHUB = (
    ClientAdapter(
        method="describe_organization_configuration",
        boto_service="securityhub",
        boto_method="describe_organization_configuration",
        operation="DescribeOrganizationConfiguration",
        success={"AutoEnable": True, "MemberAccountLimitReached": False},
    ),
    ClientAdapter(
        method="get_administrator_account",
        boto_service="securityhub",
        boto_method="get_administrator_account",
        operation="GetAdministratorAccount",
        success={"Administrator": {"AccountId": _TEST_ACCOUNT, "MemberStatus": "Enabled"}},
    ),
    # Part of the None tri-state: returns None on InvalidAccessException ("not
    # subscribed"), [] on any other failure, and a list on success -- three
    # meanings in two falsy values. It answers a dict or an error result.
    ClientAdapter(
        method="get_enabled_standards",
        boto_service="securityhub",
        boto_method="get_enabled_standards",
        operation="GetEnabledStandards",
        success={
            "StandardsSubscriptions": [
                {"StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0"}
            ]
        },
    ),
    ClientAdapter(
        method="list_delegated_administrators",
        boto_service="organizations",
        boto_method="list_delegated_administrators",
        operation="ListDelegatedAdministrators",
        success={"DelegatedAdministrators": [{"Id": _TEST_ACCOUNT, "Name": "audit"}]},
    ),
    ClientAdapter(
        method="list_enabled_products_for_import",
        boto_service="securityhub",
        boto_method="list_enabled_products_for_import",
        operation="ListEnabledProductsForImport",
        success={"ProductSubscriptions": ["arn:aws:securityhub:us-east-1::product/aws/guardduty"]},
    ),
    ClientAdapter(
        method="list_members",
        boto_service="securityhub",
        boto_method="list_members",
        operation="ListMembers",
        success={"Members": [{"AccountId": _TEST_ACCOUNT, "MemberStatus": "Enabled"}]},
    ),
    ClientAdapter(
        method="list_organization_accounts",
        boto_service="organizations",
        boto_method="list_accounts",
        operation="ListAccounts",
        success={"Accounts": [{"Id": _TEST_ACCOUNT, "Status": "ACTIVE"}]},
    ),
    ClientAdapter(
        method="list_organization_admin_accounts",
        boto_service="securityhub",
        boto_method="list_organization_admin_accounts",
        operation="ListOrganizationAdminAccounts",
        success={"AdminAccounts": [{"AccountId": _TEST_ACCOUNT, "Status": "ENABLED"}]},
    ),
)

_SECURITYINCIDENTRESPONSE = (
    ClientAdapter(
        method="batch_get_member_account_details",
        boto_service="security-ir",
        boto_method="batch_get_member_account_details",
        operation="BatchGetMemberAccountDetails",
        args=("m-abc123", [_TEST_ACCOUNT]),
        success={"items": [{"accountId": _TEST_ACCOUNT, "relationshipStatus": "Associated"}]},
    ),
    ClientAdapter(
        method="get_membership",
        boto_service="security-ir",
        boto_method="get_membership",
        operation="GetMembership",
        args=("m-abc123",),
        success={"membershipId": "m-abc123", "membershipStatus": "Active"},
    ),
    ClientAdapter(
        method="get_role",
        boto_service="iam",
        boto_method="get_role",
        operation="GetRole",
        args=("AWSServiceRoleForSecurityIncidentResponse",),
        success={"Role": {"RoleName": "AWSServiceRoleForSecurityIncidentResponse"}},
    ),
    ClientAdapter(
        method="list_accounts",
        boto_service="organizations",
        boto_method="list_accounts",
        operation="ListAccounts",
        success=({"Accounts": [{"Id": _TEST_ACCOUNT, "Status": "ACTIVE"}]},),
        paginated=True,
    ),
    ClientAdapter(
        method="list_delegated_administrators",
        boto_service="organizations",
        boto_method="list_delegated_administrators",
        operation="ListDelegatedAdministrators",
        success={"DelegatedAdministrators": [{"Id": _TEST_ACCOUNT, "Name": "audit"}]},
    ),
    ClientAdapter(
        method="list_memberships",
        boto_service="security-ir",
        boto_method="list_memberships",
        operation="ListMemberships",
        success={"items": [{"membershipId": "m-abc123", "membershipStatus": "Active"}]},
    ),
)

_SECURITYLAKE = (
    ClientAdapter(
        method="get_data_lake_sources",
        boto_service="securitylake",
        boto_method="get_data_lake_sources",
        operation="GetDataLakeSources",
        success={
            "dataLakeSources": [
                {"account": _TEST_ACCOUNT, "sourceName": "CLOUD_TRAIL_MGMT"}
            ]
        },
    ),
    ClientAdapter(
        method="get_delegated_admin",
        boto_service="organizations",
        boto_method="list_delegated_administrators",
        operation="ListDelegatedAdministrators",
        success={"DelegatedAdministrators": [{"Id": _TEST_ACCOUNT}]},
    ),
    ClientAdapter(
        method="get_organization_configuration",
        boto_service="securitylake",
        boto_method="get_data_lake_organization_configuration",
        operation="GetDataLakeOrganizationConfiguration",
        success={"autoEnableNewAccount": [{"region": _TEST_REGION, "sources": []}]},
    ),
    # Requirement 1.11: acquires sqs inside the method today.
    ClientAdapter(
        method="get_sqs_queue_encryption",
        boto_service="sqs",
        boto_method="get_queue_attributes",
        operation="GetQueueAttributes",
        args=("https://sqs.us-east-1.amazonaws.com/111122223333/queue",),
        success={"Attributes": {"KmsMasterKeyId": "alias/aws/sqs"}},
    ),
    # The second bare-bool probe (Requirement 1.7), replaced with
    # list_data_lakes and answers the bool in the base class, after the guard.
    ClientAdapter(
        method="is_security_lake_enabled",
        boto_service="securitylake",
        boto_method="list_data_lakes",
        operation="ListDataLakes",
        success={"dataLakes": [{"region": _TEST_REGION, "s3BucketArn": "arn:aws:s3:::lake"}]},
    ),
    ClientAdapter(
        method="list_data_lakes",
        boto_service="securitylake",
        boto_method="list_data_lakes",
        operation="ListDataLakes",
        success={"dataLakes": [{"region": _TEST_REGION, "s3BucketArn": "arn:aws:s3:::lake"}]},
    ),
    ClientAdapter(
        method="list_delegated_administrators",
        boto_service="organizations",
        boto_method="list_delegated_administrators",
        operation="ListDelegatedAdministrators",
        success={"DelegatedAdministrators": [{"Id": _TEST_ACCOUNT, "Name": "audit"}]},
    ),
    ClientAdapter(
        method="list_log_sources",
        boto_service="securitylake",
        boto_method="list_log_sources",
        operation="ListLogSources",
        success={
            "sources": [
                {
                    "account": _TEST_ACCOUNT,
                    "region": _TEST_REGION,
                    "sources": [{"awsLogSource": {"sourceName": "CLOUD_TRAIL_MGMT"}}],
                }
            ]
        },
    ),
    ClientAdapter(
        method="list_organization_accounts",
        boto_service="organizations",
        boto_method="list_accounts",
        operation="ListAccounts",
        success={"Accounts": [{"Id": _TEST_ACCOUNT, "Status": "ACTIVE"}]},
    ),
    # The measured masked-FAIL path. Returns [] on AccessDeniedException today,
    # the base caches the [], and SRA-SECURITYLAKE-16/17 report a confident
    # "is not set up as ... subscriber" -- 8 rows in the 2026-09-12 baseline
    # while the build log records AccessDenied on this very call.
    ClientAdapter(
        method="list_subscribers",
        boto_service="securitylake",
        boto_method="list_subscribers",
        operation="ListSubscribers",
        success={"subscribers": [{"subscriberName": "audit-query-access"}]},
    ),
)

_SHIELD = (
    ClientAdapter(
        method="describe_drt_access",
        boto_service="shield",
        boto_method="describe_drt_access",
        operation="DescribeDRTAccess",
        success={"RoleArn": f"arn:aws:iam::{_TEST_ACCOUNT}:role/DRT", "LogBucketList": []},
    ),
    # Requirement 1.11: acquired cloudwatch inside the method; now in __init__.
    #
    # The boto method is DescribeAlarmsForMetric, not DescribeAlarms. This table
    # said DescribeAlarms when it was written, which was simply wrong -- the
    # generated IAM policy grants cloudwatch:DescribeAlarmsForMetric and nothing
    # else, and that artefact is derived from this call, so the call is the
    # authority and the adapter was the copy that had drifted.
    ClientAdapter(
        method="get_cloudwatch_alarms_for_resource",
        boto_service="cloudwatch",
        boto_method="describe_alarms_for_metric",
        operation="DescribeAlarmsForMetric",
        args=(f"arn:aws:elasticloadbalancing:us-east-1:{_TEST_ACCOUNT}:loadbalancer/app/x/y",),
        success={"MetricAlarms": [{"AlarmName": "ddos", "MetricName": "DDoSDetected"}]},
    ),
    # Requirement 1.11: acquires lambda inside the method today.
    ClientAdapter(
        method="get_lambda_function",
        boto_service="lambda",
        boto_method="get_function",
        operation="GetFunction",
        args=("shield-response",),
        success={"Configuration": {"FunctionName": "shield-response"}},
    ),
    # Note the crossed names, which are in the tree and not a typo here:
    # get_subscription_state calls DescribeSubscription, and
    # get_subscription_status calls GetSubscriptionState.
    ClientAdapter(
        method="get_subscription_state",
        boto_service="shield",
        boto_method="describe_subscription",
        operation="DescribeSubscription",
        success={"Subscription": {"AutoRenew": "ENABLED", "SubscriptionLimits": {}}},
    ),
    ClientAdapter(
        method="get_subscription_status",
        boto_service="shield",
        boto_method="get_subscription_state",
        operation="GetSubscriptionState",
        success={"SubscriptionState": "ACTIVE"},
    ),
    # Branches on "cloudfront" in the ARN: an ELB ARN takes the wafv2 path, a
    # CloudFront ARN takes the cloudfront path and synthesizes a
    # WAFNonexistentItemException error result when the distribution has no WebACLId.
    # Driven here on the wafv2 branch; the cloudfront branch has its own test.
    ClientAdapter(
        method="get_web_acl_for_resource",
        boto_service="wafv2",
        boto_method="get_web_acl_for_resource",
        operation="GetWebACLForResource",
        args=(f"arn:aws:elasticloadbalancing:us-east-1:{_TEST_ACCOUNT}:loadbalancer/app/x/y",),
        success={"WebACL": {"Name": "acl", "Id": "acl-1"}},
    ),
    # First page only (Requirement 1.13).
    ClientAdapter(
        method="list_protections",
        boto_service="shield",
        boto_method="list_protections",
        operation="ListProtections",
        success={"Protections": [{"Id": "p-1", "ResourceArn": "arn:aws:cloudfront::1:distribution/D"}]},
    ),
)

_WAF = (
    ClientAdapter(
        method="describe_load_balancers",
        boto_service="elbv2",
        boto_method="describe_load_balancers",
        operation="DescribeLoadBalancers",
        success={"LoadBalancers": [{"LoadBalancerArn": "arn:aws:elasticloadbalancing:::lb/app/x/y", "Type": "application"}]},
    ),
    ClientAdapter(
        method="describe_verified_access_instances",
        boto_service="ec2",
        boto_method="describe_verified_access_instances",
        operation="DescribeVerifiedAccessInstances",
        success={"VerifiedAccessInstances": [{"VerifiedAccessInstanceId": "vai-1"}]},
    ),
    ClientAdapter(
        method="get_logging_configuration",
        boto_service="wafv2",
        boto_method="get_logging_configuration",
        operation="GetLoggingConfiguration",
        args=(f"arn:aws:wafv2:us-east-1:{_TEST_ACCOUNT}:regional/webacl/acl/1",),
        success={"LoggingConfiguration": {"LogDestinationConfigs": ["arn:aws:logs:::lg"]}},
    ),
    ClientAdapter(
        method="get_rest_apis",
        boto_service="apigateway",
        boto_method="get_rest_apis",
        operation="GetRestApis",
        success={"items": [{"id": "api1", "name": "api"}]},
    ),
    ClientAdapter(
        method="get_stages",
        boto_service="apigateway",
        boto_method="get_stages",
        operation="GetStages",
        args=("api1",),
        success={"item": [{"stageName": "prod", "webAclArn": "arn:aws:wafv2:::acl"}]},
    ),
    ClientAdapter(
        method="get_web_acl_for_resource",
        boto_service="wafv2",
        boto_method="get_web_acl_for_resource",
        operation="GetWebACLForResource",
        args=("arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/x/y",),
        success={"WebACL": {"Name": "acl", "Id": "acl-1"}},
    ),
    ClientAdapter(
        method="list_apps",
        boto_service="amplify",
        boto_method="list_apps",
        operation="ListApps",
        success={"apps": [{"appId": "d1", "name": "app"}]},
    ),
    ClientAdapter(
        method="list_distributions",
        boto_service="cloudfront",
        boto_method="list_distributions",
        operation="ListDistributions",
        success={"DistributionList": {"Items": [{"Id": "D1", "WebACLId": "acl-1"}]}},
    ),
    ClientAdapter(
        method="list_graphql_apis",
        boto_service="appsync",
        boto_method="list_graphql_apis",
        operation="ListGraphqlApis",
        success={"graphqlApis": [{"apiId": "g1", "name": "gql"}]},
    ),
    # The other reference implementation from bdad609: the only method in the
    # tree with the full three-clause shape, and the one whose transport handler
    # recovered three SRA-WAF-06 rows a failure had been discarding. Still lacks
    # Operation, which ``aws_error`` supplies.
    ClientAdapter(
        method="list_services",
        boto_service="apprunner",
        boto_method="list_services",
        operation="ListServices",
        success={"ServiceSummaryList": [{"ServiceArn": "arn:aws:apprunner:::service/x"}]},
    ),
    ClientAdapter(
        method="list_user_pools",
        boto_service="cognito-idp",
        boto_method="list_user_pools",
        operation="ListUserPools",
        success={"UserPools": [{"Id": "pool1", "Name": "pool"}]},
    ),
    ClientAdapter(
        method="list_web_acls",
        boto_service="wafv2",
        boto_method="list_web_acls",
        operation="ListWebACLs",
        args=("REGIONAL",),
        success={"WebACLs": [{"Name": "acl", "Id": "acl-1", "ARN": "arn:aws:wafv2:::acl"}]},
    ),
)

#: service -> adapters. All 18, so Property 3a can assert completeness per
#: service rather than only in aggregate.
ADAPTERS: dict[str, tuple[ClientAdapter, ...]] = {
    "accessanalyzer": _ACCESSANALYZER,
    "account": _ACCOUNT,
    "auditmanager": _AUDITMANAGER,
    "cloudtrail": _CLOUDTRAIL,
    "config": _CONFIG,
    "ec2": _EC2,
    "firewallmanager": _FIREWALLMANAGER,
    "guardduty": _GUARDDUTY,
    "iam": _IAM,
    "inspector": _INSPECTOR,
    "macie": _MACIE,
    "organizations": _ORGANIZATIONS,
    "s3": _S3,
    "securityhub": _SECURITYHUB,
    "securityincidentresponse": _SECURITYINCIDENTRESPONSE,
    "securitylake": _SECURITYLAKE,
    "shield": _SHIELD,
    "waf": _WAF,
}


# --------------------------------------------------------------------------- #
# Snapshots, taken at import so collection is stable
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Target:
    """One (service, client class, adapter) triple to drive."""

    service: str
    cls: type
    adapter: ClientAdapter

    @property
    def id(self) -> str:
        """Return the parametrize ID: ``<service>.<Class>.<method>``."""
        return f"{self.service}.{self.cls.__name__}.{self.adapter.method}"


def _build_targets() -> list[_Target]:
    """Pair every declared adapter with its client class.

    Returns:
        One target per adapter that has a matching method on the class.
    """
    targets: list[_Target] = []
    for service in _service_names():
        adapters = {a.method: a for a in ADAPTERS.get(service, ())}
        for cls in _client_classes(service):
            for method in _public_methods(cls):
                adapter = adapters.get(method)
                if adapter is not None:
                    targets.append(_Target(service, cls, adapter))
    return targets


_SERVICE_NAMES: list[str] = _service_names()
_TARGETS: list[_Target] = _build_targets()


def _params(property_key: str) -> list[Any]:
    """Return parametrize values, one per client method.

    ``property_key`` is retained and unused; see the note on
    ``test_accessor_cache_property._params``. Every one of the 92 client methods
    is now asserted unconditionally against every property.

    Args:
        property_key: Which property this parametrization drives. Unused.

    Returns:
        ``pytest.param`` values, one per target.
    """
    return [pytest.param(target, id=target.id) for target in _TARGETS]


# --------------------------------------------------------------------------- #
# The harness
# --------------------------------------------------------------------------- #


def _build_wrapper(target: _Target) -> tuple[Any, MagicMock]:
    """Construct the client wrapper against a mock context.

    The context's ``get_client`` returns one ``MagicMock`` per boto3 service id,
    memoized, so a wrapper holding nine clients gets nine distinct mocks and the
    adapter can name which one its method uses. The same mock is handed back for
    an in-method acquisition, which is what makes the harness indifferent to
    Requirement 1.11's constructor move.

    Args:
        target: The target to build for.

    Returns:
        ``(wrapper, boto_mock)`` where ``boto_mock`` is the mock for the
        adapter's ``boto_service``.
    """
    mocks: dict[str, MagicMock] = {}

    def _get_client(service_name: str, region: str | None = None) -> MagicMock:
        return mocks.setdefault(service_name, MagicMock(name=f"boto3:{service_name}"))

    ctx = MagicMock(spec=ScanContext)
    ctx.get_client.side_effect = _get_client

    # iam and organizations take (ctx); everyone else takes (region, ctx).
    parameters = list(inspect.signature(target.cls.__init__).parameters)
    if "region" in parameters:
        wrapper = target.cls(_TEST_REGION, ctx)
    else:
        wrapper = target.cls(ctx)

    return wrapper, _get_client(target.adapter.boto_service)


def _arm_success(boto_mock: MagicMock, adapter: ClientAdapter) -> None:
    """Configure the boto3 mock to answer the adapter's success shape.

    Args:
        boto_mock: The mock for the adapter's boto3 service.
        adapter: The adapter.
    """
    if adapter.paginated:
        paginator = MagicMock(name="paginator")
        paginator.paginate.return_value = list(adapter.success)
        boto_mock.get_paginator.return_value = paginator
    else:
        getattr(boto_mock, adapter.boto_method).return_value = adapter.success


def _arm_raise(
    boto_mock: MagicMock, adapter: ClientAdapter, exc: BaseException
) -> None:
    """Configure the boto3 mock to raise ``exc`` from the adapter's call.

    For a paginated method the raise is attached to ``paginate()``, because
    ``get_paginator()`` itself does not reach AWS.

    Args:
        boto_mock: The mock for the adapter's boto3 service.
        adapter: The adapter.
        exc: The exception to raise.
    """
    if adapter.paginated:
        paginator = MagicMock(name="paginator")
        paginator.paginate.side_effect = exc
        boto_mock.get_paginator.return_value = paginator
    else:
        getattr(boto_mock, adapter.boto_method).side_effect = exc


def _call(target: _Target, wrapper: Any) -> Any:
    """Invoke the adapter's method on the wrapper.

    Args:
        target: The target.
        wrapper: The constructed wrapper.

    Returns:
        Whatever the method returns.
    """
    return getattr(wrapper, target.adapter.method)(*target.adapter.args)


@pytest.fixture
def client_log() -> Any:
    """Capture records from the ``sraverify`` logger.

    Yields:
        The captured records, in emission order.
    """
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collector()
    target = logging.getLogger("sraverify")
    target.addHandler(handler)
    try:
        yield records
    finally:
        target.removeHandler(handler)


def _failure_lines(records: list[logging.LogRecord]) -> list[str]:
    """Return the ``aws_call_failed`` messages among the records.

    Args:
        records: Captured records.

    Returns:
        Messages at ``ERROR`` that begin with the structured prefix.
    """
    return [
        r.getMessage()
        for r in records
        if r.levelno >= logging.ERROR and r.getMessage().startswith("aws_call_failed ")
    ]


# --------------------------------------------------------------------------- #
# Non-vacuity and Property 3a
# --------------------------------------------------------------------------- #


def test_eighteen_services_are_discovered() -> None:
    """The enumeration found the whole tree."""
    assert len(_SERVICE_NAMES) == 18, (
        f"expected 18 service packages, found {len(_SERVICE_NAMES)}: {_SERVICE_NAMES}"
    )


def test_the_target_set_is_not_trivially_small() -> None:
    """92 client methods across the 18 clients."""
    assert len(_TARGETS) >= 90, (
        f"only {len(_TARGETS)} client methods paired with an adapter; the tree "
        f"holds 92 and either discovery or the tables are broken"
    )


@pytest.mark.parametrize("service", _SERVICE_NAMES)
def test_the_adapter_table_is_complete_and_exact(service: str) -> None:
    """Property 3a: adapters equal discovered methods, in both directions.

    This is what makes the tables fixture data rather than a maintained
    allowlist. A method added without an adapter fails here; an adapter for a
    deleted method fails here. Without it, the tables would silently stop
    covering the tree -- which is precisely the decay Requirement 7 exists to
    prevent.
    """
    discovered: set[str] = set()
    for cls in _client_classes(service):
        discovered.update(_public_methods(cls))

    declared = {adapter.method for adapter in ADAPTERS.get(service, ())}

    missing = discovered - declared
    stale = declared - discovered

    assert missing == set(), (
        f"{service}: client methods with no adapter: {sorted(missing)}. Add one "
        f"to the table in this module so the contract covers them."
    )
    assert stale == set(), (
        f"{service}: adapters for methods that no longer exist: {sorted(stale)}"
    )


@pytest.mark.parametrize("service", _SERVICE_NAMES)
def test_every_service_declares_at_least_one_adapter(service: str) -> None:
    """No service is silently uncovered."""
    assert ADAPTERS.get(service), f"{service} has no adapter table at all"


def test_every_adapter_names_a_plausible_operation() -> None:
    """Each adapter's expected operation is PascalCase and not obviously wrong.

    This guards the *harness*, not the tree. The adapter's ``operation`` is what
    the harness sets on the ``ClientError`` it raises and then asserts came back,
    so a snake_case value pasted in here would make the assertion pass against a
    name AWS would never send, and the test would stop meaning anything.
    """
    offenders = [
        f"{service}.{adapter.method}: {adapter.operation!r}"
        for service, adapters in ADAPTERS.items()
        for adapter in adapters
        if "_" in adapter.operation or not adapter.operation[:1].isupper()
    ]
    assert offenders == [], f"operation names are not PascalCase: {offenders}"


# --------------------------------------------------------------------------- #
# Property 1 -- ClientError
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("target", _params("property_1_client_error"), ids=None)
def test_every_client_method_returns_an_error_result_on_client_error(
    target: _Target, client_log: Any
) -> None:
    """Property 1: AWS's own code and message reach the caller.

    The single most consequential property in this module. 100 of the 144
    handlers in the pre-migration tree return ``{}``, ``[]``, ``None``, or a bare
    bool here, and a check handed one of those cannot tell a disabled service
    from a denied permission -- so it lands on whichever branch its author wrote
    for "no data", and where that branch is ``failed()`` an undetermined state is
    published as an established negative.
    """
    wrapper, boto_mock = _build_wrapper(target)
    _arm_raise(
        boto_mock,
        target.adapter,
        ClientError(
            {"Error": {"Code": "TestCode", "Message": "test message"}},
            target.adapter.operation,
        ),
    )

    result = _call(target, wrapper)

    assert is_error(result), (
        f"{target.id} returned {result!r} for a ClientError; expected an error result "
        f"carrying Code, Message, and Operation"
    )
    error = result["Error"]
    assert error["Code"] == "TestCode", f"{target.id} lost the AWS error code"
    assert error["Message"] == "test message", (
        f"{target.id} did not pass through the AWS message verbatim; use "
        f"e.response['Error']['Message'], not str(e)"
    )
    assert error["Operation"] == target.adapter.operation, (
        f"{target.id} reported Operation={error['Operation']!r}, expected "
        f"{target.adapter.operation!r}"
    )


@pytest.mark.parametrize("target", _params("property_1_log"), ids=None)
def test_every_client_method_logs_exactly_one_structured_failure(
    target: _Target, client_log: Any
) -> None:
    """Property 1: one parseable ``aws_call_failed`` record per failure.

    Exactly one, because the gate attributes records to checks by position and
    counts them: a method that logged twice would make one failure look like two,
    and a method that logged none would leave a FAIL-to-ERROR transition with no
    evidence and reject the batch.
    """
    wrapper, boto_mock = _build_wrapper(target)
    _arm_raise(
        boto_mock,
        target.adapter,
        ClientError(
            {"Error": {"Code": "TestCode", "Message": "test message"}},
            target.adapter.operation,
        ),
    )

    _call(target, wrapper)

    lines = _failure_lines(client_log)
    assert len(lines) == 1, (
        f"{target.id} emitted {len(lines)} aws_call_failed records, expected 1: "
        f"{lines}"
    )
    assert f"operation={target.adapter.operation} " in lines[0]
    assert "code=TestCode " in lines[0]


# --------------------------------------------------------------------------- #
# Property 2 -- the BotoCoreError family
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("target", _params("property_2_endpoint"), ids=None)
def test_every_client_method_returns_an_error_result_on_endpoint_failure(
    target: _Target, client_log: Any
) -> None:
    """Property 2: a transport failure costs one row, not a check's whole output.

    In the seven ``ClientError``-only clients an ``EndpointConnectionError``
    escapes the client, escapes ``execute()``, and reaches the orchestrator's
    guard -- which materializes ``list(check.execute())``, so the exception
    unwinds before the rows are collected and **every row already yielded for
    every other Region is discarded**. One unreachable Region costs the check.
    """
    wrapper, boto_mock = _build_wrapper(target)
    _arm_raise(
        boto_mock,
        target.adapter,
        EndpointConnectionError(endpoint_url="https://example.invalid/"),
    )

    result = _call(target, wrapper)

    assert is_error(result), (
        f"{target.id} returned {result!r} for an EndpointConnectionError; it "
        f"must be caught and returned as an error result, not propagated"
    )
    assert result["Error"]["Code"] == "EndpointConnectionError"
    # Not the adapter's operation. A BotoCoreError means the request never
    # completed, so botocore attaches no operation and none is claimed -- saying
    # otherwise would assert that a specific call was made and refused when in
    # fact nothing was sent. The Region and service the caller needs are still in
    # the message, which carries the endpoint URL.
    assert result["Error"]["Operation"] == UNKNOWN_OPERATION, (
        f"{target.id} claimed operation "
        f"{result['Error']['Operation']!r} for a transport failure"
    )


@pytest.mark.parametrize("target", _params("property_2_credentials"), ids=None)
def test_every_client_method_returns_an_error_result_on_missing_credentials(
    target: _Target, client_log: Any
) -> None:
    """Property 2: the whole ``BotoCoreError`` family, not three subclasses.

    ``NoCredentialsError`` is the discriminating case. It is not a transport
    error and carries no AWS code, so a guard enumerating only
    ``EndpointConnectionError``, ``ConnectTimeoutError``, and
    ``ReadTimeoutError`` -- which is what the tree's most complete hand-written
    handler does -- lets it propagate.
    """
    wrapper, boto_mock = _build_wrapper(target)
    _arm_raise(boto_mock, target.adapter, NoCredentialsError())

    result = _call(target, wrapper)

    assert is_error(result), (
        f"{target.id} returned {result!r} for a NoCredentialsError; the guard "
        f"must cover the whole BotoCoreError family"
    )
    assert result["Error"]["Code"] == "NoCredentialsError"


# --------------------------------------------------------------------------- #
# Property 3 -- defects propagate, contract violations are named
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("target", _params("property_3"), ids=None)
def test_a_programming_defect_propagates_out_of_every_client_method(
    target: _Target, client_log: Any
) -> None:
    """Property 3: ``RuntimeError`` is not an AWS outcome and is not caught.

    The 44 bare ``except Exception`` handlers across 10 clients are what this
    fails against today, and Requirement 1.10 requires them removed rather than
    narrowed in place. A handler that caught this would give a typo in a client a
    plausible ERROR row per Region, recurring on every scan until somebody
    noticed that ``RuntimeError`` is not an AWS error code.
    """
    wrapper, boto_mock = _build_wrapper(target)
    _arm_raise(boto_mock, target.adapter, RuntimeError("boom"))

    with pytest.raises(RuntimeError, match="boom"):
        _call(target, wrapper)


# --------------------------------------------------------------------------- #
# Property 4 -- the success path
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("target", _params("property_4"), ids=None)
def test_every_client_method_returns_a_non_error_mapping_on_success(
    target: _Target, client_log: Any
) -> None:
    """Property 4: a dict on success, and not one mistakable for a failure.

    Both halves matter. A ``Mapping`` makes ``"Error" in result`` the only test
    that separates success from failure at every tier. And a success response
    must not satisfy ``is_error``, or the accessor would refuse to cache a
    perfectly good answer.
    """
    wrapper, boto_mock = _build_wrapper(target)
    _arm_success(boto_mock, target.adapter)

    result = _call(target, wrapper)

    assert isinstance(result, Mapping), (
        f"{target.id} returned {type(result).__name__} on success, not a "
        f"Mapping; wrap the value under its AWS response member name"
    )
    assert not is_error(result), (
        f"{target.id} returned a value on the success path that satisfies "
        f"is_error: {result!r}"
    )
    assert _failure_lines(client_log) == [], (
        f"{target.id} logged an aws_call_failed record on a successful call"
    )


# --------------------------------------------------------------------------- #
# Property 6 -- static shape rules
# --------------------------------------------------------------------------- #


def _client_module_paths() -> list[Path]:
    """Return every ``services/*/client.py``, sorted.

    Returns:
        Absolute paths.
    """
    return sorted(
        _SERVICES_ROOT / service / "client.py" for service in _SERVICE_NAMES
    )


def _client_params(property_key: str) -> list[Any]:
    """Return parametrize values over client modules, one per module.

    ``property_key`` is retained and unused; see the note on
    ``test_accessor_cache_property._params``. All 18 client modules are now
    asserted unconditionally, which makes this identical to
    :func:`_all_client_params` -- the two are kept separate because the
    distinction they encoded is still the reason some properties were never
    ledger-marked at all, and collapsing them would erase that.

    Args:
        property_key: Which property this parametrization drives. Unused.

    Returns:
        ``pytest.param`` values, one per client module.
    """
    return [
        pytest.param(path, id=f"{path.parent.name}/client.py")
        for path in _client_module_paths()
    ]


def _all_client_params() -> list[Any]:
    """Return unmarked parametrize values over every client module.

    Kept distinct from :func:`_client_params` because the distinction it encodes is
    real: some properties here are *vacuously* true of a client that does not call
    ``aws_error`` at all -- it cannot pass the wrong arguments to a call it never
    makes -- and grouping those with the properties a client can actively violate
    would blur what a failure means.

    Returns:
        ``pytest.param`` values, one per client module, no marks.
    """
    return [
        pytest.param(path, id=f"{path.parent.name}/client.py")
        for path in _client_module_paths()
    ]


#: The two spellings of the catch clause a client method may use. ``AWS_EXCEPTIONS``
#: is the canonical one; the explicit tuple is accepted so a reader who writes it
#: out longhand is not failed for style.
_ALLOWED_HANDLER_TYPES: frozenset[str] = frozenset(
    {
        "AWS_EXCEPTIONS",
        "(ClientError, BotoCoreError)",
        "(BotoCoreError, ClientError)",
    }
)


@pytest.mark.parametrize("path", _client_params("property_6_handlers"), ids=None)
def test_every_client_except_clause_catches_exactly_the_aws_exceptions(
    path: Path,
) -> None:
    """Property 6, for plain ``try``/``except``: every handler catches
    ``AWS_EXCEPTIONS`` and nothing else.

    This is the static half of what makes hand-written ``try``/``except`` safe to
    repeat across 92 methods. The dynamic half is Properties 1-4 above, which
    drive every method through a simulated failure; this one reads the clause
    itself, so the two failure modes the old handlers had are each caught at the
    line that introduces them:

    * **catching too little** -- ``except ClientError`` alone, which is what let
      transport failures escape seven clients and cost a check its whole output;
    * **catching too much** -- ``except Exception``, which turns a programming
      defect into a plausible ERROR row per Region, recurring on every scan.

    Both spellings of the pair are accepted. A typed catch such as
    ``except self.client.exceptions.ResourceNotFoundException`` is rejected: that
    is a client classifying an error code, which is the check's job and the
    discriminator table's evidence rule exists to keep it there.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offenders: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            if handler.type is None:
                offenders.append(f"L{handler.lineno}: bare except")
                continue
            spelled = ast.unparse(handler.type)
            if spelled not in _ALLOWED_HANDLER_TYPES:
                offenders.append(f"L{handler.lineno}: except {spelled}")

    assert offenders == [], (
        f"{path.parent.name}/client.py has an except clause that is not exactly "
        f"the AWS pair:\n  " + "\n  ".join(offenders)
        + "\nEvery client handler must be `except AWS_EXCEPTIONS as e:` and return "
        "`self.aws_error(e)`. A narrower catch lets "
        "transport failures escape; a wider one hides programming defects; a "
        "typed catch classifies a code the check should classify."
    )


#: The one legal ``except`` body, as source. Compared as text on purpose: this is
#: the whole point of the design -- the handler is byte-identical everywhere, so
#: there is nothing per-method to get wrong. An assertion on the exact string is
#: the most direct way to hold that.
_LEGAL_HANDLER_BODY: Final = "return self.aws_error(e)"


@pytest.mark.parametrize("path", _client_params("property_6_handlers"), ids=None)
def test_every_client_except_body_is_exactly_return_self_aws_error(
    path: Path,
) -> None:
    """Property 6: the handler body is ``return self.aws_error(e)`` and nothing else.

    The 101 erasing handlers this replaces each *did something else* in the
    ``except`` -- returned ``{}``, ``[]``, ``None``, ``False``, or fell off the end.
    Requiring one exact statement rules all of those out structurally, and also
    rules out three subtler things: a handler that logs its own prose line (the
    gate parses ``aws_error``'s structured record, not prose), one that
    re-raises after building the error result, and one that inspects the code to
    decide something -- which would be a client classifying an error, the
    judgement that belongs to the check's discriminator table.

    Compared as an exact string rather than structurally, because "identical in
    every method" is the property being asserted. If this ever needs to admit a
    second form, that is a design change and should read like one.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offenders: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            body = handler.body
            rendered = ast.unparse(body[0]) if len(body) == 1 else None
            if rendered != _LEGAL_HANDLER_BODY:
                offenders.append(
                    f"L{handler.lineno}: "
                    + (
                        "; ".join(ast.unparse(s)[:60] for s in body)
                        if body
                        else "<empty>"
                    )
                )

    assert offenders == [], (
        f"{path.parent.name}/client.py has an except body that is not exactly "
        f"`{_LEGAL_HANDLER_BODY}`:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("path", _all_client_params(), ids=None)
def test_no_client_method_names_an_operation_or_region_in_its_handler(
    path: Path,
) -> None:
    """The two parameters this design removed must not come back.

    ``aws_error`` takes only the exception: the operation comes from
    ``ClientError.operation_name`` where botocore has it and is a placeholder
    where it does not, and the Region comes from ``self.region``. A method that
    reintroduced either as a keyword would be reintroducing a value typed 92
    times -- and the operation literal in particular was the one thing in the
    client layer that no test could defend, because a literal disagreeing with
    the call it labels is invisible at runtime.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offenders: list[str] = []

    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "aws_error"
        ):
            continue
        named = {kw.arg for kw in node.keywords if kw.arg}
        if named:
            offenders.append(f"L{node.lineno}: aws_error(..., {sorted(named)})")
        if len(node.args) != 1:
            offenders.append(
                f"L{node.lineno}: aws_error takes {len(node.args)} positional "
                f"arguments, expected 1"
            )

    assert offenders == [], (
        f"{path.parent.name}/client.py passes more than the exception to "
        f"aws_error:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("path", _client_params("property_6_get_client"), ids=None)
def test_every_client_acquires_its_boto3_clients_only_in_init(path: Path) -> None:
    """Requirement 1.11: ``ctx.get_client`` is called only from ``__init__``.

    Two things depend on it. A construction failure inside a method's try block
    would be caught as a ``BotoCoreError`` and turned into an error result, when it is
    actually a deterministic defect -- an unknown service id, a broken botocore
    install -- that the orchestrator should report. And every
    ``self.<attr>.<method>(...)`` in the module can only be attributed to one
    service by reading ``__init__``, which is how
    ``util/generate_iam_policy.py`` derives the least-privilege action set.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    init_spans: list[tuple[int, int]] = [
        (node.lineno, getattr(node, "end_lineno", node.lineno))
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "__init__"
    ]

    def _inside_init(lineno: int) -> bool:
        return any(start <= lineno <= end for start, end in init_spans)

    offenders = [
        f"L{node.lineno}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get_client"
        and not _inside_init(node.lineno)
    ]

    assert offenders == [], (
        f"{path.parent.name}/client.py acquires a boto3 client outside "
        f"__init__ at {offenders}; assign it to an instance attribute in "
        f"__init__ instead (Requirement 1.11)"
    )


@pytest.mark.parametrize("path", _client_params("property_6_inherits_base"), ids=None)
def test_every_client_class_inherits_the_aws_client_base(path: Path) -> None:
    """Every ``*Client`` subclasses ``AWSClient`` and chains ``__init__``.

    ``self.aws_error`` comes from the base, so a client that forgets to inherit it
    cannot compile its own ``except`` clause -- but it *could* declare
    ``self.region`` itself and drift from the base's contract. Requiring the
    inheritance and the ``super().__init__`` call keeps ``region`` and ``ctx``
    single-sourced, which is what lets ``aws_error`` take no arguments.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offenders: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or not node.name.endswith("Client"):
            continue

        bases = {ast.unparse(b) for b in node.bases}
        if "AWSClient" not in bases:
            offenders.append(
                f"L{node.lineno}: {node.name} does not inherit AWSClient "
                f"(bases: {sorted(bases) or ['none']})"
            )
            continue

        init = next(
            (
                item
                for item in node.body
                if isinstance(item, ast.FunctionDef) and item.name == "__init__"
            ),
            None,
        )
        if init is None:
            continue
        chains = any(
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "__init__"
            and isinstance(sub.func.value, ast.Call)
            and isinstance(sub.func.value.func, ast.Name)
            and sub.func.value.func.id == "super"
            for sub in ast.walk(init)
        )
        if not chains:
            offenders.append(
                f"L{init.lineno}: {node.name}.__init__ does not call "
                f"super().__init__(region, ctx)"
            )

    assert offenders == [], (
        f"{path.parent.name}/client.py:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("path", _client_params("property_6_bool"), ids=None)
def test_no_client_method_is_annotated_as_returning_a_bool(path: Path) -> None:
    """Requirement 1.7: a probe has nowhere to carry an error result.

    A method whose success path is a bare ``bool`` has no room for an error, so
    its failure path is *necessarily* erasing. ``AccessAnalyzerClient.is_access_analyzer_available``
    returns ``True`` on ``AccessDeniedException`` -- a permission failure reported
    as "the service is present" -- and ``SecurityLakeClient.is_security_lake_enabled``
    returns ``False`` on any exception.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offenders = [
        f"L{node.lineno}: {node.name}"
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not node.name.startswith("_")
        and isinstance(node.returns, ast.Name)
        and node.returns.id == "bool"
    ]

    assert offenders == [], (
        f"{path.parent.name}/client.py declares a bool-returning method at "
        f"{offenders}; return the named-key response dict and answer the boolean "
        f"in the base accessor, after the error test"
    )


def test_the_access_analyzer_probe_is_gone_from_the_tree() -> None:
    """Requirement 5.9: the probe is deleted outright, not replaced.

    It issued ``accessanalyzer:ListAnalyzers`` once per Region before any check
    ran, purely to decide whether to register a client -- and
    ``accessanalyzer`` has an endpoint in all 34 commercial Regions, so it never
    said no. It also read ``AccessDeniedException`` as "available", which is a
    permission failure reported as a presence check.

    Not replaced by the availability lookup, because a 34/34 service would make
    that lookup answer ``True`` unconditionally.
    """
    hits = [
        f"{path.relative_to(_SERVICES_ROOT).as_posix()}:{n}"
        for path in _SERVICES_ROOT.rglob("*.py")
        if "__pycache__" not in path.parts
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if "is_access_analyzer_available" in line
    ]

    assert hits == [], f"is_access_analyzer_available survives at {hits}"


def test_the_waf_local_transport_constant_is_gone() -> None:
    """Property 17 / Requirement 2.7: the constant is single-sourced in ``core``.

    ``services/waf/client.py`` declared its own ``TRANSPORT_ERROR_CODES`` as a
    hand-written literal set, while nothing in that module used it -- it existed
    for ``sra_waf_06`` to import. Two copies of the same set, one derived from
    the exception tuple and one not, is exactly how a check testing for a
    transport code and a client producing one drift apart.
    """
    source = (_SERVICES_ROOT / "waf" / "client.py").read_text(encoding="utf-8")
    declares_own = "TRANSPORT_ERROR_CODES = " in source

    assert not declares_own, (
        "services/waf/client.py still declares its own TRANSPORT_ERROR_CODES; "
        "import it from sraverify.core.aws_errors instead"
    )


# --------------------------------------------------------------------------- #
# The one branching method that needs its own case
# --------------------------------------------------------------------------- #


def test_shield_get_web_acl_for_resource_takes_the_cloudfront_branch() -> None:
    """The adapter drives the wafv2 branch; this covers the other one.

    ``ShieldClient.get_web_acl_for_resource`` branches on whether the ARN
    contains ``cloudfront``. On that branch it calls
    ``cloudfront:GetDistributionConfig`` and, when the distribution has no
    ``WebACLId``, **synthesizes** a ``WAFNonexistentItemException`` error result.

    That synthesis stays after migration: it is a real answer -- AWS said the
    distribution exists and has no Web ACL -- expressed in the error result shape,
    and ``SRA-SHIELD-12`` already reads it. Worth its own test precisely because
    it is the one place a client legitimately *constructs* an error result rather than
    catching an exception, and a reader sweeping for "clients must not classify"
    would otherwise be tempted to delete it.
    """
    target = next(
        t
        for t in _TARGETS
        if t.service == "shield" and t.adapter.method == "get_web_acl_for_resource"
    )
    wrapper, _ = _build_wrapper(target)

    # Reach the memoized cloudfront mock the same way the wrapper will.
    cloudfront = wrapper.ctx.get_client("cloudfront", region="us-east-1")
    cloudfront.get_distribution_config.return_value = {
        "DistributionConfig": {"WebACLId": ""}
    }

    result = wrapper.get_web_acl_for_resource(
        f"arn:aws:cloudfront::{_TEST_ACCOUNT}:distribution/D123"
    )

    assert isinstance(result, Mapping)
    assert "Error" in result, (
        f"expected the synthesized no-Web-ACL answer, got {result!r}"
    )
    assert result["Error"].get("Code") == "WAFNonexistentItemException"
