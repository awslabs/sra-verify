"""
Unit tests for ``util/generate_iam_policy.py``.

The generator derives the least-privilege member-role policy from the client
layer. Requirement 1.12 requires it to be tested against at least ``WAFClient``
(nine boto3 services) and ``ShieldClient`` (five), so that **multi-service
attribution is proven rather than assumed**.

That is the interesting part. A single-service client can be attributed by any
regex; a client holding nine cannot. ``self.wafv2_client.get_web_acl_for_resource``
and ``self.apprunner_client.list_services`` live in the same module, and telling
them apart means reading ``__init__`` to bind each attribute to the service id it
was constructed for.

The rewrite these tests accompany was not cosmetic. The previous implementation
matched ``session.client('<svc>')`` with regular expressions, and **nothing has
used that form since the scan-context refactor** -- every client now goes through
``ctx.get_client(...)``. So it matched nothing and emitted
``{"Statement": []}``: its output was derived from nothing, which also means
"the generated policy is unchanged" was not evidence of anything. These tests
exist so that cannot recur silently.
"""
from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

import sraverify

#: Repository root: .../sra-verify, two levels above the package directory.
_REPO_ROOT: Path = Path(sraverify.__file__).resolve().parent.parent.parent
_GENERATOR_PATH: Path = _REPO_ROOT / "util" / "generate_iam_policy.py"
_SERVICES_ROOT: Path = Path(sraverify.__file__).resolve().parent / "services"


def _load_generator() -> Any:
    """Import ``util/generate_iam_policy.py`` by path.

    ``util/`` is not a package and is not on ``sys.path`` -- the generator is a
    script run from the repository root. Loading it by path is how a test reaches
    it without adding a shim.

    Returns:
        The imported module.
    """
    spec = importlib.util.spec_from_file_location(
        "_sraverify_iam_policy_generator", _GENERATOR_PATH
    )
    assert spec is not None and spec.loader is not None, (
        f"could not load {_GENERATOR_PATH}"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")


def generator() -> Any:
    """The generator module.

    Returns:
        The imported module.
    """
    if not _GENERATOR_PATH.is_file():
        pytest.skip(f"{_GENERATOR_PATH} not present")
    return _load_generator()


def _attributed(generator: Any, service: str) -> dict[str, set[str]]:
    """Return the calls attributed for one service's ``client.py``.

    Args:
        generator: The generator module.
        service: A service package name.

    Returns:
        ``{boto3_service_id: {method, ...}}``.
    """
    path = _SERVICES_ROOT / service / "client.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    bindings = generator.bind_clients(tree)
    return generator.collect_calls(tree, bindings)


# --------------------------------------------------------------------------- #
# Requirement 1.12 -- WAFClient's nine services
# --------------------------------------------------------------------------- #

#: The exact attribution expected for ``services/waf/client.py``. Nine boto3
#: services from one wrapper, which is what makes receiver attribution necessary
#: rather than convenient.
_WAF_EXPECTED: dict[str, set[str]] = {
    "cloudfront": {"list_distributions"},
    "elbv2": {"describe_load_balancers"},
    "wafv2": {
        "get_logging_configuration",
        "get_web_acl_for_resource",
        "list_web_acls",
    },
    "apigateway": {"get_rest_apis", "get_stages"},
    "appsync": {"list_graphql_apis"},
    "cognito-idp": {"list_user_pools"},
    "apprunner": {"list_services"},
    "ec2": {"describe_verified_access_instances"},
    "amplify": {"list_apps"},
}

#: The exact attribution expected for ``services/shield/client.py``.
#:
#: Five services, four of which are acquired **inside a method body** today --
#: ``lambda``, ``cloudfront``, ``wafv2``, ``cloudwatch``. Requirement 1.11 moves
#: all four into ``__init__``. The generator binds a local assignment as well as an
#: attribute assignment precisely so this attribution is correct both before and
#: after that move; if it only read ``__init__``, Shield would lose four services'
#: worth of actions until Batch 6 landed.
_SHIELD_EXPECTED: dict[str, set[str]] = {
    "shield": {
        "describe_subscription",
        "get_subscription_state",
        "list_protections",
        "describe_drt_access",
    },
    "lambda": {"get_function"},
    "cloudfront": {"get_distribution_config"},
    "wafv2": {"get_web_acl_for_resource"},
    "cloudwatch": {"describe_alarms_for_metric"},
}


def test_waf_client_attributes_nine_services_exactly(generator: Any) -> None:
    """Requirement 1.12: the nine-service case, asserted exactly.

    Both directions. A missing service would silently drop actions from the
    policy and the member role would start failing calls at scan time; an extra
    one would grant permissions nothing needs, which is the opposite of least
    privilege.
    """
    attributed = _attributed(generator, "waf")

    assert set(attributed) == set(_WAF_EXPECTED), (
        f"WAFClient attribution covers {sorted(attributed)}, expected "
        f"{sorted(_WAF_EXPECTED)}"
    )
    for service, expected in _WAF_EXPECTED.items():
        assert attributed[service] == expected, (
            f"WAFClient/{service}: attributed {sorted(attributed[service])}, "
            f"expected {sorted(expected)}"
        )


def test_shield_client_attributes_five_services_exactly(generator: Any) -> None:
    """Requirement 1.12: the five-service case, including in-method acquisition.

    Four of Shield's five clients are acquired inside a method body today. If the
    generator read only ``__init__``, this would attribute one service and the
    policy would lose ``lambda:GetFunction``, ``cloudfront:GetDistributionConfig``,
    ``wafv2:GetWebAclForResource``, and ``cloudwatch:DescribeAlarmsForMetric``.
    """
    attributed = _attributed(generator, "shield")

    assert set(attributed) == set(_SHIELD_EXPECTED), (
        f"ShieldClient attribution covers {sorted(attributed)}, expected "
        f"{sorted(_SHIELD_EXPECTED)}"
    )
    for service, expected in _SHIELD_EXPECTED.items():
        assert attributed[service] == expected, (
            f"ShieldClient/{service}: attributed {sorted(attributed[service])}, "
            f"expected {sorted(expected)}"
        )


def test_a_multi_service_client_does_not_collapse_shared_method_names(
    generator: Any,
) -> None:
    """``get_web_acl_for_resource`` exists on both ``wafv2`` and (as a dependent
    permission) ``cognito-idp``, and must not be attributed to the wrong one.

    This is the failure mode a name-based approach has: the method name alone
    cannot say which client issued it, and Shield *and* WAF both call
    ``wafv2:GetWebACLForResource`` from different modules.
    """
    waf = _attributed(generator, "waf")

    assert "get_web_acl_for_resource" in waf["wafv2"]
    assert "get_web_acl_for_resource" not in waf.get("cognito-idp", set()), (
        "the wafv2 call was attributed to cognito-idp; the dependent permission "
        "is added by generate_iam_policy, not by attribution"
    )
    assert "get_web_acl_for_resource" not in waf.get("apprunner", set())


# --------------------------------------------------------------------------- #
# Attribution over the whole tree
# --------------------------------------------------------------------------- #


def test_every_client_module_binds_at_least_one_boto3_client(
    generator: Any,
) -> None:
    """A module with no binding contributes nothing, silently.

    This is the exact failure the rewrite fixes: the previous generator bound
    nothing anywhere and emitted an empty policy. Asserting per module means a
    single client changing its acquisition form is caught, rather than only the
    all-or-nothing case.
    """
    unbound: list[str] = []
    for path in sorted(_SERVICES_ROOT.rglob("client.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if not generator.bind_clients(tree):
            unbound.append(path.parent.name)

    assert unbound == [], (
        f"these client modules bind no boto3 client, so every call in them is "
        f"unattributed and their actions are missing from the policy: {unbound}"
    )


def test_the_generator_attributes_the_whole_tree(generator: Any) -> None:
    """The end-to-end result is non-trivial and covers the expected services."""
    service_calls, _ = generator.build(str(_SERVICES_ROOT.parent.parent))

    assert len(service_calls) >= 25, (
        f"only {len(service_calls)} boto3 services attributed across the tree; "
        f"the 18 clients reach roughly 30"
    )
    # A spread across all four kinds of client: the service's own API, an
    # organizations call, an STS call, and a call on a service borrowed by another.
    for expected in ("guardduty", "organizations", "sts", "wafv2", "s3control", "sqs"):
        assert expected in service_calls, (
            f"{expected} was not attributed anywhere in the tree"
        )


def test_the_generated_policy_reproduces_the_committed_artefact(
    generator: Any,
) -> None:
    """Task 10.3: regenerating must be a no-op against the committed files.

    This is the assertion that gives "the generated policy is unchanged" its
    meaning back. It was **not** true before the rewrite -- the generator emitted
    an empty policy -- and it is worth holding continuously rather than checking
    once, because the artefacts feed a deployed IAM managed policy.

    Compares the policy *document*, not the file bytes, so this does not fail on
    a JSON formatting change.
    """
    import json

    committed_path = _REPO_ROOT / "generated_sraverify_iam_policy.json"
    if not committed_path.is_file():
        pytest.skip("no committed policy artefact to compare against")

    service_calls, _ = generator.build(str(_SERVICES_ROOT.parent.parent))
    derived = generator.generate_iam_policy(service_calls)
    committed = json.loads(committed_path.read_text(encoding="utf-8"))

    derived_actions = {a for s in derived["Statement"] for a in s["Action"]}
    committed_actions = {a for s in committed["Statement"] for a in s["Action"]}

    missing = committed_actions - derived_actions
    extra = derived_actions - committed_actions

    assert missing == set(), (
        f"the committed policy grants actions the code no longer derives: "
        f"{sorted(missing)}. If an API call was genuinely removed, regenerate the "
        f"artefacts and update 1-sraverify-member-roles.yaml in the same change."
    )
    assert extra == set(), (
        f"the code makes calls the committed policy does not grant: "
        f"{sorted(extra)}. The member role would fail these at scan time. "
        f"Regenerate the artefacts and update 1-sraverify-member-roles.yaml."
    )


# --------------------------------------------------------------------------- #
# The pieces
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "method,action",
    [
        ("get_detector", "GetDetector"),
        ("list_organization_admin_accounts", "ListOrganizationAdminAccounts"),
        ("describe_configuration_aggregator_sources_status",
         "DescribeConfigurationAggregatorSourcesStatus"),
        ("get_caller_identity", "GetCallerIdentity"),
        ("get_ebs_encryption_by_default", "GetEbsEncryptionByDefault"),
    ],
)


def test_method_names_convert_to_pascal_case_actions(
    generator: Any, method: str, action: str
) -> None:
    """The snake_case to PascalCase conversion, on real method names."""
    assert generator.convert_to_api_action(method) == action


def test_the_s3control_public_access_block_maps_to_an_s3_action(
    generator: Any,
) -> None:
    """``s3control:GetPublicAccessBlock`` is authorized as
    ``s3:GetAccountPublicAccessBlock``.

    An account-level public access block is read through the ``s3control``
    endpoint but authorized under the ``s3`` prefix. Getting this wrong would
    grant a permission that does not exist and deny the one that does -- and
    ``SRA-S3-01`` through ``-04`` would fail at scan time with ``AccessDenied``,
    which after this feature they would correctly report as an ERROR.
    """
    policy = generator.generate_iam_policy(
        {"s3control": {"get_public_access_block"}}
    )
    actions = {a for s in policy["Statement"] for a in s["Action"]}

    assert "s3:GetAccountPublicAccessBlock" in actions
    assert not any(a.startswith("s3control:") for a in actions), (
        f"an s3control action survived the mapping: {sorted(actions)}"
    )


def test_api_gateway_is_authorized_by_http_verb(generator: Any) -> None:
    """API Gateway authorizes reads as ``apigateway:GET``, not per operation."""
    policy = generator.generate_iam_policy(
        {"apigateway": {"get_rest_apis", "get_stages"}}
    )
    actions = {a for s in policy["Statement"] for a in s["Action"]}

    assert actions == {"apigateway:GET"}


def test_access_analyzer_uses_its_hyphenated_iam_prefix(generator: Any) -> None:
    """The boto3 service id is ``accessanalyzer``; the IAM prefix is
    ``access-analyzer``.

    One of the display-name-versus-prefix mismatches that also motivated
    Requirement 4.8's ban on composing an IAM action from ``meta.service``.
    """
    policy = generator.generate_iam_policy({"accessanalyzer": {"list_analyzers"}})
    actions = {a for s in policy["Statement"] for a in s["Action"]}

    assert actions == {"access-analyzer:ListAnalyzers"}


def test_elbv2_uses_the_elasticloadbalancing_prefix(generator: Any) -> None:
    """``elbv2`` is the boto3 id; ``elasticloadbalancing`` is the IAM prefix."""
    policy = generator.generate_iam_policy({"elbv2": {"describe_load_balancers"}})
    actions = {a for s in policy["Statement"] for a in s["Action"]}

    assert actions == {"elasticloadbalancing:DescribeLoadBalancers"}


def test_the_web_acl_dependent_permissions_are_added(generator: Any) -> None:
    """``wafv2:GetWebACLForResource`` needs four companions.

    AWS requires the caller to hold the *target* service's own web-ACL read
    permission as well: Cognito, App Runner, and Verified Access each have one.
    Without them ``SRA-WAF-02`` and its siblings fail on resources of those types
    only, which is the kind of partial failure that is easy to misread.
    """
    policy = generator.generate_iam_policy({"wafv2": {"get_web_acl_for_resource"}})
    actions = {a for s in policy["Statement"] for a in s["Action"]}

    assert "wafv2:GetWebAcl" in actions
    assert "cognito-idp:GetWebAclForResource" in actions
    assert "apprunner:DescribeWebAclForService" in actions
    assert "ec2:GetVerifiedAccessInstanceWebAcl" in actions


def test_paginated_operations_are_attributed_by_their_literal(
    generator: Any,
) -> None:
    """``get_paginator('list_users')`` contributes ``ListUsers``, not
    ``GetPaginator``.

    Eight methods in the tree paginate. Attributing the wrapper call instead of
    the operation would grant a permission that does not exist and omit the one
    that does.
    """
    source = (
        "class C:\n"
        "    def __init__(self, ctx):\n"
        "        self.client = ctx.get_client('iam')\n"
        "    def list_users(self):\n"
        "        return self.client.get_paginator('list_users').paginate()\n"
    )
    tree = ast.parse(source)
    calls = generator.collect_calls(tree, generator.bind_clients(tree))

    assert calls == {"iam": {"list_users"}}


def test_boto3_internal_methods_are_not_attributed(generator: Any) -> None:
    """``can_paginate`` and friends reach no AWS API and are not permissions."""
    source = (
        "class C:\n"
        "    def __init__(self, ctx):\n"
        "        self.client = ctx.get_client('iam')\n"
        "    def go(self):\n"
        "        self.client.can_paginate('list_users')\n"
        "        self.client.get_waiter('x')\n"
        "        return self.client.list_users()\n"
    )
    tree = ast.parse(source)
    calls = generator.collect_calls(tree, generator.bind_clients(tree))

    assert calls == {"iam": {"list_users"}}


def test_an_unbound_receiver_is_not_attributed(generator: Any) -> None:
    """A call on something that is not a bound boto3 client is ignored.

    Otherwise ``self.ctx.get_account_info()`` or ``self.region.upper()`` would be
    read as AWS operations and the policy would grant nonsense.
    """
    source = (
        "class C:\n"
        "    def __init__(self, ctx):\n"
        "        self.client = ctx.get_client('iam')\n"
        "        self.region = 'us-east-1'\n"
        "    def go(self):\n"
        "        self.ctx.get_account_info()\n"
        "        self.region.upper()\n"
        "        return self.client.list_users()\n"
    )
    tree = ast.parse(source)
    calls = generator.collect_calls(tree, generator.bind_clients(tree))

    assert calls == {"iam": {"list_users"}}


def test_a_migrated_client_method_is_still_attributed(generator: Any) -> None:
    """The migrated handler shape does not disturb attribution.

    The call being attributed now sits inside a ``try``, and the ``except``
    contains a method call of its own. The collector must still see exactly the
    boto3 call and not, say, attribute ``aws_error`` to ``iam`` as a tenth action
    -- which would put a non-existent ``iam:AwsError`` in the member-role policy.

    This replaces a pair of tests for a cross-check that no longer exists. The
    generator used to compare an ``operation=`` literal in each handler against
    the receiver method; ``aws_error`` reads the operation from botocore instead,
    so there is no literal and no second opinion to reconcile.
    """
    source = (
        "class C(AWSClient):\n"
        "    def __init__(self, region, ctx):\n"
        "        super().__init__(region, ctx)\n"
        "        self.client = ctx.get_client('iam')\n"
        "    def list_users(self):\n"
        "        try:\n"
        "            return self.client.list_users()\n"
        "        except AWS_EXCEPTIONS as e:\n"
        "            return self.aws_error(e)\n"
    )
    tree = ast.parse(source)

    calls = generator.collect_calls(tree, generator.bind_clients(tree))

    assert calls == {"iam": {"list_users"}}


def test_the_generator_no_longer_exposes_a_literal_cross_check(
    generator: Any,
) -> None:
    """The removed surface stays removed.

    Both helpers scanned for a ``sentinel_from(..., operation='X')`` literal that
    no client contains. Left in place they would have gone on reporting zero
    warnings forever -- a check that cannot fail, which reads like coverage and
    is not. If either name comes back, the design question it answered has been
    reopened and this test should be deleted deliberately rather than by accident.
    """
    for name in ("collect_operation_literals", "cross_check_literals"):
        assert not hasattr(generator, name), (
            f"{name} is back; it scanned for an operation literal that "
            f"AWSClient.aws_error made unnecessary"
        )


def test_the_legacy_session_client_form_is_still_recognized(generator: Any) -> None:
    """``session.client(...)`` still binds, so a reverted module is not silently lost.

    The form is unused today. Keeping it costs one branch and means the generator
    degrades to a warning rather than to an empty policy if a client is ever
    written that way again -- which is exactly how the previous silence happened.
    """
    source = (
        "class C:\n"
        "    def __init__(self, session):\n"
        "        self.client = session.client('iam')\n"
        "    def go(self):\n"
        "        return self.client.list_users()\n"
    )
    tree = ast.parse(source)
    calls = generator.collect_calls(tree, generator.bind_clients(tree))

    assert calls == {"iam": {"list_users"}}
