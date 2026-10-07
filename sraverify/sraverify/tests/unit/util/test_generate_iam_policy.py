"""
Unit tests for ``util/generate_iam_policy.py``.

The generator derives the least-privilege member-role policy from the client
layer and writes it into ``1-sraverify-member-roles.yaml`` between the GENERATED
markers. Requirement 1.12 requires it to be tested against at least ``WAFClient``
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
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

import sraverify

#: Repository root: .../sra-verify, two levels above the package directory.
_REPO_ROOT: Path = Path(sraverify.__file__).resolve().parent.parent.parent
_GENERATOR_PATH: Path = _REPO_ROOT / "util" / "generate_iam_policy.py"
_PACKAGE_ROOT: Path = Path(sraverify.__file__).resolve().parent
_SERVICES_ROOT: Path = _PACKAGE_ROOT / "services"
#: The project root the generator is pointed at (``--base-dir``).
_PROJECT_ROOT: Path = _PACKAGE_ROOT.parent
#: The member-role template the generator writes into.
_TEMPLATE_PATH: Path = _REPO_ROOT / "1-sraverify-member-roles.yaml"


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


@pytest.fixture(scope="module")
def template_text() -> str:
    """The tracked member-role template, decoded byte for byte.

    Returns:
        The template text.
    """
    if not _TEMPLATE_PATH.is_file():
        pytest.skip(f"{_TEMPLATE_PATH} not present")
    return _TEMPLATE_PATH.read_bytes().decode("utf-8")


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


def _client_modules(generator: Any) -> list[Path]:
    """Return every walked module that declares an ``AWSClient`` subclass."""
    out: list[Path] = []
    for name in generator.find_python_modules(str(_PROJECT_ROOT)):
        path = Path(name)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=name)
        if generator.declares_aws_client(tree):
            out.append(path)
    return out


def test_every_client_module_binds_at_least_one_boto3_client(
    generator: Any,
) -> None:
    """A module with no binding contributes nothing, silently.

    This is the exact failure the rewrite fixes: the previous generator bound
    nothing anywhere and emitted an empty policy. Asserting per module means a
    single client changing its acquisition form is caught, rather than only the
    all-or-nothing case. The client modules are found by AST over the walked set
    -- every module declaring an ``AWSClient`` subclass -- so the relocated
    ``core/organizations_client.py`` is one of them.
    """
    modules = _client_modules(generator)
    relative = {p.resolve().relative_to(_PACKAGE_ROOT).as_posix() for p in modules}
    assert "core/organizations_client.py" in relative
    assert "services/organizations/client.py" not in relative
    assert len(modules) == 19, sorted(relative)

    unbound: list[str] = []
    for path in modules:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if not generator.bind_clients(tree):
            unbound.append(path.resolve().relative_to(_PACKAGE_ROOT).as_posix())

    assert unbound == [], (
        f"these client modules bind no boto3 client, so every call in them is "
        f"unattributed and their actions are missing from the policy: {unbound}"
    )


def test_the_generator_attributes_the_whole_tree(generator: Any) -> None:
    """The end-to-end result is non-trivial and covers the expected services."""
    service_calls, warnings = generator.build(str(_PROJECT_ROOT))

    assert warnings == []

    assert len(service_calls) >= 25, (
        f"only {len(service_calls)} boto3 services attributed across the tree; "
        f"the 19 clients reach roughly 30"
    )
    # A spread across all four kinds of client: the service's own API, an
    # organizations call, an STS call, and a call on a service borrowed by another.
    # ``ec2`` and ``account`` are reached from ``core/scan_context.py`` too.
    for expected in (
        "guardduty", "organizations", "sts", "wafv2", "s3control", "sqs", "ec2", "account",
    ):
        assert expected in service_calls, (
            f"{expected} was not attributed anywhere in the tree"
        )


def test_the_template_matches_the_generator(
    generator: Any, template_text: str
) -> None:
    """The deployed ``SRAVerifyLeastPrivilege`` block is what the code derives.

    Splicing the freshly generated policy into the tracked template must be a
    no-op. Anyone who adds a boto3 call without regenerating fails here, before
    the member role fails the call at scan time. Skips outside a full checkout
    (no template or no generator), as the rest of this module does.
    """
    service_calls, _ = generator.build(str(_PROJECT_ROOT))
    policy = generator.generate_iam_policy(service_calls)

    assert generator.splice(template_text, policy) == template_text, (
        f"{_TEMPLATE_PATH.name} is out of date with the boto3 calls the package "
        f"makes. Run: cd sraverify && uv run python ../util/generate_iam_policy.py"
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


# --------------------------------------------------------------------------- #
# The package-wide walk
# --------------------------------------------------------------------------- #

#: The ten operations ``OrganizationsClient`` issues.
_ORGANIZATIONS_OPERATIONS = {
    "describe_organization",
    "list_roots",
    "list_organizational_units_for_parent",
    "list_policies",
    "list_accounts",
    "describe_effective_policy",
    "list_accounts_for_parent",
    "list_delegated_administrators",
    "list_policies_for_target",
    "describe_policy",
}


def _module_calls(generator: Any, path: Path) -> dict[str, set[str]]:
    """Return the attributed calls for one module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return generator.collect_calls(tree, generator.bind_clients(tree))


def test_the_relocated_organizations_client_is_attributed_from_core(
    generator: Any,
) -> None:
    """``core/organizations_client.py`` contributes its ten operations.

    And nothing under ``services/organizations/`` contributes an Organizations
    action: ``OrganizationsCheck`` reaches AWS only through the relocated client.
    """
    core = _module_calls(generator, _PACKAGE_ROOT / "core" / "organizations_client.py")
    assert core == {"organizations": _ORGANIZATIONS_OPERATIONS}

    walked = [Path(p) for p in generator.find_python_modules(str(_PROJECT_ROOT))]
    for path in walked:
        relative = path.resolve().relative_to(_PACKAGE_ROOT).as_posix()
        if relative.startswith("services/organizations/"):
            assert "organizations" not in _module_calls(generator, path), relative
        if relative != "core/organizations_client.py":
            assert "list_accounts" not in _module_calls(generator, path).get(
                "organizations", set()
            ), relative


def test_a_region_literal_does_not_bind(generator: Any) -> None:
    """Property 24: only a known boto3 service id binds a receiver.

    ``client = self.get_client('us-east-1')`` on a service base is a Region
    lookup of the base's own wrapper. Binding it would emit a
    ``Us-east-1Permissions`` statement granting ``us-east-1:GetAdminAccount``.
    """
    region_shape = (
        "class B:\n"
        "    def go(self):\n"
        "        client = self.get_client('us-east-1')\n"
        "        return client.get_admin_account()\n"
    )
    tree = ast.parse(region_shape)
    assert generator.bind_clients(tree) == {}
    assert generator.collect_calls(tree, generator.bind_clients(tree)) == {}

    service_shape = region_shape.replace("'us-east-1'", "'fms'")
    tree = ast.parse(service_shape)
    assert generator.collect_calls(tree, generator.bind_clients(tree)) == {
        "fms": {"get_admin_account"}
    }

    for relative in ("services/firewallmanager/base.py", "services/waf/base.py"):
        assert _module_calls(generator, _PACKAGE_ROOT / relative) == {}, relative


def test_the_session_builder_is_excluded_and_assume_role_is_not_an_action(
    generator: Any,
) -> None:
    """``core/session.py`` is not walked, so ``sts:AssumeRole`` is never granted.

    The operator's principal assumes the member role; the member role does not
    assume itself. ``sts:GetCallerIdentity`` is still derived, from ``core/``.
    """
    assert "core/session.py" in generator.EXCLUDED_MODULES
    assert generator.EXCLUDED_MODULES["core/session.py"].strip()
    walked = {
        Path(p).resolve().relative_to(_PACKAGE_ROOT).as_posix()
        for p in generator.find_python_modules(str(_PROJECT_ROOT))
    }
    assert "core/session.py" not in walked
    assert "core/scan_context.py" in walked

    service_calls, _ = generator.build(str(_PROJECT_ROOT))
    policy = generator.generate_iam_policy(service_calls)
    actions = {a for s in policy["Statement"] for a in s["Action"]}
    assert "sts:AssumeRole" not in actions
    assert "sts:GetCallerIdentity" in actions
    assert {"ec2:DescribeRegions", "account:GetAccountInformation"} <= actions


def test_tests_are_not_walked(generator: Any, tmp_path: Path) -> None:
    """A binding under ``tests/`` or a dot-prefixed directory contributes nothing."""
    package = tmp_path / "sraverify"
    (package / "tests" / "unit").mkdir(parents=True)
    (package / ".venv" / "lib").mkdir(parents=True)
    (package / "core").mkdir()
    (package / "__init__.py").write_text("")
    binding = (
        "class C:\n"
        "    def __init__(self, session):\n"
        "        self.client = session.client('securitylake', region_name='us-east-1')\n"
        "    def go(self):\n"
        "        return self.client.list_log_sources()\n"
    )
    (package / "tests" / "unit" / "fixture.py").write_text(binding)
    (package / ".venv" / "lib" / "client.py").write_text(binding)
    (package / "core" / "plain.py").write_text("X = 1\n")

    walked = [
        Path(p).relative_to(package).as_posix()
        for p in generator.find_python_modules(str(tmp_path))
    ]
    assert walked == ["__init__.py", "core/plain.py"]
    assert generator.build(str(tmp_path)) == ({}, [])

    real = generator.find_python_modules(str(_PROJECT_ROOT))
    assert not any("/tests/" in p.replace("\\", "/") for p in real)


# --------------------------------------------------------------------------- #
# Property 35 -- an unbindable client site warns, wherever it is
# --------------------------------------------------------------------------- #


def _synthetic_package(tmp_path: Path, modules: dict[str, str]) -> Path:
    """Write a minimal ``sraverify`` package under ``tmp_path`` and return the project root."""
    package = tmp_path / "sraverify"
    package.mkdir()
    (package / "__init__.py").write_text("")
    for relative, source in modules.items():
        path = package / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    return tmp_path


def test_the_real_tree_has_no_unbindable_site(generator: Any) -> None:
    """Property 35: a clean tree produces no warning of either kind."""
    _, warnings = generator.build(str(_PROJECT_ROOT))
    assert warnings == []


def test_a_variable_service_id_in_core_warns_with_its_location(
    generator: Any, tmp_path: Path
) -> None:
    """Property 35: a ``core/`` binding through a variable is reported as ``file:line``.

    Not an ``AWSClient`` subclass, so the older warning could not have seen it.
    """
    root = _synthetic_package(
        tmp_path,
        {
            "core/x.py": (
                "class Lookup:\n"
                "    def __init__(self, ctx, some_var, r):\n"
                "        self.client = ctx.get_client(some_var, region=r)\n"
            )
        },
    )

    _, warnings = generator.build(str(root))

    assert len(warnings) == 1, warnings
    assert warnings[0].startswith("core/x.py:3: ")
    assert "does not name a boto3 service id" in warnings[0]


def test_the_two_allowlisted_shapes_do_not_warn(generator: Any, tmp_path: Path) -> None:
    """Property 35: the wrapper lookup and the factory are exempt by shape."""
    root = _synthetic_package(
        tmp_path,
        {
            "core/x.py": (
                "class FooCheck(SecurityCheck):\n"
                "    def f(self, region):\n"
                "        return self.get_client(region)\n"
                "\n"
                "class Ctx:\n"
                "    def get_client(self, service_name, region=None):\n"
                "        return self._session.client(service_name, region_name=region)\n"
            )
        },
    )

    assert generator.build(str(root)) == ({}, [])


def test_the_wrapper_lookup_is_exempt_only_inside_a_check_class(
    generator: Any, tmp_path: Path
) -> None:
    """Property 35: the same call outside a ``*Check`` class is not the wrapper lookup."""
    root = _synthetic_package(
        tmp_path,
        {
            "core/x.py": (
                "class Helper:\n"
                "    def f(self, region):\n"
                "        return self.get_client(region)\n"
            )
        },
    )

    _, warnings = generator.build(str(root))

    assert [w.split(" ", 1)[0] for w in warnings] == ["core/x.py:3:"]


# --------------------------------------------------------------------------- #
# Sids
# --------------------------------------------------------------------------- #


def test_every_sid_is_alphanumeric(generator: Any) -> None:
    """IAM allows only ASCII letters and digits in a Sid.

    ``str.capitalize()`` alone gave ``Cognito-idpPermissions``; now that the
    generator writes the deployed template, an invalid Sid would be a deploy
    failure rather than a cosmetic one.
    """
    service_calls, _ = generator.build(str(_PROJECT_ROOT))
    policy = generator.generate_iam_policy(service_calls)
    bad = [s["Sid"] for s in policy["Statement"] if not re.fullmatch(r"[A-Za-z0-9]+", s["Sid"])]
    assert bad == []


@pytest.mark.parametrize(
    "service,sid",
    [
        ("cognito-idp", "CognitoIdpPermissions"),
        ("security-ir", "SecurityIrPermissions"),
        ("accessanalyzer", "AccessanalyzerPermissions"),
        ("ec2", "Ec2Permissions"),
    ],
)
def test_sid_for(generator: Any, service: str, sid: str) -> None:
    """The Sid is derived from the service id, with no override table."""
    assert generator.sid_for(service) == sid


# --------------------------------------------------------------------------- #
# Splicing the template
# --------------------------------------------------------------------------- #

_BEGIN = (
    "          # BEGIN GENERATED by util/generate_iam_policy.py -- do not edit; "
    "run it to regenerate\n"
)
_END = "          # END GENERATED\n"

#: A small template exercising what the splice must leave alone: short-form
#: tags of all three node kinds, comments, and mixed quoting.
_HEAD = (
    "AWSTemplateFormatVersion: '2010-09-09'\n"
    "# a top-level comment\n"
    "Resources:\n"
    "  Role:\n"
    "    Type: AWS::IAM::Role\n"
    "    Properties:\n"
    "      RoleName: !Sub 'role-${AWS::AccountId}'   # trailing comment\n"
    "      ManagedPolicyArns:\n"
    "        - !Ref SRAVerifyLeastPrivilege\n"
    "      Tags: !If {Cond: [a, b]}\n"
    '      Description: "double \\"quoted\\""\n'
    "  SRAVerifyLeastPrivilege:\n"
    "    Type: AWS::IAM::ManagedPolicy\n"
    "    Properties:\n"
    "      PolicyDocument:\n"
    "        Version: '2012-10-17'\n"
    "        Statement:\n"
)
_STALE = (
    "          - Sid: StalePermissions\n"
    "            Effect: Allow\n"
    "            Action:\n"
    "              - stale:Action\n"
    "            Resource: '*'\n"
)
_TAIL = (
    "  Other:\n"
    "    Type: AWS::IAM::ManagedPolicy\n"
    "    Properties:\n"
    "      PolicyDocument:\n"
    "        Version: '2012-10-17'\n"
    "        Statement:\n"
    "          - Sid: Hand\n"
    "            Effect: Allow\n"
    "            Action: !GetAtt [X, Y]\n"
    "            Resource: \"*\"\n"
)
_SYNTHETIC = _HEAD + _BEGIN + _STALE + _END + _TAIL


def _small_policy(generator: Any) -> dict:
    """A one-statement policy for the synthetic template."""
    return generator.generate_iam_policy({"iam": {"list_users"}})


def _copy_template(tmp_path: Path, template_text: str) -> Path:
    """Copy the real template's bytes into ``tmp_path`` and return the copy."""
    path = tmp_path / _TEMPLATE_PATH.name
    path.write_bytes(template_text.encode("utf-8"))
    return path


def test_the_splice_is_idempotent_on_a_synthetic_template(generator: Any) -> None:
    """Splicing twice gives the same text as splicing once.

    Needs no tracked template, so it runs from an installed wheel too.
    """
    policy = _small_policy(generator)
    once = generator.splice(_SYNTHETIC, policy)
    assert once != _SYNTHETIC
    assert generator.splice(once, policy) == once


def test_the_splice_is_idempotent_on_the_real_template(
    generator: Any, template_text: str
) -> None:
    """Splicing the real template twice gives the same text as splicing once."""
    service_calls, _ = generator.build(str(_PROJECT_ROOT))
    real_policy = generator.generate_iam_policy(service_calls)
    real_once = generator.splice(template_text, real_policy)
    assert generator.splice(real_once, real_policy) == real_once


def test_bytes_outside_the_markers_are_unchanged(generator: Any) -> None:
    """Everything up to BEGIN and from END on is copied through exactly."""
    out = generator.splice(_SYNTHETIC, _small_policy(generator))

    assert out.startswith(_HEAD + _BEGIN)
    assert out.endswith(_END + _TAIL)
    block = out[len(_HEAD + _BEGIN): -len(_END + _TAIL)]
    assert block == (
        "          - Sid: IamPermissions\n"
        "            Effect: Allow\n"
        "            Action:\n"
        "              - iam:ListUsers\n"
        "            Resource: '*'\n"
    )


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(_HEAD + _STALE + _END + _TAIL, id="missing-begin"),
        pytest.param(_HEAD + _BEGIN + _STALE + _TAIL, id="missing-end"),
        pytest.param(_HEAD + _BEGIN + _BEGIN + _STALE + _END + _TAIL, id="duplicate-begin"),
        pytest.param(_HEAD + _BEGIN + _STALE + _END + _END + _TAIL, id="duplicate-end"),
        pytest.param(_HEAD + _END + _STALE + _BEGIN + _TAIL, id="end-before-begin"),
        pytest.param(
            _HEAD + _BEGIN + _STALE + "        # END GENERATED\n" + _TAIL,
            id="end-at-another-indent",
        ),
        pytest.param(
            _HEAD + _BEGIN.replace("  ", "\t", 1) + _STALE + _END + _TAIL,
            id="begin-indented-with-a-tab",
        ),
    ],
)
def test_malformed_markers_are_rejected(generator: Any, text: str) -> None:
    """Every malformed marker layout is a ``TemplateError``."""
    with pytest.raises(generator.TemplateError):
        generator.splice(text, _small_policy(generator))


def test_markers_in_the_wrong_resource_are_rejected(generator: Any) -> None:
    """Markers inside another resource's ``Statement`` list fail the re-parse check.

    The block itself would splice cleanly; only comparing the re-parsed
    ``SRAVerifyLeastPrivilege`` document with the generated one catches it.
    """
    wrong = (
        _HEAD + _STALE + _TAIL.replace(
            "        Statement:\n", "        Statement:\n" + _BEGIN, 1
        ) + _END
    )
    with pytest.raises(generator.TemplateError, match="does not equal"):
        generator.splice(wrong, _small_policy(generator))


# --------------------------------------------------------------------------- #
# The CLI
# --------------------------------------------------------------------------- #


def test_the_defaults_are_relative_to_the_script(generator: Any) -> None:
    """The template and project root resolve from the script, not the cwd."""
    assert generator.DEFAULT_TEMPLATE == _TEMPLATE_PATH
    assert generator.DEFAULT_BASE_DIR == _PROJECT_ROOT


def test_check_exits_0_in_sync(
    generator: Any, template_text: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An in-sync template is reported, and nothing goes to stdout."""
    copy = _copy_template(tmp_path, template_text)

    assert generator.main(["--check", "--template", str(copy)]) == 0

    out, err = capsys.readouterr()
    assert out == ""
    assert "in sync" in err
    assert "headroom" in err
    assert copy.read_bytes() == template_text.encode("utf-8")


def test_check_exits_1_on_drift_shows_the_diff_and_writes_nothing(
    generator: Any, template_text: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A hand edit inside the block is drift: exit 1, a diff, and no write."""
    action = "              - sts:GetCallerIdentity\n"
    assert template_text.count(action) == 1
    stale = template_text.replace(action, "")
    copy = tmp_path / _TEMPLATE_PATH.name
    copy.write_bytes(stale.encode("utf-8"))

    assert generator.main(["--check", "--template", str(copy)]) == 1

    out, err = capsys.readouterr()
    assert out == ""
    assert copy.read_bytes() == stale.encode("utf-8")
    assert "\n+" + action in err
    assert "uv run python ../util/generate_iam_policy.py" in err


def test_write_mode_brings_a_stale_template_into_sync(
    generator: Any, template_text: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """With no flags the template is rewritten, and then ``--check`` agrees."""
    stale = template_text.replace("              - sts:GetCallerIdentity\n", "")
    copy = tmp_path / _TEMPLATE_PATH.name
    copy.write_bytes(stale.encode("utf-8"))

    assert generator.main(["--template", str(copy)]) == 0
    assert copy.read_bytes() == template_text.encode("utf-8")
    assert generator.main(["--check", "--template", str(copy)]) == 0
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("mode", [[], ["--check"]], ids=["write", "check"])
def test_main_exits_2_on_bad_markers_and_writes_nothing(
    generator: Any,
    template_text: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mode: list[str],
) -> None:
    """A template with no BEGIN marker is refused in both modes."""
    broken = template_text.replace(_BEGIN, "")
    assert broken != template_text
    copy = tmp_path / _TEMPLATE_PATH.name
    copy.write_bytes(broken.encode("utf-8"))

    assert generator.main([*mode, "--template", str(copy)]) == 2

    out, err = capsys.readouterr()
    assert out == ""
    assert "BEGIN GENERATED marker not found" in err
    assert copy.read_bytes() == broken.encode("utf-8")


def test_main_exits_2_on_a_missing_template(
    generator: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An unreadable template is a usage problem, not drift."""
    assert generator.main(["--check", "--template", str(tmp_path / "absent.yaml")]) == 2
    assert "cannot read the template" in capsys.readouterr().err


def test_an_oversize_policy_is_refused(
    generator: Any,
    template_text: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Over the managed-policy quota, neither mode writes and both exit 2."""
    policy = _small_policy(generator)
    assert generator.policy_size(policy) == len(json.dumps(policy, separators=(",", ":")))

    stale = template_text.replace("              - sts:GetCallerIdentity\n", "")
    copy = tmp_path / _TEMPLATE_PATH.name
    copy.write_bytes(stale.encode("utf-8"))
    monkeypatch.setattr(generator, "POLICY_SIZE_QUOTA", 100)

    assert generator.main(["--template", str(copy)]) == 2
    assert generator.main(["--check", "--template", str(copy)]) == 2

    out, err = capsys.readouterr()
    assert out == ""
    assert "headroom" in err
    assert "exceeds the 100-character managed-policy quota" in err
    assert copy.read_bytes() == stale.encode("utf-8")


def test_nothing_attributed_exits_1(
    generator: Any, template_text: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A tree with no boto3 binding keeps the existing exit 1, and writes nothing."""
    (tmp_path / "pkg").mkdir()
    root = _synthetic_package(tmp_path / "pkg", {"core/plain.py": "X = 1\n"})
    copy = _copy_template(tmp_path, template_text)

    for mode in ([], ["--check"]):
        assert generator.main([*mode, "--base-dir", str(root), "--template", str(copy)]) == 1

    assert "no boto3 calls were attributed" in capsys.readouterr().err
    assert copy.read_bytes() == template_text.encode("utf-8")


#: A client that attributes ``iam:ListUsers`` -- the same policy as
#: :func:`_small_policy` -- and also binds a second client through a variable,
#: which the generator cannot attribute and must warn about (line 4).
_WARNING_CLIENT = (
    "class C:\n"
    "    def __init__(self, ctx, service):\n"
    "        self.client = ctx.get_client('iam')\n"
    "        self.other = ctx.get_client(service)\n"
    "    def go(self):\n"
    "        return self.client.list_users()\n"
)


def test_check_exits_2_on_a_warning_after_reporting_in_sync(
    generator: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A warning fails ``--check`` even when the template is in sync.

    The unattributed calls are absent from the policy *and* from the template,
    so the two agree; only the warning shows the member role would under-grant.
    """
    (tmp_path / "pkg").mkdir()
    root = _synthetic_package(tmp_path / "pkg", {"core/c.py": _WARNING_CLIENT})
    in_sync = generator.splice(_SYNTHETIC, _small_policy(generator))
    template = tmp_path / "template.yaml"
    template.write_bytes(in_sync.encode("utf-8"))

    assert generator.main(["--check", "--base-dir", str(root), "--template", str(template)]) == 2

    out, err = capsys.readouterr()
    assert out == ""
    assert "WARNING: core/c.py:4: " in err
    assert "is in sync" in err
    assert "1 WARNING(s) above" in err
    assert err.index("is in sync") < err.index("1 WARNING(s) above")
    assert template.read_bytes() == in_sync.encode("utf-8")


def test_write_mode_exits_2_on_a_warning_and_leaves_the_template_unchanged(
    generator: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A warning stops write mode before it writes, though the template is stale."""
    (tmp_path / "pkg").mkdir()
    root = _synthetic_package(tmp_path / "pkg", {"core/c.py": _WARNING_CLIENT})
    template = tmp_path / "template.yaml"
    template.write_bytes(_SYNTHETIC.encode("utf-8"))

    assert generator.main(["--base-dir", str(root), "--template", str(template)]) == 2

    out, err = capsys.readouterr()
    assert out == ""
    assert "WARNING: core/c.py:4: " in err
    assert "was not changed" in err
    assert "wrote" not in err
    assert template.read_bytes() == _SYNTHETIC.encode("utf-8")


def test_the_exempt_shapes_do_not_fail_the_run(
    generator: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The wrapper lookup and the factory stay exempt: write and check both exit 0."""
    (tmp_path / "pkg").mkdir()
    exempt = (
        "class FooCheck(SecurityCheck):\n"
        "    def f(self, region):\n"
        "        return self.get_client(region)\n"
        "\n"
        "class Ctx:\n"
        "    def get_client(self, service_name, region=None):\n"
        "        return self._session.client(service_name, region_name=region)\n"
    )
    root = _synthetic_package(
        tmp_path / "pkg",
        {"core/x.py": exempt, "core/c.py": _WARNING_CLIENT.replace(
            "        self.other = ctx.get_client(service)\n", ""
        )},
    )
    template = tmp_path / "template.yaml"
    template.write_bytes(_SYNTHETIC.encode("utf-8"))
    argv = ["--base-dir", str(root), "--template", str(template)]

    assert generator.main(argv) == 0
    assert generator.main(["--check", *argv]) == 0
    assert "WARNING" not in capsys.readouterr().err


def test_the_real_tree_checks_clean(
    generator: Any, template_text: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The tracked tree and template: ``--check`` exits 0 with no warning."""
    assert generator.main(["--check"]) == 0

    out, err = capsys.readouterr()
    assert out == ""
    assert "WARNING" not in err
    assert "in sync" in err


@pytest.mark.parametrize(
    "argv",
    [["--out-json", "x"], ["--out-yaml", "x"], ["--quiet"], ["--diff-out", "x"]],
    ids=["out-json", "out-yaml", "quiet", "diff-out"],
)
def test_removed_flags_are_usage_errors(generator: Any, argv: list[str]) -> None:
    """The side-artefact flags are gone, and argparse rejects them."""
    with pytest.raises(SystemExit) as excinfo:
        generator.main(argv)
    assert excinfo.value.code == 2
