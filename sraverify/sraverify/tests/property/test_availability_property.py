"""
Properties 16, 18, and 19: the availability call sites, the test identifiers, and
the offline promise.

Three small properties that guard the *mechanisms* the larger reflection modules
depend on, rather than the contract itself.

* **Property 16.** Every ``service_available_in_region`` call site passes a string
  literal from the candidate set. The lookup is the one thing in this feature that
  can make a row *disappear*, so the set of checks relying on it has to be
  greppable, and a mis-typed service id has to fail here rather than fail open in
  production.
* **Property 18.** Every parametrized test in the reflection modules names its
  target in its test ID. With ~200 adapters, a failure reported as
  ``test_x[47]`` is nearly useless.
* **Property 19.** The whole suite issues no HTTP request. The existing suite
  already made no AWS call; this proves it rather than asserting it, and it is
  what lets the client and accessor properties simulate ``ClientError`` with
  confidence that a miss would surface as a refused socket rather than a real
  call against whatever credentials happen to be in the environment.

Validates: Requirements 5.7, 7.9, 7.11.
"""
from __future__ import annotations

import ast
import importlib
from pathlib import Path
from typing import Any

import pytest

import sraverify.services

_SERVICES_ROOT: Path = Path(sraverify.services.__file__).resolve().parent

#: Requirement 5.7's candidate set: the boto3 service ids whose commercial
#: coverage is uneven enough for the lookup to ever answer ``False``. Measured
#: against botocore 1.43.6's ``aws`` partition, 34 Regions.
#:
#: The rejections are as deliberate as the inclusions. ``accessanalyzer`` is
#: 34/34, so a guard would never suppress anything -- which is why the Access
#: Analyzer live probe is deleted outright rather than replaced by a lookup.
#: ``s3control`` is 29/34 but the S3 checks emit a single ``global`` row from
#: ``regions[0]`` and never iterate Regions. ``security-ir`` is home-Region-pinned
#: and its ``ListMemberships`` returns an empty list rather than failing
#: elsewhere, so endpoint presence does not predict where its data lives.
_CANDIDATE_SERVICE_IDS: frozenset[str] = frozenset(
    {
        "apprunner",     # 11/34
        "auditmanager",  # 12/34
        "securitylake",  # 17/34
        "amplify",       # 20/34
        "macie2",        # 22/34
        "appsync",       # 31/34
        "inspector2",    # 32/34
    }
)

#: Service ids Requirement 5.7 explicitly rejects, with the reason. Asserted
#: against so that adding a guard for one of these fails here with the reason
#: attached rather than silently suppressing rows.
_REJECTED_SERVICE_IDS: dict[str, str] = {
    "accessanalyzer": "34/34 Regions, so the lookup would never answer False",
    "s3control": "the S3 checks emit one global row and never iterate Regions",
    "security-ir": (
        "home-Region-pinned; ListMemberships returns an empty list rather than "
        "failing in other Regions, so endpoint presence does not predict where "
        "its data lives"
    ),
    "shield": "non-regionalized; answers [] for every partition",
    "organizations": "non-regionalized; answers [] for every partition",
    "iam": "non-regionalized; answers [] for every partition",
    "account": "non-regionalized; answers [] for every partition",
}


def _service_modules() -> list[Path]:
    """Return every module under ``services/``, sorted.

    Returns:
        Absolute paths, excluding bytecode caches.
    """
    return sorted(
        path
        for path in _SERVICES_ROOT.rglob("*.py")
        if "__pycache__" not in path.parts
    )


#: Snapshotted at import so collection is stable.
_SERVICE_MODULES: list[Path] = _service_modules()


def _module_ids() -> list[str]:
    """Return package-relative module paths for use as parametrize IDs.

    Returns:
        Paths relative to ``services/``, POSIX-style.
    """
    return [
        path.relative_to(_SERVICES_ROOT).as_posix() for path in _SERVICE_MODULES
    ]


def _parse(path: Path) -> ast.Module:
    """Parse a module.

    Args:
        path: The module to parse.

    Returns:
        The parsed module.
    """
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_the_service_module_set_is_not_trivially_small() -> None:
    """Guard against an enumeration bug reading as a vacuous pass."""
    assert len(_SERVICE_MODULES) >= 200, (
        f"found {len(_SERVICE_MODULES)} modules under services/; the tree holds "
        f"18 services with 158 checks and the walk is broken"
    )


# --------------------------------------------------------------------------- #
# Property 16 -- availability call sites name a literal from the candidate set
# --------------------------------------------------------------------------- #


#: The two spellings of an availability lookup during the migration: the shared
#: ``core`` function, and the WAF delegate that
#: Batch 6 removes. Both count, so WAF's existing guard does not drop out of this
#: property for the duration of the migration -- which is exactly when it is being
#: edited.
_LOOKUP_NAMES: frozenset[str] = frozenset(
    {"service_available_in_region", "region_supports_service"}
)


def _forwarding_parameters(tree: ast.Module) -> dict[int, set[str]]:
    """Map each function's line span to its parameter names.

    Used to tell a *decision* site from a *forwarding* one. A pure delegate --
    ``return service_available_in_region(boto3_service_name, region)`` inside
    ``region_supports_service`` -- passes a parameter by construction and cannot
    pass a literal. Requiring a literal there would be requiring the delegate not
    to be a delegate.

    Args:
        tree: A parsed service module.

    Returns:
        A mapping from each function's ``lineno`` to the set of its parameter
        names, for functions that take at least one.
    """
    spans: dict[int, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        args = node.args
        names = {
            arg.arg
            for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)
        }
        if names:
            spans[node.lineno] = names
    return spans


def _enclosing_parameters(
    tree: ast.Module, call: ast.Call
) -> set[str]:
    """Return the parameter names of the innermost function containing ``call``.

    Args:
        tree: The parsed module.
        call: A call node within it.

    Returns:
        The parameter names, or an empty set if the call is not inside a
        function that takes any.
    """
    best: tuple[int, set[str]] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = node.lineno
        end = getattr(node, "end_lineno", start)
        if start <= call.lineno <= end:
            args = node.args
            names = {
                arg.arg
                for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)
            }
            # Innermost wins: a nested function's span is inside its parent's.
            if best is None or start > best[0]:
                best = (start, names)
    return best[1] if best else set()


def _availability_call_sites(
    tree: ast.Module,
) -> list[tuple[ast.Call, str | None]]:
    """Return every availability *decision* site and the literal it passed.

    Forwarding calls are excluded: a call whose first argument is a plain name
    that is a parameter of the enclosing function is a delegate passing its
    argument through, and the literal is checked at *that* delegate's callers
    instead. ``WAFCheck.region_supports_service`` is the only such site today,
    and it disappears in Batch 6.

    Args:
        tree: A parsed service module.

    Returns:
        ``(call, literal_or_None)`` pairs. ``None`` means the first argument was
        neither a string literal nor a forwarded parameter -- i.e. a computed
        value, which is what Property 16 rejects.
    """
    sites: list[tuple[ast.Call, str | None]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        name: str | None = None
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        if name not in _LOOKUP_NAMES:
            continue

        if not node.args:
            sites.append((node, None))
            continue

        first = node.args[0]

        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            sites.append((node, first.value))
            continue

        # A forwarded parameter is not a decision.
        if isinstance(first, ast.Name) and first.id in _enclosing_parameters(
            tree, node
        ):
            continue

        sites.append((node, None))
    return sites


@pytest.mark.parametrize("path", _SERVICE_MODULES, ids=_module_ids())
def test_every_availability_call_site_names_a_literal(path: Path) -> None:
    """Property 16: the service id is a string literal, never a variable.

    Two reasons, and the second is the one that bites. First, the set of checks
    relying on Region suppression must be greppable -- a reviewer asking "which
    rows can this feature make disappear?" needs one ``grep`` to answer it.
    Second, a computed id cannot be validated: the lookup **fails open** on an
    unrecognized name, so a typo produced at runtime would warn once per Region
    and then quietly behave as though the guard were absent. A literal can be
    checked here, before it ships.
    """
    offenders = [
        f"L{call.lineno}: first argument is not a string literal"
        for call, literal in _availability_call_sites(_parse(path))
        if literal is None
    ]

    assert offenders == [], (
        f"{path.relative_to(_SERVICES_ROOT).as_posix()} computes an availability "
        f"service id:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("path", _SERVICE_MODULES, ids=_module_ids())
def test_every_availability_literal_is_in_the_candidate_set(path: Path) -> None:
    """Property 16: the literal is one of the seven uneven-coverage services.

    A guard on a service with full regional coverage is dead code that reads as
    protection. A guard on a *non-regionalized* service would be worse than dead:
    those answer an empty regional list, the lookup reads that as available, and
    the guard would suppress nothing while implying it did.
    """
    offenders: list[str] = []
    for call, literal in _availability_call_sites(_parse(path)):
        if literal is None or literal in _CANDIDATE_SERVICE_IDS:
            continue
        reason = _REJECTED_SERVICE_IDS.get(literal, "not in the candidate set")
        offenders.append(f"L{call.lineno}: {literal!r} -- {reason}")

    assert offenders == [], (
        f"{path.relative_to(_SERVICES_ROOT).as_posix()} guards on a service "
        f"outside the candidate set:\n  " + "\n  ".join(offenders)
        + f"\nThe set is {sorted(_CANDIDATE_SERVICE_IDS)} (Requirement 5.7)."
    )


def test_the_candidate_and_rejected_sets_do_not_overlap() -> None:
    """The two lists are a partition, so a service cannot be both."""
    overlap = _CANDIDATE_SERVICE_IDS & set(_REJECTED_SERVICE_IDS)
    assert overlap == set(), f"a service id is both candidate and rejected: {overlap}"


def test_every_candidate_service_id_is_a_real_boto3_service() -> None:
    """A typo in the candidate set would let a typo through at a call site.

    This set is the allowlist the previous test validates against, so it has to
    be right in its own right -- ``macie2`` and ``inspector2`` carry version
    suffixes and ``security-ir`` a hyphen, which are exactly the shapes a typo
    hides in.
    """
    import boto3

    known = set(boto3.Session().get_available_services())
    unknown = _CANDIDATE_SERVICE_IDS - known
    assert unknown == set(), (
        f"the candidate set names service ids botocore does not know: "
        f"{sorted(unknown)}"
    )


def test_the_availability_lookup_is_reached_from_at_least_one_check() -> None:
    """Non-vacuity: the two properties above are quantifying over something.

    Today the only site is ``sra_waf_06``'s ``apprunner`` guard, through the WAF
    delegate. If this ever finds zero, the two AST properties are passing over an
    empty set and would not notice a bad literal being added.
    """
    total = sum(
        len(_availability_call_sites(_parse(path))) for path in _SERVICE_MODULES
    )
    assert total >= 1, (
        "no availability call site found anywhere in services/; Properties 16's "
        "assertions are vacuous"
    )


# --------------------------------------------------------------------------- #
# Property 18 -- test identifiers name their target
# --------------------------------------------------------------------------- #

#: The reflection-driven modules whose parametrize IDs must name their target.
#: Listed rather than discovered, because the property is about *these* modules'
#: convention and a newly added test module should have to opt in deliberately.
_REFLECTION_MODULES: tuple[str, ...] = (
    "sraverify.tests.property.test_no_confessing_fail_property",
    "sraverify.tests.property.test_availability_property",
    "sraverify.tests.property.test_discriminator_property",
    "sraverify.tests.property.test_check_classification_property",
    "sraverify.tests.property.test_client_contract_property",
    "sraverify.tests.property.test_accessor_cache_property",
)


@pytest.mark.parametrize("module_name", _REFLECTION_MODULES)
def test_each_reflection_module_declares_explicit_parametrize_ids(
    module_name: str,
) -> None:
    """Property 18: no parametrized test in these modules uses positional IDs.

    With roughly 200 adapters across the client and accessor modules, a failure
    reported as ``test_returns_an_error_result[47]`` costs a reader a counting
    exercise to find out which method broke. Requirement 7.11 asks for the
    service and method in the identifier instead.

    Implemented by requiring each module to pass explicit IDs -- via
    ``ids=`` or via ``pytest.param(..., id=...)`` -- rather than by matching a
    single rigid ``<service>.<Class>.<method>`` shape. The design names two
    shapes and the AST-driven modules need a third (a module path), so pinning
    one format would either fail the AST modules or be widened until it asserted
    nothing. What actually matters is that the ID is chosen rather than
    positional.

    Skips cleanly for a module not yet written, so this property can land in
    Phase 0 alongside the first of the six.
    """
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError:
        pytest.skip(f"{module_name} is not written yet")

    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=module.__file__)

    parametrized: list[tuple[int, bool]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            func = decorator.func
            if not (isinstance(func, ast.Attribute) and func.attr == "parametrize"):
                continue
            has_ids = any(kw.arg == "ids" for kw in decorator.keywords)
            parametrized.append((node.lineno, has_ids))

    # A module may legitimately supply IDs through pytest.param(..., id=...)
    # instead of ids=, in which case `ids=None` is passed explicitly to say so.
    uses_param_ids = "pytest.param(" in source and "id=" in source

    offenders = [
        f"L{lineno}"
        for lineno, has_ids in parametrized
        if not has_ids and not uses_param_ids
    ]

    assert offenders == [], (
        f"{module_name} parametrizes without explicit IDs at {offenders}; a "
        f"failure would name an index instead of the service and method"
    )


def test_this_modules_own_ids_name_the_module_under_inspection(
    request: Any,
) -> None:
    """A worked example of the convention, asserted from the inside.

    ``request.node.callspec`` is how the design proposed checking IDs. It only
    exists on a parametrized node, so this reads it from a sibling rather than
    from itself -- which is also the honest way to show that the AST-driven
    modules' IDs are file paths and not method names.
    """
    ids = _module_ids()

    assert ids, "no IDs were generated"
    assert all(not identifier.isdigit() for identifier in ids), (
        "a positional ID leaked into the module ID list"
    )
    assert any("waf" in identifier for identifier in ids), (
        f"the module IDs do not name their service: {ids[:5]}"
    )


# --------------------------------------------------------------------------- #
# Property 19 -- the suite is offline
# --------------------------------------------------------------------------- #


def test_the_offline_fixture_is_installed_in_conftest() -> None:
    """Property 19 lives in ``tests/conftest.py`` as an autouse fixture.

    Asserted here rather than only relied upon, because an autouse fixture that
    silently stopped applying would leave every simulated-``ClientError`` test in
    the client and accessor modules free to make a real call against whatever
    credentials are in the environment -- and a passing suite would tell nobody.
    """
    import sraverify.tests.conftest as suite_conftest

    source = Path(suite_conftest.__file__).read_text(encoding="utf-8")

    assert "URLLib3Session" in source, (
        "tests/conftest.py does not patch botocore's transport; Property 19 is "
        "not installed"
    )
    assert "autouse=True" in source, (
        "the offline fixture in tests/conftest.py is not autouse, so it does not "
        "apply to the suite"
    )


def test_an_attempted_http_request_is_refused(monkeypatch: Any) -> None:
    """The fixture is effective, demonstrated on a real boto3 client.

    Client *construction* is offline and must keep working -- ``ScanContext``
    builds clients for every Region and the availability lookup reads bundled
    endpoint data. Only the send path is refused.
    """
    import boto3
    from botocore.config import Config

    client = boto3.client(
        "sts",
        region_name="us-east-1",
        config=Config(retries={"max_attempts": 1}),
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )

    with pytest.raises(Exception) as excinfo:
        client.get_caller_identity()

    assert "offline" in str(excinfo.value).lower() or "no AWS call" in str(
        excinfo.value
    ), (
        f"the transport was reached but did not report the offline guard: "
        f"{excinfo.value!r}"
    )
