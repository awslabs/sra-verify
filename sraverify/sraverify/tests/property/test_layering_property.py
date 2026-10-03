"""
Layering: ``core/`` never reaches into ``services/``, and Organizations data has
one owner.

Static, by AST (and, for Property 30, source text). Nothing here imports a check
or issues a call, and every file read is a package ``.py`` located from
``sraverify.__file__``, so the module runs unchanged from an installed wheel.

* Property 10 -- no module under ``core/`` imports ``sraverify.services`` or names
  it in a string literal. No exemption for ``core/discovery.py``: it receives the
  package name from its caller.
* Property 11 -- no service base class inherits anything between itself and
  ``SecurityCheck``. The ``vars(base)`` enumeration of the accessor tables is then
  a complete statement about each base.
* Property 12 -- no package code (tests included) uses a retired shared-accessor
  name, by AST. Docstrings, comments and Markdown may name the history.
* Property 15 -- no service base imports or constructs ``OrganizationsClient``,
  ``OrganizationsCheck`` included; no check reaches the context's cache or the
  provider's client directly (AST attribute match on the receiver).
* Property 41 -- only the provider's client issues an Organizations operation:
  the boto3 spellings of every ``OrganizationsProvider.OWNED_OPERATIONS`` entry
  appear in ``core/organizations_client.py`` only, the wrapper methods are called
  only by the provider or through ``self.organization``, only that client binds
  an ``organizations`` boto3 client, and only it and the provider name
  ``OrganizationsClient``. Replaces Phase 1's ``ListAccounts``-only Property 8.
* Property 42 -- no service base reads the ``organizations`` namespace by key,
  and ``OrganizationsCheck`` makes no ``_has`` / ``_get`` / ``_set`` call at all.
* Property 30 -- each of the fifteen consumer checks reads the account list
  through ``self.organization.accounts()``, once.
* Property 34 -- every boto3 binding in ``core/``, ``scanner.py``, ``cli.py``
  and ``utils/`` names its Region with a non-literal value.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

import sraverify
from sraverify.core.check import SecurityCheck
from sraverify.core.organization import OrganizationsProvider
from sraverify.tests.property.test_accessor_cache_property import (
    _base_class,
    _service_names,
)

#: Every path below is derived from the installed package, never from the
#: repository, so this module runs unchanged from a wheel.
_PACKAGE_ROOT: Path = Path(sraverify.__file__).resolve().parent
_CORE_ROOT: Path = _PACKAGE_ROOT / "core"
_SERVICES_ROOT: Path = _PACKAGE_ROOT / "services"
_SERVICES_PACKAGE = "sraverify.services"

#: The names of the shared accessor this design retired. Spelled here and nowhere
#: else; this module is excluded from its own walk.
_RETIRED_NAMES = (
    "OrganizationAccountsMixin",
    "ORGANIZATION_ACCOUNTS_NAMESPACE",
    "ORGANIZATION_ACCOUNTS_KEY",
    "get_organization_accounts",
)

#: The fifteen checks that read the organization's account list.
_CONSUMERS = (
    "inspector/checks/sra_inspector_07.py",
    "macie/checks/sra_macie_07.py",
    "organizations/checks/sra_organizations_12.py",
    "securityhub/checks/sra_securityhub_08.py",
    "securityhub/checks/sra_securityhub_17.py",
    "securityincidentresponse/checks/sra_securityincidentresponse_04.py",
    "securitylake/checks/sra_securitylake_01.py",
    *(f"securitylake/checks/sra_securitylake_{n:02d}.py" for n in range(6, 14)),
)


def _python_files(root: Path) -> list[Path]:
    """Return every ``.py`` under ``root``, sorted, skipping ``__pycache__``."""
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _rel(path: Path) -> str:
    """Return ``path`` relative to the package directory, POSIX-style."""
    return path.relative_to(_PACKAGE_ROOT).as_posix()


# --------------------------------------------------------------------------- #
# Property 10 -- core never imports services
# --------------------------------------------------------------------------- #


def _names_services(module: str | None) -> bool:
    """Return whether a dotted module name is ``sraverify.services`` or inside it."""
    return module is not None and (
        module == _SERVICES_PACKAGE or module.startswith(f"{_SERVICES_PACKAGE}.")
    )


def _resolve_relative(path: Path, node: ast.ImportFrom) -> str:
    """Resolve a relative ``from`` import in a ``core/`` module to a dotted name."""
    package_parts = ["sraverify", *path.parent.relative_to(_PACKAGE_ROOT).parts]
    base = package_parts[: len(package_parts) - (node.level - 1)]
    return ".".join([*base, *([node.module] if node.module else [])])


@pytest.mark.parametrize("path", _python_files(_CORE_ROOT), ids=_rel)
def test_no_core_module_imports_services(path: Path) -> None:
    """Property 10: the import graph runs one way, ``services`` -> ``core``."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offenders += [
                f"{node.lineno}: import {a.name}" for a in node.names if _names_services(a.name)
            ]
        elif isinstance(node, ast.ImportFrom):
            target = node.module if node.level == 0 else _resolve_relative(path, node)
            if _names_services(target) or (
                node.level == 0
                and node.module == "sraverify"
                and any(a.name == "services" for a in node.names)
            ):
                offenders.append(f"{node.lineno}: from {target} import ...")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.startswith(_SERVICES_PACKAGE):
                offenders.append(f"{node.lineno}: string {node.value[:60]!r}")
    assert offenders == [], f"{_rel(path)} reaches into sraverify.services: {offenders}"


def test_the_core_walk_is_not_empty() -> None:
    """Property 10 quantifies over the real ``core/``, provider modules included."""
    names = {p.name for p in _python_files(_CORE_ROOT)}
    assert {"organization.py", "organizations_client.py", "scan_context.py"} <= names


# --------------------------------------------------------------------------- #
# Property 11 -- nothing between a service base and SecurityCheck
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("service", _service_names())
def test_no_service_base_inherits_anything_but_security_check(service: str) -> None:
    """Property 11: a base's MRO goes straight to ``SecurityCheck``."""
    base = _base_class(service)
    mro = base.__mro__
    between = [
        klass.__name__
        for klass in mro[1 : mro.index(SecurityCheck)]
        if klass.__name__ not in {"ABC", "object"}
    ]
    assert between == [], (
        f"{base.__name__} inherits {between} between itself and SecurityCheck; "
        f"organization data is reached through self.organization, not a mixin"
    )


# --------------------------------------------------------------------------- #
# Property 12 -- the retired names are gone from package code
# --------------------------------------------------------------------------- #

#: The module the retired accessor lived in. Importing from it is a hit too.
_RETIRED_MODULE = "sraverify.services.organizations.accounts"


def _code_identifiers(tree: ast.AST) -> list[tuple[int, str]]:
    """Every identifier the code *uses*, with its line -- never docstrings or comments.

    Collected: ``Name.id``, ``Attribute.attr``, import ``alias.name`` /
    ``alias.asname`` (and each dotted segment of an ``import a.b.c``),
    ``ImportFrom.module`` and its dotted segments, function and class names,
    and assignment targets (which are ``Name`` / ``Attribute`` nodes and so
    already covered). A string constant is deliberately not an identifier, so
    prose -- docstrings, comments, Markdown -- may name the history and a
    Phase 2 doc can explain the migration.
    """
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Name):
            found.append((line, node.id))
        elif isinstance(node, ast.Attribute):
            found.append((line, node.attr))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.append((line, node.name))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.ImportFrom) and node.module:
                found.append((line, node.module))
                found += [(line, part) for part in node.module.split(".")]
            for alias in node.names:
                found.append((line, alias.name))
                found += [(line, part) for part in alias.name.split(".")]
                if alias.asname:
                    found.append((line, alias.asname))
    return found


def _retired_hits(source: str, label: str) -> list[str]:
    """Return ``label:line: name`` for every retired identifier or module in ``source``."""
    hits = [
        f"{label}:{line}: {name}"
        for line, name in _code_identifiers(ast.parse(source))
        if name in _RETIRED_NAMES or name == _RETIRED_MODULE
    ]
    return sorted(set(hits))


def _package_code() -> list[Path]:
    """Every package ``.py`` except this module, which spells the names to ban them."""
    this = Path(__file__).resolve()
    return [p for p in _python_files(_PACKAGE_ROOT) if p.resolve() != this]


def test_the_retired_shared_accessor_names_appear_nowhere() -> None:
    """Property 12: no package code uses the retired accessor, by AST.

    Reads only the package's own ``.py`` files, located from
    ``sraverify.__file__``, so it runs unchanged from an installed wheel.
    """
    hits = [
        hit
        for path in _package_code()
        for hit in _retired_hits(path.read_text(encoding="utf-8"), _rel(path))
    ]
    assert hits == [], "retired names still present:\n  " + "\n  ".join(hits)
    assert not (_SERVICES_ROOT / "organizations" / "accounts.py").exists()


def test_the_retired_name_extractor_sees_code_and_not_prose() -> None:
    """Property 12 is not vacuous: code is caught, docstrings and comments are not."""
    code = (
        "from sraverify.services.organizations.accounts import OrganizationAccountsMixin\n"
        "class X(OrganizationAccountsMixin):\n"
        "    def f(self):\n"
        "        return self.get_organization_accounts()\n"
    )
    prose = (
        '"""The OrganizationAccountsMixin and get_organization_accounts are retired."""\n'
        "# ORGANIZATION_ACCOUNTS_KEY was the cache key.\n"
        "x = 'ORGANIZATION_ACCOUNTS_NAMESPACE'\n"
    )
    code_hits = _retired_hits(code, "code")
    assert any("OrganizationAccountsMixin" in h for h in code_hits)
    assert any("get_organization_accounts" in h for h in code_hits)
    assert any(_RETIRED_MODULE in h for h in code_hits)
    assert _retired_hits(prose, "prose") == []
    assert len(_package_code()) > 100


# --------------------------------------------------------------------------- #
# Property 15 -- one binding of OrganizationsClient, no cache reach-through
# --------------------------------------------------------------------------- #


def _imports_name(tree: ast.AST, name: str) -> bool:
    """Return whether ``tree`` imports ``name`` by any ``from`` import."""
    return any(
        isinstance(node, ast.ImportFrom) and any(a.name == name for a in node.names)
        for node in ast.walk(tree)
    )


@pytest.mark.parametrize(
    "path",
    # Every base, OrganizationsCheck included: all of them reach Organizations
    # through self.organization.
    sorted(_SERVICES_ROOT.glob("*/base.py")),
    ids=lambda p: f"{p.parent.name}/base.py",
)
def test_no_base_binds_the_organizations_client(path: Path) -> None:
    """Property 15: no service base imports or constructs the client."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    assert not _imports_name(tree, "OrganizationsClient")
    constructs = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == "OrganizationsClient")
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "OrganizationsClient")
        )
    ]
    assert constructs == [], f"constructs OrganizationsClient at {constructs}"


_CACHE_PRIMITIVES = frozenset({"_has", "_get", "_set"})
_CONTEXT_NAMES = frozenset({"_ctx", "ctx"})


def _is_context(node: ast.AST) -> bool:
    """Whether ``node`` names the scan context: ``<any>._ctx``, ``<any>.ctx``, ``_ctx``, ``ctx``."""
    return (isinstance(node, ast.Attribute) and node.attr in _CONTEXT_NAMES) or (
        isinstance(node, ast.Name) and node.id in _CONTEXT_NAMES
    )


def _check_reach_through(source: str) -> list[str]:
    """Return ``line: expression`` for each context-cache or provider-client reach.

    By AST, so a docstring or comment that mentions ``_has(`` is not a hit:

    * ``<ctx>._has`` / ``._get`` / ``._set``, where ``<ctx>`` is ``self._ctx``,
      any ``.ctx`` / ``._ctx`` attribute, or a bare ``_ctx`` / ``ctx`` name;
    * ``<ctx>.organization`` (a check reads ``self.organization`` instead);
    * any use or import of ``OrganizationsClient``.
    """
    hits: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute):
            if node.attr in _CACHE_PRIMITIVES and _is_context(node.value):
                hits.append(f"{node.lineno}: {ast.unparse(node)}")
            elif node.attr == "organization" and _is_context(node.value):
                hits.append(f"{node.lineno}: {ast.unparse(node)}")
            elif node.attr == "OrganizationsClient":
                hits.append(f"{node.lineno}: {ast.unparse(node)}")
        elif isinstance(node, ast.Name) and node.id == "OrganizationsClient":
            hits.append(f"{node.lineno}: OrganizationsClient")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            hits += [
                f"{node.lineno}: import {a.name}"
                for a in node.names
                if a.name.split(".")[-1] == "OrganizationsClient"
            ]
    return hits


@pytest.mark.parametrize(
    "path",
    sorted(_SERVICES_ROOT.glob("*/checks/sra_*.py")),
    ids=lambda p: p.name,
)
def test_no_check_reaches_the_cache_or_the_provider_client(path: Path) -> None:
    """Property 15: a check calls its base's accessors and ``self.organization``."""
    hits = _check_reach_through(path.read_text(encoding="utf-8"))
    assert hits == [], f"{path.name} reaches through: {hits}"


def test_the_reach_through_rule_is_not_vacuous() -> None:
    """Property 15 catches each receiver shape, and ignores prose."""
    caught = _check_reach_through(
        "self._ctx._get('ns', 'k')\n"
        "ctx._set('ns', 'k', 1)\n"
        "_ctx._has('ns', 'k')\n"
        "self._ctx.organization.accounts()\n"
        "from sraverify.core.organizations_client import OrganizationsClient\n"
    )
    assert len(caught) == 5, caught  # one per line; the import yields its alias only
    assert _check_reach_through(
        '"""Never call self._ctx._has( from a check; OrganizationsClient is private."""\n'
        "# ctx._set( is for bases\n"
        "self.organization.accounts()\n"
        "self._has_value = 1\n"
    ) == []


# --------------------------------------------------------------------------- #
# Property 41 -- only the provider's client issues an Organizations operation
# --------------------------------------------------------------------------- #

_CLIENT_MODULE = "core/organizations_client.py"
_PROVIDER_MODULE = "core/organization.py"


def _snake(operation: str) -> str:
    """``ListAccountsForParent`` -> ``list_accounts_for_parent``."""
    return "".join(f"_{c.lower()}" if c.isupper() else c for c in operation).lstrip("_")


#: The boto3 (and wrapper) method names of every operation the provider owns.
#: ``ListPolicies`` is outside ``OWNED_OPERATIONS`` because ``fms`` shares the
#: name; rule (iv) is what covers it.
_OWNED_METHODS = frozenset(_snake(op) for op in OrganizationsProvider.OWNED_OPERATIONS)


def _core_and_services_modules() -> list[Path]:
    """Every ``.py`` under ``core/`` and ``services/``."""
    return [*_python_files(_CORE_ROOT), *_python_files(_SERVICES_ROOT)]


def _production_modules() -> list[Path]:
    """Every package ``.py`` outside ``tests/``: core, services and the top level."""
    return [
        p for p in _python_files(_PACKAGE_ROOT) if "tests" not in p.relative_to(_PACKAGE_ROOT).parts
    ]


def _literal_service(call: ast.Call) -> str | None:
    """The literal service id of a ``get_client`` / ``client`` call, if any."""
    service = _service_id(call)
    if isinstance(service, ast.Constant) and isinstance(service.value, str):
        return service.value
    return None


def _organizations_reach(source: str, rel: str) -> list[str]:
    """Return ``rule line: expression`` for each Property 41 violation in ``source``.

    ``rel`` is the module's package-relative path, which decides the exemptions:

    (i)   ``get_paginator('<owned op>')`` anywhere but the client module;
    (ii)  ``<recv>.<owned op>(`` anywhere but the client and provider modules,
          unless ``<recv>`` is an attribute named ``organization``;
    (iv)  ``get_client('organizations', ...)`` or ``client('organizations', ...)``
          anywhere but the client module;
    (v)   ``OrganizationsClient`` as a name, attribute or import alias anywhere
          but the client and provider modules.

    By AST, so prose -- docstrings, comments, string constants -- is not a hit.
    """
    in_client = rel == _CLIENT_MODULE
    in_owner = rel in {_CLIENT_MODULE, _PROVIDER_MODULE}
    hits: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if (
                attr == "get_paginator"
                and not in_client
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value in _OWNED_METHODS
            ):
                hits.append(f"(i) {node.lineno}: {ast.unparse(node)}")
            if attr in _OWNED_METHODS and not in_owner:
                receiver = node.func.value
                if not (isinstance(receiver, ast.Attribute) and receiver.attr == "organization"):
                    hits.append(f"(ii) {node.lineno}: {ast.unparse(node)}")
            if (
                attr in {"get_client", "client"}
                and not in_client
                and _literal_service(node) == "organizations"
            ):
                hits.append(f"(iv) {node.lineno}: {ast.unparse(node)}")
        if in_owner:
            continue
        if isinstance(node, ast.Name) and node.id == "OrganizationsClient":
            hits.append(f"(v) {node.lineno}: OrganizationsClient")
        elif isinstance(node, ast.Attribute) and node.attr == "OrganizationsClient":
            hits.append(f"(v) {node.lineno}: {ast.unparse(node)}")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            hits += [
                f"(v) {node.lineno}: import {a.name}"
                for a in node.names
                if a.name.split(".")[-1] == "OrganizationsClient"
                or a.asname == "OrganizationsClient"
            ]
    return hits


@pytest.mark.parametrize("path", _production_modules(), ids=_rel)
def test_only_the_providers_client_issues_an_organizations_operation(path: Path) -> None:
    """Property 41 (i), (ii), (iv), (v) over every production module."""
    hits = _organizations_reach(path.read_text(encoding="utf-8"), _rel(path))
    assert hits == [], f"{_rel(path)} reaches Organizations outside the provider: {hits}"


def test_the_provider_calls_the_wrapper_and_sweeps_accounts_once() -> None:
    """Property 41 (iii): no paginator, no ``.client.`` receiver, one ``.list_accounts(``."""
    tree = ast.parse((_CORE_ROOT / "organization.py").read_text(encoding="utf-8"))
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    attrs = [c.func.attr for c in calls if isinstance(c.func, ast.Attribute)]
    assert "get_paginator" not in attrs
    assert attrs.count("list_accounts") == 1
    client_receivers = [
        n.lineno
        for n in ast.walk(tree)
        if isinstance(n, ast.Attribute)
        and isinstance(n.value, ast.Attribute)
        and n.value.attr == "client"
    ]
    assert client_receivers == []


def test_the_client_module_is_where_every_owned_operation_is_issued() -> None:
    """Property 41 is not vacuous: the client opens or calls each owned operation."""
    source = (_CORE_ROOT / "organizations_client.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    issued = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "get_paginator" and isinstance(node.args[0], ast.Constant):
                issued.add(node.args[0].value)
            elif isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "client":
                issued.add(node.func.attr)
    assert _OWNED_METHODS <= issued
    assert len(_OWNED_METHODS) == len(OrganizationsProvider.OWNED_OPERATIONS) == 9


def test_the_organizations_reach_rule_is_not_vacuous() -> None:
    """Property 41 catches each shape outside the owners, and ignores prose."""
    code = (
        "from sraverify.core.organizations_client import OrganizationsClient\n"
        "import sraverify.core.organizations_client as oc\n"
        "self.org_client = ctx.get_client('organizations', region=region)\n"
        "session.client('organizations', region_name=r)\n"
        "self.org_client.get_paginator('list_delegated_administrators')\n"
        "self.org_client.describe_organization()\n"
        "client = oc.OrganizationsClient(ctx)\n"
        "OrganizationsClient(ctx).list_accounts()\n"
    )
    hits = _organizations_reach(code, "services/example/client.py")
    rules = sorted(h.split(" ", 1)[0] for h in hits)
    assert rules.count("(i)") == 1, hits
    assert rules.count("(ii)") == 2, hits  # .describe_organization(, .list_accounts(
    assert rules.count("(iv)") == 2, hits
    assert rules.count("(v)") == 3, hits  # the import, oc.OrganizationsClient, the Name

    allowed = (
        '"""Never call get_client(\'organizations\') or OrganizationsClient here."""\n'
        "# self.org_client.describe_organization() was the Phase 1 shape\n"
        "x = 'get_paginator(\"list_roots\")'\n"
        "self.organization.describe_policy('p-1')\n"
        "self.organization.delegated_administrators('iam.amazonaws.com')\n"
        "fms.get_paginator('list_policies')\n"
        "self.get_client(region)\n"
    )
    assert _organizations_reach(allowed, "services/example/base.py") == []
    # The owners are exempt from exactly their own rules: the client from all
    # four, the provider from (ii) and (v) only.
    assert _organizations_reach(code, _CLIENT_MODULE) == []
    provider_hits = _organizations_reach(code, _PROVIDER_MODULE)
    assert {h.split(" ", 1)[0] for h in provider_hits} == {"(i)", "(iv)"}


# --------------------------------------------------------------------------- #
# Property 42 -- no service base reads the organizations namespace by key
# --------------------------------------------------------------------------- #

_ORGANIZATIONS_NAMESPACE = "organizations"


def _names_bound_to_namespace(body: list[ast.stmt]) -> set[str]:
    """Names assigned the literal ``"organizations"`` directly in ``body``."""
    names: set[str] = set()
    for stmt in body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(stmt, ast.Assign):
            targets, value = stmt.targets, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            targets, value = [stmt.target], stmt.value
        if isinstance(value, ast.Constant) and value.value == _ORGANIZATIONS_NAMESPACE:
            names |= {t.id for t in targets if isinstance(t, ast.Name)}
    return names


def _namespace_reads(source: str) -> list[str]:
    """Return ``line: call`` for each Property 42 violation in a base module.

    A ``_has`` / ``_get`` / ``_set`` call is a hit when its namespace argument is
    the literal ``"organizations"``, a module- or class-level name bound to that
    literal (reached bare or as ``<recv>.<name>``), or -- inside a class whose
    ``NAMESPACE`` is ``"organizations"`` -- anything at all, because that class
    may make no such call.
    """
    tree = ast.parse(source)
    module_names = _names_bound_to_namespace(tree.body)
    hits: list[str] = []

    def is_namespace(arg: ast.expr, class_names: set[str]) -> bool:
        if isinstance(arg, ast.Constant) and arg.value == _ORGANIZATIONS_NAMESPACE:
            return True
        if isinstance(arg, ast.Name) and arg.id in module_names | class_names:
            return True
        return isinstance(arg, ast.Attribute) and arg.attr in module_names | class_names

    def primitive_calls(node: ast.AST) -> list[ast.Call]:
        return [
            n
            for n in ast.walk(node)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr in _CACHE_PRIMITIVES
        ]

    classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    in_class: set[int] = set()
    for cls in classes:
        class_names = _names_bound_to_namespace(cls.body)
        owns_namespace = "NAMESPACE" in class_names
        for call in primitive_calls(cls):
            in_class.add(id(call))
            if owns_namespace or (call.args and is_namespace(call.args[0], class_names)):
                hits.append(f"{call.lineno}: {ast.unparse(call)}")
    for call in primitive_calls(tree):
        if id(call) not in in_class and call.args and is_namespace(call.args[0], set()):
            hits.append(f"{call.lineno}: {ast.unparse(call)}")
    return sorted(set(hits))


@pytest.mark.parametrize(
    "path", sorted(_SERVICES_ROOT.glob("*/base.py")), ids=lambda p: f"{p.parent.name}/base.py"
)
def test_no_base_reads_the_organizations_namespace_by_key(path: Path) -> None:
    """Property 42: the namespace is the provider's alone."""
    hits = _namespace_reads(path.read_text(encoding="utf-8"))
    assert hits == [], f"{path.parent.name}/base.py reads 'organizations' by key: {hits}"


def test_organizations_check_still_declares_the_namespace() -> None:
    """Property 42 is aimed at the real class: it declares the namespace it may not read."""
    source = (_SERVICES_ROOT / "organizations" / "base.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    owning = [
        c.name
        for c in ast.walk(tree)
        if isinstance(c, ast.ClassDef) and "NAMESPACE" in _names_bound_to_namespace(c.body)
    ]
    assert owning == ["OrganizationsCheck"]


def test_the_namespace_rule_is_not_vacuous() -> None:
    """Property 42 catches each spelling, and ignores prose and other namespaces."""
    caught = _namespace_reads(
        "_NS = 'organizations'\n"
        "class SecurityHubCheck:\n"
        "    NAMESPACE = 'securityhub'\n"
        "    _ORG_NS = 'organizations'\n"
        "    def a(self):\n"
        "        self._ctx._get('organizations', 'organization')\n"
        "        self._ctx._has(_NS, 'organization')\n"
        "        self._ctx._set(self._ORG_NS, 'organization', 1)\n"
        "class OrganizationsCheck:\n"
        "    NAMESPACE = 'organizations'\n"
        "    def b(self):\n"
        "        self._ctx._get(self.NAMESPACE, 'roots')\n"
        "        self._ctx._set('anything', 'k', 1)\n"
    )
    assert len(caught) == 5, caught
    assert _namespace_reads(
        '"""Never self._ctx._get("organizations", ...) from a base."""\n'
        "class GuardDutyCheck:\n"
        "    NAMESPACE = 'guardduty'\n"
        "    def a(self):\n"
        "        # self._ctx._get('organizations', 'x') was the old shape\n"
        "        self._ctx._get(self.NAMESPACE, 'detector')\n"
        "        self._ctx._set('guardduty', 'k', 1)\n"
        "        return self.organization.describe()\n"
    ) == []


# --------------------------------------------------------------------------- #
# Property 30 -- the fifteen consumers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("relative", _CONSUMERS)
def test_each_consumer_reads_accounts_through_the_provider_once(relative: str) -> None:
    """Property 30: one token changed per call site, and the old name gone."""
    source = (_SERVICES_ROOT / relative).read_text(encoding="utf-8")
    assert source.count("self.organization.accounts()") == 1
    assert "get_organization_accounts" not in source


def test_there_are_exactly_fifteen_consumers() -> None:
    """No check outside the fifteen reads the provider's account list."""
    readers = sorted(
        p.relative_to(_SERVICES_ROOT).as_posix()
        for p in _SERVICES_ROOT.glob("*/checks/sra_*.py")
        if "self.organization.accounts()" in p.read_text(encoding="utf-8")
    )
    assert len(_CONSUMERS) == 15
    assert readers == sorted(_CONSUMERS)


# --------------------------------------------------------------------------- #
# Property 34 -- core, scanner, cli and utils bind every client to a Region
# --------------------------------------------------------------------------- #

#: ``{(package-relative path, enclosing function): reason}``. Empty: every site
#: complies. An entry needs a reason saying why that binding may omit its
#: Region or pin a literal -- which would let it reach botocore's commercial
#: ``aws-global`` default, or the wrong partition, from a GovCloud or China scan.
_BINDING_ALLOWLIST: dict[tuple[str, str], str] = {}


def _binding_scope() -> list[Path]:
    """``core/**``, ``scanner.py``, ``cli.py`` and ``utils/**``."""
    return [
        *_python_files(_CORE_ROOT),
        _PACKAGE_ROOT / "scanner.py",
        _PACKAGE_ROOT / "cli.py",
        *_python_files(_PACKAGE_ROOT / "utils"),
    ]


def _service_id(call: ast.Call) -> ast.AST | None:
    """The service-id argument of a ``get_client`` call: first positional, else ``service_name=``."""
    if call.args:
        return call.args[0]
    return next((kw.value for kw in call.keywords if kw.arg == "service_name"), None)


def _names_a_region(call: ast.Call, keyword: str) -> bool:
    """Whether ``call`` passes ``keyword=`` with a non-literal value."""
    return any(
        kw.arg == keyword and not isinstance(kw.value, ast.Constant) for kw in call.keywords
    )


def _unbound_bindings(source: str) -> list[tuple[int, str, str]]:
    """Return ``(line, enclosing function, call)`` for every binding without a Region.

    (i) ``<x>.get_client(<str literal>, ...)`` -- the service id given as the
    first positional argument or as ``service_name=`` -- must pass ``region=``
    with a non-literal value. ``SecurityCheck.get_client(region)``, whose first
    argument is a name, is a wrapper lookup and is not a binding.

    (ii) ``<x>.client(...)`` must pass ``region_name=`` with a non-literal value.
    """
    found: list[tuple[int, str, str]] = []

    def visit(node: ast.AST, function: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = node.name
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "get_client":
                service = _service_id(node)
                if (
                    isinstance(service, ast.Constant)
                    and isinstance(service.value, str)
                    and not _names_a_region(node, "region")
                ):
                    found.append((node.lineno, function, ast.unparse(node)))
            elif node.func.attr == "client" and not _names_a_region(node, "region_name"):
                found.append((node.lineno, function, ast.unparse(node)))
        for child in ast.iter_child_nodes(node):
            visit(child, function)

    visit(ast.parse(source), "<module>")
    return found


@pytest.mark.parametrize("path", _binding_scope(), ids=_rel)
def test_no_core_binding_omits_or_pins_its_region(path: Path) -> None:
    """Property 34: every binding in this scope names a derived Region."""
    rel = _rel(path)
    offenders = [
        f"{line} in {function}(): {call}"
        for line, function, call in _unbound_bindings(path.read_text(encoding="utf-8"))
        if (rel, function) not in _BINDING_ALLOWLIST
    ]
    assert offenders == [], (
        f"{rel} binds a client without a derived Region: {offenders}"
    )


def test_the_binding_scope_covers_the_known_sites() -> None:
    """Property 34 quantifies over the real files that bind clients."""
    names = {_rel(p) for p in _binding_scope()}
    assert {
        "core/scan_context.py",
        "core/session.py",
        "core/organizations_client.py",
        "utils/banner.py",
        "scanner.py",
        "cli.py",
    } <= names


def test_the_binding_rule_has_both_controls() -> None:
    """Property 34 is neither vacuous nor over-broad."""
    violations = _unbound_bindings(
        "ctx.get_client('ec2', region='us-east-1')\n"
        "ctx.get_client('sts')\n"
        "ctx.get_client(service_name='sts')\n"
        "session.client('sts')\n"
    )
    assert [line for line, _, _ in violations] == [1, 2, 3, 4]
    assert _unbound_bindings(
        "ctx.get_client('sts', region=r)\n"
        "ctx.get_client(service_name='sts', region=r)\n"
        "session.client('sts', region_name=r)\n"
        "self.get_client(region)\n"
    ) == []
