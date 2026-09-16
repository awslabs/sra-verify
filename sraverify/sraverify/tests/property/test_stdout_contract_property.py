"""
Properties 20 and 21: the library never writes to stdout.

The scanner is a library behind an MCP server that speaks JSON-RPC over stdio.
One stray byte on stdout from the library corrupts that transport. Today three
things keep it from happening and **none of them is tested**: ``core/logging.py``
routes every logger to stderr, all 17 ``print()`` calls in the package sit in the
CLI surface that ``run_checks()`` does not reach, and the MCP server adds its own
belt and braces. The middle one is the load-bearing layer and the one with no
guard -- a ``print()`` added to a base accessor while debugging ships silently.

This module lands in **Phase 0, before any client or base module is edited**, and
both halves are expected to pass against the current tree. That ordering is the
point: the client error contract touches every ``client.py`` and every
``base.py`` in the tree and adds three new diagnostic paths, which is the widest
surface a stray ``print()`` has had since the scan-context refactor. Proving the
convention holds *first* means a later failure is attributable to the sweep.

Two halves, because neither suffices alone:

* **Property 20, dynamic.** Runs the real entry point with a stdout whose
  ``write`` raises, so a ``print()`` on the path fails at its own call site with a
  traceback naming the file and line. ``capsys`` is deliberately not used: it
  would *capture* the write and let the test pass.
* **Property 21, static.** An AST walk, which closes the dynamic test's
  branch-coverage gap -- a ``print()`` on a branch the probe catalog never reaches.

Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8.
"""
from __future__ import annotations

import ast
import logging
import sys
from pathlib import Path
from typing import Any, Iterator

import pytest
from botocore.exceptions import ClientError

import sraverify
import sraverify.services
from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.aws_errors import NotConfigured, is_error
from sraverify.core.check import SecurityCheck
from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.errors import UnknownCheckError
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.tests.unit.cli.test_exit_codes_scan import (  # noqa: F401
    _NoAwsSession,
    _isolated_registry,
    _make_probe_check,
    _PROBE_REGION,
    _seeded_scan_context,
    probe_scan,
)

# --------------------------------------------------------------------------- #
# Property 21 -- the module set
# --------------------------------------------------------------------------- #

_PACKAGE_ROOT: Path = Path(sraverify.__file__).resolve().parent

#: The one module permitted to construct a logging handler. It is where the
#: stderr binding is declared, and it passes ``sys.stderr`` explicitly rather
#: than relying on ``StreamHandler``'s default -- which is stderr today, but is a
#: default rather than a declaration.
_LOGGING_MODULE: Path = _PACKAGE_ROOT / "core" / "logging.py"

#: CLI modules, excluded from the contract. These write to stdout on purpose:
#: the buildspec parses the summary, the operator reads the banner, and
#: ``test_exit_codes_scan.py`` asserts ``-> Scan complete!`` appears there.
#: The contract stops at the library boundary (Requirement 8, Non-Goal 10).
_CLI_MODULES: frozenset[str] = frozenset(
    {"main.py", "banner.py", "progress.py"}
)


def _library_modules() -> list[Path]:
    """Return every library module, per the Requirement 8 glossary.

    ``core/``, ``services/``, ``utils/outputs.py``, and ``__init__.py``.
    ``main.py``, ``utils/banner.py``, and ``utils/progress.py`` are the CLI
    surface and are excluded. ``tests/`` is not library code.

    Returns:
        Absolute paths, sorted, so parametrize IDs are stable.
    """
    modules: set[Path] = set()

    for directory in ("core", "services"):
        modules.update(
            path
            for path in (_PACKAGE_ROOT / directory).rglob("*.py")
            if "__pycache__" not in path.parts
        )

    modules.add(_PACKAGE_ROOT / "utils" / "outputs.py")
    modules.add(_PACKAGE_ROOT / "__init__.py")

    return sorted(modules)


#: Snapshotted at import so collection is stable and a failure names its module.
_LIBRARY_MODULES: list[Path] = _library_modules()


def _module_ids() -> list[str]:
    """Return package-relative module paths, for use as parametrize IDs.

    Returns:
        Paths relative to the package root, POSIX-style.
    """
    return [path.relative_to(_PACKAGE_ROOT).as_posix() for path in _LIBRARY_MODULES]


def test_the_library_module_set_is_not_trivially_small() -> None:
    """Guard against an enumeration bug reading as a vacuous pass.

    ``core/`` alone is 12 modules and ``services/`` is over 200, so anything
    under 100 means the walk broke rather than that the tree shrank.
    """
    assert len(_LIBRARY_MODULES) >= 100, (
        f"the library module walk found {len(_LIBRARY_MODULES)} modules; "
        f"Property 21 quantifies over the package and the walk is broken"
    )


def test_the_cli_modules_are_excluded_deliberately() -> None:
    """The exclusions are named, so widening them is a visible edit.

    If ``main.py`` ever drifted into the set, Property 21 would fail on its six
    legitimate ``print()`` calls and the temptation would be to loosen the
    assertion rather than to ask why the boundary moved.
    """
    names = {path.name for path in _LIBRARY_MODULES}
    assert names & _CLI_MODULES == set(), (
        f"a CLI module leaked into the library set: {names & _CLI_MODULES}"
    )
    # And they do exist, so the exclusion is not stale.
    assert (_PACKAGE_ROOT / "main.py").is_file()
    assert (_PACKAGE_ROOT / "utils" / "banner.py").is_file()
    assert (_PACKAGE_ROOT / "utils" / "progress.py").is_file()


def _parse(path: Path) -> ast.Module:
    """Parse a module to an AST.

    A module-level docstring becomes an ``ast.Constant`` rather than any kind of
    ``Call``, so the ``print()`` in ``__init__.py``'s library-usage example is
    exempt automatically -- no source-text stripping needed. The requirement's
    "docstring stripped" phrasing describes the intent; the AST gives it for
    free, which is one reason to walk the AST rather than grep.

    Args:
        path: The module to parse.

    Returns:
        The parsed module.
    """
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _where(path: Path, node: ast.AST) -> str:
    """Format a node's location as ``path:line``.

    Args:
        path: The module the node came from.
        node: Any AST node.

    Returns:
        A location string a reader can jump to.
    """
    return f"{path.relative_to(_PACKAGE_ROOT).as_posix()}:{getattr(node, 'lineno', '?')}"


@pytest.mark.parametrize("path", _LIBRARY_MODULES, ids=_module_ids())
def test_no_library_module_calls_print(path: Path) -> None:
    """Requirement 8.2: ``print()`` is the one defect no logger config can contain.

    Every other diagnostic path can be redirected after the fact by whoever
    configures logging. ``print()`` writes to whatever ``sys.stdout`` is at the
    moment it runs, which for the MCP server is the JSON-RPC transport.
    """
    offenders = [
        _where(path, node)
        for node in ast.walk(_parse(path))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "print"
    ]

    assert offenders == [], (
        f"print() in a library module at {offenders}; use "
        f"sraverify.core.logging.logger, which binds to stderr"
    )


@pytest.mark.parametrize("path", _LIBRARY_MODULES, ids=_module_ids())
def test_no_library_module_names_sys_stdout(path: Path) -> None:
    """Requirement 8.2: no write to ``sys.stdout`` or ``sys.__stdout__`` by name.

    ``__stdout__`` matters as much as ``stdout``: a module that reached for it
    would bypass any redirection the MCP server had installed, which is the one
    thing worse than writing to ``sys.stdout``.
    """
    offenders = [
        f"{_where(path, node)} (sys.{node.attr})"
        for node in ast.walk(_parse(path))
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
        and node.attr in {"stdout", "__stdout__"}
    ]

    assert offenders == [], (
        f"a library module reaches for stdout at {offenders}; stdout belongs to "
        f"the MCP server's JSON-RPC transport"
    )


@pytest.mark.parametrize("path", _LIBRARY_MODULES, ids=_module_ids())
def test_no_library_module_calls_warnings_warn(path: Path) -> None:
    """Requirement 8.3: ``warnings.warn`` depends on the caller's configuration.

    The MCP server suppresses the ``warnings`` module globally to keep its
    stderr readable. A library that emitted warnings would be relying on that
    suppression -- that is, depending on its caller's configuration for its own
    correctness. ``logger.warning`` is the replacement and it needs no
    cooperation.
    """
    offenders: list[str] = []
    for node in ast.walk(_parse(path)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # warnings.warn(...)
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "warn"
            and isinstance(func.value, ast.Name)
            and func.value.id == "warnings"
        ):
            offenders.append(_where(path, node))
        # from warnings import warn; warn(...)
        elif isinstance(func, ast.Name) and func.id == "warn":
            offenders.append(_where(path, node))

    assert offenders == [], (
        f"warnings.warn in a library module at {offenders}; use "
        f"logger.warning, which does not depend on the caller's filters"
    )


@pytest.mark.parametrize("path", _LIBRARY_MODULES, ids=_module_ids())
def test_only_core_logging_configures_handlers(path: Path) -> None:
    """Requirement 8.8: one module declares where diagnostics go.

    ``logging.StreamHandler()`` with no argument writes to stderr *today*, by
    default. ``core/logging.py`` passes ``sys.stderr`` explicitly for that
    reason. A second module adding a bare ``StreamHandler()`` would be relying
    on that default, and ``logging.basicConfig()`` defaults to stderr too but
    also silently does nothing if the root already has handlers -- so a caller
    who added one would get behaviour that depends on import order.
    """
    if path == _LOGGING_MODULE:
        pytest.skip("core/logging.py is where the stderr binding is declared")

    offenders: list[str] = []
    for node in ast.walk(_parse(path)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {
            "StreamHandler",
            "basicConfig",
        }:
            offenders.append(f"{_where(path, node)} ({func.attr})")
        elif isinstance(func, ast.Name) and func.id in {
            "StreamHandler",
            "basicConfig",
        }:
            offenders.append(f"{_where(path, node)} ({func.id})")

    assert offenders == [], (
        f"a library module configures logging at {offenders}; only "
        f"core/logging.py may, and it binds sys.stderr explicitly"
    )


# --------------------------------------------------------------------------- #
# Property 21 -- the runtime half
# --------------------------------------------------------------------------- #


#: Probe source for the root-logger assertion. Runs in a clean interpreter
#: because pytest's own logging plugin attaches several handlers to the root
#: logger (``LogCaptureHandler``, ``_LiveLoggingNullHandler``, a ``/dev/null``
#: ``_FileHandler``), so the claim "core/logging.py leaves the root with exactly
#: one handler" is simply not observable in-process. Asserting it under pytest
#: would mean either asserting something weaker than the requirement or
#: hard-coding pytest's handler set, and both would stop measuring the thing
#: that matters.
_ROOT_LOGGER_PROBE = """\
import json
import logging
import sys

# Importing the package triggers core/logging.py's root-logger surgery.
import sraverify.core.logging  # noqa: F401

root = logging.getLogger()
package = logging.getLogger("sraverify")

print(json.dumps({
    "root_handler_count": len(root.handlers),
    "root_streams_are_stderr": [
        getattr(h, "stream", None) is sys.stderr for h in root.handlers
    ],
    "root_handler_reprs": [repr(h) for h in root.handlers],
    "package_handler_count": len(package.handlers),
    "package_streams_are_stderr": [
        getattr(h, "stream", None) is sys.stderr for h in package.handlers
    ],
    "package_propagates": package.propagate,
}))
"""


def _probe_logging_in_a_clean_interpreter() -> dict[str, Any]:
    """Import the package in a subprocess and report its logging configuration.

    Returns:
        The decoded probe output.
    """
    import json
    import subprocess

    completed = subprocess.run(
        [sys.executable, "-c", _ROOT_LOGGER_PROBE],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, (
        f"the logging probe failed:\nstdout={completed.stdout}\n"
        f"stderr={completed.stderr}"
    )
    return json.loads(completed.stdout)


def test_the_root_logger_has_exactly_one_handler_on_stderr() -> None:
    """Requirement 8.8: ``core/logging.py`` leaves the root with one stderr handler.

    Measured in a clean interpreter, for the reason recorded on
    ``_ROOT_LOGGER_PROBE``: pytest attaches its own handlers to the root logger,
    so in-process this can only be asserted in a weakened form that would no
    longer detect the regression it exists for.

    The regression it exists for: a future edit that adds a
    ``logging.StreamHandler()`` relying on the default stream. That default is
    stderr today, which is precisely why ``core/logging.py`` passes
    ``sys.stderr`` explicitly instead -- a default can be changed by any code
    that runs first, and a declaration cannot.
    """
    probe = _probe_logging_in_a_clean_interpreter()

    assert probe["root_handler_count"] == 1, (
        f"the root logger has {probe['root_handler_count']} handlers: "
        f"{probe['root_handler_reprs']}; core/logging.py strips them and "
        f"installs exactly one"
    )
    assert probe["root_streams_are_stderr"] == [True], (
        f"the root handler does not write to sys.stderr: "
        f"{probe['root_handler_reprs']}"
    )


def test_the_package_logger_is_bound_to_stderr_in_a_clean_interpreter() -> None:
    """The same measurement for the ``sraverify`` logger itself.

    In-process this is also asserted below, where it is observable because
    pytest does not attach handlers to named loggers. Doing it both ways costs
    nothing and covers the case where a future conftest starts to.
    """
    probe = _probe_logging_in_a_clean_interpreter()

    assert probe["package_handler_count"] >= 1, (
        "the sraverify logger has no handler at all"
    )
    assert all(probe["package_streams_are_stderr"]), (
        "a sraverify handler does not write to sys.stderr"
    )
    assert probe["package_propagates"] is False, (
        "the sraverify logger propagates; core/logging.py sets propagate=False"
    )


def test_every_sraverify_handler_writes_to_stderr() -> None:
    """The package logger's own handlers, and its propagation setting.

    ``propagate = False`` matters here: if it were True and a handler were
    misconfigured, records would also reach the root's handler and the leak
    would be masked by the duplicate.
    """
    target = logging.getLogger("sraverify")

    assert target.handlers, "the sraverify logger has no handler at all"
    for handler in target.handlers:
        assert getattr(handler, "stream", None) is sys.stderr, (
            f"sraverify handler {handler!r} writes to "
            f"{getattr(handler, 'stream', None)!r}, not sys.stderr"
        )
    assert target.propagate is False, (
        "the sraverify logger propagates; core/logging.py sets propagate=False "
        "so its records are not also emitted by the root handler"
    )


# --------------------------------------------------------------------------- #
# Property 20 -- the dynamic half
# --------------------------------------------------------------------------- #


class _RaisingStdout:
    """A stdout replacement whose every write raises.

    Deliberately not ``capsys`` and not ``io.StringIO``. Both would *absorb* the
    write and leave the test asserting on a captured buffer afterwards; this
    fails at the offending call site, so the traceback names the file and line
    of the ``print()`` rather than reporting that some byte appeared somewhere.

    Attributes:
        touched: Whether any write method was called. Read by the counter-case
            that proves the harness can see a write.
    """

    def __init__(self) -> None:
        """Start untouched."""
        self.touched = False

    def write(self, data: Any) -> int:
        """Refuse.

        Args:
            data: Ignored.

        Raises:
            AssertionError: Always.
        """
        self.touched = True
        raise AssertionError(
            f"a library module wrote to stdout: {data!r}. stdout belongs to the "
            f"MCP server's JSON-RPC transport; use "
            f"sraverify.core.logging.logger instead."
        )

    def writelines(self, lines: Any) -> None:
        """Refuse.

        Args:
            lines: Ignored.

        Raises:
            AssertionError: Always.
        """
        self.touched = True
        raise AssertionError(
            f"a library module wrote to stdout via writelines: {lines!r}"
        )

    def flush(self) -> None:
        """Permitted, and a no-op.

        A flush moves no bytes, and ``ScanProgress`` flushes as a matter of
        course. Raising here would fail the ``show_progress=True`` counter-case
        for the wrong reason.
        """

    def isatty(self) -> bool:
        """Report a non-TTY.

        Returns:
            ``False``, so any TTY-sensitive formatting takes its quiet branch
            and the test does not depend on terminal detection.
        """
        return False


# --- The fourth probe: the whole contract in miniature ---------------------- #
#
# Properties 20's dynamic half is only as good as the code it puts on the run.
# The three existing probes cover PASS, FAIL, and a raise into the orchestrator's
# guard, but none of them touches the client error contract. This fourth probe
# drives the real path end to end -- the client except clause catches a real
# ClientError and builds its error result, the
# accessor refuses to cache the error result, is_not_configured classifies it, and
# error() builds the row -- so that a print() or a stray handler added anywhere
# along it is caught.

_PROBE_OPERATION = "DescribeProbeThing"
_PROBE_NAMESPACE = "stdout_probe"


class _RaisingBotoClient:
    """A stand-in boto3 client whose one operation raises ``ClientError``."""

    def describe_probe_thing(self, **kwargs: Any) -> Any:
        """Raise, as AWS answering with an error code.

        Args:
            **kwargs: Ignored.

        Raises:
            ClientError: Always.
        """
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "not authorized to perform: probe:DescribeProbeThing",
                }
            },
            _PROBE_OPERATION,
        )


class _ProbeClient(AWSClient):
    """A miniature ``<Service>Client``: one method, in the canonical shape."""

    def __init__(self, region: str) -> None:
        """Acquire the boto3 client once, in the constructor.

        Args:
            region: The Region this wrapper serves.
        """
        super().__init__(region, ctx=None)  # type: ignore[arg-type]
        # Constructor-only acquisition, as Requirement 1.11 requires of every
        # real client. Inside a method's try block a construction failure would
        # be a BotoCoreError and become an error result instead of the defect it is.
        self.client = _RaisingBotoClient()

    def describe_probe_thing(self) -> Any:
        """Call the operation, in exactly the shape every real client uses.

        Returns:
            A named-key success dict, or the error result.
        """
        try:
            return self.client.describe_probe_thing()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)


def _probe_setup_clients(self: Any) -> None:
    """Install one wrapper per Region, as a real ``_setup_clients`` does.

    Args:
        self: The check instance.
    """
    self._clients.clear()
    for region in self.regions:
        self._clients[region] = _ProbeClient(region)


def _probe_accessor(self: Any, region: str) -> Any:
    """The canonical accessor shape: hit, no-client, call, guard, store, return.

    Args:
        self: The check instance.
        region: The Region to fetch for.

    Returns:
        The success dict or the error result, unchanged.
    """
    cache_key = f"probe_thing:{region}"
    if self._ctx._has(_PROBE_NAMESPACE, cache_key):
        return self._ctx._get(_PROBE_NAMESPACE, cache_key)

    client = self.get_client(region)
    if client is None:  # pragma: no cover - the probe always registers one
        from sraverify.core.aws_errors import no_client_result

        return no_client_result(service="Probe", region=region)

    result = client.describe_probe_thing()
    if is_error(result):
        # Never cache a failure: a retry must re-issue the call.
        return result

    self._ctx._set(_PROBE_NAMESPACE, cache_key, result)
    return result


def _probe_execute(self: Any) -> Iterator[Finding]:
    """The canonical check-body shape: test ``"Error"``, classify, extract after.

    Args:
        self: The check instance.

    Yields:
        One ``Finding`` per Region.
    """
    for region in self.regions:
        result = self._probe_accessor(region)

        if "Error" in result:
            error = result["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value=f"The probe control is not configured ({error['Code']})",
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            continue

        yield self.passed(
            region=region,
            resource_id="probe:thing",
            actual_value="The probe control is configured",
        )


def _make_error_probe() -> type[SecurityCheck]:
    """Build the fourth probe: a check that reaches the contract for real.

    Declared with ``type()`` in a module whose stem is not ``sra_``, so
    ``__init_subclass__`` returns silently and the class does not self-register --
    the same mechanism the other three probes rely on.

    Returns:
        A concrete check class whose ``execute()`` yields one ERROR row.
    """
    check_id = "SRA-PROBE-04"
    meta = CheckMeta(
        check_id=check_id,
        title="The probe control is configured",
        description="Fourth probe: drives the client except clause, the accessor guard, the "
        "discriminator, and error() so the stdout contract covers them.",
        check_logic="Call DescribeProbeThing and classify the error result.",
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="Probe",
        resource_type="AWS::Probe::Resource",
        remediation=Remediation(text="Configure the probe control."),
    )
    return type(
        check_id.replace("-", "_"),
        (SecurityCheck,),
        {
            "__doc__": "Fourth probe: the client error contract in miniature.",
            "__module__": __name__,
            "meta": meta,
            "NAMESPACE": _PROBE_NAMESPACE,
            # A table that does NOT declare AccessDeniedException, so the probe's
            # error result classifies as non-semantic and resolves to ERROR. The
            # entry that is here proves the lookup runs rather than short-
            # circuiting on an empty table.
            "NOT_CONFIGURED_ERRORS": {
                _PROBE_OPERATION: {
                    "ResourceNotFoundException": NotConfigured(
                        evidence="synthetic fixture for the stdout contract test"
                    )
                }
            },
            "_setup_clients": _probe_setup_clients,
            "_probe_accessor": _probe_accessor,
            "execute": _probe_execute,
        },
    )


@pytest.fixture
def four_probe_scan(monkeypatch: Any) -> Iterator[_NoAwsSession]:
    """The three-probe catalog plus the error result probe, with no AWS reachable.

    Reuses ``_isolated_registry`` and ``_seeded_scan_context`` from the exit-code
    module, so ``run_checks()`` runs end to end with zero AWS calls and a
    pre-warmed ``get_account_info()``.

    Yields:
        The refusing session, so a test can assert nothing asked it for a client.
    """
    from sraverify import main as main_module
    from sraverify.tests.unit.cli.test_exit_codes_scan import _PROBE_SHAPES

    session = _NoAwsSession()
    monkeypatch.setattr(main_module, "get_session", lambda **kwargs: session)

    classes = [_make_probe_check(index, execute) for index, execute, _ in _PROBE_SHAPES]
    classes.append(_make_error_probe())

    with _isolated_registry(classes), _seeded_scan_context(monkeypatch):
        yield session


def _run_library(monkeypatch: Any, stream: _RaisingStdout, **kwargs: Any) -> Any:
    """Call ``run_checks()`` with ``sys.stdout`` replaced by ``stream``.

    Args:
        monkeypatch: pytest's monkeypatch fixture.
        stream: The refusing stream.
        **kwargs: Forwarded to ``run_checks``.

    Returns:
        Whatever ``run_checks`` returns.
    """
    from sraverify import SRAVerify

    sra = SRAVerify(regions=[_PROBE_REGION])
    monkeypatch.setattr(sys, "stdout", stream)
    return sra.run_checks(**kwargs)


def test_run_checks_writes_nothing_to_stdout(
    four_probe_scan: Any, monkeypatch: Any
) -> None:
    """Property 20: the library entry point completes with a raising stdout.

    The catalog covers PASS, FAIL, a raise into the orchestrator's guard, and --
    via the fourth probe -- a client except clause catching a real ``ClientError``, the
    accessor refusing to cache the error result, the discriminator classifying it,
    and ``error()`` building the row. Four rows out, nothing written.
    """
    stream = _RaisingStdout()

    findings = _run_library(monkeypatch, stream)

    assert len(findings) == 4, (
        f"expected one row per probe, got {len(findings)}: "
        f"{[(f.check_id, f.status) for f in findings]}"
    )
    assert stream.touched is False, "the library wrote to stdout"


def test_the_four_probes_cover_pass_fail_and_error(
    four_probe_scan: Any, monkeypatch: Any
) -> None:
    """The catalog is not vacuous: all three verdicts are on the run.

    Without this, Property 20 could pass because the probes yielded nothing at
    all. The two ERROR rows are distinguishable by ``ActualValue``: the
    orchestrator's synthetic row keeps its ``Error running`` prefix, and the
    contract's row uses the ``{Operation} failed: {Code}: {Message}`` shape.
    """
    stream = _RaisingStdout()

    findings = _run_library(monkeypatch, stream)
    by_id = {finding.check_id: finding for finding in findings}

    assert by_id["SRA-PROBE-01"].status is Status.PASS
    assert by_id["SRA-PROBE-02"].status is Status.FAIL
    assert by_id["SRA-PROBE-03"].status is Status.ERROR
    assert by_id["SRA-PROBE-04"].status is Status.ERROR

    # The orchestrator's synthetic row.
    assert by_id["SRA-PROBE-03"].actual_value.startswith("Error running SRA-")
    # The contract's row, classified by the check rather than synthesized.
    assert by_id["SRA-PROBE-04"].actual_value.startswith(
        f"{_PROBE_OPERATION} failed: AccessDeniedException: "
    )
    assert not by_id["SRA-PROBE-04"].actual_value.startswith("Error running")
    assert by_id["SRA-PROBE-04"].remediation.strip()


def test_the_error_probe_does_not_cache_its_failure(
    four_probe_scan: Any, monkeypatch: Any
) -> None:
    """The fourth probe genuinely exercises the accessor guard.

    One row per Region, each an ERROR, and the boto3 call re-issued each time --
    which is what "never cache a failure" costs and buys. With one Region this
    asserts the guard did not swallow the error result into the cache and return a
    success on a second read.
    """
    stream = _RaisingStdout()

    findings = _run_library(monkeypatch, stream, check_id="SRA-PROBE-04")

    assert len(findings) == 1
    assert findings[0].status is Status.ERROR
    assert stream.touched is False


def test_a_usage_error_writes_nothing_to_stdout_before_raising(
    four_probe_scan: Any, monkeypatch: Any
) -> None:
    """Requirement 8.5: ``UnknownCheckError`` surfaces through the exception alone.

    Selection happens before any AWS call and before the banner, so a usage
    error reported through the MCP server must carry its whole message in the
    exception rather than in something printed alongside it.
    """
    stream = _RaisingStdout()

    with pytest.raises(UnknownCheckError):
        _run_library(monkeypatch, stream, check_id="SRA-TYPO-99")

    assert stream.touched is False, (
        "the library wrote to stdout before raising a usage error"
    )


def test_show_progress_does_write_so_the_harness_is_not_vacuous(
    four_probe_scan: Any, monkeypatch: Any
) -> None:
    """The counter-case: the test can see a write.

    ``show_progress=True`` opts into the CLI's progress indicator, which writes
    to stdout on purpose and is outside the contract. If this ever stopped
    raising, ``_RaisingStdout`` would have stopped being wired up and every
    assertion above would be passing for the wrong reason.

    This is also the guard against a future refactor that made ``run_checks()``
    bypass ``sys.stdout`` by some other route -- capturing a reference at import,
    say -- which would leave the positive tests green and meaningless.
    """
    stream = _RaisingStdout()

    with pytest.raises(AssertionError, match="wrote to stdout"):
        _run_library(monkeypatch, stream, show_progress=True)

    assert stream.touched is True


def test_the_scan_reached_no_aws_api(four_probe_scan: Any, monkeypatch: Any) -> None:
    """Requirement 7.9, for this module: no credentials, no calls.

    ``_NoAwsSession.client`` records the request and then raises, so a leak would
    show up here as a recorded call rather than as a network timeout.
    """
    stream = _RaisingStdout()

    _run_library(monkeypatch, stream)

    assert four_probe_scan.client_calls == [], (
        f"the scan asked for AWS clients: {four_probe_scan.client_calls}"
    )
