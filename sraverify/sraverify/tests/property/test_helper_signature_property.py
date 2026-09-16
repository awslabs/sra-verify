"""Property-based test for the call-shape contract of the finding helpers.

This module implements **Property 21: Helpers reject positional and malformed
calls**, which validates Requirements 7.1, 7.3, and 7.11 of the
check-contract-formalization spec.

Why this is a property rather than only a unit test
---------------------------------------------------

``passed()``, ``failed()``, and ``error()`` are three near-identical signatures
called from 158 migrated check bodies. If a positional argument were accepted,

    yield self.failed(region, "No detector in this Region", "Enable GuardDuty")

would bind cleanly: the sentence lands in ``resource_id``, the advice lands in
``actual_value``, and ``Remediation`` silently takes the metadata default.
Every cell holds a legal non-empty string in a legal field, so
``Finding.__post_init__`` cannot object and neither can the CSV writer, the
dashboard, or a reviewer skimming the diff. The row is *plausible*. That is the
whole failure mode: right values, wrong columns, nothing downstream able to
notice.

The five statements asserted, quantified over all three helpers:

  (a) ``inspect.signature`` reports every parameter of every helper as
      ``KEYWORD_ONLY`` (7.1). Driven off the live signature rather than a
      hand-written table, so a parameter added positionally to any helper in
      the future fails here without anyone remembering to extend this module.
  (b) Any positional argument raises ``TypeError`` and produces no Finding
      (7.11), including the exact three-positional shape above.
  (c) ``region``, ``resource_id``, and ``actual_value`` are required in all
      three, and omitting any subset raises ``TypeError`` naming each omitted
      parameter (7.3, 7.11). ``resource_id`` is required-but-nullable, not
      optional-with-a-default: ``None`` is an accepted *value*, never an
      accepted *omission*.
  (d) ``remediation=`` passed to ``passed()`` raises ``TypeError`` naming the
      helper and the parameter (7.2, 7.11).
  (e) A blank ``remediation`` passed to ``error()`` raises ``ValueError``
      naming the check ID (7.6).

Each negative case also asserts that **no Finding was returned**, via a
error result that the call would have to overwrite to have produced one. That is
the second half of Requirement 7.11 and it is not implied by the exception
type alone.

A positive control runs alongside: the fully-keyword call of each helper
succeeds and yields a Finding of the matching status. Without it, a helper that
raised ``TypeError`` unconditionally would satisfy every negative assertion
here.

Feature: check-contract-formalization, Property 21: Helpers reject positional
and malformed calls.

**Validates: Requirements 7.1, 7.3, 7.11**
"""
from __future__ import annotations

import inspect
from typing import Any, Callable, Dict, Iterable, List, Tuple

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from sraverify.core.check import SecurityCheck
from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.core.scan_context import ScanContext

# --------------------------------------------------------------------------- #
# What this module quantifies over
# --------------------------------------------------------------------------- #
#
# The three helper names and the three required parameters are spelled out
# literally, and ``test_helpers_and_required_parameters_are_as_declared``
# below ties both literals back to the live class. Everything else -- the
# parameter list of each helper, its declaration order, which parameters carry
# defaults -- is read from ``inspect.signature`` at run time, so a signature
# change is caught rather than mirrored.

HELPER_NAMES: Tuple[str, ...] = ("passed", "failed", "error")

#: Required in all three helpers (7.3). ``resource_id`` is in this tuple even
#: though it accepts ``None``: required-but-nullable forces the author to
#: decide whether the row identifies a resource and to say so.
REQUIRED_PARAMS: Tuple[str, ...] = ("region", "resource_id", "actual_value")

#: Status each helper must stamp on the Finding it returns (7.1).
HELPER_STATUS: Dict[str, Status] = {
    "passed": Status.PASS,
    "failed": Status.FAIL,
    "error": Status.ERROR,
}

#: An error result the call under test would have to return over. ``is`` identity
#: against this after a raised exception is how "SHALL return no Finding" gets
#: asserted rather than assumed.
_NO_RESULT = object()


# --------------------------------------------------------------------------- #
# Fixtures: a throwaway check and a context that touches no AWS API
# --------------------------------------------------------------------------- #
#
# This module's file stem does not begin with ``sra_``, so
# ``SecurityCheck.__init_subclass__`` returns before any identity rule runs
# and the class below is neither validated for identity nor registered. It
# still needs a real ``meta``, because the helpers read ``self.meta`` at call
# time -- and a real ``CheckMeta`` means the fixture is subject to every
# Requirement 3 validation rule, which is the right amount of realism.

_META = CheckMeta(
    check_id="SRA-HELPERFIXTURE-01",
    title="Helper call shape is enforced by the signature",
    description=(
        "Fixture metadata for the Property 21 helper signature test. Carries "
        "no security meaning and belongs to no service."
    ),
    check_logic="Not executed; this fixture exists to exercise the helpers.",
    severity=Severity.MEDIUM,
    account_type=AccountType.APPLICATION,
    service="HelperFixture",
    resource_type="AWS::Test::Fixture",
    remediation=Remediation(text="Call the helper with keyword arguments."),
)


class _HelperFixtureCheck(SecurityCheck):
    """A minimal concrete check, declared in a non-``sra_*`` module.

    ``execute`` is implemented only because ``SecurityCheck`` is an ``ABC``
    and an abstract method blocks instantiation. It is never called: this
    module exercises the helpers directly, which is the surface Property 21
    is about.
    """

    meta = _META

    def execute(self) -> Iterable[Finding]:
        """Yield nothing. Present to satisfy the abstract method."""
        return ()

    def _setup_clients(self) -> None:
        """No client wrappers. The helpers need none."""
        self._clients.clear()


def _stub_context() -> ScanContext:
    """Build a real ``ScanContext`` that will not reach AWS.

    A genuine ``ScanContext`` rather than a duck-typed stand-in, because the
    helpers call ``ctx.get_account_info()`` and the point of the positive
    control is that the success path is the real one. Nothing in
    ``ScanContext.__init__`` issues a call, so ``session=None`` is harmless,
    and pre-seeding the ``_account_info`` cache short-circuits
    ``get_account_info`` on its first-check fast path -- so the STS and
    Account API calls it would otherwise make never happen.
    """
    ctx = ScanContext(session=None, regions=["us-east-1"])
    ctx._account_info = {"account_id": "111111111111", "account_name": "fixture"}
    return ctx


def _initialized_check() -> _HelperFixtureCheck:
    """A freshly constructed, initialized check.

    A plain function rather than a pytest fixture: ``hypothesis`` reuses a
    function-scoped fixture across every example of a single test, and each
    example here wants a check nothing else has touched.
    """
    instance = _HelperFixtureCheck()
    instance.initialize(_stub_context())
    return instance


def _helper(check_instance: SecurityCheck, name: str) -> Callable[..., Finding]:
    """Return the bound helper method named ``name``."""
    return getattr(check_instance, name)


def _params(name: str) -> Dict[str, inspect.Parameter]:
    """Return the parameters of helper ``name``, read off the class.

    Read from the *unbound* function on ``SecurityCheck`` and ``self``
    dropped, so the mapping matches what a bound call sees while the source of
    truth stays the class rather than any one instance.
    """
    signature = inspect.signature(getattr(SecurityCheck, name))
    return {
        param_name: param
        for param_name, param in signature.parameters.items()
        if param_name != "self"
    }


def _valid_kwargs(name: str) -> Dict[str, Any]:
    """A complete, legal keyword-only call for helper ``name``.

    Only the parameters that helper actually requires: ``remediation`` is
    required by ``error()``, optional on ``failed()``, and does not exist on
    ``passed()``.
    """
    kwargs: Dict[str, Any] = {
        "region": "us-east-1",
        "resource_id": "arn:aws:test:::fixture/1",
        "actual_value": "Observed state of the fixture",
    }
    if name == "error":
        kwargs["remediation"] = "Grant the missing permission and re-run"
    return kwargs


# --------------------------------------------------------------------------- #
# Guard: the literals above still describe the real class
# --------------------------------------------------------------------------- #


def test_helpers_and_required_parameters_are_as_declared() -> None:
    """The three helpers are public methods and share the three required names.

    Guards every property below, all of which quantify over ``HELPER_NAMES``
    and ``REQUIRED_PARAMS``. A helper renamed, made private, or dropped would
    otherwise narrow what is being tested while leaving this module green.

    Requirement 7.10 keeps all three public, ``error()`` included, because
    checks author their own ERROR findings.

    Validates: Requirements 7.1, 7.3, 7.10.
    """
    for name in HELPER_NAMES:
        assert not name.startswith("_"), f"{name} must stay public (7.10)"
        attribute = getattr(SecurityCheck, name, None)
        assert callable(attribute), f"SecurityCheck.{name} is not callable"

        param_names = set(_params(name))
        missing = set(REQUIRED_PARAMS) - param_names
        assert not missing, (
            f"SecurityCheck.{name}() no longer declares {sorted(missing)}; "
            f"Requirement 7.3 requires all of {list(REQUIRED_PARAMS)} in all "
            f"three helpers"
        )

    # ``passed()`` is the one helper that must NOT declare remediation (7.2).
    assert "remediation" not in _params("passed")
    assert "remediation" in _params("failed")
    assert "remediation" in _params("error")


# --------------------------------------------------------------------------- #
# (a) Requirement 7.1: every parameter of every helper is keyword-only
# --------------------------------------------------------------------------- #


@given(name=st.sampled_from(HELPER_NAMES))
def test_every_parameter_of_every_helper_is_keyword_only(name: str) -> None:
    """Property 21: no helper declares a positionally-bindable parameter.

    The assertion is ``kind is KEYWORD_ONLY`` for *every* parameter, which
    rejects ``POSITIONAL_OR_KEYWORD`` (the default, and the accident this
    guards against), ``POSITIONAL_ONLY``, and ``VAR_POSITIONAL`` -- a ``*args``
    would reopen the whole failure mode while every named parameter still
    looked keyword-only.

    Because the parameter list comes from ``inspect.signature`` and not from a
    table in this file, a parameter added to any of the three without a
    preceding bare ``*`` fails here automatically. That is the point of
    driving the property off the signature.

    Validates: Requirements 7.1, 7.11.
    """
    params = _params(name)
    assert params, f"SecurityCheck.{name}() declares no parameters at all"

    for param_name, param in params.items():
        assert param.kind is inspect.Parameter.KEYWORD_ONLY, (
            f"SecurityCheck.{name}() declares {param_name!r} as "
            f"{param.kind.description}, not keyword-only; a positional "
            f"argument would then bind and a swapped call would produce a "
            f"well-formed row with the wrong values in the wrong columns"
        )


@given(name=st.sampled_from(HELPER_NAMES))
def test_required_parameters_carry_no_default(name: str) -> None:
    """Property 21: the three required parameters are genuinely required.

    ``resource_id`` is the interesting one. It accepts ``None`` as a value,
    which makes ``resource_id: Optional[str] = None`` a tempting and wrong
    declaration: the author who forgets it gets a null cell instead of a
    ``TypeError``. Required-but-nullable is asserted here as "no default",
    with ``None`` accepted as a value by the positive control below.

    ``checked_value`` is asserted to be the opposite -- optional with a
    ``None`` default in all three (7.3, 7.7).

    Validates: Requirements 7.3, 7.11.
    """
    params = _params(name)

    for param_name in REQUIRED_PARAMS:
        assert params[param_name].default is inspect.Parameter.empty, (
            f"SecurityCheck.{name}() gives {param_name!r} the default "
            f"{params[param_name].default!r}; Requirement 7.3 makes it "
            f"required, so omitting it must raise rather than fill in a value"
        )

    assert params["checked_value"].default is None, (
        f"SecurityCheck.{name}() must leave checked_value optional (7.3), "
        f"defaulting to f'{{service}} Configuration' (7.7)"
    )

    if name == "error":
        assert params["remediation"].default is inspect.Parameter.empty, (
            "error() must require remediation (7.6): an ERROR row describes "
            "fixing the scan environment, and the metadata default describes "
            "fixing the control"
        )


# --------------------------------------------------------------------------- #
# Positive control: the keyword-only call works
# --------------------------------------------------------------------------- #


@settings(max_examples=50)
@given(
    name=st.sampled_from(HELPER_NAMES),
    resource_id=st.one_of(st.none(), st.text(max_size=40)),
    checked_value=st.one_of(st.none(), st.text(max_size=40)),
)
def test_fully_keyword_call_returns_one_finding(
    name: str, resource_id: Any, checked_value: Any
) -> None:
    """Property 21's control: a correct call is accepted and yields a Finding.

    Every other test in this module asserts that something raises. Without
    this one, a helper that raised ``TypeError`` on every input -- or that had
    been deleted and replaced by a stub -- would pass the entire module.

    ``resource_id=None`` is drawn deliberately: it is the value that proves
    ``resource_id`` is *nullable*, which together with
    ``test_required_parameters_carry_no_default`` is the full statement of
    required-but-nullable.

    The fixture is rebuilt per example rather than taken from the pytest
    fixture, because ``hypothesis`` reuses a function-scoped fixture across
    every example in one run and these helpers must be called on a check that
    nothing else has touched.

    Validates: Requirements 7.1, 7.3.
    """
    instance = _initialized_check()

    kwargs = _valid_kwargs(name)
    kwargs["resource_id"] = resource_id
    kwargs["checked_value"] = checked_value

    finding = _helper(instance, name)(**kwargs)

    assert isinstance(finding, Finding)
    assert finding.status is HELPER_STATUS[name]
    assert finding.resource_id == resource_id


# --------------------------------------------------------------------------- #
# (b) Requirement 7.11: any positional argument raises TypeError
# --------------------------------------------------------------------------- #


@st.composite
def _positional_prefix_calls(draw: st.DrawFn) -> Tuple[str, Tuple[Any, ...], Dict[str, Any]]:
    """Draw a call that passes a leading run of arguments positionally.

    This is the realistic shape of the defect: an author writes the arguments
    in signature order and simply omits the keywords, so the first ``k`` of
    them arrive positionally and the remainder, if any, arrive by keyword.
    Every one of those calls must raise.

    Returns:
        ``(helper_name, args, kwargs)``.
    """
    name = draw(st.sampled_from(HELPER_NAMES))
    kwargs = _valid_kwargs(name)

    # Signature order, restricted to the parameters this call supplies, so the
    # generated call reads exactly like the one a check author would write.
    ordered: List[str] = [p for p in _params(name) if p in kwargs]
    count = draw(st.integers(min_value=1, max_value=len(ordered)))

    moved = ordered[:count]
    args = tuple(kwargs[p] for p in moved)
    remaining = {p: v for p, v in kwargs.items() if p not in moved}
    return name, args, remaining


@settings(max_examples=200)
@given(call=_positional_prefix_calls())
def test_positional_prefix_call_raises_type_error(
    call: Tuple[str, Tuple[Any, ...], Dict[str, Any]]
) -> None:
    """Property 21: passing any leading run of arguments positionally raises.

    ``count=1`` is the mildest case and still must fail -- ``self.failed(
    region, resource_id=..., actual_value=...)`` looks entirely reasonable and
    is exactly how the habit starts. ``count=3`` on ``failed()`` is the
    design's worked example of the swap.

    The message is asserted to name the helper, which CPython supplies as the
    qualified name in the "takes 1 positional argument but N were given" text.
    CPython names no parameter in that particular message; the
    parameter-naming half of Requirement 7.11 is asserted by the
    missing-argument and unexpected-keyword properties below, where CPython
    does name it.

    Validates: Requirement 7.11.
    """
    name, args, kwargs = call
    instance = _initialized_check()

    result: Any = _NO_RESULT
    with pytest.raises(TypeError) as excinfo:
        result = _helper(instance, name)(*args, **kwargs)

    assert result is _NO_RESULT, (
        f"{name}() returned {result!r} from a call with {len(args)} positional "
        f"argument(s); Requirement 7.11 requires no Finding"
    )
    assert name in str(excinfo.value), (
        f"the TypeError from a positional call to {name}() does not name the "
        f"helper: {excinfo.value}"
    )


@settings(max_examples=200)
@given(
    name=st.sampled_from(HELPER_NAMES),
    extra=st.lists(
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(),
            st.text(max_size=20),
            st.sampled_from(list(Status)),
            st.lists(st.text(max_size=4), max_size=2),
        ),
        min_size=1,
        max_size=5,
    ),
)
def test_arbitrary_positional_arguments_raise_type_error(
    name: str, extra: List[Any]
) -> None:
    """Property 21: positional arguments are refused whatever their values.

    The complement of the previous property. There, the positional values were
    plausible and drawn in signature order; here they are arbitrary and the
    keyword call is otherwise complete and correct. Refusal must not depend on
    the values, on how many there are, or on whether the keyword half of the
    call would have succeeded on its own -- an implementation that inspected
    ``*args`` and forwarded "harmless" ones would pass the first property and
    fail this one.

    Validates: Requirement 7.11.
    """
    instance = _initialized_check()

    result: Any = _NO_RESULT
    with pytest.raises(TypeError):
        result = _helper(instance, name)(*extra, **_valid_kwargs(name))

    assert result is _NO_RESULT


# --------------------------------------------------------------------------- #
# (c) Requirement 7.3: omitting a required parameter raises TypeError
# --------------------------------------------------------------------------- #


@settings(max_examples=200)
@given(
    name=st.sampled_from(HELPER_NAMES),
    omitted=st.lists(
        st.sampled_from(REQUIRED_PARAMS), min_size=1, max_size=3, unique=True
    ),
)
def test_omitting_any_required_parameter_raises_type_error_naming_it(
    name: str, omitted: List[str]
) -> None:
    """Property 21: every non-empty subset of the required three must be fatal.

    Quantifying over subsets rather than over single parameters matters
    because CPython reports missing keyword-only arguments collectively -- a
    call omitting two names produces one message listing both. Asserting each
    omitted name appears in that message is what ties this to Requirement
    7.11's "naming the parameter", and it holds for every subset size.

    Validates: Requirements 7.3, 7.11.
    """
    instance = _initialized_check()

    kwargs = _valid_kwargs(name)
    for param_name in omitted:
        del kwargs[param_name]

    result: Any = _NO_RESULT
    with pytest.raises(TypeError) as excinfo:
        result = _helper(instance, name)(**kwargs)

    assert result is _NO_RESULT, (
        f"{name}() returned {result!r} despite omitting {omitted}"
    )

    message = str(excinfo.value)
    assert name in message, (
        f"the TypeError from {name}() omitting {omitted} does not name the "
        f"helper: {message}"
    )
    for param_name in omitted:
        assert param_name in message, (
            f"the TypeError from {name}() omitting {omitted} does not name "
            f"{param_name!r}: {message}"
        )


# --------------------------------------------------------------------------- #
# (d) Requirement 7.2: remediation= is not a parameter of passed()
# --------------------------------------------------------------------------- #


@settings(max_examples=100)
@given(
    remediation=st.one_of(
        st.just(""),
        st.just("No remediation needed"),
        st.just("No action needed"),
        st.text(max_size=40),
        st.none(),
    )
)
def test_passed_rejects_a_remediation_argument(remediation: Any) -> None:
    """Property 21: ``passed(remediation=...)`` raises, whatever the value.

    The three sampled literals are the pre-change catalog's three spellings of
    "nothing to do" -- ``"No remediation needed"`` x114, ``""`` x45, ``"No
    action needed"`` x19. Requirement 7.2 makes all 178 of them
    unrepresentable rather than merely discouraged, and this is the assertion
    that they are. A ``remediation`` parameter quietly reintroduced with a
    ``""`` default would satisfy every other test in this module.

    ``None`` and the empty string are drawn alongside real text because a
    helper that accepted the argument and ignored a falsy value would still be
    accepting the argument.

    Validates: Requirements 7.2, 7.11.
    """
    instance = _initialized_check()

    result: Any = _NO_RESULT
    with pytest.raises(TypeError) as excinfo:
        result = instance.passed(
            remediation=remediation, **_valid_kwargs("passed")
        )

    assert result is _NO_RESULT
    message = str(excinfo.value)
    assert "passed" in message and "remediation" in message, (
        f"the TypeError must name the helper and the parameter (7.11): "
        f"{message}"
    )


@settings(max_examples=100)
@given(
    name=st.sampled_from(HELPER_NAMES),
    unknown=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=16
    ),
    value=st.one_of(st.none(), st.text(max_size=16), st.integers()),
)
def test_unknown_keyword_argument_raises_type_error(
    name: str, unknown: str, value: Any
) -> None:
    """Property 21: no helper accepts a keyword it does not declare.

    Generalizes the ``passed(remediation=...)`` case: a misspelling such as
    ``actual_values=`` or ``ressource_id=`` must be a ``TypeError`` and not a
    silently swallowed extra. A ``**kwargs`` catch-all on any helper -- which
    would make the whole signature contract advisory -- fails here.

    Validates: Requirement 7.11.
    """
    if unknown in _params(name):
        return  # a declared parameter; the other properties cover these

    instance = _initialized_check()

    result: Any = _NO_RESULT
    with pytest.raises(TypeError) as excinfo:
        result = _helper(instance, name)(**{unknown: value}, **_valid_kwargs(name))

    assert result is _NO_RESULT
    assert unknown in str(excinfo.value)


# --------------------------------------------------------------------------- #
# (e) Requirement 7.6: error() refuses a blank remediation
# --------------------------------------------------------------------------- #


@settings(max_examples=100)
@given(
    blank=st.one_of(
        st.just(""),
        st.text(alphabet=" \t\r\n\f\v", max_size=8),
    )
)
def test_error_rejects_a_blank_remediation(blank: str) -> None:
    """Property 21: a blank ``error()`` remediation raises ``ValueError``.

    ``ValueError`` and not ``TypeError``: the argument was supplied and bound
    correctly, so the call shape is fine and the *value* is what fails. The
    message must name the check ID, because an ERROR row that reached the CSV
    with an empty ``Remediation`` cell would be unattributable to the check
    that produced it.

    Whitespace-only strings are drawn as well as ``""`` because the rule is
    stated in terms of emptiness after stripping (7.6), and because
    ``failed()`` treats the same values as a signal to fall back to the
    metadata default -- the two helpers diverge here on purpose and the
    divergence is worth pinning.

    Validates: Requirement 7.6.
    """
    instance = _initialized_check()

    kwargs = _valid_kwargs("error")
    kwargs["remediation"] = blank

    result: Any = _NO_RESULT
    with pytest.raises(ValueError) as excinfo:
        result = instance.error(**kwargs)

    assert result is _NO_RESULT, (
        f"error() returned {result!r} for a blank remediation {blank!r}"
    )
    assert _META.check_id in str(excinfo.value), (
        f"the ValueError from error() does not name the check ID: "
        f"{excinfo.value}"
    )
