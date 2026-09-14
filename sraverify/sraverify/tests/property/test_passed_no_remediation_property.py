"""
Property-based test for ``passed()`` and remediation (task 8.6).

This module implements **Property 14: ``passed()`` carries no remediation** from
the ``check-contract-formalization`` design:

    ``passed()`` has no ``remediation`` parameter:
    ``inspect.signature(SecurityCheck.passed).parameters`` does not contain
    ``"remediation"``, and every ``Finding`` produced by ``passed()`` has
    ``remediation == ""``.

The property has two halves, and both are structural rather than conventional:

  (a) **The empty cell is unrepresentable otherwise** (Requirement 7.2).
      ``passed()`` declares no ``remediation`` parameter at all -- not even one
      defaulting to ``""`` -- so a PASS row's ``Remediation`` cell is empty
      because there is nowhere for a value to come from. That is what collapses
      the 178 semantically empty remediation arguments of the pre-change
      catalog -- ``"No remediation needed"`` x114, ``""`` x45, ``"No action
      needed"`` x19 -- into one canonical empty cell.

  (b) **Supplying one is a call-site error** (Requirement 7.11). Passing
      ``remediation=`` to ``passed()`` raises ``TypeError`` and returns no
      ``Finding``, rather than being quietly accepted and dropped.

The substance of half (a) is the *contrast with* ``failed()``. Every drawn
``CheckMeta`` carries a **non-empty** ``meta.remediation.text``, so a helper
that silently reached for the metadata default would be caught: ``failed()``
does reach for it (Requirement 7.4) and is asserted to, while ``passed()``
against the very same metadata and the very same arguments still yields ``""``.
Were ``passed()`` routed through the same fallback, the assertions below would
fail on the first draw. Generating a blank ``remediation.text`` instead would
make the whole property vacuous -- and is in any case impossible, since
``CheckMeta`` rule 7 rejects it.

The last assertion follows the value out to the CSV cell: ``to_row()``'s
``"Remediation"`` entry is ``""``. An empty ``Finding.remediation`` that the row
renderer replaced with a placeholder would satisfy the field-level assertion
and still put "No remediation needed" in the file.

**Where the strategies live.** ``tests/property/strategies.py`` is
``Finding``-focused, and its ``cell_text()`` / ``regions()`` / ``check_ids()``
are reused here for exactly the fields they were written for. The
``CheckMeta`` generator and the stub context are **local to this module**: they
exist to make this one property non-vacuous, sibling property modules are being
written against the same helper concurrently, and ``strategies.py``
deliberately keeps per-property generators out.

**No AWS calls.** ``SecurityCheck._finding`` reaches exactly one method on the
attached context, ``get_account_info()``, so ``_StubContext`` below implements
that one method and nothing else. Nothing here constructs a boto3 session.

Feature: check-contract-formalization, Property 14: ``passed()`` carries no
remediation.

**Validates: Requirements 7.2, 7.11**
"""
from __future__ import annotations

import inspect
import string
from typing import Any, Dict, Optional

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sraverify.core.check import SecurityCheck
from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation

from .strategies import cell_text, check_ids, regions


# --------------------------------------------------------------------------- #
# Local strategies: legal CheckMeta
# --------------------------------------------------------------------------- #
#
# Every draw must construct, because a CheckMeta that fails validation raises
# MetadataError and would turn this property into a test of Property 19. So the
# generators below satisfy all thirteen value rules by construction rather than
# by filtering:
#
#   * words carry no whitespace, so joining them with single spaces yields
#     whitespace-normalized text (rule 4) that is non-empty (rule 3);
#   * every title's first token is drawn from a set holding no forbidden token
#     -- "Checkpoint" and "Ensured" are in it deliberately, since rule 5 is
#     token-level and must accept both;
#   * word and list sizes keep every field far under its length cap (rule 6);
#   * remediation.text is non-empty (rule 7), which is what half (a) needs.

#: One whitespace-free word. Letters and digits only, so " ".join over a list of
#: these is already in normalized form.
_WORDS = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")),
    min_size=1,
    max_size=10,
)

#: Legal first tokens for a title. Rule 5 forbids "ensure"/"ensures"/"check"/
#: "checks" as the first token, compared case-insensitively with trailing
#: punctuation stripped; none of these is one, and the last two are near
#: misses that the rule must let through.
_TITLE_HEADS = (
    "Detector",
    "Logging",
    "Encryption",
    "Delegated",
    "Checkpoint",
    "Ensured",
)


def _normalized_text(max_words: int = 6) -> st.SearchStrategy[str]:
    """Return a strategy for non-empty, whitespace-normalized metadata text."""
    return st.lists(_WORDS, min_size=1, max_size=max_words).map(" ".join)


def _titles() -> st.SearchStrategy[str]:
    """Return a strategy for legal ``CheckMeta.title`` values."""
    return st.builds(
        lambda head, tail: " ".join([head, *tail]),
        st.sampled_from(_TITLE_HEADS),
        st.lists(_WORDS, min_size=1, max_size=5),
    )


def _resource_types() -> st.SearchStrategy[str]:
    """Return a strategy matching ``AWS::[A-Za-z0-9]+::[A-Za-z0-9]+``.

    ASCII alphabet explicitly, not the ``Lu``/``Ll``/``Nd`` categories used for
    the free-text fields: ``RESOURCE_TYPE_RE`` is compiled with ``re.ASCII``, so
    ``µ`` (category ``Ll``) and a non-ASCII digit (category ``Nd``) are both
    rejected by rule 2.
    """
    segment = st.text(
        alphabet=string.ascii_letters + string.digits,
        min_size=1,
        max_size=14,
    )
    return st.builds(lambda a, b: f"AWS::{a}::{b}", segment, segment)


@st.composite
def check_metas(draw: st.DrawFn) -> CheckMeta:
    """Draw one arbitrary legal ``CheckMeta`` with non-empty remediation text.

    The non-empty ``remediation.text`` is the load-bearing part: it is the
    value ``failed()`` falls back to and the value ``passed()`` must never
    pick up.

    Args:
        draw: Supplied by ``hypothesis``.

    Returns:
        A ``CheckMeta`` that constructed successfully, so every validation
        rule is satisfied.
    """
    return CheckMeta(
        check_id=draw(check_ids()),
        title=draw(_titles()),
        description=draw(_normalized_text(max_words=12)),
        check_logic=draw(_normalized_text(max_words=8)),
        severity=draw(st.sampled_from(list(Severity))),
        account_type=draw(st.sampled_from(list(AccountType))),
        service=draw(_normalized_text(max_words=3)),
        resource_type=draw(_resource_types()),
        remediation=Remediation(text=draw(_normalized_text(max_words=10))),
    )


# --------------------------------------------------------------------------- #
# A context stub and a throwaway check
# --------------------------------------------------------------------------- #


class _StubContext:
    """The one context method ``_finding`` reaches, and nothing else.

    ``SecurityCheck._finding`` calls ``ctx.get_account_info()`` and copies the
    two values out by value; it touches no other attribute of the context. A
    real ``ScanContext`` would resolve those two values through
    ``sts:GetCallerIdentity`` and ``account:GetAccountInformation``, so this
    stub is what keeps the property offline and credential-free. The
    ``initialize(ctx)`` parameter is annotated ``ScanContext`` but nothing
    enforces it at run time.
    """

    def __init__(self) -> None:
        self._info: Dict[str, str] = {
            "account_id": "123456789012",
            "account_name": "stub-account",
        }

    def get_account_info(self) -> Dict[str, str]:
        """Return the same dict object on every call, as ``ScanContext`` does."""
        return self._info


def _initialized_check(meta: CheckMeta) -> SecurityCheck:
    """Return a throwaway initialized ``SecurityCheck`` carrying ``meta``.

    The subclass is declared here, in a module whose file stem does not begin
    with ``sra_``, so ``__init_subclass__`` returns at its eligibility gate:
    no identity rule is applied, no ``meta`` identity cross-check runs, and the
    class never enters the registry. That is the documented reason
    ``SecurityCheck`` stays usable from a test that declares a subclass in
    memory, and it is why an arbitrary drawn ``check_id`` is fine here.

    Args:
        meta: The metadata to attach as the class's ``meta``.

    Returns:
        An instance with a stub context already attached, so the three helpers
        are callable.
    """
    declared_meta = meta

    class _ThrowawayCheck(SecurityCheck):
        meta = declared_meta

        def _setup_clients(self) -> None:
            """Register no client wrappers; no helper below needs one."""

        def execute(self) -> Any:
            """Satisfy the abstract method. Never called by this property."""
            return ()

    check = _ThrowawayCheck()
    check.initialize(_StubContext())  # type: ignore[arg-type]
    return check


# --------------------------------------------------------------------------- #
# Half (a): the parameter does not exist, and the cell is always empty
# --------------------------------------------------------------------------- #


def test_passed_signature_declares_no_remediation() -> None:
    """``passed()`` has no ``remediation`` parameter; the other two do.

    The structural half of Property 14, asserted against the signature rather
    than against behavior, because "there is no such parameter" and "the
    parameter defaults to the empty string" are indistinguishable from the
    outside yet are different contracts. Only the former makes
    ``remediation="No remediation needed"`` on a PASS unrepresentable.

    The two contrast assertions are what keep this from passing for the wrong
    reason: a refactor that dropped ``remediation`` from all three signatures
    would satisfy the first assertion alone.

    **Validates: Requirements 7.2, 7.11**
    """
    passed_params = inspect.signature(SecurityCheck.passed).parameters
    assert "remediation" not in passed_params, (
        "passed() must declare no remediation parameter (7.2); found "
        f"{list(passed_params)}"
    )

    for helper in (SecurityCheck.failed, SecurityCheck.error):
        params = inspect.signature(helper).parameters
        assert "remediation" in params, (
            f"{helper.__name__}() must declare a remediation parameter, so "
            f"that passed()'s absence of one is a real distinction; found "
            f"{list(params)}"
        )


@given(
    meta=check_metas(),
    region=regions(),
    resource_id=st.one_of(st.none(), cell_text()),
    actual_value=cell_text(),
    checked_value=st.one_of(st.none(), cell_text()),
)
def test_passed_finding_carries_no_remediation(
    meta: CheckMeta,
    region: str,
    resource_id: Optional[str],
    actual_value: str,
    checked_value: Optional[str],
) -> None:
    """Every ``Finding`` from ``passed()`` has ``remediation == ""``.

    Three assertions, in order of increasing distance from the helper:

    1. the ``Finding``'s ``remediation`` field is exactly ``""``;
    2. ``failed()``, called on the same check with the same arguments, carries
       ``meta.remediation.text`` instead -- the contrast that shows ``passed()``
       is not merely being handed an empty default but is bypassing the
       metadata fallback entirely (7.2 against 7.4);
    3. the rendered CSV cell is empty too, so nothing between the helper and
       the row substitutes a placeholder.

    **Validates: Requirements 7.2, 7.11**
    """
    check = _initialized_check(meta)

    # Non-vacuity: the value passed() must not pick up is non-empty. Guaranteed
    # by CheckMeta rule 7, asserted here because the whole property rests on it.
    assert meta.remediation.text.strip(), (
        "the drawn metadata carries a blank remediation.text, which would make "
        "the contrast with failed() vacuous"
    )

    finding = check.passed(
        region=region,
        resource_id=resource_id,
        actual_value=actual_value,
        checked_value=checked_value,
    )

    assert isinstance(finding, Finding)
    assert finding.status is Status.PASS
    assert finding.remediation == "", (
        f"a PASS Finding must carry an empty remediation, got "
        f"{finding.remediation!r}"
    )

    # The contrast. Same check, same arguments, different helper.
    failure = check.failed(
        region=region,
        resource_id=resource_id,
        actual_value=actual_value,
        checked_value=checked_value,
    )
    assert failure.remediation == meta.remediation.text, (
        "failed() must fall back to meta.remediation.text, so that passed() "
        "returning '' demonstrates it bypasses that fallback"
    )
    assert finding.remediation != failure.remediation

    # And out to the cell the dashboards read.
    assert finding.to_row()["Remediation"] == "", (
        "the PASS row's Remediation cell must be empty, got "
        f"{finding.to_row()['Remediation']!r}"
    )


# --------------------------------------------------------------------------- #
# Half (b): supplying one is a TypeError
# --------------------------------------------------------------------------- #


@given(
    meta=check_metas(),
    region=regions(),
    resource_id=st.one_of(st.none(), cell_text()),
    actual_value=cell_text(),
    remediation=st.one_of(cell_text(), st.just("No remediation needed")),
)
def test_passed_rejects_a_remediation_argument(
    meta: CheckMeta,
    region: str,
    resource_id: Optional[str],
    actual_value: str,
    remediation: str,
) -> None:
    """Passing ``remediation=`` to ``passed()`` raises ``TypeError``.

    No value is exempt: the drawn values include ``"No remediation needed"``,
    the most common of the 178 semantically empty arguments the change removes,
    and it is refused like any other. The error names both the helper and the
    parameter, so the author sees which call site to fix (7.11), and no
    ``Finding`` is produced.

    **Validates: Requirements 7.2, 7.11**
    """
    check = _initialized_check(meta)

    with pytest.raises(TypeError) as excinfo:
        check.passed(
            region=region,
            resource_id=resource_id,
            actual_value=actual_value,
            remediation=remediation,  # type: ignore[call-arg]
        )

    message = str(excinfo.value)
    assert "remediation" in message, (
        f"the TypeError must name the rejected parameter, got {message!r}"
    )
    assert "passed" in message, (
        f"the TypeError must name the helper, got {message!r}"
    )
