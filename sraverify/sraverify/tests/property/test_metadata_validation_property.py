"""
Property-based test for ``CheckMeta`` validation (task 3.3).

This module implements **Property 19: Metadata validation totality** from the
``check-contract-formalization`` design. Property 19 is the only property
covering Requirement 3, so the thirteen value rules have no other
property-level coverage, and it has two halves:

  (a) **Totality** -- for any argument set violating any rule, *no* ``CheckMeta``
      instance escapes to a caller. Construction raises ``MetadataError``
      rather than returning a partially-validated object, which is what makes
      a defective declaration an import failure of the module that declares it
      (Requirement 3.11).
  (b) **Determinism of the report** -- the rule reported is the first failing
      rule in ascending criterion order, so a declaration violating two rules
      always produces the same error regardless of which one a reader would
      have noticed first (Requirement 3.10).

The pair the design singles out is a malformed ``check_id`` (rule 1) together
with a blank ``remediation.text`` (rule 7). It has its own test below. It is
the assertion that catches a regression of the decision to keep *every* rule on
``CheckMeta.__post_init__``: ``Remediation(...)`` is evaluated as an *argument*
to ``CheckMeta(...)``, so validation moved onto ``Remediation.__post_init__``
would run strictly earlier and this declaration would report the remediation
failure instead of the malformed ID.

A third, smaller assertion covers Requirement 3.12 by reading the validator's
own imports: it validates using the standard library only.

**Where the strategies live.** All the generators here produce *illegal* input,
and ``tests/property/strategies.py`` states that illegal-input strategies
belong with the property that needs them rather than in the shared helper. That
helper is also ``Finding``-focused, and Property 19 is the only property
quantifying over ``CheckMeta``. So these strategies are local to this module.
The one legal-declaration generator, ``legal_kwargs()``, is local for the same
reason: it exists to keep half (a) non-vacuous, not to be reused.

Feature: check-contract-formalization, Property 19: Metadata validation
totality.

**Validates: Requirements 3.10, 3.11, 3.12**
"""
from __future__ import annotations

import ast
import dataclasses
import itertools
import string
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from sraverify.core import metadata as metadata_module
from sraverify.core.enums import AccountType, Severity
from sraverify.core.errors import MetadataError
from sraverify.core.metadata import (
    CHECK_ID_RE,
    MAX_CHECK_LOGIC,
    MAX_DESCRIPTION,
    MAX_REMEDIATION_EXAMPLE,
    MAX_REMEDIATION_TEXT,
    MAX_SEQUENCE_ELEMENTS,
    MAX_SERVICE,
    MAX_SRA_SECTION,
    MAX_TITLE,
    MAX_URL,
    RESOURCE_TYPE_RE,
    CheckMeta,
    Remediation,
)


# --------------------------------------------------------------------------- #
# A legal baseline, and a way to inject one illegal value into it
# --------------------------------------------------------------------------- #
#
# The baseline is legal in every respect, so a MetadataError raised from a
# construction using it can only have come from the value the test injected.
# ``_KWARGS`` is rebuilt per call rather than shared, because CheckMeta is
# frozen but the dict handed to it is not.

_CHECK_ID = "SRA-GUARDDUTY-01"


def _remediation(**overrides: str) -> Remediation:
    """Return a legal ``Remediation``, with any field overridden."""
    fields: Dict[str, str] = {
        "text": "Enable GuardDuty in every enabled region.",
        "cli": "aws guardduty create-detector --enable --region us-east-1",
        "console": "GuardDuty console -> Get Started -> Enable GuardDuty",
    }
    fields.update(overrides)
    return Remediation(**fields)


def _kwargs(**overrides: Any) -> Dict[str, Any]:
    """Return a complete set of legal ``CheckMeta`` kwargs, with overrides."""
    kwargs: Dict[str, Any] = {
        "check_id": _CHECK_ID,
        "title": "GuardDuty detector exists in every enabled region",
        "description": (
            "A GuardDuty detector represents the service in one region and "
            "must be present in every enabled region so findings are "
            "generated even where the account is not active."
        ),
        "check_logic": (
            "Calls ListDetectors per region and fails where no detector "
            "is returned."
        ),
        "severity": Severity.HIGH,
        "account_type": AccountType.APPLICATION,
        "service": "GuardDuty",
        "resource_type": "AWS::GuardDuty::Detector",
        "remediation": _remediation(),
        "sra_sections": ("Security Tooling account",),
        "additional_urls": (
            "https://docs.aws.amazon.com/guardduty/latest/ug/what-is.html",
        ),
    }
    kwargs.update(overrides)
    return kwargs


def _inject_into(
    kwargs: Dict[str, Any], channel: str, value: Any
) -> Dict[str, Any]:
    """Set ``channel`` on an existing kwargs dict, remediation fields included.

    ``channel`` is a ``CheckMeta`` field name, or one of ``remediation.text``,
    ``remediation.cli``, ``remediation.console`` -- the three fields that live
    one level down but whose rules are enforced by ``CheckMeta``.
    """
    if channel.startswith("remediation."):
        field = channel.split(".", 1)[1]
        kwargs["remediation"] = dataclasses.replace(
            kwargs["remediation"], **{field: value}
        )
    else:
        kwargs[channel] = value
    return kwargs


def _inject(channel: str, value: Any) -> Dict[str, Any]:
    """Return legal kwargs with ``channel`` set to ``value``."""
    return _inject_into(_kwargs(), channel, value)


def test_the_baseline_is_legal() -> None:
    """A guard against a vacuous suite: the baseline must construct.

    Every test below injects one illegal value into ``_kwargs()`` and asserts
    a raise. If the baseline itself were defective, all of them would pass for
    the wrong reason.
    """
    meta = CheckMeta(**_kwargs())
    assert meta.check_id == _CHECK_ID
    assert isinstance(meta.severity, Severity)


# --------------------------------------------------------------------------- #
# Strategies for illegal values, one rule at a time
# --------------------------------------------------------------------------- #
#
# Two constraints shape these generators.
#
# First, each must violate its own rule and no *lower-numbered* rule, or the
# error reported would name a different rule and the test would be asserting
# the wrong thing. The sharp case is rule 7: ``remediation.text = " "`` is
# blank, but a lone space is also not whitespace-normalized, so rule 4 fires
# first. The empty string is the only blank value that reaches rule 7, and
# that is why ``blank_remediation_text`` is ``st.just("")`` while rule 3's
# blanks are unrestricted.
#
# Second, generated text avoids ``=``, ``.``, ``,`` and ``:`` so a drawn value
# echoed back in an error message cannot accidentally contain another rule's
# reporting fragment. The pair test guards against that anyway, but keeping the
# alphabets clean means the guard almost never has to fire.

_WORD_ALPHABET = string.ascii_letters + string.digits
_LOOSE_ALPHABET = _WORD_ALPHABET + " -_"

#: Blank in the ``str.strip()`` sense, including a non-ASCII whitespace
#: character so rule 3 is exercised beyond the ASCII space.
_BLANKS = ("", " ", "   ", "\t", "\n", "\r\n", " \t\n ", "\u00a0", "\u2003")

#: The rendered value of the pre-fix ``sra_guardduty_01`` description. The
#: source used backslash continuations, so the string carries runs of leading
#: whitespace from the indentation of each continued line. Rule 4 is the only
#: defense against this defect, and anchoring the property to the real value
#: rather than a synthetic double space is the point of including it.
_GD01_PREFIX_DESCRIPTION = (
    "This check verifies that an GuardDuty detector exists in the AWS Region.\
              A detector is a resource that represents the GuardDuty service and should be present \
                in all AWS member account and AWS Region so that GuardDuty can generate findings \
                    about unauthorized or unusual activity even in those Regions that you may not \
                        be using actively."
)


def malformed_check_ids() -> st.SearchStrategy[str]:
    """Generate values that ``CHECK_ID_RE.fullmatch`` rejects.

    The samples carry the near-misses random text will not find: a one-digit
    and a three-digit number, the wrong letter case, the legacy short IDs
    still quoted in stale docstrings, surrounding whitespace, a trailing
    newline (which ``$`` would have tolerated and ``fullmatch`` does not), and
    non-ASCII digits and full-width letters, which are what ``re.ASCII``
    exists to reject.
    """
    near_misses = st.sampled_from(
        [
            "",
            " ",
            "SRA-GUARDDUTY-1",
            "SRA-GUARDDUTY-001",
            "sra-guardduty-01",
            "SRA-GuardDuty-01",
            "SRA--01",
            "SRA-GUARDDUTY-",
            "SRA-GUARDDUTY-01 ",
            " SRA-GUARDDUTY-01",
            "SRA-GUARDDUTY-01\n",
            "SRA-GUARDDUTY-01-02",
            "SRA_GUARDDUTY_01",
            "GUARDDUTY-01",
            "SRA-GD-1",            # a legacy short ID; no such check exists
            "SRA-IAA-1",
            "SRA-GUARDDUTY-\u0660\u0661",   # Arabic-Indic digits
            "SRA-GUARDDUTY-0\u0661",
            "SRA-\uff27\uff35\uff21\uff32\uff24-01",  # full-width letters
        ]
    )
    arbitrary = st.text(alphabet=_LOOSE_ALPHABET, max_size=20)
    return st.one_of(near_misses, arbitrary).filter(
        lambda value: not CHECK_ID_RE.fullmatch(value)
    )


def malformed_resource_types() -> st.SearchStrategy[str]:
    """Generate values that ``RESOURCE_TYPE_RE.fullmatch`` rejects."""
    near_misses = st.sampled_from(
        [
            "",
            "GuardDuty::Detector",
            "AWS::GuardDuty",
            "AWS::GuardDuty::",
            "AWS::::Detector",
            "AWS::GuardDuty::Detector::Extra",
            "aws::guardduty::detector",
            "Aws::GuardDuty::Detector",
            "AWS:GuardDuty:Detector",
            "AWS::Guard Duty::Detector",
            "AWS::S3-Bucket::Policy",
            "AWS::GuardDuty::Detector ",
            "AWS::GuardDuty::Detector\n",
            "AWS::\uff27uardDuty::Detector",   # full-width letter
        ]
    )
    arbitrary = st.text(alphabet=_WORD_ALPHABET + ":", max_size=24)
    return st.one_of(near_misses, arbitrary).filter(
        lambda value: not RESOURCE_TYPE_RE.fullmatch(value)
    )


def blanks() -> st.SearchStrategy[str]:
    """Generate values that are empty after ``str.strip()``."""
    return st.sampled_from(_BLANKS)


@st.composite
def non_normalized_text(draw: st.DrawFn, max_words: int = 4) -> str:
    """Generate text that differs from its whitespace-normalized form.

    Built as words joined by a whitespace run that is never a single space, or
    as a normalized value with whitespace added at one end -- the two shapes
    the rule catches. The real pre-fix GD-01 description is drawn alongside
    them, and the result is always non-blank and inside every length cap, so
    rules 3 and 6 stay out of the way.
    """
    if draw(st.booleans()):
        return _GD01_PREFIX_DESCRIPTION

    words = draw(
        st.lists(
            st.text(alphabet=_WORD_ALPHABET, min_size=1, max_size=8),
            min_size=1,
            max_size=max_words,
        )
    )
    separator = draw(
        st.sampled_from(["  ", "   ", "\t", "\n", "\r\n", " \t ", "\u00a0"])
    )
    if len(words) > 1:
        return separator.join(words)
    # One word cannot carry an interior separator, so put it at an edge.
    edge = draw(st.sampled_from(["leading", "trailing", "both"]))
    word = words[0]
    if edge == "leading":
        return f"{separator}{word}"
    if edge == "trailing":
        return f"{word}{separator}"
    return f"{separator}{word}{separator}"


@st.composite
def forbidden_titles(draw: st.DrawFn) -> str:
    """Generate titles whose first token is ``ensure``/``check`` and kin.

    Letter case is varied and trailing punctuation is optionally appended,
    because the rule lower-cases the token and strips trailing punctuation
    before comparing -- so ``"Ensure:"`` and ``"CHECKS,"`` are in range. The
    result is whitespace-normalized and inside the title cap, so rules 3, 4
    and 6 stay out of the way.
    """
    stem = draw(st.sampled_from(["ensure", "ensures", "check", "checks"]))
    cased = draw(
        st.sampled_from([stem, stem.upper(), stem.capitalize(), stem.title()])
    )
    punctuation = draw(st.sampled_from(["", ":", ",", ".", "!", '"', ")", "-"]))
    rest = draw(
        st.lists(
            st.text(alphabet=_WORD_ALPHABET, min_size=1, max_size=8),
            min_size=1,
            max_size=4,
        )
    )
    return " ".join([f"{cased}{punctuation}", *rest])


def over_long(maximum: int) -> st.SearchStrategy[str]:
    """Generate a single-token string longer than ``maximum`` characters.

    A single token of one repeated letter is already whitespace-normalized and
    is not a forbidden first token, so length is the only rule it breaks.
    """
    return st.integers(min_value=maximum + 1, max_value=maximum + 8).map(
        lambda length: "a" * length
    )


def malformed_urls() -> st.SearchStrategy[str]:
    """Generate ``additional_urls`` elements that rule 8 rejects.

    One sample per clause of the rule -- wrong scheme, nothing after the
    scheme, embedded whitespace, over the length cap -- plus arbitrary text
    filtered to the ones that fail.
    """
    near_misses = st.sampled_from(
        [
            "",
            " ",
            "http://docs.aws.amazon.com/guardduty/",
            "HTTPS://docs.aws.amazon.com/guardduty/",
            "ftp://docs.aws.amazon.com/guardduty/",
            "docs.aws.amazon.com/guardduty/",
            "//docs.aws.amazon.com/guardduty/",
            "https:/docs.aws.amazon.com/guardduty/",
            "https://",
            "https:// docs.aws.amazon.com",
            "https://docs.aws.amazon.com/a b",
            "https://docs.aws.amazon.com/a\nb",
            "https://docs.aws.amazon.com/a\tb",
            "https://docs.aws.amazon.com/x\n",
            "https://" + "a" * (MAX_URL - len("https://") + 1),
        ]
    )
    arbitrary = st.text(alphabet=_LOOSE_ALPHABET + "/", max_size=24)
    return st.one_of(near_misses, arbitrary).filter(_url_is_illegal)


def _url_is_illegal(url: str) -> bool:
    """Whether ``url`` breaks rule 8, stated independently of the validator."""
    scheme = "https://"
    return (
        not url.startswith(scheme)
        or len(url) == len(scheme)
        or any(char.isspace() for char in url)
        or len(url) > MAX_URL
    )


def malformed_sections() -> st.SearchStrategy[str]:
    """Generate ``sra_sections`` elements that rule 9 rejects.

    Only the empty string and an over-long value: any other blank value is
    also not whitespace-normalized, which rule 4 catches first.
    """
    return st.one_of(
        st.just(""),
        st.integers(
            min_value=MAX_SRA_SECTION + 1, max_value=MAX_SRA_SECTION + 40
        ).map(lambda length: "a" * length),
    )


def over_long_sequences(element: str) -> st.SearchStrategy[Tuple[str, ...]]:
    """Generate a tuple of more than ``MAX_SEQUENCE_ELEMENTS`` legal elements.

    Every element is individually legal, so rules 4, 8 and 9 stay out of the
    way and the count is the only rule broken.
    """
    return st.integers(
        min_value=MAX_SEQUENCE_ELEMENTS + 1, max_value=MAX_SEQUENCE_ELEMENTS + 10
    ).map(lambda count: tuple(f"{element}{index}" for index in range(count)))


# --------------------------------------------------------------------------- #
# The rule table
# --------------------------------------------------------------------------- #
#
# ``reported`` is a fragment of the message this rule produces, chosen to
# describe the *rule* rather than the offending value, so it also serves as the
# fragment the pair test asserts is absent when a lower-numbered rule reports.
# ``echoes_value`` records whether the message quotes the offending value.


@dataclasses.dataclass(frozen=True)
class Violation:
    """One way to break one rule, and how the resulting message identifies it."""

    rule: int
    channel: str
    values: st.SearchStrategy[Any]
    reported: str
    echoes_value: bool = True

    @property
    def label(self) -> str:
        """A pytest parameter id."""
        return f"rule{self.rule:02d}-{self.channel}"


#: One canonical violation per rule, each writing a *different* field, so any
#: two of them compose into a single declaration that breaks exactly two rules.
#: Rule 13 is absent by necessity -- it can only be broken through
#: ``sra_sections`` or ``additional_urls``, which rules 4, 8 and 9 already use,
#: so its ordering cases are three hand-written tests further down.
CANONICAL: Tuple[Violation, ...] = (
    Violation(1, "check_id", malformed_check_ids(), "check_id="),
    Violation(2, "resource_type", malformed_resource_types(), "resource_type="),
    Violation(3, "description", blanks(), "description is empty", False),
    Violation(4, "check_logic", non_normalized_text(), "is not whitespace-normalized"),
    Violation(5, "title", forbidden_titles(), "must state the control as a fact"),
    Violation(6, "service", over_long(MAX_SERVICE), "characters, maximum is", False),
    Violation(
        7, "remediation.text", st.just(""), "remediation.text is empty", False
    ),
    Violation(8, "additional_urls", malformed_urls().map(lambda url: (url,)),
              "additional_urls element"),
    Violation(9, "sra_sections", malformed_sections().map(lambda s: (s,)),
              "sra_sections element"),
)

#: Every channel each rule can be broken through, for the totality half. The
#: canonical set is a subset: rules 3, 4 and 6 reach several fields each, and a
#: rule enforced on one field but forgotten on another would otherwise pass.
EVERY_VIOLATION: Tuple[Violation, ...] = CANONICAL + (
    Violation(3, "title", blanks(), "title is empty", False),
    Violation(3, "check_logic", blanks(), "check_logic is empty", False),
    Violation(3, "service", blanks(), "service is empty", False),
    Violation(4, "title", non_normalized_text(), "is not whitespace-normalized"),
    Violation(4, "description", non_normalized_text(), "is not whitespace-normalized"),
    Violation(4, "service", non_normalized_text(2), "is not whitespace-normalized"),
    Violation(
        4,
        "remediation.text",
        non_normalized_text(),
        "is not whitespace-normalized",
    ),
    Violation(
        4,
        "sra_sections",
        non_normalized_text().map(lambda section: (section,)),
        "is not whitespace-normalized",
    ),
    Violation(6, "title", over_long(MAX_TITLE), "characters, maximum is", False),
    Violation(
        6, "description", over_long(MAX_DESCRIPTION), "characters, maximum is", False
    ),
    Violation(
        6, "check_logic", over_long(MAX_CHECK_LOGIC), "characters, maximum is", False
    ),
    Violation(
        6,
        "remediation.text",
        over_long(MAX_REMEDIATION_TEXT),
        "characters, maximum is",
        False,
    ),
    Violation(
        6,
        "remediation.cli",
        over_long(MAX_REMEDIATION_EXAMPLE),
        "characters, maximum is",
        False,
    ),
    Violation(
        6,
        "remediation.console",
        over_long(MAX_REMEDIATION_EXAMPLE),
        "characters, maximum is",
        False,
    ),
    Violation(
        13,
        "sra_sections",
        over_long_sequences("Section "),
        "elements, maximum is",
        False,
    ),
    Violation(
        13,
        "additional_urls",
        over_long_sequences("https://docs.aws.amazon.com/page"),
        "elements, maximum is",
        False,
    ),
)


# --------------------------------------------------------------------------- #
# (a) Totality: no CheckMeta escapes when any rule is violated
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "violation", EVERY_VIOLATION, ids=[v.label for v in EVERY_VIOLATION]
)
@given(data=st.data())
@settings(max_examples=100, deadline=None)
def test_no_check_meta_escapes_when_a_rule_is_violated(
    violation: Violation, data: st.DataObject
) -> None:
    """Property 19 (a): a violating declaration yields no instance at all.

    ``escaped`` stays bound to ``None`` because the assignment never completes:
    validation runs inside ``__post_init__``, during construction, so there is
    no window in which a partially-validated ``CheckMeta`` is returned and
    checked afterwards. That is the whole of Requirement 3.11 -- and the reason
    a check module declaring a defective ``CheckMeta`` fails at import rather
    than at scan time.

    ``CheckMeta`` is frozen *and* slotted, so it carries no ``__weakref__``
    slot and a weakref-based liveness assertion is not available. The unbound
    error result is the direct statement of the same thing.

    The message must also name the rule and the declaring module file, so the
    traceback alone identifies both what is wrong and where.

    Validates: Requirements 3.11, 3.10.
    """
    value = data.draw(violation.values)

    escaped = None
    with pytest.raises(MetadataError) as excinfo:
        escaped = CheckMeta(**_inject(violation.channel, value))

    assert escaped is None, (
        f"rule {violation.rule} was violated through {violation.channel} yet "
        f"a CheckMeta escaped: {escaped!r}"
    )

    message = str(excinfo.value)
    assert violation.reported in message, (
        f"a rule {violation.rule} violation on {violation.channel} must report "
        f"{violation.reported!r}; got {message!r}"
    )
    assert Path(__file__).name in message, (
        f"the error must name the declaring module file; got {message!r}"
    )
    if violation.echoes_value:
        quoted = repr(value[0] if isinstance(value, tuple) else value)
        assert quoted in message, (
            f"the error must quote the offending value {quoted}; "
            f"got {message!r}"
        )


#: The rules Requirement 3.10 orders: criteria 1 through 9, and criterion 13.
ALL_RULES = frozenset({1, 2, 3, 4, 5, 6, 7, 8, 9, 13})


def test_every_rule_is_represented() -> None:
    """The table above covers all ten rules, so totality is not partial.

    If a rule were added to ``__post_init__`` without a row here, the totality
    test would still pass while covering less, so the coverage is asserted
    rather than assumed.
    """
    covered = {violation.rule for violation in EVERY_VIOLATION}
    assert covered == set(ALL_RULES), (
        f"the violation table must cover every rule; missing "
        f"{sorted(ALL_RULES - covered)}"
    )


@st.composite
def legal_kwargs(draw: st.DrawFn) -> Dict[str, Any]:
    """Draw a declaration that satisfies every rule.

    Deliberately near the boundaries the rules draw -- a title whose first
    token merely *starts with* a forbidden word (``Checkpoint``, ``Ensured``),
    a value exactly at a length cap, exactly ``MAX_SEQUENCE_ELEMENTS``
    elements, a URL of exactly one character past the scheme -- because those
    are the draws that would fail against an off-by-one rule.
    """
    service_segment = draw(
        st.text(alphabet=string.ascii_uppercase + string.digits, min_size=1,
                max_size=12)
    )
    number = draw(st.integers(min_value=1, max_value=99))
    check_id = f"SRA-{service_segment}-{number:02d}"

    first_token = draw(
        st.sampled_from(
            ["Checkpoint", "Ensured", "GuardDuty", "Checked", "Ensuring", "S3"]
        )
    )
    rest = draw(
        st.lists(
            st.text(alphabet=_WORD_ALPHABET, min_size=1, max_size=8),
            min_size=1,
            max_size=4,
        )
    )
    title = " ".join([first_token, *rest])

    def capped(maximum: int) -> st.SearchStrategy[str]:
        """One normalized token, sometimes exactly at the cap."""
        return st.one_of(
            st.text(alphabet=_WORD_ALPHABET, min_size=1, max_size=12),
            st.just("a" * maximum),
        )

    section = draw(st.sampled_from(["Security Tooling account", "a" * MAX_SRA_SECTION]))
    sections = draw(
        st.one_of(
            st.just(()),
            st.just((section,)),
            st.just(tuple(f"Section {i}" for i in range(MAX_SEQUENCE_ELEMENTS))),
        )
    )
    url = draw(
        st.sampled_from(
            [
                "https://a",
                "https://docs.aws.amazon.com/guardduty/latest/ug/what-is.html",
                "https://" + "a" * (MAX_URL - len("https://")),
            ]
        )
    )
    urls = draw(
        st.one_of(
            st.just(()),
            st.just((url,)),
            st.just(
                tuple(
                    f"https://example.aws/{i}" for i in range(MAX_SEQUENCE_ELEMENTS)
                )
            ),
        )
    )

    return {
        "check_id": check_id,
        "title": title,
        "description": draw(capped(MAX_DESCRIPTION)),
        "check_logic": draw(capped(MAX_CHECK_LOGIC)),
        "severity": draw(st.sampled_from(list(Severity))),
        "account_type": draw(st.sampled_from(list(AccountType))),
        "service": draw(capped(MAX_SERVICE)),
        "resource_type": f"AWS::{draw(st.sampled_from(['GuardDuty', 'S3', 'EC2']))}"
                         f"::{draw(st.sampled_from(['Detector', 'Bucket', 'Vpc']))}",
        "remediation": Remediation(
            text=draw(capped(MAX_REMEDIATION_TEXT)),
            # Exempt from normalization: a command example keeps its line
            # breaks and its alignment.
            cli=draw(
                st.sampled_from(
                    [
                        "",
                        "aws guardduty create-detector \\\n    --enable",
                        "a" * MAX_REMEDIATION_EXAMPLE,
                    ]
                )
            ),
            console=draw(st.sampled_from(["", "Console ->\n  Settings"])),
        ),
        "sra_sections": sections,
        "additional_urls": urls,
    }


@given(kwargs=legal_kwargs())
@settings(max_examples=200, deadline=None)
def test_a_legal_declaration_is_accepted(kwargs: Dict[str, Any]) -> None:
    """Property 19 (a), the other direction: the validator rejects only defects.

    Without this, half (a) would be satisfied by a validator that raises
    unconditionally. The draws sit on the rules' boundaries, so an off-by-one
    in a length cap or a prefix-level implementation of the title rule fails
    here.

    Validates: Requirement 3.11.
    """
    meta = CheckMeta(**kwargs)
    assert meta.check_id == kwargs["check_id"]
    assert isinstance(meta.severity, Severity)
    assert isinstance(meta.account_type, AccountType)


# --------------------------------------------------------------------------- #
# (b) Determinism: two rules broken, the lower-numbered one is reported
# --------------------------------------------------------------------------- #


_PAIRS: List[Tuple[Violation, Violation]] = [
    (lower, higher) for lower, higher in itertools.combinations(CANONICAL, 2)
]


@pytest.mark.parametrize(
    ("lower", "higher"),
    _PAIRS,
    ids=[f"{lower.label}+{higher.label}" for lower, higher in _PAIRS],
)
@given(data=st.data())
@settings(max_examples=25, deadline=None)
def test_the_lower_numbered_rule_is_the_one_reported(
    lower: Violation, higher: Violation, data: st.DataObject
) -> None:
    """Property 19 (b): the reported rule is the first in criterion order.

    Every pair of the nine canonical violations is composed into one
    declaration -- they write nine distinct fields, so each pair breaks exactly
    two rules -- and the message must name the lower-numbered one and say
    nothing about the higher-numbered one. Pinning both directions is what
    makes the diagnostic for a given defective declaration reproducible instead
    of depending on the order a reader, or a future refactor, happens to
    prefer.

    Validates: Requirement 3.10.
    """
    lower_value = data.draw(lower.values)
    higher_value = data.draw(higher.values)

    kwargs = _inject(lower.channel, lower_value)
    kwargs = _inject_into(kwargs, higher.channel, higher_value)

    escaped = None
    with pytest.raises(MetadataError) as excinfo:
        escaped = CheckMeta(**kwargs)

    assert escaped is None
    message = str(excinfo.value)
    assert lower.reported in message, (
        f"a declaration breaking rules {lower.rule} and {higher.rule} must "
        f"report rule {lower.rule} ({lower.reported!r}); got {message!r}"
    )
    # The offending values are quoted in the message, so only assert the
    # higher rule is silent when its fragment cannot have arrived that way.
    injected = repr((lower_value, higher_value))
    if higher.reported not in injected:
        assert higher.reported not in message, (
            f"a declaration breaking rules {lower.rule} and {higher.rule} must "
            f"say nothing about rule {higher.rule} ({higher.reported!r}); got "
            f"{message!r}"
        )


@given(check_id=malformed_check_ids())
@settings(max_examples=200, deadline=None)
def test_malformed_check_id_beats_blank_remediation_text(check_id: str) -> None:
    """Property 19 (b), the pair the design singles out: rule 1 beats rule 7.

    ``Remediation(...)`` is evaluated as an argument to ``CheckMeta(...)``, so
    a ``__post_init__`` on ``Remediation`` would run strictly before
    ``CheckMeta.__post_init__``. A declaration carrying both a malformed
    ``check_id`` and a blank ``remediation.text`` would then report the
    remediation failure -- out of criterion order, and naming a field the
    reader has no way to locate because the check ID it would have been keyed
    to never got validated.

    This is the assertion that catches that regression. If someone moves any
    remediation rule onto ``Remediation``, this test fails.

    Validates: Requirement 3.10.
    """
    escaped = None
    with pytest.raises(MetadataError) as excinfo:
        escaped = CheckMeta(
            **_kwargs(check_id=check_id, remediation=_remediation(text=""))
        )

    assert escaped is None
    message = str(excinfo.value)
    assert "check_id=" in message and repr(check_id) in message, (
        f"a malformed check_id together with a blank remediation.text must "
        f"report the check_id (rule 1); got {message!r}"
    )
    # Rule 7's own reporting fragment, not the bare word "remediation": rule 1
    # quotes the offending check_id back with !r, so a drawn value of
    # "remediation" would put that word in the message by itself. Asserting the
    # fragment keeps the regression in range -- a remediation rule moved onto
    # ``Remediation.__post_init__`` reports rule 7 and this fails -- while a
    # drawn value can no longer satisfy it by accident. Guarded the same way
    # the pair test above is, so the assertion cannot be met by the echo even
    # if a future strategy widens far enough to spell the fragment out.
    rule_7_reported = "remediation.text is empty"
    if rule_7_reported not in repr(check_id):
        assert rule_7_reported not in message, (
            "rule 7 must stay silent while rule 1 is failing -- reporting it "
            "here means validation has moved onto Remediation, out of "
            f"criterion order; got {message!r}"
        )


# --------------------------------------------------------------------------- #
# (b) continued: rule 13 can only be broken through a shared field
# --------------------------------------------------------------------------- #
#
# The count rule is ordered *after* the element rules, so a twenty-one-element
# sequence containing one bad element reports the bad element. Three tests,
# one per element rule that can reach a sequence.


@given(section=non_normalized_text())
@settings(max_examples=100, deadline=None)
def test_non_normalized_section_beats_the_element_count(section: str) -> None:
    """Rule 4 beats rule 13 on ``sra_sections``.

    Validates: Requirement 3.10.
    """
    sections = (section,) + tuple(
        f"Section {index}" for index in range(MAX_SEQUENCE_ELEMENTS)
    )
    assert len(sections) > MAX_SEQUENCE_ELEMENTS

    with pytest.raises(MetadataError) as excinfo:
        CheckMeta(**_kwargs(sra_sections=sections))

    message = str(excinfo.value)
    assert "is not whitespace-normalized" in message, message
    assert "elements, maximum is" not in message, message


@given(section=malformed_sections())
@settings(max_examples=100, deadline=None)
def test_illegal_section_beats_the_element_count(section: str) -> None:
    """Rule 9 beats rule 13 on ``sra_sections``.

    Validates: Requirement 3.10.
    """
    sections = tuple(
        f"Section {index}" for index in range(MAX_SEQUENCE_ELEMENTS)
    ) + (section,)
    assert len(sections) > MAX_SEQUENCE_ELEMENTS

    with pytest.raises(MetadataError) as excinfo:
        CheckMeta(**_kwargs(sra_sections=sections))

    message = str(excinfo.value)
    assert "sra_sections element" in message, message
    assert "elements, maximum is" not in message, message


@given(url=malformed_urls())
@settings(max_examples=100, deadline=None)
def test_illegal_url_beats_the_element_count(url: str) -> None:
    """Rule 8 beats rule 13 on ``additional_urls``.

    This is the case the validator's own comment names: a thirty-element list
    holding one bad URL reports the bad URL.

    Validates: Requirement 3.10.
    """
    urls = tuple(
        f"https://example.aws/{index}" for index in range(MAX_SEQUENCE_ELEMENTS)
    ) + (url,)
    assert len(urls) > MAX_SEQUENCE_ELEMENTS

    with pytest.raises(MetadataError) as excinfo:
        CheckMeta(**_kwargs(additional_urls=urls))

    message = str(excinfo.value)
    assert "additional_urls element" in message, message
    assert "elements, maximum is" not in message, message


# --------------------------------------------------------------------------- #
# The validator uses the standard library only
# --------------------------------------------------------------------------- #


def test_the_validator_imports_only_the_standard_library() -> None:
    """Requirement 3.12: validation depends on nothing installed.

    Asserted by reading ``core/metadata.py``'s own import statements rather
    than by inspecting the imported module object, because the latter would
    also see everything imported transitively and could not distinguish a
    dependency this module took from one its importer took. Anything rooted at
    ``sraverify`` is this package itself; everything else must be in the
    standard library.

    ``CheckMeta`` validation runs at import time in every check module, so a
    third-party import here would make the whole catalog undeployable without
    that package present.

    Validates: Requirement 3.12.
    """
    source = Path(metadata_module.__file__).read_text(encoding="utf-8")
    roots = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # A relative import (level > 0) is within this package.
            if node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])

    assert roots, "no imports found; the source was probably not parsed"
    foreign = {
        root
        for root in roots
        if root != "sraverify" and root not in sys.stdlib_module_names
    }
    assert not foreign, (
        f"core/metadata.py must validate using the standard library only; "
        f"found {sorted(foreign)}"
    )
