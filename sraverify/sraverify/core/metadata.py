"""The validated check metadata type.

A ``CheckMeta`` is declared in a check class's own body and validated while
that class body executes, so a defective declaration is an import failure.
This module defines a type and validates it: it loads nothing, reads nothing,
and caches nothing.
"""

from __future__ import annotations

import re
import string
import sys
from dataclasses import dataclass
from typing import Final

from sraverify.core.enums import AccountType, Severity
from sraverify.core.errors import MetadataError

# re.ASCII on both, so a non-ASCII digit cannot satisfy \d and a full-width
# letter cannot satisfy [A-Z]. Anchored with fullmatch at the call site rather
# than relying on $ tolerating a trailing newline.
CHECK_ID_RE: Final = re.compile(r"SRA-[A-Z0-9]+-\d{2}", re.ASCII)
RESOURCE_TYPE_RE: Final = re.compile(r"AWS::[A-Za-z0-9]+::[A-Za-z0-9]+", re.ASCII)

MAX_TITLE = 120
MAX_DESCRIPTION = 1200
MAX_CHECK_LOGIC = 400
MAX_SERVICE = 60
MAX_REMEDIATION_TEXT = 1000
MAX_REMEDIATION_EXAMPLE = 2000       # cli and console
MAX_SRA_SECTION = 200
MAX_URL = 500
MAX_SEQUENCE_ELEMENTS = 20           # sra_sections, additional_urls

URL_SCHEME: Final = "https://"

#: Compared case-insensitively against the first token of title, with
#: trailing punctuation stripped. "Checkpoint" and "Ensured" are not members,
#: so they pass.
_FORBIDDEN_TITLE_TOKENS: Final = frozenset(
    {"ensure", "ensures", "check", "checks"}
)

#: Stripped from the right of title's first token before the rule 5 comparison,
#: so "Ensure:" and "Checks," are caught while "Check-in" keeps its hyphen.
_TRAILING_PUNCTUATION: Final = string.punctuation

#: This module's own file, skipped when walking the stack for the frame that
#: declared the CheckMeta.
_THIS_FILE: Final = __file__


def _defining_module_file() -> str:
    """The file of the nearest frame outside this module.

    A ``CheckMeta`` is constructed in the class body of the check module that
    declares it, so the first real file above ``__post_init__`` and above the
    dataclass-generated ``__init__`` (whose code object carries a synthetic
    ``<string>`` filename) is that module. Used only to build an error
    message, so an unidentifiable frame degrades to a placeholder rather than
    raising.
    """
    getframe = getattr(sys, "_getframe", None)
    if getframe is None:                      # pragma: no cover - non-CPython
        return "<unknown>"
    frame = getframe(1)
    while frame is not None:
        filename = frame.f_code.co_filename
        if filename != _THIS_FILE and not filename.startswith("<"):
            return filename
        frame = frame.f_back
    return "<unknown>"


@dataclass(frozen=True, slots=True)
class Remediation:
    """Remediation guidance for one check.

    Frozen, and holds only strings, which is what makes the enclosing
    ``CheckMeta`` hashable and deeply immutable.

    Deliberately declares no ``__post_init__``. ``Remediation(...)`` is
    evaluated as an *argument* to ``CheckMeta(...)``, so its validation would
    run strictly before ``CheckMeta.__post_init__`` and a declaration carrying
    both a malformed ``check_id`` and a blank ``text`` would report the
    remediation failure. The rule order is fixed as ascending criterion
    number, so every rule -- including the three concerning remediation --
    lives on ``CheckMeta``.
    """

    text: str
    cli: str = ""
    console: str = ""


@dataclass(frozen=True, slots=True)
class CheckMeta:
    """The complete, validated identity and description of one check.

    Holds only values written literally in the declaring check module: no
    ``list``, no ``dict``, no ``set``, nothing derived from an AWS response,
    and nothing derived from the invocation. ``hash(meta)`` succeeds and
    assignment to any field raises.

    ``severity`` and ``account_type`` are enum members rather than strings, so
    an illegal value is a static type error and no conversion step exists.
    """

    check_id: str
    title: str
    description: str
    check_logic: str
    severity: Severity
    account_type: AccountType
    service: str
    resource_type: str
    remediation: Remediation
    sra_sections: tuple[str, ...] = ()
    additional_urls: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Apply every value rule, in ascending criterion order.

        Stops at the first rule that fails and reports only that rule, so a
        declaration violating two rules always produces the same error. Runs
        during construction, so an instance failing any rule is unreachable.

        Static typing catches wrong types, a missing required field, and a
        misspelled keyword; this method catches wrong values.

        Raises:
            MetadataError: The first rule, in ascending criterion order, that
                this declaration fails.
        """
        where = _defining_module_file()

        # ---- Rule 1: check_id format (3.1) ------------------------------
        if not CHECK_ID_RE.fullmatch(self.check_id):
            raise MetadataError(
                f"check_id={self.check_id!r} does not match "
                f"{CHECK_ID_RE.pattern!r} (declared in {where})"
            )

        # Every later rule can name the check ID, now known to be well formed.
        cid = self.check_id

        # ---- Rule 2: resource_type format (3.2) -------------------------
        if not RESOURCE_TYPE_RE.fullmatch(self.resource_type):
            raise MetadataError(
                f"{cid}: resource_type={self.resource_type!r} does not match "
                f"{RESOURCE_TYPE_RE.pattern!r} (declared in {where})"
            )

        # ---- Rule 3: required text fields non-empty (3.3) ---------------
        for name in ("title", "description", "check_logic", "service"):
            if not getattr(self, name).strip():
                raise MetadataError(
                    f"{cid}: {name} is empty (declared in {where})"
                )

        # ---- Rule 4: whitespace normalized (3.4) ------------------------
        # remediation.cli and remediation.console are exempt: a command
        # example needs its line breaks and its alignment, and neither field
        # reaches the CSV. Compares the rendered value against its normalized
        # form, so it does not care how the string was spelled -- which is
        # what makes it the defense against a backslash continuation leaking
        # a run of whitespace into a Description cell.
        normalized_fields = (
            ("title", self.title),
            ("description", self.description),
            ("check_logic", self.check_logic),
            ("service", self.service),
            ("remediation.text", self.remediation.text),
        )
        for name, value in normalized_fields:
            if value != " ".join(value.split()):
                raise MetadataError(
                    f"{cid}: {name}={value!r} is not whitespace-normalized; "
                    f"expected {' '.join(value.split())!r} "
                    f"(declared in {where})"
                )
        for index, section in enumerate(self.sra_sections):
            if section != " ".join(section.split()):
                raise MetadataError(
                    f"{cid}: sra_sections[{index}]={section!r} is not "
                    f"whitespace-normalized; expected "
                    f"{' '.join(section.split())!r} (declared in {where})"
                )

        # ---- Rule 5: title first token (3.5) ----------------------------
        # Token-level rather than prefix-level, so "Checkpoint" and "Ensured"
        # are accepted. A title states the control as a fact, so the same
        # title reads correctly on a PASS row and on a FAIL row.
        first_token = self.title.split()[0].rstrip(_TRAILING_PUNCTUATION).lower()
        if first_token in _FORBIDDEN_TITLE_TOKENS:
            raise MetadataError(
                f"{cid}: title must state the control as a fact, not begin "
                f"with {first_token!r}: {self.title!r} (declared in {where})"
            )

        # ---- Rule 6: length caps (3.6) ----------------------------------
        capped_fields = (
            ("title", self.title, MAX_TITLE),
            ("description", self.description, MAX_DESCRIPTION),
            ("check_logic", self.check_logic, MAX_CHECK_LOGIC),
            ("service", self.service, MAX_SERVICE),
            ("remediation.text", self.remediation.text, MAX_REMEDIATION_TEXT),
            ("remediation.cli", self.remediation.cli, MAX_REMEDIATION_EXAMPLE),
            (
                "remediation.console",
                self.remediation.console,
                MAX_REMEDIATION_EXAMPLE,
            ),
        )
        for name, value, maximum in capped_fields:
            if len(value) > maximum:
                raise MetadataError(
                    f"{cid}: {name} is {len(value)} characters, maximum is "
                    f"{maximum} (declared in {where})"
                )

        # ---- Rule 7: remediation.text non-empty (3.7) -------------------
        if not self.remediation.text.strip():
            raise MetadataError(
                f"{cid}: remediation.text is empty (declared in {where})"
            )

        # ---- Rule 8: additional_urls elements (3.8) ---------------------
        for url in self.additional_urls:
            if not url.startswith(URL_SCHEME):
                reason = f"does not begin with {URL_SCHEME!r}"
            elif len(url) == len(URL_SCHEME):
                reason = f"carries no character after {URL_SCHEME!r}"
            elif any(char.isspace() for char in url):
                reason = "contains whitespace"
            elif len(url) > MAX_URL:
                reason = f"is {len(url)} characters, maximum is {MAX_URL}"
            else:
                continue
            raise MetadataError(
                f"{cid}: additional_urls element {url!r} {reason} "
                f"(declared in {where})"
            )

        # ---- Rule 9: sra_sections elements (3.9) ------------------------
        for section in self.sra_sections:
            if not section.strip():
                reason = "is empty"
            elif len(section) > MAX_SRA_SECTION:
                reason = f"is {len(section)} characters, maximum is {MAX_SRA_SECTION}"
            else:
                continue
            raise MetadataError(
                f"{cid}: sra_sections element {section!r} {reason} "
                f"(declared in {where})"
            )

        # ---- Rule 13: sequence element counts (3.13) --------------------
        # Ordered after rules 8 and 9, so a 30-element list containing one bad
        # URL reports the bad URL rather than the count.
        for name, values in (
            ("sra_sections", self.sra_sections),
            ("additional_urls", self.additional_urls),
        ):
            if len(values) > MAX_SEQUENCE_ELEMENTS:
                raise MetadataError(
                    f"{cid}: {name} holds {len(values)} elements, maximum is "
                    f"{MAX_SEQUENCE_ELEMENTS} (declared in {where})"
                )
