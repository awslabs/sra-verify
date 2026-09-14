"""Unit tests for ``sraverify.core.metadata``.

One test per validation rule, each driven by a fixture that violates **only**
that rule. That isolation is not stylistic: Requirement 3.10 fixes the rule
order as ascending criterion number with stop-at-first-failure, so a fixture
violating two rules would attribute the error to the lower-numbered one and
the test would silently stop covering the rule it names.

Two fixtures are worth calling out:

  * **Rule 4** uses the *actual* rendered ``description`` of the pre-migration
    ``sra_guardduty_01``, whose backslash line continuations leak a 14-space
    run into a ``Description`` cell. Rule 4 is the sole defense against that
    defect, so the test is anchored to the real string rather than to a
    synthetic one. The literal below is the value ``ast.literal_eval`` returns
    for that module's assignment, character for character.
  * **Rule 7** uses ``text=""`` rather than ``text="  "``. A blank-but-not-empty
    ``text`` is caught by rule 4 first -- correct under ascending order -- so
    only an already-normalized empty string reaches rule 7.

Also asserted here: the strict-key rule of Requirement 2.5, which needs no
code of its own because a frozen dataclass constructor supplies it, and the
deep immutability of Requirement 2.4.

Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.13.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from sraverify.core.enums import AccountType, Severity
from sraverify.core.errors import MetadataError, SRAVerifyError
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


CHECK_ID = "SRA-GUARDDUTY-01"

#: The rendered ``description`` of the pre-migration ``sra_guardduty_01``.
#: The source spells it with backslash line continuations, so the indentation
#: of each continued line survives into the value as a run of spaces.
GUARDDUTY_01_MANGLED_DESCRIPTION = (
    "This check verifies that an GuardDuty detector exists in the AWS Region."
    "              A detector is a resource that represents the GuardDuty "
    "service and should be present                 in all AWS member account "
    "and AWS Region so that GuardDuty can generate findings                  "
    "   about unauthorized or unusual activity even in those Regions that you "
    "may not                         be using actively."
)

#: A fully valid declaration. Every rule test starts from this and overrides
#: exactly one field, so the rule that fires is unambiguous.
VALID = {
    "check_id": CHECK_ID,
    "title": "GuardDuty detector exists",
    "description": (
        "A GuardDuty detector exists in the AWS Region. A detector "
        "represents the GuardDuty service and should be present in every "
        "member account and Region."
    ),
    "check_logic": (
        "Reads the detector ID in each Region. Fails when no detector ID "
        "is returned."
    ),
    "severity": Severity.HIGH,
    "account_type": AccountType.APPLICATION,
    "service": "GuardDuty",
    "resource_type": "AWS::GuardDuty::Detector",
    "remediation": Remediation(text="Enable GuardDuty in the Region."),
}


def make(**overrides) -> CheckMeta:
    """Build a CheckMeta from the valid baseline with the given overrides."""
    return CheckMeta(**{**VALID, **overrides})


def remediation(**overrides) -> Remediation:
    """Build a Remediation from the baseline's text with the given overrides."""
    return Remediation(**{"text": VALID["remediation"].text, **overrides})


def assert_reported(excinfo, *fragments: str) -> None:
    """Every fragment, plus the declaring file, appears in the message."""
    message = str(excinfo.value)
    for fragment in fragments:
        assert fragment in message, f"{fragment!r} missing from {message!r}"
    # Rules 2 through 13 name the check ID; rule 1 cannot, since check_id is
    # the value under test. Both name the file that declared the CheckMeta,
    # which under test is this module.
    assert "test_metadata.py" in message


# --------------------------------------------------------------------------
# The baseline itself, and the shape of the type (Requirements 2.2, 2.4)
# --------------------------------------------------------------------------

def test_the_valid_baseline_constructs():
    meta = make()
    assert meta.check_id == CHECK_ID
    assert meta.severity is Severity.HIGH
    assert meta.account_type is AccountType.APPLICATION


def test_optional_sequence_fields_default_to_empty_tuples():
    meta = make()
    assert meta.sra_sections == ()
    assert meta.additional_urls == ()
    assert isinstance(meta.sra_sections, tuple)
    assert isinstance(meta.additional_urls, tuple)


def test_remediation_cli_and_console_default_to_the_empty_string():
    rem = Remediation(text="Enable GuardDuty in the Region.")
    assert rem.cli == ""
    assert rem.console == ""


def test_metadata_error_is_an_sraverify_error():
    # main.py catches the package base; a MetadataError must be reachable
    # through it rather than only through Exception.
    assert issubclass(MetadataError, SRAVerifyError)


# Requirement 2.4: no list, no dict, no set anywhere in a CheckMeta, so the
# value is hashable and deeply immutable.

def test_check_meta_is_hashable():
    assert hash(make()) == hash(make())


def test_remediation_is_hashable():
    assert hash(remediation()) == hash(remediation())


def test_check_meta_holds_no_list_dict_or_set():
    meta = make(
        sra_sections=("Section 1",), additional_urls=("https://example.com",)
    )
    values = [getattr(meta, name) for name in CheckMeta.__slots__]
    values.append(meta.remediation.text)
    values.append(meta.remediation.cli)
    values.append(meta.remediation.console)
    for value in values:
        assert not isinstance(value, (list, dict, set)), value


@pytest.mark.parametrize("field_name", ["check_id", "title", "severity",
                                        "remediation", "sra_sections"])
def test_assignment_to_a_check_meta_field_raises(field_name):
    meta = make()
    with pytest.raises(FrozenInstanceError):
        setattr(meta, field_name, "mutated")


@pytest.mark.parametrize("field_name", ["text", "cli", "console"])
def test_assignment_to_a_remediation_member_raises(field_name):
    rem = remediation()
    with pytest.raises(FrozenInstanceError):
        setattr(rem, field_name, "mutated")


def test_slotted_storage_admits_no_new_attribute():
    with pytest.raises((AttributeError, FrozenInstanceError)):
        make().extra = "value"


# Requirement 2.5: the strict-key rule, supplied by the constructor itself.

def test_a_misspelled_keyword_raises_type_error():
    bad = dict(VALID)
    bad["check_name"] = bad.pop("title")
    with pytest.raises(TypeError) as excinfo:
        CheckMeta(**bad)
    assert "check_name" in str(excinfo.value)


@pytest.mark.parametrize("field_name", sorted(VALID))
def test_omitting_any_required_field_raises_type_error(field_name):
    incomplete = {k: v for k, v in VALID.items() if k != field_name}
    with pytest.raises(TypeError) as excinfo:
        CheckMeta(**incomplete)
    assert field_name in str(excinfo.value)


def test_omitting_remediation_text_raises_type_error():
    with pytest.raises(TypeError):
        Remediation()


# Requirement 2.3: severity and account_type are declared as enum members and
# no conversion step exists. Static typing owns the illegal-value rejection,
# which is why nothing in __post_init__ touches these two fields.

def test_enum_fields_are_stored_exactly_as_supplied():
    meta = make(severity=Severity.CRITICAL, account_type=AccountType.AUDIT)
    assert meta.severity is Severity.CRITICAL
    assert meta.account_type is AccountType.AUDIT


# --------------------------------------------------------------------------
# Rule 1 -- check_id format (Requirement 3.1)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "check_id",
    [
        "SRA-GUARDDUTY-1",       # one digit, not two
        "SRA-GUARDDUTY-001",     # three digits
        "SRA-guardduty-01",      # lower-case service segment
        "sra-GUARDDUTY-01",      # lower-case prefix
        "SRA-GUARD_DUTY-01",     # underscore in the service segment
        "SRA-GUARD DUTY-01",     # space in the service segment
        "SRA--01",               # empty service segment
        "SRA-GUARDDUTY",         # no number segment
        "GUARDDUTY-01",          # no SRA prefix
        "SRA-GD-1",              # the stale legacy short form
        "",
        " SRA-GUARDDUTY-01",     # leading space
        "SRA-GUARDDUTY-01 ",     # trailing space
        "SRA-GUARDDUTY-01\n",    # trailing newline; fullmatch must reject it
        "SRA-GUARDDUTY-01-EXTRA",
        "SRA-IAM ACCESS ANALYZER-01",
    ],
)
def test_malformed_check_id_raises(check_id):
    with pytest.raises(MetadataError) as excinfo:
        make(check_id=check_id, title="A stated fact")
    # The pattern is embedded with !r, so the fragment is its repr -- which is
    # what a reader copying the pattern out of the message actually sees.
    assert_reported(
        excinfo, "check_id", repr(check_id), repr(CHECK_ID_RE.pattern)
    )


def test_non_ascii_digit_does_not_satisfy_the_numeric_segment():
    # re.ASCII is what makes this fail; without it the Arabic-Indic digits
    # below match \d and a mangled ID would reach the registry.
    with pytest.raises(MetadataError):
        make(check_id="SRA-GUARDDUTY-\u0661\u0662", title="A stated fact")


@pytest.mark.parametrize(
    "check_id",
    [
        "SRA-GUARDDUTY-01",
        "SRA-S3-04",
        "SRA-EC2-99",
        "SRA-SECURITYINCIDENTRESPONSE-05",
        "SRA-WAF2-01",           # digits are legal in the service segment
    ],
)
def test_well_formed_check_id_is_accepted(check_id):
    assert make(check_id=check_id).check_id == check_id


# --------------------------------------------------------------------------
# Rule 2 -- resource_type format (Requirement 3.2)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "resource_type",
    [
        "aws::GuardDuty::Detector",       # lower-case prefix
        "AWS:GuardDuty:Detector",         # single colons
        "AWS::GuardDuty",                 # two segments
        "AWS::GuardDuty::Detector::X",    # four segments
        "AWS::Guard_Duty::Detector",      # underscore
        "AWS::Guard Duty::Detector",      # space
        "AWS::::Detector",                # empty middle segment
        "AWS::GuardDuty::",               # empty last segment
        "GuardDuty::Detector",
        "",
        "AWS::GuardDuty::Detector\n",     # fullmatch must reject the newline
    ],
)
def test_malformed_resource_type_raises(resource_type):
    with pytest.raises(MetadataError) as excinfo:
        make(resource_type=resource_type)
    assert_reported(
        excinfo,
        CHECK_ID,
        "resource_type",
        repr(resource_type),
        repr(RESOURCE_TYPE_RE.pattern),
    )


@pytest.mark.parametrize(
    "resource_type",
    [
        "AWS::GuardDuty::Detector",
        "AWS::S3::Bucket",
        "AWS::EC2::VPC",
        "AWS::Organizations::Organization",
    ],
)
def test_well_formed_resource_type_is_accepted(resource_type):
    assert make(resource_type=resource_type).resource_type == resource_type


# --------------------------------------------------------------------------
# Rule 3 -- required text fields non-empty (Requirement 3.3)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("field_name", ["title", "description", "check_logic",
                                        "service"])
@pytest.mark.parametrize("value", ["", "   ", "\t", "\n", " \t\n "])
def test_empty_or_blank_required_text_field_raises(field_name, value):
    # A blank value reaches rule 3 before rule 4 can see it, because rule 3
    # runs first. That ordering is what keeps this fixture single-rule.
    with pytest.raises(MetadataError) as excinfo:
        make(**{field_name: value})
    assert_reported(excinfo, CHECK_ID, field_name)


def test_a_single_character_required_text_field_is_accepted():
    assert make(title="X", description="Y", check_logic="Z", service="S")


# --------------------------------------------------------------------------
# Rule 4 -- whitespace normalization (Requirement 3.4)
#
# The defense against the backslash-continuation defect. It compares the
# rendered value against its normalized form, so it does not care how the
# string was spelled in source.
# --------------------------------------------------------------------------

def test_the_real_guardduty_01_description_is_rejected():
    with pytest.raises(MetadataError) as excinfo:
        make(description=GUARDDUTY_01_MANGLED_DESCRIPTION)
    assert_reported(excinfo, CHECK_ID, "description")
    # The message shows the value it wanted, so the fix is copy-pasteable.
    assert repr(" ".join(GUARDDUTY_01_MANGLED_DESCRIPTION.split())) in str(
        excinfo.value
    )


def test_the_real_guardduty_01_description_carries_a_fourteen_space_run():
    # Guards the fixture, not the validator: if this literal ever drifts away
    # from the defect it was copied from, the test above stops meaning what it
    # claims to mean.
    assert "Region." + " " * 14 + "A detector" in (
        GUARDDUTY_01_MANGLED_DESCRIPTION
    )


def test_the_normalized_guardduty_01_description_is_accepted():
    normalized = " ".join(GUARDDUTY_01_MANGLED_DESCRIPTION.split())
    assert make(description=normalized).description == normalized


@pytest.mark.parametrize("field_name", ["title", "description", "check_logic",
                                        "service"])
@pytest.mark.parametrize(
    "value",
    [
        "Two  spaces inside",
        "Leading space ",
        " Trailing space",
        "A tab\tinside",
        "A newline\ninside",
        "A carriage return\rinside",
        "A non-breaking\u00a0space inside",   # Unicode whitespace, per the rule
        "Trailing newline\n",
    ],
)
def test_unnormalized_required_text_field_raises(field_name, value):
    with pytest.raises(MetadataError) as excinfo:
        make(**{field_name: value})
    assert_reported(excinfo, CHECK_ID, field_name, repr(value))


def test_unnormalized_remediation_text_raises():
    with pytest.raises(MetadataError) as excinfo:
        make(remediation=remediation(text="Enable  GuardDuty in the Region."))
    assert_reported(excinfo, CHECK_ID, "remediation.text")


def test_blank_remediation_text_is_reported_by_rule_four_not_rule_seven():
    # A blank-but-not-empty text is not whitespace-normalized, so rule 4
    # claims it first. Correct under ascending criterion order, and the reason
    # the rule 7 fixture below has to use "" instead.
    with pytest.raises(MetadataError) as excinfo:
        make(remediation=remediation(text="  "))
    message = str(excinfo.value)
    assert "not whitespace-normalized" in message
    assert "remediation.text" in message


def test_unnormalized_sra_sections_element_raises():
    with pytest.raises(MetadataError) as excinfo:
        make(sra_sections=("Fine section", "Two  spaces"))
    assert_reported(excinfo, CHECK_ID, "sra_sections", repr("Two  spaces"))
    # The index is reported, so the offending element is locatable in a tuple
    # of twenty.
    assert "[1]" in str(excinfo.value)


@pytest.mark.parametrize("field_name", ["cli", "console"])
def test_remediation_examples_are_exempt_from_normalization(field_name):
    # A command example needs its line breaks and its alignment, and neither
    # field reaches the CSV. This exemption is stated in the rule itself.
    example = (
        "aws guardduty create-detector \\\n"
        "    --enable \\\n"
        "    --region us-east-1\n"
    )
    meta = make(remediation=remediation(**{field_name: example}))
    assert getattr(meta.remediation, field_name) == example


def test_additional_urls_are_exempt_from_normalization():
    # Rule 4 lists no URL field. A URL containing whitespace is rule 8's
    # business, and rule 8 rejects it for a reason of its own.
    with pytest.raises(MetadataError) as excinfo:
        make(additional_urls=("https://example.com/a b",))
    assert "contains whitespace" in str(excinfo.value)


# --------------------------------------------------------------------------
# Rule 5 -- the title states the control as a fact (Requirement 3.5)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "title",
    [
        "Ensure GuardDuty is enabled",
        "Ensures GuardDuty is enabled",
        "Check GuardDuty is enabled",
        "Checks GuardDuty is enabled",
        "ensure GuardDuty is enabled",      # case-insensitive
        "ENSURE GuardDuty is enabled",
        "CHECKS GuardDuty is enabled",
        "Ensure: GuardDuty is enabled",     # trailing punctuation stripped
        "Check, GuardDuty is enabled",
        "Checks. GuardDuty is enabled",
        "Ensure",                            # the token alone
    ],
)
def test_title_beginning_with_a_forbidden_token_raises(title):
    with pytest.raises(MetadataError) as excinfo:
        make(title=title)
    assert_reported(excinfo, CHECK_ID, "title", repr(title))


@pytest.mark.parametrize(
    "title",
    [
        "Checkpoint restore is configured",   # not the token "check"
        "Ensured delivery is configured",     # not the token "ensure"
        "Checking is not a forbidden token",
        "GuardDuty detector exists",
        "Verified GuardDuty is enabled",
        "Detector for GuardDuty ensures coverage",   # forbidden token, but not first
    ],
)
def test_title_not_beginning_with_a_forbidden_token_is_accepted(title):
    assert make(title=title).title == title


# --------------------------------------------------------------------------
# Rule 6 -- length caps (Requirement 3.6)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "field_name, maximum",
    [
        ("title", MAX_TITLE),
        ("description", MAX_DESCRIPTION),
        ("check_logic", MAX_CHECK_LOGIC),
        ("service", MAX_SERVICE),
    ],
)
def test_over_length_text_field_raises_naming_length_and_maximum(
    field_name, maximum
):
    # "A" repeated is one whitespace-normalized token whose first character is
    # not a forbidden token, so this fixture trips rule 6 and nothing earlier.
    over = "A" * (maximum + 1)
    with pytest.raises(MetadataError) as excinfo:
        make(**{field_name: over})
    assert_reported(excinfo, CHECK_ID, field_name, str(maximum + 1),
                    str(maximum))


@pytest.mark.parametrize(
    "field_name, maximum",
    [
        ("text", MAX_REMEDIATION_TEXT),
        ("cli", MAX_REMEDIATION_EXAMPLE),
        ("console", MAX_REMEDIATION_EXAMPLE),
    ],
)
def test_over_length_remediation_member_raises(field_name, maximum):
    over = "A" * (maximum + 1)
    with pytest.raises(MetadataError) as excinfo:
        make(remediation=remediation(**{field_name: over}))
    assert_reported(excinfo, CHECK_ID, f"remediation.{field_name}",
                    str(maximum + 1), str(maximum))


@pytest.mark.parametrize(
    "field_name, maximum",
    [
        ("title", MAX_TITLE),
        ("description", MAX_DESCRIPTION),
        ("check_logic", MAX_CHECK_LOGIC),
        ("service", MAX_SERVICE),
    ],
)
def test_a_field_exactly_at_its_maximum_is_accepted(field_name, maximum):
    at_limit = "A" * maximum
    assert len(getattr(make(**{field_name: at_limit}), field_name)) == maximum


def test_length_is_counted_in_code_points_not_bytes():
    # Each of these is three UTF-8 bytes and one code point, so a byte-based
    # count would reject a legal title.
    at_limit = "\u00e9" * MAX_TITLE
    assert make(title=at_limit).title == at_limit
    with pytest.raises(MetadataError):
        make(title="\u00e9" * (MAX_TITLE + 1))


# --------------------------------------------------------------------------
# Rule 7 -- remediation.text non-empty (Requirement 3.7)
# --------------------------------------------------------------------------

def test_empty_remediation_text_raises():
    # "" is already whitespace-normalized and within the length cap, so it
    # reaches rule 7 untouched. "  " would not -- see the rule 4 test above.
    with pytest.raises(MetadataError) as excinfo:
        make(remediation=remediation(text=""))
    assert_reported(excinfo, CHECK_ID, "remediation.text")
    assert "empty" in str(excinfo.value)


def test_a_single_character_remediation_text_is_accepted():
    assert make(remediation=remediation(text="X")).remediation.text == "X"


# --------------------------------------------------------------------------
# Rule 8 -- additional_urls elements (Requirement 3.8)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url, reason_fragment",
    [
        ("http://docs.aws.amazon.com/x", "does not begin with"),
        ("//docs.aws.amazon.com/x", "does not begin with"),
        ("docs.aws.amazon.com/x", "does not begin with"),
        ("HTTPS://docs.aws.amazon.com/x", "does not begin with"),
        ("", "does not begin with"),
        ("https://", "carries no character after"),
        ("https://docs.aws.amazon.com/a b", "contains whitespace"),
        ("https://docs.aws.amazon.com/a\tb", "contains whitespace"),
        ("https://docs.aws.amazon.com/a\nb", "contains whitespace"),
        ("https://docs.aws.amazon.com/x ", "contains whitespace"),
    ],
)
def test_malformed_additional_url_raises(url, reason_fragment):
    with pytest.raises(MetadataError) as excinfo:
        make(additional_urls=(url,))
    assert_reported(excinfo, CHECK_ID, "additional_urls", repr(url),
                    reason_fragment)


def test_over_length_additional_url_raises_naming_length_and_maximum():
    over = "https://" + "a" * MAX_URL          # comfortably past the cap
    with pytest.raises(MetadataError) as excinfo:
        make(additional_urls=(over,))
    assert_reported(excinfo, CHECK_ID, "additional_urls", str(len(over)),
                    str(MAX_URL))


def test_an_additional_url_exactly_at_its_maximum_is_accepted():
    at_limit = "https://" + "a" * (MAX_URL - len("https://"))
    assert len(at_limit) == MAX_URL
    assert make(additional_urls=(at_limit,)).additional_urls == (at_limit,)


def test_the_offending_url_is_reported_from_anywhere_in_the_tuple():
    with pytest.raises(MetadataError) as excinfo:
        make(
            additional_urls=(
                "https://docs.aws.amazon.com/first",
                "https://docs.aws.amazon.com/second",
                "ftp://docs.aws.amazon.com/third",
            )
        )
    assert repr("ftp://docs.aws.amazon.com/third") in str(excinfo.value)


@pytest.mark.parametrize(
    "url",
    [
        "https://a",
        "https://docs.aws.amazon.com/prescriptive-guidance/latest/x.html",
        "https://docs.aws.amazon.com/x?a=1&b=2#frag",
    ],
)
def test_well_formed_additional_url_is_accepted(url):
    assert make(additional_urls=(url,)).additional_urls == (url,)


# --------------------------------------------------------------------------
# Rule 9 -- sra_sections elements (Requirement 3.9)
# --------------------------------------------------------------------------

def test_empty_sra_sections_element_raises():
    # "" is whitespace-normalized, so rule 4 lets it through to rule 9. A
    # blank "   " would be claimed by rule 4 instead.
    with pytest.raises(MetadataError) as excinfo:
        make(sra_sections=("",))
    assert_reported(excinfo, CHECK_ID, "sra_sections")
    assert "is empty" in str(excinfo.value)


def test_over_length_sra_sections_element_raises():
    over = "A" * (MAX_SRA_SECTION + 1)
    with pytest.raises(MetadataError) as excinfo:
        make(sra_sections=(over,))
    assert_reported(excinfo, CHECK_ID, "sra_sections",
                    str(MAX_SRA_SECTION + 1), str(MAX_SRA_SECTION))


def test_an_sra_sections_element_exactly_at_its_maximum_is_accepted():
    at_limit = "A" * MAX_SRA_SECTION
    assert make(sra_sections=(at_limit,)).sra_sections == (at_limit,)


def test_well_formed_sra_sections_are_accepted():
    sections = ("Security Tooling account", "Detective controls: GuardDuty")
    assert make(sra_sections=sections).sra_sections == sections


# --------------------------------------------------------------------------
# Rule 13 -- sequence element counts (Requirement 3.13)
# --------------------------------------------------------------------------

def test_too_many_sra_sections_raises_naming_count_and_maximum():
    sections = tuple(f"Section {n}" for n in range(MAX_SEQUENCE_ELEMENTS + 1))
    with pytest.raises(MetadataError) as excinfo:
        make(sra_sections=sections)
    assert_reported(excinfo, CHECK_ID, "sra_sections",
                    str(MAX_SEQUENCE_ELEMENTS + 1),
                    str(MAX_SEQUENCE_ELEMENTS))


def test_too_many_additional_urls_raises_naming_count_and_maximum():
    urls = tuple(
        f"https://docs.aws.amazon.com/{n}"
        for n in range(MAX_SEQUENCE_ELEMENTS + 1)
    )
    with pytest.raises(MetadataError) as excinfo:
        make(additional_urls=urls)
    assert_reported(excinfo, CHECK_ID, "additional_urls",
                    str(MAX_SEQUENCE_ELEMENTS + 1),
                    str(MAX_SEQUENCE_ELEMENTS))


@pytest.mark.parametrize("field_name", ["sra_sections", "additional_urls"])
def test_exactly_the_maximum_element_count_is_accepted(field_name):
    if field_name == "sra_sections":
        values = tuple(f"Section {n}" for n in range(MAX_SEQUENCE_ELEMENTS))
    else:
        values = tuple(
            f"https://docs.aws.amazon.com/{n}"
            for n in range(MAX_SEQUENCE_ELEMENTS)
        )
    assert len(getattr(make(**{field_name: values}), field_name)) == (
        MAX_SEQUENCE_ELEMENTS
    )


def test_an_over_count_tuple_containing_a_bad_element_reports_the_element():
    # Rule 13 is ordered after rules 8 and 9 deliberately, so the actionable
    # failure wins over the count.
    urls = tuple(
        f"https://docs.aws.amazon.com/{n}"
        for n in range(MAX_SEQUENCE_ELEMENTS + 1)
    ) + ("ftp://docs.aws.amazon.com/bad",)
    with pytest.raises(MetadataError) as excinfo:
        make(additional_urls=urls)
    assert repr("ftp://docs.aws.amazon.com/bad") in str(excinfo.value)
