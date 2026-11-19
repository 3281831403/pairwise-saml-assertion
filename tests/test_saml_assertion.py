"""Security-focused acceptance tests for the SAML assertion gateway.

Every test builds its XML or parsed-assertion dict inline and uses a fixed
clock.  No files, network access or randomness are used.  The test helper
functions turn the deliberate ``NotImplementedError`` raised by the
contract-only stubs into ordinary test failures, so the initial run reports
15 failures without collection/import problems.
"""

import base64
import hashlib
import hmac

import pytest

from saml_gateway.assertion import (
    InvalidAssertion,
    authenticate,
    canonicalize,
    check_conditions,
    parse_assertion,
    verify_hmac,
)

KEY = b"0123456789abcdef0123456789abcdef"
NOW = 1700000000.0
SKEW = 120
AUDIENCE = "https://sp.example/saml"
IDP = "https://idp.example"


def _fail_not_implemented() -> None:
    raise pytest.fail.Exception("stub is not implemented yet", pytrace=False) from None


def _call(function, *args, **kwargs):
    """Call a contract function, recording the unimplemented stub as a failure."""
    try:
        return function(*args, **kwargs)
    except NotImplementedError:
        _fail_not_implemented()


def _expect_invalid(function, *args, **kwargs) -> None:
    """Require an InvalidAssertion; a successful call fails the test."""
    try:
        function(*args, **kwargs)
    except InvalidAssertion:
        return
    except NotImplementedError:
        _fail_not_implemented()
    pytest.fail(
        f"{getattr(function, '__name__', function)} accepted invalid input",
        pytrace=False,
    )


def _assertion_xml(
    assertion_id: str = "a1",
    subject: str = "alice",
    not_before: int = 1699999900,
    not_on_or_after: int = 1700000100,
    audiences: tuple[str, ...] = (AUDIENCE,),
) -> str:
    """Build the canonical (whitespace-free, attribute-sorted) assertion text."""
    audience_xml = "".join(f"<Audience>{value}</Audience>" for value in audiences)
    return (
        f'<Assertion ID="{assertion_id}">'
        f"<Issuer>{IDP}</Issuer>"
        f"<Subject><NameID>{subject}</NameID></Subject>"
        f'<Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">'
        f"<AudienceRestriction>{audience_xml}</AudienceRestriction>"
        f"</Conditions>"
        f"</Assertion>"
    )


def _signature_xml(
    reference_id: str, signed_bytes: bytes, key: bytes = KEY
) -> str:
    digest = hmac.new(key, signed_bytes, hashlib.sha256).digest()
    encoded = base64.b64encode(digest).decode("ascii")
    return (
        "<Signature><SignedInfo>"
        f'<Reference URI="#{reference_id}"></Reference>'
        "</SignedInfo>"
        f"<SignatureValue>{encoded}</SignatureValue>"
        "</Signature>"
    )


def _document(assertion_xml: str, signature_xml: str) -> str:
    return f"<Envelope>{assertion_xml}{signature_xml}</Envelope>"


def _valid_document(
    assertion_id: str = "a1", subject: str = "alice"
) -> str:
    assertion = _assertion_xml(assertion_id=assertion_id, subject=subject)
    signature = _signature_xml(assertion_id, assertion.encode("utf-8"))
    return _document(assertion, signature)


def _parsed_assertion(**overrides) -> dict:
    assertion = {
        "id": "a1",
        "subject": "alice",
        "audience": AUDIENCE,
        "not_before": NOW - 100,
        "not_on_or_after": NOW + 100,
        "signed_id": "a1",
    }
    assertion.update(overrides)
    return assertion


def test_valid_assertion_returns_subject() -> None:
    seen: set[str] = set()

    assert _call(authenticate, _valid_document(), KEY, AUDIENCE, NOW, seen) == "alice"
    assert seen == {"a1"}


def test_signature_wrapping_is_rejected() -> None:
    assertion = _assertion_xml()
    # The signature is cryptographically valid for a wrapper, but the
    # Reference must be bound to the assertion that business code reads.
    wrapper = f'<Wrapper ID="outer">{assertion}</Wrapper>'
    signature = _signature_xml("outer", wrapper.encode("utf-8"))
    _expect_invalid(parse_assertion, _document(wrapper, signature))

    # A wrapper that reuses the assertion ID must not win the ID lookup.
    same_id_wrapper = f'<Wrapper ID="a1">{assertion}</Wrapper>'
    same_id_signature = _signature_xml("a1", same_id_wrapper.encode("utf-8"))
    _expect_invalid(parse_assertion, _document(same_id_wrapper, same_id_signature))


def test_duplicate_assertions_are_rejected() -> None:
    first = _assertion_xml(assertion_id="a1", subject="alice")
    second = _assertion_xml(assertion_id="a2", subject="mallory")
    signature = _signature_xml("a1", first.encode("utf-8"))
    xml = _document(first + second, signature)

    _expect_invalid(parse_assertion, xml)


def test_comment_cannot_change_signed_text() -> None:
    assertion = _assertion_xml()
    tampered = assertion.replace(
        "<NameID>alice</NameID>",
        "<NameID>ali<!--mallory-->ce</NameID>",
    )
    assert tampered != assertion
    # The signature was made over the canonical text "alice".  Comments are
    # not signed text, so the comment must be stripped and the subject stay
    # "alice"; a canonicalizer that includes comments would reject this.
    xml = _document(tampered, _signature_xml("a1", assertion.encode("utf-8")))

    _call(verify_hmac, xml, KEY)
    assert _call(authenticate, xml, KEY, AUDIENCE, NOW, set()) == "alice"


def test_entity_expansion_bomb_is_rejected() -> None:
    bomb = (
        "<!DOCTYPE Envelope ["
        '<!ENTITY a "AAAAAAAAAA">'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
        '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
        '<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">'
        '<!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">'
        "]>"
        '<Envelope><Assertion ID="a1"><Subject><NameID>&e;</NameID>'
        "</Subject></Assertion></Envelope>"
    )
    # Tiny input, 100_000 characters of expansion: a DTD must be refused
    # before any entity is expanded.
    assert len(bomb.encode("utf-8")) < 256 * 1024

    _expect_invalid(canonicalize, bomb)


def test_oversized_input_is_rejected() -> None:
    oversized = _valid_document() + (" " * (256 * 1024))
    assert len(oversized.encode("utf-8")) > 256 * 1024

    _expect_invalid(authenticate, oversized, KEY, AUDIENCE, NOW, set())


def test_excessive_xml_depth_is_rejected() -> None:
    xml = _valid_document()
    for _ in range(40):
        xml = f"<d>{xml}</d>"

    _expect_invalid(authenticate, xml, KEY, AUDIENCE, NOW, set())


def test_not_before_in_future_is_rejected() -> None:
    # One second beyond the lower skew boundary: now < NotBefore - skew.
    assertion = _parsed_assertion(not_before=NOW + SKEW + 1)

    _expect_invalid(check_conditions, assertion, NOW, AUDIENCE, SKEW)


def test_not_on_or_after_expired_is_rejected() -> None:
    # One second beyond the upper skew boundary: now > NotOnOrAfter + skew.
    assertion = _parsed_assertion(not_on_or_after=NOW - SKEW - 1)

    _expect_invalid(check_conditions, assertion, NOW, AUDIENCE, SKEW)


def test_conditions_skew_boundaries() -> None:
    # Inside/boundary: now == NotOnOrAfter + skew and now == NotBefore - skew
    # must be accepted (both boundaries are inclusive).
    _call(
        check_conditions,
        _parsed_assertion(not_on_or_after=NOW - SKEW),
        NOW,
        AUDIENCE,
        SKEW,
    )
    _call(
        check_conditions,
        _parsed_assertion(not_before=NOW + SKEW),
        NOW,
        AUDIENCE,
        SKEW,
    )

    # Outside: one second beyond either boundary must be rejected.
    _expect_invalid(
        check_conditions,
        _parsed_assertion(not_on_or_after=NOW - SKEW - 1),
        NOW,
        AUDIENCE,
        SKEW,
    )
    _expect_invalid(
        check_conditions,
        _parsed_assertion(not_before=NOW + SKEW + 1),
        NOW,
        AUDIENCE,
        SKEW,
    )


def test_audience_mismatch_is_rejected() -> None:
    # A substring/prefix check would wrongly accept the configured audience.
    assertion = _parsed_assertion(audience=AUDIENCE + "-admin")

    _expect_invalid(check_conditions, assertion, NOW, AUDIENCE, SKEW)


def test_multi_value_audience_exact_match_is_accepted() -> None:
    _call(
        check_conditions,
        _parsed_assertion(audience="urn:example:sp-a urn:example:sp-b"),
        NOW,
        "urn:example:sp-b",
        SKEW,
    )
    _call(
        check_conditions,
        _parsed_assertion(audience="  urn:example:sp-a\n\turn:example:sp-b  "),
        NOW,
        "urn:example:sp-a",
        SKEW,
    )


def test_single_audience_exact_match_is_accepted() -> None:
    _call(
        check_conditions,
        _parsed_assertion(audience=AUDIENCE),
        NOW,
        AUDIENCE,
        SKEW,
    )


def test_replayed_assertion_is_rejected() -> None:
    xml = _valid_document()
    seen: set[str] = set()

    assert _call(authenticate, xml, KEY, AUDIENCE, NOW, seen) == "alice"
    _expect_invalid(authenticate, xml, KEY, AUDIENCE, NOW, seen)


def test_different_assertion_id_is_accepted() -> None:
    seen: set[str] = set()

    assert (
        _call(authenticate, _valid_document("a1", "alice"), KEY, AUDIENCE, NOW, seen)
        == "alice"
    )
    assert (
        _call(authenticate, _valid_document("a2", "bob"), KEY, AUDIENCE, NOW, seen)
        == "bob"
    )
