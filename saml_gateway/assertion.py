"""Contract-only stubs for a SAML assertion gateway.

A document handled here has one root element and contains exactly one
``Assertion`` element and exactly one ``Signature`` element.  Element names are
matched by local name, so the usual SAML namespace prefixes are tolerated.  The
signature is a sibling of the assertion, for example::

    <Envelope>
      <Assertion ID="a1">
        <Issuer>https://idp.example</Issuer>
        <Subject><NameID>alice</NameID></Subject>
        <Conditions NotBefore="1699999900" NotOnOrAfter="1700000100">
          <AudienceRestriction>
            <Audience>https://sp.example/saml</Audience>
          </AudienceRestriction>
        </Conditions>
      </Assertion>
      <Signature>
        <SignedInfo><Reference URI="#a1"/></SignedInfo>
        <SignatureValue>base64(HMAC-SHA256(...))</SignatureValue>
      </Signature>
    </Envelope>

All times are seconds since the Unix epoch (``float`` or ``int``).  The only
signature algorithm is HMAC-SHA256 and signatures are compared in constant
time.  Every rejection is reported as :class:`InvalidAssertion`; the public
functions below are stubs that raise ``NotImplementedError`` because
implementing this contract is the exercise.
"""

import base64
import binascii
import hashlib
import hmac
import math
import re
import xml.etree.ElementTree as ET


class InvalidAssertion(Exception):
    """Raised for every malformed, unauthenticated or replayed assertion."""


MAX_DOCUMENT_BYTES = 256 * 1024
MAX_DEPTH = 32
DEFAULT_SKEW = 120

_XML_NS = "http://www.w3.org/XML/1998/namespace"
_DOCTYPE = re.compile(r"<!DOCTYPE", re.IGNORECASE)
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


class _GuardBuilder(ET.TreeBuilder):
    """Tree builder that rejects PIs and enforces a maximum nesting depth."""

    def __init__(self, max_depth=None):
        super().__init__()
        self._depth = 0
        self._max_depth = max_depth

    def start(self, tag, attrs):
        self._depth += 1
        if self._max_depth is not None and self._depth > self._max_depth:
            raise InvalidAssertion("XML nesting is too deep")
        return super().start(tag, attrs)

    def end(self, tag):
        self._depth -= 1
        return super().end(tag)

    def pi(self, target, data):
        raise InvalidAssertion("processing instructions are not allowed")


def _parse(xml, max_depth=None):
    """Parse ``xml`` into an Element tree, refusing DTDs and PIs."""
    if not isinstance(xml, str):
        raise InvalidAssertion("XML input must be text")
    # A DTD must be refused before expat sees it: internal entities could
    # otherwise be expanded (billion laughs) while parsing.
    if _DOCTYPE.search(xml):
        raise InvalidAssertion("DTD declarations are not allowed")

    parser = ET.XMLParser(target=_GuardBuilder(max_depth))
    try:
        parser.feed(xml)
        root = parser.close()
    except InvalidAssertion:
        raise
    except (ET.ParseError, ValueError, UnicodeError, RecursionError):
        raise InvalidAssertion("malformed XML") from None
    if root is None:
        raise InvalidAssertion("empty document")
    return root


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------


def _split_tag(name):
    """Split a Clark-notation tag into ``(namespace_uri_or_None, local)``."""
    if name[:1] == "{":
        uri, _, local = name[1:].partition("}")
        return uri, local
    return None, name


def _local(name):
    return _split_tag(name)[1]


def _escape_text(value):
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # A literal carriage return would be normalised away on re-parse, which
    # would break idempotency; encode it instead.
    return value.replace("\r", "&#xD;")


def _escape_attr(value):
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
    # Attribute-value normalisation would turn literal tabs/newlines into
    # spaces on re-parse, so keep them as character references.
    value = value.replace("\t", "&#x9;").replace("\n", "&#xA;")
    return value.replace("\r", "&#xD;")


def _collect_prefixes(root):
    """Map namespace URIs to ``ns0``, ``ns1``... in first-appearance order."""
    prefixes = {}

    def register(uri):
        if uri is None or uri == _XML_NS or uri in prefixes:
            return
        prefixes[uri] = "ns%d" % len(prefixes)

    stack = [root]
    while stack:
        element = stack.pop()
        register(_split_tag(element.tag)[0])
        for key in element.attrib:
            register(_split_tag(key)[0])
        stack.extend(reversed(list(element)))
    return prefixes


def _canonical_element(root):
    """Serialize one element subtree in canonical form as UTF-8 bytes."""
    prefixes = _collect_prefixes(root)
    out = []
    # Work items are either ("element", element, is_root), ("attr", qname,
    # value), or ("raw", text).
    stack = [("element", root, True)]
    while stack:
        item = stack.pop()
        kind = item[0]
        if kind == "raw":
            out.append(item[1])
            continue
        if kind == "attr":
            out.append(' %s="%s"' % (item[1], _escape_attr(item[2])))
            continue

        _, element, is_root = item
        uri, local = _split_tag(element.tag)
        qname = "%s:%s" % (prefixes[uri], local) if uri is not None else local

        attributes = []
        if is_root:
            for ns_uri, prefix in prefixes.items():
                attributes.append(("xmlns:%s" % prefix, ns_uri))
        for key, value in element.attrib.items():
            attr_uri, attr_local = _split_tag(key)
            if attr_uri == _XML_NS:
                attr_qname = "xml:%s" % attr_local
            elif attr_uri is not None:
                attr_qname = "%s:%s" % (prefixes[attr_uri], attr_local)
            else:
                attr_qname = attr_local
            attributes.append((attr_qname, value))
        attributes.sort(key=lambda pair: pair[0])

        out.append("<" + qname)

        content = []
        children = list(element)
        if not children:
            # Leaf text is preserved exactly, whitespace included.
            content.append(("raw", _escape_text(element.text or "")))
        else:
            if element.text is not None and element.text.strip() != "":
                content.append(("raw", _escape_text(element.text)))
            for child in children:
                content.append(("element", child, False))
                if child.tail is not None and child.tail.strip() != "":
                    content.append(("raw", _escape_text(child.tail)))

        # Push in reverse order so items pop in document order: closing tag
        # first, then content, then ">", then attributes (emitted first).
        stack.append(("raw", "</%s>" % qname))
        for content_item in reversed(content):
            stack.append(content_item)
        stack.append(("raw", ">"))
        for attr_qname, attr_value in reversed(attributes):
            stack.append(("attr", attr_qname, attr_value))
    return "".join(out).encode("utf-8")


def canonicalize(xml: str) -> bytes:
    """Return the canonical UTF-8 bytes of one XML element.

    ``xml`` may be an element fragment or a whole document; the element to
    canonicalize is its single root.  The result is the exact byte string that
    HMAC-SHA256 is computed over.  Canonicalization is deterministic and
    idempotent: if ``xml`` is already canonical, the return value is exactly
    ``xml.encode("utf-8")``.

    Canonical form rules:

    - Reject any input containing a ``<!DOCTYPE`` declaration
      (case-insensitive) with ``InvalidAssertion`` *before* parsing, so
      internal entity expansion can never happen.  Also reject malformed XML,
      more than one root element and processing instructions.
    - Remove the XML declaration and every comment.  Neither participates in
      the output.  A comment inside character data is removed without changing
      the surrounding text, so ``ali<!--x-->ce`` canonicalizes as ``alice``.
    - Decode XML entities and numeric character references to Unicode
      characters, then re-encode text so that ``&``, ``<`` and ``>`` become
      ``&amp;``, ``&lt;`` and ``&gt;``.  In a double-quoted attribute value
      encode ``&``, ``<`` and ``"`` as ``&amp;``, ``&lt;`` and ``&quot;``.
    - Drop whitespace-only text nodes between elements.  Preserve text inside
      leaf elements exactly; do not trim it.
    - Sort attributes by qualified name (Unicode code point order), use double
      quotes and serialize empty elements as ``<tag></tag>``.
    - Normalize namespace prefixes: the same namespace URI must always use the
      same generated prefix (``ns0``, ``ns1``, ... in first-appearance order),
      and the canonical bytes must not depend on the prefix spelling in the
      input.  Declare generated prefixes on the root; unqualified names stay
      unqualified.
    - Return UTF-8 bytes with no BOM, no XML declaration and no trailing
      newline.

    Raise ``InvalidAssertion`` for any input that cannot be canonicalized.
    """
    return _canonical_element(_parse(xml))


# ---------------------------------------------------------------------------
# Assertion binding
# ---------------------------------------------------------------------------


def _text_of(element):
    return "".join(element.itertext())


def _time_attribute(element, name):
    value = element.get(name)
    if value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise InvalidAssertion("%s is not a number" % name) from None
    if not math.isfinite(parsed):
        raise InvalidAssertion("%s is not finite" % name)
    return parsed


def _collect_audience(assertion):
    values = []
    seen = set()
    for restriction in assertion.iter():
        if _local(restriction.tag) != "AudienceRestriction":
            continue
        for candidate in restriction.iter():
            if _local(candidate.tag) != "Audience" or id(candidate) in seen:
                continue
            seen.add(id(candidate))
            values.append(_text_of(candidate).strip())
    return " ".join(values)


def _bind(root):
    """Apply the structural/reference bindings; return (assertion, parsed, sig)."""
    assertions = [el for el in root.iter() if _local(el.tag) == "Assertion"]
    if len(assertions) != 1:
        raise InvalidAssertion("document must contain exactly one Assertion")
    assertion = assertions[0]

    signatures = [el for el in root.iter() if _local(el.tag) == "Signature"]
    if len(signatures) != 1:
        raise InvalidAssertion("document must contain exactly one Signature")
    signature = signatures[0]

    subjects = [el for el in assertion.iter() if _local(el.tag) == "Subject"]
    if len(subjects) != 1:
        raise InvalidAssertion("assertion must contain exactly one Subject")
    name_ids = [el for el in assertion.iter() if _local(el.tag) == "NameID"]
    if len(name_ids) != 1:
        raise InvalidAssertion("assertion must contain exactly one NameID")
    subject = _text_of(name_ids[0]).strip()
    if not subject:
        raise InvalidAssertion("NameID must not be empty")

    assertion_id = assertion.get("ID")
    if not assertion_id or not assertion_id.strip():
        raise InvalidAssertion("Assertion ID is required")
    # The ID lookup must be unambiguous: no other element may carry it.
    for element in root.iter():
        if element is not assertion and element.get("ID") == assertion_id:
            raise InvalidAssertion("duplicate ID in document")

    signed_infos = [c for c in list(signature) if _local(c.tag) == "SignedInfo"]
    if len(signed_infos) != 1:
        raise InvalidAssertion("Signature must contain exactly one SignedInfo")
    references = [c for c in list(signed_infos[0]) if _local(c.tag) == "Reference"]
    if len(references) != 1:
        raise InvalidAssertion("SignedInfo must contain exactly one Reference")
    uri = references[0].get("URI")
    if not isinstance(uri, str) or not uri.startswith("#") or len(uri) < 2:
        raise InvalidAssertion("Reference URI is malformed")
    signed_id = uri[1:]
    # The reference must resolve to the assertion that business code reads,
    # never to a wrapper or ancestor that merely contains it.
    if signed_id != assertion_id:
        raise InvalidAssertion("Reference is not bound to the assertion")

    conditions = next(
        (el for el in assertion.iter() if _local(el.tag) == "Conditions"), None
    )
    not_before = _time_attribute(conditions, "NotBefore") if conditions is not None else None
    not_on_or_after = (
        _time_attribute(conditions, "NotOnOrAfter") if conditions is not None else None
    )

    parsed = {
        "id": assertion_id,
        "subject": subject,
        "audience": _collect_audience(assertion),
        "not_before": not_before,
        "not_on_or_after": not_on_or_after,
        "signed_id": signed_id,
    }
    return assertion, parsed, signature


def parse_assertion(xml: str) -> dict:
    """Parse the single assertion and enforce its structural bindings.

    Contract:

    - ``xml`` is a string.  Input containing ``<!DOCTYPE`` is rejected before
      parsing, so entities are never expanded.
    - The document must contain exactly one ``Assertion`` element (matched by
      local name), exactly one ``Signature`` element, and inside the assertion
      exactly one ``Subject`` and exactly one ``NameID``.  Zero or multiple
      occurrences of any of these are rejected.
    - The ``Assertion`` must have a non-empty ``ID`` attribute.  The single
      ``Signature/SignedInfo/Reference`` must have ``URI="#<that ID>"``.  The
      reference must identify the assertion element itself, not an ancestor or
      wrapper: a missing, malformed, multiple or non-matching reference, or a
      duplicate element carrying the same ID, raises ``InvalidAssertion``.
    - Return a dict with exactly these keys::

          {
              "id": str,
              "subject": str,
              "audience": str,
              "not_before": float | None,
              "not_on_or_after": float | None,
              "signed_id": str,
          }

      ``subject`` is the ``NameID`` text with comments ignored and
      leading/trailing whitespace removed; it must be non-empty.  ``audience``
      joins the text of every ``Audience`` element below the assertion's
      ``AudienceRestriction`` elements with one space each, in document order;
      no audience produces ``""``.  ``not_before`` and ``not_on_or_after``
      are the corresponding ``Conditions`` attributes as epoch seconds
      (floats); an absent ``Conditions`` element or attribute becomes ``None``.
      ``signed_id`` is the reference URI without its leading ``#`` and must
      equal ``id``.
    - Raise ``InvalidAssertion`` for every violation.
    """
    _, parsed, _ = _bind(_parse(xml))
    return parsed


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def _decode_signature_value(raw):
    if not isinstance(raw, str):
        raise InvalidAssertion("SignatureValue must be text")
    text = raw.strip()
    if not text:
        raise InvalidAssertion("SignatureValue is empty")
    if any(character.isspace() for character in text):
        raise InvalidAssertion("SignatureValue contains whitespace")
    if _BASE64.fullmatch(text) is None:
        raise InvalidAssertion("SignatureValue is not standard Base64")
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise InvalidAssertion("SignatureValue is not valid Base64") from None
    # Re-encoding rejects non-canonical padding bits and malformed padding.
    if base64.b64encode(decoded).decode("ascii") != text:
        raise InvalidAssertion("SignatureValue is not canonical Base64")
    if len(decoded) != 32:
        raise InvalidAssertion("SignatureValue has the wrong length")
    return decoded


def _verify_bound(assertion, signature, key):
    if not isinstance(key, (bytes, bytearray)):
        raise InvalidAssertion("HMAC key must be bytes")

    values = [c for c in list(signature) if _local(c.tag) == "SignatureValue"]
    if len(values) != 1:
        raise InvalidAssertion("Signature must contain exactly one SignatureValue")
    provided = _decode_signature_value(_text_of(values[0]))

    canonical = _canonical_element(assertion)
    expected = hmac.new(bytes(key), canonical, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, provided):
        raise InvalidAssertion("signature mismatch")


def verify_hmac(xml: str, key: bytes) -> None:
    """Verify the HMAC-SHA256 signature over the referenced assertion.

    Contract:

    - Parse and bind the document exactly as :func:`parse_assertion` does; any
      structural or reference-binding failure raises ``InvalidAssertion``
      before cryptographic work.
    - Canonicalize the ``Assertion`` element with :func:`canonicalize` and
      compute ``HMAC-SHA256(key, canonical_bytes)`` over those bytes.  ``key``
      is the raw HMAC key as bytes.
    - The ``SignatureValue`` text must be strict standard Base64 (``A-Z``,
      ``a-z``, ``0-9``, ``+``, ``/`` and correct ``=`` padding) of exactly 32
      bytes.  Whitespace around the value is allowed; whitespace inside it,
      URL-safe characters, missing padding and wrong decoded lengths are
      rejected.  Decode it and compare with :func:`hmac.compare_digest` in
      constant time.  A mismatch raises ``InvalidAssertion``.
    - Only the referenced assertion is covered by the HMAC; the
      ``Signature`` element and ``SignatureValue`` are not.
    - Return ``None`` on success; raise ``InvalidAssertion`` on any failure.
    """
    assertion, _, signature = _bind(_parse(xml))
    _verify_bound(assertion, signature, key)


# ---------------------------------------------------------------------------
# Conditions and replay protection
# ---------------------------------------------------------------------------


def _as_time(value, name):
    if value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise InvalidAssertion("%s is not a number" % name) from None
    if not math.isfinite(parsed):
        raise InvalidAssertion("%s is not finite" % name)
    return parsed


def check_conditions(
    assertion: dict, now: float, audience: str, skew: int = 120
) -> None:
    """Validate the time window and audience of a parsed assertion.

    ``assertion`` is the dict returned by :func:`parse_assertion`.  ``now`` and
    ``skew`` are seconds; ``now`` may be a float and ``skew`` must be a
    non-negative integer (a negative skew is rejected).  The default skew is
    120 seconds.

    Rules (all boundaries are inclusive):

    - Lower bound: ``not_before - skew <= now``.  ``not_before is None`` means
      there is no lower bound.
    - Upper bound: ``now <= not_on_or_after + skew``.  ``not_on_or_after is
      None`` means there is no upper bound.
    - A value exactly on either boundary is accepted; one second outside it is
      rejected.
    - Audience: ``assertion["audience"]`` is a whitespace-separated list of
      exact values (the parser joins multiple ``<Audience>`` elements with one
      space).  ``audience`` must exactly equal one token.  Matching is
      case-sensitive and is never a substring/prefix match; an empty or
      missing audience never matches.
    - Return ``None`` on success; raise ``InvalidAssertion`` on any violation.
    """
    if not isinstance(assertion, dict):
        raise InvalidAssertion("assertion must be a parsed mapping")
    if not isinstance(skew, int) or skew < 0:
        raise InvalidAssertion("skew must be a non-negative integer")
    current = _as_time(now, "now")
    if current is None:
        raise InvalidAssertion("now is required")

    not_before = _as_time(assertion.get("not_before"), "not_before")
    not_on_or_after = _as_time(assertion.get("not_on_or_after"), "not_on_or_after")

    if not_before is not None and current < not_before - skew:
        raise InvalidAssertion("assertion is not yet valid")
    if not_on_or_after is not None and current > not_on_or_after + skew:
        raise InvalidAssertion("assertion has expired")

    configured = assertion.get("audience")
    if not isinstance(audience, str) or not audience:
        raise InvalidAssertion("configured audience is required")
    if not isinstance(configured, str):
        raise InvalidAssertion("assertion audience is malformed")
    # Exact token match: no prefix/substring matching, case-sensitive.
    if audience not in configured.split():
        raise InvalidAssertion("audience mismatch")


def authenticate(
    xml: str, key: bytes, audience: str, now: float, seen: set
) -> str:
    """Run the complete validation chain and consume the assertion id.

    Contract:

    - ``xml`` is a UTF-8 string.  Reject it with ``InvalidAssertion`` if its
      UTF-8 encoding is longer than 256 KiB (262144 bytes; exactly 262144 is
      allowed), if it contains ``<!DOCTYPE``, or if element nesting depth
      exceeds 32 (the root element has depth 1).  These guards run before
      parsing or entity expansion.
    - Run :func:`parse_assertion`, :func:`verify_hmac`, then
      :func:`check_conditions` with the fixed default skew of 120 seconds.
    - Replay protection: ``seen`` is the caller-owned set of already consumed
      assertion ids.  If ``assertion["id"]`` is already in ``seen``, raise
      ``InvalidAssertion``.  Otherwise add the id to ``seen`` and return the
      subject.  The id is consumed only after all previous checks succeed, so
      a failed request does not burn the id.
    - Return the validated subject string; raise ``InvalidAssertion`` on any
      failure.
    """
    if not isinstance(xml, str):
        raise InvalidAssertion("XML input must be text")
    try:
        encoded = xml.encode("utf-8")
    except UnicodeEncodeError:
        raise InvalidAssertion("XML input is not valid UTF-8 text") from None
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise InvalidAssertion("document is too large")
    if _DOCTYPE.search(xml):
        raise InvalidAssertion("DTD declarations are not allowed")

    assertion, parsed, signature = _bind(_parse(xml, max_depth=MAX_DEPTH))
    _verify_bound(assertion, signature, key)
    check_conditions(parsed, now, audience, DEFAULT_SKEW)

    assertion_id = parsed["id"]
    if assertion_id in seen:
        raise InvalidAssertion("assertion has already been used")
    seen.add(assertion_id)
    return parsed["subject"]
