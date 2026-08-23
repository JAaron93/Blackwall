"""Property-based tests for ContextHygiene sanitization invariants.

Uses Hypothesis to verify:
  - Sanitization is idempotent: sanitize(sanitize(x)) == sanitize(x)
  - Sensitive values (API keys, passwords, URLs, IPs, emails) are scrubbed from outputs
  - Non-sensitive plain text passes through unchanged
  - All injected placeholders match the canonical [[VARIABLE_NAME]] format
  - ToolCallContext structures preserve schema and metadata while scrubbing payload values
"""

import re
from typing import Any, Dict, List
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from blackwall.models import ToolCallContext
from blackwall.resolver import ContextHygiene


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

PLACEHOLDER_REGEX = re.compile(r"\[\[[A-Z_]+\]\]")
KNOWN_PLACEHOLDERS = {
    "[[API_KEY]]",
    "[[URL]]",
    "[[IP_ADDRESS]]",
    "[[FILE_PATH]]",
    "[[PASSWORD]]",
    "[[EMAIL]]",
}

# Alphanumeric benign plain text (no slashes, colons, @, http, digits in IP patterns)
benign_word_st = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ",
    min_size=1,
    max_size=50,
).filter(lambda s: bool(s.strip()))

# Secret generation strategies
api_key_secret_st = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
    min_size=20,
    max_size=40,
)
password_secret_st = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#%^&*",
    min_size=8,
    max_size=24,
).filter(lambda s: " " not in s and "'" not in s and '"' not in s)

ip_octet_st = st.integers(min_value=1, max_value=254)
ip_address_st = st.tuples(ip_octet_st, ip_octet_st, ip_octet_st, ip_octet_st).map(
    lambda octets: f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}"
)

url_st = st.builds(
    lambda scheme, domain, path: f"{scheme}://{domain}.com/{path}",
    scheme=st.sampled_from(["http", "https"]),
    domain=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=12),
    path=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789/", min_size=1, max_size=20),
)

email_st = st.builds(
    lambda user, domain: f"{user}@{domain}.com",
    user=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=3, max_size=10),
    domain=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=8),
)

file_path_st = st.builds(
    lambda d1, d2, f: f"/{d1}/{d2}/{f}",
    d1=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=2, max_size=8),
    d2=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=2, max_size=8),
    f=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789.", min_size=2, max_size=10),
)

# Text with embedded secrets
@st.composite
def text_with_secrets_st(draw):
    prefix = "prefix_benign_text"
    secret_type = draw(st.sampled_from(["api_key", "password", "ip", "url", "email", "path"]))
    if secret_type == "api_key":
        secret_val = draw(api_key_secret_st)
        sep = draw(st.sampled_from(["=", ": ", " := '", "=\""]))
        quote = "'" if "'" in sep else ('"' if '"' in sep else "")
        raw_fragment = f"api_key{sep}{secret_val}{quote}"
        return f"{prefix} {raw_fragment}", secret_val
    elif secret_type == "password":
        secret_val = draw(password_secret_st)
        sep = draw(st.sampled_from([": ", "=", " = '"]))
        quote = "'" if "'" in sep else ""
        raw_fragment = f"password{sep}{secret_val}{quote}"
        return f"{prefix} {raw_fragment}", secret_val
    elif secret_type == "ip":
        secret_val = draw(ip_address_st)
        return f"{prefix} host {secret_val} connected", secret_val
    elif secret_type == "url":
        secret_val = draw(url_st)
        return f"{prefix} fetch {secret_val} now", secret_val
    elif secret_type == "email":
        secret_val = draw(email_st)
        return f"{prefix} contact {secret_val} support", secret_val
    else:
        secret_val = draw(file_path_st)
        return f"{prefix} load {secret_val} config", secret_val


# Arbitrary nested JSON structures
json_primitive_st = st.one_of(
    st.text(max_size=80),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.booleans(),
    st.none(),
)

json_values_st = st.recursive(
    json_primitive_st,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(
            keys=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=15),
            values=children,
            max_size=5,
        ),
    ),
    max_leaves=15,
)

tool_call_context_strategy = st.builds(
    ToolCallContext,
    tool_name=benign_word_st,
    arguments=st.dictionaries(
        keys=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=15),
        values=json_values_st,
        max_size=5,
    ),
    metadata=st.one_of(
        st.none(),
        st.dictionaries(
            keys=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=15),
            values=st.text(max_size=30),
            max_size=3,
        ),
    ),
)


# ---------------------------------------------------------------------------
# Property 1: Sanitization is idempotent: sanitize(sanitize(x)) == sanitize(x)
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(text=st.text(max_size=200))
def test_sanitize_string_idempotency(text: str) -> None:
    """Property: sanitize_string(sanitize_string(s)) == sanitize_string(s)."""
    hygiene = ContextHygiene()
    first_pass = hygiene.sanitize_string(text)
    second_pass = hygiene.sanitize_string(first_pass)
    assert first_pass == second_pass, (
        f"Non-idempotent sanitization on string:\nFirst:  {first_pass!r}\nSecond: {second_pass!r}"
    )


@settings(max_examples=200)
@given(val=json_values_st)
def test_sanitize_value_idempotency(val: Any) -> None:
    """Property: sanitize_value(sanitize_value(v)) == sanitize_value(v) for arbitrary structures."""
    hygiene = ContextHygiene()
    first_pass = hygiene.sanitize_value(val)
    second_pass = hygiene.sanitize_value(first_pass)
    assert first_pass == second_pass, "Non-idempotent sanitization on arbitrary JSON structure"


@settings(max_examples=200)
@given(context=tool_call_context_strategy)
def test_sanitize_context_idempotency(context: ToolCallContext) -> None:
    """Property: sanitize_context(sanitize_context(c)) == sanitize_context(c)."""
    hygiene = ContextHygiene()
    first_pass = hygiene.sanitize_context(context)
    second_pass = hygiene.sanitize_context(first_pass)
    assert first_pass == second_pass, "Non-idempotent sanitization on ToolCallContext"


# ---------------------------------------------------------------------------
# Property 2: Sensitive values are omitted from output
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(payload=text_with_secrets_st())
def test_sensitive_values_scrubbed_from_output(payload: tuple[str, str]) -> None:
    """Property: Raw secret substrings never appear in the sanitized string."""
    raw_text, secret_val = payload
    hygiene = ContextHygiene()
    sanitized = hygiene.sanitize_string(raw_text)

    # The secret value should no longer be present verbatim
    assert secret_val not in sanitized, (
        f"Secret {secret_val!r} was not sanitized from output:\nRaw:       {raw_text!r}\nSanitized: {sanitized!r}"
    )


# ---------------------------------------------------------------------------
# Property 3: Non-sensitive plain text passes through unchanged
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(text=benign_word_st)
def test_non_sensitive_plain_text_preserved(text: str) -> None:
    """Property: Non-sensitive alphanumeric plain text without trigger patterns passes through unchanged."""
    hygiene = ContextHygiene()
    sanitized = hygiene.sanitize_string(text)
    assert sanitized == text, (
        f"Benign text unexpectedly modified:\nOriginal:  {text!r}\nSanitized: {sanitized!r}"
    )


# ---------------------------------------------------------------------------
# Property 4: All placeholder patterns match [[VARIABLE_NAME]] regex
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(payload=text_with_secrets_st())
def test_all_placeholders_match_canonical_format(payload: tuple[str, str]) -> None:
    """Property: Every placeholder injected during sanitization matches [[VARIABLE_NAME]]."""
    raw_text, _ = payload
    hygiene = ContextHygiene()
    sanitized = hygiene.sanitize_string(raw_text)

    placeholders = PLACEHOLDER_REGEX.findall(sanitized)
    for ph in placeholders:
        assert ph in KNOWN_PLACEHOLDERS, f"Unknown or malformed placeholder generated: {ph!r}"


# ---------------------------------------------------------------------------
# Property 5: ToolCallContext preserves schema and non-sensitive metadata
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(context=tool_call_context_strategy)
def test_tool_call_context_structure_preserved(context: ToolCallContext) -> None:
    """Property: sanitize_context preserves tool_name and top-level argument keys."""
    hygiene = ContextHygiene()
    sanitized = hygiene.sanitize_context(context)

    assert sanitized.tool_name == context.tool_name
    assert set(sanitized.arguments.keys()) == set(context.arguments.keys())
    if context.metadata:
        assert sanitized.metadata is not None
        assert set(sanitized.metadata.keys()) == set(context.metadata.keys())
    else:
        assert sanitized.metadata is None
