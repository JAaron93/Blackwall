import asyncio
import json
from hypothesis import given, settings
from hypothesis import strategies as st

from blackwall.middleware.context_hygiene import ContextHygiene
from blackwall.models import ToolCallContext

import string

# Keys should be alphanumeric so they don't accidentally match regex patterns like FILE_PATH or IP_ADDRESS
alphanumeric_keys = st.text(
    alphabet=string.ascii_letters + string.digits, min_size=1, max_size=10
)

# Generate random dictionaries that simulate JSON payloads
json_strategy = st.recursive(
    st.dictionaries(
        alphanumeric_keys,
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(),
            st.floats(allow_nan=False, allow_infinity=False),
            st.text(max_size=50),
        ),
        max_size=5,
    ),
    lambda children: st.dictionaries(
        alphanumeric_keys, children | st.lists(children, max_size=3), max_size=3
    ),
    max_leaves=10,
)

# A strategy that explicitly injects sensitive data patterns to ensure redactions occur
sensitive_data_strategy = st.one_of(
    st.just("api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"),
    st.just("192.168.1.100"),
    st.just("/etc/shadow"),
    st.just("password=supersecret"),
    st.just("test@example.com"),
    st.just("https://malicious.com/payload"),
    st.text(max_size=20),
)

mixed_json_strategy = st.dictionaries(
    alphanumeric_keys, sensitive_data_strategy, max_size=5
)


def run_async(coro):
    """Helper to run async code synchronously for hypothesis tests"""
    return asyncio.run(coro)


@settings(max_examples=50, deadline=None)
@given(arguments=mixed_json_strategy)
def test_property_4_sanitization_idempotence(arguments):
    """
    Property 4: Sanitization Idempotence
    Validates: Requirements 4.10
    Applying sanitization twice should yield the same result as applying it once.
    """
    context = ToolCallContext(tool_name="test_tool", arguments=arguments)
    hygiene = ContextHygiene()

    # First sanitization
    result1 = run_async(hygiene.sanitize(context))

    # Second sanitization
    result2 = run_async(hygiene.sanitize(result1))

    # The arguments should be identical
    assert result1.arguments == result2.arguments

    assert "raw_fallback" not in result1.arguments
    assert "raw_fallback" not in result2.arguments

    # Verify no raw secrets remain in sanitized output (basic check)
    sanitized_str = json.dumps(result1.arguments)
    assert "api_key=" not in sanitized_str
    assert "supersecret" not in sanitized_str
    assert "192.168.1.100" not in sanitized_str


@settings(max_examples=50, deadline=None)
@given(arguments=json_strategy)
def test_property_5_sanitization_structure_preservation(arguments):
    """
    Property 5: Sanitization Structure Preservation
    Validates: Requirements 4.11
    Sanitizing should not break JSON parsing and should preserve top-level keys.
    """
    context = ToolCallContext(tool_name="test_tool", arguments=arguments)
    hygiene = ContextHygiene()

    result = run_async(hygiene.sanitize(context))

    # The result arguments must be a dict (valid parseable JSON structure)
    assert isinstance(result.arguments, dict)
    assert "raw_fallback" not in result.arguments

    # Top-level keys should be identical
    assert set(result.arguments.keys()) == set(arguments.keys())
