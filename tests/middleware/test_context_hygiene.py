import pytest
from blackwall.middleware.context_hygiene import ContextHygiene
from blackwall.models import ToolCallContext

@pytest.fixture
def hygiene():
    return ContextHygiene()

@pytest.mark.asyncio
async def test_api_key_redaction(hygiene):
    text = '{"auth": "api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"}'
    result, redactions = await hygiene.apply_redaction(text)
    assert "[[API_KEY]]" in result
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ12345" not in result
    assert len(redactions) == 1
    assert redactions[0].pattern_matched == "API_KEY"

@pytest.mark.asyncio
async def test_ip_address_redaction(hygiene):
    text = '{"host": "192.168.1.100"}'
    result, redactions = await hygiene.apply_redaction(text)
    assert "[[IP_ADDRESS]]" in result
    assert "192.168.1.100" not in result

@pytest.mark.asyncio
async def test_file_path_redaction(hygiene):
    text = '{"file": "/etc/passwd"}'
    result, _ = await hygiene.apply_redaction(text)
    assert "[[FILE_PATH]]" in result
    assert "/etc/passwd" not in result

@pytest.mark.asyncio
async def test_password_redaction(hygiene):
    text = '{"db": "password=supersecret"}'
    result, _ = await hygiene.apply_redaction(text)
    assert "[[PASSWORD]]" in result
    assert "supersecret" not in result

@pytest.mark.asyncio
async def test_email_redaction(hygiene):
    text = '{"user": "test@example.com"}'
    result, _ = await hygiene.apply_redaction(text)
    assert "[[EMAIL]]" in result
    assert "test@example.com" not in result

@pytest.mark.asyncio
async def test_url_redaction(hygiene):
    text = '{"website": "https://malicious.com/payload"}'
    result, _ = await hygiene.apply_redaction(text)
    assert "[[URL]]" in result
    assert "https://malicious.com/payload" not in result

@pytest.mark.asyncio
async def test_json_structure_preservation_after_redaction(hygiene):
    context = ToolCallContext(
        tool_name="test_tool",
        arguments={
            "nested": {"ip": "10.0.0.1", "key": "apikey=ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"},
            "file": "/etc/passwd",
            "website": "https://malicious.com/payload"
        },
    )
    sanitized = await hygiene.sanitize(context)
    
    # Check structure
    assert "raw_fallback" not in sanitized.arguments
    assert "nested" in sanitized.arguments
    assert sanitized.arguments["nested"]["ip"] == "[[IP_ADDRESS]]"
    assert sanitized.arguments["nested"]["key"] == "[[API_KEY]]"
    assert sanitized.arguments["file"] == "[[FILE_PATH]]"
    assert sanitized.arguments["website"] == "[[URL]]"

@pytest.mark.asyncio
async def test_metadata_logging(hygiene):
    context = ToolCallContext(
        tool_name="test_tool",
        arguments={"ip": "10.0.0.1"}
    )
    sanitized = await hygiene.sanitize(context)
    
    metadata = sanitized.metadata
    assert metadata is not None
    assert metadata["redactionCount"] == 1
    assert len(metadata["redactionLog"]) == 1
    log_entry = metadata["redactionLog"][0]
    assert log_entry["pattern_matched"] == "IP_ADDRESS"
    assert "original_hash" in log_entry
    assert "originalHash" in metadata

@pytest.mark.asyncio
async def test_regex_timeout_and_auto_disable(hygiene):
    # Register a deliberately slow/catastrophic regex pattern
    # (a+)+$ on a string of many a's followed by a 'b'
    hygiene.register_pattern("SLOW", r"(a+)+$", "[[SLOW]]")
    hygiene.timeout_seconds = 0.05  # 50ms for faster testing
    
    text = '{"data": "' + "a" * 30 + 'b"}'  # This triggers catastrophic backtracking
    
    # 1. Trigger the timeout 9 times
    for _ in range(9):
        await hygiene.apply_redaction(text)
        
    slow_pattern = next(p for p in hygiene.patterns if p.name == "SLOW")
    assert slow_pattern.consecutive_timeouts == 9
    assert slow_pattern.enabled is True
    
    # 2. Trigger the 10th time
    await hygiene.apply_redaction(text)
    
    assert slow_pattern.consecutive_timeouts == 10
    assert slow_pattern.enabled is False
    
    # 3. Next time, it should be skipped immediately
    await hygiene.apply_redaction(text)
    assert slow_pattern.consecutive_timeouts == 10  # Doesn't increment since skipped
