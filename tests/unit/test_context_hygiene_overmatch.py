"""Regression tests for ContextHygiene redaction over-match (TASK-F08).

Found during the typesafe-ai skill audit (F6): the password pattern matched a
bare SQL column named ``password``/``passwd``/``pwd`` followed by any next token
(``SELECT password FROM users`` lost ``FROM``), and the ``sk-`` API-key pattern
matched inside ordinary hyphenated words (``disk-usage-report-12345`` became
``di[[OPENAI_API_KEY]]``). Both corrupt a benign tool-call state before it
reaches Jev. The fix requires a credential-shaped value after the password
keyword (an assignment or a quoted string) and anchors ``sk-`` to a word
boundary. These tests cover the production resolver path (default + IOC) and
the async middleware, and assert real credentials are still redacted.
"""

from __future__ import annotations

import pytest

from blackwall.middleware.context_hygiene import ContextHygiene as MiddlewareHygiene
from blackwall.models import ToolCallContext
from blackwall.resolver import ContextHygiene


@pytest.mark.parametrize("preserve_iocs", [False, True])
def test_password_column_is_not_corrupted(preserve_iocs: bool) -> None:
    hygiene = ContextHygiene(preserve_iocs=preserve_iocs)
    assert (
        hygiene.sanitize_string("SELECT password FROM users")
        == "SELECT password FROM users"
    )
    assert (
        hygiene.sanitize_string("SELECT passwd, pwd FROM accounts")
        == "SELECT passwd, pwd FROM accounts"
    )


@pytest.mark.parametrize("preserve_iocs", [False, True])
def test_real_password_assignments_still_redacted(preserve_iocs: bool) -> None:
    hygiene = ContextHygiene(preserve_iocs=preserve_iocs)
    for raw, secret in [
        ("password=Hunter2", "Hunter2"),
        ("password: SuperSecretPassword123", "SuperSecretPassword123"),
        ('password "quotedsecretvalue"', "quotedsecretvalue"),
        ("PWD=root123", "root123"),
    ]:
        out = hygiene.sanitize_string(raw)
        assert secret not in out, raw
        assert "[[PASSWORD]]" in out, raw


@pytest.mark.parametrize("preserve_iocs", [False, True])
def test_sk_key_not_matched_inside_hyphenated_word(preserve_iocs: bool) -> None:
    hygiene = ContextHygiene(preserve_iocs=preserve_iocs)
    for raw in ["disk-usage-report-12345", "computation_task-5531_result"]:
        out = hygiene.sanitize_string(raw)
        assert "[[OPENAI_API_KEY]]" not in out, raw
        assert out == raw, raw


@pytest.mark.parametrize("preserve_iocs", [False, True])
def test_real_openai_key_still_redacted(preserve_iocs: bool) -> None:
    hygiene = ContextHygiene(preserve_iocs=preserve_iocs)
    for raw in ["sk-proj-abcdef1234567890", "key=sk-abcdef1234567890"]:
        out = hygiene.sanitize_string(raw)
        assert "[[OPENAI_API_KEY]]" in out, raw
        assert "abcdef1234567890" not in out, raw


@pytest.mark.asyncio
async def test_middleware_password_column_is_not_corrupted() -> None:
    hygiene = MiddlewareHygiene()
    ctx = ToolCallContext(
        tool_name="query_db",
        arguments={"sql": "SELECT password FROM users"},
    )
    sanitized = await hygiene.sanitize(ctx)
    assert sanitized.arguments["sql"] == "SELECT password FROM users"


@pytest.mark.parametrize("preserve_iocs", [False, True])
def test_password_flag_space_separated_is_redacted(preserve_iocs: bool) -> None:
    """Review regression: narrowing to assignment/quoted values dropped the
    space-separated CLI flag form (``--password Hunter2``), exposing the secret
    to Jev's outbound state. A flag-specific pattern must redact it while the
    SQL-column fix stays intact."""
    hygiene = ContextHygiene(preserve_iocs=preserve_iocs)
    for raw, secret in [
        ("redis-cli --password Hunter2 PING", "Hunter2"),
        ("mysql -pwd Secret123 --host db", "Secret123"),
        ("tool --passwd SuperSecret1", "SuperSecret1"),
    ]:
        out = hygiene.sanitize_string(raw)
        assert secret not in out, raw
        assert "[[PASSWORD]]" in out, raw


@pytest.mark.parametrize("preserve_iocs", [False, True])
def test_password_flag_quoted_and_assignment_redacted(preserve_iocs: bool) -> None:
    hygiene = ContextHygiene(preserve_iocs=preserve_iocs)
    for raw, secret in [
        ('redis-cli --password "Hunter2" PING', "Hunter2"),
        ("redis-cli --password=Hunter2 PING", "Hunter2"),
    ]:
        out = hygiene.sanitize_string(raw)
        assert secret not in out, raw
        assert "[[PASSWORD]]" in out, raw


@pytest.mark.parametrize("preserve_iocs", [False, True])
def test_password_flag_fix_keeps_sql_column_intact(preserve_iocs: bool) -> None:
    hygiene = ContextHygiene(preserve_iocs=preserve_iocs)
    assert (
        hygiene.sanitize_string("SELECT password FROM users")
        == "SELECT password FROM users"
    )


@pytest.mark.asyncio
async def test_middleware_password_flag_is_redacted() -> None:
    hygiene = MiddlewareHygiene()
    ctx = ToolCallContext(
        tool_name="run_command",
        arguments={"cmd": "redis-cli --password Hunter2 PING"},
    )
    sanitized = await hygiene.sanitize(ctx)
    assert "Hunter2" not in sanitized.arguments["cmd"]
    assert "[[PASSWORD]]" in sanitized.arguments["cmd"]