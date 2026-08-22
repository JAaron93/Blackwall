"""
Unit tests for blackwall.adk_integration.

Covers:
1. ADKIntegration.__init__ — ValueError when loop is None
2. ADKIntegration.resumeCallback — ALLOW / BLOCK / QUARANTINE / unknown verdict
3. ADKIntegration._execute_quarantined — each tool-name category
4. FreeTierADKIntegration.__init__ — with and without an explicit loop
5. FreeTierADKIntegration.before_tool_callback — mocked sync_resolver.evaluate
6. FreeTierADKIntegration._apply_verdict — each decision type + unknown raises ValueError
7. ADKIntegration.before_tool_callback — full flow (mock queue.enqueue to fire resume
   callback immediately so the thread does not block)
"""

import asyncio
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blackwall.adk_integration import ADKIntegration, FreeTierADKIntegration
from blackwall.interception import InterceptionQueue
from blackwall.models import CallbackToken, ToolCallContext, Verdict, VerdictDecision


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _allow_verdict(reasoning: str = "permitted") -> Verdict:
    return Verdict(
        decision=VerdictDecision.ALLOW,
        reasoning=reasoning,
        confidence_score=0.99,
    )


def _block_verdict(reasoning: str = "blocked") -> Verdict:
    return Verdict(
        decision=VerdictDecision.BLOCK,
        reasoning=reasoning,
        confidence_score=0.99,
    )


def _quarantine_verdict(reasoning: str = "quarantined") -> Verdict:
    return Verdict(
        decision=VerdictDecision.QUARANTINE,
        reasoning=reasoning,
        confidence_score=0.99,
    )


def _token_for(tool_name: str, arguments: dict | None = None) -> CallbackToken:
    ctx = ToolCallContext(tool_name=tool_name, arguments=arguments or {})
    return CallbackToken(thread_id="thread-test", tool_context=ctx)


# ---------------------------------------------------------------------------
# 1. ADKIntegration.__init__
# ---------------------------------------------------------------------------


class TestADKIntegrationInit:
    def test_raises_value_error_when_loop_is_none(self) -> None:
        """__init__ must raise ValueError when loop=None."""
        queue = InterceptionQueue()
        with pytest.raises(ValueError, match="Event loop must be explicitly provided"):
            ADKIntegration(queue=queue, loop=None)

    def test_stores_queue_and_loop(self) -> None:
        """When a valid loop is provided, queue and loop are stored."""
        queue = InterceptionQueue()
        loop = asyncio.new_event_loop()
        try:
            integration = ADKIntegration(queue=queue, loop=loop)
            assert integration.queue is queue
            assert integration.loop is loop
        finally:
            loop.close()


# ---------------------------------------------------------------------------
# 2. ADKIntegration.resumeCallback
# ---------------------------------------------------------------------------


class TestADKIntegrationResumeCallback:
    """Tests the resumeCallback method directly, bypassing the queue."""

    def _make_integration(self) -> ADKIntegration:
        queue = InterceptionQueue()
        loop = asyncio.new_event_loop()
        return ADKIntegration(queue=queue, loop=loop)

    # -------------------------------------------------------------------

    def test_allow_returns_arguments(self) -> None:
        """ALLOW verdict must return the original arguments dict."""
        integration = self._make_integration()
        token = _token_for("safe_tool", {"key": "value"})
        arguments = {"key": "value"}
        result = integration.resumeCallback(token, _allow_verdict(), arguments)
        assert result == arguments

    def test_block_raises_permission_error(self) -> None:
        """BLOCK verdict must raise PermissionError containing the reasoning."""
        integration = self._make_integration()
        token = _token_for("dangerous_tool")
        with pytest.raises(PermissionError, match="BLOCK"):
            integration.resumeCallback(token, _block_verdict("unsafe call"), {})

    def test_quarantine_returns_quarantine_result(self) -> None:
        """QUARANTINE verdict must return the _execute_quarantined result."""
        integration = self._make_integration()
        token = _token_for("execute_terminal", {"cmd": "ls"})

        # _execute_quarantined returns a dict for terminal tools
        result = integration.resumeCallback(token, _quarantine_verdict(), {"cmd": "ls"})
        assert isinstance(result, dict)
        # terminal category response
        assert "stdout" in result
        assert result["exit_code"] == 0

    def test_unknown_verdict_raises_value_error(self) -> None:
        """An unrecognised decision on the verdict object must raise ValueError."""
        integration = self._make_integration()
        token = _token_for("some_tool")

        # Patch the verdict to carry an invalid decision string
        bad_verdict = MagicMock(spec=Verdict)
        bad_verdict.decision = "UNKNOWN_DECISION"
        bad_verdict.reasoning = "no reason"

        with pytest.raises(ValueError, match="Unknown verdict decision"):
            integration.resumeCallback(token, bad_verdict, {})


# ---------------------------------------------------------------------------
# 3. ADKIntegration._execute_quarantined
# ---------------------------------------------------------------------------


class TestADKIntegrationExecuteQuarantined:
    """Tests the quarantine sandbox mock responses for each tool-name category."""

    def _make_integration(self) -> ADKIntegration:
        queue = InterceptionQueue()
        loop = asyncio.new_event_loop()
        return ADKIntegration(queue=queue, loop=loop)

    def _ctx(self, tool_name: str, arguments: dict | None = None) -> ToolCallContext:
        return ToolCallContext(tool_name=tool_name, arguments=arguments or {})

    # --- terminal ---

    @pytest.mark.parametrize("tool_name", ["execute_terminal", "execute_bash", "run_command"])
    def test_terminal_tools_return_stdout(self, tool_name: str) -> None:
        integration = self._make_integration()
        result = integration._execute_quarantined(self._ctx(tool_name))
        assert isinstance(result, dict)
        assert "stdout" in result
        assert "stderr" in result
        assert result["exit_code"] == 0
        assert "quarantined" in result["stdout"].lower() or "mocked" in result["stdout"].lower()

    # --- file write ---

    @pytest.mark.parametrize("tool_name", ["write_file", "file_write", "save_file"])
    def test_file_write_tools_return_success(self, tool_name: str) -> None:
        integration = self._make_integration()
        result = integration._execute_quarantined(
            self._ctx(tool_name, {"path": "/tmp/out.txt", "content": "hello"})
        )
        assert isinstance(result, dict)
        assert result["success"] is True
        assert "bytes_written" in result
        assert result["path"] == "/tmp/out.txt"

    def test_file_write_bytes_written_matches_content_length(self) -> None:
        integration = self._make_integration()
        content = "hello world"
        result = integration._execute_quarantined(
            self._ctx("write_file", {"content": content, "path": "x.txt"})
        )
        assert result["bytes_written"] == len(content)

    def test_file_write_missing_path_defaults(self) -> None:
        """When path is absent, it should fall back to the default value."""
        integration = self._make_integration()
        result = integration._execute_quarantined(
            self._ctx("write_file", {"content": "data"})
        )
        assert result["path"] == "quarantined_file"

    # --- socket ---

    @pytest.mark.parametrize("tool_name", ["socket_connect", "connect"])
    def test_socket_tools_return_failure(self, tool_name: str) -> None:
        integration = self._make_integration()
        result = integration._execute_quarantined(self._ctx(tool_name))
        assert isinstance(result, dict)
        assert result["success"] is False
        assert "quarantined" in result["error"].lower()

    # --- unknown ---

    def test_unknown_tool_returns_generic_quarantine_response(self) -> None:
        integration = self._make_integration()
        result = integration._execute_quarantined(self._ctx("completely_unknown_tool"))
        assert isinstance(result, dict)
        assert result["status"] == "quarantined"
        assert "message" in result


# ---------------------------------------------------------------------------
# 4. FreeTierADKIntegration.__init__
# ---------------------------------------------------------------------------


class TestFreeTierADKIntegrationInit:
    def test_stores_sync_resolver(self) -> None:
        """sync_resolver is stored on the instance."""
        resolver = MagicMock()
        integration = FreeTierADKIntegration(sync_resolver=resolver)
        assert integration.sync_resolver is resolver

    def test_uses_explicit_loop_when_provided(self) -> None:
        """When loop is passed explicitly it must be used."""
        resolver = MagicMock()
        loop = asyncio.new_event_loop()
        try:
            integration = FreeTierADKIntegration(sync_resolver=resolver, loop=loop)
            assert integration.loop is loop
        finally:
            loop.close()

    def test_creates_loop_when_none_provided(self) -> None:
        """When no loop argument is given, __init__ creates or fetches one."""
        resolver = MagicMock()
        integration = FreeTierADKIntegration(sync_resolver=resolver, loop=None)
        assert integration.loop is not None
        assert isinstance(integration.loop, asyncio.AbstractEventLoop)


# ---------------------------------------------------------------------------
# 5. FreeTierADKIntegration.before_tool_callback
# ---------------------------------------------------------------------------


class TestFreeTierADKIntegrationBeforeToolCallback:
    """Tests before_tool_callback with a mocked sync_resolver.evaluate."""

    def _make(self, verdict: Verdict) -> FreeTierADKIntegration:
        """Build a FreeTierADKIntegration whose resolver always returns *verdict*."""
        resolver = MagicMock()
        resolver.evaluate = AsyncMock(return_value=verdict)
        loop = asyncio.new_event_loop()
        return FreeTierADKIntegration(sync_resolver=resolver, loop=loop)

    # -------------------------------------------------------------------

    def test_allow_returns_arguments(self) -> None:
        """ALLOW verdict: before_tool_callback must return the arguments dict."""
        integration = self._make(_allow_verdict())
        arguments = {"param": 42}
        result = integration.before_tool_callback("safe_tool", arguments)
        assert result == arguments

    def test_block_raises_permission_error(self) -> None:
        """BLOCK verdict: before_tool_callback must raise PermissionError."""
        integration = self._make(_block_verdict("policy violation"))
        with pytest.raises(PermissionError, match="BLOCK"):
            integration.before_tool_callback("bad_tool", {})

    def test_quarantine_returns_mock_response(self) -> None:
        """QUARANTINE verdict: before_tool_callback must return quarantine dict."""
        integration = self._make(_quarantine_verdict())
        result = integration.before_tool_callback("suspicious_tool", {"x": 1})
        assert isinstance(result, dict)
        assert result["status"] == "quarantined"

    def test_evaluate_is_called_with_context(self) -> None:
        """sync_resolver.evaluate must be called with a ToolCallContext."""
        integration = self._make(_allow_verdict())
        integration.before_tool_callback("my_tool", {"a": 1}, metadata={"b": 2})
        call_args = integration.sync_resolver.evaluate.call_args
        context_arg = call_args[0][0]
        assert isinstance(context_arg, ToolCallContext)
        assert context_arg.tool_name == "my_tool"
        assert context_arg.arguments == {"a": 1}

    def test_metadata_and_thread_id_accepted(self) -> None:
        """before_tool_callback must accept optional metadata and thread_id."""
        integration = self._make(_allow_verdict())
        result = integration.before_tool_callback(
            "tool_x",
            {"k": "v"},
            metadata={"agent": "test-agent"},
            thread_id="thread-99",
        )
        assert result == {"k": "v"}


# ---------------------------------------------------------------------------
# 6. FreeTierADKIntegration._apply_verdict
# ---------------------------------------------------------------------------


class TestFreeTierADKIntegrationApplyVerdict:
    def _integration(self) -> FreeTierADKIntegration:
        resolver = MagicMock()
        return FreeTierADKIntegration(sync_resolver=resolver)

    def _ctx(self, arguments: dict | None = None) -> ToolCallContext:
        return ToolCallContext(tool_name="tool", arguments=arguments or {"x": 1})

    # -------------------------------------------------------------------

    def test_allow_returns_context_arguments(self) -> None:
        integration = self._integration()
        ctx = self._ctx({"x": 1})
        result = integration._apply_verdict(ctx, _allow_verdict())
        assert result == ctx.arguments

    def test_block_raises_permission_error(self) -> None:
        integration = self._integration()
        ctx = self._ctx()
        with pytest.raises(PermissionError, match="BLOCK"):
            integration._apply_verdict(ctx, _block_verdict("blocked reason"))

    def test_block_error_contains_reasoning(self) -> None:
        integration = self._integration()
        ctx = self._ctx()
        with pytest.raises(PermissionError, match="my specific reasoning"):
            integration._apply_verdict(ctx, _block_verdict("my specific reasoning"))

    def test_quarantine_returns_mock_dict(self) -> None:
        integration = self._integration()
        ctx = self._ctx()
        result = integration._apply_verdict(ctx, _quarantine_verdict())
        assert isinstance(result, dict)
        assert result["status"] == "quarantined"
        assert "message" in result

    def test_unknown_decision_raises_value_error(self) -> None:
        integration = self._integration()
        ctx = self._ctx()

        bad_verdict = MagicMock(spec=Verdict)
        bad_verdict.decision = "INVALID_DECISION"
        bad_verdict.reasoning = "???"

        with pytest.raises(ValueError, match="Unknown verdict"):
            integration._apply_verdict(ctx, bad_verdict)


# ---------------------------------------------------------------------------
# 7. ADKIntegration.before_tool_callback — full flow
# ---------------------------------------------------------------------------


class TestADKIntegrationBeforeToolCallbackFullFlow:
    """
    Full integration flow for ADKIntegration.before_tool_callback.

    Strategy: replace queue.enqueue with an AsyncMock that immediately
    fires the resume_callback so the thread.Event is set before event.wait()
    is called — no real blocking occurs.
    """

    def _make_integration_with_mock_enqueue(
        self, verdict: Verdict
    ) -> tuple[ADKIntegration, MagicMock]:
        """
        Return (integration, mock_queue) where mock_queue.enqueue immediately
        invokes the resume_callback passed to it with *verdict*.
        """
        mock_queue = MagicMock(spec=InterceptionQueue)

        async def fake_enqueue(token, context, resume_callback):
            resume_callback(verdict)

        mock_queue.enqueue = AsyncMock(side_effect=fake_enqueue)

        loop = asyncio.new_event_loop()
        integration = ADKIntegration(queue=mock_queue, loop=loop)
        return integration, mock_queue

    # -------------------------------------------------------------------

    def test_allow_full_flow_returns_arguments(self) -> None:
        """Full path: enqueue fires callback → ALLOW → arguments returned."""
        integration, _ = self._make_integration_with_mock_enqueue(_allow_verdict())
        arguments = {"cmd": "ls /tmp"}
        result = integration.before_tool_callback("execute_terminal", arguments)
        assert result == arguments

    def test_block_full_flow_raises_permission_error(self) -> None:
        """Full path: enqueue fires callback → BLOCK → PermissionError raised."""
        integration, _ = self._make_integration_with_mock_enqueue(_block_verdict("blocked"))
        with pytest.raises(PermissionError, match="BLOCK"):
            integration.before_tool_callback("dangerous_tool", {"a": 1})

    def test_quarantine_full_flow_returns_mock_response(self) -> None:
        """Full path: enqueue fires callback → QUARANTINE → mock response."""
        integration, _ = self._make_integration_with_mock_enqueue(_quarantine_verdict())
        result = integration.before_tool_callback("execute_bash", {"cmd": "curl ..."})
        assert isinstance(result, dict)
        # execute_bash is in the terminal category
        assert "stdout" in result
        assert result["exit_code"] == 0

    def test_enqueue_is_called_exactly_once(self) -> None:
        """queue.enqueue must be invoked exactly once per before_tool_callback call."""
        integration, mock_queue = self._make_integration_with_mock_enqueue(_allow_verdict())
        integration.before_tool_callback("my_tool", {"p": 1})
        mock_queue.enqueue.assert_called_once()

    def test_enqueue_receives_correct_context(self) -> None:
        """The ToolCallContext passed to enqueue must match the arguments."""
        integration, mock_queue = self._make_integration_with_mock_enqueue(_allow_verdict())
        integration.before_tool_callback("target_tool", {"x": 99}, metadata={"m": "v"})

        _, context_arg, _ = mock_queue.enqueue.call_args[0]
        assert isinstance(context_arg, ToolCallContext)
        assert context_arg.tool_name == "target_tool"
        assert context_arg.arguments == {"x": 99}

    def test_callback_token_thread_id_defaults_correctly(self) -> None:
        """When thread_id is omitted, it defaults to 'thread-<ident>'."""
        integration, mock_queue = self._make_integration_with_mock_enqueue(_allow_verdict())
        integration.before_tool_callback("some_tool", {})

        token_arg, _, _ = mock_queue.enqueue.call_args[0]
        assert isinstance(token_arg, CallbackToken)
        assert token_arg.thread_id.startswith("thread-")

    def test_explicit_thread_id_is_used(self) -> None:
        """When thread_id is supplied it must appear on the CallbackToken."""
        integration, mock_queue = self._make_integration_with_mock_enqueue(_allow_verdict())
        integration.before_tool_callback("some_tool", {}, thread_id="custom-thread-42")

        token_arg, _, _ = mock_queue.enqueue.call_args[0]
        assert token_arg.thread_id == "custom-thread-42"

    def test_quarantine_write_file_full_flow(self) -> None:
        """Full QUARANTINE flow for a file-write tool returns the file-write mock."""
        integration, _ = self._make_integration_with_mock_enqueue(_quarantine_verdict())
        result = integration.before_tool_callback(
            "write_file", {"path": "/tmp/out.txt", "content": "data"}
        )
        assert isinstance(result, dict)
        assert result["success"] is True
        assert result["path"] == "/tmp/out.txt"

    def test_quarantine_socket_full_flow(self) -> None:
        """Full QUARANTINE flow for a socket tool returns the failure mock."""
        integration, _ = self._make_integration_with_mock_enqueue(_quarantine_verdict())
        result = integration.before_tool_callback("socket_connect", {"host": "evil.com"})
        assert isinstance(result, dict)
        assert result["success"] is False

    def test_quarantine_unknown_tool_full_flow(self) -> None:
        """Full QUARANTINE flow for an unknown tool returns the generic mock."""
        integration, _ = self._make_integration_with_mock_enqueue(_quarantine_verdict())
        result = integration.before_tool_callback("totally_unknown_tool", {})
        assert isinstance(result, dict)
        assert result["status"] == "quarantined"
