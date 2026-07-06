import asyncio
import structlog
import threading
from typing import Any, Callable, Dict, Optional
from uuid import uuid4

from blackwall.models import CallbackToken, ToolCallContext, Verdict, VerdictDecision
from blackwall.interception import InterceptionQueue

logger = structlog.get_logger("blackwall.adk_integration")


class ADKIntegration:
    """
    ADK Callback Integration Layer that handles tool call interception,
    thread suspension, and resume logic.
    """

    def __init__(
        self,
        queue: InterceptionQueue,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self.queue = queue
        if loop is None:
            raise ValueError("Event loop must be explicitly provided to ADKIntegration")
        self.loop = loop

    def before_tool_callback(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
        thread_id: Optional[str] = None,
    ) -> Any:
        """
        Synchronous hook called before tool execution.
        Suspends the thread using a threading.Event and waits for the verdict.
        """
        context = ToolCallContext(
            tool_name=tool_name,
            arguments=arguments,
            metadata=metadata,
        )

        event = threading.Event()
        verdict_container: Dict[str, Optional[Verdict]] = {"verdict": None}

        # Define the resume callback function that the queue will invoke
        def resume_callback(verdict: Verdict) -> None:
            verdict_container["verdict"] = verdict
            event.set()

        t_id = thread_id or f"thread-{threading.get_ident()}"
        token = CallbackToken(
            thread_id=t_id,
            tool_context=context,
        )

        logger.info(
            "before_tool_callback: Intercepted tool call, suspending execution thread",
            tool_name=tool_name,
            thread_id=t_id,
            token_id=str(token.token_id),
        )

        async def enqueue_coro():
            await self.queue.enqueue(token, context, resume_callback)

        # Enqueue the token asynchronously.
        if self.loop.is_running():
            # Check if we're on the same thread as the loop to avoid deadlock
            try:
                running_loop = asyncio.get_running_loop()
                if running_loop is self.loop:
                    raise RuntimeError(
                        "Cannot call before_tool_callback from the event loop thread; "
                        "it would deadlock waiting for itself"
                    )
            except RuntimeError:
                # No running loop in current thread, safe to proceed
                pass
            future = asyncio.run_coroutine_threadsafe(enqueue_coro(), self.loop)
            # Wait for enqueuing to finish with a timeout
            future.result(timeout=5.0)
        else:
            # If loop is not running (e.g. in synchronous tests), run it to completion
            self.loop.run_until_complete(enqueue_coro())

        # Wait (suspend thread) until resume_callback sets the event
        # Use a bounded timeout to prevent indefinite hangs
        if not event.wait(timeout=10.0):
            raise PermissionError(
                "Verdict timeout: no response from policy evaluation within 10 seconds (fail closed)"
            )

        # Apply verdict to ADK
        verdict = verdict_container["verdict"]
        if not verdict:
            raise PermissionError("No verdict received from policy evaluation")

        return self.resumeCallback(token, verdict, arguments)

    def resumeCallback(
        self,
        token: CallbackToken,
        verdict: Verdict,
        arguments: Dict[str, Any],
    ) -> Any:
        """
        Applies the verdict to the tool call.
        - ALLOW: proceed with tool execution normally (return arguments or True/None, or proceed)
        - BLOCK: return PermissionError
        - QUARANTINE: execute in sandboxed mock environment, return sanitized response
        """
        correlation_id = token.correlation_id or "N/A"
        logger.info(
            "resumeCallback: Resolving tool callback",
            token_id=str(token.token_id),
            correlation_id=correlation_id,
            decision=verdict.decision,
            reasoning=verdict.reasoning,
        )

        if verdict.decision == VerdictDecision.ALLOW:
            # ALLOW verdict: proceed with tool execution normally
            return arguments

        elif verdict.decision == VerdictDecision.BLOCK:
            # BLOCK verdict: return PermissionError to agent
            raise PermissionError(
                f"Operation blocked by Blackwall Agentic Firewall: [BLOCK] {verdict.reasoning}"
            )

        elif verdict.decision == VerdictDecision.QUARANTINE:
            # QUARANTINE verdict: execute in sandboxed mock environment, return sanitized response
            return self._execute_quarantined(token.tool_context)

        else:
            raise ValueError(f"Unknown verdict decision: {verdict.decision}")

    def _execute_quarantined(self, context: ToolCallContext) -> Any:
        """Runs the tool in a safe mock sandbox environment."""
        tool_name = context.tool_name
        args = context.arguments or {}
        logger.warning(
            "Executing tool in quarantine sandbox",
            tool_name=tool_name,
            arguments=args,
        )
        if tool_name in ("execute_terminal", "execute_bash", "run_command"):
            # Return a mock terminal execution response
            return {
                "stdout": "Command completed successfully (quarantined/mocked).",
                "stderr": "",
                "exit_code": 0,
            }
        elif tool_name in ("write_file", "file_write", "save_file"):
            # Return a mock file write result
            content_str = str(args.get("content", ""))
            return {
                "success": True,
                "bytes_written": len(content_str),
                "path": args.get("path", "quarantined_file"),
            }
        elif tool_name in ("socket_connect", "connect"):
            return {
                "success": False,
                "error": "Connection timed out (quarantined)",
            }
        else:
            # General safe mock response
            return {
                "status": "quarantined",
                "message": "Tool executed in sandboxed mock environment.",
            }


class FreeTierADKIntegration:
    """
    Free-tier ADK integration. before_tool_callback directly calls
    SyncResolver.evaluate() and blocks synchronously
    (no InterceptionQueue, no batch accumulation).
    """

    def __init__(
        self,
        sync_resolver: Any,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self.sync_resolver = sync_resolver
        try:
            self.loop = loop or asyncio.get_event_loop()
        except RuntimeError:
            self.loop = asyncio.new_event_loop()

    def before_tool_callback(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
        thread_id: Optional[str] = None,
    ) -> Any:
        """
        Synchronous: evaluates inline, returns verdict immediately.
        """
        context = ToolCallContext(
            tool_name=tool_name,
            arguments=arguments,
            metadata=metadata,
        )

        if self.loop.is_running():
            import concurrent.futures

            future = asyncio.run_coroutine_threadsafe(
                self.sync_resolver.evaluate(context), self.loop
            )
            verdict = future.result(timeout=30.0)
        else:
            verdict = self.loop.run_until_complete(
                self.sync_resolver.evaluate(context)
            )

        return self._apply_verdict(context, verdict)

    def _apply_verdict(
        self,
        context: ToolCallContext,
        verdict: Verdict,
    ) -> Any:
        """Apply verdict identically to paid-tier resumeCallback."""
        if verdict.decision == VerdictDecision.ALLOW:
            return context.arguments
        elif verdict.decision == VerdictDecision.BLOCK:
            raise PermissionError(
                f"Operation blocked by Blackwall: [BLOCK] {verdict.reasoning}"
            )
        elif verdict.decision == VerdictDecision.QUARANTINE:
            return {
                "status": "quarantined",
                "message": "Tool executed in sandboxed mock environment.",
            }
        else:
            raise ValueError(f"Unknown verdict: {verdict.decision}")
