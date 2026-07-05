import asyncio
import hashlib
import json
import logging
import multiprocessing
import queue
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Pattern, Tuple

from pydantic import BaseModel

from blackwall.models import ToolCallContext

logger = logging.getLogger(__name__)


class RedactionEntry(BaseModel):
    timestamp: datetime
    original_hash: str
    pattern_matched: str
    placeholder_used: str
    context_size: int


class RegexPattern:
    def __init__(self, name: str, regex: str, placeholder: str) -> None:
        self.name = name
        self.regex: Pattern[str] = re.compile(regex)
        self.placeholder = placeholder
        self.consecutive_timeouts = 0
        self.enabled = True


def _apply_pattern_worker(task_queue: Any, result_queue: Any) -> None:
    result_queue.put("READY")
    while True:
        try:
            task = task_queue.get()
            if task is None:
                break
            regex_str: str
            placeholder: str
            name: str
            text: str
            regex_str, placeholder, name, text = task
            pattern = re.compile(regex_str)
            redactions = []

            def replacer(match: re.Match[str]) -> str:
                matched_str = match.group(0)
                original_hash = hashlib.sha256(matched_str.encode()).hexdigest()
                redactions.append(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "original_hash": original_hash,
                        "pattern_matched": name,
                        "placeholder_used": placeholder,
                        "context_size": len(text),
                    }
                )
                return placeholder

            result_text = pattern.sub(replacer, text)
            result_queue.put(("OK", result_text, redactions))
        except Exception as e:
            result_queue.put(("ERROR", str(e), []))


class KillableRegexWorker:
    def __init__(self) -> None:
        self.ctx = multiprocessing.get_context("spawn")
        self.task_queue = self.ctx.Queue()
        self.result_queue = self.ctx.Queue()
        self._start_process()

    def _start_process(self) -> None:
        self.process = self.ctx.Process(
            target=_apply_pattern_worker, args=(self.task_queue, self.result_queue)
        )
        self.process.daemon = True
        self.process.start()

        try:
            msg = self.result_queue.get(timeout=5.0)
            if msg != "READY":
                raise RuntimeError("Unexpected startup message")
        except queue.Empty:
            raise RuntimeError("Regex worker failed to start")

    def apply(
        self, regex_str: str, placeholder: str, name: str, text: str, timeout: float
    ) -> Tuple[str, List[Dict[str, Any]]]:
        while not self.result_queue.empty():
            try:
                self.result_queue.get_nowait()
            except queue.Empty:
                break

        self.task_queue.put((regex_str, placeholder, name, text))

        try:
            status, res, redactions = self.result_queue.get(timeout=timeout)
            if status == "ERROR":
                raise RuntimeError(res)
            return res, redactions
        except queue.Empty:
            self._terminate_process()

            self.task_queue = self.ctx.Queue()
            self.result_queue = self.ctx.Queue()
            self._start_process()

            raise TimeoutError(f"Regex {name} timed out")

    def _terminate_process(self) -> None:
        try:
            self.process.terminate()
            self.process.join(timeout=1.0)
            if self.process.is_alive():
                logger.warning(
                    "Regex worker process did not terminate within timeout. Killing forcefully."
                )
                self.process.kill()
                self.process.join(timeout=1.0)
        except Exception as e:
            logger.error("Error during regex worker process termination: %s", e)

    def close(self) -> None:
        self._terminate_process()


class ContextHygiene:
    def __init__(self) -> None:
        self.patterns: List[RegexPattern] = []
        self.timeout_seconds = 0.1
        self.worker = KillableRegexWorker()
        self._lock = asyncio.Lock()
        self._initialize_default_patterns()

    def __del__(self) -> None:
        try:
            self.worker.close()
        except Exception:
            pass

    def _initialize_default_patterns(self) -> None:
        self.register_pattern(
            "API_KEY",
            r"(?i)(api[_-]?key|apikey|token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})",
            "[[API_KEY]]",
        )
        self.register_pattern(
            "IP_ADDRESS", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[[IP_ADDRESS]]"
        )
        self.register_pattern("URL", r"https?://[^\s\"']+", "[[URL]]")
        self.register_pattern("FILE_PATH", r"(?:/[^/\\\s\"']+)+/?", "[[FILE_PATH]]")
        self.register_pattern(
            "PASSWORD",
            r"(?i)(password|passwd|pwd)[\s:=]+['\"]?([^\s'\"]+)",
            "[[PASSWORD]]",
        )
        self.register_pattern(
            "EMAIL", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[[EMAIL]]"
        )

    def register_pattern(self, name: str, regex: str, placeholder: str) -> bool:
        try:
            self.patterns.append(RegexPattern(name, regex, placeholder))
            return True
        except re.error as e:
            logger.error(f"Failed to register pattern {name}: invalid regex. {e}")
            return False

    async def apply_redaction(self, text: str) -> Tuple[str, List[RedactionEntry]]:
        all_redactions = []
        current_text = text

        for pattern in self.patterns:
            if not pattern.enabled:
                continue

            try:
                # Run the regex using the persistent killable worker
                # We protect the worker call site with an asyncio.Lock to serialize concurrent requests
                async with self._lock:
                    result_text, redactions_dicts = await asyncio.to_thread(
                        self.worker.apply,
                        pattern.regex.pattern,
                        pattern.placeholder,
                        pattern.name,
                        current_text,
                        self.timeout_seconds,
                    )

                current_text = result_text

                # Reconstruct RedactionEntry objects
                redactions = [
                    RedactionEntry(
                        timestamp=datetime.fromisoformat(r["timestamp"]),
                        original_hash=r["original_hash"],
                        pattern_matched=r["pattern_matched"],
                        placeholder_used=r["placeholder_used"],
                        context_size=r["context_size"],
                    )
                    for r in redactions_dicts
                ]

                all_redactions.extend(redactions)
                pattern.consecutive_timeouts = 0  # reset on success
            except TimeoutError:
                pattern.consecutive_timeouts += 1
                logger.warning(
                    f"Regex pattern {pattern.name} timed out after {self.timeout_seconds}s"
                )

                if pattern.consecutive_timeouts >= 10:
                    pattern.enabled = False
                    logger.error(
                        f"Regex pattern {pattern.name} disabled due to 10 consecutive timeouts"
                    )
                continue
            except Exception as e:
                logger.error(f"Error applying pattern {pattern.name}: {e}")
                continue

        return current_text, all_redactions

    async def sanitize(self, context: ToolCallContext) -> ToolCallContext:
        """
        Sanitizes a ToolCallContext by applying regex redacting to arguments,
        preserving the original JSON structure.
        """
        try:
            serialized_args = json.dumps(context.arguments)
        except (TypeError, ValueError):
            serialized_args = str(context.arguments)

        sanitized_args_str, redactions = await self.apply_redaction(serialized_args)

        try:
            sanitized_args = json.loads(sanitized_args_str)
        except json.JSONDecodeError:
            sanitized_args = {"raw_fallback": sanitized_args_str}

        metadata = dict(context.metadata) if context.metadata else {}

        redaction_log = list(metadata.get("redactionLog", []))
        redaction_log.extend([r.model_dump(mode="json") for r in redactions])

        metadata["redactionLog"] = redaction_log
        metadata["redactionCount"] = metadata.get("redactionCount", 0) + len(redactions)

        if "originalHash" not in metadata:
            metadata["originalHash"] = hashlib.sha256(
                serialized_args.encode()
            ).hexdigest()

        return ToolCallContext(
            tool_name=context.tool_name, arguments=sanitized_args, metadata=metadata
        )
