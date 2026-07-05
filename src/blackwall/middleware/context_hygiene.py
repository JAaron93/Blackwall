import asyncio
import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import List, Pattern, Tuple

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


class ContextHygiene:
    def __init__(self) -> None:
        self.patterns: List[RegexPattern] = []
        self.timeout_seconds = 0.1
        self._initialize_default_patterns()

    def _initialize_default_patterns(self) -> None:
        self.register_pattern("API_KEY", r"(?i)(api[_-]?key|apikey|token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})", "[[API_KEY]]")
        self.register_pattern("IP_ADDRESS", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[[IP_ADDRESS]]")
        self.register_pattern("URL", r"https?://[^\s\"']+", "[[URL]]")
        self.register_pattern("FILE_PATH", r"(?:/[^/\s\"']+)+/?", "[[FILE_PATH]]")
        self.register_pattern("PASSWORD", r"(?i)(password|passwd|pwd)[\s:=]+['\"]?([^\s'\"]+)", "[[PASSWORD]]")
        self.register_pattern("EMAIL", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[[EMAIL]]")

    def register_pattern(self, name: str, regex: str, placeholder: str) -> bool:
        try:
            self.patterns.append(RegexPattern(name, regex, placeholder))
            return True
        except re.error as e:
            logger.error(f"Failed to register pattern {name}: invalid regex. {e}")
            return False

    def _apply_pattern_sync(self, pattern: RegexPattern, text: str) -> Tuple[str, List[RedactionEntry]]:
        redactions: List[RedactionEntry] = []
        
        def replacer(match: re.Match[str]) -> str:
            matched_str = match.group(0)
            original_hash = hashlib.sha256(matched_str.encode()).hexdigest()
            redactions.append(
                RedactionEntry(
                    timestamp=datetime.now(timezone.utc),
                    original_hash=original_hash,
                    pattern_matched=pattern.name,
                    placeholder_used=pattern.placeholder,
                    context_size=len(text)
                )
            )
            return pattern.placeholder

        result_text = pattern.regex.sub(replacer, text)
        return result_text, redactions

    async def apply_redaction(self, text: str) -> Tuple[str, List[RedactionEntry]]:
        all_redactions = []
        current_text = text

        for pattern in self.patterns:
            if not pattern.enabled:
                continue
            
            try:
                # Run the regex in a background thread to allow timeout interruption from the async loop
                result_text, redactions = await asyncio.wait_for(
                    asyncio.to_thread(self._apply_pattern_sync, pattern, current_text),
                    timeout=self.timeout_seconds
                )
                current_text = result_text
                all_redactions.extend(redactions)
                pattern.consecutive_timeouts = 0  # reset on success
            except asyncio.TimeoutError:
                pattern.consecutive_timeouts += 1
                logger.warning(f"Regex pattern {pattern.name} timed out after {self.timeout_seconds}s")
                
                if pattern.consecutive_timeouts >= 10:
                    pattern.enabled = False
                    logger.error(f"Regex pattern {pattern.name} disabled due to 10 consecutive timeouts")
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
            # Fallback if structure was broken, though regexes shouldn't break JSON 
            sanitized_args = {"raw_fallback": sanitized_args_str}

        metadata = dict(context.metadata) if context.metadata else {}
        
        redaction_log = metadata.get("redactionLog", [])
        redaction_log.extend([r.model_dump(mode='json') for r in redactions])
        
        metadata["redactionLog"] = redaction_log
        metadata["redactionCount"] = metadata.get("redactionCount", 0) + len(redactions)
        
        if "originalHash" not in metadata:
            metadata["originalHash"] = hashlib.sha256(serialized_args.encode()).hexdigest()

        return ToolCallContext(
            tool_name=context.tool_name,
            arguments=sanitized_args,
            metadata=metadata
        )
