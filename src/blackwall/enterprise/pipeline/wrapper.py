"""
Application Pipeline Interception Wrappers & Micro-Sandbox AST Filter.
FR-10: Dataset loaders and template engines execution inside isolated container sandboxes.
FR-11: AST parsing and micro-sandbox containment filters.
FR-18: Interoperability with container-sandbox-mcp (Docker API / gVisor runsc).
"""

import ast
import functools
import inspect
import logging
from typing import Any, Callable, Dict, List, Optional
from blackwall.enterprise.mcp.sandbox_mcp import ContainerSandboxMCPAdapter

logger = logging.getLogger(__name__)

UNSAFE_AST_NODES = {
    "eval",
    "exec",
    "pickle.loads",
    "pickle.load",
    "os.system",
    "os.popen",
    "subprocess.Popen",
    "subprocess.run",
    "subprocess.call",
}

UNSAFE_BARE_FUNCTIONS = {
    "system",
    "Popen",
    "loads",
}

SSTI_INJECTION_PATTERNS = (
    "__class__",
    "__mro__",
    "__subclasses__",
    "__globals__",
    "__import__",
)


class ASTPipelineFilter:
    """AST Parser and security filter analyzing Python code and template patterns."""

    def inspect_code(self, code_str: str) -> Dict[str, Any]:
        """
        Parse code payload using Python AST and inspect for unsafe deserialization,
        process execution, or Server-Side Template Injection (SSTI) patterns.
        Resolves import aliases (e.g. from subprocess import run / import os as x).
        """
        violations: List[str] = []

        # Check for SSTI injection patterns
        if "{{" in code_str or "}}" in code_str:
            if any(pattern in code_str for pattern in SSTI_INJECTION_PATTERNS):
                violations.append("ssti_injection")

        # Parse AST if valid Python code
        try:
            tree = ast.parse(inspect.cleandoc(code_str))
            alias_map: Dict[str, str] = {}

            # First pass: collect import aliases and variable assignment aliases
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias_item in node.names:
                        asname = alias_item.asname or alias_item.name
                        alias_map[asname] = alias_item.name
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias_item in node.names:
                        asname = alias_item.asname or alias_item.name
                        full_qual = f"{module}.{alias_item.name}" if module else alias_item.name
                        alias_map[asname] = full_qual
                elif isinstance(node, ast.Assign):
                    value_name = self._get_func_name(node.value)
                    if value_name:
                        resolved_val = self._resolve_alias(value_name, alias_map)
                        for target in node.targets:
                            target_name = self._get_func_name(target)
                            if target_name:
                                alias_map[target_name] = resolved_val

            # Second pass: check call expressions
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    raw_func_name = self._get_func_name(node.func)
                    resolved_name = self._resolve_alias(raw_func_name, alias_map)

                    if resolved_name in UNSAFE_AST_NODES or raw_func_name in UNSAFE_AST_NODES:
                        violations.append(resolved_name)
                    elif raw_func_name in UNSAFE_BARE_FUNCTIONS and raw_func_name not in alias_map:
                        violations.append(raw_func_name)
        except SyntaxError:
            # Fallback pattern search for raw strings/templates
            for unsafe in UNSAFE_AST_NODES:
                if unsafe in code_str:
                    violations.append(unsafe)

        is_safe = len(violations) == 0
        if not is_safe:
            logger.warning("ASTPipelineFilter detected unsafe violations: %s", violations)

        return {
            "is_safe": is_safe,
            "violations": violations,
            "code_summary": code_str[:100],
        }

    def _resolve_alias(self, func_name: str, alias_map: Dict[str, str]) -> str:
        """Resolve function name against import alias map."""
        if func_name in alias_map:
            return alias_map[func_name]
        parts = func_name.split(".", 1)
        if len(parts) == 2 and parts[0] in alias_map:
            return f"{alias_map[parts[0]]}.{parts[1]}"
        return func_name

    def _get_func_name(self, node: ast.AST) -> str:
        """Extract full function name from AST Name or Attribute node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_func_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return ""


class PipelineSandboxManager:
    """Manager for dispatching untrusted dataset loader routines into container sandboxes."""

    def __init__(
        self,
        sandbox_adapter: Optional[ContainerSandboxMCPAdapter] = None,
        ast_filter: Optional[ASTPipelineFilter] = None,
    ) -> None:
        self.sandbox_adapter: ContainerSandboxMCPAdapter = sandbox_adapter or ContainerSandboxMCPAdapter()
        self.ast_filter: ASTPipelineFilter = ast_filter or ASTPipelineFilter()

    async def execute_guarded(
        self,
        routine_fn: Callable[..., Any],
        *args: Any,
        sandbox_type: str = "gvisor",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Inspect routine via AST filter, build invocation payload with args/kwargs,
        and execute safely inside a container microVM sandbox.
        """
        fn_source = ""
        try:
            fn_source = inspect.getsource(routine_fn)
        except Exception:
            fn_source = str(routine_fn)

        # Pre-execution AST security gate
        inspection = self.ast_filter.inspect_code(fn_source)
        if not inspection["is_safe"]:
            logger.error("Pipeline execution BLOCKED by AST filter: %s", inspection["violations"])
            return {
                "status": "BLOCKED",
                "contained": False,
                "violations": inspection["violations"],
                "code_summary": inspection["code_summary"],
                "message": "Routine blocked due to unsafe AST patterns.",
            }

        if not self.sandbox_adapter.is_connected:
            await self.sandbox_adapter.connect()

        # Construct actual invocation payload with source code and call expression
        fn_name = getattr(routine_fn, "__name__", "routine")
        def _safe_repr(val: Any) -> str:
            if isinstance(val, (int, float, bool, str, bytes, type(None))):
                return repr(val)
            return f"<{type(val).__name__} object at {hex(id(val))}>"

        args_repr = ", ".join(_safe_repr(a) for a in args)
        kwargs_repr = ", ".join(f"{k}={_safe_repr(v)}" for k, v in kwargs.items())
        call_params = ", ".join(filter(None, [args_repr, kwargs_repr]))
        invocation_call = f"{fn_name}({call_params})"
        full_payload = f"{fn_source}\n# Execution Invocation:\n{invocation_call}"

        sandbox_result = await self.sandbox_adapter.run_in_sandbox(
            payload=full_payload,
            sandbox_type=sandbox_type,
        )

        return {
            "status": "EXECUTED",
            "contained": True,
            "sandbox_id": sandbox_result.get("sandbox_id"),
            "sandbox_type": sandbox_type,
            "payload_executed": full_payload,
            "stdout": sandbox_result.get("stdout"),
            "args": args,
            "kwargs": kwargs,
        }


def guard_pipeline(sandbox_type: str = "gvisor") -> Callable[..., Any]:
    """
    Decorator for pipeline functions (dataset loaders, template renderers).
    Enforces AST code inspection and micro-sandbox containment execution.
    """
    manager = PipelineSandboxManager()

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
            return await manager.execute_guarded(fn, *args, sandbox_type=sandbox_type, **kwargs)

        return wrapper

    return decorator
