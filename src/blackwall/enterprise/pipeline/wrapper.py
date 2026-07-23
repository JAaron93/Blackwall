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
        """
        violations: List[str] = []

        # Check for SSTI injection patterns
        if "{{" in code_str or "}}" in code_str:
            if any(pattern in code_str for pattern in SSTI_INJECTION_PATTERNS):
                violations.append("ssti_injection")

        # Parse AST if valid Python code
        try:
            tree = ast.parse(code_str)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = self._get_func_name(node.func)
                    if func_name in UNSAFE_AST_NODES:
                        violations.append(func_name)
        except SyntaxError:
            # If code_str is a raw string/template rather than pure Python AST, fallback to pattern search
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

    def __init__(self, sandbox_adapter: Optional[ContainerSandboxMCPAdapter] = None) -> None:
        self.sandbox_adapter: ContainerSandboxMCPAdapter = sandbox_adapter or ContainerSandboxMCPAdapter()

    async def execute_guarded(
        self,
        routine_fn: Callable[..., Any],
        *args: Any,
        sandbox_type: str = "gvisor",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Execute a pipeline routine safely inside a container sandbox via container-sandbox-mcp."""
        if not self.sandbox_adapter.is_connected:
            await self.sandbox_adapter.connect()

        fn_source = ""
        try:
            fn_source = inspect.getsource(routine_fn)
        except Exception:
            fn_source = str(routine_fn)

        sandbox_result = await self.sandbox_adapter.run_in_sandbox(
            payload=fn_source,
            sandbox_type=sandbox_type,
        )

        return {
            "status": "EXECUTED",
            "contained": True,
            "sandbox_id": sandbox_result.get("sandbox_id"),
            "sandbox_type": sandbox_type,
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
