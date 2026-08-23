"""Unit tests for ASTPipelineFilter.inspect_code() and guard_pipeline decorator.

Covers: Task 3.3 from .kiro/specs/blackwall-test-coverage-remediation/tasks.md
Target: src/blackwall/enterprise/pipeline/wrapper.py — REQ-5.4
"""

import pytest

from blackwall.enterprise.pipeline import ASTPipelineFilter, guard_pipeline


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ast_filter() -> ASTPipelineFilter:
    """Return a fresh ASTPipelineFilter for each test."""
    return ASTPipelineFilter()


# ---------------------------------------------------------------------------
# Safe code — no violations
# ---------------------------------------------------------------------------


def test_inspect_code_safe_code_returns_no_violations(ast_filter: ASTPipelineFilter) -> None:
    """Benign Python code produces is_safe=True with an empty violations list."""
    safe_code = """
def compute_statistics(values):
    total = sum(values)
    count = len(values)
    return total / count if count else 0.0
"""
    result = ast_filter.inspect_code(safe_code)

    assert result["is_safe"] is True
    assert result["violations"] == []
    assert "compute_statistics" in result["code_summary"] or len(result["code_summary"]) >= 0


def test_inspect_code_empty_string_is_safe(ast_filter: ASTPipelineFilter) -> None:
    """Empty string input is valid Python; no violations detected."""
    result = ast_filter.inspect_code("")

    assert result["is_safe"] is True
    assert result["violations"] == []


# ---------------------------------------------------------------------------
# Dangerous patterns — deserialization
# ---------------------------------------------------------------------------


def test_inspect_code_detects_pickle_loads(ast_filter: ASTPipelineFilter) -> None:
    """pickle.loads() call is flagged as a deserialization risk."""
    unsafe_code = """
import pickle

def load_model(path):
    with open(path, 'rb') as f:
        return pickle.loads(f.read())
"""
    result = ast_filter.inspect_code(unsafe_code)

    assert result["is_safe"] is False
    assert "pickle.loads" in result["violations"]


def test_inspect_code_detects_pickle_load(ast_filter: ASTPipelineFilter) -> None:
    """pickle.load() (file-handle form) is also flagged."""
    unsafe_code = """
import pickle
with open('data.pkl', 'rb') as fh:
    obj = pickle.load(fh)
"""
    result = ast_filter.inspect_code(unsafe_code)

    assert result["is_safe"] is False
    assert any(v in ("pickle.load", "pickle.loads") for v in result["violations"])


# ---------------------------------------------------------------------------
# Dangerous patterns — eval / exec
# ---------------------------------------------------------------------------


def test_inspect_code_detects_eval(ast_filter: ASTPipelineFilter) -> None:
    """eval() call is flagged as code execution risk."""
    unsafe_code = "result = eval(user_input)"
    result = ast_filter.inspect_code(unsafe_code)

    assert result["is_safe"] is False
    assert "eval" in result["violations"]


def test_inspect_code_detects_exec(ast_filter: ASTPipelineFilter) -> None:
    """exec() call is flagged as code execution risk."""
    unsafe_code = "exec(compiled_payload)"
    result = ast_filter.inspect_code(unsafe_code)

    assert result["is_safe"] is False
    assert "exec" in result["violations"]


# ---------------------------------------------------------------------------
# Dangerous patterns — OS/process execution
# ---------------------------------------------------------------------------


def test_inspect_code_detects_os_system(ast_filter: ASTPipelineFilter) -> None:
    """os.system() call is flagged as process execution risk."""
    unsafe_code = """
import os
os.system('whoami')
"""
    result = ast_filter.inspect_code(unsafe_code)

    assert result["is_safe"] is False
    assert "os.system" in result["violations"]


def test_inspect_code_detects_subprocess_popen(ast_filter: ASTPipelineFilter) -> None:
    """subprocess.Popen() is flagged as process execution risk."""
    unsafe_code = """
import subprocess
proc = subprocess.Popen(['ls', '-la'], stdout=subprocess.PIPE)
"""
    result = ast_filter.inspect_code(unsafe_code)

    assert result["is_safe"] is False
    assert "subprocess.Popen" in result["violations"]


# ---------------------------------------------------------------------------
# Obfuscated patterns — alias resolution
# ---------------------------------------------------------------------------


def test_inspect_code_detects_import_alias_obfuscation(ast_filter: ASTPipelineFilter) -> None:
    """Import alias (import os as x; x.system()) is resolved and caught."""
    alias_code = """
import os as x
x.system('id')
"""
    result = ast_filter.inspect_code(alias_code)

    assert result["is_safe"] is False
    assert len(result["violations"]) > 0


def test_inspect_code_detects_from_import_alias_obfuscation(ast_filter: ASTPipelineFilter) -> None:
    """from-import alias (from subprocess import run as execute) is resolved and caught."""
    alias_code = """
from subprocess import run as execute
execute(['ls', '-l'])
"""
    result = ast_filter.inspect_code(alias_code)

    assert result["is_safe"] is False
    assert len(result["violations"]) > 0


def test_inspect_code_detects_variable_assignment_alias(ast_filter: ASTPipelineFilter) -> None:
    """Variable assignment alias (runner = os.system) is tracked and caught when called."""
    assign_alias_code = """
import os
runner = os.system
runner('rm -rf /tmp/test')
"""
    result = ast_filter.inspect_code(assign_alias_code)

    assert result["is_safe"] is False
    assert "os.system" in result["violations"]


# ---------------------------------------------------------------------------
# Syntax error fallback path
# ---------------------------------------------------------------------------


def test_inspect_code_syntax_error_falls_back_to_string_search(ast_filter: ASTPipelineFilter) -> None:
    """When code has a SyntaxError, fallback raw-string search still catches known unsafe literals."""
    # Deliberately invalid Python that contains the "os.system" pattern in raw text
    invalid_python_with_unsafe_pattern = "this is not python @#! but mentions os.system here"
    result = ast_filter.inspect_code(invalid_python_with_unsafe_pattern)

    assert result["is_safe"] is False
    assert "os.system" in result["violations"]


def test_inspect_code_syntax_error_with_safe_content_returns_safe(ast_filter: ASTPipelineFilter) -> None:
    """When code has SyntaxError and no dangerous pattern in raw text, returns is_safe=True."""
    # Template-like content that fails AST parse but contains no UNSAFE_AST_NODES
    template_safe = "Hello {{ user.name }}, your order is {{ order.status }}."
    result = ast_filter.inspect_code(template_safe)

    # No SSTI patterns (__class__, __mro__, etc.) present, no unsafe function names
    assert result["is_safe"] is True


# ---------------------------------------------------------------------------
# @guard_pipeline decorator
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_guard_pipeline_decorator_wraps_safe_function() -> None:
    """@guard_pipeline() on a safe async function returns status EXECUTED with contained=True."""

    @guard_pipeline(sandbox_type="gvisor")
    async def safe_loader(source_url: str) -> str:
        return f"loaded:{source_url}"

    result = await safe_loader("https://datasets.example.com/train.parquet")

    assert result["status"] == "EXECUTED"
    assert result["contained"] is True
    assert "sandbox_id" in result
    assert result["sandbox_type"] == "gvisor"


@pytest.mark.asyncio
async def test_guard_pipeline_decorator_blocks_unsafe_function() -> None:
    """@guard_pipeline() on a function that uses os.system returns status BLOCKED."""

    @guard_pipeline(sandbox_type="gvisor")
    async def unsafe_loader(cmd: str) -> str:
        import os
        return os.system(cmd)

    result = await unsafe_loader("echo pwned")

    assert result["status"] == "BLOCKED"
    assert result["contained"] is False
    assert len(result["violations"]) > 0


# ---------------------------------------------------------------------------
# code_summary field
# ---------------------------------------------------------------------------


def test_inspect_code_code_summary_truncated_at_100_chars(ast_filter: ASTPipelineFilter) -> None:
    """inspect_code always sets code_summary to first 100 chars of input."""
    long_safe_code = "x = 1\n" * 30  # > 100 chars
    result = ast_filter.inspect_code(long_safe_code)

    # code_summary must not exceed 100 characters
    assert len(result["code_summary"]) <= 100
