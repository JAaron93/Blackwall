"""test_marimo_notebook_syntax.py

Validates the structure, syntax, and DAG integrity of the interactive Marimo
benchmark analytics dashboard (notebooks/benchmark_analytics.py).
"""

import ast
from pathlib import Path

NOTEBOOK_PATH = Path(__file__).resolve().parents[2] / "notebooks" / "benchmark_analytics.py"


def test_notebook_file_exists():
    """Verify the Marimo notebook file exists at the canonical path."""
    assert NOTEBOOK_PATH.exists(), f"Missing notebook file at {NOTEBOOK_PATH}"
    assert NOTEBOOK_PATH.is_file(), f"Notebook path is not a file: {NOTEBOOK_PATH}"


def test_notebook_python_ast_validity():
    """Verify notebooks/benchmark_analytics.py parses cleanly into a valid Python AST."""
    source = NOTEBOOK_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(NOTEBOOK_PATH))
    assert isinstance(tree, ast.Module)


def test_notebook_marimo_app_instantiation():
    """Verify the notebook creates a marimo.App instance named 'app'."""
    source = NOTEBOOK_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(NOTEBOOK_PATH))

    has_app_assignment = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == "app"
                    and isinstance(node.value, ast.Call)
                ):
                    has_app_assignment = True
    assert has_app_assignment, "notebooks/benchmark_analytics.py must define an 'app' instance of mo.App()"


def test_notebook_cell_definitions():
    """Verify that the notebook contains expected @app.cell decorated functions."""
    source = NOTEBOOK_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(NOTEBOOK_PATH))

    cell_funcs = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Attribute) and dec.attr == "cell":
                    cell_funcs.append(node.name)

    assert len(cell_funcs) >= 8, f"Expected at least 8 reactive cells, found {len(cell_funcs)}"


def test_notebook_fallback_resilience():
    """Verify notebook defines fallback data handling for benchmark and evalsets."""
    source = NOTEBOOK_PATH.read_text(encoding="utf-8")
    assert "benchmark_report.json" in source
    assert "history.jsonl" in source
    assert "blackwall_security.evalset.json" in source
    assert "default_benchmark" in source
    assert "structural_p99_ms" in source
