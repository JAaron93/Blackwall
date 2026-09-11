"""
Unit tests for StructuralGatingEngine._eval_ast

Tests target the AST evaluation core of the structural policy engine.
The engine uses Python's built-in `ast` module to represent conditions;
_eval_ast walks those nodes against a `variables` dict
({"toolName": ..., "environmentRole": ...}).

Coverage targets:
  1.  Simple equality match  → True
  2.  Simple equality non-match  → False (BLOCK-equivalent path)
  3.  AND combinator  (ast.BoolOp / ast.And)  — all must be True
  4.  OR  combinator  (ast.BoolOp / ast.Or)   — any may be True
  5.  NOT combinator  (ast.UnaryOp / ast.Not)
  6.  Nested combinators  (AND inside OR)
  7.  Comparison operators: <, <=, >, >=, !=, `in`, `not in`
  8.  Literal collection nodes: list, tuple, set
  9.  Name variable resolution
 10.  Expression wrapper node (ast.Expression)
 11.  Unsupported unary op → ValueError
 12.  Unsupported BoolOp   → ValueError
 13.  Unsupported node type → ValueError
 14.  Unsupported compare op → ValueError
 15.  Missing variable key  → KeyError (graceful assertion)
 16.  Short-circuit AND (stops at first falsy)
 17.  Short-circuit OR  (stops at first truthy)
 18.  Multi-comparator chained expression  (a < b < c)
 19.  Integration: full evaluate() call using ALLOW rule
 20.  Integration: full evaluate() call using BLOCK rule
"""

from __future__ import annotations

import ast
import os
from typing import Any

import pytest

from blackwall.models import ToolCallContext
from blackwall.policy.engine import StructuralGatingEngine
from blackwall.policy.models import StructuralAction
from tests.unit.policy_yaml_helpers import make_yaml, write_temp_yaml


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _engine() -> StructuralGatingEngine:
    """Return a fresh StructuralGatingEngine instance (no policy loaded)."""
    return StructuralGatingEngine()


def _parse_expr(expr: str) -> ast.AST:
    """Parse an expression string and return the root Expression body node."""
    tree = ast.parse(expr, mode="eval")
    return tree.body  # unwrap Expression wrapper → actual node


def _eval(engine: StructuralGatingEngine, expr: str, variables: dict[str, Any]) -> Any:
    """Convenience: parse *expr* and evaluate it against *variables*."""
    node = _parse_expr(expr)
    return engine._eval_ast(node, variables)


# ---------------------------------------------------------------------------
# Default variables fixture
# ---------------------------------------------------------------------------

SANDBOX_VARS = {"toolName": "read_file", "environmentRole": "sandbox"}
PROD_VARS    = {"toolName": "execute_bash", "environmentRole": "production"}


# ===========================================================================
# 1 & 2 — Simple equality: match (ALLOW path) and non-match (BLOCK path)
# ===========================================================================

class TestSimpleEquality:
    def test_match_returns_true(self) -> None:
        """toolName == 'read_file' with toolName='read_file' → True."""
        engine = _engine()
        result = _eval(engine, "toolName == 'read_file'", SANDBOX_VARS)
        assert result is True

    def test_non_match_returns_false(self) -> None:
        """toolName == 'write_file' with toolName='read_file' → False."""
        engine = _engine()
        result = _eval(engine, "toolName == 'write_file'", SANDBOX_VARS)
        assert result is False

    def test_not_equal_match(self) -> None:
        """toolName != 'execute_bash' with toolName='read_file' → True."""
        engine = _engine()
        result = _eval(engine, "toolName != 'execute_bash'", SANDBOX_VARS)
        assert result is True

    def test_not_equal_non_match(self) -> None:
        """toolName != 'read_file' with toolName='read_file' → False."""
        engine = _engine()
        result = _eval(engine, "toolName != 'read_file'", SANDBOX_VARS)
        assert result is False

    def test_environment_role_match(self) -> None:
        """environmentRole == 'sandbox' with environmentRole='sandbox' → True."""
        engine = _engine()
        result = _eval(engine, "environmentRole == 'sandbox'", SANDBOX_VARS)
        assert result is True

    def test_constant_true(self) -> None:
        """A bare True constant evaluates to True."""
        engine = _engine()
        result = _eval(engine, "True", SANDBOX_VARS)
        assert result is True

    def test_constant_false(self) -> None:
        """A bare False constant evaluates to False."""
        engine = _engine()
        result = _eval(engine, "False", SANDBOX_VARS)
        assert result is False

    def test_string_constant(self) -> None:
        """A string literal constant returns that string."""
        engine = _engine()
        result = _eval(engine, "'hello'", {})
        assert result == "hello"

    def test_integer_constant(self) -> None:
        """An integer constant returns the integer."""
        engine = _engine()
        result = _eval(engine, "42", {})
        assert result == 42


# ===========================================================================
# 3 — AND combinator
# ===========================================================================

class TestAndCombinator:
    def test_and_both_true(self) -> None:
        """AND: both conditions true → True."""
        engine = _engine()
        result = _eval(
            engine,
            "toolName == 'read_file' and environmentRole == 'sandbox'",
            SANDBOX_VARS,
        )
        assert result is True

    def test_and_first_false(self) -> None:
        """AND: first condition false → False (short-circuit)."""
        engine = _engine()
        result = _eval(
            engine,
            "toolName == 'write_file' and environmentRole == 'sandbox'",
            SANDBOX_VARS,
        )
        assert result is False

    def test_and_second_false(self) -> None:
        """AND: second condition false → False."""
        engine = _engine()
        result = _eval(
            engine,
            "toolName == 'read_file' and environmentRole == 'production'",
            SANDBOX_VARS,
        )
        assert result is False

    def test_and_both_false(self) -> None:
        """AND: both conditions false → False."""
        engine = _engine()
        result = _eval(
            engine,
            "toolName == 'write_file' and environmentRole == 'production'",
            SANDBOX_VARS,
        )
        assert result is False

    def test_and_three_conditions_all_true(self) -> None:
        """AND: three conditions all true → True."""
        engine = _engine()
        variables = {"toolName": "read_file", "environmentRole": "sandbox"}
        result = _eval(
            engine,
            "toolName == 'read_file' and environmentRole == 'sandbox' and toolName != 'execute_bash'",
            variables,
        )
        assert result is True

    def test_and_short_circuit_returns_falsy_value(self) -> None:
        """AND short-circuits on first falsy: returns that falsy value, not False."""
        engine = _engine()
        # False and anything → the False from the first comparison
        result = _eval(
            engine,
            "toolName == 'NOMATCH' and toolName == 'read_file'",
            SANDBOX_VARS,
        )
        # Result is falsy (False from the first comparison)
        assert not result


# ===========================================================================
# 4 — OR combinator
# ===========================================================================

class TestOrCombinator:
    def test_or_first_true(self) -> None:
        """OR: first condition true → True."""
        engine = _engine()
        result = _eval(
            engine,
            "toolName == 'read_file' or toolName == 'write_file'",
            SANDBOX_VARS,
        )
        assert result is True

    def test_or_second_true(self) -> None:
        """OR: second condition true (first false) → True."""
        engine = _engine()
        result = _eval(
            engine,
            "toolName == 'execute_bash' or environmentRole == 'sandbox'",
            SANDBOX_VARS,
        )
        assert result is True

    def test_or_both_false(self) -> None:
        """OR: both conditions false → False."""
        engine = _engine()
        result = _eval(
            engine,
            "toolName == 'execute_bash' or environmentRole == 'production'",
            SANDBOX_VARS,
        )
        assert result is False

    def test_or_both_true(self) -> None:
        """OR: both conditions true → truthy (first truthy value)."""
        engine = _engine()
        result = _eval(
            engine,
            "toolName == 'read_file' or environmentRole == 'sandbox'",
            SANDBOX_VARS,
        )
        assert result  # truthy

    def test_or_three_conditions_last_matches(self) -> None:
        """OR: three conditions, only last true → True."""
        engine = _engine()
        result = _eval(
            engine,
            "toolName == 'a' or toolName == 'b' or environmentRole == 'sandbox'",
            SANDBOX_VARS,
        )
        assert result is True


# ===========================================================================
# 5 — NOT combinator
# ===========================================================================

class TestNotCombinator:
    def test_not_false_becomes_true(self) -> None:
        """NOT: negating a False result → True."""
        engine = _engine()
        result = _eval(
            engine,
            "not toolName == 'execute_bash'",
            SANDBOX_VARS,
        )
        assert result is True

    def test_not_true_becomes_false(self) -> None:
        """NOT: negating a True result → False."""
        engine = _engine()
        result = _eval(
            engine,
            "not toolName == 'read_file'",
            SANDBOX_VARS,
        )
        assert result is False

    def test_not_constant_true(self) -> None:
        """NOT True → False."""
        engine = _engine()
        result = _eval(engine, "not True", {})
        assert result is False

    def test_not_constant_false(self) -> None:
        """NOT False → True."""
        engine = _engine()
        result = _eval(engine, "not False", {})
        assert result is True

    def test_double_not(self) -> None:
        """Double NOT cancels out."""
        engine = _engine()
        result = _eval(engine, "not not True", {})
        assert result is True


# ===========================================================================
# 6 — Nested combinators (AND inside OR, OR inside AND)
# ===========================================================================

class TestNestedCombinators:
    def test_and_inside_or_left_branch_matches(self) -> None:
        """(A and B) or C — left branch true → overall True."""
        engine = _engine()
        result = _eval(
            engine,
            "(toolName == 'read_file' and environmentRole == 'sandbox') or toolName == 'execute_bash'",
            SANDBOX_VARS,
        )
        assert result is True

    def test_and_inside_or_right_branch_matches(self) -> None:
        """(A and B) or C — left branch false, right branch true → True."""
        engine = _engine()
        result = _eval(
            engine,
            "(toolName == 'execute_bash' and environmentRole == 'sandbox') or environmentRole == 'sandbox'",
            SANDBOX_VARS,
        )
        assert result is True

    def test_and_inside_or_both_false(self) -> None:
        """(A and B) or C — all false → False."""
        engine = _engine()
        result = _eval(
            engine,
            "(toolName == 'execute_bash' and environmentRole == 'sandbox') or environmentRole == 'production'",
            SANDBOX_VARS,
        )
        assert result is False

    def test_or_inside_and_both_branches_match(self) -> None:
        """(A or B) and (C or D) — both sides true → True."""
        engine = _engine()
        result = _eval(
            engine,
            "(toolName == 'read_file' or toolName == 'write_file') and (environmentRole == 'sandbox' or environmentRole == 'production')",
            SANDBOX_VARS,
        )
        assert result is True

    def test_or_inside_and_one_branch_fails(self) -> None:
        """(A or B) and (C or D) — right side false → False."""
        engine = _engine()
        result = _eval(
            engine,
            "(toolName == 'read_file' or toolName == 'write_file') and (environmentRole == 'production' or environmentRole == 'staging')",
            SANDBOX_VARS,
        )
        assert result is False

    def test_not_of_and_expression(self) -> None:
        """NOT (A and B) — where A and B are both True → False."""
        engine = _engine()
        result = _eval(
            engine,
            "not (toolName == 'read_file' and environmentRole == 'sandbox')",
            SANDBOX_VARS,
        )
        assert result is False

    def test_not_of_or_expression(self) -> None:
        """NOT (A or B) — where A is True → False."""
        engine = _engine()
        result = _eval(
            engine,
            "not (toolName == 'execute_bash' or environmentRole == 'sandbox')",
            SANDBOX_VARS,
        )
        assert result is False

    def test_deeply_nested_three_levels(self) -> None:
        """Three-level nesting: ((A and B) or C) and D."""
        engine = _engine()
        result = _eval(
            engine,
            "((toolName == 'read_file' and environmentRole == 'sandbox') or toolName == 'write_file') and environmentRole != 'production'",
            SANDBOX_VARS,
        )
        assert result is True


# ===========================================================================
# 7 — Comparison operators
# ===========================================================================

class TestComparisonOperators:
    """Tests for all supported comparison operators."""

    def _vars_with_score(self, score: Any) -> dict[str, Any]:
        # toolName and environmentRole are the only allowed variables;
        # we repurpose environmentRole to carry numeric values for test
        # purposes via constant expressions (no Name node).
        return {}

    def test_less_than_true(self) -> None:
        engine = _engine()
        # Use a pure constant comparison — no Name nodes needed.
        node = _parse_expr("1 < 2")
        assert engine._eval_ast(node, {}) is True

    def test_less_than_false(self) -> None:
        engine = _engine()
        node = _parse_expr("2 < 1")
        assert engine._eval_ast(node, {}) is False

    def test_less_than_or_equal_true(self) -> None:
        engine = _engine()
        assert engine._eval_ast(_parse_expr("2 <= 2"), {}) is True

    def test_less_than_or_equal_false(self) -> None:
        engine = _engine()
        assert engine._eval_ast(_parse_expr("3 <= 2"), {}) is False

    def test_greater_than_true(self) -> None:
        engine = _engine()
        assert engine._eval_ast(_parse_expr("5 > 3"), {}) is True

    def test_greater_than_false(self) -> None:
        engine = _engine()
        assert engine._eval_ast(_parse_expr("3 > 5"), {}) is False

    def test_greater_than_or_equal_true(self) -> None:
        engine = _engine()
        assert engine._eval_ast(_parse_expr("5 >= 5"), {}) is True

    def test_greater_than_or_equal_false(self) -> None:
        engine = _engine()
        assert engine._eval_ast(_parse_expr("4 >= 5"), {}) is False

    def test_in_operator_true(self) -> None:
        """toolName in ['read_file', 'write_file'] → True."""
        engine = _engine()
        result = _eval(engine, "toolName in ['read_file', 'write_file']", SANDBOX_VARS)
        assert result is True

    def test_in_operator_false(self) -> None:
        """toolName in ['execute_bash'] → False when toolName='read_file'."""
        engine = _engine()
        result = _eval(engine, "toolName in ['execute_bash']", SANDBOX_VARS)
        assert result is False

    def test_not_in_operator_true(self) -> None:
        """toolName not in ['execute_bash'] → True when toolName='read_file'."""
        engine = _engine()
        result = _eval(engine, "toolName not in ['execute_bash']", SANDBOX_VARS)
        assert result is True

    def test_not_in_operator_false(self) -> None:
        """toolName not in ['read_file'] → False when toolName='read_file'."""
        engine = _engine()
        result = _eval(engine, "toolName not in ['read_file']", SANDBOX_VARS)
        assert result is False

    def test_chained_comparison_all_true(self) -> None:
        """Python chained comparison: 1 < 2 < 3 → True."""
        engine = _engine()
        assert engine._eval_ast(_parse_expr("1 < 2 < 3"), {}) is True

    def test_chained_comparison_fails_in_middle(self) -> None:
        """Python chained comparison: 1 < 3 < 2 → False."""
        engine = _engine()
        assert engine._eval_ast(_parse_expr("1 < 3 < 2"), {}) is False


# ===========================================================================
# 8 — Literal collection nodes
# ===========================================================================

class TestCollectionLiterals:
    def test_list_literal(self) -> None:
        """A list literal node returns a Python list."""
        engine = _engine()
        result = engine._eval_ast(_parse_expr("['a', 'b', 'c']"), {})
        assert result == ["a", "b", "c"]

    def test_tuple_literal(self) -> None:
        """A tuple literal node returns a Python tuple."""
        engine = _engine()
        result = engine._eval_ast(_parse_expr("('x', 'y')"), {})
        assert result == ("x", "y")

    def test_set_literal(self) -> None:
        """A set literal node returns a Python set."""
        engine = _engine()
        result = engine._eval_ast(_parse_expr("{'alpha', 'beta'}"), {})
        assert result == {"alpha", "beta"}

    def test_nested_list_in_compare(self) -> None:
        """toolName in list where list is built from a literal node."""
        engine = _engine()
        result = _eval(
            engine,
            "toolName in ['read_file', 'write_file', 'list_dir']",
            SANDBOX_VARS,
        )
        assert result is True


# ===========================================================================
# 9 — Variable (Name) node resolution
# ===========================================================================

class TestVariableResolution:
    def test_tool_name_variable_resolved(self) -> None:
        """toolName Name node returns the value from variables dict."""
        engine = _engine()
        node = _parse_expr("toolName")
        result = engine._eval_ast(node, {"toolName": "my_tool", "environmentRole": "sandbox"})
        assert result == "my_tool"

    def test_environment_role_variable_resolved(self) -> None:
        """environmentRole Name node returns the value from variables dict."""
        engine = _engine()
        node = _parse_expr("environmentRole")
        result = engine._eval_ast(node, {"toolName": "t", "environmentRole": "production"})
        assert result == "production"


# ===========================================================================
# 10 — ast.Expression wrapper node
# ===========================================================================

class TestExpressionWrapper:
    def test_expression_wrapper_is_unwrapped(self) -> None:
        """_eval_ast handles ast.Expression by delegating to its body."""
        engine = _engine()
        tree = ast.parse("toolName == 'read_file'", mode="eval")
        # tree is an ast.Expression; pass the whole tree in
        result = engine._eval_ast(tree, SANDBOX_VARS)
        assert result is True

    def test_expression_wrapper_non_match(self) -> None:
        """ast.Expression wrapping a non-matching condition → False."""
        engine = _engine()
        tree = ast.parse("toolName == 'execute_bash'", mode="eval")
        result = engine._eval_ast(tree, SANDBOX_VARS)
        assert result is False


# ===========================================================================
# 11 — Unsupported unary op → ValueError
# ===========================================================================

class TestUnsupportedUnaryOp:
    def test_unary_minus_raises(self) -> None:
        """Unary minus (-x) is not supported and must raise ValueError."""
        engine = _engine()
        node = _parse_expr("-1")
        with pytest.raises(ValueError, match="Unsupported unary op"):
            engine._eval_ast(node, {})

    def test_bitwise_not_raises(self) -> None:
        """Bitwise NOT (~x) is not supported and must raise ValueError."""
        engine = _engine()
        node = _parse_expr("~1")
        with pytest.raises(ValueError, match="Unsupported unary op"):
            engine._eval_ast(node, {})

    def test_unary_plus_raises(self) -> None:
        """Unary plus (+x) is not supported and must raise ValueError."""
        engine = _engine()
        node = _parse_expr("+1")
        with pytest.raises(ValueError, match="Unsupported unary op"):
            engine._eval_ast(node, {})


# ===========================================================================
# 12 — Unsupported BoolOp → ValueError
# ===========================================================================

class TestUnsupportedBoolOp:
    def test_custom_boolop_raises(self) -> None:
        """Injecting an unknown BoolOp subclass raises ValueError."""
        engine = _engine()

        class FakeBoolOp(ast.boolop):
            pass

        # Manually build an ast.BoolOp with an unrecognised operator.
        node = ast.BoolOp(
            op=FakeBoolOp(),
            values=[ast.Constant(value=True), ast.Constant(value=False)],
        )
        with pytest.raises(ValueError, match="Unsupported bool op"):
            engine._eval_ast(node, {})


# ===========================================================================
# 13 — Unsupported node type → ValueError
# ===========================================================================

class TestUnsupportedNodeType:
    def test_call_node_raises(self) -> None:
        """ast.Call nodes are not in the allowed set and must raise ValueError."""
        engine = _engine()
        # Build a Call node manually (it won't pass the validator, but _eval_ast
        # should still reject it if somehow presented directly).
        node = ast.Call(
            func=ast.Name(id="len", ctx=ast.Load()),
            args=[ast.Constant(value="hello")],
            keywords=[],
        )
        with pytest.raises(ValueError, match="Unsupported node type"):
            engine._eval_ast(node, {})

    def test_dict_node_raises(self) -> None:
        """ast.Dict is not supported and must raise ValueError."""
        engine = _engine()
        node = ast.Dict(keys=[ast.Constant(value="k")], values=[ast.Constant(value="v")])
        with pytest.raises(ValueError, match="Unsupported node type"):
            engine._eval_ast(node, {})

    def test_lambda_node_raises(self) -> None:
        """ast.Lambda is not supported and must raise ValueError."""
        engine = _engine()
        node = ast.Lambda(
            args=ast.arguments(
                posonlyargs=[], args=[], vararg=None,
                kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]
            ),
            body=ast.Constant(value=True),
        )
        with pytest.raises(ValueError, match="Unsupported node type"):
            engine._eval_ast(node, {})


# ===========================================================================
# 14 — Unsupported compare operator → ValueError
# ===========================================================================

class TestUnsupportedCompareOp:
    def test_custom_compare_op_raises(self) -> None:
        """A Compare node with an unrecognised op raises ValueError."""
        engine = _engine()

        class FakeOp(ast.cmpop):
            pass

        node = ast.Compare(
            left=ast.Constant(value=1),
            ops=[FakeOp()],
            comparators=[ast.Constant(value=2)],
        )
        with pytest.raises(ValueError, match="Unsupported op"):
            engine._eval_ast(node, {})


# ===========================================================================
# 15 — Missing variable key → KeyError
# ===========================================================================

class TestMissingVariableKey:
    def test_missing_tool_name_raises_key_error(self) -> None:
        """Accessing toolName when it is not in variables dict raises KeyError."""
        engine = _engine()
        node = _parse_expr("toolName")
        with pytest.raises(KeyError):
            engine._eval_ast(node, {})

    def test_missing_environment_role_raises_key_error(self) -> None:
        """Accessing environmentRole when absent raises KeyError."""
        engine = _engine()
        node = _parse_expr("environmentRole == 'sandbox'")
        with pytest.raises(KeyError):
            engine._eval_ast(node, {})

    def test_partial_variables_raises_key_error(self) -> None:
        """Only toolName supplied but environmentRole accessed → KeyError."""
        engine = _engine()
        node = _parse_expr("environmentRole == 'sandbox'")
        with pytest.raises(KeyError):
            engine._eval_ast(node, {"toolName": "read_file"})


# ===========================================================================
# 16 — Short-circuit AND (stops at first falsy value)
# ===========================================================================

class TestShortCircuitAnd:
    def test_and_short_circuit_on_first_false(self) -> None:
        """AND stops evaluation at first False; second operand not evaluated."""
        engine = _engine()
        # If short-circuit works, accessing missing 'environmentRole' key
        # in the second operand will NOT be reached, so no KeyError should occur.
        result = _eval(
            engine,
            "toolName == 'NOMATCH' and environmentRole == 'sandbox'",
            {"toolName": "read_file"},  # environmentRole intentionally missing
        )
        # First operand is False → short-circuit → no KeyError, returns falsy
        assert not result

    def test_and_evaluates_second_when_first_true(self) -> None:
        """When first AND operand is True, second IS evaluated."""
        engine = _engine()
        # toolName == 'read_file' is True, then environmentRole is accessed.
        # environmentRole is missing → KeyError confirms second was evaluated.
        with pytest.raises(KeyError):
            _eval(
                engine,
                "toolName == 'read_file' and environmentRole == 'sandbox'",
                {"toolName": "read_file"},  # environmentRole missing
            )


# ===========================================================================
# 17 — Short-circuit OR (stops at first truthy value)
# ===========================================================================

class TestShortCircuitOr:
    def test_or_short_circuit_on_first_true(self) -> None:
        """OR stops evaluation at first True; second operand not evaluated."""
        engine = _engine()
        # First operand is True → short-circuit → environmentRole not accessed.
        result = _eval(
            engine,
            "toolName == 'read_file' or environmentRole == 'sandbox'",
            {"toolName": "read_file"},  # environmentRole intentionally missing
        )
        assert result  # truthy, and no KeyError

    def test_or_evaluates_second_when_first_false(self) -> None:
        """When first OR operand is False, second IS evaluated."""
        engine = _engine()
        # First operand is False → second is reached → KeyError confirms evaluation.
        with pytest.raises(KeyError):
            _eval(
                engine,
                "toolName == 'NOMATCH' or environmentRole == 'sandbox'",
                {"toolName": "read_file"},  # environmentRole missing
            )


# ===========================================================================
# 18 — Multi-comparator chained expression (a < b < c)
# ===========================================================================

class TestChainedComparisons:
    def test_three_way_chain_true(self) -> None:
        """1 < 2 < 3 → True (both sub-comparisons pass)."""
        engine = _engine()
        assert engine._eval_ast(_parse_expr("1 < 2 < 3"), {}) is True

    def test_three_way_chain_false_at_second(self) -> None:
        """1 < 2 > 3 — second comparison (2 > 3) fails → False."""
        engine = _engine()
        assert engine._eval_ast(_parse_expr("1 < 2 > 3"), {}) is False

    def test_four_way_chain_all_equal(self) -> None:
        """1 <= 1 <= 1 <= 1 → True."""
        engine = _engine()
        assert engine._eval_ast(_parse_expr("1 <= 1 <= 1"), {}) is True

    def test_equality_chain(self) -> None:
        """1 == 1 == 1 → True."""
        engine = _engine()
        assert engine._eval_ast(_parse_expr("1 == 1 == 1"), {}) is True

    def test_equality_chain_breaks(self) -> None:
        """1 == 1 == 2 → False because 1 != 2."""
        engine = _engine()
        assert engine._eval_ast(_parse_expr("1 == 1 == 2"), {}) is False


# ===========================================================================
# 19 & 20 — Integration: evaluate() with ALLOW and BLOCK rules
# ===========================================================================

class TestIntegrationEvaluate:
    """End-to-end tests through load_policy → evaluate using _eval_ast internally."""

    def _load_engine_from_rules(self, rules: str) -> tuple[StructuralGatingEngine, str]:
        engine = StructuralGatingEngine()
        yaml_path = write_temp_yaml(make_yaml(rules))
        engine.load_policy(yaml_path)
        return engine, yaml_path

    def test_allow_rule_matched(self) -> None:
        """Full evaluate(): ALLOW rule condition matches → ALLOW decision."""
        rules = """
- ruleId: "allow-read"
  condition: "toolName == 'read_file' and environmentRole == 'sandbox'"
  action: ALLOW
  priority: 1
  enabled: true
"""
        engine, yaml_path = self._load_engine_from_rules(rules)
        try:
            ctx = ToolCallContext(tool_name="read_file", arguments={})
            result = engine.evaluate(ctx, "sandbox")
            assert result.decision == StructuralAction.ALLOW
            assert result.requireSemanticReview is False
            assert result.ruleId == "allow-read"
        finally:
            os.remove(yaml_path)

    def test_block_rule_matched(self) -> None:
        """Full evaluate(): BLOCK rule condition matches → BLOCK decision."""
        rules = """
- ruleId: "block-bash"
  condition: "toolName == 'execute_bash'"
  action: BLOCK
  priority: 1
  enabled: true
"""
        engine, yaml_path = self._load_engine_from_rules(rules)
        try:
            ctx = ToolCallContext(tool_name="execute_bash", arguments={"cmd": "whoami"})
            result = engine.evaluate(ctx, "sandbox")
            assert result.decision == StructuralAction.BLOCK
            assert result.requireSemanticReview is False
            assert result.ruleId == "block-bash"
        finally:
            os.remove(yaml_path)

    def test_escalate_rule_matched(self) -> None:
        """Full evaluate(): ESCALATE_TO_SEMANTIC rule matches → requireSemanticReview True."""
        rules = """
- ruleId: "escalate-write"
  condition: "toolName == 'write_file'"
  action: ESCALATE_TO_SEMANTIC
  priority: 1
  enabled: true
"""
        engine, yaml_path = self._load_engine_from_rules(rules)
        try:
            ctx = ToolCallContext(tool_name="write_file", arguments={"path": "/tmp/out"})
            result = engine.evaluate(ctx, "sandbox")
            assert result.decision == StructuralAction.ESCALATE_TO_SEMANTIC
            assert result.requireSemanticReview is True
        finally:
            os.remove(yaml_path)

    def test_no_rule_matches_defaults_to_escalate(self) -> None:
        """Full evaluate(): unmatched tool name → ESCALATE_TO_SEMANTIC default."""
        rules = """
- ruleId: "allow-read"
  condition: "toolName == 'read_file'"
  action: ALLOW
  priority: 1
  enabled: true
"""
        engine, yaml_path = self._load_engine_from_rules(rules)
        try:
            ctx = ToolCallContext(tool_name="unknown_tool", arguments={})
            result = engine.evaluate(ctx, "sandbox")
            assert result.decision == StructuralAction.ESCALATE_TO_SEMANTIC
            assert result.requireSemanticReview is True
            assert result.ruleId is None
        finally:
            os.remove(yaml_path)

    def test_in_list_allow_rule(self) -> None:
        """Full evaluate(): toolName in list rule → ALLOW when matched."""
        rules = """
- ruleId: "allow-list"
  condition: "toolName in ['read_file', 'list_dir', 'stat_file']"
  action: ALLOW
  priority: 1
  enabled: true
"""
        engine, yaml_path = self._load_engine_from_rules(rules)
        try:
            ctx = ToolCallContext(tool_name="list_dir", arguments={})
            result = engine.evaluate(ctx, "sandbox")
            assert result.decision == StructuralAction.ALLOW
        finally:
            os.remove(yaml_path)

    def test_in_list_block_rule_no_match(self) -> None:
        """Full evaluate(): toolName not in list → falls through to ESCALATE."""
        rules = """
- ruleId: "block-dangerous"
  condition: "toolName in ['execute_bash', 'eval_code']"
  action: BLOCK
  priority: 1
  enabled: true
"""
        engine, yaml_path = self._load_engine_from_rules(rules)
        try:
            ctx = ToolCallContext(tool_name="read_file", arguments={})
            result = engine.evaluate(ctx, "sandbox")
            assert result.decision == StructuralAction.ESCALATE_TO_SEMANTIC
        finally:
            os.remove(yaml_path)

    def test_or_condition_allow_rule(self) -> None:
        """Full evaluate(): OR condition ALLOW rule."""
        rules = """
- ruleId: "allow-read-or-list"
  condition: "toolName == 'read_file' OR toolName == 'list_dir'"
  action: ALLOW
  priority: 1
  enabled: true
"""
        engine, yaml_path = self._load_engine_from_rules(rules)
        try:
            ctx = ToolCallContext(tool_name="list_dir", arguments={})
            result = engine.evaluate(ctx, "sandbox")
            assert result.decision == StructuralAction.ALLOW
            assert result.ruleId == "allow-read-or-list"
        finally:
            os.remove(yaml_path)

    def test_not_condition_block_rule(self) -> None:
        """Full evaluate(): NOT condition BLOCK rule — blocks everything except read_file."""
        rules = """
- ruleId: "block-non-read"
  condition: "not toolName == 'read_file'"
  action: BLOCK
  priority: 1
  enabled: true
"""
        engine, yaml_path = self._load_engine_from_rules(rules)
        try:
            ctx_blocked = ToolCallContext(tool_name="execute_bash", arguments={})
            result_blocked = engine.evaluate(ctx_blocked, "sandbox")
            assert result_blocked.decision == StructuralAction.BLOCK

            ctx_allowed = ToolCallContext(tool_name="read_file", arguments={})
            result_allowed = engine.evaluate(ctx_allowed, "sandbox")
            # NOT (True) == False → rule does NOT match → escalate
            assert result_allowed.decision == StructuralAction.ESCALATE_TO_SEMANTIC
        finally:
            os.remove(yaml_path)

    def test_require_semantic_review_flag_on_allow(self) -> None:
        """Full evaluate(): ALLOW rule with requireSemanticReview: true → flag is True."""
        rules = """
- ruleId: "allow-with-review"
  condition: "toolName == 'write_file'"
  action: ALLOW
  priority: 1
  enabled: true
  requireSemanticReview: true
"""
        engine, yaml_path = self._load_engine_from_rules(rules)
        try:
            ctx = ToolCallContext(tool_name="write_file", arguments={})
            result = engine.evaluate(ctx, "sandbox")
            assert result.decision == StructuralAction.ALLOW
            assert result.requireSemanticReview is True
        finally:
            os.remove(yaml_path)

    def test_no_policy_loaded_defaults_to_escalate(self) -> None:
        """Full evaluate() without load_policy → ESCALATE_TO_SEMANTIC."""
        engine = StructuralGatingEngine()
        ctx = ToolCallContext(tool_name="read_file", arguments={})
        result = engine.evaluate(ctx, "sandbox")
        assert result.decision == StructuralAction.ESCALATE_TO_SEMANTIC
        assert result.requireSemanticReview is True
        assert result.ruleId is None

    def test_unknown_environment_role_defaults_to_escalate(self) -> None:
        """Full evaluate() with unknown role → ESCALATE_TO_SEMANTIC."""
        rules = """
- ruleId: "allow-read"
  condition: "toolName == 'read_file'"
  action: ALLOW
  priority: 1
  enabled: true
"""
        engine, yaml_path = self._load_engine_from_rules(rules)
        try:
            ctx = ToolCallContext(tool_name="read_file", arguments={})
            result = engine.evaluate(ctx, "UNKNOWN_ROLE")
            assert result.decision == StructuralAction.ESCALATE_TO_SEMANTIC
        finally:
            os.remove(yaml_path)
