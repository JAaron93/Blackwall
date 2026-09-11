"""Property-based tests for StructuralGatingEngine._eval_ast and evaluate().

Tests the following properties:
1. evaluate() always returns a StructuralGatingResult (never crashes on valid input)
2. An ALLOW-all policy always allows any context
3. A BLOCK-all policy always blocks any context
4. Double negation: NOT(NOT(rule)) == rule
5. AND with empty conditions list = allow (vacuous truth)
6. OR with empty conditions list = block (vacuous false)
7. Determinism: same policy + same context = same result

Follows Rule 12 (Hypothesis Test Scope Isolation): settings applied per test, NOT at
module scope.

Follows Rule 17 (Hypothesis Property Constraint & Rejection Testing): each property
includes both acceptance and rejection branches where applicable.
"""

from __future__ import annotations

import ast
import os
import tempfile

import pytest
from hypothesis import given, settings, strategies as st

from blackwall.models import ToolCallContext
from blackwall.policy.engine import StructuralGatingEngine, StructuralGatingResult
from blackwall.policy.models import StructuralAction


# ---------------------------------------------------------------------------
# YAML template (minimal valid policy)
# ---------------------------------------------------------------------------

_BASE_YAML_TEMPLATE = """
version: "1.0.0"
global:
  threatThreshold: 0.75
  quarantineThreshold: 0.5
  enableStructuralGating: true
  enableSemanticGating: true
environmentRoles:
  sandbox:
    allowedTools: ["read_file", "write_file"]
    blockedTools: ["execute_bash"]
    requireSemanticReview: false
    maxThreatScore: 0.8
  production:
    allowedTools: ["read_file"]
    blockedTools: ["execute_bash", "write_file"]
    requireSemanticReview: true
    maxThreatScore: 0.5
structuralRules:
{rules}
semanticGuidelines:
  - "Property test guideline"
mcpServers:
  gti:
    enabled: true
    apiKey: "vault://gti"
    cacheEnabled: true
    cacheTTL: 3600
    timeout: 5000
  codebaseMemory:
    enabled: true
    apiKey: "vault://cbm"
    cacheEnabled: true
    cacheTTL: 3600
    timeout: 2000
threatSignatureGraph:
  dbPath: "/tmp/prop-test-tsg.db"
  walMode: true
  maxConnections: 10
  similarityThreshold: 0.85
  ttlSeconds: 3600
  maxSignatures: 1000
  embeddingDimension: 384
"""


def _build_yaml(rules_block: str) -> str:
    """Render the template with an indented rules block."""
    stripped = rules_block.strip()
    if stripped:
        indented = "\n".join("  " + line for line in stripped.split("\n"))
    else:
        indented = "  []"
    return _BASE_YAML_TEMPLATE.format(rules=indented)


def _write_temp_yaml(content: str) -> str:
    """Write content to a temp file and return its path. Caller must delete."""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


def _load_engine(rules_block: str) -> StructuralGatingEngine:
    """Build and load a StructuralGatingEngine from a YAML rules block."""
    engine = StructuralGatingEngine()
    yaml_content = _build_yaml(rules_block)
    path = _write_temp_yaml(yaml_content)
    try:
        engine.load_policy(path)
    finally:
        os.remove(path)
    return engine


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Valid tool names: alphanumeric + underscore, non-empty, no whitespace.
tool_name_st = st.from_regex(r"[a-zA-Z][a-zA-Z0-9_]{0,29}", fullmatch=True)

# Environment roles defined in the base template.
env_role_st = st.sampled_from(["sandbox", "production"])

# Arguments dict: empty is fine; just needs to be JSON-like.
arguments_st = st.fixed_dictionaries({})


@st.composite
def tool_call_context_st(draw):
    """Strategy for valid ToolCallContext instances."""
    return ToolCallContext(
        tool_name=draw(tool_name_st),
        arguments=draw(arguments_st),
        metadata=None,
    )


# ---------------------------------------------------------------------------
# Direct _eval_ast strategies — AST node builders
# ---------------------------------------------------------------------------

@st.composite
def constant_ast_st(draw):
    """Strategy for ast.Constant nodes (True, False, or a string)."""
    value = draw(st.one_of(st.booleans(), tool_name_st))
    return ast.Constant(value=value)


@st.composite
def bool_constant_ast_st(draw):
    """Strategy for boolean ast.Constant nodes only."""
    return ast.Constant(value=draw(st.booleans()))


@st.composite
def not_wrapped_ast_st(draw, inner_st):
    """Wraps an inner AST node with ast.UnaryOp(ast.Not(), ...)."""
    inner = draw(inner_st)
    return ast.UnaryOp(op=ast.Not(), operand=inner)


@st.composite
def and_ast_st(draw, values_st):
    """Strategy for ast.BoolOp(ast.And(), [...values...])."""
    values = draw(values_st)
    return ast.BoolOp(op=ast.And(), values=values)


@st.composite
def or_ast_st(draw, values_st):
    """Strategy for ast.BoolOp(ast.Or(), [...values...])."""
    values = draw(values_st)
    return ast.BoolOp(op=ast.Or(), values=values)


# ---------------------------------------------------------------------------
# Helper: evaluate a raw AST node through _eval_ast
# ---------------------------------------------------------------------------

def _bare_engine() -> StructuralGatingEngine:
    """Return an unloaded engine instance (good enough for _eval_ast calls)."""
    return StructuralGatingEngine()


# ---------------------------------------------------------------------------
# Property 1: evaluate() always returns a StructuralGatingResult on valid input
# ---------------------------------------------------------------------------

_ALLOW_ALL_RULES = """\
- ruleId: "allow-all"
  condition: "toolName == toolName"
  action: ALLOW
  priority: 1
  enabled: true
  requireSemanticReview: false
"""


@settings(max_examples=100)
@given(ctx=tool_call_context_st(), role=env_role_st)
def test_property_evaluate_always_returns_gating_result(ctx, role):
    """Property 1: evaluate() must always return a StructuralGatingResult on valid input."""
    engine = _load_engine(_ALLOW_ALL_RULES)
    result = engine.evaluate(ctx, role)
    assert isinstance(result, StructuralGatingResult)
    assert isinstance(result.decision, StructuralAction)
    assert isinstance(result.requireSemanticReview, bool)


# ---------------------------------------------------------------------------
# Property 2: ALLOW-all policy always allows any context
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(ctx=tool_call_context_st(), role=env_role_st)
def test_property_allow_all_policy_always_allows(ctx, role):
    """Property 2: A policy with a catch-all ALLOW rule must always return ALLOW."""
    engine = _load_engine(_ALLOW_ALL_RULES)
    result = engine.evaluate(ctx, role)
    assert result.decision == StructuralAction.ALLOW, (
        f"Expected ALLOW for tool={ctx.tool_name!r} role={role!r}, "
        f"got {result.decision}"
    )


# ---------------------------------------------------------------------------
# Property 3: BLOCK-all policy always blocks any context
# ---------------------------------------------------------------------------

_BLOCK_ALL_RULES = """\
- ruleId: "block-all"
  condition: "toolName == toolName"
  action: BLOCK
  priority: 1
  enabled: true
  requireSemanticReview: false
"""


@settings(max_examples=100)
@given(ctx=tool_call_context_st(), role=env_role_st)
def test_property_block_all_policy_always_blocks(ctx, role):
    """Property 3: A policy with a catch-all BLOCK rule must always return BLOCK."""
    engine = _load_engine(_BLOCK_ALL_RULES)
    result = engine.evaluate(ctx, role)
    assert result.decision == StructuralAction.BLOCK, (
        f"Expected BLOCK for tool={ctx.tool_name!r} role={role!r}, "
        f"got {result.decision}"
    )


# ---------------------------------------------------------------------------
# Property 4: Double negation — NOT(NOT(x)) == x
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(value=st.booleans())
def test_property_double_negation_bool_constant(value):
    """Property 4: NOT(NOT(constant)) must equal the original constant value."""
    engine = _bare_engine()
    variables: dict = {}

    # Build NOT(NOT(value))
    inner = ast.Constant(value=value)
    single_not = ast.UnaryOp(op=ast.Not(), operand=inner)
    double_not = ast.UnaryOp(op=ast.Not(), operand=single_not)

    original_result = engine._eval_ast(inner, variables)
    double_negated_result = engine._eval_ast(double_not, variables)

    assert double_negated_result == original_result, (
        f"Double negation failed: original={original_result!r}, "
        f"double_negated={double_negated_result!r}"
    )


@settings(max_examples=100)
@given(tool=tool_name_st)
def test_property_double_negation_compare_expression(tool):
    """Property 4: NOT(NOT(toolName == 'x')) must equal toolName == 'x' for any tool."""
    engine = _bare_engine()
    variables = {"toolName": tool, "environmentRole": "sandbox"}

    # Build: toolName == 'fixed_name'
    fixed_name = "read_file"
    compare_node = ast.Compare(
        left=ast.Name(id="toolName", ctx=ast.Load()),
        ops=[ast.Eq()],
        comparators=[ast.Constant(value=fixed_name)],
    )
    single_not = ast.UnaryOp(op=ast.Not(), operand=compare_node)
    double_not = ast.UnaryOp(op=ast.Not(), operand=single_not)

    original = engine._eval_ast(compare_node, variables)
    double_negated = engine._eval_ast(double_not, variables)
    assert double_negated == original


# ---------------------------------------------------------------------------
# Property 5: AND with non-empty list of constants (vacuous-truth check)
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(values=st.lists(st.booleans(), min_size=1, max_size=10))
def test_property_and_semantics_matches_all(values):
    """Property 5: AND(values) must return True iff all values are True."""
    engine = _bare_engine()
    variables: dict = {}

    bool_nodes = [ast.Constant(value=v) for v in values]
    and_node = ast.BoolOp(op=ast.And(), values=bool_nodes)

    result = engine._eval_ast(and_node, variables)
    expected = all(values)
    assert bool(result) == expected, (
        f"AND({values!r}) expected {expected!r}, got {result!r}"
    )


def test_property_and_empty_values_short_circuits_to_true():
    """Property 5 (vacuous truth): AND with empty values list starts from True sentinel.

    CPython's ast.BoolOp(And, []) is syntactically invalid, but _eval_ast
    initialises its accumulator to True and returns it when the list is empty,
    matching Python's `all([]) == True` semantics.
    """
    engine = _bare_engine()
    variables: dict = {}

    # Manually construct the node with an empty values list to test engine internals.
    and_node = ast.BoolOp(op=ast.And(), values=[])
    result = engine._eval_ast(and_node, variables)
    assert result is True, (
        f"AND([]) expected True (vacuous truth), got {result!r}"
    )


# ---------------------------------------------------------------------------
# Property 6: OR with non-empty list of constants (vacuous-false check)
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(values=st.lists(st.booleans(), min_size=1, max_size=10))
def test_property_or_semantics_matches_any(values):
    """Property 6: OR(values) must return True iff at least one value is True."""
    engine = _bare_engine()
    variables: dict = {}

    bool_nodes = [ast.Constant(value=v) for v in values]
    or_node = ast.BoolOp(op=ast.Or(), values=bool_nodes)

    result = engine._eval_ast(or_node, variables)
    expected = any(values)
    assert bool(result) == expected, (
        f"OR({values!r}) expected {expected!r}, got {result!r}"
    )


def test_property_or_empty_values_short_circuits_to_false():
    """Property 6 (vacuous false): OR with empty values list starts from False sentinel.

    _eval_ast initialises its accumulator to False and returns it immediately
    when the values list is empty — matching Python's `any([]) == False` semantics.
    """
    engine = _bare_engine()
    variables: dict = {}

    or_node = ast.BoolOp(op=ast.Or(), values=[])
    result = engine._eval_ast(or_node, variables)
    assert result is False, (
        f"OR([]) expected False (vacuous false), got {result!r}"
    )


# ---------------------------------------------------------------------------
# Property 7: Determinism — same policy + same context = same result
# ---------------------------------------------------------------------------

_MIXED_RULES = """\
- ruleId: "allow-read"
  condition: "toolName == 'read_file'"
  action: ALLOW
  priority: 1
  enabled: true
  requireSemanticReview: false
- ruleId: "block-exec"
  condition: "toolName == 'execute_bash'"
  action: BLOCK
  priority: 2
  enabled: true
  requireSemanticReview: false
- ruleId: "escalate-rest"
  condition: "toolName == toolName"
  action: ESCALATE_TO_SEMANTIC
  priority: 3
  enabled: true
  requireSemanticReview: true
"""


@settings(max_examples=100)
@given(ctx=tool_call_context_st(), role=env_role_st)
def test_property_determinism_same_policy_same_context(ctx, role):
    """Property 7: Evaluating the same context twice on the same engine returns identical results."""
    engine = _load_engine(_MIXED_RULES)

    result_a = engine.evaluate(ctx, role)
    result_b = engine.evaluate(ctx, role)

    assert result_a.decision == result_b.decision, (
        f"Non-deterministic decision: {result_a.decision!r} vs {result_b.decision!r} "
        f"for tool={ctx.tool_name!r} role={role!r}"
    )
    assert result_a.requireSemanticReview == result_b.requireSemanticReview, (
        f"Non-deterministic requireSemanticReview: "
        f"{result_a.requireSemanticReview!r} vs {result_b.requireSemanticReview!r}"
    )
    assert result_a.ruleId == result_b.ruleId, (
        f"Non-deterministic ruleId: {result_a.ruleId!r} vs {result_b.ruleId!r}"
    )


@settings(max_examples=100)
@given(ctx=tool_call_context_st(), role=env_role_st)
def test_property_determinism_fresh_engine_instances(ctx, role):
    """Property 7b: Two independently-loaded engines with the same policy return identical results."""
    engine_a = _load_engine(_MIXED_RULES)
    engine_b = _load_engine(_MIXED_RULES)

    result_a = engine_a.evaluate(ctx, role)
    result_b = engine_b.evaluate(ctx, role)

    assert result_a.decision == result_b.decision, (
        f"Cross-instance non-determinism: {result_a.decision!r} vs {result_b.decision!r} "
        f"for tool={ctx.tool_name!r} role={role!r}"
    )
    assert result_a.requireSemanticReview == result_b.requireSemanticReview
    assert result_a.ruleId == result_b.ruleId


# ---------------------------------------------------------------------------
# Supplementary: _eval_ast direct node type coverage
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(value=st.one_of(st.booleans(), st.integers(), st.text(max_size=20)))
def test_property_eval_ast_constant_round_trip(value):
    """_eval_ast(Constant(x)) must return x unchanged for any constant value."""
    engine = _bare_engine()
    node = ast.Constant(value=value)
    result = engine._eval_ast(node, {})
    assert result == value


@settings(max_examples=100)
@given(
    left=st.from_regex(r"[a-zA-Z0-9_]{1,10}", fullmatch=True),
    right=st.from_regex(r"[a-zA-Z0-9_]{1,10}", fullmatch=True),
)
def test_property_eval_ast_eq_compare(left, right):
    """_eval_ast Compare(Eq) must return True iff left == right."""
    engine = _bare_engine()
    node = ast.Compare(
        left=ast.Constant(value=left),
        ops=[ast.Eq()],
        comparators=[ast.Constant(value=right)],
    )
    result = engine._eval_ast(node, {})
    assert result == (left == right)


@settings(max_examples=100)
@given(
    left=st.from_regex(r"[a-zA-Z0-9_]{1,10}", fullmatch=True),
    right=st.from_regex(r"[a-zA-Z0-9_]{1,10}", fullmatch=True),
)
def test_property_eval_ast_neq_compare(left, right):
    """_eval_ast Compare(NotEq) must return True iff left != right."""
    engine = _bare_engine()
    node = ast.Compare(
        left=ast.Constant(value=left),
        ops=[ast.NotEq()],
        comparators=[ast.Constant(value=right)],
    )
    result = engine._eval_ast(node, {})
    assert result == (left != right)


@settings(max_examples=100)
@given(
    needle=st.from_regex(r"[a-zA-Z0-9]{1,5}", fullmatch=True),
    haystack=st.lists(
        st.from_regex(r"[a-zA-Z0-9]{1,5}", fullmatch=True),
        min_size=0,
        max_size=8,
    ),
)
def test_property_eval_ast_in_compare(needle, haystack):
    """_eval_ast Compare(In) must return True iff needle is in haystack."""
    engine = _bare_engine()
    list_node = ast.List(
        elts=[ast.Constant(value=h) for h in haystack],
        ctx=ast.Load(),
    )
    node = ast.Compare(
        left=ast.Constant(value=needle),
        ops=[ast.In()],
        comparators=[list_node],
    )
    result = engine._eval_ast(node, {})
    assert result == (needle in haystack)


@settings(max_examples=100)
@given(
    needle=st.from_regex(r"[a-zA-Z0-9]{1,5}", fullmatch=True),
    haystack=st.lists(
        st.from_regex(r"[a-zA-Z0-9]{1,5}", fullmatch=True),
        min_size=0,
        max_size=8,
    ),
)
def test_property_eval_ast_not_in_compare(needle, haystack):
    """_eval_ast Compare(NotIn) must return True iff needle is not in haystack."""
    engine = _bare_engine()
    list_node = ast.List(
        elts=[ast.Constant(value=h) for h in haystack],
        ctx=ast.Load(),
    )
    node = ast.Compare(
        left=ast.Constant(value=needle),
        ops=[ast.NotIn()],
        comparators=[list_node],
    )
    result = engine._eval_ast(node, {})
    assert result == (needle not in haystack)


@settings(max_examples=100)
@given(tool=tool_name_st, role=env_role_st)
def test_property_eval_ast_name_lookup(tool, role):
    """_eval_ast Name node must return the variable value from the supplied dict."""
    engine = _bare_engine()
    variables = {"toolName": tool, "environmentRole": role}

    tool_node = ast.Name(id="toolName", ctx=ast.Load())
    role_node = ast.Name(id="environmentRole", ctx=ast.Load())

    assert engine._eval_ast(tool_node, variables) == tool
    assert engine._eval_ast(role_node, variables) == role


# ---------------------------------------------------------------------------
# Supplementary: unsupported node type raises ValueError
# ---------------------------------------------------------------------------

def test_property_eval_ast_unsupported_node_raises():
    """_eval_ast must raise ValueError for an unsupported AST node type."""
    engine = _bare_engine()
    unsupported = ast.Module(body=[], type_ignores=[])
    with pytest.raises(ValueError, match="Unsupported node type"):
        engine._eval_ast(unsupported, {})


def test_property_eval_ast_unsupported_unary_op_raises():
    """_eval_ast must raise ValueError for an unsupported unary operator (e.g. USub)."""
    engine = _bare_engine()
    node = ast.UnaryOp(op=ast.USub(), operand=ast.Constant(value=1))
    with pytest.raises(ValueError, match="Unsupported unary op"):
        engine._eval_ast(node, {})


# ---------------------------------------------------------------------------
# Supplementary: no-policy default escalation
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(ctx=tool_call_context_st(), role=env_role_st)
def test_property_no_policy_loaded_defaults_to_escalate(ctx, role):
    """When no policy is loaded, evaluate() must default to ESCALATE_TO_SEMANTIC."""
    engine = StructuralGatingEngine()  # no load_policy call
    result = engine.evaluate(ctx, role)
    assert result.decision == StructuralAction.ESCALATE_TO_SEMANTIC
    assert result.requireSemanticReview is True


# ---------------------------------------------------------------------------
# Supplementary: unknown environment role defaults to escalation
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    ctx=tool_call_context_st(),
    role=st.from_regex(r"unknown_role_[a-z]{3,8}", fullmatch=True),
)
def test_property_unknown_environment_role_defaults_to_escalate(ctx, role):
    """evaluate() must return ESCALATE_TO_SEMANTIC for an unknown environment role."""
    engine = _load_engine(_ALLOW_ALL_RULES)
    result = engine.evaluate(ctx, role)
    assert result.decision == StructuralAction.ESCALATE_TO_SEMANTIC
    assert result.requireSemanticReview is True
