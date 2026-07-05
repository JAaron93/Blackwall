import ast
import os
import re
import time
from typing import Any, List, Optional
from threading import Lock
import yaml  # type: ignore[import-untyped]
import structlog

from blackwall.models import ToolCallContext
from blackwall.policy.models import PolicyConfig, StructuralAction, StructuralRule

logger = structlog.get_logger("blackwall.policy")


class StructuralGatingResult:
    def __init__(
        self,
        decision: StructuralAction,
        requireSemanticReview: bool,
        ruleId: Optional[str] = None,
    ) -> None:
        self.decision = decision
        self.requireSemanticReview = requireSemanticReview
        self.ruleId = ruleId

    def __repr__(self) -> str:
        return (
            f"StructuralGatingResult(decision={self.decision}, "
            f"requireSemanticReview={self.requireSemanticReview}, ruleId={self.ruleId})"
        )


def normalize_operators(condition: str) -> str:
    """Normalizes case-insensitive AND/OR operators outside string literals to python equivalents."""
    parts = re.split(r"('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")", condition)
    for i in range(0, len(parts), 2):
        if parts[i]:
            parts[i] = re.sub(r"\bAND\b", "and", parts[i], flags=re.IGNORECASE)
            parts[i] = re.sub(r"\bOR\b", "or", parts[i], flags=re.IGNORECASE)
    return "".join(parts)


class StructuralGatingEngine:
    """Fast, deterministic structural gating engine for evaluating tool call contexts against YAML policies."""

    def __init__(self) -> None:
        self._policy: Optional[PolicyConfig] = None
        self._compiled_rules: List[tuple[StructuralRule, Any]] = []
        self._policy_lock = Lock()
        self.yaml_path: Optional[str] = None

    def load_policy(self, yaml_path: str) -> None:
        """Loads and validates a YAML policy file."""
        if not os.path.exists(yaml_path):
            raise FileNotFoundError(f"Policy file not found: {yaml_path}")

        try:
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            raise ValueError(f"Failed to parse YAML: {e}")

        # Parse and validate schema with Pydantic
        try:
            config = PolicyConfig.model_validate(data)
        except Exception as e:
            raise ValueError(f"Policy schema validation failed: {e}")

        # Validate unique rule IDs
        rule_ids = set()
        for rule in config.structuralRules:
            if rule.ruleId in rule_ids:
                raise ValueError(f"Duplicate structural rule ID: {rule.ruleId}")
            rule_ids.add(rule.ruleId)

        # Validate and compile conditions
        compiled_rules = []
        for rule in config.structuralRules:
            if not rule.enabled:
                continue
            try:
                normalized = normalize_operators(rule.condition)
                self._validate_condition_ast(normalized)
                compiled_code = compile(normalized, "<string>", "eval")
                compiled_rules.append((rule, compiled_code))
            except Exception as e:
                raise ValueError(f"Invalid condition in rule '{rule.ruleId}': {e}")

        # Sort compiled rules by priority ascending (priority 1 evaluated before 2)
        compiled_rules.sort(key=lambda x: x[0].priority)

        # Atomic swap
        with self._policy_lock:
            self._policy = config
            self._compiled_rules = compiled_rules
            self.yaml_path = yaml_path

        logger.info(
            "Policy loaded successfully",
            version=config.version,
            active_rules_count=len(compiled_rules),
        )

    def _validate_condition_ast(self, normalized_condition: str) -> None:
        """Validates that condition contains only safe AST nodes and allowed variables."""
        node = ast.parse(normalized_condition, mode="eval")

        allowed_nodes = (
            ast.Expression,
            ast.BoolOp,
            ast.And,
            ast.Or,
            ast.Compare,
            ast.Eq,
            ast.Name,
            ast.Constant,
            ast.Load,
        )

        allowed_variables = {"toolName", "environmentRole"}

        for n in ast.walk(node):
            if not isinstance(n, allowed_nodes):
                raise ValueError(
                    f"Unauthorized expression component: {type(n).__name__}"
                )
            if isinstance(n, ast.Name):
                if n.id not in allowed_variables:
                    raise ValueError(
                        f"Unauthorized variable: '{n.id}'. Only toolName and environmentRole are allowed."
                    )
                if not isinstance(n.ctx, ast.Load):
                    raise ValueError(
                        f"Unauthorized variable context: {type(n.ctx).__name__}"
                    )

    def evaluate(
        self, context: ToolCallContext, environment_role: str
    ) -> StructuralGatingResult:
        """
        Evaluates a tool call context against structural rules in priority ascending order.
        Target latency: <5ms at 99th percentile.
        """
        start_time = time.perf_counter()

        with self._policy_lock:
            rules_to_eval = list(self._compiled_rules)
            policy = self._policy

        if not policy:
            # If no policy loaded, default to ESCALATE_TO_SEMANTIC
            logger.warning("No policy loaded; defaulting to ESCALATE_TO_SEMANTIC")
            return StructuralGatingResult(
                decision=StructuralAction.ESCALATE_TO_SEMANTIC,
                requireSemanticReview=True,
            )

        # Ensure environment role exists in configured roles
        if environment_role not in policy.environmentRoles:
            logger.warning(
                "Environment role not defined in policy. Defaulting to ESCALATE_TO_SEMANTIC.",
                environment_role=environment_role,
            )
            return StructuralGatingResult(
                decision=StructuralAction.ESCALATE_TO_SEMANTIC,
                requireSemanticReview=True,
            )

        variables = {
            "toolName": context.tool_name,
            "environmentRole": environment_role,
        }

        matched_rule = None
        for rule, compiled_code in rules_to_eval:
            try:
                # Safe eval of the pre-compiled AST code object
                result = eval(compiled_code, {"__builtins__": {}}, variables)
                if result:
                    matched_rule = rule
                    break
            except Exception as e:
                logger.error(
                    "Error evaluating rule condition",
                    rule_id=rule.ruleId,
                    condition=rule.condition,
                    error=str(e),
                )
                continue

        eval_latency_ms = (time.perf_counter() - start_time) * 1000.0

        if matched_rule:
            # Apply matched rule action
            action = matched_rule.action
            # If ALLOW, requireSemanticReview defaults to rule's setting, or False if not specified.
            # For ESCALATE_TO_SEMANTIC, it is always True.
            # For BLOCK, it is False.
            if action == StructuralAction.ALLOW:
                req_semantic = (
                    matched_rule.requireSemanticReview
                    if matched_rule.requireSemanticReview is not None
                    else False
                )
            elif action == StructuralAction.BLOCK:
                req_semantic = False
            else:
                req_semantic = True

            logger.info(
                "Structural Gating rule matched",
                rule_id=matched_rule.ruleId,
                action=action.value,
                require_semantic_review=req_semantic,
                latency_ms=eval_latency_ms,
            )
            return StructuralGatingResult(
                decision=action,
                requireSemanticReview=req_semantic,
                ruleId=matched_rule.ruleId,
            )

        # Default to ESCALATE_TO_SEMANTIC if no rules match
        logger.info(
            "No structural rules matched; defaulting to ESCALATE_TO_SEMANTIC",
            latency_ms=eval_latency_ms,
        )
        return StructuralGatingResult(
            decision=StructuralAction.ESCALATE_TO_SEMANTIC,
            requireSemanticReview=True,
        )
