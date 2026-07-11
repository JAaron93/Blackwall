import os
import pytest
from blackwall.models import ToolCallContext
from blackwall.policy.engine import StructuralGatingEngine
from blackwall.policy.models import StructuralAction

def test_concrete_policy_yaml_loading() -> None:
    """Verifies that the production config/policy.yaml can be successfully loaded and parses properly."""
    policy_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "config", "policy.yaml"
    )
    assert os.path.exists(policy_path), f"policy.yaml not found at {policy_path}"

    engine = StructuralGatingEngine()
    # If this raises an exception, the test fails (schema validation, duplicate IDs, invalid AST conditions)
    engine.load_policy(policy_path)

    policy = engine._policy
    assert policy is not None
    assert policy.version == "1.0.0"

    # Global config checks
    assert policy.global_config.threatThreshold == 0.75
    assert policy.global_config.quarantineThreshold == 0.5
    assert policy.global_config.enableStructuralGating is True
    assert policy.global_config.enableSemanticGating is True

    # Check environment roles are correctly configured
    expected_roles = {"sandbox", "development", "staging", "production"}
    assert set(policy.environmentRoles.keys()) == expected_roles

    # Verify sandbox config
    sandbox_role = policy.environmentRoles["sandbox"]
    assert "read_file" in sandbox_role.allowedTools
    assert "list_dir" in sandbox_role.allowedTools
    assert "web_search" in sandbox_role.allowedTools
    assert sandbox_role.requireSemanticReview is False
    assert sandbox_role.maxThreatScore == 0.8

    # Verify production config
    production_role = policy.environmentRoles["production"]
    assert "execute_bash" in production_role.blockedTools
    assert "run_python" in production_role.blockedTools
    assert "install_package" in production_role.blockedTools
    assert production_role.requireSemanticReview is True
    assert production_role.maxThreatScore == 0.5


def test_concrete_policy_priority_ordering() -> None:
    """Verifies that rules are sorted and evaluated in ascending order of priority."""
    policy_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "config", "policy.yaml"
    )
    engine = StructuralGatingEngine()
    engine.load_policy(policy_path)

    compiled_rules = engine._compiled_rules
    assert len(compiled_rules) > 0

    priorities = [rule.priority for rule, _ in compiled_rules]
    # Ensure priorities are strictly sorted in ascending order
    assert priorities == sorted(priorities)


def test_concrete_policy_rules_evaluation() -> None:
    """Verifies that the concrete rules in config/policy.yaml trigger correct decisions."""
    policy_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "config", "policy.yaml"
    )
    engine = StructuralGatingEngine()
    engine.load_policy(policy_path)

    # 1. BLOCK rule: execute_bash in production
    ctx_block1 = ToolCallContext(tool_name="execute_bash", arguments={"command": "whoami"})
    res_block1 = engine.evaluate(ctx_block1, "production")
    assert res_block1.decision == StructuralAction.BLOCK
    assert res_block1.requireSemanticReview is False
    assert res_block1.ruleId == "rule-block-dangerous-tools-prod-staging"

    # 2. BLOCK rule: install_package in staging
    ctx_block2 = ToolCallContext(tool_name="install_package", arguments={"package": "curl"})
    res_block2 = engine.evaluate(ctx_block2, "staging")
    assert res_block2.decision == StructuralAction.BLOCK
    assert res_block2.requireSemanticReview is False
    assert res_block2.ruleId == "rule-block-dangerous-tools-prod-staging"

    # 3. ESCALATE rule: write_file
    ctx_escalate1 = ToolCallContext(tool_name="write_file", arguments={"path": "test.txt", "content": "hello"})
    res_escalate1 = engine.evaluate(ctx_escalate1, "production")
    assert res_escalate1.decision == StructuralAction.ESCALATE_TO_SEMANTIC
    assert res_escalate1.requireSemanticReview is True
    assert res_escalate1.ruleId == "rule-escalate-write-operations"

    # 4. ESCALATE rule: web_search in staging/production (but sandbox is allowed or escalates if no rule matches sandbox)
    ctx_escalate2 = ToolCallContext(tool_name="web_search", arguments={"query": "exploit"})
    res_escalate2 = engine.evaluate(ctx_escalate2, "production")
    assert res_escalate2.decision == StructuralAction.ESCALATE_TO_SEMANTIC
    assert res_escalate2.requireSemanticReview is True
    assert res_escalate2.ruleId == "rule-escalate-network-operations"

    # 5. ALLOW rule: read_file in development
    ctx_allow1 = ToolCallContext(tool_name="read_file", arguments={"path": "README.md"})
    res_allow1 = engine.evaluate(ctx_allow1, "development")
    assert res_allow1.decision == StructuralAction.ALLOW
    assert res_allow1.requireSemanticReview is False
    assert res_allow1.ruleId == "rule-allow-safe-read-dev"

    # 6. ALLOW rule: list_dir in sandbox
    ctx_allow2 = ToolCallContext(tool_name="list_dir", arguments={"path": "."})
    res_allow2 = engine.evaluate(ctx_allow2, "sandbox")
    assert res_allow2.decision == StructuralAction.ALLOW
    assert res_allow2.requireSemanticReview is False
    assert res_allow2.ruleId == "rule-allow-safe-read-sandbox"
