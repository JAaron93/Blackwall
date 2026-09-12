import os

import pytest

from blackwall.models import ToolCallContext
from blackwall.policy.engine import StructuralGatingEngine
from blackwall.policy.models import StructuralAction
from tests.unit.policy_yaml_helpers import make_yaml, write_temp_yaml


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
    assert "file_read" in sandbox_role.allowedTools
    assert "list_dir" in sandbox_role.allowedTools
    assert "web_search" not in sandbox_role.allowedTools
    assert sandbox_role.requireSemanticReview is False
    assert sandbox_role.maxThreatScore == 0.8

    # Verify development config
    dev_role = policy.environmentRoles["development"]
    assert "read_file" in dev_role.allowedTools
    assert "file_read" in dev_role.allowedTools
    assert "list_dir" in dev_role.allowedTools
    assert dev_role.requireSemanticReview is False
    assert dev_role.maxThreatScore == 0.7

    # Verify staging config
    staging_role = policy.environmentRoles["staging"]
    assert "read_file" in staging_role.allowedTools
    assert "file_read" in staging_role.allowedTools
    assert "list_dir" in staging_role.allowedTools
    assert "execute_bash" in staging_role.blockedTools
    assert "execute_shell" in staging_role.blockedTools
    assert "run_python" in staging_role.blockedTools
    assert "install_package" in staging_role.blockedTools
    assert staging_role.requireSemanticReview is True
    assert staging_role.maxThreatScore == 0.6

    # Verify production config
    production_role = policy.environmentRoles["production"]
    assert "execute_bash" in production_role.blockedTools
    assert "execute_shell" in production_role.blockedTools
    assert "run_python" in production_role.blockedTools
    assert "install_package" in production_role.blockedTools
    assert production_role.requireSemanticReview is True
    assert production_role.maxThreatScore == 0.5

    # Verify MCP server endpoints
    assert policy.mcpServers.gti.enabled is True
    assert policy.mcpServers.gti.url == "https://gti.googleapis.com/mcp"
    assert policy.mcpServers.codebaseMemory.enabled is True
    assert policy.mcpServers.codebaseMemory.url == "http://localhost:8080/mcp"

    # Verify threat signature graph config
    assert policy.threatSignatureGraph.batchSize == 900
    assert policy.threatSignatureGraph.embeddingDimension == 768


def test_policy_yaml_root_and_config_parity() -> None:
    """Verifies that config/policy.yaml and root policy.yaml both exist and have identical contents and schema."""
    root_dir = os.path.join(os.path.dirname(__file__), "..", "..")
    config_path = os.path.join(root_dir, "config", "policy.yaml")
    root_path = os.path.join(root_dir, "policy.yaml")

    assert os.path.exists(config_path), f"config/policy.yaml not found at {config_path}"
    assert os.path.exists(root_path), f"policy.yaml not found at {root_path}"

    with open(config_path, "r", encoding="utf-8") as f:
        config_text = f.read().strip()
    with open(root_path, "r", encoding="utf-8") as f:
        root_text = f.read().strip()

    assert config_text == root_text, (
        "config/policy.yaml and policy.yaml must have identical content"
    )

    engine_config = StructuralGatingEngine()
    engine_config.load_policy(config_path)

    engine_root = StructuralGatingEngine()
    engine_root.load_policy(root_path)

    assert engine_config._policy is not None
    assert engine_root._policy is not None
    assert engine_config._policy.model_dump() == engine_root._policy.model_dump()


def test_policy_yaml_duplicate_rule_ids_rejected() -> None:
    """Verifies that duplicate rule IDs in a YAML policy are rejected with a ValueError."""
    engine = StructuralGatingEngine()
    rules = """
- ruleId: "duplicate-rule"
  condition: "toolName == 'read_file'"
  action: ALLOW
  priority: 1
  enabled: true
- ruleId: "duplicate-rule"
  condition: "toolName == 'write_file'"
  action: BLOCK
  priority: 2
  enabled: true
"""
    yaml_path = write_temp_yaml(make_yaml(rules))
    try:
        with pytest.raises(
            ValueError, match="Duplicate structural rule ID: duplicate-rule"
        ):
            engine.load_policy(yaml_path)
    finally:
        os.remove(yaml_path)


def test_policy_yaml_schema_validation_passes() -> None:
    """Verifies that the policy schema conforms to all Requirements (17.2, 17.3, 17.4, 22.1)."""
    policy_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "config", "policy.yaml"
    )
    engine = StructuralGatingEngine()
    engine.load_policy(policy_path)
    policy = engine._policy
    assert policy is not None

    # Version format (MAJOR.MINOR.PATCH)
    parts = policy.version.split(".")
    assert len(parts) == 3 and all(p.isdigit() for p in parts)

    # Global thresholds in range [0.0, 1.0]
    assert 0.0 <= policy.global_config.threatThreshold <= 1.0
    assert 0.0 <= policy.global_config.quarantineThreshold <= 1.0
    assert (
        policy.global_config.quarantineThreshold <= policy.global_config.threatThreshold
    )

    # Environment roles contain sandbox and production at minimum
    assert "sandbox" in policy.environmentRoles
    assert "production" in policy.environmentRoles

    # Structural rules verification
    rule_ids = [rule.ruleId for rule in policy.structuralRules]
    assert len(rule_ids) == len(set(rule_ids)), "Rule IDs must be unique"
    for rule in policy.structuralRules:
        assert rule.ruleId
        assert rule.condition
        assert rule.action in (
            StructuralAction.ALLOW,
            StructuralAction.BLOCK,
            StructuralAction.ESCALATE_TO_SEMANTIC,
        )
        assert isinstance(rule.priority, int)
        assert isinstance(rule.enabled, bool)

    # MCP Server endpoints
    assert policy.mcpServers.gti.url.startswith("http")
    assert policy.mcpServers.codebaseMemory.url.startswith("http")


def test_concrete_policy_priority_ordering() -> None:
    """Verifies that rules are sorted and evaluated in ascending order of priority (lowest priority number executed first)."""
    policy_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "config", "policy.yaml"
    )
    engine = StructuralGatingEngine()
    engine.load_policy(policy_path)

    compiled_rules = engine._compiled_rules
    assert len(compiled_rules) >= 6

    priorities = [rule.priority for rule, _ in compiled_rules]
    # Ensure priorities are strictly sorted in ascending order
    assert priorities == sorted(priorities)
    assert priorities == [1, 2, 3, 4, 5, 6]


def test_policy_yaml_block_rules_fire() -> None:
    """Verifies BLOCK rules fire for malicious tools (execute_bash, execute_shell, run_python, install_package) in production/staging."""
    policy_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "config", "policy.yaml"
    )
    engine = StructuralGatingEngine()
    engine.load_policy(policy_path)

    malicious_tools = ["execute_bash", "execute_shell", "run_python", "install_package"]
    restricted_envs = ["production", "staging"]

    for tool in malicious_tools:
        for env in restricted_envs:
            ctx = ToolCallContext(tool_name=tool, arguments={"cmd": "whoami"})
            res = engine.evaluate(ctx, env)
            assert res.decision == StructuralAction.BLOCK, (
                f"Expected BLOCK for {tool} in {env}"
            )
            assert res.requireSemanticReview is False
            assert res.ruleId == "rule-block-dangerous-tools-prod-staging"


def test_policy_yaml_escalate_rules_fire() -> None:
    """Verifies ESCALATE rules fire for privileged write/network/database operations."""
    policy_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "config", "policy.yaml"
    )
    engine = StructuralGatingEngine()
    engine.load_policy(policy_path)

    # 1. Privileged write operations: write_file across environments
    for env in ["production", "staging", "development", "sandbox"]:
        ctx_write = ToolCallContext(
            tool_name="write_file",
            arguments={"path": "/tmp/out.txt", "content": "data"},
        )
        res_write = engine.evaluate(ctx_write, env)
        assert res_write.decision == StructuralAction.ESCALATE_TO_SEMANTIC
        assert res_write.requireSemanticReview is True
        assert res_write.ruleId == "rule-escalate-write-operations"

    # 2. Privileged network operations: web_search and http_request in production/staging/sandbox
    for tool in ["web_search", "http_request"]:
        for env in ["production", "staging", "sandbox"]:
            ctx_net = ToolCallContext(
                tool_name=tool,
                arguments={"query": "test", "url": "https://example.com"},
            )
            res_net = engine.evaluate(ctx_net, env)
            assert res_net.decision == StructuralAction.ESCALATE_TO_SEMANTIC
            assert res_net.requireSemanticReview is True
            assert res_net.ruleId == "rule-escalate-network-operations"

    # 3. Privileged database operations: database_query across environments
    for env in ["production", "staging", "development", "sandbox"]:
        ctx_db = ToolCallContext(
            tool_name="database_query", arguments={"query": "SELECT * FROM users"}
        )
        res_db = engine.evaluate(ctx_db, env)
        assert res_db.decision == StructuralAction.ESCALATE_TO_SEMANTIC
        assert res_db.requireSemanticReview is True
        assert res_db.ruleId == "rule-escalate-database-operations"


def test_policy_yaml_allow_rules_fire() -> None:
    """Verifies ALLOW rules fire for safe read-only operations (read_file, file_read, list_dir) in development/sandbox."""
    policy_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "config", "policy.yaml"
    )
    engine = StructuralGatingEngine()
    engine.load_policy(policy_path)

    safe_tools = ["read_file", "file_read", "list_dir"]

    # In development
    for tool in safe_tools:
        ctx = ToolCallContext(tool_name=tool, arguments={"path": "/docs"})
        res = engine.evaluate(ctx, "development")
        assert res.decision == StructuralAction.ALLOW, (
            f"Expected ALLOW for {tool} in development"
        )
        assert res.requireSemanticReview is False
        assert res.ruleId == "rule-allow-safe-read-dev"

    # In sandbox
    for tool in safe_tools:
        ctx = ToolCallContext(tool_name=tool, arguments={"path": "/sandbox/data"})
        res = engine.evaluate(ctx, "sandbox")
        assert res.decision == StructuralAction.ALLOW, (
            f"Expected ALLOW for {tool} in sandbox"
        )
        assert res.requireSemanticReview is False
        assert res.ruleId == "rule-allow-safe-read-sandbox"


def test_concrete_policy_rules_evaluation() -> None:
    """Verifies that the concrete rules in config/policy.yaml trigger correct decisions."""
    policy_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "config", "policy.yaml"
    )
    engine = StructuralGatingEngine()
    engine.load_policy(policy_path)

    # 1. BLOCK rule: execute_bash in production
    ctx_block1 = ToolCallContext(
        tool_name="execute_bash", arguments={"command": "whoami"}
    )
    res_block1 = engine.evaluate(ctx_block1, "production")
    assert res_block1.decision == StructuralAction.BLOCK
    assert res_block1.requireSemanticReview is False
    assert res_block1.ruleId == "rule-block-dangerous-tools-prod-staging"

    # 2. BLOCK rule: install_package in staging
    ctx_block2 = ToolCallContext(
        tool_name="install_package", arguments={"package": "curl"}
    )
    res_block2 = engine.evaluate(ctx_block2, "staging")
    assert res_block2.decision == StructuralAction.BLOCK
    assert res_block2.requireSemanticReview is False
    assert res_block2.ruleId == "rule-block-dangerous-tools-prod-staging"

    # 3. ESCALATE rule: write_file
    ctx_escalate1 = ToolCallContext(
        tool_name="write_file", arguments={"path": "test.txt", "content": "hello"}
    )
    res_escalate1 = engine.evaluate(ctx_escalate1, "production")
    assert res_escalate1.decision == StructuralAction.ESCALATE_TO_SEMANTIC
    assert res_escalate1.requireSemanticReview is True
    assert res_escalate1.ruleId == "rule-escalate-write-operations"

    # 4. ESCALATE rule: web_search in staging/production/sandbox
    ctx_escalate2 = ToolCallContext(
        tool_name="web_search", arguments={"query": "exploit"}
    )
    res_escalate2 = engine.evaluate(ctx_escalate2, "production")
    assert res_escalate2.decision == StructuralAction.ESCALATE_TO_SEMANTIC
    assert res_escalate2.requireSemanticReview is True
    assert res_escalate2.ruleId == "rule-escalate-network-operations"

    # 4b. ESCALATE rule: web_search in sandbox now routes through semantic review
    ctx_escalate2_sandbox = ToolCallContext(
        tool_name="web_search", arguments={"query": "API_KEY=secret"}
    )
    res_escalate2_sandbox = engine.evaluate(ctx_escalate2_sandbox, "sandbox")
    assert res_escalate2_sandbox.decision == StructuralAction.ESCALATE_TO_SEMANTIC
    assert res_escalate2_sandbox.requireSemanticReview is True
    assert res_escalate2_sandbox.ruleId == "rule-escalate-network-operations"

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
