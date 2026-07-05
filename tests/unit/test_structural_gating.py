import os
import tempfile
import time
import pytest

from blackwall.models import ToolCallContext
from blackwall.policy.engine import StructuralGatingEngine, normalize_operators
from blackwall.policy.models import StructuralAction
from blackwall.policy.watcher import PolicyWatcher

BASE_YAML_TEMPLATE = """
version: "{version}"
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
  - "Test guideline"
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
  dbPath: "/tmp/test-tsg.db"
  walMode: true
  maxConnections: 10
  similarityThreshold: 0.85
  ttlSeconds: 3600
  maxSignatures: 1000
  embeddingDimension: 384
"""


def make_yaml(rules_yaml: str, version: str = "1.0.0") -> str:
    # Indent rules properly
    indented_rules = (
        "\n".join("  " + line for line in rules_yaml.strip().split("\n"))
        if rules_yaml.strip()
        else ""
    )
    if not indented_rules:
        indented_rules = "  []"
    return BASE_YAML_TEMPLATE.format(version=version, rules=indented_rules)


def write_temp_yaml(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


def test_normalize_operators() -> None:
    # Basic operator normalization
    assert normalize_operators("a AND b") == "a and b"
    assert normalize_operators("a OR b") == "a or b"
    # Case insensitivity
    assert normalize_operators("a and b") == "a and b"
    assert normalize_operators("a And b") == "a and b"
    # Not replacing inside string literals
    assert (
        normalize_operators(
            "toolName == 'AND_command' AND environmentRole == 'sandbox'"
        )
        == "toolName == 'AND_command' and environmentRole == 'sandbox'"
    )
    assert (
        normalize_operators('toolName == "OR_command" OR environmentRole == "sandbox"')
        == 'toolName == "OR_command" or environmentRole == "sandbox"'
    )


def test_yaml_loading_and_validation() -> None:
    engine = StructuralGatingEngine()

    # Valid policy
    rules = """
- ruleId: "rule-1"
  condition: "toolName == 'read_file'"
  action: ALLOW
  priority: 1
  enabled: true
"""
    yaml_path = write_temp_yaml(make_yaml(rules))
    try:
        engine.load_policy(yaml_path)
        assert engine._policy is not None
        assert engine._policy.version == "1.0.0"
    finally:
        os.remove(yaml_path)


def test_invalid_semver() -> None:
    engine = StructuralGatingEngine()
    yaml_path = write_temp_yaml(make_yaml("", version="1.0"))
    try:
        with pytest.raises(ValueError, match="Version must be in MAJOR.MINOR.PATCH"):
            engine.load_policy(yaml_path)
    finally:
        os.remove(yaml_path)


def test_duplicate_rule_ids() -> None:
    engine = StructuralGatingEngine()
    rules = """
- ruleId: "duplicate-id"
  condition: "toolName == 'read_file'"
  action: ALLOW
  priority: 1
  enabled: true
- ruleId: "duplicate-id"
  condition: "toolName == 'write_file'"
  action: BLOCK
  priority: 2
  enabled: true
"""
    yaml_path = write_temp_yaml(make_yaml(rules))
    try:
        with pytest.raises(
            ValueError, match="Duplicate structural rule ID: duplicate-id"
        ):
            engine.load_policy(yaml_path)
    finally:
        os.remove(yaml_path)


def test_invalid_condition_ast_components() -> None:
    engine = StructuralGatingEngine()

    # Condition with invalid function call (RCE prevention)
    rules = """
- ruleId: "dangerous-rule"
  condition: "toolName == eval('read_file')"
  action: ALLOW
  priority: 1
  enabled: true
"""
    yaml_path = write_temp_yaml(make_yaml(rules))
    try:
        with pytest.raises(ValueError, match="Unauthorized expression component"):
            engine.load_policy(yaml_path)
    finally:
        os.remove(yaml_path)

    # Condition with unauthorized variable name
    rules_var = """
- ruleId: "bad-var"
  condition: "someOtherVar == 'read_file'"
  action: ALLOW
  priority: 1
  enabled: true
"""
    yaml_path = write_temp_yaml(make_yaml(rules_var))
    try:
        with pytest.raises(ValueError, match="Unauthorized variable"):
            engine.load_policy(yaml_path)
    finally:
        os.remove(yaml_path)


def test_rule_matching_and_actions() -> None:
    engine = StructuralGatingEngine()
    rules = """
- ruleId: "allow-read"
  condition: "toolName == 'read_file' AND environmentRole == 'sandbox'"
  action: ALLOW
  priority: 1
  enabled: true
- ruleId: "block-bash"
  condition: "toolName == 'execute_bash'"
  action: BLOCK
  priority: 2
  enabled: true
- ruleId: "escalate-write"
  condition: "toolName == 'write_file'"
  action: ESCALATE_TO_SEMANTIC
  priority: 3
  enabled: true
"""
    yaml_path = write_temp_yaml(make_yaml(rules))
    try:
        engine.load_policy(yaml_path)

        # Match ALLOW
        ctx1 = ToolCallContext(
            tool_name="read_file", arguments={"path": "settings.yaml"}
        )
        res1 = engine.evaluate(ctx1, "sandbox")
        assert res1.decision == StructuralAction.ALLOW
        assert res1.requireSemanticReview is False
        assert res1.ruleId == "allow-read"

        # Match BLOCK
        ctx2 = ToolCallContext(
            tool_name="execute_bash", arguments={"command": "rm -rf /"}
        )
        res2 = engine.evaluate(ctx2, "sandbox")
        assert res2.decision == StructuralAction.BLOCK
        assert res2.requireSemanticReview is False
        assert res2.ruleId == "block-bash"

        # Match ESCALATE_TO_SEMANTIC
        ctx3 = ToolCallContext(
            tool_name="write_file", arguments={"path": "output.txt", "content": "hi"}
        )
        res3 = engine.evaluate(ctx3, "sandbox")
        assert res3.decision == StructuralAction.ESCALATE_TO_SEMANTIC
        assert res3.requireSemanticReview is True
        assert res3.ruleId == "escalate-write"

    finally:
        os.remove(yaml_path)


def test_default_escalation_when_no_rules_match() -> None:
    engine = StructuralGatingEngine()
    yaml_path = write_temp_yaml(make_yaml(""))
    try:
        engine.load_policy(yaml_path)
        ctx = ToolCallContext(tool_name="unknown_tool", arguments={})
        res = engine.evaluate(ctx, "sandbox")
        assert res.decision == StructuralAction.ESCALATE_TO_SEMANTIC
        assert res.requireSemanticReview is True
        assert res.ruleId is None
    finally:
        os.remove(yaml_path)


def test_rule_priority_ordering() -> None:
    engine = StructuralGatingEngine()
    # Rules with overlapping conditions but different actions and priorities.
    # Rule with priority 1 (ALLOW) should match before rule with priority 2 (BLOCK)
    rules = """
- ruleId: "block-bash-low-priority"
  condition: "toolName == 'execute_bash'"
  action: BLOCK
  priority: 2
  enabled: true
- ruleId: "allow-bash-high-priority"
  condition: "toolName == 'execute_bash'"
  action: ALLOW
  priority: 1
  enabled: true
"""
    yaml_path = write_temp_yaml(make_yaml(rules))
    try:
        engine.load_policy(yaml_path)
        ctx = ToolCallContext(tool_name="execute_bash", arguments={"command": "echo"})
        res = engine.evaluate(ctx, "sandbox")
        assert res.decision == StructuralAction.ALLOW
        assert res.ruleId == "allow-bash-high-priority"
    finally:
        os.remove(yaml_path)


def test_disabled_rules_are_skipped() -> None:
    engine = StructuralGatingEngine()
    rules = """
- ruleId: "block-bash"
  condition: "toolName == 'execute_bash'"
  action: BLOCK
  priority: 1
  enabled: false
- ruleId: "allow-bash"
  condition: "toolName == 'execute_bash'"
  action: ALLOW
  priority: 2
  enabled: true
"""
    yaml_path = write_temp_yaml(make_yaml(rules))
    try:
        engine.load_policy(yaml_path)
        ctx = ToolCallContext(tool_name="execute_bash", arguments={"command": "echo"})
        res = engine.evaluate(ctx, "sandbox")
        assert res.decision == StructuralAction.ALLOW
        assert res.ruleId == "allow-bash"
    finally:
        os.remove(yaml_path)


def test_latency_requirement() -> None:
    engine = StructuralGatingEngine()
    rules = "\n".join(
        f"- ruleId: 'rule-{i}'\n  condition: \"toolName == 'tool-{i}'\"\n  action: ALLOW\n  priority: {i}\n  enabled: true"
        for i in range(100)
    )
    yaml_path = write_temp_yaml(make_yaml(rules))
    try:
        engine.load_policy(yaml_path)
        ctx = ToolCallContext(tool_name="tool-99", arguments={})

        # Measure 100 runs to get p99 latency
        latencies = []
        for _ in range(100):
            start = time.perf_counter()
            engine.evaluate(ctx, "sandbox")
            latencies.append((time.perf_counter() - start) * 1000.0)

        p99 = sorted(latencies)[98]
        assert p99 < 5.0, f"p99 latency was {p99}ms, target is < 5ms"
    finally:
        os.remove(yaml_path)


def test_hot_reload_functionality() -> None:
    engine = StructuralGatingEngine()
    rules_v1 = """
- ruleId: "rule-1"
  condition: "toolName == 'read_file'"
  action: ALLOW
  priority: 1
  enabled: true
"""
    yaml_path = write_temp_yaml(make_yaml(rules_v1))

    try:
        engine.load_policy(yaml_path)
        ctx = ToolCallContext(tool_name="read_file", arguments={})

        # Initially ALLOW
        res1 = engine.evaluate(ctx, "sandbox")
        assert res1.decision == StructuralAction.ALLOW

        # Start watcher
        watcher = PolicyWatcher(yaml_path, engine.load_policy)
        watcher.start()

        try:
            # Update file to BLOCK action
            rules_v2 = """
- ruleId: "rule-1"
  condition: "toolName == 'read_file'"
  action: BLOCK
  priority: 1
  enabled: true
"""
            with open(yaml_path, "w") as f:
                f.write(make_yaml(rules_v2))

            # Wait for file system event to propagate (debounced or standard delay)
            # 1 second should be sufficient.
            time.sleep(1.0)

            # Should be BLOCK now
            res2 = engine.evaluate(ctx, "sandbox")
            assert res2.decision == StructuralAction.BLOCK

            # Update with invalid YAML (schema violation)
            invalid_yaml = "invalid: yaml: structure: :"
            with open(yaml_path, "w") as f:
                f.write(invalid_yaml)

            time.sleep(1.0)

            # Should still retain previous valid config (BLOCK)
            res3 = engine.evaluate(ctx, "sandbox")
            assert res3.decision == StructuralAction.BLOCK
        finally:
            watcher.stop()
    finally:
        if os.path.exists(yaml_path):
            os.remove(yaml_path)


def test_deterministic_evaluation() -> None:
    engine = StructuralGatingEngine()
    rules = """
- ruleId: "rule-1"
  condition: "toolName == 'read_file'"
  action: ALLOW
  priority: 1
  enabled: true
"""
    yaml_path = write_temp_yaml(make_yaml(rules))
    try:
        engine.load_policy(yaml_path)
        ctx = ToolCallContext(tool_name="read_file", arguments={})
        res1 = engine.evaluate(ctx, "sandbox")
        res2 = engine.evaluate(ctx, "sandbox")
        assert res1.decision == res2.decision
        assert res1.requireSemanticReview == res2.requireSemanticReview
        assert res1.ruleId == res2.ruleId
    finally:
        os.remove(yaml_path)
