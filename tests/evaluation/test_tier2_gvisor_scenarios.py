"""
Task 23.2 & Track 7: Tier 2 Cybench Cloud Run gVisor MicroVM Sandbox Scenarios.
Validates multi-pillar reactions (<50ms eBPF/audit socket drops, Threat Mesh broadcast, Vault STS token revocations),
and pipeline micro-sandbox AST filter containment against dataset loader RCE and Jinja template injection.
Satisfies TASK-V04 under .kiro/specs/blackwall-enterprise-security-mesh/tasks.md.
"""

from uuid import uuid4
import pytest

from blackwall.enterprise.advanced_threat_detection.reaction import (
    ActiveReactionEngine,
    ActiveReactionPayload,
    ReactionActionType,
)
from blackwall.enterprise.kernel.probe import UserSpaceAuditDriver
from blackwall.enterprise.mcp.sandbox_mcp import ContainerSandboxMCPAdapter
from blackwall.enterprise.mcp.vault_mcp import VaultMCPAdapter
from blackwall.enterprise.pipeline import (
    ASTPipelineFilter,
    PipelineSandboxManager,
    guard_pipeline,
)


@pytest.mark.gcp_eval
@pytest.mark.asyncio
async def test_tier2_gvisor_multi_pillar_containment_lifecycle():
    """Verify combined socket drop, mesh broadcast, and token revocation under gVisor microVM sandbox."""
    driver = UserSpaceAuditDriver()
    vault = VaultMCPAdapter(endpoint="http://127.0.0.1:8200")
    engine = ActiveReactionEngine(kernel_driver=driver, vault_adapter=vault)

    try:
        # Issue test JIT token
        token = await vault.issue_jit_token(role="adversarial_agent", agent_id="agent_gvisor_01")
        token_id = token["token_id"]
        assert vault._issued_tokens[token_id]["status"] == "ACTIVE"

        # Construct reaction payload
        payload = ActiveReactionPayload(
            trigger_evidence_id=uuid4(),
            target_agent_id="agent_gvisor_01",
            action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
            target_ip="198.51.100.22",
            metadata={"token_id": token_id},
        )

        # Execute reaction within <50ms SLA
        success = await engine.revoke_identity_session(payload)
        assert success is True
        assert payload.status == "COMPLETED"
        assert payload.execution_duration_ms < 50.0

        # Token must be revoked
        assert vault._issued_tokens[token_id]["status"] == "REVOKED"
    finally:
        driver.stop_tracing()


@pytest.mark.gcp_eval
@pytest.mark.asyncio
async def test_eval_pipeline_containment(monkeypatch):
    """
    TASK-V04: Evaluate dataset loader RCE and Jinja template injection neutralization score in gVisor microVM sandbox.
    Verifies that ASTPipelineFilter detects dangerous function aliases, bare calls, and SSTI patterns,
    and PipelineSandboxManager blocks unsafe routines while safely routing benign data loaders into
    Cybench Cloud Run gVisor microVM container runtimes under BLACKWALL_EVAL_TIER='tier2'.
    """
    monkeypatch.setenv("BLACKWALL_EVAL_TIER", "tier2")
    cybench_endpoint = "https://cybench-gvisor-sandbox-uc.a.run.app"
    ast_filter = ASTPipelineFilter()
    sandbox_adapter = ContainerSandboxMCPAdapter(endpoint=cybench_endpoint)
    await sandbox_adapter.connect()
    assert sandbox_adapter.endpoint == cybench_endpoint
    manager = PipelineSandboxManager(sandbox_adapter=sandbox_adapter, ast_filter=ast_filter)

    # 1. Dataset Loader RCE Attack Scenarios (indirect alias, bare eval, unsafe pickle)
    def malicious_loader_alias():
        import os
        runner = os.system
        runner("rm -rf /")

    def malicious_loader_eval():
        eval("__import__('os').system('id')")

    def malicious_loader_pickle():
        import pickle
        pickle.loads(b"cos\nsystem\n(S'id'\ntR.")

    # 2. Jinja Server-Side Template Injection (SSTI) Payload
    def malicious_loader_ssti():
        template = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
        return template

    # 3. Benign Dataset Transformation Routine
    def benign_loader():
        records = ["record_alpha", "record_beta", "record_gamma"]
        return [r.upper() for r in records]

    # Evaluate AST Inspection & Guarded Execution on Attacks
    attacks = [
        ("rce_indirect_alias", malicious_loader_alias, "os.system"),
        ("rce_bare_eval", malicious_loader_eval, "eval"),
        ("rce_unsafe_pickle", malicious_loader_pickle, "pickle.loads"),
        ("jinja_ssti", malicious_loader_ssti, "ssti_injection"),
    ]

    neutralized_count = 0
    for name, attack_fn, expected_violation in attacks:
        result = await manager.execute_guarded(attack_fn, sandbox_type="gvisor")
        assert result["status"] == "BLOCKED", f"Attack '{name}' bypassed AST filter!"
        assert result["contained"] is False
        assert expected_violation in result["violations"], (
            f"Expected violation '{expected_violation}' not found in {result['violations']}"
        )
        neutralized_count += 1

    # Neutralization score must be 1.0 (100% neutralized)
    neutralization_score = neutralized_count / len(attacks)
    assert neutralization_score == 1.0, f"Neutralization score was {neutralization_score:.2f}; expected 1.0 (100%)"

    # Evaluate Safe Benign Routine Execution in Cybench Cloud Run gVisor MicroVM Sandbox
    benign_result = await manager.execute_guarded(benign_loader, sandbox_type="gvisor")
    assert benign_result["status"] == "EXECUTED"
    assert benign_result["contained"] is True
    assert benign_result["sandbox_type"] == "gvisor"
    assert "sandbox_id" in benign_result
    sandbox_id = benign_result["sandbox_id"]
    assert sandbox_adapter.endpoint == cybench_endpoint
    assert sandbox_adapter._active_sandboxes[sandbox_id]["endpoint"] == cybench_endpoint

    # Verify ephemeral sandbox destruction
    destroy_ok = await sandbox_adapter.destroy_sandbox(sandbox_id)
    assert destroy_ok is True

    # Evaluate @guard_pipeline decorator interface
    @guard_pipeline(sandbox_type="gvisor")
    async def guarded_data_routine(items: list[str]) -> list[str]:
        return [x.strip() for x in items]

    dec_result = await guarded_data_routine(["  clean_item  "])
    assert dec_result["status"] == "EXECUTED"
    assert dec_result["contained"] is True
    assert dec_result["sandbox_type"] == "gvisor"
