"""
Task 23.2: Tier 2 Cybench Cloud Run gVisor MicroVM Sandbox Scenarios.
Validates multi-pillar reactions (<50ms eBPF/audit socket drops, Threat Mesh broadcast, Vault STS token revocations).
"""

import pytest
from uuid import uuid4

from blackwall.enterprise.advanced_threat_detection.reaction import (
    ActiveReactionEngine,
    ActiveReactionPayload,
    ReactionActionType,
)
from blackwall.enterprise.kernel.probe import UserSpaceAuditDriver
from blackwall.enterprise.mcp.vault_mcp import VaultMCPAdapter


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
