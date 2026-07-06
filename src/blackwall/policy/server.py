import asyncio
from datetime import datetime, timezone
import structlog
from typing import List

from blackwall.models import ToolCallContext, Verdict, VerdictDecision, PolicyServerState
from blackwall.policy.engine import StructuralGatingEngine, StructuralAction
from blackwall.policy.semantic import SemanticGatingEngine
from blackwall.exceptions import APIRateLimitException

logger = structlog.get_logger("blackwall.policy.server")


class HybridPolicyServer:
    """
    Orchestrates structural (fast-path) and semantic (deep) gating for tool calls.
    """

    def __init__(
        self,
        structural_engine: StructuralGatingEngine,
        semantic_engine: SemanticGatingEngine,
    ) -> None:
        self.structural_engine = structural_engine
        self.semantic_engine = semantic_engine
        self.last_updated = datetime.now(timezone.utc)

    async def evaluate(self, context: ToolCallContext, environment_role: str) -> Verdict:
        """
        Evaluates a tool call context.
        First executes Structural Gating. If it is ALLOW (without review) or BLOCK, returns immediately.
        Otherwise, escalates to Semantic Gating.
        """
        # 1. Structural Gating (Fast Path)
        struct_result = self.structural_engine.evaluate(context, environment_role)

        if struct_result.decision == StructuralAction.BLOCK:
            return Verdict(
                decision=VerdictDecision.BLOCK,
                reasoning="BLOCKED_BY_STRUCTURAL_RULE",
                confidence_score=1.0,
            )

        if (
            struct_result.decision == StructuralAction.ALLOW
            and not struct_result.requireSemanticReview
        ):
            return Verdict(
                decision=VerdictDecision.ALLOW,
                reasoning="ALLOWED_BY_STRUCTURAL_RULE",
                confidence_score=0.0,
            )

        # 2. Semantic Gating (Escalation Path)
        # Note: SemanticGatingEngine.evaluate accepts context, environment_role and optional structural_result
        semantic_result = await self.semantic_engine.evaluate(
            context, environment_role, structural_result=struct_result
        )

        return Verdict(
            decision=semantic_result.verdict,
            reasoning=semantic_result.reason,
            confidence_score=semantic_result.threat_score,
        )

    async def evaluateBatch(
        self, contexts: List[ToolCallContext], env_roles: List[str]
    ) -> List[Verdict]:
        """
        Evaluates multiple contexts in parallel.
        On rate limits or timeout, returns QUARANTINE verdicts (fail-closed).
        Individual item failures are isolated; successful results are preserved.
        """
        if len(contexts) != len(env_roles):
            raise ValueError("Mismatched contexts and environment roles lengths")

        # Enforce a hardcoded 10-second evaluation timeout per item for the local MVP.
        # asyncio.wait_for() raises TimeoutError and cancels the evaluation coroutine.
        tasks = [
            asyncio.wait_for(self.evaluate(ctx, role), timeout=10.0)
            for ctx, role in zip(contexts, env_roles)
        ]

        # Execute all evaluations in parallel, capturing per-item exceptions
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results, converting exceptions to QUARANTINE verdicts for affected items
        verdicts = []
        for i, result in enumerate(results):
            if isinstance(result, (APIRateLimitException, asyncio.TimeoutError)):
                logger.warning(
                    "Fail-closed triggered for item in batch",
                    item_index=i,
                    error=type(result).__name__,
                    details=str(result),
                )
                verdicts.append(
                    Verdict(
                        decision=VerdictDecision.QUARANTINE,
                        reasoning=f"Fail-closed: {str(result)}",
                        confidence_score=0.5,
                    )
                )
            elif isinstance(result, Exception):
                logger.error(
                    "Unexpected error evaluating item in batch",
                    item_index=i,
                    error=str(result),
                )
                verdicts.append(
                    Verdict(
                        decision=VerdictDecision.QUARANTINE,
                        reasoning="Unexpected error in semantic evaluation",
                        confidence_score=0.5,
                    )
                )
            else:
                # Successful evaluation
                verdicts.append(result)

        return verdicts

    async def getCurrentState(self) -> PolicyServerState:
        """
        Returns a snapshot of the Policy Server's state.
        """
        version = "0.0.0"
        if self.structural_engine._policy:
            version = self.structural_engine._policy.version

        active_signatures = 0
        if self.semantic_engine.repo:
            stats = await self.semantic_engine.repo.getStatistics()
            active_signatures = stats.get("totalSignatures", 0)

        return PolicyServerState(
            version=version,
            last_updated=self.last_updated,
            active_signatures=active_signatures,
        )

    def updatePolicy(self, yaml_path: str) -> None:
        """
        Hot-reloads the policy config using the structural gating engine.
        """
        self.structural_engine.load_policy(yaml_path)
        self.last_updated = datetime.now(timezone.utc)
        logger.info("Hybrid Policy Server reloaded policy successfully", path=yaml_path)
