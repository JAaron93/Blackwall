import logging
import os
import time
from typing import Optional
from uuid import uuid4

from google import genai

from blackwall.models import SecurityEvent, VerdictDecision
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.config import get_genai_client

logger = logging.getLogger(__name__)


class AgentBehavioralAnalytics:
    def __init__(
        self,
        repo: SQLiteThreatRepository,
        client: Optional[genai.Client] = None,
        webhook_url: Optional[str] = None,
        in_process: Optional[bool] = None,
    ):
        self.repo = repo
        self.client = client or get_genai_client()
        self.webhook_url = (
            webhook_url
            or os.getenv("BLACKWALL_WEBHOOK_URL")
            or "http://localhost:8090/webhook/analysis_complete"
        )
        if in_process is None:
            self.in_process = os.getenv(
                "BLACKWALL_IN_PROCESS_BACKGROUND_ANALYSIS", ""
            ).strip().lower() in ("true", "1", "yes")
        else:
            self.in_process = bool(in_process)

    async def submitBackgroundAnalysis(self, event: SecurityEvent) -> Optional[str]:
        if not event.verdict or event.verdict.decision not in {
            VerdictDecision.BLOCK,
            VerdictDecision.QUARANTINE,
        }:
            return None

        prompt = (
            f"Analyze the following security event for behavioral drift and threat patterns:\n"
            f"Tool Context: {event.tool_context.model_dump_json()}\n"
            f"Verdict: {event.verdict.model_dump_json()}\n"
            f"Related Signatures: {[str(sig) for sig in event.related_signatures]}\n"
            f"CBM Dependency Chain: {event.cbm_response.model_dump_json() if event.cbm_response else 'None'}\n"
            f"GTI IOC Data: {event.gti_response.model_dump_json() if event.gti_response else 'None'}\n"
        )

        try:
            create_kwargs = {
                "model": "gemini-3.8-flash",
                "input": prompt,
            }
            if not self.in_process:
                create_kwargs["background"] = True
                create_kwargs["webhook_config"] = {"uris": [self.webhook_url]}

            # Using the async client 'aio' if available, otherwise defaulting to synchronous client running in a thread.
            # Assuming google-genai 2.3.0+ supports aio for interactions
            if hasattr(self.client, "aio"):
                interaction = await self.client.aio.interactions.create(**create_kwargs)
            else:
                import asyncio

                interaction = await asyncio.to_thread(
                    self.client.interactions.create,
                    **create_kwargs,
                )

            task_id = interaction.id

            if self.in_process:
                # In-process mode: consume completed interaction immediately
                candidates = []
                if isinstance(interaction, dict):
                    candidates = interaction.get("threat_signature_candidates", [])
                elif hasattr(interaction, "parsed") and interaction.parsed is not None:
                    parsed = interaction.parsed
                    if hasattr(parsed, "threat_signature_candidates"):
                        candidates = parsed.threat_signature_candidates
                    elif isinstance(parsed, dict):
                        candidates = parsed.get("threat_signature_candidates", [])
                elif hasattr(interaction, "threat_signature_candidates"):
                    candidates = interaction.threat_signature_candidates

                signatures = []
                for candidate in candidates:
                    try:
                        from blackwall.analytics import AgentBehavioralAnalytics as ABA
                        aba_inst = ABA()
                        if hasattr(aba_inst, "generateSignature"):
                            sig = await aba_inst.generateSignature(candidate)
                        elif hasattr(aba_inst, "generate_signature"):
                            sig = await aba_inst.generate_signature(candidate)
                        else:
                            sig = candidate

                        if hasattr(sig, "model_dump"):
                            sig_payload = sig.model_dump()
                            sig_payload["signatureId"] = str(getattr(sig, "signature_id", sig_payload.get("signature_id", "")) or uuid4())
                            created_at_val = getattr(sig, "created_at", sig_payload.get("created_at", None))
                            if created_at_val:
                                if hasattr(created_at_val, "timestamp"):
                                    sig_payload["createdAt"] = int(created_at_val.timestamp())
                                else:
                                    try:
                                        sig_payload["createdAt"] = int(created_at_val)
                                    except Exception:
                                        sig_payload["createdAt"] = int(time.time())
                            else:
                                sig_payload["createdAt"] = int(time.time())
                            sig_payload["attackerIntent"] = getattr(sig, "description", getattr(sig, "attacker_intent", sig_payload.get("attacker_intent", sig_payload.get("description", ""))))
                            sig_payload["payloadPattern"] = getattr(sig, "pattern", getattr(sig, "payload_pattern", sig_payload.get("payload_pattern", sig_payload.get("pattern", ""))))
                            tool_val = getattr(sig, "target_tool", sig_payload.get("target_tool", None))
                            if not tool_val and event.tool_context:
                                tool_val = event.tool_context.tool_name
                            sig_payload["targetTool"] = tool_val or "unknown_tool"
                            sig_payload["targetSink"] = str(getattr(sig, "sink_type", getattr(sig, "target_sink", sig_payload.get("target_sink", sig_payload.get("sink_type", "")))))
                            sig_payload["mitigationAction"] = getattr(sig, "mitigation_action", sig_payload.get("mitigation_action", "BLOCK"))
                            sig_payload["dependencyChain"] = getattr(sig, "dependency_chain", sig_payload.get("dependency_chain", None))
                            sig_payload["similarityVector"] = getattr(sig, "similarity_vector", sig_payload.get("similarity_vector", None))
                            sig_payload["metadata"] = getattr(sig, "metadata", sig_payload.get("metadata", None))
                            signatures.append(sig_payload)
                        elif isinstance(sig, dict):
                            sig_dict = dict(sig)
                            sig_dict.setdefault("signatureId", str(sig.get("signature_id") or sig.get("signatureId") or uuid4()))
                            created = sig.get("createdAt") or sig.get("created_at")
                            if created and hasattr(created, "timestamp"):
                                sig_dict["createdAt"] = int(created.timestamp())
                            sig_dict.setdefault("attackerIntent", sig.get("attacker_intent") or sig.get("attackerIntent") or sig.get("description", ""))
                            sig_dict.setdefault("payloadPattern", sig.get("payload_pattern") or sig.get("payloadPattern") or sig.get("pattern", ""))
                            tool_val = sig.get("target_tool") or sig.get("targetTool")
                            if not tool_val and event.tool_context:
                                tool_val = event.tool_context.tool_name
                            sig_dict.setdefault("targetTool", tool_val or "unknown_tool")
                            sig_dict.setdefault("targetSink", str(sig.get("target_sink") or sig.get("targetSink") or sig.get("sink_type", "")))
                            sig_dict.setdefault("mitigationAction", sig.get("mitigation_action") or sig.get("mitigationAction", "BLOCK"))
                            sig_dict.setdefault("dependencyChain", sig.get("dependency_chain") or sig.get("dependencyChain"))
                            sig_dict.setdefault("similarityVector", sig.get("similarity_vector") or sig.get("similarityVector"))
                            sig_dict.setdefault("metadata", sig.get("metadata"))
                            signatures.append(sig_dict)
                        else:
                            signatures.append(sig)
                    except Exception as sig_err:
                        logger.warning(
                            f"Failed to generate signature for candidate in in-process mode: {sig_err}"
                        )

                if signatures and hasattr(self.repo, "write_signatures_batch"):
                    try:
                        await self.repo.write_signatures_batch(signatures)
                    except Exception as db_err:
                        logger.error(
                            f"Failed to persist signatures in in-process mode: {db_err}"
                        )

                await self.repo.add_background_task(task_id, "COMPLETED")
            else:
                await self.repo.add_background_task(task_id, "PENDING_WEBHOOK_CALLBACK")

            logger.info(
                f"Submitted background analysis task. task_id={task_id}, timestamp={event.timestamp.isoformat()}"
            )

            return task_id

        except Exception as e:
            logger.error(f"Failed to submit background analysis task: {str(e)}")
            # Fail-closed implies we return None; the action (BLOCK/QUARANTINE) is already decided
            return None
