import logging
from typing import Optional
from google import genai

from blackwall.models import SecurityEvent, VerdictDecision
from blackwall.db.repository import SQLiteThreatRepository

logger = logging.getLogger(__name__)

class AgentBehavioralAnalytics:
    def __init__(self, repo: SQLiteThreatRepository, client: Optional[genai.Client] = None):
        self.repo = repo
        self.client = client or genai.Client()
        self.webhook_url = "http://localhost:8090/webhook/analysis_complete"

    async def submitBackgroundAnalysis(self, event: SecurityEvent) -> Optional[str]:
        if not event.verdict or event.verdict.decision not in {VerdictDecision.BLOCK, VerdictDecision.QUARANTINE}:
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
            # Using the async client 'aio' if available, otherwise defaulting to synchronous client running in a thread.
            # Assuming google-genai 2.3.0+ supports aio for interactions
            if hasattr(self.client, 'aio'):
                interaction = await self.client.aio.interactions.create(
                    model="gemini-3.1-pro-preview",
                    input=prompt,
                    background=True,
                    webhook_config={"uris": [self.webhook_url]}
                )
            else:
                import asyncio
                interaction = await asyncio.to_thread(
                    self.client.interactions.create,
                    model="gemini-3.1-pro-preview",
                    input=prompt,
                    background=True,
                    webhook_config={"uris": [self.webhook_url]}
                )
            
            task_id = interaction.id
            
            await self.repo.add_background_task(task_id, "PENDING_WEBHOOK_CALLBACK")
            
            logger.info(f"Submitted background analysis task. task_id={task_id}, timestamp={event.timestamp.isoformat()}")
            
            return task_id
            
        except Exception as e:
            logger.error(f"Failed to submit background analysis task: {str(e)}")
            # Fail-closed implies we return None; the action (BLOCK/QUARANTINE) is already decided
            return None
