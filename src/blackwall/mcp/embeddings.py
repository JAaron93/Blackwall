import asyncio
import logging
from typing import Any, List
from google.genai import types

logger = logging.getLogger(__name__)

class GeminiEmbeddingClient:
    """
    Client for interacting with the Gemini Embedding API to generate
    high-dimensional threat signature vectors.
    """

    def __init__(self, client: Any) -> None:
        self.client = client

    async def embed(self, text: str) -> List[float]:
        """
        Generates a 768-dimensional float embedding vector for the given text
        using the gemini-embedding-001 model.
        """
        model_name = "gemini-embedding-001"
        config = types.EmbedContentConfig(
            task_type="SEMANTIC_SIMILARITY",
            output_dimensionality=768
        )

        try:
            # Check if an async client (aio) is available and if its embed_content is awaitable
            use_async = False
            if hasattr(self.client, "aio") and self.client.aio is not None:
                models = getattr(self.client.aio, "models", None)
                if models is not None:
                    embed_fn = getattr(models, "embed_content", None)
                    if embed_fn is not None:
                        from unittest.mock import AsyncMock
                        import inspect
                        if isinstance(embed_fn, AsyncMock) or inspect.iscoroutinefunction(embed_fn):
                            use_async = True

            if use_async:
                response = await self.client.aio.models.embed_content(
                    model=model_name,
                    contents=text,
                    config=config
                )
            else:
                # Fallback to run in executor for synchronous client method
                loop = asyncio.get_running_loop()
                response = await loop.run_in_executor(
                    None,
                    lambda: self.client.models.embed_content(
                        model=model_name,
                        contents=text,
                        config=config
                    )
                )

            if not response or not response.embeddings:
                raise ValueError("Embedding API returned empty response")

            # Extract floats list
            return response.embeddings[0].values

        except Exception as e:
            logger.error(f"Gemini Embedding API call failed: {e}")
            raise
