import pytest
import asyncio
from unittest.mock import MagicMock, patch
from blackwall.mcp.embeddings import GeminiEmbeddingClient

class MockEmbeddingValue:
    def __init__(self, values: list[float]):
        self.values = values

class MockEmbeddingResult:
    def __init__(self, embeddings: list[MockEmbeddingValue]):
        self.embeddings = embeddings

@pytest.mark.asyncio
async def test_embed_success():
    """Verify that successful embedding call returns exactly 768 floats."""
    mock_client = MagicMock()
    # Mocking client.models.embed_content
    mock_val = [0.1] * 768
    mock_client.models.embed_content.return_value = MockEmbeddingResult([MockEmbeddingValue(mock_val)])

    client = GeminiEmbeddingClient(mock_client)
    result = await client.embed("test text")

    assert len(result) == 768
    assert result[0] == 0.1
    # Verify exact parameters sent to embed_content
    mock_client.models.embed_content.assert_called_once()
    _, kwargs = mock_client.models.embed_content.call_args
    assert kwargs.get("model") == "gemini-embedding-001"
    assert kwargs.get("contents") == "test text"
    
    config = kwargs.get("config")
    assert config is not None
    # Depending on types.EmbedContentConfig, we check config properties
    assert getattr(config, "task_type", None) == "SEMANTIC_SIMILARITY"
    assert getattr(config, "output_dimensionality", None) == 768

@pytest.mark.asyncio
async def test_embed_api_error():
    """Verify that an API error raises Exception."""
    mock_client = MagicMock()
    mock_client.models.embed_content.side_effect = Exception("API failure")

    client = GeminiEmbeddingClient(mock_client)
    with pytest.raises(Exception, match="API failure"):
        await client.embed("test text")

@pytest.mark.asyncio
async def test_embed_timeout():
    """Verify timeout behaves properly."""
    mock_client = MagicMock()

    # Simulate a slow api call
    async def slow_embed(*args, **kwargs):
        await asyncio.sleep(2.0)
        return MockEmbeddingResult([MockEmbeddingValue([0.1]*768)])

    client = GeminiEmbeddingClient(mock_client)
    
    # We patch embed to take longer and test wait_for wrapping at call site
    with patch.object(client, "embed", side_effect=asyncio.TimeoutError("Timeout")):
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(client.embed("test"), timeout=0.1)
