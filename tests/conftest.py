import pytest
import structlog

pytest_plugins = ["pytester"]
from structlog.testing import LogCapture
from unittest.mock import AsyncMock

from dotenv import load_dotenv

# Make gitignored .env credentials (e.g. BW_OTX_API_KEY) visible to tests the
# same way scripts/ loads them. override=False: real environment always wins.
load_dotenv(override=False)


@pytest.fixture(name="log_output")
def fixture_log_output() -> LogCapture:
    return LogCapture()


@pytest.fixture(autouse=True)
def fixture_gcp_vertex_ai_env(monkeypatch) -> None:
    """Ensure GCP Vertex AI Mode environment variables are present during tests."""
    monkeypatch.setenv("GCP_PROJECT", "dummy-gcp-project")
    monkeypatch.setenv("GCP_LOCATION", "global")
    monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
    monkeypatch.setenv("GEMINI_TIER", "paid")
    monkeypatch.setenv("BLACKWALL_TIER", "paid")
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "none")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)


@pytest.fixture(autouse=True)
def fixture_reset_kernel_probe_drivers():
    """Ensure kernel probe drivers and audit hooks are reset and deactivated after each test."""
    yield
    try:
        from blackwall.enterprise.kernel.probe import KernelProbeDriver

        KernelProbeDriver.reset_all_active_instances()
    except (ImportError, Exception):
        pass


@pytest.fixture(autouse=True)
def fixture_configure_structlog(log_output: LogCapture) -> None:
    structlog.configure(
        processors=[log_output],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )


@pytest.fixture
def clean_sqlite():
    def _clean(db_path: str) -> None:
        from pathlib import Path

        for path in (db_path, f"{db_path}-wal", f"{db_path}-journal", f"{db_path}-shm"):
            try:
                Path(path).unlink(missing_ok=True)
            except PermissionError:
                pass

    return _clean


@pytest.fixture
def mock_cbm_client() -> AsyncMock:
    client = AsyncMock()
    client.queryDependencyChain = AsyncMock(return_value="mock_dep_chain")
    client.identifyCriticalSinks = AsyncMock(return_value="mock_sinks")
    client.traceDataFlow = AsyncMock(return_value="mock_data_flow")
    client.getBlastRadius = AsyncMock(return_value="mock_blast_radius")
    return client


@pytest.fixture
def mock_ti_client() -> AsyncMock:
    client = AsyncMock()
    client.lookup_ip = AsyncMock(return_value="mock_ip")
    client.lookup_url = AsyncMock(return_value="mock_url")
    client.lookup_domain = AsyncMock(return_value="mock_domain")
    client.lookup_file_hash = AsyncMock(return_value="mock_hash")
    return client


@pytest.fixture
def safe_sla_limit():
    def _helper(env_var: str, default: float) -> float:
        import os
        import math

        if not math.isfinite(default) or default <= 0.0:
            raise ValueError(f"Invalid default SLA limit: {default}")
        val_str = os.getenv(env_var)
        if not val_str:
            return default
        try:
            val = float(val_str)
            if math.isfinite(val) and val > 0.0:
                return val
        except ValueError:
            pass
        return default

    return _helper


@pytest.fixture
def hermetic_vertexai_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the managed EvalTask path hermetic on hosts without the optional SDK.

    ``GCPVertexAIEvaluationHarness.run_eval_task`` imports three modules as a
    group: ``vertexai.preview.evaluation``, ``vertexai.generative_models`` and
    ``google.cloud.aiplatform_v1beta1.types.content``. The SDK ships only in the
    optional ``evaluation``/``eval`` extras, so stubbing just ``EvalTask`` still
    leaves the cloud path failing with ``ModuleNotFoundError``. This fixture
    installs minimal stand-ins for that whole import surface and is a no-op when
    the real SDK is present. Request it explicitly in tests that force the
    managed gate; unrelated tests keep their existing environment.
    """
    import importlib.util
    import sys
    import types
    from unittest.mock import MagicMock

    if importlib.util.find_spec("vertexai") is not None:
        return

    def ensure_package(name: str) -> types.ModuleType:
        existing = sys.modules.get(name)
        if existing is not None:
            return existing
        package = types.ModuleType(name)
        package.__path__ = []  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, name, package)
        if "." in name:
            parent_name, _, child_name = name.rpartition(".")
            parent = ensure_package(parent_name)
            monkeypatch.setattr(parent, child_name, package, raising=False)
        return package

    class StubGenerationConfig:
        """Mirrors the config layout ``run_eval_task`` inspects on the model."""

        def __init__(self, **kwargs: object) -> None:
            self._values = dict(kwargs)
            self.max_output_tokens = kwargs.get("max_output_tokens")
            self._raw_generation_config = types.SimpleNamespace(thinking_config=None)

        def to_dict(self) -> dict:
            return dict(self._values)

    class StubGenerativeModel:
        def __init__(
            self,
            model_name: str,
            generation_config: StubGenerationConfig | None = None,
        ) -> None:
            self.model_name = model_name
            self._generation_config = generation_config or StubGenerationConfig()

    class StubThinkingConfig:
        def __init__(self, **kwargs: object) -> None:
            for key, value in kwargs.items():
                setattr(self, key, value)

    # from google.cloud.aiplatform_v1beta1.types import content
    types_package = ensure_package("google.cloud.aiplatform_v1beta1.types")
    content = types.ModuleType("google.cloud.aiplatform_v1beta1.types.content")
    content.GenerationConfig = types.SimpleNamespace(ThinkingConfig=StubThinkingConfig)
    monkeypatch.setitem(sys.modules, content.__name__, content)
    monkeypatch.setattr(types_package, "content", content, raising=False)

    # import vertexai; vertexai.init(...)
    vertexai = ensure_package("vertexai")
    monkeypatch.setattr(vertexai, "init", lambda **kwargs: None, raising=False)

    # from vertexai.preview.evaluation import AutoraterConfig, EvalTask
    preview = ensure_package("vertexai.preview")
    evaluation = types.ModuleType("vertexai.preview.evaluation")
    evaluation.EvalTask = MagicMock(name="EvalTask")
    evaluation.AutoraterConfig = MagicMock(name="AutoraterConfig")
    monkeypatch.setitem(sys.modules, evaluation.__name__, evaluation)
    monkeypatch.setattr(preview, "evaluation", evaluation, raising=False)

    # from vertexai.generative_models import GenerativeModel, GenerationConfig
    generative_models = types.ModuleType("vertexai.generative_models")
    generative_models.GenerativeModel = StubGenerativeModel
    generative_models.GenerationConfig = StubGenerationConfig
    monkeypatch.setitem(sys.modules, generative_models.__name__, generative_models)
    monkeypatch.setattr(vertexai, "generative_models", generative_models, raising=False)
