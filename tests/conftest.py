import pytest
import structlog
from structlog.testing import LogCapture
from unittest.mock import AsyncMock


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
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)


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
def mock_gti_client() -> AsyncMock:
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


# ---------------------------------------------------------------------------
# Weave evaluation marker: collection-time skip + detector_suite fixture
# ---------------------------------------------------------------------------

def _has_wandb_credentials() -> bool:
    """Check for W&B credentials in standard file locations.

    Mirrors the 4th enablement path in should_enable_weave():
    netrc (~/.netrc, host api.wandb.ai) or W&B config file (~/.config/wandb/settings).
    Returns True only when a non-empty, non-placeholder API key value is found.
    """
    import netrc
    import pathlib

    # netrc check — authenticators() returns (login, account, password); password is the key
    try:
        creds = netrc.netrc()
        auth = creds.authenticators("api.wandb.ai")
        if auth and auth[2] and auth[2].strip():
            return True
    except (FileNotFoundError, netrc.NetrcParseError, OSError):
        pass

    # W&B config file check (wandb >= 0.12 stores api_key in INI-style settings)
    # Parse with configparser to avoid false-positives from commented lines or
    # empty values (e.g. "api_key =", "# api_key = ...", "api_key = None").
    settings_path = pathlib.Path.home() / ".config" / "wandb" / "settings"
    try:
        if settings_path.exists():
            import configparser
            parser = configparser.ConfigParser()
            parser.read(settings_path)
            for section in parser.sections():
                val = parser.get(section, "api_key", fallback="")
                if val.strip() and val.strip().lower() not in ("none", "null", '""', "''"):
                    return True
    except (OSError, configparser.Error):
        # Malformed or unreadable settings file — treat as no credentials
        pass

    return False


def _weave_available() -> bool:
    """Return True if Weave is enabled and the weave package is importable.

    Priority order (mirrors should_enable_weave()):
    1. WEAVE_DISABLED=true  → False (always wins)
    2. WEAVE_OFFLINE=true   → True if weave importable (local traces, no credentials)
    3. WANDB_API_KEY set    → True if weave importable
    4. netrc / config creds → True if weave importable
    5. (none of the above)  → False
    """
    import os
    if os.getenv("WEAVE_DISABLED") == "true":
        return False

    def _weave_importable() -> bool:
        try:
            import weave  # noqa: F401
            return True
        except ImportError:
            return False

    if os.getenv("WEAVE_OFFLINE") == "true":
        return _weave_importable()
    if os.getenv("WANDB_API_KEY"):
        return _weave_importable()
    if _has_wandb_credentials():
        return _weave_importable()
    return False


def pytest_collection_modifyitems(items: list) -> None:
    """Auto-skip @pytest.mark.weave tests when Weave is unavailable.

    This makes the marker description in pyproject.toml accurate: tests
    are collected but skipped with a clear reason rather than failing with
    ImportError or producing misleading results.
    """
    if _weave_available():
        return  # Weave is active; nothing to skip

    skip_reason = pytest.mark.skip(
        reason=(
            "Weave not available: set WANDB_API_KEY or WEAVE_OFFLINE=true "
            "and ensure 'weave' is installed (pip install -e \".[weave]\"). "
            "Set WEAVE_DISABLED=true to suppress this message entirely."
        )
    )
    for item in items:
        if item.get_closest_marker("weave"):
            item.add_marker(skip_reason)


@pytest.fixture
def detector_suite(request):
    """Yield a DetectorSuite with traced or bare components based on the weave marker.

    - @pytest.mark.weave tests: WeaveTraced* wrappers (when should_enable_weave() is True)
    - All other tests: bare components, zero Weave overhead regardless of env vars

    Marker state is read via request.node.get_closest_marker() — pytest's
    stable public API. build_detector_suite() has no marker-detection logic.
    """
    try:
        from blackwall.enterprise.advanced_threat_detection.weave_factory import (
            build_detector_suite,
        )
        from blackwall.enterprise.advanced_threat_detection.correlator import PathCorrelator
        from blackwall.enterprise.advanced_threat_detection.collector import EventStreamCollector
        from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
    except ImportError:
        pytest.skip("Advanced threat detection components not yet implemented")
        return

    marked = request.node.get_closest_marker("weave") is not None
    return build_detector_suite(
        correlator=PathCorrelator(),
        swarm_detector=None,   # placeholder until AgentSwarmDetector is implemented
        ailm_tracker=None,
        exploit_analyzer=None,
        c2_detector=None,
        force_traced=marked,
    )
