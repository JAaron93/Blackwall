"""Unit tests for Weave configuration and initialization infrastructure (Subtask 22.1)."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from blackwall.enterprise.advanced_threat_detection.weave_config import (
    WeaveConfig,
    has_wandb_credentials,
    init_weave,
    load_weave_config,
    should_enable_weave,
)


def test_weave_config_defaults() -> None:
    config = WeaveConfig(project_name="test-project")
    assert config.project_name == "test-project"
    assert config.entity is None
    assert config.offline_mode is False
    assert config.parallelism == 1
    assert config.tags == []


def test_weave_config_custom() -> None:
    config = WeaveConfig(
        project_name="custom-project",
        entity="security-team",
        offline_mode=True,
        parallelism=5,
        tags=["redteam", "eval"],
    )
    assert config.project_name == "custom-project"
    assert config.entity == "security-team"
    assert config.offline_mode is True
    assert config.parallelism == 5
    assert config.tags == ["redteam", "eval"]


def test_should_enable_weave_disabled_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEAVE_DISABLED", "true")
    monkeypatch.setenv("WEAVE_OFFLINE", "true")
    monkeypatch.setenv("WANDB_API_KEY", "dummy_key")
    assert should_enable_weave() is False


def test_should_enable_weave_offline_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEAVE_DISABLED", raising=False)
    monkeypatch.setenv("WEAVE_OFFLINE", "true")
    monkeypatch.delenv("WANDB_API_KEY", raising=False)
    assert should_enable_weave() is True


def test_should_enable_weave_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEAVE_DISABLED", raising=False)
    monkeypatch.delenv("WEAVE_OFFLINE", raising=False)
    monkeypatch.setenv("WANDB_API_KEY", "dummy_api_key")
    assert should_enable_weave() is True


def test_should_enable_weave_credentials_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("WEAVE_DISABLED", raising=False)
    monkeypatch.delenv("WEAVE_OFFLINE", raising=False)
    monkeypatch.delenv("WANDB_API_KEY", raising=False)

    with patch(
        "blackwall.enterprise.advanced_threat_detection.weave_config.has_wandb_credentials",
        return_value=True,
    ):
        assert should_enable_weave() is True

    with patch(
        "blackwall.enterprise.advanced_threat_detection.weave_config.has_wandb_credentials",
        return_value=False,
    ):
        assert should_enable_weave() is False


def test_has_wandb_credentials_netrc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("WANDB_API_KEY", raising=False)
    mock_netrc_content = "machine api.wandb.ai login user password test-netrc-key\n"
    netrc_file = tmp_path / ".netrc"
    netrc_file.write_text(mock_netrc_content)

    with patch("netrc.netrc") as mock_netrc:
        mock_instance = MagicMock()
        mock_instance.authenticators.return_value = (
            "user",
            "account",
            "test-netrc-key",
        )
        mock_netrc.return_value = mock_instance
        assert has_wandb_credentials() is True


def test_has_wandb_credentials_wandb_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("WANDB_API_KEY", raising=False)
    settings_dir = tmp_path / ".config" / "wandb"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_file = settings_dir / "settings"
    settings_file.write_text("[default]\napi_key = test-config-key\n")

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    with patch("netrc.netrc", side_effect=FileNotFoundError):
        assert has_wandb_credentials() is True


def test_load_weave_config_from_file(tmp_path: Path) -> None:
    yaml_content = """
weave:
  project_name: "custom-yaml-project"
  entity: "custom-entity"
  offline_mode: true
  parallelism: 4
  tags:
    - "atd"
    - "benchmark"
"""
    config_file = tmp_path / "weave_config.yaml"
    config_file.write_text(yaml_content)

    config = load_weave_config(str(config_file))
    assert config.project_name == "custom-yaml-project"
    assert config.entity == "custom-entity"
    assert config.offline_mode is True
    assert config.parallelism == 4
    assert config.tags == ["atd", "benchmark"]


def test_load_weave_config_fallback_on_missing(tmp_path: Path) -> None:
    non_existent = str(tmp_path / "missing.yaml")
    config = load_weave_config(non_existent)
    assert config.project_name == "blackwall-advanced-threat-detection"
    assert config.offline_mode is False


def test_init_weave_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEAVE_DISABLED", "true")
    assert init_weave() is False


def test_init_weave_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEAVE_DISABLED", raising=False)
    monkeypatch.setenv("WEAVE_OFFLINE", "true")

    mock_weave_module = MagicMock()
    with patch(
        "blackwall.enterprise.advanced_threat_detection.weave_config.weave",
        mock_weave_module,
    ):
        res = init_weave(WeaveConfig(project_name="my-test-proj"))
        assert res is True
        mock_weave_module.init.assert_called_once()
