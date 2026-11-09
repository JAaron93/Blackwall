"""Fleet-parseability regression for the project's `[tool.uv]` settings.

Older uv releases abort settings discovery on values they cannot parse and then
silently drop the entire `[tool.uv]` block (warn + exit 0) — including settings
like `prerelease` and any future `required-version`. Nothing about a parse-failed
block can self-guard, so the only defense that reaches old uv is a manifest that
parses fleet-wide. This test asserts exactly that: the live `[tool.uv]` table,
executed by a pinned pre-cooldown uv binary, resolves without a parse warning.

The probe reads the table from `pyproject.toml` itself (not a copy), so any
manifest change is automatically executed against the pinned old uv — the
check cannot drift out of sync with the manifest it guards.

Requires network on first run (the pinned uv binary is fetched via `uvx` from
PyPI and then cached); skips gracefully when the tool environment is unavailable.
"""

import json
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
OLD_UV = "0.9.5"  # ship date predates duration cooldowns; cannot parse relative cooldowns
TOOL_UV_TABLE = ("tool", "uv")
_TIMEOUT_LOCK_S = 240


def _format_toml_value(value: object) -> str:
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, (bool, int, float)):
        return json.dumps(value)
    raise AssertionError(
        "[tool.uv] grew a nested/complex value; extend the probe serializer to cover it"
    )


def _fetch_old_uv(uvx: str) -> None:
    """Warm (and verify) the pinned uv tool environment; skip when unavailable."""
    probe = subprocess.run(
        [uvx, "--from", f"uv=={OLD_UV}", "uv", "--version"],
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_LOCK_S,
    )
    if probe.returncode != 0:
        pytest.skip(f"uv {OLD_UV} tool environment unavailable (offline?): {probe.stderr[-200:]}")


def test_tool_uv_settings_parse_under_pre_cooldown_uv(tmp_path: Path) -> None:
    uvx = shutil.which("uvx") or shutil.which("uv")
    if not uvx:
        pytest.skip("uv CLI not installed")
    _fetch_old_uv(uvx)

    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    table: dict[str, object] = project
    for key in TOOL_UV_TABLE:
        try:
            table = table[key]
        except KeyError as exc:  # pragma: no cover - manifest regression, not env
            pytest.fail(f"{REPO_ROOT / 'pyproject.toml'} is missing [{']['.join(TOOL_UV_TABLE)}]: {exc}")

    lines = [
        '[project]',
        'name = "tool-uv-fleet-parse-probe"',
        'version = "0.0.1"',
        'requires-python = ">=3.9"',
        "",
        f"[{'.'.join(TOOL_UV_TABLE)}]",
    ]
    lines.extend(f"{key} = {_format_toml_value(value)}" for key, value in table.items())
    (tmp_path / "pyproject.toml").write_text("\n".join(lines) + "\n")

    result = subprocess.run(
        [uvx, "--from", f"uv=={OLD_UV}", "uv", "lock"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_LOCK_S,
    )
    output = result.stdout + result.stderr

    assert result.returncode == 0, f"old uv rejected [tool.uv] settings: {output[-800:]}"
    assert "Failed to parse" not in output, (
        "[tool.uv] no longer parses under pre-cooldown uv: settings would be "
        f"silently dropped (warn + exit 0) on older uv releases: {output[-800:]}"
    )
    assert "Resolved" in output, f"old uv did not complete resolution: {output[-800:]}"
