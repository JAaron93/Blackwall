"""TDD coverage for TASK-G06 recording infrastructure and README integration.

The pure-Python helpers in ``scripts.gateway_demo.recording`` generate
asciinema-v2 ``.cast`` files and self-contained SVG thumbnails without
requiring asciinema/tmux to be installed (CI-safe path). The shell scripts
delegate to these helpers so recordings are reproducible on any platform.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RECORDINGS_DIR = REPO_ROOT / "docs" / "recordings"
README = REPO_ROOT / "README.md"

EXPECTED_KEYS = ("honeypot", "heist", "quarantine", "poisoned_package", "bouncer")


def _import_recording():
    from scripts.gateway_demo import recording

    return recording


def test_scenario_registry_covers_all_five_demos():
    recording = _import_recording()
    assert tuple(s.key for s in recording.SCENARIOS) == EXPECTED_KEYS
    for scenario in recording.SCENARIOS:
        assert scenario.title
        assert scenario.owasp.startswith("https://")
        assert scenario.mitre.startswith("https://")
        assert scenario.cast_file == f"{scenario.key}.cast"
        assert scenario.thumbnail_file == f"{scenario.key}.svg"
        if scenario.key != "honeypot":
            assert scenario.module.startswith("scripts.gateway_demo.scenario_")


def test_build_cast_is_valid_asciinema_v2_with_bounded_events():
    recording = _import_recording()
    lines = ["line one", "line two", "line three"]
    cast = recording.build_cast(
        lines, title="The Heist", width=100, height=24, timestamp=1000, step=0.25
    )
    rows = [json.loads(line) for line in cast.splitlines()]
    header = rows[0]
    assert header["version"] == 2
    assert header["width"] == 100
    assert header["height"] == 24
    assert header["title"] == "The Heist"
    events = rows[1:]
    assert len(events) == len(lines)
    assert all(len(event) == 3 and event[1] == "o" for event in events)
    times = [event[0] for event in events]
    assert times == sorted(times)
    assert times == pytest.approx([0.25, 0.5, 0.75])
    assert [event[2] for event in events] == [f"{line}\r\n" for line in lines]


def test_build_cast_bounds_oversized_output():
    recording = _import_recording()
    cast = recording.build_cast([f"line {i}" for i in range(500)], title="x")
    rows = [json.loads(line) for line in cast.splitlines()]
    assert len(rows) - 1 <= recording.MAX_CAST_LINES
    assert any("truncated" in event[2] for event in rows[1:])


def test_redact_output_masks_real_home_and_secret_patterns():
    recording = _import_recording()
    text = (
        "read /Users/real-operator/.ssh/id_rsa\n"
        "key=AKIA1234567890ABCDEF\n"
        "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
        "sk-abcdefghijklmnopqrstuvwxyz0123456789\n"
    )
    redacted = recording.redact_output(text, home="/Users/real-operator")
    assert "/Users/real-operator" not in redacted
    assert "~/" in redacted
    assert "AKIA1234567890ABCDEF" not in redacted
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in redacted
    assert "sk-abcdefghijklmnopqrstuvwxyz0123456789" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_output_masks_json_fields_and_private_key_blocks():
    recording = _import_recording()
    text = (
        '{"token": "demo-json-secret", "api_key": "another-json-secret"}\n'
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA2secretkeymaterial\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    redacted = recording.redact_output(text)
    assert "demo-json-secret" not in redacted
    assert "another-json-secret" not in redacted
    assert "MIIEowIBAAKCAQEA2secretkeymaterial" not in redacted
    assert "[REDACTED]" in redacted
    assert "[REDACTED PRIVATE KEY BLOCK]" in redacted


def test_sanitize_cast_redacts_existing_live_capture(tmp_path: Path):
    recording = _import_recording()
    cast = tmp_path / "live.cast"
    cast.write_text(
        '{"version": 2, "width": 120, "height": 30}\n'
        '[0.1, "o", "traceback token=live-secret-value\\r\\n"]\n',
        encoding="utf-8",
    )
    result = recording.sanitize_cast(cast)
    assert result == cast
    text = cast.read_text()
    assert "live-secret-value" not in text
    assert "[REDACTED]" in text
    rows = [json.loads(line) for line in text.splitlines()]
    assert rows[0]["version"] == 2
    assert rows[1][1] == "o"


def test_write_cast_and_thumbnail_roundtrip(tmp_path: Path):
    recording = _import_recording()
    scenario = recording.SCENARIO_BY_KEY["heist"]
    lines = ["ALLOW read_url", "BLOCK read_file (-32603)"]
    cast_path = recording.write_cast(
        tmp_path / scenario.cast_file,
        lines,
        title=scenario.title,
        timestamp=1000,
    )
    svg_path = recording.write_thumbnail(
        tmp_path / scenario.thumbnail_file, lines, title=scenario.title
    )
    assert cast_path.exists() and svg_path.exists()
    assert next(json.loads(line) for line in cast_path.read_text().splitlines())["version"] == 2
    svg = svg_path.read_text()
    assert svg.lstrip().startswith("<svg")
    assert "The Heist" in svg
    assert "BLOCK read_file (-32603)" in svg


def test_thumbnail_escapes_markup_and_bounds_lines():
    recording = _import_recording()
    lines = ["<script>alert('x')</script> & more"] + [f"event {i}" for i in range(80)]
    svg = recording.render_svg_thumbnail(lines, title="A & B <demo>")
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg
    assert "&amp;" in svg
    assert "A &amp; B &lt;demo&gt;" in svg
    assert "truncated" in svg


def test_committed_recording_assets_are_valid_and_complete():
    recording = _import_recording()
    assert RECORDINGS_DIR.is_dir()
    for scenario in recording.SCENARIOS:
        cast_path = RECORDINGS_DIR / scenario.cast_file
        svg_path = RECORDINGS_DIR / scenario.thumbnail_file
        assert cast_path.is_file(), f"missing {cast_path}"
        assert svg_path.is_file(), f"missing {svg_path}"
        rows = [json.loads(line) for line in cast_path.read_text().splitlines()]
        assert rows[0]["version"] == 2
        assert rows[0]["title"] == scenario.title
        assert svg_path.read_text().lstrip().startswith("<svg")


def test_isolated_exec_survives_existing_process_group(monkeypatch):
    from scripts.gateway_demo import _isolated_exec

    calls = []
    monkeypatch.setattr(
        _isolated_exec.os,
        "setsid",
        lambda: (_ for _ in ()).throw(OSError("already a group leader")),
    )
    monkeypatch.setattr(_isolated_exec.os, "execvp", lambda *a: calls.append(a))
    assert _isolated_exec.main(["python3", "-m", "demo"]) == 127
    assert calls == [("python3", ["python3", "-m", "demo"])]
    assert _isolated_exec.main([]) == 2


def test_readme_has_gateway_demos_section_with_all_five_scenarios():
    recording = _import_recording()
    readme = README.read_text()
    assert "## 🛡️ MCP Gateway Demos" in readme
    assert "./scripts/gateway_demo/run_gateway_demo.sh" in readme
    assert "indirect prompt injection" in readme.lower()
    for scenario in recording.SCENARIOS:
        assert scenario.title in readme
        assert scenario.owasp in readme
        assert scenario.mitre in readme
        assert f"docs/recordings/{scenario.thumbnail_file}" in readme
        assert f"docs/recordings/{scenario.cast_file}" in readme
