"""Recording helpers for the MCP Gateway demo suite (TASK-G06).

This module is the portable core behind ``record_demo.sh``. It writes
asciinema-v2 ``.cast`` files and self-contained SVG thumbnails from captured
demo output, so recording infrastructure works on CI hosts where neither
``asciinema`` nor ``tmux`` is installed. When those tools *are* available the
shell script records a live split-pane session with them and still uses this
module for the README thumbnail.

Security invariant: every line that enters a cast or thumbnail is passed
through :func:`redact_output` before serialization. Demo fixtures are
synthetic, but a recording must never leak an operator's real home path or
credential-shaped values even if a scenario prints them.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from html import escape
from pathlib import Path

CAST_VERSION = 2
DEFAULT_WIDTH = 120
DEFAULT_HEIGHT = 30
DEFAULT_STEP = 0.08
MAX_CAST_LINES = 240
MAX_THUMBNAIL_LINES = 18

OWASP_LLM01 = "https://genai.owasp.org/"
OWASP_LLM05 = "https://genai.owasp.org/"
OWASP_LLM07 = "https://genai.owasp.org/"
MITRE_T0051 = "https://atlas.mitre.org/techniques/AML.T0051"
MITRE_T0054 = "https://atlas.mitre.org/techniques/AML.T0054"
MITRE_T0049 = "https://atlas.mitre.org/techniques/AML.T0049"


@dataclass(frozen=True)
class DemoScenario:
    """Metadata shared by the demo scripts, the recorder and the README."""

    key: str
    title: str
    module: str | None
    owasp: str
    mitre: str
    summary: str
    verdicts: tuple[str, ...]

    @property
    def cast_file(self) -> str:
        return f"{self.key}.cast"

    @property
    def thumbnail_file(self) -> str:
        return f"{self.key}.svg"


SCENARIOS: tuple[DemoScenario, ...] = (
    DemoScenario(
        key="honeypot",
        title="The Honeypot",
        module=None,  # long-running FastAPI server, not a terminating script
        owasp=OWASP_LLM01,
        mitre=MITRE_T0051,
        summary=(
            "Locally hosted fake library docs carrying hidden indirect prompt "
            "injection payloads and a simulated C2 capture endpoint."
        ),
        verdicts=("served /docs/fake-library", "served /docs/compromised-response"),
    ),
    DemoScenario(
        key="heist",
        title="The Heist",
        module="scripts.gateway_demo.scenario_heist",
        owasp=OWASP_LLM01,
        mitre=MITRE_T0051,
        summary=(
            "A poisoned webpage hijacks an agent into reading a credential file "
            "and POSTing it to attacker C2; the gateway blocks both steps."
        ),
        verdicts=(
            "ALLOW read_url (research continues)",
            "BLOCK read_file (-32603) threat_score=0.95",
            "BLOCK http_request (-32603) threat_score=0.95",
            "zero POSTs reached /exfil",
        ),
    ),
    DemoScenario(
        key="quarantine",
        title="The Quarantine",
        module="scripts.gateway_demo.scenario_quarantine",
        owasp=OWASP_LLM07,
        mitre=MITRE_T0054,
        summary=(
            "Surgical isolation: legitimate write_file calls are ALLOW'd while a "
            "credential-harvesting read_file is BLOCK'd, without killing the session."
        ),
        verdicts=(
            "ALLOW write_file (downstream confirmed)",
            "BLOCK read_file (-32603) threat_score=0.95",
            "ALLOW write_file (session continuity)",
        ),
    ),
    DemoScenario(
        key="poisoned_package",
        title="The Poisoned Package",
        module="scripts.gateway_demo.scenario_poisoned_package",
        owasp=OWASP_LLM05,
        mitre=MITRE_T0049,
        summary=(
            "The gateway ALLOW's a legitimate pip install, but the Python audit "
            "hook blocks the postinstall script's runtime escapes."
        ),
        verdicts=(
            "ALLOW run_command (protocol layer)",
            "PermissionError subprocess.Popen (audit layer)",
            "PermissionError os.system (audit layer)",
            "PermissionError socket.connect (audit layer)",
        ),
    ),
    DemoScenario(
        key="bouncer",
        title="The Bouncer",
        module="scripts.gateway_demo.scenario_bouncer",
        owasp=OWASP_LLM01,
        mitre=MITRE_T0051,
        summary=(
            "Tier-1 Jev fast path handles clear cases while only an ambiguous "
            "probe escalates to Gemini Tier-2 deep reasoning."
        ),
        verdicts=(
            "ALLOW get_weather (jev fast path, P=0.02)",
            "BLOCK execute_bash (jev fast path, P=0.98)",
            "BLOCK http_request (gemini-tier-2 escalation, P=0.25)",
        ),
    ),
)

SCENARIO_BY_KEY: dict[str, DemoScenario] = {s.key: s for s in SCENARIOS}
SCENARIO_KEYS: tuple[str, ...] = tuple(s.key for s in SCENARIOS)

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Whole PEM blocks first: masking only the header leaves the key body visible.
    (
        re.compile(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[REDACTED PRIVATE KEY BLOCK]",
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED]"),
    # JSON fields: the closing quote of the key sits between the name and ':'.
    (
        re.compile(r'(?i)("(?:api[_-]?key|token|secret|passwd|password)"\s*:\s*")([^"]+)'),
        r"\1[REDACTED]",
    ),
    # Bare or quoted assignments: keep any opening quote and restore it.
    (
        re.compile(r"(?i)\b(api[_-]?key|token|secret|passwd|password)(\s*[:=]\s*)([\"']?)([^\s,;}\"']+)"),
        r"\1\2\3[REDACTED]\3",
    ),
)


def redact_output(text: str, *, home: str | Path | None = None) -> str:
    """Mask operator home paths and credential-shaped values in captured text."""
    redacted = text
    home_str = str(home) if home is not None else str(Path.home())
    if home_str and home_str != "/":
        redacted = redacted.replace(home_str, "~")
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _bounded_lines(lines: Sequence[str], limit: int) -> list[str]:
    values = [str(line) for line in lines]
    if len(values) <= limit:
        return values
    return values[: limit - 1] + [f"... (truncated to {limit} lines)"]


def build_cast(
    lines: Sequence[str],
    *,
    title: str,
    width: int = DEFAULT_WIDTH,
    height: int = DEFAULT_HEIGHT,
    timestamp: int = 0,
    step: float = DEFAULT_STEP,
) -> str:
    """Serialize captured lines into a valid asciinema-v2 ``.cast`` document."""
    header = {
        "version": CAST_VERSION,
        "width": width,
        "height": height,
        "timestamp": timestamp,
        "title": title,
        "env": {"SHELL": "bash", "TERM": "xterm-256color"},
    }
    rows: list[str] = [json.dumps(header, ensure_ascii=False)]
    for index, line in enumerate(_bounded_lines(lines, MAX_CAST_LINES)):
        event = [round((index + 1) * step, 3), "o", f"{redact_output(line)}\r\n"]
        rows.append(json.dumps(event, ensure_ascii=False))
    return "\n".join(rows) + "\n"


def write_cast(
    path: Path,
    lines: Sequence[str],
    *,
    title: str,
    width: int = DEFAULT_WIDTH,
    height: int = DEFAULT_HEIGHT,
    timestamp: int = 0,
    step: float = DEFAULT_STEP,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        build_cast(
            lines,
            title=title,
            width=width,
            height=height,
            timestamp=timestamp,
            step=step,
        ),
        encoding="utf-8",
    )
    return path


def sanitize_cast(path: Path) -> Path:
    """Redact the text payload of an existing (live-recorded) ``.cast`` file.

    ``asciinema rec`` writes terminal output verbatim, bypassing the redaction
    applied by :func:`build_cast`. This pass rewrites every output event with
    :func:`redact_output` before a live cast is kept as a recording asset.
    """
    rows: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            rows.append(redact_output(line))
            continue
        if (
            isinstance(event, list)
            and len(event) == 3
            and event[1] == "o"
            and isinstance(event[2], str)
        ):
            event[2] = redact_output(event[2])
        rows.append(json.dumps(event, ensure_ascii=False))
    scratch = path.with_name(path.name + ".tmp")
    scratch.write_text("\n".join(rows) + "\n", encoding="utf-8")
    os.replace(scratch, path)
    return path


def render_svg_thumbnail(
    lines: Sequence[str],
    *,
    title: str,
    width: int = 900,
    max_lines: int = MAX_THUMBNAIL_LINES,
) -> str:
    """Render a self-contained, escaped SVG thumbnail for README embedding."""
    visible = _bounded_lines(lines, max_lines)
    line_height = 18
    height = 64 + len(visible) * line_height
    parts = [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" role="img" '
            f'aria-label="{escape(title, quote=True)}">'
        ),
        f"<title>{escape(title)}</title>",
        '<rect width="100%" height="100%" fill="#0b1021"/>',
        (
            f'<text x="16" y="28" fill="#7ee787" font-family="ui-monospace, monospace" '
            f'font-size="17">{escape(title)}</text>'
        ),
    ]
    for offset, line in enumerate(visible):
        y = 54 + offset * line_height
        parts.append(
            f'<text x="16" y="{y}" fill="#c9d1d9" font-family="ui-monospace, monospace" '
            f'font-size="12">{escape(redact_output(line))}</text>'
        )
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def write_thumbnail(
    path: Path,
    lines: Sequence[str],
    *,
    title: str,
    width: int = 900,
    max_lines: int = MAX_THUMBNAIL_LINES,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        render_svg_thumbnail(lines, title=title, width=width, max_lines=max_lines),
        encoding="utf-8",
    )
    return path


def preview_lines(scenario: DemoScenario) -> list[str]:
    """Narrated, clearly labelled preview used for committed README assets."""
    return [
        f"[PREVIEW] Blackwall MCP Gateway - {scenario.title}",
        "[PREVIEW] Regenerate a live cast with scripts/gateway_demo/record_demo.sh",
        f"[PREVIEW] {scenario.summary}",
        f"[PREVIEW] taxonomy: OWASP {scenario.owasp} | MITRE {scenario.mitre}",
        *[f"[PREVIEW] {verdict}" for verdict in scenario.verdicts],
    ]


def _render_command(args: argparse.Namespace) -> int:
    scenario = SCENARIO_BY_KEY[args.key]
    source_lines = args.source.read_text(encoding="utf-8").splitlines()
    output_dir: Path = args.output_dir
    cast_path = output_dir / scenario.cast_file
    if not (args.keep_existing_cast and cast_path.exists()):
        write_cast(cast_path, source_lines, title=scenario.title, timestamp=args.timestamp)
    svg_path = write_thumbnail(output_dir / scenario.thumbnail_file, source_lines, title=scenario.title)
    print(
        json.dumps(
            {"key": args.key, "cast": str(cast_path), "thumbnail": str(svg_path)}
        )
    )
    return 0


def _preview_command(args: argparse.Namespace) -> int:
    output_dir: Path = args.output_dir
    assets = []
    for scenario in SCENARIOS:
        lines = preview_lines(scenario)
        cast_path = write_cast(
            output_dir / scenario.cast_file, lines, title=scenario.title, timestamp=args.timestamp
        )
        svg_path = write_thumbnail(
            output_dir / scenario.thumbnail_file, lines, title=scenario.title
        )
        assets.append({"key": scenario.key, "cast": str(cast_path), "thumbnail": str(svg_path)})
    print(json.dumps(assets))
    return 0


def _sanitize_command(args: argparse.Namespace) -> int:
    cast_path = sanitize_cast(args.path)
    print(json.dumps({"cast": str(cast_path)}))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    render = subparsers.add_parser("render", help="Turn captured output into cast + SVG")
    render.add_argument("--key", required=True, choices=tuple(SCENARIO_BY_KEY))
    render.add_argument("--source", required=True, type=Path)
    render.add_argument("--output-dir", required=True, type=Path)
    render.add_argument("--keep-existing-cast", action="store_true")
    render.add_argument("--timestamp", type=int, default=0)
    render.set_defaults(handler=_render_command)

    preview = subparsers.add_parser("preview", help="Write narrated preview assets")
    preview.add_argument("--output-dir", required=True, type=Path)
    preview.add_argument("--timestamp", type=int, default=0)
    preview.set_defaults(handler=_preview_command)

    sanitize = subparsers.add_parser(
        "sanitize", help="Redact an asciinema cast captured directly by asciinema rec"
    )
    sanitize.add_argument("--path", required=True, type=Path)
    sanitize.set_defaults(handler=_sanitize_command)

    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
