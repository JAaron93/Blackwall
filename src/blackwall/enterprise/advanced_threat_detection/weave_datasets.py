"""Weave Dataset Creation from benchmark YAML scenarios.

Subtask 22.5: Weave Dataset Creation from YAML Scenarios.
Requirement 21.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from blackwall.enterprise.advanced_threat_detection.weave_config import (
    should_enable_weave,
)
from blackwall.enterprise.advanced_threat_detection.weave_serializer import (
    WeaveTraceSerializer,
)

try:
    import weave
except ImportError:  # pragma: no cover
    weave = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


@dataclass
class LocalEvaluationDataset:
    """Local fallback representation of an evaluation dataset."""

    name: str
    rows: list[dict[str, Any]] = field(default_factory=list)

    def __iter__(self) -> Any:
        return iter(self.rows)

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, idx: int) -> dict[str, Any]:
        return self.rows[idx]


def _sanitize_scenario_event(event_dict: dict[str, Any]) -> dict[str, Any]:
    """Sanitize raw scenario event dictionary for dataset rows.

    Preserves structured event attributes (event_id, agent_id, timestamp, source, action,
    target, risk_score) required for evaluation models to reconstruct NormalizedEvent instances,
    while recursively masking sensitive metadata values via WeaveTraceSerializer.mask_metadata.
    """
    safe_event: dict[str, Any] = {
        "event_id": str(event_dict.get("event_id", "")),
        "agent_id": str(event_dict.get("agent_id", "")),
        "timestamp": str(event_dict.get("timestamp", "")),
        "source": str(event_dict.get("source", "")),
        "action": str(event_dict.get("action", "")),
        "target": str(event_dict.get("target", "")),
    }
    if "risk_score" in event_dict:
        try:
            safe_event["risk_score"] = float(event_dict["risk_score"])
        except (ValueError, TypeError):
            safe_event["risk_score"] = 0.0
    if "metadata" in event_dict and isinstance(event_dict["metadata"], dict):
        safe_event["metadata"] = WeaveTraceSerializer.mask_metadata(event_dict["metadata"])
    elif "metadata" in event_dict:
        safe_event["metadata"] = {}
    return safe_event


def _load_scenario_file(file_path: Path) -> list[dict[str, Any]]:
    """Parse a scenario YAML file and return validated sanitized dataset rows."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            logger.warning("Scenario file '%s' did not parse to a dictionary. Skipping.", file_path)
            return []

        # Validate name
        name = data.get("name")
        if not name or not isinstance(name, str) or not name.strip():
            logger.warning("Scenario in '%s' missing valid 'name'. Skipping.", file_path)
            return []

        # Validate description (Requirement 21: skip if missing, non-string, or whitespace-only)
        desc = data.get("description")
        if desc is None or not isinstance(desc, str) or not desc.strip():
            logger.warning(
                "Scenario '%s' in '%s' missing non-empty string 'description'. Skipping.",
                name,
                file_path,
            )
            return []

        # Validate events
        raw_events = data.get("events", [])
        if not isinstance(raw_events, list):
            logger.warning("Scenario '%s' in '%s' has non-list events. Skipping.", name, file_path)
            return []

        sanitized_events = [
            _sanitize_scenario_event(e) if isinstance(e, dict) else e
            for e in raw_events
        ]

        expected = data.get("expected_detections", [])

        row: dict[str, Any] = {
            "name": name.strip(),
            "description": desc.strip(),
            "events": sanitized_events,
            "expected_detections": expected,
            "file_path": str(file_path),
        }
        return [row]
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error parsing scenario YAML '%s': %s", file_path, exc)
        return []


def create_evaluation_dataset(
    scenarios_dir_or_files: str | Path | Sequence[str | Path],
    name: str = "blackwall-atd-benchmark",
) -> Any:
    """Create a Weave (or local fallback) dataset from benchmark scenario YAML files.

    Args:
        scenarios_dir_or_files: Directory path, file path, or sequence of file paths.
        name: Name identifier for the dataset.

    Returns:
        weave.Dataset instance if Weave is enabled and available, or LocalEvaluationDataset.
    """
    candidate_files: list[Path] = []

    if isinstance(scenarios_dir_or_files, (str, Path)):
        p = Path(scenarios_dir_or_files)
        if p.is_dir():
            candidate_files.extend(sorted(p.glob("**/*.yaml")))
            candidate_files.extend(sorted(p.glob("**/*.yml")))
        elif p.is_file():
            candidate_files.append(p)
    elif isinstance(scenarios_dir_or_files, (list, tuple, Sequence)):
        for item in scenarios_dir_or_files:
            p = Path(item)
            if p.is_dir():
                candidate_files.extend(sorted(p.glob("**/*.yaml")))
                candidate_files.extend(sorted(p.glob("**/*.yml")))
            elif p.is_file():
                candidate_files.append(p)

    rows: list[dict[str, Any]] = []
    for f in candidate_files:
        rows.extend(_load_scenario_file(f))

    logger.info("Loaded %d benchmark scenario rows for dataset '%s'.", len(rows), name)

    # Attempt Weave native Dataset creation
    if should_enable_weave() and weave is not None and hasattr(weave, "Dataset"):
        try:
            return weave.Dataset(name=name, rows=rows)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to instantiate weave.Dataset for '%s': %s. Falling back to local dataset.",
                name,
                exc,
            )

    return LocalEvaluationDataset(name=name, rows=rows)
