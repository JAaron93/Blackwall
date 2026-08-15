"""Weave Evaluation Harness for running benchmark evaluations and tracking metrics.

Subtask 22.2: WeaveEvaluationHarness Class.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from typing import Any

from blackwall.enterprise.advanced_threat_detection import weave_config
from blackwall.enterprise.advanced_threat_detection.weave_config import (
    WeaveConfig,
    load_weave_config,
    should_enable_weave,
)

try:
    import weave
except ImportError:  # pragma: no cover
    weave = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


class WeaveEvaluationHarness:
    """Evaluation harness integrating with Weave for tracking detection quality."""

    def __init__(self, config: WeaveConfig | None = None) -> None:
        self.config: WeaveConfig = config or load_weave_config()
        self.enabled: bool = False

        if should_enable_weave():
            self.enabled = weave_config.init_weave(self.config)
        else:
            logger.info(
                "Weave tracking is disabled. Operating in local-only fallback mode."
            )

    def track_detection_metrics(
        self, dataset_name: str, metrics: dict[str, Any]
    ) -> None:
        """Track aggregated threat detection metrics in Weave."""
        if not self.enabled or weave is None:
            return

        try:
            payload = {
                "dataset_name": dataset_name,
                "project_name": self.config.project_name,
                **metrics,
            }
            if hasattr(weave, "publish"):
                weave.publish(payload)
            elif hasattr(weave, "log"):
                weave.log(payload)
            logger.debug(
                "Published detection metrics to Weave for dataset '%s'", dataset_name
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to publish metrics to Weave for dataset '%s': %s",
                dataset_name,
                exc,
            )

    async def run_evaluation(
        self,
        name: str,
        dataset: Any,
        model: Any,
        scorers: list[Callable[..., Any]] | None = None,
    ) -> dict[str, Any]:
        """Run an evaluation over a dataset using a model/callable and optional scorers."""
        scorers = scorers or []

        # Attempt Weave native evaluation if enabled and available
        if self.enabled and weave is not None and hasattr(weave, "Evaluation"):
            try:
                eval_kwargs: dict[str, Any] = {"dataset": dataset, "scorers": scorers}
                try:
                    evaluation = weave.Evaluation(name=name, **eval_kwargs)
                except TypeError:
                    evaluation = weave.Evaluation(**eval_kwargs)

                if inspect.iscoroutinefunction(evaluation.evaluate):
                    eval_res = await evaluation.evaluate(model)
                else:
                    eval_res = evaluation.evaluate(model)

                return {"name": name, "results": eval_res, "tracked_in_weave": True}
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Weave Evaluation '%s' encountered an error: %s. Falling back to local runner.",
                    name,
                    exc,
                )

        # Local fallback execution
        results: list[dict[str, Any]] = []
        rows = dataset if isinstance(dataset, list) else getattr(dataset, "rows", [])

        for idx, row in enumerate(rows):
            try:
                if inspect.iscoroutinefunction(model):
                    output = await model(row)
                elif callable(model):
                    output = model(row)
                elif hasattr(model, "predict"):
                    predict_fn = model.predict
                    if inspect.iscoroutinefunction(predict_fn):
                        output = await predict_fn(row)
                    else:
                        output = predict_fn(row)
                else:
                    output = None

                row_scores: dict[str, Any] = {}
                for scorer in scorers:
                    try:
                        s_name = getattr(
                            scorer, "__name__", f"scorer_{len(row_scores)}"
                        )
                        if inspect.iscoroutinefunction(scorer):
                            score_val = await scorer(row, output)
                        else:
                            score_val = scorer(row, output)
                        row_scores[s_name] = score_val
                    except Exception as s_exc:  # noqa: BLE001
                        logger.debug("Scorer %s error: %s", scorer, s_exc)

                results.append(
                    {"index": idx, "input": row, "output": output, "scores": row_scores}
                )
            except Exception as row_exc:  # noqa: BLE001
                logger.warning("Error evaluating row %d: %s", idx, row_exc)
                results.append({"index": idx, "input": row, "error": str(row_exc)})

        return {
            "name": name,
            "total_samples": len(rows),
            "results": results,
            "tracked_in_weave": False,
        }
