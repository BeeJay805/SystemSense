"""RED: a bound synthetic task must survive the real frontier adapter projection."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

from benchmarks.source_backed_full_run import run_full_run_pilot
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    LocalDeepFrontierRanker,
    MixedFrontierRanker,
)
from systemsense.domain.time import utc_now
from systemsense.inference.laya_runtime import LayaAttentionResult, LayaRanker
from systemsense.inference.ollama import OllamaChatClient
from systemsense.inference.settings import LocalInferenceConfig

_MODEL_SHA = "a" * 64
_SYNTHETIC_LIMITATION = "Synthetic fixture only; no Windows browser or document was opened."


class _RecordingLaya:
    def __init__(self) -> None:
        self.call: dict[str, Any] | None = None

    def attend(self, **kwargs: Any) -> LayaAttentionResult:
        self.call = kwargs
        raise RuntimeError("recording transport deliberately did not invoke a model")


class _RecordingDeep:
    def __init__(self) -> None:
        self.config = LocalInferenceConfig(
            enabled=True,
            reasoning_model="fixture-local-deep",
            reasoning_digest=_MODEL_SHA,
            allow_gpu=False,
        )
        self.prompt: str | None = None

    def fits_context(self, prompt: str, _schema: dict[str, object]) -> bool:
        self.prompt = prompt
        return True

    def complete(self, **kwargs: object) -> dict[str, object]:
        self.prompt = cast(str, kwargs["prompt"])
        offered = [item["item_id"] for item in json.loads(self.prompt)["offered_items"]]
        return {"ranked_item_ids": offered, "considered_item_ids": offered}


def _capture(request: FrontierRankRequestV1) -> dict[str, dict[str, Any]]:
    laya = _RecordingLaya()
    mixed = MixedFrontierRanker(
        ranker=cast(LayaRanker, laya),
        provider=request.provider,
        model_weight_sha256=request.model_weight_sha256,
        cache_size=0,
    )
    mixed_result = mixed.rank(request)
    assert mixed_result.degraded_reason == "worker_error"
    assert laya.call is not None

    deep = _RecordingDeep()
    deep_adapter = LocalDeepFrontierRanker(
        client=cast(OllamaChatClient, deep),
        model="fixture-local-deep",
        model_weight_sha256=_MODEL_SHA,
    )
    deep_request = FrontierRankRequestV1.model_validate(
        request.model_copy(
            update={"provider": deep_adapter.provider, "model_weight_sha256": _MODEL_SHA}
        ).model_dump(mode="json")
    )
    deep_result = deep_adapter.rank(deep_request)
    assert deep_result.ranking_source == "local_deep"
    assert deep.prompt is not None
    return {
        "laya": {
            "state": laya.call["state"],
            "evidence_packets": laya.call["evidence"],
            "offered_items": laya.call["candidates"],
        },
        "local_deep": json.loads(deep.prompt),
    }


def test_bound_task_reaches_each_actual_frontier_adapter_input(tmp_path: Path) -> None:
    output = tmp_path / "full-run"
    assert run_full_run_pilot(output)["cells"] == 8
    attempts = json.loads((output / "attempts.json").read_text(encoding="utf-8"))
    missing_by_cell: dict[str, list[str]] = {}
    for cell in attempts["cells"]:
        task = attempts["checkpoints"][cell["case_key"]]["task_observation"]
        request = FrontierRankRequestV1.model_validate(cell["rank_request"])
        request = FrontierRankRequestV1.model_validate(
            request.model_copy(
                update={"deadline_at": utc_now() + timedelta(seconds=30)}
            ).model_dump(mode="json")
        )
        for adapter, payload in _capture(request).items():
            packets = payload["evidence_packets"]
            assert 1 <= len(packets) <= 16
            assert task["evidence_id"] in {packet["evidence_id"] for packet in packets}
            wire = json.dumps(payload, sort_keys=True)
            assert _SYNTHETIC_LIMITATION in wire
            fields = task["facts"]
            required = {
                "target_handle": fields["target_handle"],
                "expected": fields["expected"],
                "observed": fields["observed"],
                "synthetic_window_start_utc": fields["synthetic_window_start_utc"],
                "synthetic_window_end_utc": fields["synthetic_window_end_utc"],
            }
            missing = [name for name, value in required.items() if str(value) not in wire]
            if missing:
                missing_by_cell[f"{cell['world_key']}:{cell['choice']}:{adapter}"] = missing
    assert not missing_by_cell, missing_by_cell
