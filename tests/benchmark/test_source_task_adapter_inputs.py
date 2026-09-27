"""A bound synthetic task must survive both frontier adapters and Laya fit."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from benchmarks.source_backed_full_run import run_full_run_pilot
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    LocalDeepFrontierRanker,
    MixedFrontierRanker,
)
from systemsense.domain.time import utc_now
from systemsense.inference import laya_worker
from systemsense.inference.laya_runtime import (
    LayaAttentionResult,
    LayaRanker,
    LayaSubprocessRuntime,
)
from systemsense.inference.ollama import OllamaChatClient
from systemsense.inference.settings import LocalInferenceConfig
from tests.unit.inference.test_laya_runtime import (
    _config,  # pyright: ignore[reportPrivateUsage]
    _factory,  # pyright: ignore[reportPrivateUsage]
    _FakeProcess,  # pyright: ignore[reportPrivateUsage]
)

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


def test_bound_task_reaches_each_actual_frontier_adapter_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "full-run"
    assert run_full_run_pilot(output)["cells"] == 8
    attempts = json.loads((output / "attempts.json").read_text(encoding="utf-8"))

    class Tokenizer:
        mask_token = "[MASK]"
        mask_token_id = 1

        def __call__(self, value: str, *, add_special_tokens: bool = False) -> dict[str, object]:
            del add_special_tokens
            return {"input_ids": [len(part) for part in value.split()]}

    class Agent:
        tok = Tokenizer()

        def __init__(self) -> None:
            self.cfg: dict[str, object] = {"max_len": 512, "head_max_len": 80}

        def predict(
            self, state: dict[str, object], questions: dict[str, dict[str, object]]
        ) -> dict[str, object]:
            del state
            return {"answers": {key: {"noul": 0.8} for key in questions}}

    agent = cast(laya_worker._LayaAgent, Agent())  # pyright: ignore[reportPrivateUsage]

    def capture_model_input(
        worker: laya_worker._LayaAgent,  # pyright: ignore[reportPrivateUsage]
        state: dict[str, object],
        questions: dict[str, dict[str, object]],
    ) -> tuple[dict[str, object], dict[str, object] | None, str | None]:
        count = len(questions)
        row = [101, 1, 102]
        model_input: dict[str, object] = {
            "input_ids": [row[:] for _ in range(count)],
            "attention_mask": [[1, 1, 1] for _ in range(count)],
            "marker_pos": [[1, 2] for _ in range(count)],
            "marker_mask": [[True, True] for _ in range(count)],
            "qtype": [2] * count,
        }
        return worker.predict(state, questions), model_input, None

    monkeypatch.setattr(laya_worker, "_predict_with_model_input_capture", capture_model_input)
    process = _FakeProcess(
        response=lambda request: laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
            agent, request
        )
    )
    runtime = LayaSubprocessRuntime(
        _config(tmp_path / "fake-laya"),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    last_laya_state: dict[str, object] | None = None
    last_context: dict[str, str | int] | None = None
    for cell in attempts["cells"]:
        task = attempts["checkpoints"][cell["case_key"]]["task_observation"]
        request = FrontierRankRequestV1.model_validate(cell["rank_request"])
        assert request.schema_version == 2
        assert request.task_context is not None
        context = request.task_context.model_visible()
        assert context["case_id"] == task["case_id"]
        assert context["evidence_id"] == task["evidence_id"]
        assert context["source_id"] == task["source_id"]
        assert context["collector_id"] == task["collector_id"]
        assert context["collector_version"] == 1
        assert context["execution_id"] == task["execution_id"]
        assert request.task_context.record_sha256 == task["record_sha256"]
        assert context["kind"] == "synthetic_task_observation_v1"
        assert context["scope"] == "synthetic_fixture"
        assert context["limitation"] == _SYNTHETIC_LIMITATION
        assert context["time_quality"] == "exact"
        assert context["status"] == "observed"
        assert context["observed_at"] == task["observed_at"]
        assert context["captured_at"] == task["captured_at"]
        fields = task["facts"]
        assert context["target_handle"] == fields["target_handle"]
        assert context["action"] == fields["action"]
        assert context["expected"] == fields["expected"]
        assert context["observed"] == fields["observed"]
        assert context["window_start"] == fields["synthetic_window_start_utc"]
        assert context["window_end"] == fields["synthetic_window_end_utc"]
        assert context["sample_window_ms"] == fields["sample_window_ms"]
        request = FrontierRankRequestV1.model_validate(
            request.model_copy(
                update={"deadline_at": utc_now() + timedelta(seconds=30)}
            ).model_dump(mode="json")
        )
        adapter_inputs = _capture(request)
        last_laya_state = cast(dict[str, object], adapter_inputs["laya"]["state"])
        last_context = context
        for adapter, payload in adapter_inputs.items():
            packets = payload["evidence_packets"]
            assert 1 <= len(packets) <= 16
            assert task["evidence_id"] in {packet["evidence_id"] for packet in packets}
            actual = (
                payload["state"]["task_context"] if adapter == "laya" else payload["task_context"]
            )
            assert actual == context
            assert "world_key" not in json.dumps(payload)
            assert "compatible_toy_causes" not in json.dumps(payload)
            assert task["record_sha256"] not in json.dumps(payload)
        captures: list[tuple[str, dict[str, object]]] = []
        ranker = MixedFrontierRanker(
            ranker=cast(LayaRanker, runtime),
            provider=request.provider,
            model_weight_sha256=request.model_weight_sha256,
            timeout_seconds=15,
            cache_size=0,
        )
        ranking = ranker.rank(
            request,
            capture_worker_batch=lambda phase, _index, call, _proof, sink=captures: sink.append(
                (phase, call)
            ),
        )
        assert ranking.ranking_source == "laya", ranking.degraded_reason
        assert captures
        assert {phase for phase, _call in captures} >= {"evidence", "probe"}
        for phase, call in captures:
            assert phase in {"evidence", "probe", "compare"}
            assert cast(dict[str, object], call["state"])["task_context"] == context
            assert call["model_input"]
    # The frozen four-item menu has no compare phase. Expand only the fake
    # worker menu to exercise Laya's finalist comparison with the same task.
    assert last_laya_state is not None
    assert last_context is not None
    compare_captures: list[tuple[str, dict[str, object]]] = []
    runtime.attend(
        state=last_laya_state,
        evidence=(),
        candidates=tuple(
            {"probe_id": f"synthetic-compare-{index}", "description": "fixture choice"}
            for index in range(21)
        ),
        timeout_seconds=15,
        capture_exact_worker_call=lambda phase, _index, call, _proof: compare_captures.append(
            (phase, call)
        ),
        capture_model_input=True,
    )
    assert {phase for phase, _call in compare_captures} == {"probe", "compare"}
    assert all(
        cast(dict[str, object], call["state"])["task_context"] == last_context
        for _phase, call in compare_captures
    )
    runtime.close()
