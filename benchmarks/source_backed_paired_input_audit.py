"""Linked CPU-only audit of actual adapter inputs for the eight synthetic cells.

This runs fake transports and an in-process fake Laya worker. It records what
the adapters serialize and what the fake worker fits, never model outcomes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from benchmarks.source_backed_frontier_pilot import (
    _canonical,  # pyright: ignore[reportPrivateUsage]
    _git_head,  # pyright: ignore[reportPrivateUsage]
    _sha,  # pyright: ignore[reportPrivateUsage]
    _source_sha,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.source_backed_full_run import run_full_run_pilot, verify_full_run_pilot
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    LocalDeepFrontierRanker,
    MixedFrontierRanker,
)
from systemsense.domain.time import utc_now
from systemsense.inference import laya_worker
from systemsense.inference.laya_runtime import LayaRanker, LayaSubprocessRuntime
from systemsense.inference.ollama import OllamaChatClient
from systemsense.inference.settings import LocalInferenceConfig
from tests.unit.inference.test_laya_runtime import (
    _config,  # pyright: ignore[reportPrivateUsage]
    _factory,  # pyright: ignore[reportPrivateUsage]
    _FakeProcess,  # pyright: ignore[reportPrivateUsage]
)

_MODEL_SHA = "a" * 64
_EV49 = "ev_" + f"{49:032x}"
_EV50 = "ev_" + f"{50:032x}"


class _Tokenizer:
    mask_token = "[MASK]"
    mask_token_id = 1

    def __call__(self, value: str, *, add_special_tokens: bool = False) -> dict[str, object]:
        del add_special_tokens
        return {"input_ids": [len(part) for part in value.split()]}


class _Agent:
    tok = _Tokenizer()

    def __init__(self) -> None:
        self.cfg: dict[str, object] = {"max_len": 512, "head_max_len": 80}

    def predict(
        self, state: dict[str, object], questions: dict[str, dict[str, object]]
    ) -> dict[str, object]:
        del state
        return {"answers": {key: {"noul": 0.8} for key in questions}}


def _fake_model_input(
    agent: laya_worker._LayaAgent,  # pyright: ignore[reportPrivateUsage]
    state: dict[str, object],
    questions: dict[str, dict[str, object]],
) -> tuple[dict[str, object], dict[str, object] | None, str | None]:
    count = len(questions)
    tensors: dict[str, object] = {
        "input_ids": [[101, 1, 102] for _ in range(count)],
        "attention_mask": [[1, 1, 1] for _ in range(count)],
        "marker_pos": [[1, 2] for _ in range(count)],
        "marker_mask": [[True, True] for _ in range(count)],
        "qtype": [2] * count,
    }
    return agent.predict(state, questions), tensors, None


class _RecordingLaya:
    def __init__(self, runtime: LayaSubprocessRuntime) -> None:
        self.runtime = runtime
        self.attend_input: dict[str, object] | None = None

    def attend(self, **kwargs: Any) -> Any:
        self.attend_input = {
            "state": kwargs["state"],
            "evidence": kwargs["evidence"],
            "candidates": kwargs["candidates"],
        }
        return self.runtime.attend(**kwargs)


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


def _capture(request: FrontierRankRequestV1, runtime: LayaSubprocessRuntime) -> dict[str, Any]:
    # The recorded deadline has expired. It is not sent to either model.
    request = FrontierRankRequestV1.model_validate(
        request.model_copy(update={"deadline_at": utc_now() + timedelta(seconds=30)}).model_dump(
            mode="json"
        )
    )
    laya = _RecordingLaya(runtime)
    phases: list[dict[str, object]] = []

    def capture(phase: str, index: int, call: dict[str, object], proof: Any) -> None:
        phases.append(
            {
                "phase": phase,
                "batch_index": index,
                "state": call["state"],
                "questions": call["questions"],
                "state_fields_omitted": proof.state_fields_omitted,
                "state_list_items_omitted": proof.state_list_items_omitted,
                "fitted_state_tokens_fake_tokenizer": proof.fitted_state_tokens,
                "instruction_truncated_items_fake_tokenizer": sum(
                    item.instruction_presented_tokens < item.instruction_tokens
                    for item in proof.questions
                ),
            }
        )

    mixed = MixedFrontierRanker(
        ranker=cast(LayaRanker, laya),
        provider=request.provider,
        model_weight_sha256=request.model_weight_sha256,
        timeout_seconds=15,
        cache_size=0,
    )
    fast = mixed.rank(request, capture_worker_batch=capture)
    if fast.ranking_source != "laya" or laya.attend_input is None or not phases:
        raise ValueError(f"fake Laya capture failed: {fast.degraded_reason}")
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
    if deep_result.ranking_source != "local_deep" or deep.prompt is None:
        raise ValueError("fake local deep capture failed")
    payload: dict[str, Any] = {
        "laya_attend": laya.attend_input,
        "laya_fitted_worker": phases,
        "local_deep_prompt": json.loads(deep.prompt),
        "local_deep_provider": deep_adapter.provider.model_dump(mode="json"),
    }
    task = request.task_context
    if task is None or any(
        cast(dict[str, object], item["state"]).get("task_context") != task.model_visible()
        for item in phases
    ):
        raise ValueError("complete task did not survive fake worker fit")
    return payload


def _counterbalance(request: FrontierRankRequestV1) -> FrontierRankRequestV1:
    """Reverse presentation only; this is an unexecuted adapter counterfactual."""

    return FrontierRankRequestV1.model_validate(
        request.model_copy(
            update={
                "items": tuple(reversed(request.items)),
                "item_semantics": tuple(reversed(request.item_semantics)),
            }
        ).model_dump(mode="json")
    )


def _digest(value: object) -> str:
    return _sha(value)


def _blind_summary(request: FrontierRankRequestV1, payload: dict[str, Any]) -> dict[str, Any]:
    laya = cast(dict[str, object], payload["laya_attend"])
    candidates = cast(tuple[dict[str, str], ...], laya["candidates"])
    return {
        "item_ids_in_order": [item["probe_id"] for item in candidates],
        "descriptions_in_order": [item["description"] for item in candidates],
        "task_context": request.task_context.model_visible() if request.task_context else None,
        "laya_attend": laya,
        "laya_fitted_worker": payload["laya_fitted_worker"],
        "local_deep_prompt": payload["local_deep_prompt"],
        "actual_adapter_payload_sha256": _digest(
            {
                key: payload[key]
                for key in ("laya_attend", "laya_fitted_worker", "local_deep_prompt")
            }
        ),
    }


def audit_paired_inputs(output_dir: Path) -> dict[str, object]:
    """Create a new linked artifact; the v3 source replay remains immutable."""

    output_dir.mkdir(parents=True, exist_ok=False)
    source_dir = output_dir / "source-v3"
    run_full_run_pilot(source_dir)
    if verify_full_run_pilot(source_dir)["integrity_verified"] is not True:
        raise ValueError("source replay integrity failed")
    blind = json.loads((source_dir / "policy-visible" / "requests.json").read_text())
    attempts = json.loads((source_dir / "attempts.json").read_text())
    if len(blind["cells"]) != 8 or len(attempts["cells"]) != 8:
        raise ValueError("paired audit requires all eight frozen cells")
    (output_dir / "policy-visible").mkdir()
    (output_dir / "evaluator-only").mkdir()
    agent = cast(laya_worker._LayaAgent, _Agent())  # pyright: ignore[reportPrivateUsage]
    process = _FakeProcess(
        response=lambda request: laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
            agent, request
        )
    )
    fake_install = tempfile.TemporaryDirectory(prefix="systemsense-paired-input-")
    runtime = LayaSubprocessRuntime(
        _config(Path(fake_install.name)),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    policy_cells: list[dict[str, object]] = []
    failures: list[dict[str, str]] = []
    try:
        with patch.object(laya_worker, "_predict_with_model_input_capture", _fake_model_input):
            for blind_cell in blind["cells"]:
                try:
                    request = FrontierRankRequestV1.model_validate(blind_cell["rank_request"])
                    normal = _capture(request, runtime)
                    reversed_request = _counterbalance(request)
                    reversed_payload = _capture(reversed_request, runtime)
                    original = _blind_summary(request, normal)
                    counterbalanced = _blind_summary(reversed_request, reversed_payload)
                    original_map = dict(
                        zip(
                            original["item_ids_in_order"],
                            original["descriptions_in_order"],
                            strict=True,
                        )
                    )
                    reversed_map = dict(
                        zip(
                            counterbalanced["item_ids_in_order"],
                            counterbalanced["descriptions_in_order"],
                            strict=True,
                        )
                    )
                    if (
                        original_map != reversed_map
                        or original["task_context"] != counterbalanced["task_context"]
                        or original["laya_attend"]["evidence"]
                        != counterbalanced["laya_attend"]["evidence"]
                        or original["local_deep_prompt"]["evidence_packets"]
                        != counterbalanced["local_deep_prompt"]["evidence_packets"]
                        or original["item_ids_in_order"]
                        != list(reversed(counterbalanced["item_ids_in_order"]))
                    ):
                        raise ValueError(
                            "counterbalance changed source meaning or failed to reverse order"
                        )
                    policy_cells.append(
                        {
                            "anonymous_cell_id": blind_cell["anonymous_cell_id"],
                            "case_key": blind_cell["case_key"],
                            "status": "captured",
                            "fast_provider": request.provider.model_dump(mode="json"),
                            "local_deep_provider": normal["local_deep_provider"],
                            "original": original,
                            "counterbalanced_adapter_only_not_executed": counterbalanced,
                        }
                    )
                except (KeyError, RuntimeError, TypeError, ValueError) as error:
                    failure = {
                        "anonymous_cell_id": str(blind_cell["anonymous_cell_id"]),
                        "error_type": type(error).__name__,
                    }
                    failures.append(failure)
                    policy_cells.append(
                        {**failure, "status": "failed", "case_key": blind_cell["case_key"]}
                    )
    finally:
        runtime.close()
        fake_install.cleanup()
    (output_dir / "policy-visible" / "inputs.json").write_bytes(
        _canonical(
            {"schema_version": 1, "eligible_cells": 8, "cells": policy_cells, "failures": failures}
        )
    )
    by_id = {item["anonymous_cell_id"]: item for item in policy_cells}
    groups: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for index, cell in enumerate(attempts["cells"]):
        groups[(cell["case_key"], cell["choice"])].append(
            {"world_key": cell["world_key"], "blind": by_id[f"cell_{index:02d}"], "cell": cell}
        )
    pairs: list[dict[str, object]] = []
    for (case_key, choice), members in sorted(groups.items()):
        if len(members) != 2:
            raise ValueError("hidden-world pair is incomplete")
        first, second = members
        if any(
            cast(dict[str, object], member["blind"])["status"] != "captured" for member in members
        ):
            pairs.append(
                {
                    "case_key": case_key,
                    "choice": choice,
                    "actual_adapter_payload_parity": "unknown_capture_failed",
                    "comparison_admissible": False,
                }
            )
            continue
        a = cast(dict[str, object], cast(dict[str, object], first["blind"])["original"])
        b = cast(dict[str, object], cast(dict[str, object], second["blind"])["original"])
        request = FrontierRankRequestV1.model_validate(
            cast(dict[str, Any], cast(dict[str, object], first["cell"])["rank_request"])
        )
        ids = [str(item.reference.evidence_id) for item in request.items]
        descriptions = cast(list[str], a["descriptions_in_order"])
        title49 = json.loads(descriptions[ids.index(_EV49)])["information_goal"]
        title50 = json.loads(descriptions[ids.index(_EV50)])["information_goal"]
        task_phrase = "Browser route" if "network" in case_key else "Document viewer phase"
        lexical_matches = [
            evidence_id
            for evidence_id, description in zip(ids, descriptions, strict=True)
            if task_phrase in json.loads(description)["information_goal"]
        ]
        title_cue = (
            "Browser route" in title49 and "Host processor" in title50
            if "network" in case_key
            else "Document viewer phase" in title49 and "storage" in title50.lower()
        )
        raw_commitments = [
            cast(dict[str, object], member["cell"])["prechoice_request_normalized_sha256"]
            for member in members
        ]
        pairs.append(
            {
                "case_key": case_key,
                "choice": choice,
                "world_keys_evaluator_only": [first["world_key"], second["world_key"]],
                "raw_prechoice_request_parity": (
                    "matched" if len(set(raw_commitments)) == 1 else "mismatched"
                ),
                "raw_request_commitments": raw_commitments,
                "actual_adapter_payload_parity": "matched"
                if a["actual_adapter_payload_sha256"] == b["actual_adapter_payload_sha256"]
                else "mismatched",
                "ev49_title": title49,
                "ev50_title": title50,
                "title_cues_relevance": title_cue,
                "ev49_position_zero_based": ids.index(_EV49),
                "ev50_position_zero_based": ids.index(_EV50),
                "counterbalanced_ev49_position_zero_based": len(ids) - 1 - ids.index(_EV49),
                "source_ids_in_order": ids,
                "source_ids_and_order_cue_identity": ids == sorted(ids) and ids.index(_EV49) == 0,
                "first_item_baseline_picks_ev49": ids[0] == _EV49,
                "lexical_title_baseline_matches": lexical_matches,
                "lexical_title_baseline_picks_ev49": lexical_matches == [_EV49],
                "counterbalance_feasible_adapter_only": True,
                "counterbalanced_first_item_picks_ev49": ids[-1] == _EV49,
                "counterbalance_removes_title_cue": False,
            }
        )
    evaluator = {
        "schema_version": 1,
        "pairs": pairs,
        "comparison_admissible": False,
        "reason": (
            "Original exact request includes hidden-world ev49 content commitment; "
            "titles and stable ID/order cue relevance. Reversed presentation is "
            "an unexecuted adapter counterfactual and leaves titles intact."
        ),
    }
    (output_dir / "evaluator-only" / "pairs.json").write_bytes(_canonical(evaluator))
    protocol = {
        "schema_version": 1,
        "classification": "synthetic_adapter_input_audit_only",
        "source_manifest_sha256": hashlib.sha256(
            (source_dir / "manifest.json").read_bytes()
        ).hexdigest(),
        "code_sha": _git_head(),
        "audit_source_sha256": _source_sha(Path(__file__)),
        "fake_worker": "split_tokenizer_and_fake_tensors_no_installed_model",
        "fake_laya_token_limits": {"max_len": 512, "head_max_len": 80},
        "local_deep_fit": "recording_fake_fits_context_true_no_real_tokenizer",
        "counterbalance": "reverse_item_and_semantic_order_adapter_only_not_executed",
        "excluded_from_model_payload": ["deadline_at", "timeout_seconds"],
        "comparison_admissible": False,
    }
    (output_dir / "protocol.json").write_bytes(_canonical(protocol))
    files = ["protocol.json", "policy-visible/inputs.json", "evaluator-only/pairs.json"]
    manifest = {
        "schema_version": 1,
        "source_manifest_sha256": protocol["source_manifest_sha256"],
        "files": {
            name: hashlib.sha256((output_dir / name).read_bytes()).hexdigest() for name in files
        },
    }
    (output_dir / "manifest.json").write_bytes(_canonical(manifest))
    return {
        "eligible_cells": 8,
        "capture_failures": len(failures),
        "pairs": len(pairs),
        "comparison_admissible": False,
    }


def verify_paired_inputs(output_dir: Path) -> dict[str, object]:
    source = output_dir / "source-v3"
    verify_full_run_pilot(source)
    manifest = json.loads((output_dir / "manifest.json").read_text())
    protocol = json.loads((output_dir / "protocol.json").read_text())
    if protocol["audit_source_sha256"] != _source_sha(Path(__file__)):
        raise ValueError("audit code source hash mismatch")
    if (
        hashlib.sha256((source / "manifest.json").read_bytes()).hexdigest()
        != manifest["source_manifest_sha256"]
    ):
        raise ValueError("source artifact hash mismatch")
    for name, expected in manifest["files"].items():
        if hashlib.sha256((output_dir / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"audit artifact hash mismatch: {name}")
    audit = json.loads((output_dir / "policy-visible" / "inputs.json").read_text())
    pairs = json.loads((output_dir / "evaluator-only" / "pairs.json").read_text())
    if len(audit["cells"]) != 8 or len(pairs["pairs"]) != 4:
        raise ValueError("audit is incomplete")
    return {"integrity_verified": True, "cells": 8, "pairs": 4, "comparison_admissible": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    result = (
        verify_paired_inputs(args.output_dir)
        if args.verify
        else audit_paired_inputs(args.output_dir)
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
