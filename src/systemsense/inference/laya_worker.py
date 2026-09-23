"""Standalone JSON-lines worker for a pinned local Laya checkpoint."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import json
import sys
from collections.abc import Callable
from importlib import metadata
from pathlib import Path
from typing import Literal, Protocol, cast

PROTOCOL_VERSION = 1
PRESENTATION_VERSION = 1
MAX_PRESENTATION_QUESTIONS = 128


class _LayaAgent(Protocol):
    cfg: dict[str, object]
    device: object
    dtype: object
    model: _TorchModel
    tok: _Tokenizer

    def predict(
        self, state: dict[str, object], questions: dict[str, dict[str, object]]
    ) -> dict[str, object]: ...


class _LayaModule(Protocol):
    def load(self, model_path: str, *, device: str) -> _LayaAgent: ...


class _TorchModule(Protocol):
    cuda: _TorchCuda
    float16: object

    def set_num_threads(self, threads: int) -> None: ...

    def set_num_interop_threads(self, threads: int) -> None: ...


class _TorchCuda(Protocol):
    def is_available(self) -> bool: ...

    def mem_get_info(self) -> tuple[int, int]: ...

    def empty_cache(self) -> None: ...


class _TorchModel(Protocol):
    def to(self, *, dtype: object) -> object: ...


class _Tokenizer(Protocol):
    mask_token: str
    mask_token_id: int

    def __call__(self, text: str, *, add_special_tokens: bool = False) -> dict[str, object]: ...


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--threads", type=int, choices=range(1, 5), default=2)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    parser.add_argument("--precision", choices=("float32", "float16"), default="float32")
    parser.add_argument("--min-free-vram-mb", type=int, default=1536)
    parser.add_argument("--max-request-bytes", type=int, default=262_144)
    return parser


def _load_agent(
    model_path: Path,
    threads: int,
    device: Literal["cpu", "cuda"],
    min_free_vram_mb: int,
    precision: Literal["float32", "float16"],
) -> tuple[_LayaAgent, Callable[[], None]]:
    with contextlib.redirect_stdout(sys.stderr):
        if metadata.version("laya") != "0.3.5":
            raise RuntimeError("Laya package version differs from the admitted runtime")
        if metadata.version("transformers") != "5.17.0":
            raise RuntimeError("Transformers version differs from the admitted runtime")
        laya = cast(_LayaModule, cast(object, importlib.import_module("laya")))
        torch = cast(_TorchModule, cast(object, importlib.import_module("torch")))
        if metadata.version("torch") not in {"2.10.0", "2.10.0+cpu", "2.10.0+cu128"}:
            raise RuntimeError("PyTorch version differs from the admitted runtime")

        torch.set_num_threads(threads)
        torch.set_num_interop_threads(1)
        if device == "cuda":
            if not torch.cuda.is_available():
                raise RuntimeError("CUDA is unavailable in the pinned Laya runtime")
            free_bytes, _total_bytes = torch.cuda.mem_get_info()
            if free_bytes < min_free_vram_mb * 1024 * 1024:
                raise RuntimeError("CUDA admission rejected: insufficient free VRAM")
        agent = laya.load(str(model_path.resolve()), device=device)
        if device == "cuda" and not str(agent.device).casefold().startswith("cuda"):
            raise RuntimeError("Laya refused CUDA placement; CPU fallback is not admitted")
        if device == "cpu" and str(agent.device).casefold() != "cpu":
            raise RuntimeError("Laya did not honor the admitted CPU placement")
        if precision == "float16":
            if device != "cuda":
                raise RuntimeError("reduced Laya precision is admitted only for CUDA")
            agent.model.to(dtype=torch.float16)
            agent.dtype = torch.float16
            torch.cuda.empty_cache()
        release_cuda_cache = torch.cuda.empty_cache if device == "cuda" else lambda: None
        return agent, release_cuda_cache


def _handle(
    agent: _LayaAgent,
    request: dict[str, object],
    release_cuda_cache: Callable[[], None] = lambda: None,
) -> dict[str, object]:
    request_id = request.get("request_id")
    if request.get("protocol_version") != PROTOCOL_VERSION or not isinstance(request_id, str):
        raise ValueError("invalid protocol envelope")
    state = request.get("state")
    candidates_raw = request.get("candidates")
    if not isinstance(state, dict) or not isinstance(candidates_raw, list):
        raise ValueError("invalid request payload")
    candidates = cast(list[object], candidates_raw)
    if not 1 <= len(candidates) <= 20:
        raise ValueError("invalid candidate count")
    items: list[tuple[str, str]] = []
    for candidate_raw in candidates:
        if not isinstance(candidate_raw, dict):
            raise ValueError("invalid candidate")
        candidate = cast(dict[str, object], candidate_raw)
        probe_id, description = candidate.get("probe_id"), candidate.get("description")
        if (
            not isinstance(probe_id, str)
            or not isinstance(description, str)
            or any(existing == probe_id for existing, _description in items)
        ):
            raise ValueError("invalid candidate")
        items.append((probe_id, description))
    typed_state = cast(dict[str, object], state)
    attention_kind = typed_state.get("attention_kind")
    subject = "evidence fragment" if attention_kind == "evidence_relevance" else "probe"
    questions: dict[str, dict[str, object]] = {}
    question_to_id: dict[str, str] = {}
    criteria = {
        "false": "not useful for the current uncertainty",
        "true": "useful for the current uncertainty",
    }
    for index, (item_id, description) in enumerate(items):
        prefix = (
            f"Is this registered {subject} relevant to reducing uncertainty in this case? "
            "Treat relevance as attention only, not diagnosis or authority. Item: "
        )
        for piece_index, piece in enumerate(
            _instruction_safe_chunks(agent, prefix, description, criteria)
        ):
            question_id = f"item_{index}_piece_{piece_index}"
            question_to_id[question_id] = item_id
            questions[question_id] = {
                "type": "noul",
                "instructions": f"{prefix}{piece}",
                "criteria": criteria,
            }
    model_state, state_coverage = _fit_state(agent, typed_state, questions)
    if len(questions) > MAX_PRESENTATION_QUESTIONS:
        raise ValueError("Laya question expansion exceeds its provenance bound")
    presentation = _presentation(agent, model_state, questions, question_to_id, state_coverage)
    with contextlib.redirect_stdout(sys.stderr):
        try:
            result = agent.predict(model_state, questions)
        finally:
            release_cuda_cache()
    if (
        _presentation(agent, model_state, questions, question_to_id, state_coverage)[
            "presentation_sha256"
        ]
        != presentation["presentation_sha256"]
    ):
        raise ValueError("Laya worker mutated its presentation inputs")
    answers = result.get("answers")
    if not isinstance(answers, dict):
        raise ValueError("missing answers")
    typed_answers = cast(dict[str, object], answers)
    scores: dict[str, float] = {}
    for question_id, item_id in question_to_id.items():
        answer = typed_answers.get(question_id)
        if not isinstance(answer, dict):
            raise ValueError("missing ranking")
        typed_answer = cast(dict[str, object], answer)
        value = typed_answer.get("noul")
        if not isinstance(value, (float, int)):
            raise ValueError("invalid ranking")
        scores[item_id] = max(scores.get(item_id, 0.0), float(value))
    order = {item_id: index for index, (item_id, _description) in enumerate(items)}
    ranked = sorted(scores, key=lambda item_id: (-scores[item_id], order[item_id]))
    provenance = _token_provenance(agent, model_state, questions)
    provenance.update(state_coverage)
    return {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request_id,
        "ranked_probe_ids": ranked,
        "relevance_scores": scores,
        "token_provenance": provenance,
        "presentation": presentation,
    }


def _presentation(
    agent: _LayaAgent,
    state: dict[str, object],
    questions: dict[str, dict[str, object]],
    question_to_id: dict[str, str],
    state_coverage: dict[str, int],
) -> dict[str, object]:
    """Fingerprint the exact worker call without returning model-visible text."""

    state_tokens = _state_token_count(agent, state)
    max_len = agent.cfg.get("max_len", 512)
    head_max_len = agent.cfg.get("head_max_len", 192)
    if not isinstance(max_len, int) or not isinstance(head_max_len, int):
        raise ValueError("invalid model token limits")
    details: list[dict[str, object]] = []
    for question_id, question in questions.items():
        instructions = str(question["instructions"]).replace(agent.tok.mask_token, " ")
        instruction_tokens = len(_token_ids(agent.tok, f"noul question: {instructions}"))
        criteria = cast(dict[str, str], question["criteria"])
        raw_options = [
            [agent.tok.mask_token_id, *_token_ids(agent.tok, f" {label}: {criteria[label]}")]
            for label in ("false", "true")
        ]
        option_tokens = [item[:49] for item in raw_options]
        option_budget = head_max_len - sum(len(item) for item in option_tokens)
        if option_budget < 16:
            per_option = max(4, (head_max_len - 16) // len(option_tokens))
            option_tokens = [item[:per_option] for item in option_tokens]
            option_budget = head_max_len - sum(len(item) for item in option_tokens)
        instruction_presented = min(instruction_tokens, max(8, option_budget))
        prefix_tokens = 1 + instruction_presented + 1 + sum(map(len, option_tokens)) + 1
        state_capacity = max(0, max_len - prefix_tokens - 1)
        details.append(
            {
                "question_id": question_id,
                "item_id": question_to_id[question_id],
                "question_sha256": _presentation_digest("question", question),
                "instruction_tokens": instruction_tokens,
                "instruction_presented_tokens": instruction_presented,
                "criteria_tokens": sum(map(len, raw_options)),
                "criteria_presented_tokens": sum(map(len, option_tokens)),
                "state_presented_tokens": min(state_tokens, state_capacity),
            }
        )
    ordered_questions = [
        {"question_id": key, "item_id": question_to_id[key], "question": value}
        for key, value in questions.items()
    ]
    return {
        "schema_version": PRESENTATION_VERSION,
        "presentation_sha256": _presentation_digest(
            "presentation",
            {
                "state": state,
                "questions": ordered_questions,
                "max_len": max_len,
                "head_max_len": head_max_len,
            },
        ),
        "fitted_state_sha256": _presentation_digest("state", state),
        "questions_sha256": _presentation_digest("questions", ordered_questions),
        "presented_item_ids": list(dict.fromkeys(question_to_id.values())),
        "fitted_state_tokens": state_tokens,
        "state_tokens_original": state_coverage["state_tokens_original"],
        "state_fields_omitted": state_coverage["state_fields_omitted"],
        "state_list_items_omitted": state_coverage["state_list_items_omitted"],
        "questions": details,
    }


def _presentation_digest(kind: str, value: object) -> str:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(
        f"systemsense.laya.{kind}.v{PRESENTATION_VERSION}\0".encode() + payload.encode("utf-8")
    ).hexdigest()


def _token_ids(tokenizer: _Tokenizer, text: str) -> list[int]:
    raw = tokenizer(text, add_special_tokens=False).get("input_ids")
    if not isinstance(raw, list):
        raise ValueError("tokenizer did not return token IDs")
    raw_items = cast(list[object], raw)
    if not all(isinstance(item, int) for item in raw_items):
        raise ValueError("tokenizer did not return token IDs")
    return cast(list[int], raw_items)


def _instruction_safe_chunks(
    agent: _LayaAgent,
    prefix: str,
    description: str,
    criteria: dict[str, str],
) -> tuple[str, ...]:
    """Split content so the pinned sequence builder presents every instruction token."""

    capacity = _instruction_capacity(agent, criteria)
    if len(_token_ids(agent.tok, f"noul question: {prefix}")) > capacity:
        raise ValueError("Laya ranking instruction prefix exceeds its token budget")
    remaining = description or " "
    chunks: list[str] = []
    while remaining:
        low, high, fitting = 1, len(remaining), 0
        while low <= high:
            middle = (low + high) // 2
            token_count = len(_token_ids(agent.tok, f"noul question: {prefix}{remaining[:middle]}"))
            if token_count <= capacity:
                fitting = middle
                low = middle + 1
            else:
                high = middle - 1
        if fitting == 0:
            raise ValueError("Laya could not fit evidence content in its instruction budget")
        chunks.append(remaining[:fitting])
        remaining = remaining[fitting:]
    return tuple(chunks)


def _instruction_capacity(agent: _LayaAgent, criteria: dict[str, str]) -> int:
    head_max_len_raw = agent.cfg.get("head_max_len", 192)
    if not isinstance(head_max_len_raw, int):
        raise ValueError("invalid model head token limit")
    option_tokens = [
        [
            agent.tok.mask_token_id,
            *_token_ids(agent.tok, f" {label}: {criteria[label]}")[:48],
        ]
        for label in ("false", "true")
    ]
    option_budget = head_max_len_raw - sum(len(item) for item in option_tokens)
    if option_budget < 16:
        per_option = max(4, (head_max_len_raw - 16) // len(option_tokens))
        option_tokens = [item[:per_option] for item in option_tokens]
        option_budget = head_max_len_raw - sum(len(item) for item in option_tokens)
    return max(8, option_budget)


def _fit_state(
    agent: _LayaAgent,
    state: dict[str, object],
    questions: dict[str, dict[str, object]],
) -> tuple[dict[str, object], dict[str, int]]:
    """Admit complete semantic fields using the actual per-question token capacity."""

    capacities = [_state_capacity(agent, question) for question in questions.values()]
    capacity = min(capacities)
    original_tokens = _state_token_count(agent, state)
    fitted: dict[str, object] = {}

    def require(key: str, value: object) -> None:
        if value in (None, "", (), [], {}):
            return
        candidate = {**fitted, key: value}
        if _state_token_count(agent, candidate) > capacity:
            raise ValueError(f"essential Laya state field does not fit: {key}")
        fitted[key] = value

    require("symptom", state.get("symptom"))
    require("preferred_probe_ids", state.get("preferred_probe_ids"))
    require("attention_kind", state.get("attention_kind"))
    ranked_context = _object_sequence(state.get("ranked_evidence_context"))
    if ranked_context:
        require("ranked_evidence_context", [ranked_context[0]])
    reference_relations = _object_sequence(state.get("reference_knowledge"))
    machine_relations = _object_sequence(state.get("machine_relationships"))
    if reference_relations:
        require("reference_knowledge", [reference_relations[0]])
    elif machine_relations:
        require("machine_relationships", [machine_relations[0]])
    hypotheses = _object_sequence(state.get("hypothesis_briefs"))
    if hypotheses:
        require("hypothesis_briefs", [hypotheses[0]])

    for key, value in state.items():
        if key in fitted:
            existing = fitted[key]
            items = _object_sequence(value)
            if not items or not isinstance(existing, list):
                continue
            existing_items = cast(list[object], existing)
            for item in items[len(existing_items) :]:
                candidate_items: list[object] = [*existing_items, item]
                candidate = {**fitted, key: candidate_items}
                if _state_token_count(agent, candidate) > capacity:
                    break
                existing_items = candidate_items
                fitted[key] = existing_items
            continue
        items = _object_sequence(value)
        if items:
            admitted: list[object] = []
            for item in items:
                candidate_items = [*admitted, item]
                candidate = {**fitted, key: candidate_items}
                if _state_token_count(agent, candidate) > capacity:
                    break
                admitted = candidate_items
                fitted[key] = admitted
            continue
        candidate = {**fitted, key: value}
        if _state_token_count(agent, candidate) <= capacity:
            fitted[key] = value

    original_list_items = sum(len(_object_sequence(value)) for value in state.values())
    fitted_list_items = sum(len(_object_sequence(value)) for value in fitted.values())
    return fitted, {
        "state_tokens_original": original_tokens,
        "state_fields_omitted": len(state) - len(fitted),
        "state_list_items_omitted": original_list_items - fitted_list_items,
    }


def _object_sequence(value: object) -> list[object] | tuple[object, ...]:
    if isinstance(value, list):
        return cast(list[object], value)
    if isinstance(value, tuple):
        return cast(tuple[object, ...], value)
    return ()


def _state_token_count(agent: _LayaAgent, state: dict[str, object]) -> int:
    serialized = json.dumps(state, ensure_ascii=False).replace(agent.tok.mask_token, " ")
    return len(_token_ids(agent.tok, serialized))


def _state_capacity(agent: _LayaAgent, question: dict[str, object]) -> int:
    max_len_raw = agent.cfg.get("max_len", 512)
    if not isinstance(max_len_raw, int):
        raise ValueError("invalid model sequence token limit")
    instructions = str(question["instructions"]).replace(agent.tok.mask_token, " ")
    instruction_tokens = len(_token_ids(agent.tok, f"noul question: {instructions}"))
    criteria = cast(dict[str, str], question["criteria"])
    option_tokens = [
        [
            agent.tok.mask_token_id,
            *_token_ids(agent.tok, f" {label}: {criteria[label]}")[:48],
        ]
        for label in ("false", "true")
    ]
    head_max_len_raw = agent.cfg.get("head_max_len", 192)
    if not isinstance(head_max_len_raw, int):
        raise ValueError("invalid model head token limit")
    option_budget = head_max_len_raw - sum(len(item) for item in option_tokens)
    if option_budget < 16:
        per_option = max(4, (head_max_len_raw - 16) // len(option_tokens))
        option_tokens = [item[:per_option] for item in option_tokens]
    prefix_tokens = 1 + instruction_tokens + 1 + sum(len(item) for item in option_tokens) + 1
    return max(0, max_len_raw - prefix_tokens - 1)


def _token_provenance(
    agent: _LayaAgent,
    state: dict[str, object],
    questions: dict[str, dict[str, object]],
) -> dict[str, object]:
    """Report actual sequence budgets used by the pinned Laya serializer."""

    max_len_raw = agent.cfg.get("max_len", 512)
    head_max_len_raw = agent.cfg.get("head_max_len", 192)
    if not isinstance(max_len_raw, int) or not isinstance(head_max_len_raw, int):
        raise ValueError("invalid model token limits")
    max_len = max_len_raw
    head_max_len = head_max_len_raw
    serialized_state = json.dumps(state, ensure_ascii=False).replace(agent.tok.mask_token, " ")
    state_tokens = len(_token_ids(agent.tok, serialized_state))
    state_presented_min = max_len
    instruction_tokens_max = 0
    instruction_presented_min = head_max_len
    instruction_truncated_items = 0
    for question in questions.values():
        instructions = str(question["instructions"]).replace(agent.tok.mask_token, " ")
        head_tokens = len(_token_ids(agent.tok, f"noul question: {instructions}"))
        criteria = cast(dict[str, str], question["criteria"])
        option_tokens = [
            [
                agent.tok.mask_token_id,
                *_token_ids(agent.tok, f" {label}: {criteria[label]}")[:48],
            ]
            for label in ("false", "true")
        ]
        option_budget = head_max_len - sum(len(item) for item in option_tokens)
        if option_budget < 16:
            per_option = max(4, (head_max_len - 16) // len(option_tokens))
            option_tokens = [item[:per_option] for item in option_tokens]
            option_budget = head_max_len - sum(len(item) for item in option_tokens)
        instruction_presented = min(head_tokens, max(8, option_budget))
        # CLS + instruction + SEP + options + SEP + state + final SEP.
        prefix_tokens = 1 + instruction_presented + 1 + sum(len(item) for item in option_tokens) + 1
        state_capacity = max(0, max_len - prefix_tokens - 1)
        state_presented_min = min(state_presented_min, min(state_tokens, state_capacity))
        instruction_tokens_max = max(instruction_tokens_max, head_tokens)
        instruction_presented_min = min(instruction_presented_min, instruction_presented)
        instruction_truncated_items += int(instruction_presented < head_tokens)
    return {
        "max_sequence_tokens": max_len,
        "state_tokens": state_tokens,
        "state_presented_tokens_min": state_presented_min,
        "state_truncated": state_presented_min < state_tokens,
        "instruction_tokens_max": instruction_tokens_max,
        "instruction_presented_tokens_min": instruction_presented_min,
        "instruction_truncated_items": instruction_truncated_items,
        "items": len(questions),
    }


def main() -> int:
    args = _parser().parse_args()
    protocol_output = sys.stdout.buffer
    agent, release_cuda_cache = _load_agent(
        args.model_path,
        args.threads,
        cast(Literal["cpu", "cuda"], args.device),
        args.min_free_vram_mb,
        cast(Literal["float32", "float16"], args.precision),
    )
    while True:
        line = sys.stdin.buffer.readline(args.max_request_bytes + 1)
        if not line:
            return 0
        request_id: str | None = None
        try:
            if len(line) > args.max_request_bytes or not line.endswith(b"\n"):
                raise ValueError("request exceeds byte limit")
            decoded = cast(object, json.loads(line))
            if not isinstance(decoded, dict):
                raise ValueError("request must be an object")
            request = cast(dict[str, object], decoded)
            raw_request_id = request.get("request_id")
            request_id = raw_request_id if isinstance(raw_request_id, str) else None
            response = _handle(agent, request, release_cuda_cache)
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            response = {
                "protocol_version": PROTOCOL_VERSION,
                "request_id": request_id,
                "error": type(error).__name__,
            }
        protocol_output.write(json.dumps(response, separators=(",", ":")).encode() + b"\n")
        protocol_output.flush()


if __name__ == "__main__":
    raise SystemExit(main())
