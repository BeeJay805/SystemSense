"""CPU scripted advisory replay over receipt-backed synthetic source choices.

The provider reads only its ReasoningRequest. Hidden toy variants and exact
source/task bytes are used by the separate evaluator, never by the provider.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.source_backed_frontier_pilot import (
    _git_head,  # pyright: ignore[reportPrivateUsage]
    _source_sha,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.source_task_relation_red import run_balanced_relation_probe
from systemsense.decision.contracts import ProviderIdentity
from systemsense.domain.ids import EvidenceId
from systemsense.reasoning.contracts import (
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)

_RIVALS: dict[str, tuple[tuple[str, str], tuple[str, str]]] = {
    "network_browser": (
        ("h_browser_profile_proxy_route", "The configured browser proxy path may contribute."),
        ("h_external_origin_unreachable", "The external origin may be unavailable."),
    ),
    "application_performance": (
        ("h_viewer_rendering_delay", "The document viewer may contribute to delay."),
        ("h_external_document_source_delay", "The external document source may be slow."),
    ),
}


def _family(request: ReasoningRequest) -> str | None:
    task = request.task_observation
    if task is None:
        return None
    if task.target_handle.startswith("synthetic:browser-profile:"):
        return "network_browser"
    if task.target_handle.startswith("synthetic:document-viewer:"):
        return "application_performance"
    return None


def _contrast(domain: str, facts: dict[str, Any]) -> int | None:
    """Choose a toy contrast from visible controls, never a cause or recipe ID."""

    if domain == "network_browser" and facts.get("browser_request_timed_out") is True:
        if (
            facts.get("browser_proxy_enabled") is True
            and facts.get("configured_proxy_reachable") is False
            and facts.get("direct_same_origin_reachable") is True
        ):
            return 0
        if (
            facts.get("browser_proxy_enabled") is False
            and facts.get("configured_proxy_reachable") is True
            and facts.get("direct_same_origin_reachable") is False
        ):
            return 1
    if domain == "application_performance":
        viewer = facts.get("viewer_render_p95_ms")
        external = facts.get("external_fetch_p95_ms")
        independent = facts.get("independent_document_open_ms")
        if (
            isinstance(viewer, int)
            and not isinstance(viewer, bool)
            and isinstance(external, int)
            and not isinstance(external, bool)
            and isinstance(independent, int)
            and not isinstance(independent, bool)
        ):
            if viewer >= 3 * external and independent < external:
                return 0
            if external >= 3 * viewer and independent < viewer:
                return 1
    return None


class ScriptedPostretrievalReasoner:
    """Use task coverage and observed contrasts; keep every cause unresolved."""

    def __init__(self) -> None:
        self.exchanges: list[tuple[ReasoningRequest, ReasoningResponse]] = []

    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="scripted-postretrieval-advisory",
            provider_version="1",
            role="reasoning",
        )

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        domain = _family(request)
        cited: EvidenceId | None = None
        favored: int | None = None
        focused = {item.evidence_id: item for item in request.evidence_context}
        if domain is not None:
            for source in request.selected_sources:
                relation = source.source_task_relation
                context = focused.get(source.evidence_id)
                if (
                    relation is None
                    or relation.status != "same_target_full_window"
                    or context is None
                    or context.status.value != "observed"
                ):
                    continue
                contrast = _contrast(domain, context.facts)
                if contrast is not None:
                    cited, favored = source.evidence_id, contrast
                    break
        rivals = _RIVALS[domain] if domain is not None else ()
        hypotheses = tuple(
            Hypothesis(
                hypothesis_id=hypothesis_id,
                statement=statement + " This remains an unverified explanation.",
                status=(
                    HypothesisStatus.CONTESTED
                    if cited is not None and favored != index
                    else HypothesisStatus.UNRESOLVED
                ),
                supporting_evidence_ids=(cited,) if cited is not None and favored == index else (),
                contradicting_evidence_ids=(cited,)
                if cited is not None and favored != index
                else (),
            )
            for index, (hypothesis_id, statement) in enumerate(rivals)
        )
        response = ReasoningResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            status=(
                ReasoningStatus.UNRESOLVED
                if hypotheses
                else ReasoningStatus.INSUFFICIENT_OBSERVABILITY
            ),
            summary="Observed contrasts may narrow toy rivals; no cause or repair is verified.",
            hypotheses=hypotheses,
            considered_evidence_ids=(cited,) if cited is not None else (),
        ).validate_against(request)
        self.exchanges.append((request, response))
        return response


def run_postretrieval_pilot(root: Path) -> list[dict[str, Any]]:
    """Freeze the first choice before later selections; review linked final separately."""

    from benchmarks.source_task_discrimination_oracle import review_cell

    providers: list[ScriptedPostretrievalReasoner] = []

    def provider_factory() -> ScriptedPostretrievalReasoner:
        provider = ScriptedPostretrievalReasoner()
        providers.append(provider)
        return provider

    cells = run_balanced_relation_probe(root, world_scope="all", reasoning_factory=provider_factory)
    assert len(cells) == len(providers) == 16
    rows: list[dict[str, Any]] = []
    for cell, provider in zip(cells, providers, strict=True):
        chosen_id = str(cell["chosen_evidence_id"])
        alternative_id = str(cell["alternative_evidence_id"])
        first = next(
            (request, response)
            for request, response in provider.exchanges
            if chosen_id in {str(item.evidence_id) for item in request.selected_sources}
        )
        request, response = first
        assert alternative_id not in {str(item.evidence_id) for item in request.selected_sources}
        chosen = next(
            item for item in request.selected_sources if str(item.evidence_id) == chosen_id
        )
        reviewed = review_cell(cell)
        rows.append(
            {
                "domain": cell["domain"],
                "world_key": cell["world_key"],
                "matched_evidence_id": cell["matched_evidence_id"],
                "chosen_evidence_id": chosen_id,
                "first_request": request.model_dump(mode="json"),
                "first_response": response.model_dump(mode="json"),
                "last_response": provider.exchanges[-1][1].model_dump(mode="json"),
                "first_relation_status": (
                    chosen.source_task_relation.status if chosen.source_task_relation else None
                ),
                "review": reviewed,
                "review_inputs": {
                    "database": cell["database"],
                    "domain": cell["domain"],
                    "chosen_evidence_id": chosen_id,
                    "request": cell["request"].model_dump(mode="json"),
                    "selected_readback": cell["selected_readback"],
                    "assessment": cell["assessment"],
                },
                "terminal_status": cell["status"],
                "terminal_outcome": cell["outcome"],
                "terminal_assessment": cell["assessment"],
                "terminal_hypotheses": cell["terminal_hypotheses"],
                "terminal_stop_reason": cell["terminal_stop_reason"],
                "all_deep_calls": len(provider.exchanges),
            }
        )
    return rows


def _save_json(path: Path, value: Any) -> str:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_postretrieval_pilot(output_dir: Path) -> dict[str, Any]:
    """Freeze provider-visible first turns and evaluator-only exact readbacks."""

    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "policy-visible").mkdir()
    (output_dir / "evaluator-only").mkdir()
    rows = run_postretrieval_pilot(output_dir / "cases")
    blind = [
        {
            "cell_index": index,
            "first_request": row["first_request"],
            "first_response": row["first_response"],
        }
        for index, row in enumerate(rows)
    ]
    reviews = [
        {
            "cell_index": index,
            **{
                key: value
                for key, value in row.items()
                if key not in {"first_request", "first_response"}
            },
        }
        for index, row in enumerate(rows)
    ]
    blind_sha = _save_json(output_dir / "policy-visible" / "first_choices.json", blind)
    reviews_sha = _save_json(output_dir / "evaluator-only" / "reviews.json", reviews)
    source_paths = (
        Path(__file__),
        Path(__file__).with_name("source_task_relation_red.py"),
        Path(__file__).with_name("source_task_discrimination_oracle.py"),
    )
    manifest = {
        "schema_version": 1,
        "code_head": _git_head(),
        "source_sha256": {item.name: _source_sha(item) for item in source_paths},
        "policy_visible_sha256": blind_sha,
        "evaluator_only_sha256": reviews_sha,
        "case_db_sha256": {
            str(Path(row["review_inputs"]["database"]).relative_to(output_dir)): hashlib.sha256(
                Path(row["review_inputs"]["database"]).read_bytes()
            ).hexdigest()
            for row in rows
        },
        "cells": len(rows),
        "first_useful": sum(
            row["review"]["observed_effect"] == "reduces_toy_rivals" for row in rows
        ),
        "first_wasted": sum(
            row["review"]["observed_effect"] == "does_not_reduce_toy_rivals" for row in rows
        ),
        "terminal_unresolved": sum(
            row["terminal_outcome"] == "no_progress" and row["terminal_assessment"] is None
            for row in rows
        ),
        "actual_model_calls": 0,
        "scout": "disabled",
        "scope": "synthetic_one_host_scripted_provider_no_causal_or_model_policy_claim",
    }
    _save_json(output_dir / "manifest.json", manifest)
    return verify_postretrieval_pilot(output_dir)


def verify_postretrieval_pilot(output_dir: Path) -> dict[str, Any]:
    """Reopen exact local rows and independently rescore the frozen first choice."""

    from benchmarks.source_task_discrimination_oracle import review_cell
    from systemsense.decision.frontier_ranker import FrontierRankRequestV1

    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    blind_path = output_dir / "policy-visible" / "first_choices.json"
    reviews_path = output_dir / "evaluator-only" / "reviews.json"
    assert hashlib.sha256(blind_path.read_bytes()).hexdigest() == manifest["policy_visible_sha256"]
    assert (
        hashlib.sha256(reviews_path.read_bytes()).hexdigest() == manifest["evaluator_only_sha256"]
    )
    blind = json.loads(blind_path.read_text(encoding="utf-8"))
    reviews = json.loads(reviews_path.read_text(encoding="utf-8"))
    assert len(blind) == len(reviews) == manifest["cells"] == 16
    for name, digest in manifest["source_sha256"].items():
        assert _source_sha(Path(__file__).with_name(name)) == digest
    for relative, digest in manifest["case_db_sha256"].items():
        assert hashlib.sha256((output_dir / relative).read_bytes()).hexdigest() == digest
    for index, (visible, evaluator) in enumerate(zip(blind, reviews, strict=True)):
        assert visible["cell_index"] == evaluator["cell_index"] == index
        assert not {"world_key", "matched_evidence_id", "review"}.intersection(visible)
        first_request = ReasoningRequest.model_validate(visible["first_request"])
        first_response = ReasoningResponse.model_validate(visible["first_response"])
        first_response.validate_against(first_request)
        inputs = evaluator["review_inputs"]
        inputs["request"] = FrontierRankRequestV1.model_validate(inputs["request"])
        assert review_cell(inputs) == evaluator["review"]
        assert evaluator["terminal_outcome"] == "no_progress"
        assert evaluator["terminal_assessment"] is None
    assert manifest["first_useful"] == manifest["first_wasted"] == 8
    return {
        "verified_cells": len(reviews),
        "first_useful": manifest["first_useful"],
        "first_wasted": manifest["first_wasted"],
        "terminal_unresolved": manifest["terminal_unresolved"],
        "manifest_sha256": hashlib.sha256((output_dir / "manifest.json").read_bytes()).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    result = (
        verify_postretrieval_pilot(args.output_dir)
        if args.verify
        else write_postretrieval_pilot(args.output_dir)
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
