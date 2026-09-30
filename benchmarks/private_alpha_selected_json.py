"""Frozen, evaluator-only selected-file trials through the normal application service.

Default CLI runs development Basic cases only. Holdouts require the exact frozen
protocol digest and explicit case IDs. No arm falls back to another provider.
Recipes/oracles stay in this process and are never supplied to provider context.
Run output is private evaluation material, not model input or training labels.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import math
import os
import sqlite3
import subprocess
import tempfile
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

FIXTURES = Path(__file__).parent / "fixtures" / "selected_json_v1"
CHECKS = {"file.utf8", "file.json_syntax"}
ALLOWED = CHECKS | {"task.local_json"}
INTAKE = "Check whether the selected local file is accepted as strict UTF-8 JSON."
CONTROL = b'{"evaluation_control_8a25":true}'


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write(path: Path, value: Any) -> None:
    # Exclusive writes preserve failed attempts and prevent result replacement.
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def frozen_suite(directory: Path = FIXTURES) -> tuple[dict[str, Any], str]:
    raw = (directory / "protocol.json").read_bytes()
    digest = _hash(raw)
    if digest != (directory / "freeze.sha256").read_text().strip():
        raise ValueError("protocol freeze differs")
    protocol = json.loads(raw)
    for name, expected in protocol["files"].items():
        if Path(name).name != name or _hash((directory / name).read_bytes()) != expected:
            raise ValueError("fixture freeze differs")
    return protocol, digest


def load_cases(
    split: str, *, release_digest: str | None = None, directory: Path = FIXTURES
) -> list[dict[str, Any]]:
    protocol, digest = frozen_suite(directory)
    if split not in {"development", "holdout"}:
        raise ValueError("unknown split")
    if split == "holdout" and release_digest != digest:
        raise ValueError("holdouts are sealed; explicit frozen digest required")
    name = "ground_truth.json" if split == "holdout" else "development.json"
    cases = json.loads((directory / name).read_bytes())
    ids = [case["case_id"] for case in cases]
    if len(set(ids)) != len(ids) or (split == "holdout" and ids != protocol["case_ids"]):
        raise ValueError("frozen denominator differs")
    return cases


def materialize(recipe: dict[str, Any]) -> bytes:
    if "hex" in recipe:
        return bytes.fromhex(recipe["hex"])
    if "text" in recipe:
        return recipe["text"].encode("utf-8")
    return (recipe["repeat"] * recipe["count"] + recipe.get("suffix", "")).encode("utf-8")


def independent_oracle(path: Path) -> dict[str, Any]:
    """Use independent file IO/stdlib parsing, never product capture/check helpers."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(262146)
    except FileNotFoundError:
        return {"task": "unavailable", "error": "read_unavailable", "capture": "missing"}
    except PermissionError:
        return {"task": "unavailable", "error": "read_unavailable", "capture": "read_denied"}
    base: dict[str, Any] = {"sha256": _hash(raw), "bytes": len(raw), "capture": "none"}
    if len(raw) > 262144:
        return {**base, "task": "unavailable", "error": "read_unavailable", "capture": "too_large"}
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return {**base, "task": "rejected", "error": "invalid_utf8"}
    if text.startswith("\ufeff"):
        return {**base, "task": "rejected", "error": "utf8_bom"}
    if not text.strip():
        return {**base, "task": "rejected", "error": "empty_document"}
    # Independent lexical depth bound ignores delimiters inside escaped strings.
    quoted = escaped = False
    depth = 0
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 128:
                return {**base, "task": "rejected", "error": "nesting_limit"}
        elif char in "]}":
            depth -= 1

    def integer(token: str) -> int:
        if len(token.lstrip("-")) > 4300:
            raise OverflowError("number_limit")
        return int(token)

    def floating(token: str) -> float:
        value = float(token)
        if not math.isfinite(value):
            raise OverflowError("non_finite_number")
        return value

    def constant(_token: str) -> None:
        raise OverflowError("non_finite_number")

    try:
        json.loads(text, parse_int=integer, parse_float=floating, parse_constant=constant)
    except json.JSONDecodeError:
        return {**base, "task": "rejected", "error": "json_syntax"}
    except OverflowError as error:
        return {**base, "task": "rejected", "error": str(error)}
    return {**base, "task": "accepted", "error": "none"}


@contextmanager
def exclusive_owned_file(path: Path) -> Generator[None]:
    """Deny sharing on this trial's file; CloseHandle alone restores access."""
    if os.name != "nt":
        raise RuntimeError("Windows required")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    handle = kernel.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "owned exclusive open failed")
    try:
        yield
    finally:
        if not kernel.CloseHandle(handle):
            raise OSError(ctypes.get_last_error(), "owned exclusive handle cleanup failed")


@contextmanager
def condition(path: Path, spec: dict[str, Any]) -> Generator[None]:
    path.write_bytes(materialize(spec["recipe"]))
    if spec.get("condition") == "missing":
        path.unlink()
    if spec.get("condition") == "exclusive":
        with exclusive_owned_file(path):
            yield
    else:
        yield


def _model_evidence(store: Any, case_id: str, required: set[str]) -> dict[str, Any]:
    from systemsense.application.deep_worker import DeepWorkerResultV1, FrozenDeepTaskV1
    from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository

    used_in_applied = False
    providers: set[str] = set()
    for row in store.connection.execute(
        "SELECT task_json,result_json FROM deep_mailbox WHERE case_id=? AND status='applied'",
        (case_id,),
    ):
        task = FrozenDeepTaskV1.model_validate_json(row[0])
        result = DeepWorkerResultV1.model_validate_json(row[1])
        response = result.response
        if response is None or response.degraded:
            continue
        response.validate_against(task.request)
        used = {
            str(eid)
            for hypothesis in response.hypotheses
            for eid in (
                *hypothesis.supporting_evidence_ids,
                *hypothesis.contradicting_evidence_ids,
                *(ref.evidence_id for ref in hypothesis.noncausal_observation_refs),
            )
        }
        presented = {str(item.evidence_id) for item in task.request.evidence_context}
        reviewed = set(map(str, response.considered_evidence_ids))
        if required <= used & presented & reviewed:
            used_in_applied = True
            providers.add(response.provider.provider_id)
    from systemsense.storage.candidate_dispatch_admissions import (
        CandidateDispatchAdmissionRepository,
    )

    menus: list[dict[str, Any]] = []
    selected_used = False
    repository = CandidateDecisionSnapshotRepository(store)
    for row in store.connection.execute(
        "SELECT snapshot_id FROM candidate_decision_snapshots WHERE case_id=?",
        (case_id,),
    ):
        if not str(row[0]).startswith("frontier_decision_snapshot_"):
            continue
        snapshot = repository.readback_frontier(row[0])
        probes = sorted({ref.probe_id for ref in snapshot.candidate_refs})
        linked_used = False
        if (
            snapshot.response.ranking_source == "laya"
            and not snapshot.response.model_abstained
            and snapshot.response.degraded_reason is None
            and snapshot.response.coverage_complete
        ):
            for link in repository.execution_links(snapshot.snapshot_id):
                if link.candidate_id != snapshot.candidate_id:
                    continue
                admission_row = store.connection.execute(
                    "SELECT admission_id FROM candidate_dispatch_admissions "
                    "WHERE snapshot_id=? AND candidate_id=? AND case_id=?",
                    (snapshot.snapshot_id, link.candidate_id, case_id),
                ).fetchone()
                if admission_row is None:
                    continue
                admission = CandidateDispatchAdmissionRepository(store).readback(
                    str(admission_row[0])
                )
                execution = store.probe_execution(str(link.execution_id))
                if (
                    admission.outcome_status != "linked"
                    or execution is None
                    or execution.status != "ok"
                ):
                    continue
                actual_ids = {
                    str(row[0])
                    for row in store.connection.execute(
                        "SELECT evidence_id FROM evidence WHERE case_id=? AND execution_id=?",
                        (case_id, str(link.execution_id)),
                    )
                }
                linked_used = bool(actual_ids & required)
                selected_used |= linked_used
        menus.append(
            {
                "snapshot_id": row[0],
                "probes": probes,
                "ranking_source": snapshot.response.ranking_source,
                "selected_check_used": linked_used,
            }
        )
    return {
        "deep_used_discriminating_evidence": used_in_applied,
        "deep_providers": sorted(providers),
        "menus": menus,
        "competing_menu": any(CHECKS <= set(menu["probes"]) for menu in menus),
        "selected_discriminator_executed_and_used": selected_used,
    }


def privacy_failures(
    database: Path, report: object, selected: Path, spec: dict[str, Any]
) -> list[str]:
    """Scan saved output for the native path and exact document transport, not hashes."""
    raw = materialize(spec["recipe"])
    forbidden = [str(selected), selected.name]
    if len(raw) >= 24:
        forbidden.extend(
            [raw.decode("utf-8", errors="replace"), base64.b64encode(raw).decode("ascii")]
        )
    if spec.get("privacy_canary"):
        forbidden.append(spec["privacy_canary"])
    values = [json.dumps(report, ensure_ascii=False)]
    with sqlite3.connect(database) as connection:
        # Inspect every text field using quoted local schema identifiers, no input SQL.
        tables = [
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        ]
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            for row in connection.execute("SELECT * FROM " + quoted):
                values.extend(value for value in row if isinstance(value, str))
    return (
        ["private_path_or_content_persisted"]
        if any(
            token in value or json.dumps(token, ensure_ascii=False)[1:-1] in value
            for token in forbidden
            for value in values
        )
        else []
    )


def score_saved_case(
    database: Path, case_id: str, spec: dict[str, Any], arm: str
) -> dict[str, Any]:
    """Score actual detailed checks and their use in the scoped terminal report.

    The product's custody resolver is reused, but the expected outcome/error,
    content digest, budget, completeness and actual final wording are checked
    against independently frozen evaluator expectations. Model authenticity and
    natural-language overclaims remain separate review gates, never inferred.
    """
    from systemsense.application.local_json_result import selected_json_finding
    from systemsense.domain.evidence import EvidenceRecord
    from systemsense.storage.investigations import InvestigationRepository
    from systemsense.storage.sqlite_store import SQLiteStore

    failures: list[str] = []
    with SQLiteStore(database) as store:
        state = InvestigationRepository(store).load(case_id)
        rows = store.connection.execute(
            "SELECT record_json FROM evidence WHERE case_id=?", (case_id,)
        ).fetchall()
        records = tuple(EvidenceRecord.model_validate_json(row[0]) for row in rows)
        details = tuple(r for r in records if r.collector.id in CHECKS)
        finding = selected_json_finding(store, state, details)
        tasks = [r for r in records if r.collector.id == "task.local_json"]
        if len(tasks) != 1:
            failures.append("unique_task_missing")
        facts = {f.name: f.value for f in tasks[0].facts} if len(tasks) == 1 else {}
        if facts.get("outcome") != spec["expected_task"]:
            failures.append("wrong_task_outcome")
        capture = facts.get("selected_file", {})
        if not isinstance(capture, dict):
            capture = {}
        expected_hash = _hash(materialize(spec["recipe"]))
        if (
            spec["expected_task"] != "unavailable"
            and capture.get("content_sha256") != expected_hash
        ):
            failures.append("wrong_capture")
        if capture.get("error_code") != spec.get("expected_capture", "none"):
            failures.append("wrong_capture_error")
        if finding is None:
            failures.append("no_custodied_discriminating_finding")
            used: set[str] = set()
        else:
            used = set(finding.evidence_ids)
            if state.summary != finding.summary or state.outcome != finding.outcome:
                failures.append("final_report_does_not_use_finding")
            decisive = [r for r in details if str(r.evidence_id) in used]
            if not any(
                isinstance(r.facts[0].value, dict)
                and r.facts[0].value.get("error_code") == spec["expected_error"]
                for r in decisive
            ):
                failures.append("wrong_used_discriminator")
        if str(state.status) != "complete":
            failures.append("incomplete")
        if state.objective != INTAKE or state.budget_ms != 60000 or state.max_rounds != 6:
            failures.append("intake_or_budget_differs")
        if state.max_probes != 16:
            failures.append("probe_budget_differs")
        executions = store.connection.execute(
            "SELECT probe_id,parameters_json FROM probe_executions WHERE case_id=?", (case_id,)
        ).fetchall()
        if any(
            probe not in ALLOWED or (probe in CHECKS and params != "{}")
            for probe, params in executions
        ):
            failures.append("unrelated_or_parameterized_probe")
        if arm == "basic" and not CHECKS <= {probe for probe, _ in executions}:
            failures.append("basic_missing_cheap_check")
        model = _model_evidence(store, case_id, used) if arm != "basic" else {}
        if arm != "basic" and not (
            model["deep_used_discriminating_evidence"]
            and model["competing_menu"]
            and model["selected_discriminator_executed_and_used"]
        ):
            failures.append("model_use_or_competing_menu_missing")
        return {
            "automated_task_success": not failures,
            "failures": failures,
            "used_evidence_ids": sorted(used),
            "model_evidence": model,
            "effective_budget": {
                "ms": state.budget_ms,
                "rounds": state.max_rounds,
                "probes": state.max_probes,
            },
            "observed_provider_calls": [
                call.model_dump(mode="json") for call in state.provider_calls
            ],
            "model_attribution_verified": False,
            "independent_prose_review": "pending" if arm != "basic" else "fixed_report",
            "qualified_model_success": False,
        }


@contextmanager
def application_factory(arm: str) -> Generator[tuple[Callable[..., Any], dict[str, object]]]:
    from systemsense.application.bootstrap import (
        default_capabilities,
        default_case_runtime,
        default_investigator,
    )

    if arm == "basic":
        yield default_investigator, {"mode": "deterministic"}
        return
    if arm != "laya_sol":
        raise ValueError("deep-led route unavailable; never synthesize a comparator")
    from systemsense.application.investigator import Investigator
    from systemsense.application.subscription_setup import load_desktop_subscription_providers

    providers = load_desktop_subscription_providers()
    try:

        def factory(store: Any) -> Any:
            return Investigator(
                store=store,
                runtime=default_case_runtime(store),
                capabilities=default_capabilities(),
                decision=providers.decision,
                reasoning=providers.reasoning,
                knowledge=providers.knowledge,
                catalog_attention=providers.catalog_attention,
                frontier_ranker=providers.frontier_ranker,
            )

        yield factory, providers.runtime_status()
    finally:
        providers.close()


def _source_stamp() -> dict[str, Any]:
    import systemsense.application.service as module

    root = Path(module.__file__).resolve().parents[3]
    revision = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    hashes = {
        str(p.relative_to(root)): _hash(p.read_bytes())
        for p in sorted((root / "src" / "systemsense").rglob("*.py"))
    }
    return {"revision": revision, "dirty": bool(dirty), "source_hashes": hashes}


def run_trial(
    spec: dict[str, Any],
    output: Path,
    *,
    arm: str = "basic",
    release_digest: str | None = None,
) -> dict[str, Any]:
    from systemsense.application.service import ApplicationService

    if os.name != "nt":
        raise RuntimeError("Windows owned-file trials required")
    if spec not in load_cases(spec["split"], release_digest=release_digest):
        raise ValueError("case differs from frozen fixture")
    if arm not in {"basic", "laya_sol"}:
        raise ValueError("unsupported arm; no synthetic comparator")
    _, digest = frozen_suite()
    attempt = output / f"{spec['case_id']}-{arm}-{uuid4().hex}"
    attempt.mkdir(parents=True, exist_ok=False)
    result: dict[str, Any] = {
        "case_id": spec["case_id"],
        "split": spec["split"],
        "arm": arm,
        "protocol_sha256": digest,
        "started_at": datetime.now(UTC).isoformat(),
        "attempt_id": attempt.name,
        "source": None,
        "failures": [],
        "cleanup": False,
        "model_qualification": False,
    }
    _write(attempt / "started.json", result)
    started = time.monotonic()
    owned = tempfile.TemporaryDirectory(prefix="dyad-json-evaluator-")
    selected = Path(owned.name) / spec.get("filename", "private-evaluation-document.json")
    control = Path(owned.name) / "control.json"
    app = None
    warm_started: float | None = None
    resources = None
    try:
        result["source"] = _source_stamp()
        selected.write_bytes(CONTROL)
        control.write_bytes(CONTROL)
        result["before"] = {
            "target": independent_oracle(selected),
            "control": independent_oracle(control),
        }
        with condition(selected, spec):
            result["during"] = {
                "target": independent_oracle(selected),
                "control": independent_oracle(control),
            }
            cold_started = time.monotonic()
            with application_factory(arm) as (factory, runtime):
                from benchmarks.private_alpha_loopback import ResourceSampler

                result["provider_startup_s"] = time.monotonic() - cold_started
                result["runtime"] = runtime
                warm_started = time.monotonic()
                resources = ResourceSampler()
                resources.__enter__()
                app = ApplicationService(
                    attempt / "case.db", factory=factory, enable_local_json=True
                )
                try:
                    opened = app.start_local_json_case(str(selected))
                    case_id = str(opened["case_id"])
                    result["product_case_id"] = case_id
                    app.wait(timeout=75)
                    report = app.get_case(case_id)
                    _write(attempt / "report.json", report)
                    result["failures"].extend(
                        privacy_failures(attempt / "case.db", report, selected, spec)
                    )
                    result["score"] = score_saved_case(attempt / "case.db", case_id, spec, arm)
                finally:
                    app.close()
                    app = None
                    result["warm_elapsed_s"] = time.monotonic() - warm_started
    except Exception as error:
        result["failures"].append(type(error).__name__)
    finally:
        if resources is not None:
            resources.__exit__(None, None, None)
            result["resource_scope"] = (
                "evaluator Python and descendant processes, sampled every 200ms"
            )
            result["tree_rss_peak_bytes"] = max(
                (sample["tree_rss_bytes"] for sample in resources.samples), default=0
            )
            result.update(resources.cpu_metrics())
        if warm_started is not None and "warm_elapsed_s" not in result:
            result["warm_elapsed_s"] = time.monotonic() - warm_started
        if app is not None:
            try:
                app.close()
            except Exception as error:
                result["failures"].append(f"close:{type(error).__name__}")
        try:
            selected.write_bytes(CONTROL)
            result["restored"] = {
                "target": independent_oracle(selected),
                "control": independent_oracle(control),
            }
            for phase in ("before", "during", "restored"):
                pair = result.get(phase)
                if pair is None:
                    result["failures"].append(f"{phase}_missing")
                    continue
                if pair["control"]["task"] != "accepted":
                    result["failures"].append(f"{phase}_control_failed")
                expected = spec["expected_task"] if phase == "during" else "accepted"
                if pair["target"]["task"] != expected:
                    result["failures"].append(f"{phase}_target_failed")
            during = result.get("during", {}).get("target", {})
            if during.get("error") != spec["expected_error"]:
                result["failures"].append("independent_oracle_differs")
        except Exception as error:
            result["failures"].append(f"restore:{type(error).__name__}")
        try:
            owned.cleanup()
            result["cleanup"] = not Path(owned.name).exists()
        except Exception as error:
            result["failures"].append(f"cleanup:{type(error).__name__}")
        result["elapsed_s"] = round(time.monotonic() - started, 6)
        result["success"] = bool(
            not result["failures"]
            and result["cleanup"]
            and result.get("score", {}).get("automated_task_success")
        )
        _write(attempt / "result.json", result)
    return result


def denominator_report(output: Path, *, split: str = "holdout") -> dict[str, Any]:
    protocol, digest = frozen_suite()
    ids = (
        protocol["case_ids"]
        if split == "holdout"
        else [case["case_id"] for case in load_cases("development")]
    )
    results: list[dict[str, Any]] = []
    for started in output.glob("*/started.json"):
        row = json.loads(started.read_text(encoding="utf-8"))
        finished = started.with_name("result.json")
        if finished.exists():
            row = json.loads(finished.read_text(encoding="utf-8"))
        else:
            row["success"] = False
        results.append(row)
    cells: list[dict[str, Any]] = []
    for case_id in ids:
        arms = {}
        for arm in ("basic", "laya_sol", "deep_led"):
            attempts = sorted(
                (
                    row
                    for row in results
                    if row["case_id"] == case_id
                    and row["arm"] == arm
                    and row["protocol_sha256"] == digest
                ),
                key=lambda row: row["started_at"],
            )
            arms[arm] = {
                "attempt_count": len(attempts),
                "first_attempt_success": bool(attempts and attempts[0]["success"]),
                "attempt_ids": [row["attempt_id"] for row in attempts],
            }
        cells.append({"case_id": case_id, "arms": arms})
    return {
        "frozen_denominator": len(ids),
        "cases": cells,
        "deep_led": "unavailable",
        "model_qualification": False,
        "limitation": "No uplift from missing arms, repeats, or unreviewed model receipts.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--split", choices=("development", "holdout"), default="development")
    parser.add_argument("--arm", choices=("basic", "laya_sol"), default="basic")
    parser.add_argument("--case-id", action="append")
    parser.add_argument("--consume-frozen")
    parser.add_argument("--report-only", action="store_true")
    args = parser.parse_args()
    if args.report_only:
        print(json.dumps(denominator_report(args.output, split=args.split), indent=2))
        return
    if args.split == "holdout" and not args.case_id:
        parser.error("holdout runs require explicit --case-id and --consume-frozen")
    cases = load_cases(args.split, release_digest=args.consume_frozen)
    chosen = [case for case in cases if not args.case_id or case["case_id"] in args.case_id]
    if args.case_id and set(args.case_id) != {case["case_id"] for case in chosen}:
        parser.error("unknown case ID")
    for case in chosen:
        result = run_trial(case, args.output, arm=args.arm, release_digest=args.consume_frozen)
        print(json.dumps({key: result[key] for key in ("attempt_id", "success", "failures")}))


if __name__ == "__main__":
    main()
