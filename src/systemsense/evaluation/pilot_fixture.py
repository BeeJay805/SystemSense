"""Replay one synthetic 019 custody episode into a non-trainable pilot corpus.

This deliberately exercises registry and snapshot readback, not Windows probes,
the actual Laya worker, execution, or outcome labels. It is a fixture contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from systemsense.decision.candidates import (
    AdmittedCandidateRefV1,
    CandidateDecisionRequestV1,
    CandidateDecisionResponseV1,
    CandidateProposalV1,
)
from systemsense.decision.contracts import DiagnosticPurpose, ProviderIdentity
from systemsense.domain.ids import CaseId
from systemsense.domain.probes import ProbeInvocation, SafetyClass
from systemsense.evaluation.pilot_corpus import (
    PilotCaseRegistration,
    PilotCorpus,
    assemble_pilot_corpus,
    verify_pilot_corpus,
)
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.sqlite_store import SQLiteStore

_FIXTURE_VERSION = "synthetic-candidate-custody-v1"
_PROVIDER = ProviderIdentity(
    provider_id="fixture-contract", provider_version="1", role="fast_decision"
)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _replay_fixture() -> PilotCorpus:
    now = datetime.now(UTC) - timedelta(seconds=10)
    case_id = CaseId.new()
    with TemporaryDirectory(prefix="systemsense-pilot-fixture-") as scratch:
        with SQLiteStore(Path(scratch) / "fixture.sqlite") as store:
            store.create_case(
                case_id=str(case_id),
                kind="general",
                symptom="Synthetic slow PDF process",
                created_at=now.isoformat(),
                status="collecting",
                state_version=1,
            )
            refs: list[AdmittedCandidateRefV1] = []
            for ordinal in (1, 2):
                candidate_id = f"cand_v1_{ordinal:032x}"
                invocation = ProbeInvocation(
                    probe_id="fixture.pressure",
                    probe_version=1,
                    observable="fixture.pressure",
                    target_handle=f"proc_{ordinal:032x}",
                    parameters={"pid": 100 + ordinal},
                )
                invocation_json = _canonical(invocation.model_dump(mode="json"))
                description = f"Synthetic process pressure target {ordinal}"
                manifest_sha = _digest(_FIXTURE_VERSION)
                store.connection.execute(
                    "INSERT INTO case_measurement_candidates ("
                    "candidate_id,schema_version,case_id,epoch_state_version,probe_id,"
                    "manifest_version,manifest_sha256,invocation_json,invocation_sha256,"
                    "observable,target_handle,source_evidence_id,source_evidence_sha256,"
                    "dependency_bindings_json,dependency_sha256,binding_sha256,cost_ms,"
                    "resource_class,safety_class,description,issued_at,expires_at) "
                    "VALUES (?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        candidate_id,
                        str(case_id),
                        1,
                        invocation.probe_id,
                        invocation.probe_version,
                        manifest_sha,
                        invocation_json,
                        _digest(invocation_json),
                        invocation.observable,
                        invocation.target_handle,
                        "ev_" + "f" * 32,
                        _digest("synthetic-source"),
                        "[]",
                        _digest("[]"),
                        _digest(candidate_id),
                        100,
                        ResourceClass.CPU.value,
                        SafetyClass.R1.value,
                        description,
                        now.isoformat(),
                        (now + timedelta(minutes=5)).isoformat(),
                    ),
                )
                refs.append(
                    AdmittedCandidateRefV1(
                        candidate_id=candidate_id,
                        probe_id=invocation.probe_id,
                        description=description,
                        manifest_sha256=manifest_sha,
                        invocation_sha256=_digest(invocation_json),
                        cost_ms=100,
                        resource_class=ResourceClass.CPU,
                        safety_class=SafetyClass.R1,
                    )
                )
            request = CandidateDecisionRequestV1(
                case_id=case_id,
                state_version=1,
                correlation_id="fixture:pilot:1",
                deadline_at=now + timedelta(minutes=5),
                symptom="Synthetic slow PDF process",
                available_candidates=tuple(refs),
                budget_ms=200,
                max_candidates=1,
            )
            response = CandidateDecisionResponseV1(
                provider=_PROVIDER,
                case_id=case_id,
                state_version=1,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                ranked_candidate_ids=(refs[1].candidate_id, refs[0].candidate_id),
                considered_candidate_ids=tuple(item.candidate_id for item in refs),
                proposals=(
                    CandidateProposalV1(
                        candidate_id=refs[1].candidate_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1.0,
                    ),
                ),
            )
            snapshots = CandidateDecisionSnapshotRepository(
                store, clock=lambda: now + timedelta(seconds=1)
            )
            snapshot = snapshots.capture(request, response, request_frozen_at=now)
            registration = PilotCaseRegistration(
                snapshot_id=snapshot.snapshot_id,
                split="fixture",
                source_kind="fixture_contract",
                source_artifact_sha256=_digest(_FIXTURE_VERSION),
                machine_key="synthetic-machine-1",
                fault_family="synthetic-process-pressure",
                application_key="synthetic-pdf-reader",
                application_version="1",
            )
            return assemble_pilot_corpus(store, snapshots, (registration,))


def write_fixture_corpus(output_dir: Path) -> dict[str, object]:
    """Write an exclusive output directory; never overwrite a previous pilot."""

    corpus = _replay_fixture()
    digest = verify_pilot_corpus(corpus)
    manifest: dict[str, object] = {
        "schema_version": 1,
        "classification": "candidate_custody_pilot_only",
        "source_kind": "fixture_contract",
        "source_authenticity": "not_verified",
        "worker_input_parity": "not_proven",
        "training_admissible": False,
        "diagnostic_performance_admissible": False,
        "corpus_manifest_sha256": digest,
        "source_counts": corpus.source_counts,
        "label_quality_counts": corpus.label_quality_counts,
        "split_counts": corpus.split_counts,
        "episode_count": len(corpus.episodes),
        "candidate_count": sum(len(item.candidates) for item in corpus.episodes),
        "unrun_alternative_count": sum(
            candidate.execution_id is None
            for item in corpus.episodes
            for candidate in item.candidates
        ),
    }
    output_dir.mkdir(parents=False, exist_ok=False)
    with (output_dir / "corpus.json").open("x", encoding="utf-8") as stream:
        stream.write(corpus.model_dump_json(indent=2))
    with (output_dir / "run_manifest.json").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(manifest, indent=2, sort_keys=True))
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay a non-trainable fixture pilot corpus")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(write_fixture_corpus(args.output_dir), sort_keys=True))


if __name__ == "__main__":
    main()
