"""The v4 advisory adapters serialize every neural consumer."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from systemsense.decision.catalog_attention import CatalogAttentionRequest
from systemsense.decision.contracts import ProbeCapability, ResourceClass
from systemsense.decision.frontier_ranker import FrontierItemSemanticV1, FrontierRankRequestV1
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.evidence.retrieval import EvidenceCatalogEntry, EvidenceCatalogPage
from systemsense.inference.control import inference_cancellation
from systemsense.inference.factory import load_sequential_v4_providers
from systemsense.inference.host_lease import LeaseBudget
from systemsense.inference.laya_runtime import (
    LayaAttentionMicrobatch,
    LayaAttentionResult,
    LayaCachedOrigin,
    LayaRuntimeConfig,
    LayaRuntimeError,
    LayaSubprocessRuntime,
)
from systemsense.inference.managed_ollama import ManagedOllamaStatus
from systemsense.inference.ollama import LocalInferenceError
from systemsense.inference.profile import LocalInferenceProfile
from systemsense.inference.sequential_providers import (
    ManagedDeepSession,
    ManagedFastSession,
    SequentialAdvisoryRuntime,
)
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.inference.tree_host_lease import TreeHostInferenceLeaseLedger
from systemsense.reasoning.contracts import ReasoningRequest
from systemsense.storage.search_frontier import (
    FrontierItemV1,
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
)


class _Session:
    def __init__(self, role: str, events: list[str], *, release: bool = True) -> None:
        self.role = role
        self.events = events
        self.release = release
        self.open = False

    def start(self) -> None:
        assert sum(item.startswith("start:") for item in self.events) == sum(
            item.startswith("close:") for item in self.events
        )
        self.open = True
        self.events.append(f"start:{self.role}")

    def is_usable(self) -> bool:
        return self.open

    def close_verified(self) -> bool:
        assert sum(item.startswith("start:") for item in self.events) == 1 + sum(
            item.startswith("close:") for item in self.events
        )
        self.events.append(f"close:{self.role}")
        self.open = False
        return self.release

    def attend(self, **kwargs: Any) -> Any:
        self.events.append("attend")
        return "attention"

    def rank(self, **kwargs: Any) -> str:
        self.events.append("rank")
        return "ranking"

    def complete(self, **kwargs: Any) -> dict[str, str]:
        self.events.append("complete")
        return {"answer": "bounded"}


@pytest.mark.parametrize(
    "reason", ("startup_server_exited", "vram_headroom", "service_readiness_unverified")
)
def test_deep_session_exposes_sanitized_startup_status(reason: str) -> None:
    status = ManagedOllamaStatus("closed", reason, None, None, "a" * 64)
    admission = SimpleNamespace(
        start=lambda: status,
        call_admission=lambda: False,
        close=lambda: status,
    )
    session = ManagedDeepSession(
        LocalInferenceConfig(enabled=True, allow_gpu=True),
        admission,  # type: ignore[arg-type]
    )
    with pytest.raises(LocalInferenceError, match=reason):
        session.start()


def test_all_fast_consumers_and_deep_call_use_one_coordinator() -> None:
    events: list[str] = []
    runtime = SequentialAdvisoryRuntime(
        fast_factory=lambda: _Session("fast", events),
        deep_factory=lambda: _Session("deep", events),
        reasoning_config=LocalInferenceConfig(),
    )
    assert runtime.role_status("fast") == ("not_started", "not_started")
    assert runtime.role_status("deep") == ("not_started", "not_started")
    assert (
        runtime.ranker.attend(state={}, evidence=(), candidates=(), timeout_seconds=1)
        == "attention"
    )
    assert runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1) == "ranking"
    assert runtime.client.complete(model="local", prompt="x", schema={}, timeout_seconds=1) == {
        "answer": "bounded"
    }
    assert runtime.role_status("fast")[0] == "closed"
    assert runtime.role_status("deep")[0] == "active"
    assert runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1) == "ranking"
    assert events == [
        "start:fast",
        "attend",
        "rank",
        "close:fast",
        "start:deep",
        "complete",
        "close:deep",
        "start:fast",
        "rank",
    ]
    assert runtime.close(deadline_at=time.monotonic() + 1)
    assert events[-1] == "close:fast"


def test_unverified_release_quarantines_opposite_role() -> None:
    events: list[str] = []
    runtime = SequentialAdvisoryRuntime(
        fast_factory=lambda: _Session("fast", events, release=False),
        deep_factory=lambda: _Session("deep", events),
        reasoning_config=LocalInferenceConfig(),
    )
    runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1)
    with pytest.raises(LocalInferenceError, match="close_unverified"):
        runtime.client.complete(model="local", prompt="x", schema={}, timeout_seconds=1)
    assert events == ["start:fast", "rank", "close:fast"]
    assert runtime.status.quarantined_reason == "close_unverified"
    assert not runtime.close(deadline_at=time.monotonic() + 1)


def test_failed_call_retires_session_before_reuse() -> None:
    events: list[str] = []

    class Failed(_Session):
        def attend(self, **kwargs: Any) -> str:
            raise RuntimeError("worker failed")

    runtime = SequentialAdvisoryRuntime(
        fast_factory=lambda: Failed("fast", events),
        deep_factory=lambda: _Session("deep", events),
        reasoning_config=LocalInferenceConfig(),
    )
    with pytest.raises(RuntimeError, match="worker failed"):
        runtime.ranker.attend(state={}, evidence=(), candidates=(), timeout_seconds=1)
    assert events == ["start:fast", "close:fast"]
    runtime.client.complete(model="local", prompt="x", schema={}, timeout_seconds=1)
    assert events[-2:] == ["start:deep", "complete"]


def test_self_retired_deep_session_cannot_return_accepted_advice() -> None:
    events: list[str] = []

    class Retiring(_Session):
        def complete(self, **kwargs: Any) -> dict[str, str]:
            self.open = False
            return {"answer": "stale"}

    runtime = SequentialAdvisoryRuntime(
        fast_factory=lambda: _Session("fast", events),
        deep_factory=lambda: Retiring("deep", events),
        reasoning_config=LocalInferenceConfig(),
    )
    with pytest.raises(LocalInferenceError, match="session_retired"):
        runtime.client.complete(model="local", prompt="x", schema={}, timeout_seconds=1)
    assert events == ["start:deep", "close:deep"]


def test_cancelled_fast_waiter_never_starts_after_deep_releases() -> None:
    events: list[str] = []
    entered = threading.Event()
    release = threading.Event()
    cancelled = threading.Event()

    class BusyDeep(_Session):
        def complete(self, **kwargs: Any) -> dict[str, str]:
            entered.set()
            assert release.wait(2)
            return {"answer": "ok"}

    runtime = SequentialAdvisoryRuntime(
        fast_factory=lambda: _Session("fast", events),
        deep_factory=lambda: BusyDeep("deep", events),
        reasoning_config=LocalInferenceConfig(),
    )
    thread = threading.Thread(
        target=lambda: runtime.client.complete(
            model="local", prompt="x", schema={}, timeout_seconds=2
        )
    )
    thread.start()
    assert entered.wait(1)
    with inference_cancellation(cancelled):
        cancelled.set()
        with pytest.raises(LayaRuntimeError, match="call_cancelled"):
            runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1)
    release.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert "start:fast" not in events


def test_proxy_forwards_owned_runtime_trace_after_role_switch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = LayaAttentionResult(
        ranked_probe_ids=("p",),
        considered_probe_ids=("p",),
        microbatches=(
            LayaAttentionMicrobatch(
                phase="probe",
                batch_index=0,
                candidate_ids=("p",),
                cache_hit_ids=("p",),
                cached_origins=(LayaCachedOrigin(item_id="p", presentation_sha256="a" * 64),),
            ),
        ),
    )
    worker = LayaSubprocessRuntime(
        LayaRuntimeConfig(interpreter_path=tmp_path / "python.exe", model_path=tmp_path)
    )

    def attend(**_kwargs: Any) -> LayaAttentionResult:
        return result

    # This verifies adapter provenance routing; worker-input parity has separate runtime tests.
    monkeypatch.setattr(worker, "attend", attend)
    session = object.__new__(ManagedFastSession)
    session.runtime = worker

    class Admission:
        status = type("Status", (), {"phase": "ready"})()

        def close(self) -> Any:
            return type("Status", (), {"phase": "closed"})()

    session.admission = Admission()  # type: ignore[assignment]
    runtime = SequentialAdvisoryRuntime(
        fast_factory=lambda: session,
        deep_factory=lambda: _Session("deep", []),
        reasoning_config=LocalInferenceConfig(),
    )
    attention = runtime.ranker.attend(state={}, evidence=(), candidates=(), timeout_seconds=1)
    runtime.client.complete(model="local", prompt="x", schema={}, timeout_seconds=1)
    provider = LayaDecisionProvider(ranker=runtime.ranker)
    assert (
        provider._presentation_trace(  # pyright: ignore[reportPrivateUsage]
            attention, (), ({"probe_id": "p", "description": "probe"},)
        )
        is not None
    )

    class UntrustedRanker:
        def attend(self, **_kwargs: Any) -> LayaAttentionResult:
            return attention

        def attests_result(self, _attention: LayaAttentionResult) -> bool:
            return True

    spoof = LayaDecisionProvider(ranker=UntrustedRanker())
    assert (
        spoof._presentation_trace(  # pyright: ignore[reportPrivateUsage]
            attention, (), ({"probe_id": "p", "description": "probe"},)
        )
        is None
    )


def test_explicit_factory_keeps_one_ledger_and_inert_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import systemsense.inference.sequential_providers as sequential_module

    executable = tmp_path / "ollama.exe"
    executable.write_bytes(b"fixture")
    models = tmp_path / "models"
    models.mkdir()

    def valid_install(_self: LayaRuntimeConfig) -> object:
        return object()

    monkeypatch.setattr(LayaRuntimeConfig, "validate_install", valid_install)
    resources = {
        "gpu_device_index": 0,
        "gpu_uuid": "GPU-12345678-1234-1234-1234-123456789abc",
    }
    profile = LocalInferenceProfile.model_validate(
        {
            "schema_version": 4,
            "decision_provider": "laya",
            "reasoning_provider": "ollama",
            "laya": {
                "enabled": True,
                "device": "cuda",
                "interpreter_path": str(tmp_path / "python.exe"),
                "model_path": str(tmp_path),
            },
            "managed_resources": resources,
            "managed_reasoning": {
                "executable": str(executable),
                "executable_sha256": "a" * 64,
                "models_dir": str(models),
                "endpoint": "http://127.0.0.1:12435/api/chat",
                "model": "local:1",
                "model_digest": "b" * 64,
                "gpu_device_index": 0,
                "peak_ram_bytes": 2 * 1024**3,
                "peak_vram_bytes": 2 * 1024**3,
                "ram_reserve_bytes": 4 * 1024**3,
                "target_vram_reserve_bytes": 6 * 1024**3,
                "context_tokens": 32768,
                "output_tokens": 512,
                "startup_timeout_seconds": 2,
                "call_timeout_seconds": 3,
                "idle_timeout_seconds": 3,
                "exit_timeout_seconds": 2,
            },
        }
    )
    ledger = TreeHostInferenceLeaseLedger(
        tmp_path / "leases.sqlite3", LeaseBudget(1, 2 * 1024**3, 2 * 1024**3, 0)
    )
    events: list[str] = []
    seen: list[TreeHostInferenceLeaseLedger] = []

    class FrontierSession(_Session):
        def attend(self, **kwargs: Any) -> LayaAttentionResult:
            self.events.append("attend")
            candidates = kwargs["candidates"]
            offered = tuple(item["probe_id"] for item in candidates)
            return LayaAttentionResult(
                ranked_probe_ids=offered,
                considered_probe_ids=offered,
                attention_notes=(
                    "coverage_limited=false",
                    "state_truncated_batches=0",
                    "instruction_truncated_items=0",
                ),
                microbatches=(
                    LayaAttentionMicrobatch(
                        phase="probe",
                        batch_index=0,
                        candidate_ids=offered,
                        cache_hit_ids=offered,
                        cached_origins=tuple(
                            LayaCachedOrigin(item_id=item, presentation_sha256="a" * 64)
                            for item in offered
                        ),
                    ),
                ),
            )

    def fast(_profile: LocalInferenceProfile, supplied: TreeHostInferenceLeaseLedger) -> _Session:
        seen.append(supplied)
        return FrontierSession("fast", events)

    def deep(_profile: LocalInferenceProfile, supplied: TreeHostInferenceLeaseLedger) -> _Session:
        seen.append(supplied)
        return _Session("deep", events)

    monkeypatch.setattr(sequential_module, "build_fast_session", fast)
    monkeypatch.setattr(sequential_module, "build_deep_session", deep)
    providers = load_sequential_v4_providers(profile, ledger)
    assert isinstance(providers.decision, LayaDecisionProvider)
    assert providers.runtime_status()["decision_status"] == "not_started"
    assert providers.runtime_status()["neural_reasoning_status"] == "not_started"
    assert providers.runtime_status()["reasoning_digest"] == "b" * 64
    assert not events and not seen
    assert providers.catalog_attention is not None
    assert providers.frontier_ranker is not None
    runtime = providers._sequential_runtime  # pyright: ignore[reportPrivateUsage]
    assert runtime is not None
    runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1)
    runtime.client.complete(model="local:1", prompt="x", schema={}, timeout_seconds=1)
    assert seen == [ledger, ledger]
    assert providers.runtime_status()["neural_reasoning_status"] == "active"
    request = ReasoningRequest(
        case_id=CaseId.new(),
        state_version=1,
        correlation_id="v4_reasoning",
        deadline_at=datetime.now(UTC) + timedelta(seconds=10),
        objective="Explain the failure using only observed evidence.",
        available_probes=(
            ProbeCapability(
                probe_id="core.system",
                description="Read-only system snapshot",
                cost_ms=100,
                resource_class=ResourceClass.CPU,
            ),
        ),
        budget_ms=500,
        max_probes=1,
    )
    assert providers.reasoning.investigate(request).degraded
    assert events.count("complete") == 2
    case_id = CaseId.new()
    now = datetime.now(UTC)
    page = EvidenceCatalogPage(
        case_evidence_generation=1,
        entries=(
            EvidenceCatalogEntry(
                evidence_id=EvidenceId.new(),
                case_id=case_id,
                observed_at=now,
                captured_at=now,
                collector_id="eventlog",
                source_id="source",
                summary="untrusted summary",
            ),
        ),
    )
    attention_request = CatalogAttentionRequest.from_page(
        case_id=case_id,
        page=page,
        visible_evidence_ids=(),
        deadline_at=now + timedelta(seconds=5),
    )
    assert providers.catalog_attention is not None
    providers.catalog_attention.rank_catalog(attention_request)
    assert events.count("rank") >= 2
    assert seen == [ledger, ledger, ledger]
    assert providers.frontier_ranker is not None
    frontier_case = CaseId.new()
    frontier_now = datetime.now(UTC)
    item = FrontierItemV1(
        item_id="fr_v1_" + "1" * 64,
        case_id=frontier_case,
        reference=FrontierReferenceV1(
            kind="consult_deep",
            question_id="question_v1_" + "2" * 32,
        ),
        versions=RelevantVersionsV1(objective=1),
        status=FrontierStatus.REQUESTED,
        created_at=frontier_now,
    )
    semantic = FrontierItemSemanticV1(
        item_id=item.item_id,
        case_id=frontier_case,
        reference_id="question_v1_" + "2" * 32,
        source_kind="reasoning_question",
        source_record_sha256="c" * 64,
        source_recorded_at=frontier_now,
        source_time_quality="source_recorded",
        quality="proposed",
        information_goal="What explains the failure?",
        target_scope="host",
        target_label="Current case",
    )
    frontier_request = FrontierRankRequestV1(
        case_id=frontier_case,
        provider=providers.decision.identity,
        model_weight_sha256=providers.frontier_ranker.model_weight_sha256,
        deadline_at=frontier_now + timedelta(seconds=5),
        symptom="Application failed",
        items=(item,),
        item_semantics=(semantic,),
    )
    first = providers.frontier_ranker.rank(frontier_request)
    second = providers.frontier_ranker.rank(frontier_request)
    assert first.ranking_source == "laya"
    assert not first.cache_hit and second.cache_hit
    assert events.count("attend") == 1
    providers.close()
    assert providers.runtime_status()["decision_status"] == "closed"


def test_core_laya_and_factory_import_without_windows_job_modules() -> None:
    program = """
import importlib.abc
import sys
class BlockWindowsJob(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith('win32'):
            raise ModuleNotFoundError(fullname)
        return None
sys.meta_path.insert(0, BlockWindowsJob())
import systemsense.decision.laya
import systemsense.inference.factory
"""
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_v4_prewarm_returns_typed_degradation_without_starting_role() -> None:
    events: list[str] = []
    runtime = SequentialAdvisoryRuntime(
        fast_factory=lambda: _Session("fast", events),
        deep_factory=lambda: _Session("deep", events),
        reasoning_config=LocalInferenceConfig(
            enabled=True,
            reasoning_model="local:1",
            reasoning_digest="b" * 64,
        ),
    )
    result = runtime.client.preload(model="local:1", timeout_seconds=1)
    assert result.status == "degraded"
    assert result.reason == "managed_prewarm_requires_owner"
    assert result.digest is None
    assert not events
    assert runtime.status.active_role is None
