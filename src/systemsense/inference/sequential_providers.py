"""Opt-in v4 provider adapters over one sequential, tree-owned local runtime."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from contextvars import ContextVar
from typing import Any, Protocol, cast

from systemsense.inference.control import current_cancellation
from systemsense.inference.laya_runtime import (
    LayaAttentionResult,
    LayaRuntimeConfig,
    LayaRuntimeError,
    LayaSubprocessRuntime,
)
from systemsense.inference.managed_laya import ManagedLayaAdmission, ManagedLayaPolicy
from systemsense.inference.managed_ollama import ManagedOllamaAdmission, ManagedOllamaPolicy
from systemsense.inference.ollama import LocalInferenceError, OllamaChatClient, OllamaPreloadResult
from systemsense.inference.owned_ollama import OwnedOllamaConfig
from systemsense.inference.profile import LocalInferenceProfile
from systemsense.inference.sequential_local import (
    OwnedLocalSession,
    SequentialLocalCoordinator,
    SequentialLocalStatus,
    SequentialLocalUnavailable,
)
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.inference.tree_host_lease import TreeHostInferenceLeaseLedger


class _FastSession(Protocol):
    def start(self) -> None: ...

    def is_usable(self) -> bool: ...

    def close_verified(self) -> bool: ...

    def attend(self, **kwargs: Any) -> Any: ...

    def rank(self, **kwargs: Any) -> Any: ...


class _DeepSession(Protocol):
    def start(self) -> None: ...

    def is_usable(self) -> bool: ...

    def close_verified(self) -> bool: ...

    def complete(self, **kwargs: Any) -> Any: ...


_call_deadline: ContextVar[float | None] = ContextVar("v4_call_deadline", default=None)


def _checked_call[ResultT](
    session: OwnedLocalSession,
    call: Callable[[], ResultT],
    error_type: type[RuntimeError],
) -> ResultT:
    result = call()
    try:
        usable = session.is_usable()
    except Exception:
        usable = False
    if not usable:
        raise error_type("session_retired")
    return result


class SequentialLayaRanker:
    def __init__(self, owner: SequentialAdvisoryRuntime) -> None:
        self._owner = owner
        self._attested: OrderedDict[int, LayaAttentionResult] = OrderedDict()
        self._attestation_lock = threading.Lock()

    def attests_result(self, attention: LayaAttentionResult) -> bool:
        with self._attestation_lock:
            return self._attested.get(id(attention)) is attention

    def _attend_session(
        self,
        session: OwnedLocalSession,
        deadline: float,
        timeout_seconds: float,
        kwargs: dict[str, Any],
    ) -> Any:
        result = _checked_call(
            session,
            lambda: cast(_FastSession, session).attend(
                timeout_seconds=min(timeout_seconds, max(0.0, deadline - time.monotonic())),
                **kwargs,
            ),
            LayaRuntimeError,
        )
        # Only an exact owned production runtime may attest model presentation.
        if (
            type(session) is ManagedFastSession
            and type(session.runtime) is LayaSubprocessRuntime
            and session.runtime._using_real_subprocess
            and type(result) is LayaAttentionResult
        ):
            with self._attestation_lock:
                self._attested[id(result)] = result
                self._attested.move_to_end(id(result))
                if len(self._attested) > 64:
                    self._attested.popitem(last=False)
        return result

    def attend(self, *, timeout_seconds: float, **kwargs: Any) -> Any:
        cancellation = current_cancellation()
        try:
            return self._owner.coordinator.run(
                "fast",
                lambda session, deadline, _cancelled: self._attend_session(
                    session, deadline, timeout_seconds, kwargs
                ),
                deadline_at=time.monotonic() + timeout_seconds,
                cancelled=(cancellation.is_set if cancellation is not None else lambda: False),
            )
        except SequentialLocalUnavailable as error:
            raise LayaRuntimeError(str(error)) from error

    def rank(self, *, timeout_seconds: float, **kwargs: Any) -> Any:
        cancellation = current_cancellation()
        try:
            return self._owner.coordinator.run(
                "fast",
                lambda session, deadline, _cancelled: _checked_call(
                    session,
                    lambda: cast(_FastSession, session).rank(
                        timeout_seconds=min(timeout_seconds, max(0.0, deadline - time.monotonic())),
                        **kwargs,
                    ),
                    LayaRuntimeError,
                ),
                deadline_at=time.monotonic() + timeout_seconds,
                cancelled=(cancellation.is_set if cancellation is not None else lambda: False),
            )
        except SequentialLocalUnavailable as error:
            raise LayaRuntimeError(str(error)) from error

    def prewarm(self, *, timeout_seconds: float) -> None:
        self.rank(
            state={"attention_kind": "probe_relevance", "symptom": "worker readiness"},
            candidates=({"probe_id": "core.system", "description": "Read-only system snapshot"},),
            timeout_seconds=timeout_seconds,
        )


class _Client(OllamaChatClient):
    def __init__(self, owner: SequentialAdvisoryRuntime, config: LocalInferenceConfig):
        self._owner = owner
        super().__init__(config=config)

    def fits_context(self, prompt: str, schema: Any) -> bool:
        return super().fits_context(prompt, schema)

    def complete(self, *, timeout_seconds: float, **kwargs: Any) -> Any:
        deadline_at = time.monotonic() + timeout_seconds
        token = _call_deadline.set(deadline_at)
        cancellation = current_cancellation()
        try:
            return self._owner.coordinator.run(
                "deep",
                lambda session, deadline, _cancelled: _checked_call(
                    session,
                    lambda: cast(_DeepSession, session).complete(
                        timeout_seconds=min(timeout_seconds, max(0.0, deadline - time.monotonic())),
                        **kwargs,
                    ),
                    LocalInferenceError,
                ),
                deadline_at=deadline_at,
                cancelled=(cancellation.is_set if cancellation is not None else lambda: False),
            )
        except SequentialLocalUnavailable as error:
            raise LocalInferenceError(str(error)) from error
        finally:
            _call_deadline.reset(token)

    def preload(self, *, model: str, timeout_seconds: float) -> OllamaPreloadResult:
        return OllamaPreloadResult(
            status="degraded",
            model=model,
            digest=None,
            keep_alive_seconds=0,
            reason="managed_prewarm_requires_owner",
        )


class SequentialAdvisoryRuntime:
    """One coordinator for all fast rank entry points and deep completions."""

    def __init__(
        self,
        *,
        fast_factory: Callable[[], OwnedLocalSession],
        deep_factory: Callable[[], OwnedLocalSession],
        reasoning_config: LocalInferenceConfig,
    ) -> None:
        self._session_lock = threading.Lock()
        self._last_fast: OwnedLocalSession | None = None
        self._last_deep: OwnedLocalSession | None = None

        def track_fast() -> OwnedLocalSession:
            session = fast_factory()
            with self._session_lock:
                self._last_fast = session
            return session

        def track_deep() -> OwnedLocalSession:
            session = deep_factory()
            with self._session_lock:
                self._last_deep = session
            return session

        self.coordinator = SequentialLocalCoordinator(
            fast_factory=track_fast, deep_factory=track_deep
        )
        self.ranker = SequentialLayaRanker(self)
        self.client = _Client(self, reasoning_config)

    @property
    def status(self) -> SequentialLocalStatus:
        return self.coordinator.status

    def role_status(self, role: str) -> tuple[str, str]:
        with self._session_lock:
            session = self._last_fast if role == "fast" else self._last_deep
        if session is None:
            return "not_started", "not_started"
        if isinstance(session, (ManagedFastSession, ManagedDeepSession)):
            status = session.admission.status
            return status.phase, status.reason
        try:
            usable = session.is_usable()
        except Exception:
            return "unknown", "admission_status_unavailable"
        return ("active" if usable else "closed"), "admission_status_unavailable"

    def close(self, *, deadline_at: float) -> bool:
        return self.coordinator.close(deadline_at=deadline_at)


class ManagedFastSession:
    """One Laya runtime and its one-shot Job-tree admission."""

    def __init__(self, config: LayaRuntimeConfig, admission: ManagedLayaAdmission) -> None:
        self.admission = admission
        self.runtime = LayaSubprocessRuntime(
            config,
            startup_admission=admission.startup_admission,
            call_admission=admission.call_admission,
            tree_custody_enabled=True,
        )
        admission.attach_runtime(self.runtime)

    def start(self) -> None:
        # The first bounded rank starts the worker; construction/start are inert.
        if self.admission.status.phase != "ready":
            raise LayaRuntimeError("managed Laya admission unavailable")

    def is_usable(self) -> bool:
        return self.admission.status.phase in ("ready", "leased")

    def close_verified(self) -> bool:
        return self.admission.close().phase == "closed"

    def attend(self, **kwargs: Any) -> Any:
        return self.runtime.attend(**kwargs)

    def rank(self, **kwargs: Any) -> Any:
        return self.runtime.rank(**kwargs)


class ManagedDeepSession:
    """One dedicated owned Ollama server with an admitted managed client."""

    def __init__(self, config: LocalInferenceConfig, admission: ManagedOllamaAdmission) -> None:
        self.admission = admission
        self.client = OllamaChatClient(
            config=config,
            managed_call_admission=admission.call_admission,
            managed_abort=lambda: admission.close().phase == "closed",
        )

    def start(self) -> None:
        if self.admission.start().phase != "ready":
            raise LocalInferenceError("owned Ollama service is unavailable")

    def is_usable(self) -> bool:
        return self.admission.status.phase == "ready"

    def close_verified(self) -> bool:
        return self.admission.close().phase == "closed"

    def complete(self, **kwargs: Any) -> Any:
        return self.client.complete(**kwargs)


def build_fast_session(
    profile: LocalInferenceProfile, ledger: TreeHostInferenceLeaseLedger
) -> ManagedFastSession:
    resources = profile.managed_resources
    if profile.schema_version != 4 or resources is None:
        raise ValueError("v4 fast session requires pinned managed resources")
    config = profile.laya.runtime_config()
    policy = ManagedLayaPolicy(
        gpu_device_index=resources.gpu_device_index,
        gpu_uuid=resources.gpu_uuid,
        peak_ram_bytes=resources.peak_ram_bytes,
        peak_vram_bytes=resources.peak_vram_bytes,
        ram_reserve_bytes=resources.ram_reserve_bytes,
        target_vram_reserve_bytes=resources.target_vram_reserve_bytes,
        max_telemetry_age_ms=resources.max_telemetry_age_ms,
        renew_interval_seconds=resources.renew_interval_seconds,
    )
    admission = ManagedLayaAdmission(policy, ledger)
    return ManagedFastSession(config, admission)


def build_deep_session(
    profile: LocalInferenceProfile, ledger: TreeHostInferenceLeaseLedger
) -> ManagedDeepSession:
    pin = profile.managed_reasoning
    resources = profile.managed_resources
    if profile.schema_version != 4 or pin is None or resources is None:
        raise ValueError("v4 deep session requires pinned managed reasoning")
    deadline_at = _call_deadline.get()
    startup_timeout = pin.startup_timeout_seconds
    if deadline_at is not None:
        startup_timeout = min(startup_timeout, deadline_at - time.monotonic())
        if startup_timeout <= 0:
            raise LocalInferenceError("owned Ollama startup deadline elapsed")
    config = OwnedOllamaConfig(
        executable=pin.executable,
        executable_sha256=pin.executable_sha256,
        models_dir=pin.models_dir,
        endpoint=pin.endpoint,
        model=pin.model,
        model_digest=pin.model_digest,
        startup_timeout_seconds=startup_timeout,
        exit_timeout_seconds=pin.exit_timeout_seconds,
    )
    policy = ManagedOllamaPolicy(
        gpu_device_index=pin.gpu_device_index,
        gpu_uuid=resources.gpu_uuid,
        peak_ram_bytes=pin.peak_ram_bytes,
        peak_vram_bytes=pin.peak_vram_bytes,
        ram_reserve_bytes=pin.ram_reserve_bytes,
        vram_reserve_bytes=pin.target_vram_reserve_bytes,
        max_telemetry_age_ms=resources.max_telemetry_age_ms,
        renew_interval_seconds=resources.renew_interval_seconds,
    )
    return ManagedDeepSession(
        reasoning_config(profile), ManagedOllamaAdmission(config, policy, ledger)
    )


def reasoning_config(profile: LocalInferenceProfile) -> LocalInferenceConfig:
    pin = profile.managed_reasoning
    if profile.schema_version != 4 or pin is None:
        raise ValueError("v4 reasoning requires a pinned service")
    return LocalInferenceConfig(
        enabled=True,
        endpoint=pin.endpoint,
        reasoning_model=pin.model,
        reasoning_digest=pin.model_digest,
        allow_gpu=True,
        keep_alive_seconds=0,
        timeout_seconds=pin.call_timeout_seconds,
        context_tokens=pin.context_tokens,
        output_tokens=pin.output_tokens,
    )
