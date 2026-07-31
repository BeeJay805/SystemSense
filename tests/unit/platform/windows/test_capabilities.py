from datetime import UTC, datetime, timedelta

from systemsense.platform.windows.capabilities import (
    CapabilityDetector,
    CapabilityProbe,
    CapabilityState,
    SystemInfo,
)

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


class FakeBackend:
    def __init__(self, *, platform_name: str = "Windows") -> None:
        self.platform_name = platform_name
        self.probe_calls = 0
        self.raise_for: str | None = None

    def system_info(self) -> SystemInfo:
        return SystemInfo(
            platform=self.platform_name,
            windows_build="26100.1" if self.platform_name == "Windows" else None,
            architecture="AMD64",
        )

    def probe_dll(self, name: str) -> CapabilityProbe:
        return self._probe(f"dll.{name.removesuffix('.dll')}")

    def probe_event_channel(self, name: str) -> CapabilityProbe:
        return self._probe(f"event_channel.{name.lower()}")

    def probe_wer_access(self) -> CapabilityProbe:
        return self._probe("wer.report_archive")

    def probe_tool(self, name: str) -> CapabilityProbe:
        return self._probe(f"tool.{name.removesuffix('.exe').replace('-', '_')}")

    def probe_standard_user(self) -> CapabilityProbe:
        return self._probe("permission.standard_user")

    def _probe(self, name: str) -> CapabilityProbe:
        self.probe_calls += 1
        if name == self.raise_for:
            raise OSError("fixture failure")
        states = {
            "dll.wevtapi": CapabilityState.AVAILABLE,
            "event_channel.application": CapabilityState.DENIED,
            "wer.report_archive": CapabilityState.UNAVAILABLE,
            "tool.nvidia_smi": CapabilityState.UNAVAILABLE,
            "permission.standard_user": CapabilityState.AVAILABLE,
        }
        return CapabilityProbe(
            state=states.get(name, CapabilityState.AVAILABLE),
            detail=f"fixture result for {name}",
        )


def test_detector_returns_structured_windows_capabilities() -> None:
    detector = CapabilityDetector(FakeBackend(), cache_ttl=timedelta(minutes=5))

    snapshot = detector.detect(now=_NOW)

    assert snapshot.platform == "Windows"
    assert snapshot.windows_build == "26100.1"
    assert snapshot.architecture == "AMD64"
    assert snapshot.captured_at == _NOW
    assert snapshot.expires_at == _NOW + timedelta(minutes=5)
    assert snapshot.capability("dll.wevtapi").state is CapabilityState.AVAILABLE
    assert snapshot.capability("event_channel.application").state is CapabilityState.DENIED
    assert snapshot.capability("wer.report_archive").state is CapabilityState.UNAVAILABLE
    assert snapshot.capability("permission.standard_user").state is CapabilityState.AVAILABLE


def test_snapshot_is_cached_until_ttl_expires() -> None:
    backend = FakeBackend()
    detector = CapabilityDetector(backend, cache_ttl=timedelta(minutes=5))

    first = detector.detect(now=_NOW)
    call_count = backend.probe_calls
    cached = detector.detect(now=_NOW + timedelta(minutes=4))
    refreshed = detector.detect(now=_NOW + timedelta(minutes=6))

    assert cached is first
    assert backend.probe_calls == call_count * 2
    assert refreshed is not first


def test_non_windows_platform_reports_unsupported_without_optional_probes() -> None:
    backend = FakeBackend(platform_name="Linux")
    detector = CapabilityDetector(backend)

    snapshot = detector.detect(now=_NOW)

    assert backend.probe_calls == 0
    assert snapshot.capabilities
    assert all(
        capability.state is CapabilityState.UNSUPPORTED for capability in snapshot.capabilities
    )


def test_optional_probe_exception_becomes_structured_error() -> None:
    backend = FakeBackend()
    backend.raise_for = "dll.wevtapi"
    detector = CapabilityDetector(backend)

    snapshot = detector.detect(now=_NOW)

    failed = snapshot.capability("dll.wevtapi")
    assert failed.state is CapabilityState.ERROR
    assert failed.detail == "OSError: fixture failure"
