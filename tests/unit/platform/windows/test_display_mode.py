from datetime import UTC, datetime

from systemsense.platform.windows import display_mode


class FakeMode:
    def __init__(self, frequency: int) -> None:
        self.PelsWidth = 2560
        self.PelsHeight = 1440
        self.DisplayFrequency = frequency


class FakeDisplayBackend:
    def __init__(self, frequency: int = 144) -> None:
        self.frequency = frequency
        self.calls: list[tuple[None, int]] = []

    def EnumDisplaySettings(self, name: None, setting: int) -> FakeMode:
        self.calls.append((name, setting))
        return FakeMode(self.frequency)


NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)


def test_current_display_mode_reports_refresh_as_display_fact_only() -> None:
    backend = FakeDisplayBackend()
    observation = display_mode.collect_display_mode(backend=backend, clock=lambda: NOW)

    assert backend.calls == [(None, -1)]
    assert observation.status == "available"
    assert observation.refresh_hz == 144
    assert observation.width_pixels == 2560
    assert observation.height_pixels == 1440
    assert observation.observed_at == NOW
    assert observation.captured_at == NOW
    assert "game" in " ".join(observation.limitations).lower()


def test_default_refresh_is_unknown_not_one_hertz() -> None:
    observation = display_mode.collect_display_mode(
        backend=FakeDisplayBackend(frequency=1), clock=lambda: NOW
    )

    assert observation.status == "partial"
    assert observation.refresh_hz is None
    assert "default" in " ".join(observation.limitations).lower()


def test_display_query_failure_preserves_unavailable_status() -> None:
    class FailingBackend:
        def EnumDisplaySettings(self, name: None, setting: int) -> FakeMode:
            raise OSError("display unavailable")

    observation = display_mode.collect_display_mode(backend=FailingBackend(), clock=lambda: NOW)

    assert observation.status == "failed"
    assert observation.refresh_hz is None
    assert observation.width_pixels is None
    assert observation.height_pixels is None
    assert observation.schema_version == 1
    assert "display unavailable" not in " ".join(observation.limitations)
    assert "query failed" in " ".join(observation.limitations)


def test_win32_backend_error_is_evidence_not_a_successful_empty_mode() -> None:
    class FailingBackend:
        def EnumDisplaySettings(self, name: None, setting: int) -> FakeMode:
            raise RuntimeError(r"C:\Users\private\device-profile.txt")

    observation = display_mode.collect_display_mode(backend=FailingBackend(), clock=lambda: NOW)

    assert observation.status == "failed"
    assert observation.refresh_hz is None
    assert "C:\\Users" not in " ".join(observation.limitations)
    assert "RuntimeError" in " ".join(observation.limitations)
