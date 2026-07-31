from pathlib import Path

from benchmarks.resources import measure_idle, measure_operation
from systemsense.storage.sqlite_store import SQLiteStore

_MEBIBYTE = 1024 * 1024


def test_idle_process_stays_below_cpu_and_memory_budget() -> None:
    measurement = measure_idle(
        duration_seconds=0.25,
        sample_interval_seconds=0.05,
    )

    assert measurement.average_cpu_percent <= 10.0
    assert measurement.peak_rss_bytes <= 128 * _MEBIBYTE
    assert measurement.sample_count >= 4


def test_case_measurement_reports_time_io_and_database_growth(tmp_path: Path) -> None:
    database_path = tmp_path / "systemsense.db"

    def create_case() -> None:
        with SQLiteStore(database_path) as store:
            store.create_case(
                case_id="case_11111111111111111111111111111111",
                kind="general",
                symptom="resource fixture",
                created_at="2026-07-30T12:00:00+00:00",
            )

    measurement = measure_operation(create_case, database_path=database_path)

    assert measurement.elapsed_ms >= 0
    assert measurement.peak_rss_bytes > 0
    assert measurement.read_bytes >= 0
    assert measurement.write_bytes >= 0
    assert measurement.database_growth_bytes > 0
