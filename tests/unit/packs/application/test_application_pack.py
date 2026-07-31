import hashlib
from datetime import UTC, datetime
from pathlib import Path

from systemsense.packs.application.files import (
    SignatureState,
    StaticFileMetadataBackend,
    inspect_file,
)
from systemsense.packs.application.ports import (
    NetworkConnection,
    collect_expected_ports,
)
from systemsense.packs.application.processes import (
    ProcessSnapshot,
    collect_matching_processes,
)
from systemsense.packs.application.services import (
    ServiceObservation,
    collect_services,
)
from systemsense.packs.application.wer import scan_wer_reports

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def test_file_identity_hashes_content_and_reports_metadata(tmp_path: Path) -> None:
    target = tmp_path / "sample.exe"
    target.write_bytes(b"not-a-real-pe")

    identity = inspect_file(
        target,
        StaticFileMetadataBackend(
            version="1.2.3",
            signature=SignatureState.UNSIGNED,
        ),
        captured_at=_NOW,
    )

    assert identity.sha256 == hashlib.sha256(b"not-a-real-pe").hexdigest()
    assert identity.byte_size == len(b"not-a-real-pe")
    assert identity.version == "1.2.3"
    assert identity.architecture == "not_pe"
    assert identity.signature is SignatureState.UNSIGNED


def test_process_collection_matches_name_and_is_bounded() -> None:
    snapshots = (
        ProcessSnapshot(pid=10, name="sample.exe", executable="C:\\Apps\\sample.exe"),
        ProcessSnapshot(pid=11, name="other.exe", executable="C:\\Apps\\other.exe"),
    )

    matches = collect_matching_processes(snapshots, executable_name="SAMPLE.EXE")

    assert [process.pid for process in matches] == [10]


def test_service_collection_keeps_declared_dependencies() -> None:
    observations = (
        ServiceObservation(
            name="AudioSrv",
            display_name="Windows Audio",
            status="running",
            start_type="auto",
            dependencies=("RpcSs",),
        ),
    )

    result = collect_services(observations, registered_names=frozenset({"AudioSrv"}))

    assert result[0].dependencies == ("RpcSs",)


def test_expected_port_collection_ignores_unrelated_connections() -> None:
    connections = (
        NetworkConnection(
            local_address="127.0.0.1",
            local_port=8000,
            remote_address=None,
            remote_port=None,
            status="LISTEN",
            pid=10,
        ),
        NetworkConnection(
            local_address="127.0.0.1",
            local_port=9000,
            remote_address=None,
            remote_port=None,
            status="LISTEN",
            pid=11,
        ),
    )

    result = collect_expected_ports(connections, expected_ports=frozenset({8000}))

    assert len(result) == 1
    assert result[0].local_port == 8000


def test_wer_scan_is_related_and_bounded(tmp_path: Path) -> None:
    related = tmp_path / "AppCrash_sample.exe_123"
    unrelated = tmp_path / "AppCrash_other.exe_456"
    related.mkdir()
    unrelated.mkdir()
    (related / "Report.wer").write_text(
        "AppName=sample.exe\nAppVersion=1.2.3\nExceptionCode=c0000005\n",
        encoding="utf-16",
    )
    (unrelated / "Report.wer").write_text("AppName=other.exe\n", encoding="utf-16")

    reports = scan_wer_reports((tmp_path,), application_name="sample.exe", max_reports=1)

    assert len(reports) == 1
    assert reports[0].fields["ExceptionCode"] == "c0000005"
