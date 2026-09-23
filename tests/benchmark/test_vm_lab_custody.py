from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from benchmarks.vm_lab_custody import (
    CaptureKind,
    CaptureReceipt,
    CustodyError,
    capture_bytes,
    check_review_custody,
    check_trial_custody,
    verify_capture,
)

OBSERVED = datetime(2026, 9, 22, 12, tzinfo=UTC)


def test_capture_is_write_once_and_verifiable(tmp_path: Path) -> None:
    receipt = capture_bytes(
        tmp_path,
        episode_id="proxy-001",
        capture_id="clean-1",
        kind=CaptureKind.CLEAN_ORACLE,
        controller_id="oracle-controller",
        source_observed_at=OBSERVED,
        data=b"measured endpoint response\n",
        collected_at=OBSERVED + timedelta(seconds=1),
    )

    assert receipt.role == "oracle"
    assert receipt.source_observed_at == OBSERVED
    assert receipt.collected_at == OBSERVED + timedelta(seconds=1)
    assert verify_capture(tmp_path, receipt)
    with pytest.raises(FileExistsError):
        capture_bytes(
            tmp_path,
            episode_id="proxy-001",
            capture_id="clean-1",
            kind=CaptureKind.CLEAN_ORACLE,
            controller_id="oracle-controller",
            source_observed_at=OBSERVED,
            data=b"replacement",
        )


def test_tampering_or_missing_receipt_fails_verification(tmp_path: Path) -> None:
    receipt = capture_bytes(
        tmp_path,
        episode_id="proxy-001",
        capture_id="clean-1",
        kind=CaptureKind.CLEAN_ORACLE,
        controller_id="oracle-controller",
        source_observed_at=OBSERVED,
        data=b"measured",
    )
    payload = tmp_path / "proxy-001" / "oracle" / "clean-1.bin"
    payload.write_bytes(b"fabricated")
    assert not verify_capture(tmp_path, receipt)
    payload.unlink()
    assert not verify_capture(tmp_path, receipt)


def test_kind_controls_custody_namespace(tmp_path: Path) -> None:
    rig = capture_bytes(
        tmp_path,
        episode_id="proxy-001",
        capture_id="reset-1",
        kind=CaptureKind.RESET_READBACK,
        controller_id="rig-controller",
        source_observed_at=OBSERVED,
        data=b"clean digest evidence",
    )
    arm = capture_bytes(
        tmp_path,
        episode_id="proxy-001",
        capture_id="trace-1",
        kind=CaptureKind.ARM_TRACE,
        controller_id="arm-controller",
        source_observed_at=OBSERVED,
        data=b"case trace",
    )
    assert rig.role == "rig_sealed"
    assert arm.role == "arm"
    assert (tmp_path / "proxy-001" / "rig_sealed" / "reset-1.bin").exists()
    assert (tmp_path / "proxy-001" / "arm" / "trace-1.bin").exists()


@pytest.mark.parametrize("bad_id", ["../other", "a/b", "a\\b", "", "UPPER"])
def test_rejects_path_like_identifiers(tmp_path: Path, bad_id: str) -> None:
    with pytest.raises(CustodyError):
        capture_bytes(
            tmp_path,
            episode_id="proxy-001",
            capture_id=bad_id,
            kind=CaptureKind.CLEAN_ORACLE,
            controller_id="oracle-controller",
            source_observed_at=OBSERVED,
            data=b"measured",
        )


def test_rejects_impossible_observation_time(tmp_path: Path) -> None:
    with pytest.raises(CustodyError):
        capture_bytes(
            tmp_path,
            episode_id="proxy-001",
            capture_id="clean-1",
            kind=CaptureKind.CLEAN_ORACLE,
            controller_id="oracle-controller",
            source_observed_at=OBSERVED + timedelta(seconds=2),
            data=b"measured",
            collected_at=OBSERVED,
        )


def _capture_trial(tmp_path: Path) -> list[CaptureReceipt]:
    kinds = (
        CaptureKind.PREFLIGHT,
        CaptureKind.RESET_READBACK,
        CaptureKind.CLEAN_ORACLE,
        CaptureKind.INJECTION_READBACK,
        CaptureKind.INJECTED_ORACLE,
        CaptureKind.ARM_TRACE,
        CaptureKind.AFTER_ARM_ORACLE,
        CaptureKind.RESET_READBACK,
        CaptureKind.AFTER_RESTORE_ORACLE,
    )
    receipts: list[CaptureReceipt] = []
    for index, kind in enumerate(kinds):
        if kind in (
            CaptureKind.PREFLIGHT,
            CaptureKind.RESET_READBACK,
            CaptureKind.INJECTION_READBACK,
        ):
            controller = "rig-controller"
        elif kind is CaptureKind.ARM_TRACE:
            controller = "arm-controller"
        else:
            controller = "oracle-controller"
        receipts.append(
            capture_bytes(
                tmp_path,
                episode_id="proxy-001",
                capture_id=f"capture-{index}",
                kind=kind,
                controller_id=controller,
                source_observed_at=OBSERVED + timedelta(seconds=index),
                collected_at=OBSERVED + timedelta(seconds=index + 1),
                data=f"raw-{index}".encode(),
            )
        )
    return receipts


def test_trial_custody_requires_distinct_oracle_and_complete_capture_set(tmp_path: Path) -> None:
    receipts = _capture_trial(tmp_path)
    assert check_trial_custody(tmp_path, receipts).complete
    assert (
        "missing_after_restore_oracle" in check_trial_custody(tmp_path, receipts[:-1]).reason_codes
    )

    same_controller = tuple(
        replace(receipt, controller_id="rig-controller") if receipt.role == "oracle" else receipt
        for receipt in receipts
    )
    assert (
        "controller_ids_not_distinct" in check_trial_custody(tmp_path, same_controller).reason_codes
    )
    out_of_order = tuple(
        replace(receipt, source_observed_at=OBSERVED - timedelta(seconds=1))
        if receipt.kind is CaptureKind.AFTER_ARM_ORACLE
        else receipt
        for receipt in receipts
    )
    assert "source_order_invalid" in check_trial_custody(tmp_path, out_of_order).reason_codes


def test_reviewer_capture_closes_separate_host_custody_gate(tmp_path: Path) -> None:
    receipts = _capture_trial(tmp_path)
    review = capture_bytes(
        tmp_path,
        episode_id="proxy-001",
        capture_id="blind-review-1",
        kind=CaptureKind.BLINDED_REVIEW,
        controller_id="independent-reviewer",
        source_observed_at=OBSERVED + timedelta(seconds=10),
        collected_at=OBSERVED + timedelta(seconds=11),
        data=b"cited reviewer verdict",
    )
    check = check_review_custody(tmp_path, receipts, review)
    assert check.classification == "host_review_capture_set_only"
    assert check.complete
    assert (
        "review_capture_kind_invalid"
        in check_review_custody(tmp_path, receipts, receipts[-1]).reason_codes
    )
    assert (
        "reviewer_controller_not_distinct"
        in check_review_custody(
            tmp_path, receipts, replace(review, controller_id="arm-controller")
        ).reason_codes
    )
    assert (
        "review_precedes_trial_completion"
        in check_review_custody(
            tmp_path,
            receipts,
            replace(review, source_observed_at=OBSERVED, collected_at=OBSERVED),
        ).reason_codes
    )
    too_early_to_be_sealed = capture_bytes(
        tmp_path,
        episode_id="proxy-001",
        capture_id="blind-review-before-seal",
        kind=CaptureKind.BLINDED_REVIEW,
        controller_id="independent-reviewer",
        source_observed_at=receipts[-1].source_observed_at + timedelta(milliseconds=500),
        collected_at=receipts[-1].collected_at + timedelta(seconds=1),
        data=b"premature review",
    )
    assert (
        "review_precedes_trial_completion"
        in check_review_custody(tmp_path, receipts, too_early_to_be_sealed).reason_codes
    )


def test_orphan_payload_blocks_retry(tmp_path: Path) -> None:
    orphan = tmp_path / "proxy-001" / "oracle" / "clean-1.bin"
    orphan.parent.mkdir(parents=True)
    orphan.write_bytes(b"incomplete earlier capture")
    with pytest.raises(FileExistsError):
        capture_bytes(
            tmp_path,
            episode_id="proxy-001",
            capture_id="clean-1",
            kind=CaptureKind.CLEAN_ORACLE,
            controller_id="oracle-controller",
            source_observed_at=OBSERVED,
            data=b"retry",
        )
    assert orphan.read_bytes() == b"incomplete earlier capture"


def test_oversized_persisted_payload_fails_verification(tmp_path: Path) -> None:
    receipt = capture_bytes(
        tmp_path,
        episode_id="proxy-001",
        capture_id="clean-1",
        kind=CaptureKind.CLEAN_ORACLE,
        controller_id="oracle-controller",
        source_observed_at=OBSERVED,
        data=b"measured",
    )
    payload = tmp_path / "proxy-001" / "oracle" / "clean-1.bin"
    with payload.open("ab") as stream:
        stream.truncate(8 * 1024 * 1024 + 1)
    assert not verify_capture(tmp_path, receipt)
