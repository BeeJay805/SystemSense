from datetime import UTC, datetime

import pytest

from systemsense.audit import AuditChain, AuditOutcome
from systemsense.domain.ids import CaseId

_CASE_ID = CaseId(root="case_0123456789abcdef0123456789abcdef")
_OCCURRED_AT = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "outcome",
    [
        AuditOutcome.ALLOWED,
        AuditOutcome.DENIED,
        AuditOutcome.FAILED,
        AuditOutcome.TIMED_OUT,
        AuditOutcome.CANCELLED,
        AuditOutcome.TRUNCATED,
    ],
)
def test_every_probe_outcome_can_be_recorded(outcome: AuditOutcome) -> None:
    chain = AuditChain()

    entry = chain.append(
        event_id=f"audit-{outcome.value}",
        case_id=_CASE_ID,
        probe_id="application.file_identity",
        outcome=outcome,
        occurred_at=_OCCURRED_AT,
    )

    assert entry.outcome is outcome
    assert entry.sequence == 1


def test_entries_link_to_previous_hash_and_verify() -> None:
    chain = AuditChain()
    first = chain.append(
        event_id="audit-1",
        case_id=_CASE_ID,
        probe_id="application.file_identity",
        outcome=AuditOutcome.ALLOWED,
        occurred_at=_OCCURRED_AT,
    )
    second = chain.append(
        event_id="audit-2",
        case_id=_CASE_ID,
        probe_id="eventlog.application",
        outcome=AuditOutcome.FAILED,
        occurred_at=_OCCURRED_AT,
    )

    verification = AuditChain.verify(chain.entries, checkpoint=chain.checkpoint())

    assert second.previous_hash == first.event_hash
    assert verification.valid
    assert verification.limitation == "tamper-evident only; not forensic integrity"


def test_changed_entry_is_detected() -> None:
    chain = AuditChain()
    chain.append(
        event_id="audit-1",
        case_id=_CASE_ID,
        probe_id="application.file_identity",
        outcome=AuditOutcome.ALLOWED,
        occurred_at=_OCCURRED_AT,
    )
    checkpoint = chain.checkpoint()
    changed = chain.entries[0].model_copy(update={"probe_id": "changed.probe"})

    verification = AuditChain.verify((changed,), checkpoint=checkpoint)

    assert not verification.valid
    assert verification.failure_index == 0
    assert verification.reason == "event hash mismatch"


def test_removed_tail_is_detected_against_checkpoint() -> None:
    chain = AuditChain()
    for index in range(2):
        chain.append(
            event_id=f"audit-{index}",
            case_id=_CASE_ID,
            probe_id="eventlog.application",
            outcome=AuditOutcome.ALLOWED,
            occurred_at=_OCCURRED_AT,
        )
    checkpoint = chain.checkpoint()

    verification = AuditChain.verify(chain.entries[:-1], checkpoint=checkpoint)

    assert not verification.valid
    assert verification.reason == "entry count mismatch"


def test_parameters_and_errors_are_redacted_before_hashing() -> None:
    def append_with_secret(secret: str):
        chain = AuditChain()
        entry = chain.append(
            event_id="audit-redaction",
            case_id=_CASE_ID,
            probe_id="application.file_identity",
            outcome=AuditOutcome.FAILED,
            occurred_at=_OCCURRED_AT,
            parameters={
                "api_token": secret,
                "nested": {"user_path": r"C:\Users\brennan\private.txt"},
            },
            error=f"request failed at https://user:{secret}@example.test/private",
        )
        return entry

    first = append_with_secret("first-secret")
    second = append_with_secret("different-secret")
    serialized = first.model_dump_json()

    assert "first-secret" not in serialized
    assert "brennan" not in serialized
    assert "user:first-secret" not in serialized
    assert "<redacted-" in serialized
    assert first.event_hash == second.event_hash
