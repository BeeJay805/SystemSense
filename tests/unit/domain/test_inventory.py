from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from systemsense.domain.evidence import CollectorReference, EvidenceSource
from systemsense.domain.ids import EntityId, ExecutionId
from systemsense.domain.inventory import InventoryFact


def inventory_fact(**overrides: object) -> InventoryFact:
    values: dict[str, object] = {
        "schema_version": 1,
        "entity_id": str(EntityId.new()),
        "category": "drivers",
        "name": "display.driver.version",
        "value": "32.0.15.6094",
        "source": EvidenceSource(
            type="win32_pnp",
            source_id="src_" + ("c" * 64),
            locator={"instance_id": "redacted:device"},
        ),
        "collector": CollectorReference(
            id="devices.drivers",
            version=1,
            execution_id=ExecutionId.new(),
        ),
        "observed_at": datetime(2026, 7, 30, 18, 0, tzinfo=UTC),
        "captured_at": datetime(2026, 7, 30, 18, 0, 1, tzinfo=UTC),
        "extraction": {
            "confidence": 1.0,
            "parser": "driver_inventory",
            "parser_version": 1,
        },
        "freshness_ttl_seconds": 3600,
        "sensitivity": "system_metadata",
        "limitations": [],
    }
    values.update(overrides)
    return InventoryFact.model_validate(values)


def test_inventory_fact_is_fresh_before_ttl_and_stale_after() -> None:
    fact = inventory_fact()

    assert not fact.is_stale(datetime(2026, 7, 30, 18, 59, tzinfo=UTC))
    assert fact.is_stale(datetime(2026, 7, 30, 19, 0, 1, tzinfo=UTC))


def test_inventory_invalidation_makes_fact_stale() -> None:
    fact = inventory_fact(invalidated_at=datetime(2026, 7, 30, 18, 10, tzinfo=UTC))

    assert fact.is_stale(datetime(2026, 7, 30, 18, 11, tzinfo=UTC))


def test_inventory_rejects_invalidation_before_observation() -> None:
    with pytest.raises(ValidationError, match="invalidation"):
        inventory_fact(invalidated_at=datetime(2026, 7, 30, 17, 59, tzinfo=UTC))


def test_inventory_rejects_naive_staleness_check() -> None:
    fact = inventory_fact()

    with pytest.raises(ValueError, match="timezone"):
        fact.is_stale(datetime(2026, 7, 30, 19, 0))


def test_inventory_rejects_non_positive_ttl() -> None:
    with pytest.raises(ValidationError):
        inventory_fact(freshness_ttl_seconds=0)


def test_inventory_freshness_boundary_is_inclusive() -> None:
    fact = inventory_fact()
    boundary = fact.observed_at + timedelta(seconds=fact.freshness_ttl_seconds)

    assert not fact.is_stale(boundary)
