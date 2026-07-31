from datetime import UTC, datetime, timedelta
from pathlib import Path

from systemsense.domain.evidence import CollectorReference, EvidenceSource
from systemsense.domain.ids import EntityId, ExecutionId
from systemsense.domain.inventory import InventoryFact
from systemsense.inventory.freshness import InvalidationSignal
from systemsense.inventory.service import InventoryService
from systemsense.storage.sqlite_store import SQLiteStore

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
_DRIVER_ENTITY = EntityId(root="entity_0123456789abcdef0123456789abcdef")
_NETWORK_ENTITY = EntityId(root="entity_fedcba9876543210fedcba9876543210")


def _fact(
    *,
    entity_id: EntityId = _DRIVER_ENTITY,
    category: str = "drivers",
    name: str = "display.driver.version",
    value: str = "1.0",
    captured_offset: int = 0,
) -> InventoryFact:
    return InventoryFact.model_validate(
        {
            "entity_id": entity_id,
            "category": category,
            "name": name,
            "value": value,
            "source": EvidenceSource(
                type="fixture",
                source_id=f"src_{'a' * 64}",
                locator={"entity": str(entity_id)},
            ),
            "collector": CollectorReference(
                id="fixture.inventory",
                version=1,
                execution_id=ExecutionId.new(),
            ),
            "observed_at": _NOW + timedelta(seconds=captured_offset),
            "captured_at": _NOW + timedelta(seconds=captured_offset),
            "extraction": {
                "confidence": 1.0,
                "parser": "fixture",
                "parser_version": 1,
            },
            "freshness_ttl_seconds": 60,
            "sensitivity": "system_metadata",
        }
    )


def test_current_inventory_returns_immediately_with_age_and_staleness(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        service = InventoryService(store)
        service.refresh(_fact())

        view = service.get(
            category="drivers",
            entity_id=_DRIVER_ENTITY,
            name="display.driver.version",
            at=_NOW + timedelta(seconds=30),
        )

        assert view is not None
        assert view.fact.value == "1.0"
        assert view.freshness.age_seconds == 30
        assert not view.freshness.stale


def test_unchanged_refresh_updates_current_without_adding_history(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        service = InventoryService(store)

        assert service.refresh(_fact())
        history_after_first = store.inventory_history_count(
            category="drivers",
            fact_key=f"{_DRIVER_ENTITY}:display.driver.version",
        )
        assert not service.refresh(_fact(captured_offset=10))
        history_after_unchanged = store.inventory_history_count(
            category="drivers",
            fact_key=f"{_DRIVER_ENTITY}:display.driver.version",
        )
        assert service.refresh(_fact(value="2.0", captured_offset=20))
        history_after_change = store.inventory_history_count(
            category="drivers",
            fact_key=f"{_DRIVER_ENTITY}:display.driver.version",
        )

        assert history_after_unchanged == history_after_first
        assert history_after_change == history_after_first + 1


def test_passive_invalidation_targets_only_related_categories(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        service = InventoryService(store)
        service.refresh(_fact())
        service.refresh(
            _fact(
                entity_id=_NETWORK_ENTITY,
                category="network",
                name="adapter.state",
                value="up",
            )
        )

        invalidated = service.invalidate_for(
            InvalidationSignal.DRIVER_CHANGE,
            at=_NOW + timedelta(seconds=5),
        )
        driver = service.get(
            category="drivers",
            entity_id=_DRIVER_ENTITY,
            name="display.driver.version",
            at=_NOW + timedelta(seconds=6),
        )
        network = service.get(
            category="network",
            entity_id=_NETWORK_ENTITY,
            name="adapter.state",
            at=_NOW + timedelta(seconds=6),
        )

        assert invalidated == 1
        assert driver is not None and driver.freshness.stale
        assert network is not None and not network.freshness.stale
