"""Persistent current inventory with change-only history."""

from datetime import datetime

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import EntityId
from systemsense.domain.inventory import InventoryFact
from systemsense.domain.time import UtcDateTime
from systemsense.inventory.freshness import (
    Freshness,
    InvalidationSignal,
    assess_freshness,
    categories_for_signal,
)
from systemsense.storage.sqlite_store import SQLiteStore


class InventoryView(FrozenModel):
    fact: InventoryFact
    freshness: Freshness


class InventoryService:
    def __init__(self, store: SQLiteStore) -> None:
        self._store = store

    def refresh(self, fact: InventoryFact) -> bool:
        with self._store.transaction() as transaction:
            return transaction.upsert_inventory(
                category=fact.category,
                fact_key=self._fact_key(fact.entity_id, fact.name),
                record_json=fact.model_dump_json(),
                observed_at=fact.observed_at.isoformat(),
            )

    def get(
        self,
        *,
        category: str,
        entity_id: EntityId,
        name: str,
        at: datetime,
    ) -> InventoryView | None:
        record = self._store.inventory_record(
            category=category,
            fact_key=self._fact_key(entity_id, name),
        )
        if record is None:
            return None
        fact = InventoryFact.model_validate_json(record)
        return InventoryView(
            fact=fact,
            freshness=assess_freshness(
                observed_at=fact.observed_at,
                ttl_seconds=fact.freshness_ttl_seconds,
                invalidated_at=fact.invalidated_at,
                at=at,
            ),
        )

    def invalidate_for(
        self,
        signal: InvalidationSignal,
        *,
        at: UtcDateTime,
    ) -> int:
        categories = categories_for_signal(signal)
        with self._store.transaction() as transaction:
            return sum(
                transaction.invalidate_inventory(
                    category=category,
                    invalidated_at=at.isoformat(),
                )
                for category in categories
            )

    @staticmethod
    def _fact_key(entity_id: EntityId, name: str) -> str:
        return f"{entity_id}:{name}"
