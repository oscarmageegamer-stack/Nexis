from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Capability:
    name: str
    category: str
    description: str
    safe: bool = True
    runner: Callable | None = None


class CapabilityRegistry:
    """Central registry for Nexis modules and approved tool adapters."""

    def __init__(self) -> None:
        self._items: dict[str, Capability] = {}

    def register(self, capability: Capability) -> None:
        key = capability.name.strip().lower()
        if not key:
            raise ValueError("Capability name cannot be empty.")
        self._items[key] = capability

    def get(self, name: str) -> Capability | None:
        return self._items.get(name.strip().lower())

    def list(self, category: str | None = None) -> list[Capability]:
        values = list(self._items.values())
        if category:
            values = [item for item in values if item.category.lower() == category.lower()]
        return sorted(values, key=lambda item: (item.category, item.name))

    def summary(self) -> dict:
        items = self.list()
        return {
            "count": len(items),
            "safe_count": sum(item.safe for item in items),
            "categories": sorted({item.category for item in items}),
        }
