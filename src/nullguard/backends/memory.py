"""In-memory backend for tests, demos and replaying exported logs."""

from __future__ import annotations

import fnmatch
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from ..models import parse_time
from .base import AccessDenied, Backend


def get_field(event: dict[str, Any], path: str) -> Any:
    """Read 'a.b.c' from either a flat dotted key or nested dicts."""
    if path in event:
        return event[path]
    value: Any = event
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _matches(value: Any, expected: Any) -> bool:
    options = expected if isinstance(expected, (list, tuple)) else [expected]
    for option in options:
        if isinstance(value, str) and isinstance(option, str):
            if value.casefold() == option.casefold():
                return True
        elif value is not None and str(value) == str(option):
            return True
    return False


class MemoryBackend(Backend):
    """Events are dicts with '@timestamp' and '_index' keys (ECS-style field names)."""

    def __init__(self, events: Iterable[dict[str, Any]] = (), denied_indices: Iterable[str] = ()):
        self.events: list[dict[str, Any]] = []
        self.denied_indices = list(denied_indices)
        self.add(events)

    def add(self, events: Iterable[dict[str, Any]]) -> None:
        for event in events:
            event = dict(event)
            event["@timestamp"] = parse_time(event["@timestamp"])
            self.events.append(event)

    @classmethod
    def from_ndjson(cls, path: str | Path) -> "MemoryBackend":
        with open(path, encoding="utf-8") as fh:
            return cls(json.loads(line) for line in fh if line.strip())

    def _select(self, index: str, filters: dict[str, Any]) -> list[dict[str, Any]]:
        if any(fnmatch.fnmatch(index, d) or fnmatch.fnmatch(d, index) for d in self.denied_indices):
            raise AccessDenied(f"read access to {index} denied")
        return [
            e
            for e in self.events
            if fnmatch.fnmatch(e.get("_index", ""), index)
            and all(_matches(get_field(e, k), v) for k, v in filters.items())
        ]

    @staticmethod
    def _in_window(events, start, end):
        return [e for e in events if start <= e["@timestamp"] < end]

    def count(self, index, filters, start, end):
        return len(self._in_window(self._select(index, filters), start, end))

    def bucket_counts(self, index, filters, start, end, interval: timedelta):
        n = max(1, -(-(end - start) // interval))
        counts = [0] * n
        for e in self._in_window(self._select(index, filters), start, end):
            counts[(e["@timestamp"] - start) // interval] += 1
        return counts

    def field_fill(self, index, filters, start, end, fields):
        events = self._in_window(self._select(index, filters), start, end)
        filled = {f: sum(1 for e in events if get_field(e, f) not in (None, "")) for f in fields}
        return len(events), filled

    def time_bounds(self, index, filters) -> tuple[datetime, datetime] | None:
        stamps = [e["@timestamp"] for e in self._select(index, filters)]
        return (min(stamps), max(stamps)) if stamps else None
