"""Backend interface: the few read-only primitives the verifier needs from a SIEM."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any


class BackendError(Exception):
    pass


class AccessDenied(BackendError):
    """The querying identity is not allowed to read the source."""


class Backend(ABC):
    """Every method scopes to one source: an index pattern plus exact-match filters."""

    @abstractmethod
    def count(
        self, index: str, filters: dict[str, Any], start: datetime, end: datetime
    ) -> int:
        """Number of events matching `filters` in [start, end)."""

    @abstractmethod
    def bucket_counts(
        self,
        index: str,
        filters: dict[str, Any],
        start: datetime,
        end: datetime,
        interval: timedelta,
    ) -> list[int]:
        """Event counts per `interval`-sized bucket, starting at `start`."""

    @abstractmethod
    def field_fill(
        self,
        index: str,
        filters: dict[str, Any],
        start: datetime,
        end: datetime,
        fields: list[str],
    ) -> tuple[int, dict[str, int]]:
        """Total matching events and, per field, how many have it populated."""

    @abstractmethod
    def time_bounds(
        self, index: str, filters: dict[str, Any]
    ) -> tuple[datetime, datetime] | None:
        """Earliest and latest event timestamp in the source, or None if it is empty."""
