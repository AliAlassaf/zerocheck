"""Core data types: questions, sources, gaps and verdicts."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd])\s*$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_duration(value: str | int | timedelta) -> timedelta:
    """Parse '30m', '2h', '1d' or a number of seconds into a timedelta."""
    if isinstance(value, timedelta):
        return value
    if isinstance(value, int):
        return timedelta(seconds=value)
    match = _DURATION_RE.match(value)
    if not match:
        raise ValueError(f"invalid duration {value!r}; expected e.g. '30m', '2h', '1d'")
    amount, unit = match.groups()
    return timedelta(**{_UNITS[unit]: int(amount)})


def parse_time(value: str | datetime) -> datetime:
    """Parse an ISO-8601 timestamp; naive values are treated as UTC."""
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class Verdict(str, Enum):
    FOUND = "FOUND"
    VERIFIED_NEGATIVE = "VERIFIED_NEGATIVE"
    INSUFFICIENT_VISIBILITY = "INSUFFICIENT_VISIBILITY"


class GapReason(str, Enum):
    SOURCE_SILENT = "source_silent"  # the entity sent nothing from this source for too long
    INGESTION_LAG = "ingestion_lag"  # the source has not been ingested this far yet
    RETENTION = "retention"  # data this old is no longer stored
    FIELD_MISSING = "field_missing"  # events exist but required fields are empty (parser drift)
    SOURCE_EMPTY = "source_empty"  # the source holds no data at all
    NO_ACCESS = "no_access"  # the querying identity cannot read the source


NEXT_STEPS = {
    GapReason.SOURCE_SILENT: "Check agent/sensor health on the entity for that interval; "
    "pull local logs or EDR telemetry from the host directly if it is still available.",
    GapReason.INGESTION_LAG: "Re-run the search after the pipeline catches up, or query the "
    "source (EDR console, host) directly for the lagging interval.",
    GapReason.RETENTION: "Look for archived/cold-tier data or another source with longer retention; "
    "otherwise record the interval as unobservable in the case.",
    GapReason.FIELD_MISSING: "Search on a field that is populated, or fix the parser and re-run; "
    "raw events may still hold the value.",
    GapReason.SOURCE_EMPTY: "Confirm the source is collected and its audit policy is enabled; "
    "this question cannot be answered from it today.",
    GapReason.NO_ACCESS: "Re-run with an identity that can read the source, or ask its owner to run the search.",
}


@dataclass(frozen=True)
class Source:
    """One telemetry source able to answer a question, e.g. Sysmon EID 1."""

    name: str
    index: str
    filter: dict[str, Any]
    required_fields: tuple[str, ...]
    max_silence: timedelta
    # Filter proving the source is alive for the entity. Defaults to `filter`;
    # set it wider for rare events, whose own silence proves nothing.
    liveness_filter: dict[str, Any] | None = None

    @property
    def alive_filter(self) -> dict[str, Any]:
        return self.filter if self.liveness_filter is None else self.liveness_filter


@dataclass(frozen=True)
class Question:
    """An investigative question and the telemetry needed to answer it.

    `sources` are alternatives: a moment in the window counts as observable
    if at least one usable source covers it.
    """

    id: str
    description: str
    entity_field: str
    sources: tuple[Source, ...]
    match_fields: tuple[str, ...]
    min_field_fill: float = 0.9


@dataclass
class Gap:
    source: str
    reason: GapReason
    start: datetime
    end: datetime
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "reason": self.reason.value,
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "detail": self.detail,
            "next_step": NEXT_STEPS[self.reason],
        }


@dataclass
class Result:
    verdict: Verdict
    question: str
    entity: str
    start: datetime
    end: datetime
    match: dict[str, Any]
    match_count: int
    coverage: float  # fraction of the window observable by at least one usable source
    uncovered: list[tuple[datetime, datetime]] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        data["start"] = self.start.isoformat()
        data["end"] = self.end.isoformat()
        data["coverage"] = round(self.coverage, 4)
        data["uncovered"] = [{"start": s.isoformat(), "end": e.isoformat()} for s, e in self.uncovered]
        data["gaps"] = [g.to_dict() for g in self.gaps]
        return data
