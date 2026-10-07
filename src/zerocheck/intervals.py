"""Small helpers for half-open time intervals [start, end)."""

from __future__ import annotations

from datetime import datetime, timedelta

Interval = tuple[datetime, datetime]


def union(intervals: list[Interval]) -> list[Interval]:
    merged: list[Interval] = []
    for start, end in sorted(i for i in intervals if i[0] < i[1]):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def subtract(base: Interval, remove: list[Interval]) -> list[Interval]:
    """Return the parts of `base` not covered by `remove`."""
    result: list[Interval] = []
    cursor, end = base
    for r_start, r_end in union(remove):
        if r_end <= cursor or r_start >= end:
            continue
        if r_start > cursor:
            result.append((cursor, r_start))
        cursor = max(cursor, r_end)
    if cursor < end:
        result.append((cursor, end))
    return result


def clip(interval: Interval, window: Interval) -> Interval | None:
    start, end = max(interval[0], window[0]), min(interval[1], window[1])
    return (start, end) if start < end else None


def total(intervals: list[Interval]) -> timedelta:
    return sum((e - s for s, e in union(intervals)), timedelta())
