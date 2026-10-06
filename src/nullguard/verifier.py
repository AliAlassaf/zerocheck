"""Decide whether an empty search is a verified negative or a blind spot."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from . import intervals as iv
from .backends.base import AccessDenied, Backend
from .models import Gap, GapReason, Question, Result, Source, Verdict, parse_time

# Tolerated distance between the newest ingested event and the window end
# before the tail of the window is reported as not yet ingested.
DEFAULT_INGEST_TOLERANCE = timedelta(minutes=5)


class Verifier:
    def __init__(
        self,
        backend: Backend,
        questions: dict[str, Question],
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        ingest_tolerance: timedelta = DEFAULT_INGEST_TOLERANCE,
    ):
        self.backend = backend
        self.questions = questions
        self.now = now
        self.ingest_tolerance = ingest_tolerance

    def verify(
        self,
        question_id: str,
        entity: str,
        start: str | datetime,
        end: str | datetime,
        match: dict[str, Any] | None = None,
    ) -> Result:
        question = self.questions.get(question_id)
        if question is None:
            raise ValueError(f"unknown question {question_id!r}; known: {sorted(self.questions)}")
        match = dict(match or {})
        unknown = set(match) - set(question.match_fields)
        if unknown:
            raise ValueError(
                f"fields {sorted(unknown)} are not matchable for {question_id}; "
                f"allowed: {list(question.match_fields)}"
            )
        start, end = parse_time(start), min(parse_time(end), self.now())
        if start >= end:
            raise ValueError("start must be before end (and not in the future)")
        window = (start, end)

        match_count = 0
        covered: list[iv.Interval] = []
        gaps: list[Gap] = []
        for source in question.sources:
            source_covered, source_gaps, source_matches = self._check_source(
                question, source, entity, window, match
            )
            covered.extend(source_covered)
            gaps.extend(source_gaps)
            match_count += source_matches

        uncovered = iv.subtract(window, covered)
        coverage = 1 - iv.total(uncovered) / (end - start)
        if match_count:
            verdict = Verdict.FOUND
        elif not uncovered:
            verdict = Verdict.VERIFIED_NEGATIVE
        else:
            verdict = Verdict.INSUFFICIENT_VISIBILITY
        return Result(
            verdict=verdict,
            question=question_id,
            entity=entity,
            start=start,
            end=end,
            match=match,
            match_count=match_count,
            coverage=coverage,
            uncovered=uncovered,
            gaps=sorted(gaps, key=lambda g: (g.start, g.source)),
        )

    def _check_source(
        self,
        question: Question,
        source: Source,
        entity: str,
        window: iv.Interval,
        match: dict[str, Any],
    ) -> tuple[list[iv.Interval], list[Gap], int]:
        """Return (covered intervals, gaps, match count) for one source."""
        start, end = window
        whole = lambda reason, detail: [Gap(source.name, reason, start, end, detail)]  # noqa: E731
        entity_filter = {question.entity_field: entity}

        try:
            if self.backend.time_bounds(source.index, source.filter) is None:
                return [], whole(GapReason.SOURCE_EMPTY, f"no events at all in {source.index} for {source.filter}"), 0
            alive_bounds = self.backend.time_bounds(source.index, source.alive_filter)
            matches = self.backend.count(
                source.index, {**source.filter, **entity_filter, **match}, start, end
            )
        except AccessDenied as exc:
            return [], whole(GapReason.NO_ACCESS, str(exc)), 0
        assert alive_bounds is not None  # a source with events is alive somewhere
        earliest, latest = alive_bounds

        gaps: list[Gap] = []
        hard_limits: list[iv.Interval] = []
        if earliest > start:
            hard_limits.append((start, earliest))
            gaps.append(
                Gap(source.name, GapReason.RETENTION, start, min(earliest, end),
                    f"oldest stored event is {earliest.isoformat()} (retention limit or onboarding date)")
            )
        if end - latest > self.ingest_tolerance:
            hard_limits.append((latest, end))
            gaps.append(
                Gap(source.name, GapReason.INGESTION_LAG, max(latest, start), end,
                    f"newest ingested event is {latest.isoformat()}")
            )

        for silent in self._silent_runs(source, entity_filter, window):
            for part in iv.subtract(silent, hard_limits):
                clipped = iv.clip(part, window)
                if clipped:
                    gaps.append(
                        Gap(source.name, GapReason.SOURCE_SILENT, *clipped,
                            f"{entity} sent no {source.name} events for longer than "
                            f"{_fmt(source.max_silence)}")
                    )

        drift = self._field_drift(question, source, entity_filter, window, match)
        if drift:
            gaps.append(Gap(source.name, GapReason.FIELD_MISSING, start, end, drift))
            return [], gaps, matches

        unobservable = hard_limits + [(g.start, g.end) for g in gaps]
        return iv.subtract(window, unobservable), gaps, matches

    def _silent_runs(
        self, source: Source, entity_filter: dict[str, Any], window: iv.Interval
    ) -> list[iv.Interval]:
        """Stretches around the window where the entity sent nothing for >= max_silence."""
        ext_start = window[0] - source.max_silence
        ext_end = min(window[1] + source.max_silence, self.now())
        bucket = max(timedelta(minutes=1), source.max_silence / 6)
        counts = self.backend.bucket_counts(
            source.index, {**source.alive_filter, **entity_filter}, ext_start, ext_end, bucket
        )
        runs: list[iv.Interval] = []
        run_start: datetime | None = None
        for i, count in enumerate(counts + [1]):  # sentinel closes a trailing run
            bucket_start = min(ext_start + i * bucket, ext_end)
            if count == 0 and run_start is None:
                run_start = bucket_start
            elif count and run_start is not None:
                if bucket_start - run_start >= source.max_silence:
                    runs.append((run_start, bucket_start))
                run_start = None
        return runs

    def _field_drift(
        self,
        question: Question,
        source: Source,
        entity_filter: dict[str, Any],
        window: iv.Interval,
        match: dict[str, Any],
    ) -> str | None:
        """Describe required or matched fields that are mostly empty, if any."""
        fields = list(dict.fromkeys([*source.required_fields, *match]))
        if not fields:
            return None
        ext = (window[0] - source.max_silence, min(window[1] + source.max_silence, self.now()))
        total, filled = self.backend.field_fill(source.index, {**source.filter, **entity_filter}, *ext, fields)
        scope = "this entity"
        if total == 0:  # nothing from this entity to judge; fall back to the whole source
            total, filled = self.backend.field_fill(source.index, source.filter, *ext, fields)
            scope = "all entities"
        if total == 0:
            return None
        poor = {f: n / total for f, n in filled.items() if n / total < question.min_field_fill}
        if not poor:
            return None
        listed = ", ".join(f"{f} ({ratio:.0%} filled)" for f, ratio in poor.items())
        return f"parser or schema drift: {listed} across {total} events from {scope}"


def _fmt(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    return f"{minutes // 60}h{minutes % 60:02d}m" if minutes >= 60 else f"{minutes}m"
