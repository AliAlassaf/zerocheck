"""Load investigative questions from YAML catalog files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..models import Question, Source, parse_duration

BUILTIN_DIR = Path(__file__).parent


def _source(raw: dict[str, Any]) -> Source:
    return Source(
        name=raw["name"],
        index=raw["index"],
        filter=dict(raw.get("filter") or {}),
        required_fields=tuple(raw.get("required_fields") or ()),
        max_silence=parse_duration(raw.get("max_silence", "30m")),
        liveness_filter=raw.get("liveness_filter"),
    )


def _question(raw: dict[str, Any]) -> Question:
    sources = tuple(_source(s) for s in raw["sources"])
    if not sources:
        raise ValueError(f"question {raw['id']!r} has no sources")
    return Question(
        id=raw["id"],
        description=raw.get("description", ""),
        entity_field=raw.get("entity_field", "host.name"),
        sources=sources,
        match_fields=tuple(raw.get("match_fields") or ()),
        min_field_fill=float(raw.get("min_field_fill", 0.9)),
    )


def load_catalog(*paths: str | Path) -> dict[str, Question]:
    """Load questions from the built-in catalog plus any extra files or directories.

    Later definitions override earlier ones with the same id.
    """
    files: list[Path] = sorted(BUILTIN_DIR.glob("*.yaml"))
    for path in map(Path, paths):
        files.extend(sorted(path.glob("*.yaml")) if path.is_dir() else [path])
    questions: dict[str, Question] = {}
    for file in files:
        for raw in yaml.safe_load(file.read_text(encoding="utf-8")) or []:
            question = _question(raw)
            questions[question.id] = question
    return questions
