"""Command-line interface: `zerocheck verify`, `zerocheck questions`, `zerocheck demo`."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .backends import BackendError, ElasticBackend, MemoryBackend
from .catalog import load_catalog
from .models import NEXT_STEPS, Result, Verdict
from .verifier import Verifier

_LABELS = {
    Verdict.FOUND: "FOUND — matching evidence exists",
    Verdict.VERIFIED_NEGATIVE: "VERIFIED NEGATIVE — no matches, and the whole window was observable",
    Verdict.INSUFFICIENT_VISIBILITY: "INSUFFICIENT VISIBILITY — zero results here do NOT mean it didn't happen",
}


def format_result(result: Result) -> str:
    lines = [
        _LABELS[result.verdict],
        f"  question : {result.question} on {result.entity}",
        f"  window   : {result.start:%Y-%m-%d %H:%M} -> {result.end:%Y-%m-%d %H:%M} UTC",
        f"  match    : {result.match or '(any)'}  ->  {result.match_count} event(s)",
        f"  coverage : {result.coverage:.0%} of the window observable",
    ]
    if result.uncovered:
        lines.append("  blind    : " + ", ".join(_span(s, e) for s, e in result.uncovered))
    for gap in result.gaps:
        lines.append(f"    - [{gap.reason.value}] {gap.source} {_span(gap.start, gap.end)}: {gap.detail}")
    if result.verdict is Verdict.INSUFFICIENT_VISIBILITY:
        steps = dict.fromkeys(NEXT_STEPS[g.reason] for g in result.gaps)
        lines.append("  next steps:")
        lines.extend(f"    * {step}" for step in steps)
    return "\n".join(lines)


def _span(start, end) -> str:
    if start.date() == end.date():
        return f"{start:%m-%d %H:%M}-{end:%H:%M}"
    return f"{start:%m-%d %H:%M} -> {end:%m-%d %H:%M}"


def _parse_match(pairs: list[str]) -> dict[str, Any]:
    match: dict[str, Any] = {}
    for pair in pairs:
        field, sep, value = pair.partition("=")
        if not sep:
            raise SystemExit(f"--match expects field=value, got {pair!r}")
        match[field] = value
    return match


def _backend(args: argparse.Namespace):
    if args.ndjson:
        return MemoryBackend.from_ndjson(args.ndjson)
    return ElasticBackend.from_env()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="zerocheck", description="Tell a verified negative from a blind spot."
    )
    parser.add_argument("--catalog", action="append", default=[], help="extra question catalog file or directory")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="verify a search over an entity and time window")
    verify.add_argument("--question", "-q", required=True)
    verify.add_argument("--entity", "-e", required=True, help="e.g. a host name")
    verify.add_argument("--start", required=True, help="ISO-8601, e.g. 2026-10-06T02:00:00Z")
    verify.add_argument("--end", required=True)
    verify.add_argument("--match", "-m", action="append", default=[], help="field=value (repeatable)")
    verify.add_argument("--ndjson", help="read events from an NDJSON file instead of Elasticsearch")
    verify.add_argument("--json", action="store_true", help="print machine-readable JSON")

    sub.add_parser("questions", help="list the investigative questions in the catalog")

    demo = sub.add_parser("demo", help="run the built-in lab with injected blind spots")
    demo.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    questions = load_catalog(*args.catalog)

    if args.command == "questions":
        for q in questions.values():
            print(f"{q.id:24} {q.description}")
            print(f"{'':24} sources: {', '.join(s.name for s in q.sources)}")
            print(f"{'':24} match fields: {', '.join(q.match_fields)}")
        return 0

    if args.command == "demo":
        from .demo import NOW, build_lab

        backend, scenarios = build_lab()
        verifier = Verifier(backend, questions, now=lambda: NOW)
        out, failures = [], 0
        for s in scenarios:
            result = verifier.verify(s.question, s.entity, s.start, s.end, s.match)
            failures += result.verdict.value != s.expected
            if args.json:
                out.append({"scenario": s.title, "expected": s.expected, **result.to_dict()})
            else:
                print(f"=== {s.title}: {s.story}")
                print(format_result(result), end="\n\n")
        if args.json:
            print(json.dumps(out, indent=2))
        return 1 if failures else 0

    try:
        result = Verifier(_backend(args), questions).verify(
            args.question, args.entity, args.start, args.end, _parse_match(args.match)
        )
    except (ValueError, BackendError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict(), indent=2) if args.json else format_result(result))
    return {Verdict.FOUND: 0, Verdict.VERIFIED_NEGATIVE: 0, Verdict.INSUFFICIENT_VISIBILITY: 3}[result.verdict]


if __name__ == "__main__":
    sys.exit(main())
