"""Evaluate ZeroCheck on OTRF Security-Datasets recordings with injected visibility failures.

For every recording the attack's process is known. Each fault hides that evidence
in a different way, so a plain search returns zero results; a good verdict is
INSUFFICIENT_VISIBILITY. Clean replays measure false warnings: searching for a
process that never ran must come back VERIFIED_NEGATIVE.

    python evaluation/run.py            # downloads ~6 MB on first run, writes evaluation/RESULTS.md
"""

from __future__ import annotations

import argparse
import copy
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

import yaml

from otrf import SECURITY_INDEX, SYSMON_INDEX, load
from zerocheck import GapReason, Question, Source, Verifier
from zerocheck.models import parse_time
from zerocheck.backends import MemoryBackend

HERE = Path(__file__).parent
ABSENT_PROCESS = "mimikatz.exe"  # never runs in any selected recording; checked at runtime
PROCESS_CODES = {"1", "4688"}
EDGE = timedelta(milliseconds=500)

Events = list[dict[str, Any]]


def question(max_silence: timedelta) -> dict[str, Question]:
    """process_execution, with liveness judged from the whole channel.

    Recordings last seconds to minutes and hold only a handful of process-creation
    events, so silence of EID 1 / 4688 alone says nothing about whether a sensor was up.
    """
    sources = (
        Source("sysmon_process_create", SYSMON_INDEX, {"event.code": "1"},
               ("process.name",), max_silence, liveness_filter={}),
        Source("security_4688", SECURITY_INDEX, {"event.code": "4688"},
               ("process.name",), max_silence, liveness_filter={}),
    )
    q = Question("process_execution", "Did a process run on a host?", "host.name", sources,
                 ("process.name", "process.command_line"))
    return {q.id: q}


# Each fault returns (events, denied indices) and names the gap reason it should produce.
def sensor_outage(events, host, t0, t1, outage):
    lo, hi = t0 - outage / 2, t1 + outage / 2
    return [e for e in events if not (e["host"]["name"] == host and lo <= e["@timestamp"] <= hi)], []


def ingestion_lag(events, host, t0, t1, outage):
    return [e for e in events if e["@timestamp"] < t0 - EDGE], []


def retention(events, host, t0, t1, outage):
    return [e for e in events if e["@timestamp"] > t1 + EDGE], []


def parser_drift(events, host, t0, t1, outage):
    out = []
    for e in events:
        if e["event"]["code"] in PROCESS_CODES and e["@timestamp"] >= t0 - EDGE:
            e = copy.deepcopy(e)
            e["process"]["name"] = None
        out.append(e)
    return out, []


def logging_disabled(events, host, t0, t1, outage):
    return [e for e in events if e["event"]["code"] not in PROCESS_CODES], []


def access_denied(events, host, t0, t1, outage):
    return events, [SYSMON_INDEX, SECURITY_INDEX]


FAULTS: dict[str, tuple[Callable, GapReason]] = {
    "sensor_outage": (sensor_outage, GapReason.SOURCE_SILENT),
    "ingestion_lag": (ingestion_lag, GapReason.INGESTION_LAG),
    "retention": (retention, GapReason.RETENTION),
    "parser_drift": (parser_drift, GapReason.FIELD_MISSING),
    "logging_disabled": (logging_disabled, GapReason.SOURCE_EMPTY),
    "access_denied": (access_denied, GapReason.NO_ACCESS),
}


def indicator_times(events: Events, host: str, name: str) -> list[datetime]:
    return sorted(
        e["@timestamp"] for e in events
        if e["host"]["name"] == host and e["event"]["code"] in PROCESS_CODES
        and (e.get("process", {}).get("name") or "").casefold() == name.casefold()
    )


def evaluate_dataset(ds: dict[str, Any], events: Events, levels: list[timedelta], outage: timedelta):
    host, indicator = ds["host"], ds["indicator"]
    hits = indicator_times(events, host, indicator)
    if not hits:
        raise SystemExit(f"{ds['name']}: indicator {indicator} not found on {host}; fix datasets.yaml")
    if indicator_times(events, host, ABSENT_PROCESS):
        raise SystemExit(f"{ds['name']}: {ABSENT_PROCESS} occurs; pick another negative control")
    t0, t1 = hits[0], hits[-1]
    # Recordings are clips: each channel starts and stops at a slightly different moment.
    # Search the span every source channel covers, so clip edges are not counted as
    # retention or ingestion gaps.
    bounds = [
        [e["@timestamp"] for e in events if e.get("_index") == index]
        for index in (SYSMON_INDEX, SECURITY_INDEX)
    ]
    start = max(min(b) for b in bounds)
    end = min(max(b) for b in bounds) + timedelta(milliseconds=1)
    if not start <= t0 <= t1 < end:
        raise SystemExit(f"{ds['name']}: attack falls outside the span covered by both channels")

    cases = [("clean_positive", events, [], indicator, None),
             ("clean_negative", events, [], ABSENT_PROCESS, None)]
    for fault, (inject, reason) in FAULTS.items():
        faulty, denied = inject(events, host, t0, t1, outage)
        cases.append((fault, faulty, denied, indicator, reason))

    known = [(parse_time(g["start"]), parse_time(g["end"]), g["cause"]) for g in ds.get("known_gaps", [])]

    def explained_by(uncovered) -> str | None:
        """Cause of a confirmed gap in the original recording, if it accounts for every blind interval."""
        causes = set()
        for u_start, u_end in uncovered:
            hit = [cause for k_start, k_end, cause in known if u_start < k_end and k_start < u_end]
            if not hit:
                return None
            causes.update(hit)
        return ", ".join(sorted(causes)) if causes else None

    rows = []
    for name, case_events, denied, process, expected_reason in cases:
        backend = MemoryBackend(denied_indices=denied)
        backend.events = case_events  # already parsed; skip re-validation
        # Did the fault actually hide the evidence from a plain search?
        hidden = not any(
            e["host"]["name"] == host and e["event"]["code"] in PROCESS_CODES
            and (e.get("process", {}).get("name") or "").casefold() == process.casefold()
            for e in case_events
        ) or bool(denied)
        for level in levels:
            verifier = Verifier(backend, question(level), now=lambda: end + timedelta(hours=1),
                                ingest_tolerance=timedelta(seconds=1), min_bucket=timedelta(milliseconds=100))
            result = verifier.verify("process_execution", host, start, end, {"process.name": process})
            rows.append({
                "dataset": ds["name"], "technique": ds["technique"], "case": name,
                "max_silence_s": level.total_seconds(), "hidden": hidden,
                "verdict": result.verdict.value, "coverage": round(result.coverage, 3),
                "reasons": sorted({g.reason.value for g in result.gaps}),
                "expected_reason": expected_reason.value if expected_reason else None,
                "recording_s": round((end - start).total_seconds(), 1),
                "known_gap": explained_by(result.uncovered) if name == "clean_negative" else None,
            })
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[float, dict[str, Any]]:
    by_level: dict[float, dict[str, Any]] = {}
    for level in sorted({r["max_silence_s"] for r in rows}):
        rs = [r for r in rows if r["max_silence_s"] == level]
        faults = [r for r in rs if r["case"] in FAULTS and r["hidden"]]
        negatives = [r for r in rs if r["case"] == "clean_negative"]
        positives = [r for r in rs if r["case"] == "clean_positive"]
        per_fault = defaultdict(lambda: [0, 0, 0])
        for r in faults:
            stats = per_fault[r["case"]]
            stats[0] += r["verdict"] == "INSUFFICIENT_VISIBILITY"
            stats[1] += r["expected_reason"] in r["reasons"]
            stats[2] += 1
        by_level[level] = {
            "detected": sum(r["verdict"] == "INSUFFICIENT_VISIBILITY" for r in faults),
            "reason_ok": sum(r["expected_reason"] in r["reasons"] for r in faults),
            "faults": len(faults),
            "false_warnings": sum(r["verdict"] != "VERIFIED_NEGATIVE" and not r["known_gap"] for r in negatives),
            "real_gaps": sum(r["verdict"] != "VERIFIED_NEGATIVE" and bool(r["known_gap"]) for r in negatives),
            "negatives": len(negatives),
            "found": sum(r["verdict"] == "FOUND" for r in positives),
            "positives": len(positives),
            "per_fault": dict(per_fault),
            "not_hidden": [f"{r['dataset']}/{r['case']}" for r in rs if r["case"] in FAULTS and not r["hidden"]],
        }
    return by_level


def pct(a: int, b: int) -> str:
    return f"{a}/{b} ({a / b:.0%})" if b else "n/a"


def write_report(rows, summary, datasets, outage: timedelta, path: Path) -> None:
    levels = list(summary)
    lines = [
        "# Evaluation on OTRF Security-Datasets",
        "",
        "_Generated by `python evaluation/run.py`. Do not edit by hand._",
        "",
        f"**Data:** {len(datasets)} recordings of real attack techniques from "
        "[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (Sysmon + Windows Security logs). "
        f"Searched spans (where both Sysmon and Security have data) last {min(r['recording_s'] for r in rows):.0f}s "
        f"to {max(r['recording_s'] for r in rows):.0f}s.",
        "",
        "**Question:** `process_execution` — did the attack's process (for example `ntdsutil.exe`) run on the attacked host "
        "during the recording? Ground truth is the attack process, confirmed in each recording.",
        "",
        "**Faults** (each one hides the evidence so a plain search returns zero results):",
        "",
        "| Fault | What is injected | Expected reason |",
        "|---|---|---|",
        f"| sensor_outage | Every event from the host dropped for {outage.total_seconds():.0f}s around the attack | `source_silent` |",
        "| ingestion_lag | Everything from just before the attack onward not ingested yet | `ingestion_lag` |",
        "| retention | Everything up to just after the attack already aged out | `retention` |",
        "| parser_drift | `process.name` empty in process events from just before the attack onward | `field_missing` |",
        "| logging_disabled | Sysmon EID 1 and Security 4688 not collected at all | `source_empty` |",
        "| access_denied | The querying identity cannot read the Sysmon and Security indices | `no_access` |",
        "",
        "**Baseline:** an analyst or agent who treats zero results as \"didn't happen\" accepts every one of these "
        "faulted searches as clean: 0% detected by construction.",
        "",
        "**False warnings** are measured on the unmodified recordings: searching for a process that never ran "
        f"(`{ABSENT_PROCESS}`) must return `VERIFIED_NEGATIVE`. A warning whose blind intervals all fall inside a "
        "gap confirmed by hand in the original recording (listed under Datasets) is counted as a real gap instead.",
        "",
        "## Results by silence threshold",
        "",
        "`max_silence` is how long a host may send nothing on a channel before it counts as blind. "
        "Real deployments use minutes; these recordings are seconds long, so thresholds are scaled down to seconds. "
        f"The outage length ({outage.total_seconds():.0f}s) and the thresholds 1-8s were fixed before the first run; "
        "15s and 30s were added after it, to show where false warnings stop and what that costs in detection.",
        "",
        "| max_silence | Blind spots detected | Correct reason | False warnings (clean data) | Real gaps flagged (clean data) | Real evidence still FOUND |",
        "|---|---|---|---|---|---|",
    ]
    for level, s in summary.items():
        lines.append(
            f"| {level:g}s | {pct(s['detected'], s['faults'])} | {pct(s['reason_ok'], s['faults'])} "
            f"| {pct(s['false_warnings'], s['negatives'])} | {s['real_gaps']} | {pct(s['found'], s['positives'])} |"
        )
    lines += ["", "## Detection by fault type", "",
              "Each cell: blind spots detected, and in brackets how many of those named the expected reason.", "",
              "| Fault | " + " | ".join(f"{l:g}s" for l in levels) + " |",
              "|---|" + "---|" * len(levels)]
    for fault in FAULTS:
        cells = []
        for level in levels:
            d, ok, n = summary[level]["per_fault"].get(fault, [0, 0, 0])
            cells.append(f"{pct(d, n)} [{ok}]")
        lines.append(f"| {fault} | " + " | ".join(cells) + " |")

    not_hidden = sorted({x for s in summary.values() for x in s["not_hidden"]})
    if not_hidden:
        lines += ["", f"Excluded because the injected fault did not hide all evidence: {', '.join(not_hidden)}."]

    lines += ["", "## Misses and false warnings", "",
              "Every case at every threshold that did not get the right verdict:", "",
              "| max_silence | Dataset | Case | Verdict | Gap reasons | Coverage |", "|---|---|---|---|---|---|"]
    misses = [
        r for r in rows
        if (r["case"] in FAULTS and r["hidden"] and r["verdict"] != "INSUFFICIENT_VISIBILITY")
        or (r["case"] == "clean_negative" and r["verdict"] != "VERIFIED_NEGATIVE")
        or (r["case"] == "clean_positive" and r["verdict"] != "FOUND")
    ]
    for r in misses:
        verdict = r["verdict"] + (f" (real gap: {r['known_gap']})" if r["known_gap"] else "")
        lines.append(f"| {r['max_silence_s']:g}s | {r['dataset']} | {r['case']} | {verdict} "
                     f"| {', '.join(r['reasons']) or '-'} | {r['coverage']:.0%} |")
    if not misses:
        lines.append("| - | none | | | | |")

    lines += ["", "## Datasets", "", "| Dataset | Technique | Host | Attack process | Searched span | Confirmed gaps |",
              "|---|---|---|---|---|---|"]
    lengths = {r["dataset"]: r["recording_s"] for r in rows}
    for ds in datasets:
        gaps = "; ".join(f"{g['cause']} {g['start'][11:19]}-{g['end'][11:19]}" for g in ds.get("known_gaps", [])) or "-"
        lines.append(f"| {ds['name']} | {ds['technique']} | {ds['host']} | `{ds['indicator']}` "
                     f"| {lengths[ds['name']]:g}s | {gaps} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cache", type=Path, default=HERE / ".cache")
    parser.add_argument("--report", type=Path, default=HERE / "RESULTS.md")
    parser.add_argument("--json", type=Path, default=HERE / "results.json")
    parser.add_argument("--outage", type=float, default=5.0, help="sensor outage length in seconds")
    parser.add_argument("--levels", type=float, nargs="+", default=[1, 2, 3, 5, 8, 15, 30],
                        help="max_silence thresholds to sweep, in seconds")
    args = parser.parse_args()

    datasets = yaml.safe_load((HERE / "datasets.yaml").read_text(encoding="utf-8"))
    levels = [timedelta(seconds=s) for s in args.levels]
    outage = timedelta(seconds=args.outage)
    rows = []
    for ds in datasets:
        events = load(ds["path"], args.cache)
        print(f"{ds['name']}: {len(events)} events")
        rows += evaluate_dataset(ds, events, levels, outage)

    summary = summarize(rows)
    write_report(rows, summary, datasets, outage, args.report)
    args.json.write_text(json.dumps({"summary": summary, "rows": rows}, indent=1, default=str), encoding="utf-8")
    for level, s in summary.items():
        print(f"max_silence={level:g}s detected {pct(s['detected'], s['faults'])}, "
              f"false warnings {pct(s['false_warnings'], s['negatives'])}, real gaps {s['real_gaps']}, found {pct(s['found'], s['positives'])}")
    print(f"wrote {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
