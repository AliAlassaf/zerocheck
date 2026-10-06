"""A synthetic lab with deliberately injected blind spots, one per verdict path."""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .backends.memory import MemoryBackend

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
SYSMON = "logs-windows.sysmon_operational-default"
SECURITY = "logs-system.security-default"
BENIGN = ["svchost.exe", "chrome.exe", "explorer.exe", "OneDrive.exe", "msedge.exe"]


@dataclass
class Scenario:
    title: str
    story: str
    question: str
    entity: str
    start: datetime
    end: datetime
    match: dict[str, Any]
    expected: str


def _process_events(host: str, start: datetime, end: datetime, step: timedelta):
    names = itertools.cycle(BENIGN)
    t = start
    while t < end:
        name = next(names)
        sysmon = {
            "_index": SYSMON, "@timestamp": t, "host": {"name": host}, "event": {"code": "1"},
            "process": {"name": name, "command_line": f"C:\\Windows\\{name}",
                        "parent": {"name": "services.exe"}},
        }
        security = {
            "_index": SECURITY, "@timestamp": t + timedelta(seconds=1), "host": {"name": host},
            "event": {"code": "4688"}, "process": {"name": name, "command_line": f"C:\\Windows\\{name}"},
        }
        yield sysmon
        yield security
        t += step


def build_lab(now: datetime = NOW) -> tuple[MemoryBackend, list[Scenario]]:
    day_ago = now - timedelta(hours=24)
    step = timedelta(minutes=3)
    ingested_until = now - timedelta(minutes=40)  # the pipeline is 40 minutes behind
    events: list[dict[str, Any]] = []

    # WS-01: healthy host. PowerShell ran at 09:15.
    events += _process_events("WS-01", day_ago, ingested_until, step)
    events.append({
        "_index": SYSMON, "@timestamp": now.replace(hour=9, minute=15), "host": {"name": "WS-01"},
        "event": {"code": "1"},
        "process": {"name": "powershell.exe", "command_line": "powershell -enc SQBFAFgA...",
                    "parent": {"name": "winword.exe"}},
    })

    # WS-02: both sensors went quiet 02:00-03:30 (agent crash, host still running).
    outage = (now.replace(hour=2), now.replace(hour=3, minute=30))
    events += [e for e in _process_events("WS-02", day_ago, ingested_until, step)
               if not outage[0] <= e["@timestamp"] < outage[1]]

    # WS-03: at 06:00 a Sysmon parser update stopped populating command_line,
    # and a GPO change the same morning disabled 4688 command-line auditing.
    for e in _process_events("WS-03", day_ago, ingested_until, step):
        if e["@timestamp"] >= now.replace(hour=6):
            e["process"]["command_line"] = None
        events.append(e)

    backend = MemoryBackend(events)
    scenarios = [
        Scenario(
            "Evidence found", "WS-01 is healthy and PowerShell really ran.",
            "process_execution", "WS-01", now.replace(hour=9), now.replace(hour=10),
            {"process.name": "powershell.exe"}, "FOUND",
        ),
        Scenario(
            "Real negative", "WS-01 is healthy; mimikatz never ran. Zero results can be trusted.",
            "process_execution", "WS-01", now.replace(hour=1), now.replace(hour=5),
            {"process.name": "mimikatz.exe"}, "VERIFIED_NEGATIVE",
        ),
        Scenario(
            "Sensor outage", "WS-02's agents were silent 02:00-03:30. A Tier 1 would close this as clean.",
            "process_execution", "WS-02", now.replace(hour=1), now.replace(hour=5),
            {"process.name": "mimikatz.exe"}, "INSUFFICIENT_VISIBILITY",
        ),
        Scenario(
            "Parser drift", "Searching WS-03 by command line after a parser update emptied that field.",
            "process_execution", "WS-03", now.replace(hour=7), now.replace(hour=9),
            {"process.command_line": "powershell -enc SQBFAFgA..."}, "INSUFFICIENT_VISIBILITY",
        ),
        Scenario(
            "Ingestion lag", "Searching the last hour while the pipeline is 40 minutes behind.",
            "process_execution", "WS-01", now - timedelta(hours=1), now,
            {"process.name": "mimikatz.exe"}, "INSUFFICIENT_VISIBILITY",
        ),
        Scenario(
            "Retention", "Searching three days back when only 24 hours are stored.",
            "process_execution", "WS-01", now - timedelta(days=3), now - timedelta(days=2),
            {"process.name": "mimikatz.exe"}, "INSUFFICIENT_VISIBILITY",
        ),
    ]
    return backend, scenarios
