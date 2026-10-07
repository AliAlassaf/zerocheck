"""Download OTRF Security-Datasets recordings and normalize them to the ECS fields ZeroCheck uses."""

from __future__ import annotations

import json
import tarfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

RAW_BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/"

SYSMON_INDEX = "logs-windows.sysmon_operational-otrf"
SECURITY_INDEX = "logs-system.security-otrf"
POWERSHELL_INDEX = "logs-windows.powershell_operational-otrf"


def fetch(path: str, cache_dir: Path) -> Path:
    """Download one archive into the cache (once) and return its local path."""
    target = cache_dir / path
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(RAW_BASE + path, timeout=120) as resp:
            data = resp.read()
        target.write_bytes(data)
    return target


def _json_lines(archive: Path) -> Iterator[bytes]:
    """Yield JSON lines from every .json member, reading in memory (nothing is extracted)."""
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zf:
            for name in zf.namelist():
                if name.endswith(".json"):
                    yield from zf.read(name).splitlines()
    else:
        with tarfile.open(archive) as tf:
            for member in tf.getmembers():
                if member.isfile() and member.name.endswith(".json"):
                    yield from tf.extractfile(member).read().splitlines()


def _timestamp(raw: dict[str, Any]) -> datetime:
    value = raw.get("@timestamp") or raw.get("TimeCreated") or raw.get("EventTime")
    value = value.replace("Z", "+00:00").replace(" ", "T", 1)
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)  # OTRF records UTC


def _base(path: str | None) -> str | None:
    return path.split("\\")[-1] if path else None


def normalize(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Map one raw Windows event to the ECS fields used by the catalog; None if unused."""
    channel = (raw.get("Channel") or "").lower()
    code = int(raw.get("EventID", 0))
    event: dict[str, Any] = {
        "@timestamp": _timestamp(raw),
        "host": {"name": raw.get("Hostname") or raw.get("host")},
        "event": {"code": str(code)},
    }
    if "sysmon" in channel:
        event["_index"] = SYSMON_INDEX
        if code == 1:
            event["process"] = {
                "name": _base(raw.get("Image")),
                "executable": raw.get("Image"),
                "command_line": raw.get("CommandLine"),
                "parent": {"name": _base(raw.get("ParentImage"))},
            }
            event["user"] = {"name": raw.get("User")}
        elif code == 3:
            event["process"] = {"name": _base(raw.get("Image"))}
            event["destination"] = {"ip": raw.get("DestinationIp"), "port": raw.get("DestinationPort")}
        elif code == 22:
            event["process"] = {"name": _base(raw.get("Image"))}
            event["dns"] = {"question": {"name": raw.get("QueryName")}}
    elif channel == "security":
        event["_index"] = SECURITY_INDEX
        if code == 4688:
            event["process"] = {
                "name": _base(raw.get("NewProcessName")),
                "command_line": raw.get("CommandLine"),
                "parent": {"name": _base(raw.get("ParentProcessName"))},
            }
            event["user"] = {"name": raw.get("SubjectUserName")}
        elif code == 4624:
            event["user"] = {"name": raw.get("TargetUserName")}
            event["source"] = {"ip": raw.get("IpAddress")}
            event["winlog"] = {"logon": {"type": str(raw.get("LogonType"))}}
        elif code == 4698:
            event["winlog"] = {"event_data": {"TaskName": raw.get("TaskName")}}
    elif "powershell" in channel:
        event["_index"] = POWERSHELL_INDEX
        if code == 4104:
            event["powershell"] = {"file": {"script_block_text": raw.get("ScriptBlockText")}}
    else:
        return None
    return event


def load(path: str, cache_dir: Path) -> list[dict[str, Any]]:
    events = []
    for line in _json_lines(fetch(path, cache_dir)):
        if line.strip():
            event = normalize(json.loads(line))
            if event is not None:
                events.append(event)
    return events
