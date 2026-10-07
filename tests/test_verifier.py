from datetime import datetime, timedelta, timezone

import pytest

from zerocheck import GapReason, Verdict, Verifier, load_catalog
from zerocheck.backends import MemoryBackend
from zerocheck.demo import NOW, build_lab

SYSMON = "logs-windows.sysmon_operational-default"
SECURITY = "logs-system.security-default"
QUESTIONS = load_catalog()


def sysmon(host, t, name="svchost.exe", **extra):
    return {"_index": SYSMON, "@timestamp": t, "host": {"name": host}, "event": {"code": "1"},
            "process": {"name": name, "command_line": name, "parent": {"name": "services.exe"}}, **extra}


def steady(host, start, end, step=timedelta(minutes=5), make=sysmon):
    t = start
    while t < end:
        yield make(host, t)
        t += step


def verifier(events, **kw):
    return Verifier(MemoryBackend(events, **kw), QUESTIONS, now=lambda: NOW)


H = lambda h, m=0: NOW.replace(hour=h, minute=m)  # noqa: E731


@pytest.mark.parametrize("scenario", build_lab()[1], ids=lambda s: s.title)
def test_demo_scenarios(scenario):
    backend, _ = build_lab()
    result = Verifier(backend, QUESTIONS, now=lambda: NOW).verify(
        scenario.question, scenario.entity, scenario.start, scenario.end, scenario.match
    )
    assert result.verdict.value == scenario.expected


def test_short_quiet_period_is_not_a_gap():
    events = [e for e in steady("WS", H(0), H(11)) if not H(3) <= e["@timestamp"] < H(3, 20)]
    result = verifier(events).verify("process_execution", "WS", H(2), H(5), {"process.name": "evil.exe"})
    assert result.verdict is Verdict.VERIFIED_NEGATIVE
    assert result.coverage == 1


def test_gap_in_one_source_is_covered_by_the_other():
    def security(host, t):
        return {"_index": SECURITY, "@timestamp": t, "host": {"name": host}, "event": {"code": "4688"},
                "process": {"name": "svchost.exe", "command_line": "svchost.exe"}}

    events = [e for e in steady("WS", H(0), H(11)) if not H(2) <= e["@timestamp"] < H(4)]
    events += list(steady("WS", H(0), H(11), make=security))
    result = verifier(events).verify("process_execution", "WS", H(1), H(5), {"process.name": "evil.exe"})
    assert result.verdict is Verdict.VERIFIED_NEGATIVE
    assert [g.reason for g in result.gaps] == [GapReason.SOURCE_SILENT]  # still reported, just not blinding


def test_silence_before_window_start_is_detected():
    # The host died at 01:00; a window starting at 02:00 must still be flagged.
    events = list(steady("WS", H(0), H(1))) + list(steady("OTHER", H(0), H(11)))
    result = verifier(events).verify("process_execution", "WS", H(2), H(3), {"process.name": "evil.exe"})
    assert result.verdict is Verdict.INSUFFICIENT_VISIBILITY
    assert result.coverage == 0


def test_unknown_host_is_blind_not_clean():
    result = verifier(steady("WS", H(0), H(11))).verify(
        "process_execution", "TYPO-HOST", H(2), H(3), {"process.name": "evil.exe"}
    )
    assert result.verdict is Verdict.INSUFFICIENT_VISIBILITY


def test_access_denied_is_reported():
    events = list(steady("WS", H(0), H(11)))
    result = verifier(events, denied_indices=["logs-windows.sysmon_operational-*"]).verify(
        "process_execution", "WS", H(2), H(3), {"process.name": "evil.exe"}
    )
    assert result.verdict is Verdict.INSUFFICIENT_VISIBILITY
    assert GapReason.NO_ACCESS in {g.reason for g in result.gaps}


def test_rare_event_uses_channel_liveness():
    def security_logon(host, t):
        return {"_index": SECURITY, "@timestamp": t, "host": {"name": host}, "event": {"code": "4624"},
                "user": {"name": "bob"}, "winlog": {"logon": {"type": "3"}}}

    task = {"_index": SECURITY, "@timestamp": H(0, 1), "host": {"name": "OTHER"}, "event": {"code": "4698"},
            "winlog": {"event_data": {"TaskName": "\\Updater"}}}
    events = list(steady("WS", H(0), H(11), make=security_logon)) + [task]
    result = verifier(events).verify("scheduled_task_created", "WS", H(2), H(6))
    assert result.verdict is Verdict.VERIFIED_NEGATIVE


def test_never_collected_event_is_source_empty():
    events = list(steady("WS", H(0), H(11)))
    result = verifier(events).verify("scheduled_task_created", "WS", H(2), H(6))
    assert result.verdict is Verdict.INSUFFICIENT_VISIBILITY
    assert {g.reason for g in result.gaps} == {GapReason.SOURCE_EMPTY}


def test_matching_on_unknown_field_is_rejected():
    with pytest.raises(ValueError, match="not matchable"):
        verifier([]).verify("process_execution", "WS", H(1), H(2), {"proc.nam": "x"})


def test_window_end_in_future_is_clipped():
    result = verifier(steady("WS", H(0), H(12))).verify(
        "process_execution", "WS", H(11), NOW + timedelta(hours=3), {"process.name": "evil.exe"}
    )
    assert result.end == NOW
    assert result.verdict is Verdict.VERIFIED_NEGATIVE


def test_result_serializes():
    data = verifier(steady("WS", H(0), H(1))).verify(
        "process_execution", "WS", H(0), H(3), {"process.name": "evil.exe"}
    ).to_dict()
    assert data["verdict"] == "INSUFFICIENT_VISIBILITY"
    assert all("next_step" in g for g in data["gaps"])
    assert datetime.fromisoformat(data["start"]).tzinfo == timezone.utc
