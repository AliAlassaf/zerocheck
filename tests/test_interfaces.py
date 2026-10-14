import json
from datetime import timedelta

from zerocheck import cli, load_catalog
from zerocheck.backends.elastic import ElasticBackend
from zerocheck.demo import NOW


def test_catalog_loads_builtin_questions():
    questions = load_catalog()
    assert {"process_execution", "network_connection", "user_logon"} <= set(questions)
    assert questions["process_execution"].sources[0].max_silence == timedelta(minutes=30)


def test_demo_command_passes(capsys):
    assert cli.main(["demo", "--json"]) == 0
    results = json.loads(capsys.readouterr().out)
    assert [r["verdict"] for r in results] == [r["expected"] for r in results]


def test_verify_command_on_ndjson(tmp_path, capsys):
    events = tmp_path / "events.ndjson"
    events.write_text(
        "\n".join(
            json.dumps({"_index": "logs-windows.sysmon_operational-x", "@timestamp": f"2026-10-06T0{h}:00:00Z",
                        "host": {"name": "WS"}, "event": {"code": "1"},
                        "process": {"name": "a.exe", "command_line": "a", "parent": {"name": "b"}}})
            for h in range(3)
        )
    )
    code = cli.main(["verify", "-q", "process_execution", "-e", "WS", "--start", "2026-10-06T00:00:00Z",
                     "--end", "2026-10-06T03:00:00Z", "-m", "process.name=evil.exe",
                     "--ndjson", str(events), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 3 and out["verdict"] == "INSUFFICIENT_VISIBILITY"  # hourly events, 30m max silence


def test_mcp_tool(monkeypatch, tmp_path):
    from zerocheck import mcp_server

    events = tmp_path / "e.ndjson"
    events.write_text("")
    monkeypatch.setenv("ZEROCHECK_NDJSON", str(events))
    monkeypatch.setattr(mcp_server, "_verifier", None)
    assert any(q["id"] == "process_execution" for q in mcp_server.list_questions())
    result = mcp_server.verify_search("process_execution", "WS", "2026-10-06T00:00:00Z",
                                      "2026-10-06T01:00:00Z", {"process.name": "x"})
    assert result["verdict"] == "INSUFFICIENT_VISIBILITY"


def test_elastic_query_shape():
    q = ElasticBackend._query({"event.code": "1", "host.name": ["A", "B"]}, NOW - timedelta(hours=1), NOW)
    clauses = q["bool"]["filter"]
    assert clauses[0]["bool"]["should"][0]["term"]["event.code"]["value"] == "1"
    assert len(clauses[1]["bool"]["should"]) == 2
    assert clauses[2]["range"]["@timestamp"]["lt"] == NOW.isoformat()


def _http_error(code):
    import io
    import urllib.error

    def raise_it(*_args, **_kwargs):
        raise urllib.error.HTTPError("http://x", code, "err", {}, io.BytesIO(b"{}"))
    return raise_it


def test_elastic_login_failure_is_an_error_not_a_gap(monkeypatch):
    import pytest
    import urllib.request

    from zerocheck.backends import AccessDenied, BackendError

    backend = ElasticBackend("http://kibana:5601", username="u", password="p", via_kibana=True)
    monkeypatch.setattr(urllib.request, "urlopen", _http_error(401))
    with pytest.raises(BackendError, match="authentication failed"):
        backend.count("winlogbeat-*", {}, NOW - timedelta(hours=1), NOW)
    monkeypatch.setattr(urllib.request, "urlopen", _http_error(403))
    with pytest.raises(AccessDenied):
        backend.count("winlogbeat-*", {}, NOW - timedelta(hours=1), NOW)


def test_kibana_mode_routes_through_console_proxy(monkeypatch):
    import urllib.request

    seen = {}

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"hits": {"total": {"value": 3}}}'

    def fake_urlopen(request, **_kwargs):
        seen["url"], seen["headers"] = request.full_url, dict(request.header_items())
        return Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    backend = ElasticBackend("http://kibana:5601/", via_kibana=True)
    assert backend.count("winlogbeat-*", {}, NOW - timedelta(hours=1), NOW) == 3
    assert seen["url"].startswith("http://kibana:5601/api/console/proxy?path=winlogbeat-%2A%2F_search")
    assert seen["url"].endswith("&method=POST")
    assert seen["headers"].get("Kbn-xsrf") == "true"
