"""Load the synthetic demo lab into Elasticsearch so `zerocheck verify` can run against it.

Usage:
    python scripts/load_demo_into_elastic.py                 # Elastic Agent layout (logs-* data streams)
    python scripts/load_demo_into_elastic.py --winlogbeat    # Winlogbeat layout (one winlogbeat-demo index)

Connects to ZEROCHECK_ES_URL (default http://localhost:9200), with ZEROCHECK_ES_USERNAME /
ZEROCHECK_ES_PASSWORD if set. Both layouts map strings as keywords, as the real shippers do.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.request
from datetime import datetime

from zerocheck.demo import SECURITY, SYSMON, build_lab

WINLOGBEAT_INDEX = "winlogbeat-demo"
CHANNELS = {SYSMON: "Microsoft-Windows-Sysmon/Operational", SECURITY: "Security"}
WINLOGBEAT_TEMPLATE = {
    "index_patterns": ["winlogbeat-*"],
    "priority": 500,
    "template": {"mappings": {
        "dynamic_templates": [{"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}],
        "properties": {"@timestamp": {"type": "date"}},
    }},
}


def _request(url: str, method: str, body: bytes, content_type: str) -> dict:
    headers = {"Content-Type": content_type}
    if os.environ.get("ZEROCHECK_ES_USERNAME"):
        creds = f"{os.environ['ZEROCHECK_ES_USERNAME']}:{os.environ.get('ZEROCHECK_ES_PASSWORD', '')}"
        headers["Authorization"] = "Basic " + base64.b64encode(creds.encode()).decode()
    with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers, method=method)) as resp:
        return json.load(resp)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--winlogbeat", action="store_true", help="write a Winlogbeat-style index instead")
    args = parser.parse_args()
    url = os.environ.get("ZEROCHECK_ES_URL", "http://localhost:9200").rstrip("/")
    if args.winlogbeat:
        _request(f"{url}/_index_template/zerocheck-winlogbeat-demo", "PUT",
                 json.dumps(WINLOGBEAT_TEMPLATE).encode(), "application/json")
    backend, _ = build_lab()
    lines = []
    for event in backend.events:
        doc = {k: v for k, v in event.items() if k != "_index"}
        doc["@timestamp"] = event["@timestamp"].isoformat()
        index = event["_index"]
        if args.winlogbeat:
            doc["winlog"] = {"channel": CHANNELS[index]}
            index = WINLOGBEAT_INDEX
        lines.append(json.dumps({"create": {"_index": index}}))
        lines.append(json.dumps(doc, default=lambda o: o.isoformat() if isinstance(o, datetime) else str(o)))
    body = ("\n".join(lines) + "\n").encode()
    result = _request(f"{url}/_bulk?refresh=wait_for", "POST", body, "application/x-ndjson")
    if result.get("errors"):
        first = next(i for i in result["items"] if "error" in i["create"])
        print(f"bulk load had errors, first: {first}", file=sys.stderr)
        return 1
    print(f"loaded {len(backend.events)} events into {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
