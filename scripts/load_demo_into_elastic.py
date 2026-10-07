"""Load the synthetic demo lab into Elasticsearch so `zerocheck verify` can run against it.

Usage:
    python scripts/load_demo_into_elastic.py            # uses ZEROCHECK_ES_URL (default http://localhost:9200)

Events go into `logs-*` data streams, which Elasticsearch maps with keyword strings
the same way Elastic Agent integrations do.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from datetime import datetime

from zerocheck.demo import build_lab


def main() -> int:
    url = os.environ.get("ZEROCHECK_ES_URL", "http://localhost:9200").rstrip("/")
    backend, _ = build_lab()
    lines = []
    for event in backend.events:
        doc = {k: v for k, v in event.items() if k != "_index"}
        doc["@timestamp"] = event["@timestamp"].isoformat()
        lines.append(json.dumps({"create": {"_index": event["_index"]}}))
        lines.append(json.dumps(doc, default=lambda o: o.isoformat() if isinstance(o, datetime) else str(o)))
    body = ("\n".join(lines) + "\n").encode()
    request = urllib.request.Request(
        f"{url}/_bulk?refresh=wait_for", data=body, headers={"Content-Type": "application/x-ndjson"}
    )
    with urllib.request.urlopen(request) as resp:
        result = json.load(resp)
    if result.get("errors"):
        first = next(i for i in result["items"] if "error" in i["create"])
        print(f"bulk load had errors, first: {first}", file=sys.stderr)
        return 1
    print(f"loaded {len(backend.events)} events into {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
