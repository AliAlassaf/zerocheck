"""Elasticsearch / Elastic Security backend using the REST search API (no client library)."""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from ..models import parse_time
from .base import AccessDenied, Backend, BackendError


class ElasticBackend(Backend):
    """Talks to Elasticsearch directly, or through Kibana's console proxy when `via_kibana`
    is set. The proxy is what Kibana Dev Tools uses, so it works where only Kibana is exposed.
    """

    def __init__(
        self,
        url: str,
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        ca_cert: str | None = None,
        verify_tls: bool = True,
        timeout: float = 30.0,
        via_kibana: bool = False,
    ):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.via_kibana = via_kibana
        self.headers = {"Content-Type": "application/json"}
        if via_kibana:
            self.headers["kbn-xsrf"] = "true"
        if api_key:
            self.headers["Authorization"] = f"ApiKey {api_key}"
        elif username:
            token = base64.b64encode(f"{username}:{password or ''}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"
        self.ssl_context = ssl.create_default_context(cafile=ca_cert)
        if not verify_tls:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

    @classmethod
    def from_env(cls) -> "ElasticBackend":
        kibana = os.environ.get("ZEROCHECK_KIBANA_URL")
        return cls(
            url=kibana or os.environ.get("ZEROCHECK_ES_URL", "http://localhost:9200"),
            via_kibana=bool(kibana),
            api_key=os.environ.get("ZEROCHECK_ES_API_KEY"),
            username=os.environ.get("ZEROCHECK_ES_USERNAME"),
            password=os.environ.get("ZEROCHECK_ES_PASSWORD"),
            ca_cert=os.environ.get("ZEROCHECK_ES_CA_CERT"),
            verify_tls=os.environ.get("ZEROCHECK_ES_VERIFY_TLS", "true").lower() != "false",
        )

    def _search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        path = f"{index}/_search?ignore_unavailable=true&allow_no_indices=true"
        if self.via_kibana:
            url = f"{self.url}/api/console/proxy?path={urllib.parse.quote(path, safe='')}&method=POST"
        else:
            url = f"{self.url}/{path}"
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode(),
            headers=self.headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            if exc.code == 401:
                # Login failed: a configuration error, not a blind spot in the data.
                raise BackendError(
                    f"authentication failed at {self.url} (401); check ZEROCHECK_ES_USERNAME / "
                    "ZEROCHECK_ES_PASSWORD or ZEROCHECK_ES_API_KEY"
                ) from exc
            if exc.code == 403:
                raise AccessDenied(f"403 reading {index}: {detail}") from exc
            raise BackendError(f"{exc.code} reading {index}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise BackendError(f"cannot reach {self.url}: {exc.reason}") from exc

    @staticmethod
    def _query(filters: dict[str, Any], start: datetime | None = None, end: datetime | None = None):
        clauses: list[dict[str, Any]] = []
        for field_name, value in filters.items():
            values = value if isinstance(value, (list, tuple)) else [value]
            clauses.append(
                {
                    "bool": {
                        "should": [
                            {"term": {field_name: {"value": v, "case_insensitive": True}}}
                            if isinstance(v, str)
                            else {"term": {field_name: v}}
                            for v in values
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )
        if start or end:
            rng: dict[str, str] = {"format": "strict_date_optional_time"}
            if start:
                rng["gte"] = start.isoformat()
            if end:
                rng["lt"] = end.isoformat()
            clauses.append({"range": {"@timestamp": rng}})
        return {"bool": {"filter": clauses}}

    def count(self, index, filters, start, end):
        body = {"size": 0, "track_total_hits": True, "query": self._query(filters, start, end)}
        return int(self._search(index, body)["hits"]["total"]["value"])

    def bucket_counts(self, index, filters, start, end, interval: timedelta):
        n = max(1, -(-(end - start) // interval))
        body = {
            "size": 0,
            "query": self._query(filters, start, end),
            "aggs": {
                "buckets": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": f"{int(interval.total_seconds())}s",
                        "offset": f"{int(start.timestamp()) % int(interval.total_seconds())}s",
                        "min_doc_count": 0,
                        "extended_bounds": {"min": start.isoformat(), "max": end.isoformat()},
                    }
                }
            },
        }
        counts = [0] * n
        for bucket in self._search(index, body)["aggregations"]["buckets"]["buckets"]:
            key = parse_time(bucket["key_as_string"]) if "key_as_string" in bucket else None
            if key is None:
                key = datetime.fromtimestamp(bucket["key"] / 1000, tz=timezone.utc)
            slot = (key - start) // interval
            if 0 <= slot < n:
                counts[slot] += bucket["doc_count"]
        return counts

    def field_fill(self, index, filters, start, end, fields):
        body = {
            "size": 0,
            "track_total_hits": True,
            "query": self._query(filters, start, end),
            "aggs": {f"f{i}": {"filter": {"exists": {"field": f}}} for i, f in enumerate(fields)},
        }
        data = self._search(index, body)
        aggs = data.get("aggregations", {})
        filled = {f: int(aggs.get(f"f{i}", {}).get("doc_count", 0)) for i, f in enumerate(fields)}
        return int(data["hits"]["total"]["value"]), filled

    def time_bounds(self, index, filters):
        body = {
            "size": 0,
            "query": self._query(filters),
            "aggs": {"lo": {"min": {"field": "@timestamp"}}, "hi": {"max": {"field": "@timestamp"}}},
        }
        aggs = self._search(index, body).get("aggregations", {})
        lo, hi = aggs.get("lo", {}).get("value"), aggs.get("hi", {}).get("value")
        if lo is None or hi is None:
            return None
        return (
            datetime.fromtimestamp(lo / 1000, tz=timezone.utc),
            datetime.fromtimestamp(hi / 1000, tz=timezone.utc),
        )
