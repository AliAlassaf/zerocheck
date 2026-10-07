"""MCP server so AI SOC agents can check an empty result before closing a case.

Run with `zerocheck-mcp` (stdio). Configure Elasticsearch with ZEROCHECK_ES_* env vars,
or set ZEROCHECK_NDJSON to a file of events for offline use.
"""

from __future__ import annotations

import os
from typing import Any

from mcp.server.mcpserver import MCPServer

from .backends import ElasticBackend, MemoryBackend
from .catalog import load_catalog
from .verifier import Verifier

server = MCPServer(
    name="zerocheck",
    instructions=(
        "Before concluding that activity did not happen because a search returned no results, "
        "call verify_search. Only a VERIFIED_NEGATIVE verdict supports that conclusion. "
        "INSUFFICIENT_VISIBILITY means the case must not be closed as benign on this evidence; "
        "report the blind intervals and gap reasons to the analyst."
    ),
)

_verifier: Verifier | None = None


def _get_verifier() -> Verifier:
    global _verifier
    if _verifier is None:
        extra = [p for p in os.environ.get("ZEROCHECK_CATALOG", "").split(os.pathsep) if p]
        ndjson = os.environ.get("ZEROCHECK_NDJSON")
        backend = MemoryBackend.from_ndjson(ndjson) if ndjson else ElasticBackend.from_env()
        _verifier = Verifier(backend, load_catalog(*extra))
    return _verifier


@server.tool()
def list_questions() -> list[dict[str, Any]]:
    """List investigative questions this server can verify, with their matchable fields."""
    return [
        {"id": q.id, "description": q.description, "entity_field": q.entity_field,
         "match_fields": list(q.match_fields), "sources": [s.name for s in q.sources]}
        for q in _get_verifier().questions.values()
    ]


@server.tool()
def verify_search(
    question: str, entity: str, start: str, end: str, match: dict[str, str] | None = None
) -> dict[str, Any]:
    """Check whether a search for `match` on `entity` between `start` and `end` (ISO-8601)
    returns a trustworthy answer.

    Verdicts: FOUND (evidence exists), VERIFIED_NEGATIVE (no matches and the whole window
    was observable), INSUFFICIENT_VISIBILITY (no matches, but parts of the window were blind;
    see `uncovered` and `gaps`).
    """
    return _get_verifier().verify(question, entity, start, end, match).to_dict()


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
