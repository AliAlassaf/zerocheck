"""Runs the demo scenarios against a real Elasticsearch, directly or through Kibana.

Direct tests need ZEROCHECK_ES_URL and `python scripts/load_demo_into_elastic.py`.
The Kibana test needs ZEROCHECK_KIBANA_URL and the `--winlogbeat` layout loaded.
"""

import os
from pathlib import Path

import pytest

from zerocheck import Verifier, load_catalog
from zerocheck.backends import ElasticBackend
from zerocheck.demo import NOW, build_lab

needs_es = pytest.mark.skipif(not os.environ.get("ZEROCHECK_ES_URL") or bool(os.environ.get("ZEROCHECK_KIBANA_URL")),
                              reason="ZEROCHECK_ES_URL not set (or Kibana mode selected)")


@needs_es
@pytest.mark.parametrize("scenario", build_lab()[1], ids=lambda s: s.title)
def test_demo_scenarios_on_elastic(scenario):
    verifier = Verifier(ElasticBackend.from_env(), load_catalog(), now=lambda: NOW)
    result = verifier.verify(scenario.question, scenario.entity, scenario.start, scenario.end, scenario.match)
    assert result.verdict.value == scenario.expected, result.to_dict()


@needs_es
def test_elastic_matches_memory_backend():
    memory, scenarios = build_lab()
    questions = load_catalog()
    elastic = Verifier(ElasticBackend.from_env(), questions, now=lambda: NOW)
    local = Verifier(memory, questions, now=lambda: NOW)
    for s in scenarios:
        a = elastic.verify(s.question, s.entity, s.start, s.end, s.match)
        b = local.verify(s.question, s.entity, s.start, s.end, s.match)
        assert (a.verdict, a.match_count, a.uncovered) == (b.verdict, b.match_count, b.uncovered), s.title


WINLOGBEAT_CATALOG = Path(__file__).parent.parent / "examples" / "catalogs" / "winlogbeat.yaml"


@pytest.mark.skipif(not os.environ.get("ZEROCHECK_KIBANA_URL"), reason="ZEROCHECK_KIBANA_URL not set")
@pytest.mark.parametrize("scenario", build_lab()[1], ids=lambda s: s.title)
def test_demo_scenarios_through_kibana_with_winlogbeat_layout(scenario):
    # Needs: python scripts/load_demo_into_elastic.py --winlogbeat
    backend = ElasticBackend.from_env()
    assert backend.via_kibana
    verifier = Verifier(backend, load_catalog(WINLOGBEAT_CATALOG), now=lambda: NOW)
    result = verifier.verify(scenario.question, scenario.entity, scenario.start, scenario.end, scenario.match)
    assert result.verdict.value == scenario.expected, result.to_dict()
