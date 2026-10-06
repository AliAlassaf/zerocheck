"""Runs the demo scenarios against a real Elasticsearch.

Skipped unless NULLGUARD_ES_URL is set and the demo lab has been loaded with
scripts/load_demo_into_elastic.py.
"""

import os

import pytest

from nullguard import Verifier, load_catalog
from nullguard.backends import ElasticBackend
from nullguard.demo import NOW, build_lab

pytestmark = pytest.mark.skipif(not os.environ.get("NULLGUARD_ES_URL"), reason="NULLGUARD_ES_URL not set")


@pytest.mark.parametrize("scenario", build_lab()[1], ids=lambda s: s.title)
def test_demo_scenarios_on_elastic(scenario):
    verifier = Verifier(ElasticBackend.from_env(), load_catalog(), now=lambda: NOW)
    result = verifier.verify(scenario.question, scenario.entity, scenario.start, scenario.end, scenario.match)
    assert result.verdict.value == scenario.expected, result.to_dict()


def test_elastic_matches_memory_backend():
    memory, scenarios = build_lab()
    questions = load_catalog()
    elastic = Verifier(ElasticBackend.from_env(), questions, now=lambda: NOW)
    local = Verifier(memory, questions, now=lambda: NOW)
    for s in scenarios:
        a = elastic.verify(s.question, s.entity, s.start, s.end, s.match)
        b = local.verify(s.question, s.entity, s.start, s.end, s.match)
        assert (a.verdict, a.match_count, a.uncovered) == (b.verdict, b.match_count, b.uncovered), s.title
