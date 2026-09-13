"""Thin aggregate-only CLI checks for CyberGym enrichment."""

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('enrich_cybergym_bundles', ROOT / 'scripts/enrich_cybergym_bundles.py')
wrapper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wrapper)


def test_arguments_are_required(tmp_path):
    with pytest.raises(SystemExit):
        wrapper.main(['--bundles', str(tmp_path)])


def test_wrapper_prints_only_stable_aggregates(monkeypatch, capsys, tmp_path):
    class Fake:
        def __init__(self, *_args): pass
        def build(self, _output):
            return type('Report', (), {'bundle_count': 2, 'enriched': 1, 'unmatched': 1,
                'class_filled': 1, 'sanitizer_filled': 1, 'architecture_filled': 1,
                'mitigation_links': 4, 'redactions_by_type': {}})()
    monkeypatch.setattr(wrapper, 'CyberGymEnrichmentAdapter', Fake)
    wrapper.main(['--bundles', str(tmp_path), '--metadata', str(tmp_path), '--revision', 'a' * 40,
                  '--output', str(tmp_path / 'out')])
    report = json.loads(capsys.readouterr().out)
    assert report == {'architecture_filled': 1, 'bundle_count': 2, 'class_filled': 1, 'enriched': 1,
                      'mitigation_links': 4, 'redactions_by_type': {}, 'sanitizer_filled': 1, 'unmatched': 1}
