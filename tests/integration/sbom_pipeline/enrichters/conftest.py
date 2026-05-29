"""Fixtures shared across enrichters integration tests."""

import pytest
from sbom_pipeline.enrichters import bdu


@pytest.fixture(autouse=True)
def isolate_bdu_cache(monkeypatch, tmp_path):
    """Redirect DEFAULT_CACHE_DIR to a fresh per-test temp dir.

    Prevents stale .bdu_cache/bdu_cache.json on disk from producing cache
    hits that skip network calls (and therefore rate-limit sleeps) in tests
    that mock requests but don't pass an explicit cache_dir.
    """
    monkeypatch.setattr(bdu, "DEFAULT_CACHE_DIR", tmp_path / ".bdu_cache")
