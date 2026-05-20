"""Fixtures shared across enrichters unit tests."""

import pytest
from sbom_pipeline.enrichters import bdu


@pytest.fixture(autouse=True)
def isolate_bdu_cache(monkeypatch, tmp_path):
    """Redirect DEFAULT_CACHE_DIR to a fresh per-test temp dir.

    Tests in test_bdu.py mock the network but not the disk cache.  Without
    this fixture, a stale .bdu_cache/bdu_cache.json left on disk from a
    previous run would cause cache hits and make those tests fail.

    Tests in test_bdu_cache.py pass cache_dir explicitly, so they are
    unaffected by this patch.
    """
    monkeypatch.setattr(bdu, "DEFAULT_CACHE_DIR", tmp_path / ".bdu_cache")
