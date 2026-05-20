"""Integration tests for BDU disk cache — real filesystem, mocked HTTP.

These tests exercise the full cache read→fetch→write cycle without hitting
the real bdu.fstec.ru endpoint.  They are marked *integration* because they
test the interaction between the cache layer and the filesystem rather than
pure in-memory logic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import pytest

ROOT = Path(__file__).resolve().parents[4]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sbom_pipeline.enrichters import bdu

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _csrf_cookies():
    class _C:
        def get(self, key, default=None):
            return {'YII_CSRF_TOKEN': '%22tok%22', 'PHPSESSID': 'sid'}.get(key, default)
    return _C()


def _make_fake_get(results: dict[str, Optional[str]]):
    """Return a fake requests.get that serves CSRF cookies and BDU search results."""

    def fake_get(url, params=None, **kwargs):
        class _Resp:
            def __init__(self, text, cookies):
                self.text = text
                self.cookies = cookies

            def raise_for_status(self):
                pass

        if params is None:
            return _Resp('', _csrf_cookies())

        key = params.get('VulFilterForm[idval]', '')
        bdu_id = results.get(key)
        if bdu_id:
            html = f'<div id="vuls"><a class="confirm-vul" href="/vul/x">{bdu_id}</a></div>'
        else:
            html = "<div id='vuls'></div>"
        return _Resp(html, _csrf_cookies())

    return fake_get


# ---------------------------------------------------------------------------
# Cache file lifecycle
# ---------------------------------------------------------------------------

class TestCacheFileLifecycle:
    def test_cache_file_created_on_first_call(self, tmp_path, monkeypatch):
        """After the first lookup the cache JSON file must exist on disk."""
        monkeypatch.setattr(bdu.requests, 'get', _make_fake_get({'2024-0001': 'BDU:2024-00001'}))
        monkeypatch.setattr(bdu.time, 'sleep', lambda _: None)

        bdu.get_bdu_ids_by_cves(['CVE-2024-0001'], cache_dir=tmp_path)

        assert (tmp_path / bdu._CACHE_FILE_NAME).exists()

    def test_cache_file_contains_found_result(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bdu.requests, 'get', _make_fake_get({'2024-0001': 'BDU:2024-00001'}))
        monkeypatch.setattr(bdu.time, 'sleep', lambda _: None)

        bdu.get_bdu_ids_by_cves(['CVE-2024-0001'], cache_dir=tmp_path)

        data = json.loads((tmp_path / bdu._CACHE_FILE_NAME).read_text(encoding='utf-8'))
        assert data['CVE-2024-0001'] == 'BDU:2024-00001'

    def test_cache_file_contains_null_for_not_found(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bdu.requests, 'get', _make_fake_get({}))

        bdu.get_bdu_ids_by_cves(['CVE-2024-0099'], cache_dir=tmp_path)

        data = json.loads((tmp_path / bdu._CACHE_FILE_NAME).read_text(encoding='utf-8'))
        assert data['CVE-2024-0099'] is None

    def test_cache_file_not_created_when_all_inputs_invalid(self, tmp_path, monkeypatch):
        """Non-CVE inputs are discarded before the cache phase; no file should be written."""
        called = [False]

        def must_not_call(*args, **kwargs):
            called[0] = True

        monkeypatch.setattr(bdu.requests, 'get', must_not_call)

        bdu.get_bdu_ids_by_cves(['not-a-cve', 'GHSA-1234-5678-9012'], cache_dir=tmp_path)

        assert not (tmp_path / bdu._CACHE_FILE_NAME).exists()
        assert not called[0]


# ---------------------------------------------------------------------------
# Two-call round-trip: cache prevents redundant network traffic
# ---------------------------------------------------------------------------

class TestTwoCallRoundTrip:
    def test_second_call_requires_no_http_requests(self, tmp_path, monkeypatch):
        """After the cache is warm a second identical call must make zero HTTP requests."""
        http_calls = []

        def counting_get(url, params=None, **kwargs):
            http_calls.append({'url': url, 'params': params})

            class _Resp:
                cookies = type('C', (), {
                    'get': lambda self, k, d=None: {'YII_CSRF_TOKEN': '%22t%22'}.get(k, d)
                })()
                text = '<div id="vuls"><a class="confirm-vul" href="/vul/x">BDU:2024-00001</a></div>'

                def raise_for_status(self):
                    pass

            return _Resp()

        monkeypatch.setattr(bdu.requests, 'get', counting_get)
        monkeypatch.setattr(bdu.time, 'sleep', lambda _: None)

        # First call — populates the cache.
        result1 = bdu.get_bdu_ids_by_cves(['CVE-2024-0001'], cache_dir=tmp_path)
        count_after_first = len(http_calls)

        # Second call — must be fully served by the cache.
        result2 = bdu.get_bdu_ids_by_cves(['CVE-2024-0001'], cache_dir=tmp_path)

        assert result1 == result2
        assert len(http_calls) == count_after_first  # no new HTTP requests

    def test_cache_grows_incrementally(self, tmp_path, monkeypatch):
        """Each new CVE lookup should add entries to the existing cache file."""
        monkeypatch.setattr(
            bdu.requests, 'get',
            _make_fake_get({'2024-0001': 'BDU:2024-00001', '2024-0002': 'BDU:2024-00002'}),
        )
        monkeypatch.setattr(bdu.time, 'sleep', lambda _: None)

        bdu.get_bdu_ids_by_cves(['CVE-2024-0001'], cache_dir=tmp_path)
        bdu.get_bdu_ids_by_cves(['CVE-2024-0002'], cache_dir=tmp_path)

        data = json.loads((tmp_path / bdu._CACHE_FILE_NAME).read_text(encoding='utf-8'))
        assert 'CVE-2024-0001' in data
        assert 'CVE-2024-0002' in data

    def test_null_cached_entry_prevents_refetch(self, tmp_path, monkeypatch):
        """A CVE cached as null must NOT be re-fetched on subsequent calls."""
        call_count = [0]

        def counting_get(url, params=None, **kwargs):
            call_count[0] += 1

            class _Resp:
                cookies = type('C', (), {
                    'get': lambda self, k, d=None: {'YII_CSRF_TOKEN': '%22t%22'}.get(k, d)
                })()
                text = "<div id='vuls'></div>"

                def raise_for_status(self):
                    pass

            return _Resp()

        monkeypatch.setattr(bdu.requests, 'get', counting_get)

        # First call stores null in the cache.
        bdu.get_bdu_ids_by_cves(['CVE-2024-0099'], cache_dir=tmp_path)
        count_after_first = call_count[0]

        # Second call must not touch the network.
        bdu.get_bdu_ids_by_cves(['CVE-2024-0099'], cache_dir=tmp_path)

        assert call_count[0] == count_after_first


# ---------------------------------------------------------------------------
# Atomic write safety
# ---------------------------------------------------------------------------

class TestAtomicWrite:
    def test_no_leftover_tmp_files_after_write(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bdu.requests, 'get', _make_fake_get({'2024-0001': 'BDU:2024-00001'}))
        monkeypatch.setattr(bdu.time, 'sleep', lambda _: None)

        bdu.get_bdu_ids_by_cves(['CVE-2024-0001'], cache_dir=tmp_path)

        assert list(tmp_path.glob('*.tmp')) == []

    def test_cache_is_readable_json_after_concurrent_batches(self, tmp_path, monkeypatch):
        """Simulate two sequential batches; the resulting cache must be valid JSON."""
        monkeypatch.setattr(
            bdu.requests, 'get',
            _make_fake_get({
                '2024-0001': 'BDU:2024-00001',
                '2024-0002': 'BDU:2024-00002',
                '2024-0003': None,
            }),
        )
        monkeypatch.setattr(bdu.time, 'sleep', lambda _: None)

        bdu.get_bdu_ids_by_cves(['CVE-2024-0001', 'CVE-2024-0002'], cache_dir=tmp_path)
        bdu.get_bdu_ids_by_cves(['CVE-2024-0003'], cache_dir=tmp_path)

        raw = (tmp_path / bdu._CACHE_FILE_NAME).read_text(encoding='utf-8')
        data = json.loads(raw)  # must not raise
        assert len(data) == 3
