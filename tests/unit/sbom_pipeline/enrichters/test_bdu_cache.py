"""Unit tests for BDU disk-cache helpers and cache-aware get_bdu_ids_by_cves."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[4]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sbom_pipeline.enrichters import bdu


# ---------------------------------------------------------------------------
# Helpers shared across test classes
# ---------------------------------------------------------------------------

def _csrf_response():
    """Minimal fake CSRF-token response."""

    class _Cookies:
        def get(self, key, default=None):
            return {'YII_CSRF_TOKEN': '%22tok%22', 'PHPSESSID': 'sid'}.get(key, default)

    class _Resp:
        cookies = _Cookies()
        text = ''

        def raise_for_status(self):
            pass

    return _Resp()


def _bdu_found_html(bdu_id: str) -> str:
    return f'<div id="vuls"><a class="confirm-vul" href="/vul/x">{bdu_id}</a></div>'


def _bdu_not_found_html() -> str:
    return "<html><div id='vuls'></div></html>"


class _FakeGet:
    """Configurable fake for requests.get.

    *results* maps the search-key (e.g. "2024-0001") to a BDU ID string or
    None (not found).  Any CVE whose key is absent from *results* gets a
    "not found" response.
    """

    def __init__(self, results: dict[str, Optional[str]] | None = None):
        self._results = results or {}
        self.calls: list[dict] = []

    def __call__(self, url, params=None, **kwargs):
        self.calls.append({'url': url, 'params': params})
        if params is None:
            return _csrf_response()
        key = params.get('VulFilterForm[idval]', '')
        bdu_id = self._results.get(key)

        class _Cookies:
            def get(self, k, default=None):
                return {'YII_CSRF_TOKEN': '%22tok%22'}.get(k, default)

        class _Resp:
            def __init__(self, text):
                self.text = text
                self.cookies = _Cookies()

            def raise_for_status(self):
                pass

        if bdu_id:
            return _Resp(_bdu_found_html(bdu_id))
        return _Resp(_bdu_not_found_html())

    @property
    def search_call_count(self) -> int:
        return sum(1 for c in self.calls if c['params'] is not None)


# ===========================================================================
# _load_cache
# ===========================================================================

class TestLoadCache:
    def test_returns_empty_dict_when_dir_missing(self, tmp_path):
        assert bdu._load_cache(tmp_path / 'no_such_dir') == {}

    def test_returns_empty_dict_when_file_missing(self, tmp_path):
        assert bdu._load_cache(tmp_path) == {}

    def test_reads_existing_cache_file(self, tmp_path):
        data = {'CVE-2024-0001': 'BDU:2024-00001', 'CVE-2024-0002': None}
        (tmp_path / bdu._CACHE_FILE_NAME).write_text(json.dumps(data), encoding='utf-8')
        assert bdu._load_cache(tmp_path) == data

    def test_returns_empty_on_corrupt_json(self, tmp_path):
        (tmp_path / bdu._CACHE_FILE_NAME).write_text('{bad json', encoding='utf-8')
        assert bdu._load_cache(tmp_path) == {}

    def test_returns_empty_when_root_is_list(self, tmp_path):
        (tmp_path / bdu._CACHE_FILE_NAME).write_text('[1, 2, 3]', encoding='utf-8')
        assert bdu._load_cache(tmp_path) == {}

    def test_returns_empty_when_root_is_null(self, tmp_path):
        (tmp_path / bdu._CACHE_FILE_NAME).write_text('null', encoding='utf-8')
        assert bdu._load_cache(tmp_path) == {}

    def test_returns_empty_on_empty_file(self, tmp_path):
        (tmp_path / bdu._CACHE_FILE_NAME).write_text('', encoding='utf-8')
        assert bdu._load_cache(tmp_path) == {}

    def test_preserves_null_values(self, tmp_path):
        data = {'CVE-2024-0001': None}
        (tmp_path / bdu._CACHE_FILE_NAME).write_text(json.dumps(data), encoding='utf-8')
        result = bdu._load_cache(tmp_path)
        assert result['CVE-2024-0001'] is None


# ===========================================================================
# _save_cache
# ===========================================================================

class TestSaveCache:
    def test_creates_missing_parent_directories(self, tmp_path):
        cache_dir = tmp_path / 'a' / 'b' / 'c'
        bdu._save_cache(cache_dir, {})
        assert cache_dir.is_dir()

    def test_creates_cache_json_file(self, tmp_path):
        bdu._save_cache(tmp_path, {'CVE-2024-0001': 'BDU:2024-00001'})
        assert (tmp_path / bdu._CACHE_FILE_NAME).exists()

    def test_file_is_valid_json(self, tmp_path):
        data = {'CVE-2024-0001': 'BDU:2024-00001', 'CVE-2024-0002': None}
        bdu._save_cache(tmp_path, data)
        loaded = json.loads((tmp_path / bdu._CACHE_FILE_NAME).read_text(encoding='utf-8'))
        assert loaded == data

    def test_no_tmp_files_left_behind(self, tmp_path):
        bdu._save_cache(tmp_path, {'CVE-2024-0001': 'BDU:2024-00001'})
        assert list(tmp_path.glob('*.tmp')) == []

    def test_subsequent_save_overwrites_previous(self, tmp_path):
        bdu._save_cache(tmp_path, {'CVE-2024-0001': 'BDU:2024-00001'})
        bdu._save_cache(tmp_path, {'CVE-2024-0002': 'BDU:2024-00002'})
        loaded = json.loads((tmp_path / bdu._CACHE_FILE_NAME).read_text(encoding='utf-8'))
        assert 'CVE-2024-0001' not in loaded
        assert loaded['CVE-2024-0002'] == 'BDU:2024-00002'

    def test_keys_are_sorted_in_output(self, tmp_path):
        bdu._save_cache(tmp_path, {'CVE-2024-0003': 'C', 'CVE-2024-0001': 'A', 'CVE-2024-0002': 'B'})
        raw = (tmp_path / bdu._CACHE_FILE_NAME).read_text(encoding='utf-8')
        positions = [raw.index(k) for k in ['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003']]
        assert positions == sorted(positions)

    def test_round_trip_preserves_null_values(self, tmp_path):
        data = {'CVE-2024-0001': 'BDU:2024-00001', 'CVE-2024-0002': None}
        bdu._save_cache(tmp_path, data)
        assert bdu._load_cache(tmp_path) == data


# ===========================================================================
# get_bdu_ids_by_cves — cache behaviour
# ===========================================================================

class TestGetBduIdsCacheIntegration:
    def test_cached_cve_skips_http_entirely(self, tmp_path, monkeypatch):
        """A hit in the on-disk cache must not generate any HTTP request."""
        bdu._save_cache(tmp_path, {'CVE-2024-0001': 'BDU:2024-00001'})

        fake = _FakeGet()
        monkeypatch.setattr(bdu.requests, 'get', fake)

        result = bdu.get_bdu_ids_by_cves(['CVE-2024-0001'], cache_dir=tmp_path)

        assert result == {'CVE-2024-0001': 'BDU:2024-00001'}
        assert len(fake.calls) == 0  # zero HTTP requests

    def test_null_cached_entry_skips_http(self, tmp_path, monkeypatch):
        """A 'not found' entry (None) in cache must also suppress re-fetching."""
        bdu._save_cache(tmp_path, {'CVE-2024-0099': None})

        fake = _FakeGet()
        monkeypatch.setattr(bdu.requests, 'get', fake)

        result = bdu.get_bdu_ids_by_cves(['CVE-2024-0099'], cache_dir=tmp_path)

        assert result == {}
        assert len(fake.calls) == 0

    def test_found_result_written_to_cache(self, tmp_path, monkeypatch):
        """A successful lookup must persist the BDU ID to disk."""
        fake = _FakeGet({'2024-0001': 'BDU:2024-00001'})
        monkeypatch.setattr(bdu.requests, 'get', fake)
        monkeypatch.setattr(bdu.time, 'sleep', lambda _: None)

        bdu.get_bdu_ids_by_cves(['CVE-2024-0001'], cache_dir=tmp_path)

        assert bdu._load_cache(tmp_path).get('CVE-2024-0001') == 'BDU:2024-00001'

    def test_not_found_result_cached_as_null(self, tmp_path, monkeypatch):
        """A CVE with no BDU match must be saved as null so it won't be re-fetched."""
        fake = _FakeGet()  # empty results → not found for everything
        monkeypatch.setattr(bdu.requests, 'get', fake)

        bdu.get_bdu_ids_by_cves(['CVE-2024-0099'], cache_dir=tmp_path)

        cached = bdu._load_cache(tmp_path)
        assert 'CVE-2024-0099' in cached
        assert cached['CVE-2024-0099'] is None

    def test_network_error_not_written_to_cache(self, tmp_path, monkeypatch):
        """CVEs that fail with a network error must NOT be written to the cache."""
        import requests as req_lib

        def failing_get(url, params=None, **kwargs):
            if params is None:
                return _csrf_response()
            raise req_lib.RequestException('timeout')

        monkeypatch.setattr(bdu.requests, 'get', failing_get)

        bdu.get_bdu_ids_by_cves(['CVE-2024-0001'], cache_dir=tmp_path)

        assert 'CVE-2024-0001' not in bdu._load_cache(tmp_path)

    def test_only_uncached_cves_are_fetched(self, tmp_path, monkeypatch):
        """Mixed input: cached CVEs are served from disk; only uncached ones hit the network."""
        bdu._save_cache(tmp_path, {'CVE-2024-0001': 'BDU:2024-00001'})

        fetched: list[str] = []

        def spy_get(url, params=None, **kwargs):
            if params is None:
                return _csrf_response()
            key = params.get('VulFilterForm[idval]', '')
            fetched.append(key)
            return type('R', (), {
                'text': _bdu_not_found_html(),
                'cookies': type('C', (), {'get': lambda self, k, d=None: None})(),
                'raise_for_status': lambda self: None,
            })()

        monkeypatch.setattr(bdu.requests, 'get', spy_get)
        monkeypatch.setattr(bdu.time, 'sleep', lambda _: None)

        result = bdu.get_bdu_ids_by_cves(
            ['CVE-2024-0001', 'CVE-2024-0002'], cache_dir=tmp_path
        )

        assert result == {'CVE-2024-0001': 'BDU:2024-00001'}
        assert fetched == ['2024-0002']  # only the uncached one was queried

    def test_all_cached_no_csrf_call(self, tmp_path, monkeypatch):
        """When all CVEs are cached the CSRF token endpoint is never called."""
        bdu._save_cache(tmp_path, {
            'CVE-2024-0001': 'BDU:2024-00001',
            'CVE-2024-0002': None,
        })

        called = [False]

        def must_not_be_called(*args, **kwargs):
            called[0] = True

        monkeypatch.setattr(bdu.requests, 'get', must_not_be_called)

        result = bdu.get_bdu_ids_by_cves(
            ['CVE-2024-0001', 'CVE-2024-0002'], cache_dir=tmp_path
        )

        assert result == {'CVE-2024-0001': 'BDU:2024-00001'}
        assert not called[0]

    def test_default_cache_dir_used_when_cache_dir_is_none(self, tmp_path, monkeypatch):
        """Passing cache_dir=None falls back to DEFAULT_CACHE_DIR."""
        custom_default = tmp_path / 'default'
        monkeypatch.setattr(bdu, 'DEFAULT_CACHE_DIR', custom_default)

        fake = _FakeGet({'2024-0001': 'BDU:2024-00001'})
        monkeypatch.setattr(bdu.requests, 'get', fake)
        monkeypatch.setattr(bdu.time, 'sleep', lambda _: None)

        bdu.get_bdu_ids_by_cves(['CVE-2024-0001'], cache_dir=None)

        assert (custom_default / bdu._CACHE_FILE_NAME).exists()

    def test_custom_cache_dir_is_used(self, tmp_path, monkeypatch):
        """Providing an explicit cache_dir stores results there, not in DEFAULT_CACHE_DIR."""
        custom_dir = tmp_path / 'my_cache'
        fake = _FakeGet({'2024-0001': 'BDU:2024-00001'})
        monkeypatch.setattr(bdu.requests, 'get', fake)
        monkeypatch.setattr(bdu.time, 'sleep', lambda _: None)

        bdu.get_bdu_ids_by_cves(['CVE-2024-0001'], cache_dir=custom_dir)

        assert (custom_dir / bdu._CACHE_FILE_NAME).exists()
        assert not (bdu.DEFAULT_CACHE_DIR / bdu._CACHE_FILE_NAME).exists()

    def test_second_call_fully_cached_no_requests(self, tmp_path, monkeypatch):
        """A second call with the same CVEs must not produce any HTTP traffic."""
        fake = _FakeGet({'2024-0001': 'BDU:2024-00001'})
        monkeypatch.setattr(bdu.requests, 'get', fake)
        monkeypatch.setattr(bdu.time, 'sleep', lambda _: None)

        # First call populates the cache.
        bdu.get_bdu_ids_by_cves(['CVE-2024-0001'], cache_dir=tmp_path)
        first_call_count = len(fake.calls)

        # Second call must read from cache and make no new HTTP requests.
        bdu.get_bdu_ids_by_cves(['CVE-2024-0001'], cache_dir=tmp_path)

        assert len(fake.calls) == first_call_count  # no new requests
