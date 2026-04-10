from pathlib import Path
import sys

import requests

ROOT = Path(__file__).resolve().parents[4]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sbom_pipeline.enrichters import bdu


class FakeCookies:
    def __init__(self, initial=None):
        self._data = dict(initial or {})

    def get(self, key, default=None):
        return self._data.get(key, default)


class FakeResponse:
    def __init__(self, text="", cookies=None, status_code=200):
        self.text = text
        self.cookies = FakeCookies(cookies)
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


class FakeRequestsGet:
    def __init__(
        self,
        search_results=None,
        failing_cves=None,
        cookie_token='%22query-token%22',
        php_session_id="session-id",
    ):
        self.search_results = dict(search_results or {})
        self.failing_cves = set(failing_cves or set())
        self.cookie_token = cookie_token
        self.php_session_id = php_session_id
        self.calls = []

    def __call__(self, url, params=None, timeout=None, verify=None, headers=None, cookies=None):
        self.calls.append(
            {
                "url": url,
                "params": params,
                "timeout": timeout,
                "verify": verify,
                "headers": headers,
                "cookies": cookies,
            }
        )

        if params is None:
            return FakeResponse(
                cookies={
                    "YII_CSRF_TOKEN": self.cookie_token,
                    "PHPSESSID": self.php_session_id,
                }
            )

        search_value = params["VulFilterForm[idval]"]
        if search_value in self.failing_cves:
            raise requests.RequestException("network error")

        bdu_id = self.search_results.get(search_value)
        if not bdu_id:
            return FakeResponse("<html><body>No results</body></html>")

        html = f"""
        <div id="vuls">
          <table class="table table-striped table-vuls">
              <tr>
                <td class="col-lg-3 col-xs-3">
                  <h4><a class="confirm-vul" href="/vul/mock">{bdu_id}</a></h4>
                </td>
              </tr>
          </table>
        </div>
        """
        return FakeResponse(html)


def test_get_bdu_ids_by_cves_returns_dict_for_found_cves(monkeypatch):
    fake_get = FakeRequestsGet(
        search_results={
            "2024-0001": "BDU:2024-00001",
            "2024-0002": "BDU:2024-00002",
        }
    )
    monkeypatch.setattr(bdu.requests, "get", fake_get)

    result = bdu.get_bdu_ids_by_cves(["CVE-2024-0001", "CVE-2024-0002"])

    assert result == {
        "CVE-2024-0001": "BDU:2024-00001",
        "CVE-2024-0002": "BDU:2024-00002",
    }

    search_calls = [call for call in fake_get.calls if call["params"] is not None]
    assert len(search_calls) == 2
    assert fake_get.calls[0]["params"] is None
    assert fake_get.calls[0]["verify"] is False
    assert fake_get.calls[0]["timeout"] == bdu.REQUEST_TIMEOUT
    assert fake_get.calls[0]["headers"] == bdu.DEFAULT_HEADERS
    assert fake_get.calls[0]["cookies"] is None
    assert search_calls[0]["params"]["YII_CSRF_TOKEN"] == "query-token"
    assert search_calls[0]["params"]["VulFilterForm[idval]"] == "2024-0001"
    assert search_calls[1]["params"]["VulFilterForm[idval]"] == "2024-0002"
    assert search_calls[0]["verify"] is False
    assert search_calls[1]["verify"] is False
    assert search_calls[0]["timeout"] == bdu.REQUEST_TIMEOUT
    assert search_calls[1]["timeout"] == bdu.REQUEST_TIMEOUT
    assert search_calls[0]["cookies"] == {
        "YII_CSRF_TOKEN": "%22query-token%22",
        "PHPSESSID": "session-id",
    }


def test_get_bdu_ids_by_cves_skips_not_found_and_failed_requests(monkeypatch):
    fake_get = FakeRequestsGet(
        search_results={"2024-0001": "BDU:2024-00001"},
        failing_cves={"2024-0003"},
    )
    monkeypatch.setattr(bdu.requests, "get", fake_get)

    result = bdu.get_bdu_ids_by_cves(
        ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
    )

    assert result == {
        "CVE-2024-0001": "BDU:2024-00001",
    }


def test_get_bdu_ids_by_cves_returns_empty_dict_for_empty_input():
    assert bdu.get_bdu_ids_by_cves([]) == {}
    assert bdu.get_bdu_ids_by_cves(["", "   "]) == {}


def test_extract_query_token_decodes_cookie_value():
    assert bdu._extract_query_token("%22query-token%22") == "query-token"


def test_outgoing_token_param_is_urlencoded(monkeypatch):
    fake_get = FakeRequestsGet(search_results={"2024-0001": "BDU:2024-00001"})
    monkeypatch.setattr(bdu.requests, "get", fake_get)
    token = "MXFNX3JSMDVhVHB1aG5GdH5abGtzSXB6UHN3Z3FDaEfoi3zMNAVr3f4467gBT3vvq7kwsHY_WHa5kSFgcIupqg=="
    monkeypatch.setattr(
        bdu,
        "_get_csrf_tokens",
        lambda: ({"YII_CSRF_TOKEN": token, "PHPSESSID": "session-id"}, token),
    )

    bdu.get_bdu_ids_by_cves(["CVE-2024-0001"])

    search_call = next(call for call in fake_get.calls if call["params"] is not None)
    assert (
        search_call["params"]["YII_CSRF_TOKEN"]
        == "MXFNX3JSMDVhVHB1aG5GdH5abGtzSXB6UHN3Z3FDaEfoi3zMNAVr3f4467gBT3vvq7kwsHY_WHa5kSFgcIupqg%3D%3D"
    )


def test_get_csrf_tokens_returns_cookie_and_query_token(monkeypatch):
    fake_get = FakeRequestsGet(cookie_token="%22csrf-query-token%22")
    monkeypatch.setattr(bdu.requests, "get", fake_get)

    cookie_jar, query_token = bdu._get_csrf_tokens()

    assert cookie_jar == {
        "YII_CSRF_TOKEN": "%22csrf-query-token%22",
        "PHPSESSID": "session-id",
    }
    assert query_token == "csrf-query-token"
    assert fake_get.calls[0]["params"] is None
    assert fake_get.calls[0]["verify"] is False
    assert fake_get.calls[0]["timeout"] == bdu.REQUEST_TIMEOUT
    assert fake_get.calls[0]["headers"] == bdu.DEFAULT_HEADERS
    assert fake_get.calls[0]["cookies"] is None


def test_to_bdu_search_value_strips_cve_prefix():
    assert bdu._to_bdu_search_value("CVE-2026-24017") == "2026-24017"
    assert bdu._to_bdu_search_value("cve-2026-24017") == "2026-24017"
    assert bdu._to_bdu_search_value("2026-24017") == "2026-24017"


def test_extract_bdu_id_returns_none_when_selector_missing():
    html = "<html><body><div id='vuls'></div></body></html>"
    assert bdu._extract_bdu_id(html) is None


def test_extract_bdu_id_returns_none_for_multiple_matches():
        html = """
        <div id="vuls">
            <table class="table table-striped table-vuls">
                <tr>
                    <td class="col-lg-3 col-xs-3">
                        <h4><a class="confirm-vul" href="/vul/one">BDU:2026-00001</a></h4>
                    </td>
                </tr>
                <tr>
                    <td class="col-lg-3 col-xs-3">
                        <h4><a class="confirm-vul" href="/vul/two">BDU:2026-00002</a></h4>
                    </td>
                </tr>
            </table>
        </div>
        """

        assert bdu._extract_bdu_id(html) is None


def test_extract_bdu_id_from_real_html_fixture():
    html_path = Path(__file__).with_name("html.html")
    html = html_path.read_text(encoding="utf-8")

    assert bdu._extract_bdu_id(html) == "BDU:2026-03213"


def test_extract_bdu_id_returns_none_for_real_notfound_fixture():
    html_path = Path(__file__).with_name("html_notfound.html")
    html = html_path.read_text(encoding="utf-8")

    assert bdu._extract_bdu_id(html) is None


def test_get_bdu_ids_by_cves_skips_non_cve_strings(monkeypatch):
    fake_get = FakeRequestsGet(search_results={"2024-0001": "BDU:2024-00001"})
    monkeypatch.setattr(bdu.requests, "get", fake_get)

    result = bdu.get_bdu_ids_by_cves(
        ["CVE-2024-0001", "GHSA-1234-5678-9012", "not-a-cve", "BDU:2024-00001"]
    )

    # Only the valid CVE entry should be processed and returned
    assert result == {"CVE-2024-0001": "BDU:2024-00001"}
    # Non-CVE inputs must not trigger any search requests to BDU
    search_calls = [c for c in fake_get.calls if c["params"] is not None]
    assert len(search_calls) == 1


def test_get_bdu_ids_by_cves_returns_empty_dict_if_all_inputs_are_non_cve(monkeypatch):
    fake_get = FakeRequestsGet()
    monkeypatch.setattr(bdu.requests, "get", fake_get)

    result = bdu.get_bdu_ids_by_cves(["GHSA-1234-5678-9012", "not-a-cve"])

    assert result == {}
    # No network requests should be made at all
    assert fake_get.calls == []


def test_get_bdu_ids_by_cves_returns_empty_dict_when_csrf_fetch_fails(monkeypatch):
    def raises(*args, **kwargs):
        raise requests.ConnectionError("connection refused")

    monkeypatch.setattr(bdu.requests, "get", raises)

    result = bdu.get_bdu_ids_by_cves(["CVE-2024-0001"])

    assert result == {}


def test_get_bdu_ids_by_cves_returns_empty_dict_when_csrf_token_missing(monkeypatch):
    monkeypatch.setattr(
        bdu,
        "_get_csrf_tokens",
        lambda: (_ for _ in ()).throw(RuntimeError("Не найден cookie YII_CSRF_TOKEN")),
    )

    result = bdu.get_bdu_ids_by_cves(["CVE-2024-0001"])

    assert result == {}


def test_rate_limit_sleep_called_between_requests(monkeypatch):
    fake_get = FakeRequestsGet(
        search_results={
            "2024-0001": "BDU:2024-00001",
            "2024-0002": "BDU:2024-00002",
            "2024-0003": "BDU:2024-00003",
        }
    )
    monkeypatch.setattr(bdu.requests, "get", fake_get)

    sleep_calls: list[float] = []
    monkeypatch.setattr(bdu.time, "sleep", lambda s: sleep_calls.append(s))

    bdu.get_bdu_ids_by_cves(["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"])

    # N CVEs → N-1 sleeps, each equal to RATE_LIMIT_DELAY
    assert len(sleep_calls) == 2
    assert all(s == bdu.RATE_LIMIT_DELAY for s in sleep_calls)


def test_rate_limit_sleep_not_called_for_single_cve(monkeypatch):
    fake_get = FakeRequestsGet(search_results={"2024-0001": "BDU:2024-00001"})
    monkeypatch.setattr(bdu.requests, "get", fake_get)

    sleep_calls: list[float] = []
    monkeypatch.setattr(bdu.time, "sleep", lambda s: sleep_calls.append(s))

    bdu.get_bdu_ids_by_cves(["CVE-2024-0001"])

    assert sleep_calls == []


def test_rate_limit_sleep_not_called_when_no_valid_cves(monkeypatch):
    sleep_calls: list[float] = []
    monkeypatch.setattr(bdu.time, "sleep", lambda s: sleep_calls.append(s))

    bdu.get_bdu_ids_by_cves(["not-a-cve", "GHSA-1234-5678-9012"])

    assert sleep_calls == []