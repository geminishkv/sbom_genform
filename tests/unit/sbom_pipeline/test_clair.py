"""Unit tests for sbom_pipeline.scanner.clair (no network, no Docker)."""

from __future__ import annotations

import io
import json
import tempfile
import urllib.error
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from sbom_pipeline.scanner.clair import (
    _apply_cvss_enrichments,
    _build_component_from_clair,
    _build_cvss_index,
    _clair_server_alive,
    _fetch_cvss_from_nvd,
    _fetch_enrichments_from_clair_api,
    _fetch_vuln_report,
    _get_index_state,
    _parse,
    _pick_score_from_flat,
    _pick_score_from_item,
    _read_manifest_hash,
    _submit_manifest,
    _vendor_sev_to_acceptability,
)
from sbom_pipeline.vuln_merger import VulnFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_report(tmp: Path, data: Dict[str, Any]) -> Path:
    p = tmp / "report.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _minimal_report(
    manifest_hash: str = "sha256:aabbcc",
    packages: dict | None = None,
    vulnerabilities: dict | None = None,
    package_vulnerabilities: dict | None = None,
) -> Dict[str, Any]:
    return {
        "manifest_hash": manifest_hash,
        "packages": packages or {},
        "distributions": {},
        "environments": {},
        "vulnerabilities": vulnerabilities or {},
        "package_vulnerabilities": package_vulnerabilities or {},
        "enrichments": {},
    }


def _make_finding(cve: str = "CVE-2024-0001", score: float = 0.0) -> VulnFinding:
    return VulnFinding(
        cve_id=cve,
        component_name="libfoo",
        component_version="1.0",
        component_purl="",
        cvss_score=score,
        severity="HIGH",
        description="desc",
        scanner="clair",
    )


# ===========================================================================
# _vendor_sev_to_acceptability
# ===========================================================================

class TestVendorSevToAcceptability:
    def test_unimportant_maps_to_neprimenimo(self):
        assert _vendor_sev_to_acceptability("unimportant") == "Неприменимо"

    def test_unimportant_case_insensitive(self):
        assert _vendor_sev_to_acceptability("Unimportant") == "Неприменимо"
        assert _vendor_sev_to_acceptability("UNIMPORTANT") == "Неприменимо"

    def test_other_values_return_empty(self):
        for v in ("", "not yet assigned", "low", "high", "medium", "critical"):
            assert _vendor_sev_to_acceptability(v) == ""

    def test_none_like_empty_string(self):
        assert _vendor_sev_to_acceptability("") == ""


# ===========================================================================
# _pick_score_from_item
# ===========================================================================

class TestPickScoreFromItem:
    def test_format_a_v3_wins_over_v2(self):
        item = {"v3": {"baseScore": 9.8}, "v2": {"baseScore": 6.5}}
        assert _pick_score_from_item(item) == 9.8

    def test_format_a_v3_only(self):
        item = {"v3": {"baseScore": 7.5}}
        assert _pick_score_from_item(item) == 7.5

    def test_format_a_v2_only(self):
        item = {"v2": {"baseScore": 5.0}}
        assert _pick_score_from_item(item) == 5.0

    def test_format_a_v3_score_key(self):
        item = {"v3": {"score": 8.1}}
        assert _pick_score_from_item(item) == 8.1

    def test_format_b_v3score(self):
        item = {"cvss": {"v3Score": 8.1, "v2Score": 6.0}}
        assert _pick_score_from_item(item) == 8.1

    def test_format_b_v3basescore(self):
        item = {"cvss": {"v3BaseScore": 7.2}}
        assert _pick_score_from_item(item) == 7.2

    def test_format_b_basescore(self):
        item = {"cvss": {"baseScore": 6.3}}
        assert _pick_score_from_item(item) == 6.3

    def test_direct_basescore_field(self):
        item = {"baseScore": 5.5}
        assert _pick_score_from_item(item) == 5.5

    def test_empty_dict_returns_zero(self):
        assert _pick_score_from_item({}) == 0.0

    def test_non_dict_returns_zero(self):
        assert _pick_score_from_item(None) == 0.0  # type: ignore[arg-type]
        assert _pick_score_from_item("string") == 0.0  # type: ignore[arg-type]

    def test_best_score_chosen_across_all_keys(self):
        item = {
            "v2": {"baseScore": 5.0},
            "cvss": {"v3Score": 8.0},
            "baseScore": 3.0,
        }
        assert _pick_score_from_item(item) == 8.0


# ===========================================================================
# _pick_score_from_flat
# ===========================================================================

class TestPickScoreFromFlat:
    def test_cvssv3basescore(self):
        assert _pick_score_from_flat({"cvssv3BaseScore": 7.2}) == 7.2

    def test_camel_case_variant(self):
        assert _pick_score_from_flat({"cvssV3BaseScore": 9.0}) == 9.0

    def test_v2_fallback(self):
        assert _pick_score_from_flat({"cvssv2BaseScore": 5.5}) == 5.5

    def test_basescore_fallback(self):
        assert _pick_score_from_flat({"baseScore": 4.3}) == 4.3

    def test_max_chosen(self):
        data = {"cvssv3BaseScore": 7.5, "cvssv2BaseScore": 5.0}
        assert _pick_score_from_flat(data) == 7.5

    def test_empty_returns_zero(self):
        assert _pick_score_from_flat({}) == 0.0

    def test_non_numeric_skipped(self):
        assert _pick_score_from_flat({"baseScore": "N/A"}) == 0.0


# ===========================================================================
# _build_cvss_index
# ===========================================================================

class TestBuildCvssIndex:
    def test_empty_enrichments(self):
        assert _build_cvss_index({}) == {}

    # ---- Format A ----

    def test_format_a_basic(self):
        enrichments = {
            "org.quay.clair/enricher/cvss/v1": [
                {"vuln": "CVE-2023-1234", "data": [{"v3": {"baseScore": 9.8}}]},
            ]
        }
        idx = _build_cvss_index(enrichments)
        assert idx == {"CVE-2023-1234": 9.8}

    def test_format_a_multiple_entries(self):
        enrichments = {
            "org.quay.clair/enricher/cvss/v1": [
                {"vuln": "CVE-2023-0001", "data": [{"v3": {"baseScore": 9.8}}]},
                {"vuln": "CVE-2023-0002", "data": [{"v3": {"baseScore": 4.0}}]},
            ]
        }
        idx = _build_cvss_index(enrichments)
        assert idx["CVE-2023-0001"] == 9.8
        assert idx["CVE-2023-0002"] == 4.0

    def test_format_a_multiple_data_items_best_wins(self):
        enrichments = {
            "org.quay.clair/enricher/cvss/v1": [
                {
                    "vuln": "CVE-2023-9999",
                    "data": [
                        {"v2": {"baseScore": 5.0}},
                        {"v3": {"baseScore": 8.5}},
                    ],
                }
            ]
        }
        idx = _build_cvss_index(enrichments)
        assert idx["CVE-2023-9999"] == 8.5

    # ---- Format B ----

    def test_format_b_nvd_list(self):
        enrichments = {
            "nvd": [
                {"vuln": "CVE-2024-0001", "data": [{"cvss": {"v3Score": 8.1, "v2Score": 6.0}}]},
            ]
        }
        idx = _build_cvss_index(enrichments)
        assert idx["CVE-2024-0001"] == 8.1

    def test_format_b_v2_only_when_no_v3(self):
        enrichments = {
            "nvd": [
                {"vuln": "CVE-2024-0002", "data": [{"cvss": {"v2Score": 6.0}}]},
            ]
        }
        idx = _build_cvss_index(enrichments)
        assert idx["CVE-2024-0002"] == 6.0

    # ---- Format C ----

    def test_format_c_flat_dict(self):
        enrichments = {
            "nvd": {"CVE-2023-5555": {"cvssv3BaseScore": 7.2, "cvssv2BaseScore": 5.5}}
        }
        idx = _build_cvss_index(enrichments)
        assert idx["CVE-2023-5555"] == 7.2

    def test_format_c_camel_case(self):
        enrichments = {
            "nvd": {"CVE-2023-6666": {"cvssV3BaseScore": 9.0}}
        }
        idx = _build_cvss_index(enrichments)
        assert idx["CVE-2023-6666"] == 9.0

    # ---- Edge cases ----

    def test_record_missing_vuln_key_skipped(self):
        enrichments = {
            "nvd": [{"data": [{"v3": {"baseScore": 7.0}}]}]  # no "vuln" key
        }
        assert _build_cvss_index(enrichments) == {}

    def test_first_enricher_for_same_cve_wins(self):
        enrichments = {
            "enricher_a": [
                {"vuln": "CVE-2024-0001", "data": [{"v3": {"baseScore": 9.0}}]},
            ],
            "enricher_b": [
                {"vuln": "CVE-2024-0001", "data": [{"v3": {"baseScore": 5.0}}]},
            ],
        }
        idx = _build_cvss_index(enrichments)
        assert idx["CVE-2024-0001"] == 9.0

    def test_unknown_enricher_key_still_parsed(self):
        enrichments = {
            "some/custom/enricher": [
                {"vuln": "CVE-2025-0001", "data": [{"v3": {"baseScore": 6.0}}]},
            ]
        }
        idx = _build_cvss_index(enrichments)
        assert idx["CVE-2025-0001"] == 6.0


# ===========================================================================
# _apply_cvss_enrichments
# ===========================================================================

class TestApplyCvssEnrichments:
    def test_fills_zero_score(self):
        findings = [_make_finding("CVE-2024-0001", score=0.0)]
        enrichments = {
            "nvd": [{"vuln": "CVE-2024-0001", "data": [{"cvss": {"v3Score": 8.5}}]}]
        }
        _apply_cvss_enrichments(findings, enrichments)
        assert findings[0].cvss_score == 8.5

    def test_does_not_overwrite_existing_score(self):
        findings = [_make_finding("CVE-2024-0001", score=7.0)]
        enrichments = {
            "nvd": [{"vuln": "CVE-2024-0001", "data": [{"cvss": {"v3Score": 9.9}}]}]
        }
        _apply_cvss_enrichments(findings, enrichments)
        assert findings[0].cvss_score == 7.0

    def test_empty_enrichments_leaves_scores_unchanged(self):
        findings = [_make_finding("CVE-2024-0001", score=0.0)]
        _apply_cvss_enrichments(findings, {})
        assert findings[0].cvss_score == 0.0

    def test_unmatched_cve_leaves_score_zero(self):
        findings = [_make_finding("CVE-2024-9999", score=0.0)]
        enrichments = {
            "nvd": [{"vuln": "CVE-2024-0001", "data": [{"cvss": {"v3Score": 8.5}}]}]
        }
        _apply_cvss_enrichments(findings, enrichments)
        assert findings[0].cvss_score == 0.0

    def test_multiple_findings_enriched_selectively(self):
        findings = [
            _make_finding("CVE-2024-0001", score=0.0),
            _make_finding("CVE-2024-0002", score=0.0),
            _make_finding("CVE-2024-0003", score=5.0),  # already set
        ]
        enrichments = {
            "nvd": [
                {"vuln": "CVE-2024-0001", "data": [{"cvss": {"v3Score": 9.0}}]},
                {"vuln": "CVE-2024-0002", "data": [{"cvss": {"v3Score": 7.0}}]},
                {"vuln": "CVE-2024-0003", "data": [{"cvss": {"v3Score": 8.0}}]},
            ]
        }
        _apply_cvss_enrichments(findings, enrichments)
        assert findings[0].cvss_score == 9.0
        assert findings[1].cvss_score == 7.0
        assert findings[2].cvss_score == 5.0   # unchanged


# ===========================================================================
# _read_manifest_hash
# ===========================================================================

class TestReadManifestHash:
    def test_reads_hash_from_valid_file(self, tmp_path):
        p = tmp_path / "report.json"
        p.write_text(json.dumps({"manifest_hash": "sha256:deadbeef"}))
        assert _read_manifest_hash(p) == "sha256:deadbeef"

    def test_returns_none_on_missing_file(self, tmp_path):
        assert _read_manifest_hash(tmp_path / "nonexistent.json") is None

    def test_returns_none_on_invalid_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json")
        assert _read_manifest_hash(p) is None

    def test_returns_empty_string_when_key_absent(self, tmp_path):
        p = tmp_path / "report.json"
        p.write_text(json.dumps({"other": "data"}))
        assert _read_manifest_hash(p) == ""


# ===========================================================================
# _fetch_cvss_from_nvd
# ===========================================================================

class TestFetchCvssFromNvd:
    def _nvd_resp(self, cve_id: str, score_v31: float | None = None, score_v2: float | None = None) -> MagicMock:
        metrics: dict = {}
        if score_v31 is not None:
            metrics["cvssMetricV31"] = [{"cvssData": {"baseScore": score_v31}}]
        if score_v2 is not None:
            metrics["cvssMetricV2"] = [{"cvssData": {"baseScore": score_v2}}]
        body = {"vulnerabilities": [{"cve": {"id": cve_id, "metrics": metrics}}]}
        raw = json.dumps(body).encode()
        resp = MagicMock()
        resp.status = 200
        resp.read.return_value = raw
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_returns_v31_score(self):
        resp = self._nvd_resp("CVE-2024-0001", score_v31=9.8)
        with patch("urllib.request.urlopen", return_value=resp):
            with patch("time.sleep"):
                result = _fetch_cvss_from_nvd(["CVE-2024-0001"])
        assert result == {"CVE-2024-0001": 9.8}

    def test_falls_back_to_v2_when_no_v31(self):
        resp = self._nvd_resp("CVE-2024-0002", score_v2=6.5)
        with patch("urllib.request.urlopen", return_value=resp):
            with patch("time.sleep"):
                result = _fetch_cvss_from_nvd(["CVE-2024-0002"])
        assert result == {"CVE-2024-0002": 6.5}

    def test_empty_input_returns_empty(self):
        result = _fetch_cvss_from_nvd([])
        assert result == {}

    def test_no_vulnerabilities_in_response_skipped(self):
        body = {"vulnerabilities": []}
        raw = json.dumps(body).encode()
        resp = MagicMock()
        resp.status = 200
        resp.read.return_value = raw
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=resp):
            with patch("time.sleep"):
                result = _fetch_cvss_from_nvd(["CVE-2024-9999"])
        assert result == {}

    def test_network_error_skipped_continues(self):
        responses = [OSError("timeout"), self._nvd_resp("CVE-2024-0002", score_v31=7.0)]
        with patch("urllib.request.urlopen", side_effect=responses):
            with patch("time.sleep"):
                result = _fetch_cvss_from_nvd(["CVE-2024-0001", "CVE-2024-0002"])
        assert "CVE-2024-0001" not in result
        assert result.get("CVE-2024-0002") == 7.0

    def test_api_key_included_in_header(self):
        resp = self._nvd_resp("CVE-2024-0001", score_v31=5.0)
        with patch("urllib.request.urlopen", return_value=resp) as mock_open:
            with patch("time.sleep"):
                _fetch_cvss_from_nvd(["CVE-2024-0001"], api_key="my-key")
        req = mock_open.call_args[0][0]
        assert req.get_header("Apikey") == "my-key"

    def test_non_200_status_skipped(self):
        resp = MagicMock()
        resp.status = 404
        resp.read.return_value = b"{}"
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=resp):
            with patch("time.sleep"):
                result = _fetch_cvss_from_nvd(["CVE-2024-0001"])
        assert result == {}


# ===========================================================================
# _fetch_enrichments_from_clair_api
# ===========================================================================

class TestFetchEnrichments:
    def _mock_response(self, body: dict, status: int = 200) -> MagicMock:
        raw = json.dumps(body).encode()
        resp = MagicMock()
        resp.status = status
        resp.read.return_value = raw
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_returns_enrichments_on_200(self):
        enrichments = {"nvd": [{"vuln": "CVE-2024-0001", "data": []}]}
        resp = self._mock_response({"enrichments": enrichments})
        with patch("urllib.request.urlopen", return_value=resp):
            result = _fetch_enrichments_from_clair_api(
                "http://clair:8080", "sha256:abc123"
            )
        assert result == enrichments

    def test_returns_empty_dict_when_enrichments_key_missing(self):
        resp = self._mock_response({"other": "data"})
        with patch("urllib.request.urlopen", return_value=resp):
            result = _fetch_enrichments_from_clair_api(
                "http://clair:8080", "sha256:abc123"
            )
        assert result == {}

    def test_returns_none_on_non_200(self):
        resp = self._mock_response({}, status=404)
        with patch("urllib.request.urlopen", return_value=resp):
            result = _fetch_enrichments_from_clair_api(
                "http://clair:8080", "sha256:abc123"
            )
        assert result is None

    def test_returns_none_on_connection_error(self):
        with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
            result = _fetch_enrichments_from_clair_api(
                "http://clair:8080", "sha256:abc123"
            )
        assert result is None

    def test_url_is_constructed_correctly(self):
        resp = self._mock_response({"enrichments": {}})
        with patch("urllib.request.urlopen", return_value=resp) as mock_open:
            _fetch_enrichments_from_clair_api(
                "http://clair:8080", "sha256:deadbeef"
            )
        called_req = mock_open.call_args[0][0]
        assert called_req.full_url == (
            "http://clair:8080/matcher/api/v1/vulnerability_report/sha256:deadbeef"
        )
        assert called_req.get_header("Accept") == "application/json"


# ===========================================================================
# _clair_server_alive
# ===========================================================================

class TestClairServerAlive:
    def _resp(self, status: int) -> MagicMock:
        r = MagicMock()
        r.status = status
        r.__enter__ = lambda s: s
        r.__exit__ = MagicMock(return_value=False)
        return r

    def test_returns_true_on_200(self):
        with patch("urllib.request.urlopen", return_value=self._resp(200)):
            assert _clair_server_alive("http://clair:8080") is True

    def test_returns_false_on_500(self):
        err = urllib.error.HTTPError("url", 500, "err", {}, None)  # type: ignore[arg-type]
        with patch("urllib.request.urlopen", side_effect=err):
            assert _clair_server_alive("http://clair:8080") is False

    def test_returns_true_on_4xx_http_error(self):
        err = urllib.error.HTTPError("url", 404, "Not Found", {}, None)  # type: ignore[arg-type]
        with patch("urllib.request.urlopen", side_effect=err):
            assert _clair_server_alive("http://clair:8080") is True

    def test_returns_false_on_connection_error(self):
        with patch("urllib.request.urlopen", side_effect=OSError("refused")):
            assert _clair_server_alive("http://clair:8080") is False


# ===========================================================================
# _parse
# ===========================================================================

class TestParse:
    # ---- missing / invalid file ----

    def test_missing_file_returns_empty(self, tmp_path):
        assert _parse(tmp_path / "nonexistent.json") == []

    def test_invalid_json_returns_empty(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json")
        assert _parse(p) == []

    # ---- empty report ----

    def test_empty_vulnerabilities_returns_empty(self, tmp_path):
        p = _write_report(tmp_path, _minimal_report())
        assert _parse(p) == []

    # ---- package_vulnerabilities path (primary) ----

    def test_resolves_binary_package_name_and_version(self, tmp_path):
        report = _minimal_report(
            packages={
                "10": {"id": "10", "name": "libssl3", "version": "3.5.5-1", "kind": "binary"},
            },
            vulnerabilities={
                "v1": {
                    "id": "v1",
                    "name": "CVE-2024-0001",
                    "description": "desc",
                    "severity": "low",
                    "normalized_severity": "Low",
                    "links": "https://tracker/CVE-2024-0001",
                    "fixed_in_version": "",
                    "package": {"name": "openssl", "version": ""},
                }
            },
            package_vulnerabilities={"10": ["v1"]},
        )
        findings = _parse(_write_report(tmp_path, report))
        assert len(findings) == 1
        f = findings[0]
        assert f.cve_id == "CVE-2024-0001"
        assert f.component_name == "libssl3"
        assert f.component_version == "3.5.5-1"
        assert f.scanner == "clair"

    def test_fixed_version_populated(self, tmp_path):
        report = _minimal_report(
            packages={"1": {"id": "1", "name": "libssl3", "version": "3.5.5-1", "kind": "binary"}},
            vulnerabilities={
                "v1": {
                    "name": "CVE-2024-1111",
                    "description": "",
                    "severity": "not yet assigned",
                    "normalized_severity": "Unknown",
                    "links": "",
                    "fixed_in_version": "3.5.5-2",
                    "package": {},
                }
            },
            package_vulnerabilities={"1": ["v1"]},
        )
        f = _parse(_write_report(tmp_path, report))[0]
        assert f.fixed_version == "3.5.5-2"

    def test_unimportant_maps_to_acceptability(self, tmp_path):
        report = _minimal_report(
            packages={"1": {"id": "1", "name": "bash", "version": "5.2.37", "kind": "binary"}},
            vulnerabilities={
                "v1": {
                    "name": "CVE-2022-1111",
                    "description": "",
                    "severity": "unimportant",
                    "normalized_severity": "Low",
                    "links": "",
                    "fixed_in_version": "",
                    "package": {},
                }
            },
            package_vulnerabilities={"1": ["v1"]},
        )
        f = _parse(_write_report(tmp_path, report))[0]
        assert f.acceptability_status == "Неприменимо"

    def test_non_unimportant_acceptability_empty(self, tmp_path):
        report = _minimal_report(
            packages={"1": {"id": "1", "name": "curl", "version": "7.88.0", "kind": "binary"}},
            vulnerabilities={
                "v1": {
                    "name": "CVE-2024-2222",
                    "description": "",
                    "severity": "high",
                    "normalized_severity": "High",
                    "links": "",
                    "fixed_in_version": "",
                    "package": {},
                }
            },
            package_vulnerabilities={"1": ["v1"]},
        )
        f = _parse(_write_report(tmp_path, report))[0]
        assert f.acceptability_status == ""

    def test_recommendation_carries_links_field(self, tmp_path):
        report = _minimal_report(
            packages={"1": {"id": "1", "name": "curl", "version": "7.88.0", "kind": "binary"}},
            vulnerabilities={
                "v1": {
                    "name": "CVE-2024-3333",
                    "description": "",
                    "severity": "medium",
                    "normalized_severity": "Medium",
                    "links": "https://tracker/CVE-2024-3333",
                    "fixed_in_version": "",
                    "package": {},
                }
            },
            package_vulnerabilities={"1": ["v1"]},
        )
        f = _parse(_write_report(tmp_path, report))[0]
        assert f.recommendation == "https://tracker/CVE-2024-3333"

    def test_severity_normalized_integer_mapping(self, tmp_path):
        sev_map = {
            "0": "UNKNOWN",  # numeric 0 stays UNKNOWN; string "Unknown" → "NOT_STATED"
            "1": "LOW",
            "2": "LOW",
            "3": "MEDIUM",
            "4": "HIGH",
            "5": "CRITICAL",
        }
        for raw, expected in sev_map.items():
            sub = tmp_path / f"sev_{raw}"
            sub.mkdir(parents=True, exist_ok=True)
            report = _minimal_report(
                packages={"1": {"id": "1", "name": "pkg", "version": "1.0", "kind": "binary"}},
                vulnerabilities={
                    "v1": {
                        "name": f"CVE-2024-{raw}",
                        "description": "",
                        "severity": "low",
                        "normalized_severity": raw,
                        "links": "",
                        "fixed_in_version": "",
                        "package": {},
                    }
                },
                package_vulnerabilities={"1": ["v1"]},
            )
            findings = _parse(_write_report(sub, report))
            assert findings[0].severity == expected, f"raw={raw}"

    def test_missing_vuln_id_in_package_vulnerabilities_skipped(self, tmp_path):
        report = _minimal_report(
            packages={"1": {"id": "1", "name": "curl", "version": "7.88.0", "kind": "binary"}},
            vulnerabilities={},  # no vulnerability data
            package_vulnerabilities={"1": ["v_missing"]},
        )
        assert _parse(_write_report(tmp_path, report)) == []

    def test_multiple_packages_multiple_vulns(self, tmp_path):
        report = _minimal_report(
            packages={
                "1": {"id": "1", "name": "pkgA", "version": "1.0", "kind": "binary"},
                "2": {"id": "2", "name": "pkgB", "version": "2.0", "kind": "binary"},
            },
            vulnerabilities={
                "v1": {
                    "name": "CVE-2024-0001",
                    "description": "",
                    "severity": "high",
                    "normalized_severity": "High",
                    "links": "",
                    "fixed_in_version": "",
                    "package": {},
                },
                "v2": {
                    "name": "CVE-2024-0002",
                    "description": "",
                    "severity": "medium",
                    "normalized_severity": "Medium",
                    "links": "",
                    "fixed_in_version": "",
                    "package": {},
                },
            },
            package_vulnerabilities={"1": ["v1", "v2"], "2": ["v1"]},
        )
        findings = _parse(_write_report(tmp_path, report))
        assert len(findings) == 3
        names = {(f.component_name, f.cve_id) for f in findings}
        assert ("pkgA", "CVE-2024-0001") in names
        assert ("pkgA", "CVE-2024-0002") in names
        assert ("pkgB", "CVE-2024-0001") in names

    # ---- fallback path (no package_vulnerabilities) ----

    def test_fallback_path_uses_vuln_package_field(self, tmp_path):
        report = _minimal_report(
            packages={},
            vulnerabilities={
                "v1": {
                    "name": "CVE-2024-0099",
                    "description": "fallback path",
                    "severity": "low",
                    "normalized_severity": "Low",
                    "links": "",
                    "fixed_in_version": "",
                    "package": {"name": "openssl", "version": "3.0.0"},
                }
            },
            package_vulnerabilities={},  # empty → triggers fallback
        )
        findings = _parse(_write_report(tmp_path, report))
        assert len(findings) == 1
        f = findings[0]
        assert f.cve_id == "CVE-2024-0099"
        assert f.component_name == "openssl"
        assert f.component_version == "3.0.0"

    # ---- real fixture files ----

    @pytest.mark.parametrize("fixture_name", [
        "clair-postgres_14.json",
        "clair-postgres_15-alpine.json",
    ])
    def test_real_fixture_parsed_successfully(self, fixture_name):
        fixture = (
            Path(__file__).parent.parent.parent.parent
            / "secgensbom_out" / "clair" / fixture_name
        )
        if not fixture.exists():
            pytest.skip(f"fixture not found: {fixture}")

        findings = _parse(fixture)
        # The alpine fixture has no vulnerabilities in this snapshot — that is
        # valid.  We only assert schema correctness for those that do exist.
        for f in findings:
            assert f.component_name, f"component_name is empty for {f.cve_id}"
            assert f.component_version, f"component_version is empty for {f.cve_id}"
            assert f.scanner == "clair"
            assert f.severity in {"UNKNOWN", "NOT_STATED", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_real_fixture_postgres14_accepts_unimportant(self):
        fixture = (
            Path(__file__).parent.parent.parent.parent
            / "secgensbom_out" / "clair" / "clair-postgres_14.json"
        )
        if not fixture.exists():
            pytest.skip("fixture not found")

        findings = _parse(fixture)
        accept_filled = [f for f in findings if f.acceptability_status]
        assert len(accept_filled) > 0, (
            "Expected 'unimportant' vulns to produce non-empty acceptability_status"
        )

    def test_real_fixture_postgres14_fixed_versions_present(self):
        fixture = (
            Path(__file__).parent.parent.parent.parent
            / "secgensbom_out" / "clair" / "clair-postgres_14.json"
        )
        if not fixture.exists():
            pytest.skip("fixture not found")

        findings = _parse(fixture)
        fixed = [f for f in findings if f.fixed_version]
        assert len(fixed) > 0, "Expected at least one finding with a fixed_version"
        # Spot-check: one of the known fixed openssl CVEs
        known = {f.cve_id for f in fixed}
        assert any("openssl" in f.component_name.lower() or "ssl" in f.component_name.lower()
                   for f in fixed), "Expected at least one SSL package with a fix"


# ---------------------------------------------------------------------------
# _set_prop
# ---------------------------------------------------------------------------

class TestSetProp:
    def _import(self):
        from sbom_pipeline.scanner.clair import _set_prop
        return _set_prop

    def test_appends_new_property(self):
        _set_prop = self._import()
        props: list = []
        _set_prop(props, "container_image", "myimage:1.0")
        assert props == [{"name": "container_image", "value": "myimage:1.0"}]

    def test_updates_existing_property(self):
        _set_prop = self._import()
        props = [{"name": "container_image", "value": "old"}]
        _set_prop(props, "container_image", "new")
        assert len(props) == 1
        assert props[0]["value"] == "new"

    def test_does_not_duplicate(self):
        _set_prop = self._import()
        props: list = []
        _set_prop(props, "k", "v1")
        _set_prop(props, "k", "v2")
        assert len(props) == 1
        assert props[0]["value"] == "v2"

    def test_multiple_different_props(self):
        _set_prop = self._import()
        props: list = []
        _set_prop(props, "a", "1")
        _set_prop(props, "b", "2")
        assert len(props) == 2
        names = {p["name"] for p in props}
        assert names == {"a", "b"}

    def test_only_first_matching_name_updated(self):
        """If there are duplicate prop names (malformed data), only the first is updated."""
        _set_prop = self._import()
        props = [{"name": "x", "value": "first"}, {"name": "x", "value": "second"}]
        _set_prop(props, "x", "updated")
        assert props[0]["value"] == "updated"
        assert props[1]["value"] == "second"


# ---------------------------------------------------------------------------
# enrich_sbom_with_clair_packages
# ---------------------------------------------------------------------------

def _make_report(
    packages: dict,
    environments: dict,
    distributions: dict,
    manifest_hash: str = "sha256:aabbcc",
) -> dict:
    return {
        "manifest_hash": manifest_hash,
        "packages": packages,
        "environments": environments,
        "distributions": distributions,
        "vulnerabilities": {},
        "package_vulnerabilities": {},
        "enrichments": {},
    }


def _make_sbom(components: list) -> dict:
    return {"components": components}


def _comp(name: str, version: str, props: list | None = None) -> dict:
    c: dict = {"type": "library", "name": name, "version": version}
    if props is not None:
        c["properties"] = props
    return c


class TestEnrichSbomWithClairPackages:
    def _fn(self):
        from sbom_pipeline.scanner.clair import enrich_sbom_with_clair_packages
        return enrich_sbom_with_clair_packages

    # ---- file handling ----

    def test_missing_file_returns_sbom_unchanged(self, tmp_path):
        fn = self._fn()
        sbom = _make_sbom([_comp("curl", "7.88.0")])
        result = fn(sbom, tmp_path / "nonexistent.json")
        assert result["components"][0].get("properties") is None

    def test_invalid_json_returns_sbom_unchanged(self, tmp_path):
        fn = self._fn()
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        sbom = _make_sbom([_comp("curl", "7.88.0")])
        result = fn(sbom, bad)
        assert result["components"][0].get("properties") is None

    def test_empty_packages_returns_sbom_unchanged(self, tmp_path):
        """With no Clair packages there are no matches, so no properties are set."""
        import json
        fn = self._fn()
        report = _make_report({}, {}, {}, manifest_hash="sha256:abc")
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        sbom = _make_sbom([_comp("curl", "7.88.0")])
        result = fn(sbom, p, image_name="myimage:1.0")
        assert result["components"][0].get("properties") is None

    # ---- matching ----

    def test_matching_component_gets_container_image_from_arg(self, tmp_path):
        import json
        fn = self._fn()
        report = _make_report(
            packages={"1": {"id": "1", "name": "libssl", "version": "3.0.0", "kind": "binary"}},
            environments={"1": [{"introduced_in": "sha256:layer1", "distribution_id": "1"}]},
            distributions={"1": {"name": "Debian", "version": "12", "pretty_name": "Debian GNU/Linux 12"}},
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        sbom = _make_sbom([_comp("libssl", "3.0.0")])
        result = fn(sbom, p, image_name="postgres:14")
        props = {pr["name"]: pr["value"] for pr in result["components"][0]["properties"]}
        assert props["container_image"] == "postgres:14"

    def test_matching_component_gets_container_role_from_env(self, tmp_path):
        import json
        fn = self._fn()
        report = _make_report(
            packages={"1": {"id": "1", "name": "libssl", "version": "3.0.0", "kind": "binary"}},
            environments={"1": [{"introduced_in": "sha256:layer1", "distribution_id": "1"}]},
            distributions={"1": {"name": "Debian", "version": "12", "pretty_name": ""}},
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        sbom = _make_sbom([_comp("libssl", "3.0.0")])
        result = fn(sbom, p, image_name="img")
        props = {pr["name"]: pr["value"] for pr in result["components"][0]["properties"]}
        assert props["container_role"] == "sha256:layer1"

    def test_matching_component_gets_os_distribution(self, tmp_path):
        import json
        fn = self._fn()
        report = _make_report(
            packages={"1": {"id": "1", "name": "libssl", "version": "3.0.0", "kind": "binary"}},
            environments={"1": [{"introduced_in": "sha256:layer1", "distribution_id": "2"}]},
            distributions={"2": {"name": "Alpine", "version": "3.18", "pretty_name": "Alpine Linux 3.18"}},
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        sbom = _make_sbom([_comp("libssl", "3.0.0")])
        result = fn(sbom, p, image_name="img")
        props = {pr["name"]: pr["value"] for pr in result["components"][0]["properties"]}
        assert props["os_distribution"] == "Alpine Linux 3.18"

    def test_os_distribution_falls_back_to_name_version(self, tmp_path):
        import json
        fn = self._fn()
        report = _make_report(
            packages={"1": {"id": "1", "name": "busybox", "version": "1.36", "kind": "binary"}},
            environments={"1": [{"introduced_in": "sha256:lx", "distribution_id": "3"}]},
            distributions={"3": {"name": "Alpine", "version": "3.18", "pretty_name": ""}},
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        sbom = _make_sbom([_comp("busybox", "1.36")])
        result = fn(sbom, p, image_name="img")
        props = {pr["name"]: pr["value"] for pr in result["components"][0]["properties"]}
        assert props["os_distribution"] == "Alpine 3.18"

    def test_no_clair_match_original_component_unchanged(self, tmp_path):
        """Version mismatch: the original SBOM component gets no properties."""
        import json
        fn = self._fn()
        report = _make_report(
            packages={"1": {"id": "1", "name": "curl", "version": "8.0.0", "kind": "binary"}},
            environments={"1": [{"introduced_in": "sha256:lx", "distribution_id": "1"}]},
            distributions={"1": {"name": "Debian", "version": "12", "pretty_name": "Debian 12"}},
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        sbom = _make_sbom([_comp("curl", "7.88.0")])
        result = fn(sbom, p, image_name="img")
        # original component (curl 7.88.0) must not have been modified
        assert result["components"][0].get("properties") is None

    def test_unmatched_clair_package_added_as_new_component(self, tmp_path):
        """A Clair package not in the SBOM is appended as a new component."""
        import json
        fn = self._fn()
        report = _make_report(
            packages={"1": {"id": "1", "name": "curl", "version": "8.0.0", "kind": "binary", "arch": "amd64"}},
            environments={"1": [{"introduced_in": "sha256:lx", "distribution_id": "1"}]},
            distributions={"1": {"name": "Debian", "version": "12", "pretty_name": "Debian 12", "did": "debian"}},
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        sbom = _make_sbom([_comp("curl", "7.88.0")])  # different version
        result = fn(sbom, p, image_name="img")
        assert len(result["components"]) == 2
        new_comp = result["components"][1]
        assert new_comp["name"] == "curl"
        assert new_comp["version"] == "8.0.0"
        props = {pr["name"]: pr["value"] for pr in new_comp["properties"]}
        assert props["container_image"] == "img"

    def test_added_component_has_deb_purl(self, tmp_path):
        """New component from dpkg package gets a pkg:deb/... PURL."""
        import json
        fn = self._fn()
        report = _make_report(
            packages={"1": {"id": "1", "name": "libssl3", "version": "3.5.5", "kind": "binary", "arch": "amd64"}},
            environments={"1": [{"introduced_in": "sha256:l1", "distribution_id": "2"}]},
            distributions={"2": {"name": "Debian", "version": "13", "pretty_name": "Debian 13", "did": "debian"}},
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        sbom = _make_sbom([])
        result = fn(sbom, p, image_name="postgres:14")
        new_comp = result["components"][0]
        assert new_comp["purl"] == "pkg:deb/debian/libssl3@3.5.5?arch=amd64"
        assert new_comp["bom-ref"] == new_comp["purl"]

    def test_added_component_has_golang_purl(self, tmp_path):
        """New component from a Go binary gets a pkg:golang/... PURL."""
        import json
        fn = self._fn()
        report = _make_report(
            packages={
                "1": {
                    "id": "1",
                    "name": "stdlib",
                    "version": "v1.24.0",
                    "kind": "binary",
                    "arch": "",
                    "detector": "urn:claircore:detector:gobin:7:package",
                }
            },
            environments={"1": [{"introduced_in": "sha256:l2", "distribution_id": ""}]},
            distributions={},
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        sbom = _make_sbom([])
        result = fn(sbom, p, image_name="myapp:latest")
        new_comp = result["components"][0]
        assert new_comp["purl"] == "pkg:golang/stdlib@v1.24.0"

    def test_empty_sbom_components_all_clair_packages_added(self, tmp_path):
        """When SBOM has no components, all Clair packages become new components."""
        import json
        fn = self._fn()
        report = _make_report(
            packages={
                "1": {"id": "1", "name": "bash", "version": "5.2", "kind": "binary"},
                "2": {"id": "2", "name": "grep", "version": "3.11", "kind": "binary"},
            },
            environments={
                "1": [{"introduced_in": "sha256:l1", "distribution_id": "1"}],
                "2": [{"introduced_in": "sha256:l1", "distribution_id": "1"}],
            },
            distributions={"1": {"name": "Debian", "version": "12", "pretty_name": "Debian 12"}},
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        sbom = {"components": []}
        result = fn(sbom, p, image_name="myimg")
        assert len(result["components"]) == 2
        names = {c["name"] for c in result["components"]}
        assert names == {"bash", "grep"}

    def test_existing_matched_and_unmatched_both_handled(self, tmp_path):
        """Matched component is updated; unmatched Clair package is added."""
        import json
        fn = self._fn()
        report = _make_report(
            packages={
                "1": {"id": "1", "name": "curl", "version": "7.88", "kind": "binary"},
                "2": {"id": "2", "name": "openssl", "version": "3.0", "kind": "binary"},
            },
            environments={
                "1": [{"introduced_in": "sha256:l1", "distribution_id": "1"}],
                "2": [{"introduced_in": "sha256:l1", "distribution_id": "1"}],
            },
            distributions={"1": {"name": "Debian", "version": "12", "pretty_name": "Debian 12"}},
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        # SBOM only has curl (matches), not openssl (will be added)
        sbom = _make_sbom([_comp("curl", "7.88")])
        result = fn(sbom, p, image_name="img")
        assert len(result["components"]) == 2
        names = {c["name"] for c in result["components"]}
        assert "curl" in names
        assert "openssl" in names
        # the original curl component should have been enriched
        curl_comp = next(c for c in result["components"] if c["name"] == "curl")
        props = {pr["name"]: pr["value"] for pr in curl_comp["properties"]}
        assert props["container_image"] == "img"

    def test_image_name_falls_back_to_manifest_hash(self, tmp_path):
        import json
        fn = self._fn()
        report = _make_report(
            packages={"1": {"id": "1", "name": "curl", "version": "7.88.0", "kind": "binary"}},
            environments={"1": [{"introduced_in": "sha256:ly", "distribution_id": "1"}]},
            distributions={"1": {"name": "Debian", "version": "12", "pretty_name": "Debian 12"}},
            manifest_hash="sha256:deadbeef",
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        sbom = _make_sbom([_comp("curl", "7.88.0")])
        result = fn(sbom, p)  # no image_name
        props = {pr["name"]: pr["value"] for pr in result["components"][0]["properties"]}
        assert props["container_image"] == "sha256:deadbeef"

    def test_deep_copy_original_not_mutated(self, tmp_path):
        import json, copy
        fn = self._fn()
        report = _make_report(
            packages={"1": {"id": "1", "name": "curl", "version": "7.88.0", "kind": "binary"}},
            environments={"1": [{"introduced_in": "sha256:ly", "distribution_id": "1"}]},
            distributions={"1": {"name": "Debian", "version": "12", "pretty_name": "Debian 12"}},
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        original_sbom = _make_sbom([_comp("curl", "7.88.0")])
        snapshot = copy.deepcopy(original_sbom)
        fn(original_sbom, p, image_name="img")
        # original must not be mutated
        assert original_sbom == snapshot

    def test_matching_is_case_insensitive(self, tmp_path):
        """Clair names are lower-case; SBOM names may have mixed case."""
        import json
        fn = self._fn()
        report = _make_report(
            packages={"1": {"id": "1", "name": "libssl1.1", "version": "1.1.1n-0+deb11u3", "kind": "binary"}},
            environments={"1": [{"introduced_in": "sha256:lx", "distribution_id": "1"}]},
            distributions={"1": {"name": "Debian", "version": "11", "pretty_name": "Debian GNU/Linux 11"}},
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        sbom = _make_sbom([_comp("LibSSL1.1", "1.1.1n-0+deb11u3")])
        result = fn(sbom, p, image_name="img")
        props = {pr["name"]: pr["value"] for pr in result["components"][0]["properties"]}
        assert "container_image" in props

    def test_existing_properties_preserved(self, tmp_path):
        import json
        fn = self._fn()
        report = _make_report(
            packages={"1": {"id": "1", "name": "curl", "version": "7.88", "kind": "binary"}},
            environments={"1": [{"introduced_in": "sha256:l1", "distribution_id": "1"}]},
            distributions={"1": {"name": "Debian", "version": "12", "pretty_name": "Debian 12"}},
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        sbom = _make_sbom([_comp("curl", "7.88", props=[{"name": "attack-surface", "value": "yes"}])])
        result = fn(sbom, p, image_name="img")
        props = {pr["name"]: pr["value"] for pr in result["components"][0]["properties"]}
        assert props["attack-surface"] == "yes"
        assert "container_image" in props

    def test_no_env_entry_skips_role_and_dist(self, tmp_path):
        """Package with no environment record: only container_image should be set."""
        import json
        fn = self._fn()
        report = _make_report(
            packages={"1": {"id": "1", "name": "curl", "version": "7.88", "kind": "binary"}},
            environments={},  # no env data
            distributions={},
        )
        p = tmp_path / "r.json"
        p.write_text(json.dumps(report))
        sbom = _make_sbom([_comp("curl", "7.88")])
        result = fn(sbom, p, image_name="img")
        props = {pr["name"]: pr["value"] for pr in result["components"][0]["properties"]}
        assert props["container_image"] == "img"
        assert "container_role" not in props
        assert "os_distribution" not in props


# ===========================================================================
# Clair HTTP API helpers
# ===========================================================================

def _make_urlopen_mock(response_body: bytes, status: int = 200):
    """Return a context-manager mock that mimics urllib.request.urlopen."""
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = response_body
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestSubmitManifest:
    """_submit_manifest() POSTs to /indexer/api/v1/index_report."""

    def test_returns_manifest_hash(self):
        body = json.dumps({"manifest_hash": "sha256:abc123"}).encode()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_mock(body)):
            result = _submit_manifest("http://clair:8080", "postgres:14")
        assert result == "sha256:abc123"

    def test_falls_back_to_hash_key(self):
        body = json.dumps({"hash": "sha256:fallback"}).encode()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_mock(body)):
            result = _submit_manifest("http://clair:8080", "myimage:1.0")
        assert result == "sha256:fallback"

    def test_returns_empty_string_when_no_hash(self):
        body = json.dumps({"state": "IndexQueued"}).encode()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_mock(body)):
            result = _submit_manifest("http://clair:8080", "myimage:1.0")
        assert result == ""

    def test_posts_to_correct_url(self):
        body = json.dumps({"manifest_hash": "sha256:x"}).encode()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_mock(body)) as mock_open:
            _submit_manifest("http://clair:8080", "postgres:14")
        req = mock_open.call_args[0][0]
        assert req.full_url == "http://clair:8080/indexer/api/v1/index_report"
        assert req.method == "POST"
        assert json.loads(req.data) == {"image_name": "postgres:14"}

    def test_network_error_propagates(self):
        with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
            with pytest.raises(OSError):
                _submit_manifest("http://clair:8080", "myimage:1.0")


class TestGetIndexState:
    """_get_index_state() GETs /indexer/api/v1/index_report/{hash}."""

    def test_returns_index_finished(self):
        body = json.dumps({"state": "IndexFinished"}).encode()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_mock(body)):
            assert _get_index_state("http://clair:8080", "sha256:abc") == "IndexFinished"

    def test_returns_index_error(self):
        body = json.dumps({"state": "IndexError"}).encode()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_mock(body)):
            assert _get_index_state("http://clair:8080", "sha256:abc") == "IndexError"

    def test_returns_empty_string_when_no_state(self):
        body = json.dumps({}).encode()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_mock(body)):
            assert _get_index_state("http://clair:8080", "sha256:abc") == ""

    def test_uses_manifest_hash_in_url(self):
        body = json.dumps({"state": "IndexFinished"}).encode()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_mock(body)) as mock_open:
            _get_index_state("http://clair:8080", "sha256:deadbeef")
        req = mock_open.call_args[0][0]
        assert "sha256:deadbeef" in req.full_url


class TestFetchVulnReport:
    """_fetch_vuln_report() GETs /matcher/api/v1/vulnerability_report/{hash}."""

    def test_returns_parsed_json(self):
        report = {"manifest_hash": "sha256:abc", "vulnerabilities": {}}
        body = json.dumps(report).encode()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_mock(body)):
            result = _fetch_vuln_report("http://clair:8080", "sha256:abc")
        assert result == report

    def test_uses_manifest_hash_in_url(self):
        body = json.dumps({}).encode()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_mock(body)) as mock_open:
            _fetch_vuln_report("http://clair:8080", "sha256:myhash")
        req = mock_open.call_args[0][0]
        assert "sha256:myhash" in req.full_url
        assert "/matcher/api/v1/vulnerability_report/" in req.full_url

    def test_network_error_propagates(self):
        with patch("urllib.request.urlopen", side_effect=OSError("timeout")):
            with pytest.raises(OSError):
                _fetch_vuln_report("http://clair:8080", "sha256:abc")
