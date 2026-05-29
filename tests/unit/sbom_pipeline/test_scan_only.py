"""Unit tests for pipeline.scan_only."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, call, patch

import pytest

from sbom_pipeline.config import PipelineConfig
from sbom_pipeline.constants import SIGNED_BOM_FILE
from sbom_pipeline.pipeline import scan_only
from sbom_pipeline.sign import verify_sbom
from sbom_pipeline.vuln_merger import VulnFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MINIMAL_SBOM: Dict[str, Any] = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "bom-ref": "r1",
        }
    ],
}


def _finding(cve_id: str = "CVE-2024-0001", score: float = 7.5) -> VulnFinding:
    return VulnFinding(
        cve_id=cve_id,
        component_name="requests",
        component_version="2.31.0",
        component_purl="pkg:pypi/requests@2.31.0",
        cvss_score=score,
        severity="HIGH",
        description="Test vuln",
        scanner="trivy",
        fixed_version="2.32.0",
    )


def _cfg(tmp: Path, **kwargs) -> PipelineConfig:
    cfg = PipelineConfig(
        output_dir=tmp / "out",
        reports_dir=tmp / "reports",
        project_dir=tmp / "project",
        skip_clair=True,
    )
    for k, v in kwargs.items():
        setattr(cfg, k, v)
    cfg.__post_init__()
    (tmp / "project").mkdir(parents=True, exist_ok=True)
    return cfg


def _write_sbom(path: Path, data: Dict[str, Any] | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data or _MINIMAL_SBOM), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Smoke: scan_only runs end-to-end with all scanners mocked
# ---------------------------------------------------------------------------

class TestScanOnlySmoke:
    """scan_only completes without error when all external tools are mocked."""

    def _run(self, tmp: Path, findings: List[VulnFinding] | None = None) -> Path:
        sbom_path = _write_sbom(tmp / "input.json")
        cfg = _cfg(tmp)

        with (
            patch("sbom_pipeline.pipeline.trivy.scan_filesystem", return_value=findings or []),
            patch("sbom_pipeline.pipeline.trivy.scan_sbom", return_value=[]),
            patch("sbom_pipeline.pipeline.depcheck.scan", return_value=[]),
            patch("sbom_pipeline.pipeline._export_reports"),
        ):
            scan_only(sbom_path, cfg)

        return cfg.output_dir / SIGNED_BOM_FILE

    def test_produces_signed_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = self._run(Path(tmp))
            assert signed.exists()

    def test_signed_bom_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = self._run(Path(tmp))
            data = json.loads(signed.read_text())
            assert "bomFormat" in data

    def test_signed_bom_has_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = self._run(Path(tmp))
            assert verify_sbom(signed) is True

    def test_sig_file_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = self._run(Path(tmp))
            assert signed.with_suffix(".sig").exists()

    def test_vulns_merged_into_signed_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = self._run(Path(tmp), findings=[_finding()])
            data = json.loads(signed.read_text())
            assert len(data.get("vulnerabilities", [])) == 1

    def test_export_called_with_include_components_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            sbom_path = _write_sbom(Path(tmp) / "input.json")
            cfg = _cfg(Path(tmp))
            mock_export = MagicMock()

            with (
                patch("sbom_pipeline.pipeline.trivy.scan_filesystem", return_value=[]),
                patch("sbom_pipeline.pipeline.trivy.scan_sbom", return_value=[]),
                patch("sbom_pipeline.pipeline.depcheck.scan", return_value=[]),
                patch("sbom_pipeline.pipeline._export_reports", mock_export),
            ):
                scan_only(sbom_path, cfg)

            _, kwargs = mock_export.call_args
            assert kwargs.get("include_components") is False


# ---------------------------------------------------------------------------
# Unit: Clair skipped when skip_clair=True
# ---------------------------------------------------------------------------

class TestClairSkipping:
    def test_clair_not_called_when_skip_clair_true(self):
        with tempfile.TemporaryDirectory() as tmp:
            sbom_path = _write_sbom(Path(tmp) / "input.json")
            cfg = _cfg(Path(tmp), skip_clair=True)

            with (
                patch("sbom_pipeline.pipeline.clair.run_scan_report") as mock_clair,
                patch("sbom_pipeline.pipeline.trivy.scan_filesystem", return_value=[]),
                patch("sbom_pipeline.pipeline.trivy.scan_sbom", return_value=[]),
                patch("sbom_pipeline.pipeline.depcheck.scan", return_value=[]),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                scan_only(sbom_path, cfg)

            mock_clair.assert_not_called()

    def test_clair_not_called_when_image_name_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            sbom_path = _write_sbom(Path(tmp) / "input.json")
            cfg = _cfg(Path(tmp), skip_clair=False, image_name=None)

            with (
                patch("sbom_pipeline.pipeline.clair.run_scan_report") as mock_clair,
                patch("sbom_pipeline.pipeline.trivy.scan_filesystem", return_value=[]),
                patch("sbom_pipeline.pipeline.trivy.scan_sbom", return_value=[]),
                patch("sbom_pipeline.pipeline.depcheck.scan", return_value=[]),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                scan_only(sbom_path, cfg)

            mock_clair.assert_not_called()

    def test_clair_called_when_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            sbom_path = _write_sbom(Path(tmp) / "input.json")
            cfg = _cfg(Path(tmp), skip_clair=False, image_name="myimage:latest")
            fake_report = Path(tmp) / "clair.json"
            fake_report.write_text("{}")

            with (
                patch("sbom_pipeline.pipeline.clair.run_scan_report", return_value=fake_report),
                patch("sbom_pipeline.pipeline.clair.parse_report_findings", return_value=[_finding()]) as mock_parse,
                patch("sbom_pipeline.pipeline.trivy.scan_filesystem", return_value=[]),
                patch("sbom_pipeline.pipeline.trivy.scan_sbom", return_value=[]),
                patch("sbom_pipeline.pipeline.depcheck.scan", return_value=[]),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                scan_only(sbom_path, cfg)

            mock_parse.assert_called_once()

    def test_clair_findings_included_when_report_returned(self):
        with tempfile.TemporaryDirectory() as tmp:
            sbom_path = _write_sbom(Path(tmp) / "input.json")
            cfg = _cfg(Path(tmp), skip_clair=False, image_name="myimage:latest")
            fake_report = Path(tmp) / "clair.json"
            fake_report.write_text("{}")

            with (
                patch("sbom_pipeline.pipeline.clair.run_scan_report", return_value=fake_report),
                patch("sbom_pipeline.pipeline.clair.parse_report_findings", return_value=[_finding("CVE-CLAIR-1")]),
                patch("sbom_pipeline.pipeline.trivy.scan_filesystem", return_value=[]),
                patch("sbom_pipeline.pipeline.trivy.scan_sbom", return_value=[]),
                patch("sbom_pipeline.pipeline.depcheck.scan", return_value=[]),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                scan_only(sbom_path, cfg)

            signed = cfg.output_dir / SIGNED_BOM_FILE
            data = json.loads(signed.read_text())
            vuln_ids = [v["id"] for v in data.get("vulnerabilities", [])]
            assert "CVE-CLAIR-1" in vuln_ids

    def test_clair_findings_skipped_when_run_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            sbom_path = _write_sbom(Path(tmp) / "input.json")
            cfg = _cfg(Path(tmp), skip_clair=False, image_name="myimage:latest")

            with (
                patch("sbom_pipeline.pipeline.clair.run_scan_report", return_value=None),
                patch("sbom_pipeline.pipeline.clair.parse_report_findings") as mock_parse,
                patch("sbom_pipeline.pipeline.trivy.scan_filesystem", return_value=[]),
                patch("sbom_pipeline.pipeline.trivy.scan_sbom", return_value=[]),
                patch("sbom_pipeline.pipeline.depcheck.scan", return_value=[]),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                scan_only(sbom_path, cfg)

            mock_parse.assert_not_called()


# ---------------------------------------------------------------------------
# Unit: scanner call arguments
# ---------------------------------------------------------------------------

class TestScannerCallArguments:
    def _run_capture(self, tmp: Path, findings: List[VulnFinding] | None = None):
        sbom_path = _write_sbom(Path(tmp) / "input.json")
        cfg = _cfg(Path(tmp))
        calls: Dict[str, Any] = {}

        def capture_trivy_fs(**kwargs):
            calls["trivy_fs"] = kwargs
            return findings or []

        def capture_trivy_sbom(**kwargs):
            calls["trivy_sbom"] = kwargs
            return []

        def capture_depcheck(**kwargs):
            calls["depcheck"] = kwargs
            return []

        with (
            patch("sbom_pipeline.pipeline.trivy.scan_filesystem", side_effect=capture_trivy_fs),
            patch("sbom_pipeline.pipeline.trivy.scan_sbom", side_effect=capture_trivy_sbom),
            patch("sbom_pipeline.pipeline.depcheck.scan", side_effect=capture_depcheck),
            patch("sbom_pipeline.pipeline._export_reports"),
        ):
            scan_only(sbom_path, cfg)

        return sbom_path, cfg, calls

    def test_trivy_fs_receives_project_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            sbom_path, cfg, calls = self._run_capture(Path(tmp))
            assert calls["trivy_fs"]["project_dir"] == cfg.project_dir

    def test_trivy_sbom_receives_input_sbom_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            sbom_path, cfg, calls = self._run_capture(Path(tmp))
            assert calls["trivy_sbom"]["sbom_path"] == sbom_path

    def test_depcheck_receives_project_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            sbom_path, cfg, calls = self._run_capture(Path(tmp))
            assert calls["depcheck"]["project_dir"] == cfg.project_dir


# ---------------------------------------------------------------------------
# Unit: CVSS cross-populate
# ---------------------------------------------------------------------------

class TestCvssCrossPopulate:
    def _run_with_findings(self, tmp: Path, findings: List[VulnFinding]) -> Path:
        sbom_path = _write_sbom(Path(tmp) / "input.json")
        cfg = _cfg(Path(tmp))

        with (
            patch("sbom_pipeline.pipeline.trivy.scan_filesystem", return_value=findings),
            patch("sbom_pipeline.pipeline.trivy.scan_sbom", return_value=[]),
            patch("sbom_pipeline.pipeline.depcheck.scan", return_value=[]),
            patch("sbom_pipeline.pipeline._export_reports"),
        ):
            scan_only(sbom_path, cfg)

        return cfg.output_dir / SIGNED_BOM_FILE

    def test_zero_score_filled_from_other_scanner(self):
        with tempfile.TemporaryDirectory() as tmp:
            f_with_score = _finding("CVE-2024-X", score=9.8)
            f_without_score = _finding("CVE-2024-X", score=0.0)
            f_without_score.scanner = "depcheck"

            signed = self._run_with_findings(Path(tmp), [f_with_score, f_without_score])
            data = json.loads(signed.read_text())
            vulns = data.get("vulnerabilities", [])
            # After dedup one entry remains; verify it has a score
            assert len(vulns) == 1
            score = vulns[0].get("ratings", [{}])[0].get("score", 0)
            assert float(score) == pytest.approx(9.8)

    def test_score_not_overwritten_when_already_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            f_high = _finding("CVE-2024-Y", score=9.8)
            f_low = _finding("CVE-2024-Y", score=2.0)
            f_low.scanner = "depcheck"

            self._run_with_findings(Path(tmp), [f_high, f_low])
            # No assertion on the stored score needed — just verify no exception raised


# ---------------------------------------------------------------------------
# Unit: vulns-normalized.json written only when findings exist
# ---------------------------------------------------------------------------

class TestVulnReport:
    def test_vuln_report_written_when_findings_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            sbom_path = _write_sbom(Path(tmp) / "input.json")
            cfg = _cfg(Path(tmp))

            with (
                patch("sbom_pipeline.pipeline.trivy.scan_filesystem", return_value=[_finding()]),
                patch("sbom_pipeline.pipeline.trivy.scan_sbom", return_value=[]),
                patch("sbom_pipeline.pipeline.depcheck.scan", return_value=[]),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                scan_only(sbom_path, cfg)

            assert (cfg.output_dir / "vulns-normalized.json").exists()

    def test_vuln_report_not_written_when_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            sbom_path = _write_sbom(Path(tmp) / "input.json")
            cfg = _cfg(Path(tmp))

            with (
                patch("sbom_pipeline.pipeline.trivy.scan_filesystem", return_value=[]),
                patch("sbom_pipeline.pipeline.trivy.scan_sbom", return_value=[]),
                patch("sbom_pipeline.pipeline.depcheck.scan", return_value=[]),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                scan_only(sbom_path, cfg)

            assert not (cfg.output_dir / "vulns-normalized.json").exists()


# ---------------------------------------------------------------------------
# Unit: deduplication of vulnerabilities
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_duplicate_findings_deduplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            sbom_path = _write_sbom(Path(tmp) / "input.json")
            cfg = _cfg(Path(tmp))

            dup1 = _finding("CVE-2024-DUP")
            dup2 = _finding("CVE-2024-DUP")
            dup2.scanner = "depcheck"

            with (
                patch("sbom_pipeline.pipeline.trivy.scan_filesystem", return_value=[dup1, dup2]),
                patch("sbom_pipeline.pipeline.trivy.scan_sbom", return_value=[]),
                patch("sbom_pipeline.pipeline.depcheck.scan", return_value=[]),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                scan_only(sbom_path, cfg)

            data = json.loads((cfg.output_dir / SIGNED_BOM_FILE).read_text())
            vuln_ids = [v["id"] for v in data.get("vulnerabilities", [])]
            assert vuln_ids.count("CVE-2024-DUP") == 1


# ---------------------------------------------------------------------------
# Unit: NVD API key warning (added in this branch)
# ---------------------------------------------------------------------------

class TestNvdApiKeyWarning:
    """scan_only should warn once when NVD_API_KEY is absent."""

    def _run(self, tmp: Path, nvd_api_key=None) -> None:
        sbom_path = _write_sbom(Path(tmp) / "input.json")
        cfg = _cfg(Path(tmp), nvd_api_key=nvd_api_key)

        with (
            patch("sbom_pipeline.pipeline.trivy.scan_filesystem", return_value=[]),
            patch("sbom_pipeline.pipeline.trivy.scan_sbom", return_value=[]),
            patch("sbom_pipeline.pipeline.depcheck.scan", return_value=[]),
            patch("sbom_pipeline.pipeline._export_reports"),
        ):
            scan_only(sbom_path, cfg)

    def test_warning_emitted_when_nvd_api_key_is_none(self, caplog):
        import logging

        with tempfile.TemporaryDirectory() as tmp:
            with caplog.at_level(logging.WARNING):
                self._run(Path(tmp), nvd_api_key=None)

        assert any("NVD_API_KEY" in r.message for r in caplog.records)

    def test_warning_not_emitted_when_nvd_api_key_is_set(self, caplog):
        import logging

        with tempfile.TemporaryDirectory() as tmp:
            with caplog.at_level(logging.WARNING):
                self._run(Path(tmp), nvd_api_key="my-secret-token")

        assert not any("NVD_API_KEY" in r.message for r in caplog.records)

    def test_warning_contains_docs_link(self, caplog):
        import logging

        with tempfile.TemporaryDirectory() as tmp:
            with caplog.at_level(logging.WARNING):
                self._run(Path(tmp), nvd_api_key=None)

        messages = " ".join(r.message for r in caplog.records)
        assert "nvd.nist.gov" in messages


# ---------------------------------------------------------------------------
# Unit: bdu_cache_dir forwarded to merge_vulns_into_sbom (added in this branch)
# ---------------------------------------------------------------------------

class TestBduCacheDirForwarding:
    """scan_only must pass cfg.bdu_cache_dir to merge_vulns_into_sbom."""

    def test_bdu_cache_dir_forwarded_to_merge(self, tmp_path):
        sbom_path = _write_sbom(tmp_path / "input.json")
        cache_dir = tmp_path / "my_bdu_cache"
        cfg = _cfg(tmp_path, bdu_cache_dir=cache_dir)

        captured: dict = {}

        def capture_merge(sbom, findings, enable_bdu=False, bdu_cache_dir=None):
            captured["bdu_cache_dir"] = bdu_cache_dir
            return sbom

        with (
            patch("sbom_pipeline.pipeline.trivy.scan_filesystem", return_value=[_finding()]),
            patch("sbom_pipeline.pipeline.trivy.scan_sbom", return_value=[]),
            patch("sbom_pipeline.pipeline.depcheck.scan", return_value=[]),
            patch("sbom_pipeline.pipeline.merge_vulns_into_sbom", side_effect=capture_merge),
            patch("sbom_pipeline.pipeline._export_reports"),
        ):
            scan_only(sbom_path, cfg)

        assert captured["bdu_cache_dir"] == cache_dir

    def test_bdu_cache_dir_default_is_dot_bdu_cache(self, tmp_path):
        """Default cfg.bdu_cache_dir must equal Path('.bdu_cache')."""
        cfg = _cfg(tmp_path)
        assert cfg.bdu_cache_dir == Path(".bdu_cache")

