"""Unit tests for pipeline.gen_sbom."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from sbom_pipeline.config import PipelineConfig
from sbom_pipeline.constants import (
    APP_BOM_FILE,
    DEDUP_BOM_FILE,
    SIGNED_DEDUP_BOM_FILE,
    SIGNED_BOM_FILE,
)
from sbom_pipeline.pipeline import gen_sbom
from sbom_pipeline.sign import verify_sbom


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
        },
        {
            "type": "library",
            "name": "flask",
            "version": "3.0.0",
            "purl": "pkg:pypi/flask@3.0.0",
            "bom-ref": "f1",
        },
    ],
}

_DUP_SBOM: Dict[str, Any] = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "bom-ref": "r1",
        },
        {
            "type": "library",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "bom-ref": "r2",
        },
    ],
}


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


def _fake_gen_dir(sbom_data: Dict[str, Any]):
    """Stub for generate.generate_from_dir."""
    def _fn(project_dir, output_file):
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(sbom_data), encoding="utf-8")
    return _fn


def _fake_gen_git(sbom_data: Dict[str, Any]):
    """Stub for generate.generate_from_git."""
    def _fn(url, output_file, **kwargs):
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(sbom_data), encoding="utf-8")
    return _fn


# ---------------------------------------------------------------------------
# Smoke: gen_sbom runs end-to-end with generate mocked
# ---------------------------------------------------------------------------

class TestGenSbomSmoke:
    """gen_sbom completes without error and produces the expected artefacts."""

    def _run(self, tmp: Path, sbom_data: Dict[str, Any] | None = None) -> Path:
        cfg = _cfg(tmp)
        with (
            patch("sbom_pipeline.pipeline.generate.generate_from_dir", _fake_gen_dir(sbom_data or _MINIMAL_SBOM)),
            patch("sbom_pipeline.pipeline._export_reports"),
        ):
            gen_sbom(cfg)
        return cfg.output_dir / SIGNED_DEDUP_BOM_FILE

    def test_produces_signed_dedup_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = self._run(Path(tmp))
            assert signed.exists()

    def test_signed_dedup_bom_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = self._run(Path(tmp))
            data = json.loads(signed.read_text())
            assert "bomFormat" in data

    def test_signed_dedup_bom_has_valid_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = self._run(Path(tmp))
            assert verify_sbom(signed) is True

    def test_sig_file_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = self._run(Path(tmp))
            assert signed.with_suffix(".sig").exists()

    def test_does_not_produce_merged_bom(self):
        """gen_sbom must NOT write the vulnerabilities SBOM."""
        with tempfile.TemporaryDirectory() as tmp:
            self._run(Path(tmp))
            cfg = _cfg(Path(tmp))
            assert not (cfg.output_dir / SIGNED_BOM_FILE).exists()

    def test_signed_dedup_bom_has_no_vulnerabilities(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = self._run(Path(tmp))
            data = json.loads(signed.read_text())
            assert "vulnerabilities" not in data

    def test_export_called_with_include_vulns_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            mock_export = MagicMock()
            with (
                patch("sbom_pipeline.pipeline.generate.generate_from_dir", _fake_gen_dir(_MINIMAL_SBOM)),
                patch("sbom_pipeline.pipeline._export_reports", mock_export),
            ):
                gen_sbom(cfg)

            _, kwargs = mock_export.call_args
            assert kwargs.get("include_vulns") is False

    def test_export_called_with_include_components_true(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            mock_export = MagicMock()
            with (
                patch("sbom_pipeline.pipeline.generate.generate_from_dir", _fake_gen_dir(_MINIMAL_SBOM)),
                patch("sbom_pipeline.pipeline._export_reports", mock_export),
            ):
                gen_sbom(cfg)

            _, kwargs = mock_export.call_args
            assert kwargs.get("include_vulns") is False
            # include_components defaults to True — not passed explicitly, but let's verify
            assert kwargs.get("include_components", True) is True

    def test_export_uses_signed_dedup_bom_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            mock_export = MagicMock()
            with (
                patch("sbom_pipeline.pipeline.generate.generate_from_dir", _fake_gen_dir(_MINIMAL_SBOM)),
                patch("sbom_pipeline.pipeline._export_reports", mock_export),
            ):
                gen_sbom(cfg)

            _, kwargs = mock_export.call_args
            assert kwargs.get("sbom_file") == SIGNED_DEDUP_BOM_FILE


# ---------------------------------------------------------------------------
# Unit: intermediate artefacts
# ---------------------------------------------------------------------------

class TestIntermediateArtefacts:
    def test_app_bom_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            with (
                patch("sbom_pipeline.pipeline.generate.generate_from_dir", _fake_gen_dir(_MINIMAL_SBOM)),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                gen_sbom(cfg)
            assert (cfg.output_dir / APP_BOM_FILE).exists()

    def test_dedup_bom_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            with (
                patch("sbom_pipeline.pipeline.generate.generate_from_dir", _fake_gen_dir(_MINIMAL_SBOM)),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                gen_sbom(cfg)
            assert (cfg.output_dir / DEDUP_BOM_FILE).exists()

    def test_dedup_bom_has_no_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            with (
                patch("sbom_pipeline.pipeline.generate.generate_from_dir", _fake_gen_dir(_DUP_SBOM)),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                gen_sbom(cfg)
            data = json.loads((cfg.output_dir / DEDUP_BOM_FILE).read_text())
            assert len(data["components"]) == 1


# ---------------------------------------------------------------------------
# Unit: source routing (local vs git)
# ---------------------------------------------------------------------------

class TestSourceRouting:
    def test_local_source_calls_generate_from_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            cfg.source = "local"

            mock_local_fn = MagicMock(side_effect=_fake_gen_dir(_MINIMAL_SBOM))
            mock_git_fn = MagicMock()
            with (
                patch("sbom_pipeline.pipeline.generate.generate_from_dir", mock_local_fn),
                patch("sbom_pipeline.pipeline.generate.generate_from_git", mock_git_fn),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                gen_sbom(cfg)

            mock_local_fn.assert_called_once()
            mock_git_fn.assert_not_called()

    def test_github_source_calls_generate_from_git(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            cfg.source = "github"
            cfg.git_url = "https://github.com/org/repo"

            mock_git_fn = MagicMock(side_effect=_fake_gen_git(_MINIMAL_SBOM))
            mock_local_fn = MagicMock()
            with (
                patch("sbom_pipeline.pipeline.generate.generate_from_dir", mock_local_fn),
                patch("sbom_pipeline.pipeline.generate.generate_from_git", mock_git_fn),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                gen_sbom(cfg)

            mock_git_fn.assert_called_once()
            mock_local_fn.assert_not_called()

    def test_missing_git_url_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            cfg.source = "github"
            cfg.git_url = None

            with (
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                with pytest.raises(ValueError, match="--url"):
                    gen_sbom(cfg)


# ---------------------------------------------------------------------------
# Unit: Clair enrichment
# ---------------------------------------------------------------------------

class TestClairEnrichment:
    def test_clair_not_called_when_skip_clair_true(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp), skip_clair=True)
            mock_clair = MagicMock()
            with (
                patch("sbom_pipeline.pipeline.generate.generate_from_dir", _fake_gen_dir(_MINIMAL_SBOM)),
                patch("sbom_pipeline.pipeline.clair.run_scan_report", mock_clair),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                gen_sbom(cfg)
            mock_clair.assert_not_called()

    def test_clair_not_called_when_image_name_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp), skip_clair=False, image_name=None)
            mock_clair = MagicMock()
            with (
                patch("sbom_pipeline.pipeline.generate.generate_from_dir", _fake_gen_dir(_MINIMAL_SBOM)),
                patch("sbom_pipeline.pipeline.clair.run_scan_report", mock_clair),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                gen_sbom(cfg)
            mock_clair.assert_not_called()

    def test_clair_enriches_sbom_when_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp), skip_clair=False, image_name="myimage:latest")
            fake_report = Path(tmp) / "clair.json"
            fake_report.write_text("{}")

            enriched_sbom = dict(_MINIMAL_SBOM)
            enriched_sbom["components"] = list(_MINIMAL_SBOM["components"]) + [
                {"type": "library", "name": "libssl", "version": "1.1.1",
                 "purl": "pkg:deb/debian/libssl@1.1.1", "bom-ref": "ssl1"}
            ]

            with (
                patch("sbom_pipeline.pipeline.generate.generate_from_dir", _fake_gen_dir(_MINIMAL_SBOM)),
                patch("sbom_pipeline.pipeline.clair.run_scan_report", return_value=fake_report),
                patch("sbom_pipeline.pipeline.clair.enrich_sbom_with_clair_packages",
                      return_value=enriched_sbom) as mock_enrich,
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                gen_sbom(cfg)

            mock_enrich.assert_called_once()

    def test_clair_enrich_skipped_when_run_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp), skip_clair=False, image_name="myimage:latest")
            mock_enrich = MagicMock()
            with (
                patch("sbom_pipeline.pipeline.generate.generate_from_dir", _fake_gen_dir(_MINIMAL_SBOM)),
                patch("sbom_pipeline.pipeline.clair.run_scan_report", return_value=None),
                patch("sbom_pipeline.pipeline.clair.enrich_sbom_with_clair_packages", mock_enrich),
                patch("sbom_pipeline.pipeline._export_reports"),
            ):
                gen_sbom(cfg)
            mock_enrich.assert_not_called()
