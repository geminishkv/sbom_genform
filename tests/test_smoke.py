"""Smoke tests — import and basic unit checks (no external tools required)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from sbom_pipeline import cli
from sbom_pipeline import __version__
from sbom_pipeline.config import PipelineConfig
from sbom_pipeline.constants import SIGNED_DEDUP_BOM_FILE, SIGNED_BOM_FILE
from sbom_pipeline.dedup import dedup_sbom, dedup_vulns
from sbom_pipeline.exporter import Exporter
from sbom_pipeline.sign import sign_sbom, verify_sbom
from sbom_pipeline.vuln_merger import VulnFinding, merge_vulns_into_sbom


_MINIMAL_SBOM: dict = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {"type": "library", "name": "requests", "version": "2.31.0",
         "purl": "pkg:pypi/requests@2.31.0", "bom-ref": "r1"},
        {"type": "library", "name": "requests", "version": "2.31.0",
         "purl": "pkg:pypi/requests@2.31.0", "bom-ref": "r2"},
        {"type": "library", "name": "flask", "version": "3.0.0",
         "purl": "pkg:pypi/flask@3.0.0", "bom-ref": "f1"},
    ],
}

_CLI_RUNNER = CliRunner()


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

def test_version_is_semver():
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def test_cli_no_bdu_overrides_bdu_env(monkeypatch):
    captured: dict[str, bool] = {}

    def fake_pipeline_run(cfg: PipelineConfig) -> None:
        captured["use_bdu"] = cfg.use_bdu

    monkeypatch.setenv("BDU", "true")
    monkeypatch.setattr(cli, "pipeline_run", fake_pipeline_run)
    monkeypatch.setattr(cli, "_print_banner", lambda: None)
    monkeypatch.setattr(cli, "_print_footer", lambda: None)
    monkeypatch.setattr(cli, "setup_logging", lambda verbose: None)

    result = _CLI_RUNNER.invoke(cli.app, ["run", "--no-bdu"])

    assert result.exit_code == 0
    assert captured["use_bdu"] is False


def test_cli_bdu_enables_use_bdu(monkeypatch):
    captured: dict[str, bool] = {}

    def fake_pipeline_run(cfg: PipelineConfig) -> None:
        captured["use_bdu"] = cfg.use_bdu

    monkeypatch.delenv("BDU", raising=False)
    monkeypatch.setattr(cli, "pipeline_run", fake_pipeline_run)
    monkeypatch.setattr(cli, "_print_banner", lambda: None)
    monkeypatch.setattr(cli, "_print_footer", lambda: None)
    monkeypatch.setattr(cli, "setup_logging", lambda verbose: None)

    result = _CLI_RUNNER.invoke(cli.app, ["run", "--bdu"])

    assert result.exit_code == 0
    assert captured["use_bdu"] is True


def test_config_defaults():
    cfg = PipelineConfig()
    assert cfg.source == "local"
    assert cfg.skip_clair is True
    assert cfg.use_bdu is False
    assert cfg.project_dir == Path("examples/project_inject")


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("SOURCE", "github")
    monkeypatch.setenv("GIT_URL", "https://github.com/org/repo")
    monkeypatch.setenv("SKIP_CLAIR", "false")
    monkeypatch.setenv("BDU", "true")
    cfg = PipelineConfig.from_env()
    assert cfg.source == "github"
    assert cfg.git_url == "https://github.com/org/repo"
    assert cfg.skip_clair is False
    assert cfg.use_bdu is True


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------

def test_dedup_removes_duplicates():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        inp = p / "bom.json"
        out = p / "bom-dedup.json"
        inp.write_text(json.dumps(_MINIMAL_SBOM))

        dedup_sbom(inp, out)

        result = json.loads(out.read_text())
        assert len(result["components"]) == 2


# ---------------------------------------------------------------------------
# Sign & Verify
# ---------------------------------------------------------------------------

def test_sign_and_verify():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        inp = p / "bom.json"
        out = p / "bom-signed.json"
        inp.write_text(json.dumps(_MINIMAL_SBOM))

        sign_sbom(inp, out)
        assert out.exists()

        ok = verify_sbom(out)
        assert ok is True


def test_verify_fails_on_tampered_sbom():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        inp = p / "bom.json"
        out = p / "bom-signed.json"
        inp.write_text(json.dumps(_MINIMAL_SBOM))

        sign_sbom(inp, out)

        data = json.loads(out.read_text())
        data["components"].append({"name": "evil", "version": "0.0.1"})
        out.write_text(json.dumps(data))

        ok = verify_sbom(out)
        assert ok is False


# ---------------------------------------------------------------------------
# VulnMerger
# ---------------------------------------------------------------------------

def test_merge_vulns_into_sbom():
    sbom = json.loads(json.dumps(_MINIMAL_SBOM))
    findings = [
        VulnFinding(
            cve_id="CVE-2023-1234",
            scanner="trivy",
            component_name="requests",
            component_version="2.31.0",
            component_purl="pkg:pypi/requests@2.31.0",
            severity="HIGH",
            cvss_score=7.5,
            description="Test vuln",
            fixed_version="2.32.0",
        )
    ]
    result = merge_vulns_into_sbom(sbom, findings)
    vulnerability = result["vulnerabilities"][0]

    assert "vulnerabilities" in result
    assert vulnerability["id"] == "CVE-2023-1234"
    assert "properties" not in vulnerability


def test_merge_vulns_with_bdu_into_sbom():
    sbom = json.loads(json.dumps(_MINIMAL_SBOM))
    findings = [
        VulnFinding(
            cve_id="CVE-2023-1234",
            bdu_id="BDU:2023-01813",
            scanner="trivy",
            component_name="requests",
            component_version="2.31.0",
            component_purl="pkg:pypi/requests@2.31.0",
            severity="HIGH",
            cvss_score=7.5,
            description="Test vuln",
            fixed_version="2.32.0",
        )
    ]
    result = merge_vulns_into_sbom(sbom, findings)
    vulnerability = result["vulnerabilities"][0]

    assert "vulnerabilities" in result
    assert vulnerability["id"] == "CVE-2023-1234"
    assert vulnerability["properties"] == [
        {"name": "ru.fstec.bdu:id", "value": "BDU:2023-01813"}
    ]


def test_exporter_hides_bdu_column_when_disabled():
    findings = [
        VulnFinding(
            cve_id="CVE-2023-1234",
            bdu_id="BDU:2023-01813",
            scanner="trivy",
            component_name="requests",
            component_version="2.31.0",
            component_purl="pkg:pypi/requests@2.31.0",
            severity="HIGH",
            cvss_score=7.5,
            description="Test vuln",
            fixed_version="2.32.0",
        )
    ]

    exporter = Exporter([], vulns=findings)
    vuln_rows = exporter._vuln_rows()

    assert exporter._vuln_columns() == [
        "Компонент",
        "Версия",
        "CVE / ID",
        "CVSS",
        "Критичность",
        "Описание",
        "Сканер",
        "Исправлено в версии",
        "Рекомендация / компенсирующая мера",
        "Статус допустимости в рассматриваемой конфигурации",
    ]
    assert "BDU / ID" not in vuln_rows[0]


def test_exporter_shows_bdu_column_when_enabled():
    findings = [
        VulnFinding(
            cve_id="CVE-2023-1234",
            bdu_id="BDU:2023-01813",
            scanner="trivy",
            component_name="requests",
            component_version="2.31.0",
            component_purl="pkg:pypi/requests@2.31.0",
            severity="HIGH",
            cvss_score=7.5,
            description="Test vuln",
            fixed_version="2.32.0",
        )
    ]

    exporter = Exporter([], vulns=findings, include_bdu=True)
    vuln_rows = exporter._vuln_rows()

    assert exporter._vuln_columns() == [
        "Компонент",
        "Версия",
        "CVE / ID",
        "BDU / ID",
        "CVSS",
        "Критичность",
        "Описание",
        "Сканер",
        "Исправлено в версии",
        "Рекомендация / компенсирующая мера",
        "Статус допустимости в рассматриваемой конфигурации",
    ]
    assert vuln_rows[0]["BDU / ID"] == "BDU:2023-01813"


# ---------------------------------------------------------------------------
# dedup_vulns
# ---------------------------------------------------------------------------

def _vuln(cve_id: str, purl: str, score: float, scanner: str = "trivy") -> VulnFinding:
    return VulnFinding(
        cve_id=cve_id,
        component_name="pkg",
        component_version="1.0",
        component_purl=purl,
        cvss_score=score,
        severity="HIGH",
        description="test",
        scanner=scanner,
    )


def test_dedup_vulns_empty_input():
    assert dedup_vulns([]) == []


def test_dedup_vulns_removes_same_cve_same_component():
    findings = [
        _vuln("CVE-2023-1234", "pkg:pypi/requests@2.31.0", 7.5, "trivy"),
        _vuln("CVE-2023-1234", "pkg:pypi/requests@2.31.0", 7.5, "depcheck"),
    ]
    result = dedup_vulns(findings)
    assert len(result) == 1


def test_dedup_vulns_keeps_entry_with_highest_cvss():
    findings = [
        _vuln("CVE-2023-1234", "pkg:pypi/requests@2.31.0", 6.0, "trivy"),
        _vuln("CVE-2023-1234", "pkg:pypi/requests@2.31.0", 9.8, "depcheck"),
    ]
    result = dedup_vulns(findings)
    assert len(result) == 1
    assert result[0].cvss_score == 9.8
    assert result[0].scanner == "depcheck"


def test_dedup_vulns_keeps_different_cves_for_same_component():
    findings = [
        _vuln("CVE-2023-0001", "pkg:pypi/requests@2.31.0", 7.5),
        _vuln("CVE-2023-0002", "pkg:pypi/requests@2.31.0", 5.0),
    ]
    result = dedup_vulns(findings)
    assert len(result) == 2


def test_dedup_vulns_keeps_same_cve_for_different_components():
    findings = [
        _vuln("CVE-2023-1234", "pkg:pypi/requests@2.31.0", 7.5),
        _vuln("CVE-2023-1234", "pkg:pypi/flask@3.0.0", 7.5),
    ]
    result = dedup_vulns(findings)
    assert len(result) == 2


def test_dedup_vulns_fallback_key_no_purl():
    """When purl is empty, key is composed from name@version."""
    f1 = VulnFinding(
        cve_id="CVE-2023-9999",
        component_name="lib",
        component_version="1.0",
        component_purl="",
        cvss_score=5.0,
        severity="MEDIUM",
        description="",
        scanner="trivy",
    )
    f2 = VulnFinding(
        cve_id="CVE-2023-9999",
        component_name="lib",
        component_version="1.0",
        component_purl="",
        cvss_score=5.0,
        severity="MEDIUM",
        description="",
        scanner="depcheck",
    )
    result = dedup_vulns([f1, f2])
    assert len(result) == 1


def test_dedup_vulns_no_cross_match_purl_vs_nopurl():
    """A finding with purl and one without for the same name@version are distinct keys."""
    f1 = _vuln("CVE-2023-5555", "pkg:pypi/lib@1.0", 5.0)
    f2 = VulnFinding(
        cve_id="CVE-2023-5555",
        component_name="lib",
        component_version="1.0",
        component_purl="",
        cvss_score=5.0,
        severity="HIGH",
        description="",
        scanner="clair",
    )
    # Different keys → both kept (purl vs name@version)
    result = dedup_vulns([f1, f2])
    assert len(result) == 2


# ---------------------------------------------------------------------------
# Two signed SBOMs
# ---------------------------------------------------------------------------

def test_sign_sig_file_named_after_output():
    """.sig file name must match the output JSON filename, not the input."""
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        inp = p / "source.json"
        out = p / SIGNED_DEDUP_BOM_FILE
        inp.write_text(json.dumps(_MINIMAL_SBOM))

        sign_sbom(inp, out)

        assert out.with_suffix(".sig").exists(), "Expected <output>.sig"
        assert not (p / "source.sig").exists(), "Sig must not inherit input name"


def test_two_signed_sboms_are_independent():
    """Pipeline produces two independently verifiable signed SBOMs."""
    finding = VulnFinding(
        cve_id="CVE-2024-0001",
        component_name="requests",
        component_version="2.31.0",
        component_purl="pkg:pypi/requests@2.31.0",
        cvss_score=8.0,
        severity="HIGH",
        description="test",
        scanner="trivy",
    )

    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        dedup_path = p / "app-bom-dedup.json"
        dedup_path.write_text(json.dumps(_MINIMAL_SBOM))

        # Step 3 — sign without vulnerabilities
        signed_dedup = p / SIGNED_DEDUP_BOM_FILE
        sign_sbom(dedup_path, signed_dedup)

        assert signed_dedup.exists()
        assert signed_dedup.with_suffix(".sig").exists()
        assert verify_sbom(signed_dedup)

        # Step 6+7 — merge vulns then sign
        sbom_data = json.loads(dedup_path.read_text())
        sbom_data = merge_vulns_into_sbom(sbom_data, [finding])

        signed_merged = p / SIGNED_BOM_FILE
        signed_merged.write_text(json.dumps(sbom_data, indent=2, ensure_ascii=False))
        sign_sbom(signed_merged, signed_merged)

        assert signed_merged.exists()
        assert signed_merged.with_suffix(".sig").exists()
        assert verify_sbom(signed_merged)

        # Signatures must differ
        sig1 = json.loads(signed_dedup.read_text())["metadata"]["signature"]["value"]
        sig2 = json.loads(signed_merged.read_text())["metadata"]["signature"]["value"]
        assert sig1 != sig2

        # Without-vuln SBOM has no vulnerabilities; with-vuln SBOM has them
        d_no_vuln = json.loads(signed_dedup.read_text())
        d_with_vuln = json.loads(signed_merged.read_text())
        assert "vulnerabilities" not in d_no_vuln
        assert "vulnerabilities" in d_with_vuln
        assert len(d_with_vuln["vulnerabilities"]) == 1


def test_two_sig_files_are_distinct():
    """Each signed SBOM writes its own .sig file with matching digest."""
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)

        signed_dedup = p / SIGNED_DEDUP_BOM_FILE
        signed_dedup.write_text(json.dumps(_MINIMAL_SBOM))
        sign_sbom(signed_dedup, signed_dedup)

        sbom_with_vuln = json.loads(signed_dedup.read_text())
        sbom_with_vuln["vulnerabilities"] = [{"id": "CVE-2024-0002"}]

        signed_merged = p / SIGNED_BOM_FILE
        signed_merged.write_text(json.dumps(sbom_with_vuln))
        sign_sbom(signed_merged, signed_merged)

        sig_dedup = signed_dedup.with_suffix(".sig").read_text().strip()
        sig_merged = signed_merged.with_suffix(".sig").read_text().strip()

        assert sig_dedup.startswith("SHA256=")
        assert sig_merged.startswith("SHA256=")
        # The two .sig files contain different digests
        assert sig_dedup != sig_merged
