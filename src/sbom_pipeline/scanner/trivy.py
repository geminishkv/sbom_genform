"""Trivy — сканирование файловой системы и SBOM."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import List

from ..vuln_merger import VulnFinding


_STATUS_RU: dict[str, str] = {
    "affected":             "Подвержен уязвимости",
    "fixed":                "Исправлено",
    "will_not_fix":         "Исправление не планируется",
    "fix_deferred":         "Исправление отложено",
    "end_of_life":          "Продукт снят с поддержки",
    "under_investigation":  "Под расследованием",
}


def scan_filesystem(project_dir: Path, output_dir: Path) -> List[VulnFinding]:
    """trivy fs — сканирование директории проекта."""
    if not shutil.which("trivy"):
        logging.warning("[trivy] trivy не найден в PATH, шаг пропущен")
        return []

    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "trivy-fs.json"

    cmd = [
        "trivy", "fs",
        "--db-repository", "ghcr.io/aquasecurity/trivy-db",
        "--java-db-repository", "ghcr.io/aquasecurity/trivy-java-db",
        "--scanners", "vuln,secret,misconfig",
        "--exit-code", "0",
        "--format", "json",
        "--output", str(out_file),
        str(project_dir),
    ]
    logging.info(f"[trivy] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        logging.error(f"[trivy] fs ошибка: {result.stderr[:400]}")
        return []

    return _parse(out_file, "trivy")


def scan_sbom(sbom_path: Path, output_dir: Path) -> List[VulnFinding]:
    """trivy sbom — сканирование по готовому SBOM-файлу."""
    if not shutil.which("trivy"):
        return []

    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "sbom-vulns.json"

    cmd = [
        "trivy", "sbom",
        "--db-repository", "ghcr.io/aquasecurity/trivy-db",
        "--quiet",
        "--format", "json",
        "--output", str(out_file),
        str(sbom_path),
    ]
    logging.info(f"[trivy] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        logging.warning(f"[trivy] sbom scan ошибка: {result.stderr[:300]}")
        return []

    return _parse(out_file, "trivy")


# ------------------------------------------------------------------
# Парсинг JSON-отчёта Trivy
# ------------------------------------------------------------------

def _parse(result_file: Path, scanner: str) -> List[VulnFinding]:
    if not result_file.exists():
        return []
    try:
        with open(result_file, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logging.error(f"[trivy] Не удалось прочитать {result_file}: {e}")
        return []

    findings: List[VulnFinding] = []
    for result_block in data.get("Results", []):
        for vuln in result_block.get("Vulnerabilities") or []:
            cvss_score = _extract_cvss(vuln.get("CVSS", {}))
            fixed = vuln.get("FixedVersion", "")
            recommendation = (
                vuln.get("PrimaryURL", "")
                or (f"Обновить до версии {fixed}" if fixed else "")
            )
            findings.append(
                VulnFinding(
                    cve_id=vuln.get("VulnerabilityID", ""),
                    component_name=vuln.get("PkgName", ""),
                    component_version=vuln.get("InstalledVersion", ""),
                    component_purl=vuln.get("PkgRef", ""),
                    cvss_score=cvss_score,
                    severity=vuln.get("Severity", "UNKNOWN"),
                    description=vuln.get("Title") or vuln.get("Description", ""),
                    scanner=scanner,
                    fixed_version=fixed,
                    recommendation=recommendation,
                    acceptability_status=_STATUS_RU.get(vuln.get("Status", ""), vuln.get("Status", "")),
                )
            )

    logging.info(f"[trivy] Найдено {len(findings)} уязвимостей в {result_file.name}")
    return findings


def _extract_cvss(cvss_map: dict) -> float:
    best = 0.0
    for src_data in cvss_map.values():
        for key in ("V3Score", "V2Score"):
            score = src_data.get(key)
            if score and float(score) > best:
                best = float(score)
    return best
