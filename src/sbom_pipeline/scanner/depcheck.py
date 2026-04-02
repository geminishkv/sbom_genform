"""OWASP Dependency-Check — запуск через Docker."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import List, Optional

from ..vuln_merger import VulnFinding


def scan(
    project_dir: Path,
    output_dir: Path,
    data_dir: Path,
    host_project_dir: Optional[Path] = None,
    host_output_dir: Optional[Path] = None,
) -> List[VulnFinding]:
    """
    Запустить OWASP dependency-check через Docker.

    ``host_project_dir`` / ``host_output_dir`` — хостовые пути для
    Docker volume-маунтов (актуально при запуске внутри контейнера).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    src = (host_project_dir or project_dir).resolve()
    rep = (host_output_dir or output_dir).resolve()

    cmd = [
        "docker", "run", "--rm",
        "--platform", "linux/amd64",
        "-v", f"{src}:/src",
        "-v", f"{data_dir.resolve()}:/usr/share/dependency-check/data",
        "-v", f"{rep}:/report",
        "owasp/dependency-check:latest",
        "--scan", "/src",
        "--format", "ALL",
        "--out", "/report",
    ]
    logging.info(f"[depcheck] Запуск dependency-check...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    # exit 1 = уязвимости найдены (штатный код)
    if result.returncode not in (0, 1):
        logging.error(
            f"[depcheck] Завершился с кодом {result.returncode}. "
            f"stderr: {result.stderr[:400]}"
        )
        return []

    json_report = output_dir / "dependency-check-report.json"
    return _parse(json_report)


# ------------------------------------------------------------------
# Парсинг JSON-отчёта dependency-check
# ------------------------------------------------------------------

def _parse(result_file: Path) -> List[VulnFinding]:
    if not result_file.exists():
        logging.warning(f"[depcheck] JSON-отчёт не найден: {result_file}")
        return []
    try:
        with open(result_file, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logging.error(f"[depcheck] Не удалось прочитать {result_file}: {e}")
        return []

    findings: List[VulnFinding] = []

    for dep in data.get("dependencies", []):
        pkg_name = dep.get("fileName") or dep.get("name") or ""
        packages = dep.get("packages") or []
        purl = packages[0].get("id", "") if packages else ""

        for vuln in dep.get("vulnerabilities") or []:
            cvss_score = _extract_cvss(vuln)
            refs: list = vuln.get("references") or []
            recommendation = (
                vuln.get("notes", "")
                or next((r.get("url", "") for r in refs if r.get("url")), "")
            )
            findings.append(
                VulnFinding(
                    cve_id=vuln.get("name", ""),
                    component_name=pkg_name,
                    component_version="",
                    component_purl=purl,
                    cvss_score=cvss_score,
                    severity=vuln.get("severity", "UNKNOWN").upper(),
                    description=vuln.get("description", ""),
                    scanner="dependency-check",
                    fixed_version="",
                    recommendation=recommendation,
                )
            )

    logging.info(f"[depcheck] Найдено {len(findings)} уязвимостей")
    return findings


def _extract_cvss(vuln: dict) -> float:
    v3 = vuln.get("cvssv3") or {}
    v2 = vuln.get("cvssv2") or {}
    score = v3.get("baseScore") or v2.get("score") or 0.0
    return float(score)
