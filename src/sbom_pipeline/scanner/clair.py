"""Clair — сканирование контейнерного образа через clairctl (Docker)."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import List

from ..vuln_merger import VulnFinding

# Severity mapping из Clair → нормализованный вид
_SEVERITY_MAP = {
    "Unknown": "UNKNOWN",
    "Negligible": "LOW",
    "Low": "LOW",
    "Medium": "MEDIUM",
    "High": "HIGH",
    "Critical": "CRITICAL",
}


def scan_image(
    image_name: str,
    output_dir: Path,
    clair_endpoint: str = "http://clair:8080",
) -> List[VulnFinding]:
    """
    Запустить clairctl через Docker для анализа образа.
    Шаг опциональный: при любой ошибке возвращает пустой список.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    sanitized = image_name.replace(":", "_").replace("/", "_")
    out_file = output_dir / f"clair-{sanitized}.json"

    cmd = [
        "docker", "run", "--rm",
        "--platform", "linux/amd64",
        "-v", f"{output_dir.resolve()}:/reports",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-e", f"CLAIR_ENDPOINT={clair_endpoint}",
        "quay.io/projectclair/clairctl:latest",
        "report",
        "--log-level", "info",
        "--format", "json",
        "--output", f"/reports/clair-{sanitized}.json",
        image_name,
    ]
    logging.info(f"[clair] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        logging.warning(
            f"[clair] Шаг Clair пропущен (код {result.returncode}). "
            f"Требуется Clair + docker-compose. stderr: {result.stderr[:200]}"
        )
        return []

    return _parse(out_file)


# ------------------------------------------------------------------
# Парсинг JSON-отчёта Clair
# ------------------------------------------------------------------

def _parse(result_file: Path) -> List[VulnFinding]:
    if not result_file.exists():
        return []
    try:
        with open(result_file, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logging.error(f"[clair] Не удалось прочитать {result_file}: {e}")
        return []

    findings: List[VulnFinding] = []

    # Формат Clair v4 / clairctl report:
    # { "vulnerabilities": { "<cve-id>": { "Package": {...}, ... } } }
    for vuln_id, vuln_data in (data.get("vulnerabilities") or {}).items():
        pkg = vuln_data.get("Package") or {}
        raw_sev = vuln_data.get("NormalizedSeverity", "Unknown")
        links: list = vuln_data.get("Links") or []
        recommendation = links[0] if links else ""
        findings.append(
            VulnFinding(
                cve_id=vuln_id,
                component_name=pkg.get("Name", ""),
                component_version=pkg.get("Version", ""),
                component_purl="",
                cvss_score=0.0,
                severity=_SEVERITY_MAP.get(raw_sev, raw_sev.upper()),
                description=vuln_data.get("Description", ""),
                scanner="clair",
                fixed_version=vuln_data.get("FixedInVersion", ""),
                recommendation=recommendation,
            )
        )

    logging.info(f"[clair] Найдено {len(findings)} уязвимостей")
    return findings
