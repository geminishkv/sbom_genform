"""OWASP Dependency-Check — запуск через Docker."""

from __future__ import annotations

import json
import logging
import re
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
    host_data_dir: Optional[Path] = None,
    nvd_api_key: Optional[str] = None,
) -> List[VulnFinding]:
    """
    Запустить OWASP dependency-check через Docker.

    ``host_project_dir`` / ``host_output_dir`` / ``host_data_dir`` —
    хостовые пути для Docker volume-маунтов (актуально при запуске
    внутри контейнера).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    src = (host_project_dir or project_dir).resolve()
    rep = (host_output_dir or output_dir).resolve()
    dat = (host_data_dir or data_dir).resolve()

    cmd = [
        "docker", "run", "--rm",
        "--platform", "linux/amd64",
        "-v", f"{src}:/src",
        "-v", f"{dat}:/usr/share/dependency-check/data",
        "-v", f"{rep}:/report",
        "owasp/dependency-check:latest",
        "--scan", "/src",
        "--format", "ALL",
        "--out", "/report",
        "--nvdValidForHours", "168",
    ]
    if nvd_api_key:
        cmd += ["--nvdApiKey", nvd_api_key]
    logging.info(f"[depcheck] Запуск dependency-check...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    # exit 1 = уязвимости найдены (штатный код)
    # exit 13 = fatal (обычно: НВД-база не скачана или нет API-ключа)
    if result.returncode not in (0, 1):
        hint = (
            " Убедитесь, что установлена переменная NVD_API_KEY "
            "(https://nvd.nist.gov/developers/request-an-api-key)"
            if result.returncode == 13 else ""
        )
        logging.error(
            f"[depcheck] Завершился с кодом {result.returncode}.{hint} "
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
            raw_name: str = vuln.get("name", "")
            cve_id = _extract_cve_id(raw_name, refs)
            fixed_version = _extract_fixed_version(vuln)
            acceptability_status = "Оценка не присвоена (advisory)" if vuln.get("unscored") == "true" else ""
            recommendation = (
                vuln.get("notes", "")
                or next((r.get("url", "") for r in refs if r.get("url")), "")
            )
            findings.append(
                VulnFinding(
                    cve_id=cve_id,
                    component_name=pkg_name,
                    component_version="",
                    component_purl=purl,
                    cvss_score=cvss_score,
                    severity=vuln.get("severity", "UNKNOWN").upper(),
                    description=vuln.get("description", ""),
                    scanner="dependency-check",
                    fixed_version=fixed_version,
                    recommendation=recommendation,
                    acceptability_status=acceptability_status,
                )
            )

    logging.info(f"[depcheck] Найдено {len(findings)} уязвимостей")
    return findings


def _extract_fixed_version(vuln: dict) -> str:
    """Extract the fixed version from the vulnerableSoftware CPE version ranges.

    dependency-check encodes ranges in the CPE version field, e.g.
    ``cpe:2.3:a:*:pkg:\\>\\=2.0.0\\<2.0.3:*:...``
    An exclusive upper bound ``<X.Y.Z`` means the fix was released as ``X.Y.Z``.
    Inclusive upper bounds (``<=X``) cannot be directly converted to a fix version
    and are skipped.
    """
    for sw_entry in vuln.get("vulnerableSoftware") or []:
        cpe_id: str = (sw_entry.get("software") or {}).get("id", "")
        if not cpe_id:
            continue
        parts = cpe_id.split(":")
        if len(parts) < 6:
            continue
        version_field = parts[5].replace("\\>", ">").replace("\\<", "<").replace("\\=", "=")
        # Exclusive upper bound: <X.Y.Z → fix is X.Y.Z
        m = re.search(r"(?<!=)<([^\s<>=\\]+)", version_field)
        if m:
            return m.group(1)
    return ""


def _extract_cve_id(name: str, refs: list) -> str:
    """Return a CVE ID for the vuln.

    If *name* is already a CVE identifier, return it as-is.
    When dependency-check reports a GHSA identifier, look through the
    reference URLs for an NVD link and extract the CVE from there.
    Fall back to *name* (the GHSA ID) when no CVE is found.
    """
    if not name.upper().startswith("GHSA-"):
        return name
    for ref in refs:
        url: str = ref.get("url", "")
        m = re.search(r"(CVE-\d{4}-\d+)", url, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return name


def _extract_cvss(vuln: dict) -> float:
    v3 = vuln.get("cvssv3") or {}
    v2 = vuln.get("cvssv2") or {}
    score = v3.get("baseScore") or v2.get("score") or 0.0
    return float(score)
