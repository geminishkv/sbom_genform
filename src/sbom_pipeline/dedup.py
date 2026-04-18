"""Дедупликация компонентов и уязвимостей SBOM — чистый Python."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from .vuln_merger import VulnFinding


def dedup_sbom(input_path: Path, output_path: Path) -> Path:
    """
    Дедуплицировать компоненты CycloneDX SBOM по ключу PURL.

    Если PURL отсутствует, ключом служит «name@version».
    """
    with open(input_path, encoding="utf-8") as f:
        sbom: Dict[str, Any] = json.load(f)

    components = sbom.get("components", [])
    seen: set[str] = set()
    deduped: list[Dict[str, Any]] = []

    for comp in components:
        purl = comp.get("purl", "")
        key = purl if purl else f"{comp.get('name', '')}@{comp.get('version', '')}"
        if key not in seen:
            seen.add(key)
            deduped.append(comp)

    removed = len(components) - len(deduped)
    logging.info(
        f"[dedup] {len(components)} → {len(deduped)} компонентов (удалено {removed} дублей)"
    )

    sbom["components"] = deduped

    # Пересчитать metadata.component count если есть
    if "metadata" in sbom and isinstance(sbom["metadata"].get("component"), dict):
        pass  # не трогаем — cdxgen управляет metadata.component

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)

    logging.info(f"[dedup] Записан: {output_path}")
    return output_path


def dedup_vulns(findings: List["VulnFinding"]) -> List["VulnFinding"]:
    """
    Дедуплицировать список VulnFinding по ключу «CVE-ID :: компонент».

    Если несколько сканеров обнаружили одну и ту же уязвимость в одном
    компоненте — оставляем запись с наибольшим cvss_score; при равном
    балле — первую встреченную.

    После дедупликации заполняем cvss_score == 0.0 используя лучший
    известный балл для этого CVE из других компонентов (cross-component
    propagation).
    """
    best: dict[str, "VulnFinding"] = {}

    for f in findings:
        comp_key = f.component_purl if f.component_purl else f"{f.component_name}@{f.component_version}"
        key = f"{f.cve_id}::{comp_key}"
        if key not in best or f.cvss_score > best[key].cvss_score:
            best[key] = f

    deduped = list(best.values())
    removed = len(findings) - len(deduped)
    logging.info(
        f"[dedup] {len(findings)} → {len(deduped)} уязвимостей (удалено {removed} дублей)"
    )

    # Second pass: fill cvss_score == 0 from the best score for that CVE ID
    # seen across all (possibly different) components.
    cve_best_score: dict[str, float] = {}
    for f in deduped:
        if f.cvss_score > cve_best_score.get(f.cve_id, 0.0):
            cve_best_score[f.cve_id] = f.cvss_score
    filled = 0
    for f in deduped:
        if f.cvss_score == 0.0 and cve_best_score.get(f.cve_id, 0.0) > 0.0:
            f.cvss_score = cve_best_score[f.cve_id]
            filled += 1
    if filled:
        logging.debug(f"[dedup] cvss_score заполнен для {filled} уязвимостей")

    return deduped
