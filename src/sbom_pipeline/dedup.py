"""Дедупликация компонентов и уязвимостей SBOM — чистый Python."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from .vuln_merger import VulnFinding


def _merge_component(target: Dict[str, Any], source: Dict[str, Any]) -> None:
    """
    Перенести все полезные данные из source в target (in-place).

    Применяется при дедупликации: если один компонент попал в SBOM
    из нескольких источников (cdxgen + Clair и т.п.), все полезные
    свойства объединяются в одну запись.
    """
    # --- properties (union by name+value; CycloneDX допускает повторы имён) ---
    if source.get("properties"):
        target_props: List[Dict[str, str]] = target.setdefault("properties", [])
        existing: set[tuple[str, str]] = {
            (str(p.get("name", "")), str(p.get("value", "")))
            for p in target_props
            if isinstance(p, dict)
        }
        for prop in source["properties"]:
            if not isinstance(prop, dict):
                continue
            key = (str(prop.get("name", "")), str(prop.get("value", "")))
            if key not in existing:
                target_props.append(prop)
                existing.add(key)

    # --- скалярные поля (заполняем только если у target пусто) ---
    for field in ("cpe", "description", "purl", "version", "bom-ref", "name", "type"):
        if not target.get(field) and source.get(field):
            target[field] = source[field]

    # --- licenses (union by JSON-ключ) ---
    if source.get("licenses"):
        existing_lic: set = {
            json.dumps(lic, sort_keys=True)
            for lic in (target.get("licenses") or [])
        }
        for lic in source["licenses"]:
            k = json.dumps(lic, sort_keys=True)
            if k not in existing_lic:
                target.setdefault("licenses", []).append(lic)
                existing_lic.add(k)

    # --- hashes (union by alg) ---
    if source.get("hashes"):
        existing_algs: Dict[str, Any] = {
            str(h["alg"]): h
            for h in (target.get("hashes") or [])
            if isinstance(h, dict) and h.get("alg") is not None
        }
        for h in source["hashes"]:
            if isinstance(h, dict) and h.get("alg") is not None:
                alg = str(h["alg"])
                if alg not in existing_algs:
                    target.setdefault("hashes", []).append(h)
                    existing_algs[alg] = h

    # --- externalReferences (union by url) ---
    if source.get("externalReferences"):
        existing_urls: set = {
            r.get("url")
            for r in (target.get("externalReferences") or [])
            if isinstance(r, dict)
        }
        for ref in source["externalReferences"]:
            if isinstance(ref, dict) and ref.get("url") not in existing_urls:
                target.setdefault("externalReferences", []).append(ref)
                existing_urls.add(ref.get("url"))


def _remap_dependencies(
    dependencies: List[Any],
    ref_map: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Переписать dependencies с учётом слитых bom-ref и объединить по ref."""
    if not dependencies:
        return []

    merged: list[dict[str, Any]] = []
    by_ref: dict[str, dict[str, Any]] = {}

    for dep in dependencies:
        if not isinstance(dep, dict):
            continue

        raw_ref = dep.get("ref")
        ref = ref_map.get(raw_ref, raw_ref) if raw_ref else raw_ref

        depends_on: list[Any] = []
        for child in dep.get("dependsOn") or []:
            depends_on.append(ref_map.get(child, child) if isinstance(child, str) else child)

        if not ref:
            entry = {k: v for k, v in dep.items() if k != "dependsOn"}
            if depends_on:
                # de-dupe while preserving order
                seen_child: set[str] = set()
                unique_children: list[Any] = []
                for child in depends_on:
                    key = child if isinstance(child, str) else json.dumps(child, sort_keys=True)
                    if key not in seen_child:
                        seen_child.add(str(key))
                        unique_children.append(child)
                entry["dependsOn"] = unique_children
            merged.append(entry)
            continue

        current = by_ref.get(ref)
        if current is None:
            current = {"ref": ref, "dependsOn": []}
            by_ref[ref] = current
            merged.append(current)

        existing_children = current.setdefault("dependsOn", [])
        for child in depends_on:
            if child not in existing_children:
                existing_children.append(child)

    # Drop empty dependsOn arrays for cleaner CycloneDX
    for entry in merged:
        if isinstance(entry, dict) and not entry.get("dependsOn"):
            entry.pop("dependsOn", None)

    return merged


def _remap_vulnerability_refs(
    vulnerabilities: List[Any],
    ref_map: Dict[str, str],
) -> None:
    """Обновить affects[].ref у существующих уязвимостей после слияния компонентов."""
    if not ref_map:
        return
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        for affect in vuln.get("affects") or []:
            if isinstance(affect, dict) and affect.get("ref") in ref_map:
                affect["ref"] = ref_map[affect["ref"]]


def dedup_sbom(input_path: Path, output_path: Path) -> Path:
    """
    Дедуплицировать компоненты CycloneDX SBOM по ключу PURL.

    Если PURL отсутствует, ключом служит «name@version».
    При обнаружении дублей все полезные данные (properties, cpe, hashes,
    licenses, externalReferences) объединяются в одну запись, чтобы не
    потерять сведения из разных источников (cdxgen, Clair и т.д.).

    Ссылки bom-ref в dependencies / vulnerabilities.affects переписываются
    на канонический ref оставшегося компонента.
    """
    with open(input_path, encoding="utf-8") as f:
        sbom: Dict[str, Any] = json.load(f)

    components = sbom.get("components", [])
    seen: Dict[str, Dict[str, Any]] = {}
    order: list[str] = []
    ref_map: Dict[str, str] = {}

    for comp in components:
        if not isinstance(comp, dict):
            continue
        purl = comp.get("purl", "")
        key = purl if purl else f"{comp.get('name', '')}@{comp.get('version', '')}"
        if key not in seen:
            seen[key] = comp
            order.append(key)
        else:
            kept = seen[key]
            discarded_ref = comp.get("bom-ref")
            # Merge first so kept may gain a bom-ref from the duplicate
            _merge_component(kept, comp)
            kept_ref = kept.get("bom-ref")
            if discarded_ref and kept_ref and discarded_ref != kept_ref:
                ref_map[str(discarded_ref)] = str(kept_ref)

    deduped = [seen[k] for k in order]
    removed = len(components) - len(deduped)
    logging.info(
        f"[dedup] {len(components)} → {len(deduped)} компонентов (удалено {removed} дублей)"
    )

    sbom["components"] = deduped

    if ref_map:
        if isinstance(sbom.get("dependencies"), list):
            sbom["dependencies"] = _remap_dependencies(sbom["dependencies"], ref_map)
        if isinstance(sbom.get("vulnerabilities"), list):
            _remap_vulnerability_refs(sbom["vulnerabilities"], ref_map)
        logging.debug(f"[dedup] Переписано bom-ref: {len(ref_map)} ссылок")

    # Пересчитать metadata.component count если есть
    if "metadata" in sbom and isinstance(sbom["metadata"].get("component"), dict):
        pass  # не трогаем — cdxgen управляет metadata.component

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)

    logging.info(f"[dedup] Записан: {output_path}")
    return output_path


def _component_key(f: "VulnFinding", name_ver_to_purl: Dict[str, str]) -> str:
    """Канонический ключ компонента: PURL, иначе name@version (с подстановкой PURL)."""
    if f.component_purl:
        return f.component_purl
    name_ver = f"{f.component_name}@{f.component_version}"
    return name_ver_to_purl.get(name_ver, name_ver)


def _merge_finding_fields(target: "VulnFinding", source: "VulnFinding") -> None:
    """Дополнить выбранную запись непустыми полями из дубликата."""
    if not target.fixed_version and source.fixed_version:
        target.fixed_version = source.fixed_version
    if not target.recommendation and source.recommendation:
        target.recommendation = source.recommendation
    if not target.acceptability_status and source.acceptability_status:
        target.acceptability_status = source.acceptability_status
    if not target.description and source.description:
        target.description = source.description
    if not target.bdu_id and source.bdu_id:
        target.bdu_id = source.bdu_id
    if not target.component_purl and source.component_purl:
        target.component_purl = source.component_purl
    # Prefer a more informative severity when current is UNKNOWN/empty
    if (not target.severity or target.severity.upper() == "UNKNOWN") and source.severity:
        target.severity = source.severity


def dedup_vulns(findings: List["VulnFinding"]) -> List["VulnFinding"]:
    """
    Дедуплицировать список VulnFinding по ключу «CVE-ID :: компонент».

    Если несколько сканеров обнаружили одну и ту же уязвимость в одном
    компоненте — оставляем запись с наибольшим cvss_score; при равном
    балле — первую встреченную. Непустые поля (fixed_version, recommendation
    и т.д.) из остальных дублей переносятся в выбранную запись.

    Finding без PURL сопоставляется с finding, у которого есть PURL при
    совпадении name@version (типичный случай Clair + Trivy).

    После дедупликации заполняем cvss_score == 0.0 используя лучший
    известный балл для этого CVE из других компонентов (cross-component
    propagation).
    """
    name_ver_to_purl: dict[str, str] = {}
    for f in findings:
        if f.component_purl:
            name_ver_to_purl[f"{f.component_name}@{f.component_version}"] = f.component_purl

    best: dict[str, "VulnFinding"] = {}

    for f in findings:
        comp_key = _component_key(f, name_ver_to_purl)
        key = f"{f.cve_id}::{comp_key}"
        if key not in best:
            best[key] = f
        elif f.cvss_score > best[key].cvss_score:
            _merge_finding_fields(f, best[key])
            best[key] = f
        else:
            _merge_finding_fields(best[key], f)

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
