"""Дедупликация компонентов и уязвимостей SBOM — чистый Python."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from .vuln_merger import VulnFinding

# Scalar CycloneDX component fields filled from a duplicate when target is empty.
_COMPONENT_SCALAR_FIELDS = (
    "cpe",
    "description",
    "purl",
    "version",
    "bom-ref",
    "name",
    "type",
    "group",
    "scope",
    "copyright",
    "publisher",
    "author",
    "supplier",
    "mime-type",
)


def _normalize_purl(purl: str) -> str:
    """Strip PURL qualifiers/subpath so Clair `?arch=` and plain purls match."""
    if not purl:
        return ""
    base = purl.split("#", 1)[0]
    return base.split("?", 1)[0]


def _fallback_identity(comp: Dict[str, Any]) -> str:
    """Stable identity when PURL is absent: type|group|name@version."""
    ctype = str(comp.get("type") or "")
    group = str(comp.get("group") or "")
    name = str(comp.get("name") or "")
    version = str(comp.get("version") or "")
    return f"{ctype}|{group}|{name}@{version}"


def _component_identity(comp: Dict[str, Any]) -> Optional[str]:
    """
    Canonical dedup key for a component.

    Prefer normalized PURL. Fall back to type|group|name@version.
    Return None when there is no usable identity (do not merge anonymously).
    """
    purl = _normalize_purl(str(comp.get("purl") or ""))
    if purl:
        return f"purl:{purl}"

    name = str(comp.get("name") or "")
    version = str(comp.get("version") or "")
    if not name and not version:
        return None

    return f"nv:{_fallback_identity(comp)}"


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
    for field in _COMPONENT_SCALAR_FIELDS:
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

    # --- hashes (union by alg+content; conflicting digests are retained) ---
    if source.get("hashes"):
        existing_hashes: set[tuple[str, str]] = {
            (str(h.get("alg", "")), str(h.get("content", "")))
            for h in (target.get("hashes") or [])
            if isinstance(h, dict)
        }
        for h in source["hashes"]:
            if not isinstance(h, dict):
                continue
            key = (str(h.get("alg", "")), str(h.get("content", "")))
            if key not in existing_hashes:
                target.setdefault("hashes", []).append(h)
                existing_hashes.add(key)

    # --- externalReferences (union by url+type) ---
    if source.get("externalReferences"):
        existing_refs: set[tuple[Any, Any]] = {
            (r.get("url"), r.get("type"))
            for r in (target.get("externalReferences") or [])
            if isinstance(r, dict)
        }
        for ref in source["externalReferences"]:
            if not isinstance(ref, dict):
                continue
            key = (ref.get("url"), ref.get("type"))
            if key not in existing_refs:
                target.setdefault("externalReferences", []).append(ref)
                existing_refs.add(key)

    # --- nested components: append unique by identity ---
    if source.get("components"):
        target_nested = target.setdefault("components", [])
        nested_keys = {
            _component_identity(c)
            for c in target_nested
            if isinstance(c, dict) and _component_identity(c)
        }
        for child in source["components"]:
            if not isinstance(child, dict):
                target_nested.append(child)
                continue
            child_key = _component_identity(child)
            if child_key and child_key in nested_keys:
                continue
            target_nested.append(child)
            if child_key:
                nested_keys.add(child_key)


def _apply_ref(value: Any, ref_map: Dict[str, str]) -> Any:
    if isinstance(value, str):
        return ref_map.get(value, value)
    return value


def _remap_ref_list(values: List[Any], ref_map: Dict[str, str]) -> List[Any]:
    remapped: list[Any] = []
    seen: set[str] = set()
    for value in values:
        new_val = _apply_ref(value, ref_map)
        marker = new_val if isinstance(new_val, str) else json.dumps(new_val, sort_keys=True)
        if marker in seen:
            continue
        seen.add(str(marker))
        remapped.append(new_val)
    return remapped


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
        ref = _apply_ref(raw_ref, ref_map) if raw_ref else raw_ref

        depends_on = _remap_ref_list(list(dep.get("dependsOn") or []), ref_map)
        # Drop self-edges introduced when a duplicate depended on the survivor
        if isinstance(ref, str):
            depends_on = [c for c in depends_on if c != ref]

        provides = _remap_ref_list(list(dep.get("provides") or []), ref_map)

        if not ref:
            entry = {k: v for k, v in dep.items() if k not in ("dependsOn", "provides")}
            if depends_on:
                entry["dependsOn"] = depends_on
            if provides:
                entry["provides"] = provides
            merged.append(entry)
            continue

        current = by_ref.get(str(ref))
        if current is None:
            current = {k: v for k, v in dep.items() if k not in ("ref", "dependsOn", "provides")}
            current["ref"] = ref
            current["dependsOn"] = []
            if provides:
                current["provides"] = list(provides)
            by_ref[str(ref)] = current
            merged.append(current)
        else:
            # Merge extra fields that the first entry lacked
            for key, value in dep.items():
                if key in ("ref", "dependsOn", "provides"):
                    continue
                if key not in current and value:
                    current[key] = value
            if provides:
                existing_provides = current.setdefault("provides", [])
                for item in provides:
                    if item not in existing_provides:
                        existing_provides.append(item)

        existing_children = current.setdefault("dependsOn", [])
        for child in depends_on:
            if child not in existing_children:
                existing_children.append(child)

    for entry in merged:
        if isinstance(entry, dict) and not entry.get("dependsOn"):
            entry.pop("dependsOn", None)
        if isinstance(entry, dict) and not entry.get("provides"):
            entry.pop("provides", None)

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


def _remap_compositions(
    compositions: List[Any],
    ref_map: Dict[str, str],
) -> None:
    """Переписать bom-ref внутри compositions (assemblies / dependencies / vulnerabilities)."""
    if not ref_map:
        return
    for composition in compositions:
        if not isinstance(composition, dict):
            continue
        for field in ("assemblies", "dependencies", "vulnerabilities"):
            values = composition.get(field)
            if isinstance(values, list):
                composition[field] = _remap_ref_list(values, ref_map)


def _register_aliases(
    identity_to_key: Dict[str, str],
    name_ver_to_key: Dict[str, str],
    key: str,
    comp: Dict[str, Any],
) -> None:
    """Index a kept component under all identities that should resolve to it."""
    identity_to_key[key] = key
    purl = _normalize_purl(str(comp.get("purl") or ""))
    if purl:
        identity_to_key[f"purl:{purl}"] = key

    name = str(comp.get("name") or "")
    version = str(comp.get("version") or "")
    if not (name or version):
        return

    identity_to_key[f"nv:{_fallback_identity(comp)}"] = key
    name_ver = f"{name}@{version}"
    # Prefer a PURL-backed entry for the plain name@version index.
    if purl or name_ver not in name_ver_to_key:
        name_ver_to_key[name_ver] = key


def _resolve_existing_key(
    comp: Dict[str, Any],
    identity: str,
    identity_to_key: Dict[str, str],
    name_ver_to_key: Dict[str, str],
    seen: Dict[str, Dict[str, Any]],
) -> Optional[str]:
    """Find the canonical key of an already-seen duplicate, if any."""
    key = identity_to_key.get(identity)
    if key is not None:
        return key

    name = str(comp.get("name") or "")
    version = str(comp.get("version") or "")
    name_ver = f"{name}@{version}"
    has_purl = bool(_normalize_purl(str(comp.get("purl") or "")))

    if not has_purl:
        # no-PURL may join an earlier PURL twin; do not collapse two no-PURL
        # components that only share name@version but differ by group/type.
        prior = name_ver_to_key.get(name_ver)
        if prior is not None and _normalize_purl(str(seen[prior].get("purl") or "")):
            return prior
        return None

    # PURL joins an earlier no-PURL twin (exact type|group|name@version first)
    prior = identity_to_key.get(f"nv:{_fallback_identity(comp)}")
    if prior is not None and not _normalize_purl(str(seen[prior].get("purl") or "")):
        return prior

    prior = name_ver_to_key.get(name_ver)
    if prior is not None and not _normalize_purl(str(seen[prior].get("purl") or "")):
        return prior

    return None


def _record_ref_map(
    ref_map: Dict[str, str],
    discarded_ref: Any,
    kept_ref: Any,
) -> None:
    if discarded_ref and kept_ref and discarded_ref != kept_ref:
        ref_map[str(discarded_ref)] = str(kept_ref)


def dedup_sbom(input_path: Path, output_path: Path) -> Path:
    """
    Дедуплицировать компоненты CycloneDX SBOM по ключу PURL.

    Если PURL отсутствует, ключом служит «type|group|name@version».
    PURL сравниваются без qualifiers (`?arch=` и т.п.), чтобы Clair и
    генераторы склеивали один и тот же пакет.

    При обнаружении дублей все полезные данные (properties, cpe, hashes,
    licenses, externalReferences, supplier, …) объединяются в одну запись.

    Ссылки bom-ref в dependencies / compositions / vulnerabilities.affects
    переписываются на канонический ref оставшегося компонента.
    """
    with open(input_path, encoding="utf-8") as f:
        sbom: Dict[str, Any] = json.load(f)

    components = sbom.get("components", [])
    if not isinstance(components, list):
        components = []

    seen: Dict[str, Dict[str, Any]] = {}
    order: list[str] = []
    ref_map: Dict[str, str] = {}
    identity_to_key: Dict[str, str] = {}
    name_ver_to_key: Dict[str, str] = {}
    passthrough: list[Any] = []
    anonymous_idx = 0

    for comp in components:
        if not isinstance(comp, dict):
            passthrough.append(comp)
            continue

        identity = _component_identity(comp)
        if identity is None:
            bom_ref = comp.get("bom-ref")
            anon_key = f"anon-ref:{bom_ref}" if bom_ref else f"anon:{anonymous_idx}"
            if not bom_ref:
                anonymous_idx += 1
            if anon_key not in seen:
                seen[anon_key] = comp
                order.append(anon_key)
            else:
                kept = seen[anon_key]
                _merge_component(kept, comp)
                _record_ref_map(ref_map, comp.get("bom-ref"), kept.get("bom-ref"))
            continue

        key = _resolve_existing_key(
            comp, identity, identity_to_key, name_ver_to_key, seen
        )
        if key is None:
            key = identity
            seen[key] = comp
            order.append(key)
            _register_aliases(identity_to_key, name_ver_to_key, key, comp)
            continue

        kept = seen[key]
        discarded_ref = comp.get("bom-ref")
        _merge_component(kept, comp)
        _record_ref_map(ref_map, discarded_ref, kept.get("bom-ref"))
        _register_aliases(identity_to_key, name_ver_to_key, key, kept)

    deduped = [seen[k] for k in order] + passthrough
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
        if isinstance(sbom.get("compositions"), list):
            _remap_compositions(sbom["compositions"], ref_map)
        logging.debug(f"[dedup] Переписано bom-ref: {len(ref_map)} ссылок")

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
        return _normalize_purl(f.component_purl)
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
            name_ver_to_purl[f"{f.component_name}@{f.component_version}"] = _normalize_purl(
                f.component_purl
            )

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
