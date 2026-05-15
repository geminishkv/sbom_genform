"""
Оркестратор SBOM-пайплайна.

Шаги:
  1. Генерация SBOM через cdxgen + syft + обогащение пакетами из Clair  (generate.py, scanner/clair.py)
  2. Дедупликация компонентов                                           (dedup.py)  ← объединяет cdxgen + syft + Clair
  3. Подпись SBOM без уязвимостей                                       (sign.py)  → app-bom-dedup-signed.json
  4. Сканирование уязвимостей                                           (scanner/trivy, depcheck, clair — повторное использование отчёта)
  5. Дедупликация уязвимостей                                           (dedup.py)
  6. Слияние уязв. в SBOM                                               (vuln_merger.py)
  7. Подпись SBOM с уязвимостями                                        (sign.py)  → merged-bom-signed.json
  8. Экспорт отчётов                                                    (exporter.py)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import PipelineConfig
from .constants import (
    APP_BOM_FILE,
    APP_BOM_CDXGEN_FILE,
    APP_BOM_SYFT_FILE,
    CYCLONEDX_FORMAT,
    CYCLONEDX_SPEC_VERSION,
    DEDUP_BOM_FILE,
    SIGNED_DEDUP_BOM_FILE,
    SIGNED_BOM_FILE,
    EXCEL_DIR,
    ODT_DIR,
    DOCX_DIR,
    EXCEL_EXTENSION,
    ODT_EXTENSION,
    DOCX_EXTENSION,
    COMPONENT_TYPE_LIBRARY,
)
from . import generate, dedup, sign
from .scanner import trivy, clair, depcheck
from .vuln_merger import VulnFinding, merge_vulns_into_sbom, save_vuln_report
from .dependency import Dependency
from .exporter import Exporter
from .sbom_handler import SbomHandler


def _write_empty_sbom(path: Path, image_name: str) -> None:
    """Создать минимальный пустой SBOM CycloneDX (для режима только-образ)."""
    data: Dict[str, Any] = {
        "bomFormat": CYCLONEDX_FORMAT,
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "components": [],
        "metadata": {
            "component": {
                "type": "container",
                "name": image_name,
            }
        },
    }
    SbomHandler.write_json(data, path)


def scan_only(sbom_path: Path, cfg: PipelineConfig) -> None:
    """Сканирование уязвимостей для готового SBOM (шаги 4–8).

    Шаги: 
        1. Сканирование
            Используется переданный *sbom_path*.
            Включает Clair-сканирование образа (если настроено), Trivy по файловой системе и по SBOM, Dependency-Check.
        2. Дедупликация уязвимостей
        3. Слияние уязвимостей в SBOM
        4. Подпись SBOM с уязвимостями
        5. Экспорт отчётов (только листы уязвимостей)
    """
    cfg.ensure_output_dirs()

    # ------------------------------------------------------------------
    # 1. Сканирование уязвимостей
    # ------------------------------------------------------------------
    all_findings: List[VulnFinding] = []

    # Clair: запустить сканирование и разобрать уязвимости из отчёта.
    if not cfg.skip_clair and not cfg.image_name:
        logging.warning(
            "[clair] SKIP_CLAIR=false, но IMAGE_NAME не задан — "
            "сканирование Clair пропущено. "
            "Укажите переменную окружения IMAGE_NAME=<image>:<tag>."
        )
    _clair_report_file: Optional[Path] = None
    if not cfg.skip_clair and cfg.image_name:
        _clair_report_file = clair.run_scan_report(
            image_name=cfg.image_name,
            output_dir=cfg.clair_dir,
            clair_endpoint=cfg.clair_endpoint,
        )
        if _clair_report_file is not None:
            all_findings += clair.parse_report_findings(
                report_file=_clair_report_file,
                clair_endpoint=cfg.clair_endpoint,
                nvd_api_key=cfg.nvd_api_key or "",
            )

    # Trivy — filesystem (только если project_dir задан явно)
    if cfg.project_dir is not None:
        all_findings += trivy.scan_filesystem(
            project_dir=cfg.project_dir,
            output_dir=cfg.trivy_dir,
        )
    else:
        logging.info("[pipeline] project_dir не задан — Trivy FS пропущен")
    # Trivy — по SBOM
    all_findings += trivy.scan_sbom(
        sbom_path=sbom_path,
        output_dir=cfg.trivy_dir,
    )
    # Dependency-Check (только если project_dir задан явно)
    if cfg.project_dir is not None:
        all_findings += depcheck.scan(
            project_dir=cfg.project_dir,
            output_dir=cfg.depcheck_dir,
            data_dir=cfg.dep_check_data or Path(".dependency-check-data"),
            host_project_dir=cfg.host_project_dir,
            host_output_dir=cfg.host_dep_report_dir,
            host_data_dir=cfg.host_dep_check_data,
            nvd_api_key=cfg.nvd_api_key,
        )
    else:
        logging.info("[pipeline] project_dir не задан — Dependency-Check пропущен")

    logging.info(f"[pipeline] Всего уязвимостей из всех сканеров: {len(all_findings)}")

    # Cross-populate CVSS scores
    _cve_score: Dict[str, float] = {}
    for _f in all_findings:
        if _f.cvss_score and _f.cve_id not in _cve_score:
            _cve_score[_f.cve_id] = _f.cvss_score
        elif _f.cvss_score and _f.cvss_score > _cve_score.get(_f.cve_id, 0.0):
            _cve_score[_f.cve_id] = _f.cvss_score
    _filled = 0
    for _f in all_findings:
        if _f.cvss_score == 0.0 and _f.cve_id in _cve_score:
            _f.cvss_score = _cve_score[_f.cve_id]
            _filled += 1
    if _filled:
        logging.info(f"[pipeline] CVSS cross-populated для {_filled} уязвимостей")

    # ------------------------------------------------------------------
    # 2. Дедупликация уязвимостей
    # ------------------------------------------------------------------
    all_findings = dedup.dedup_vulns(all_findings)

    # ------------------------------------------------------------------
    # 3. Слияние уязвимостей в SBOM
    # ------------------------------------------------------------------
    with open(sbom_path, encoding="utf-8") as f:
        sbom_data: Dict[str, Any] = json.load(f)

    if all_findings:
        sbom_data = merge_vulns_into_sbom(
            sbom_data,
            all_findings,
            enable_bdu=cfg.use_bdu,
        )
        save_vuln_report(all_findings, cfg.output_dir / "vulns-normalized.json")

    # ------------------------------------------------------------------
    # 4. Подпись SBOM с уязвимостями
    # ------------------------------------------------------------------
    signed_bom = cfg.output_dir / SIGNED_BOM_FILE
    SbomHandler.write_json(sbom_data, signed_bom)
    sign.sign_sbom(signed_bom, signed_bom)

    logging.info(f"[pipeline] SBOM с уязвимостями: {signed_bom}")

    # ------------------------------------------------------------------
    # 5. Экспорт отчётов (только листы уязвимостей)
    # ------------------------------------------------------------------
    logging.info("[pipeline] Экспорт отчётов уязвимостей...")
    _export_reports(sbom_data, all_findings, cfg, include_components=False)

    logging.info("[pipeline] Сканирование завершено.")


def gen_sbom(cfg: PipelineConfig) -> None:
    """Генерация SBOM (шаги 1–3) + экспорт листа компонентов (шаг 8).

    Шаги:
        1. Генерация SBOM из источника + обогащение пакетами Clair (если настроено).
        2. Дедупликация компонентов.
        3. Подпись SBOM без уязвимостей → app-bom-dedup-signed.json.
        4. Экспорт отчётов (только лист компонентов).
    """
    cfg.ensure_output_dirs()

    # ------------------------------------------------------------------
    # 1. Генерация SBOM
    # ------------------------------------------------------------------
    app_bom = cfg.output_dir / APP_BOM_FILE

    _has_code = cfg.project_dir is not None or cfg.git_url is not None
    _has_image = not cfg.skip_clair and bool(cfg.image_name)

    if not _has_code and not _has_image:
        raise ValueError(
            "Не задан ни один источник. Укажите --path/--url (исходный код) "
            "и/или --image --clair (образ контейнера)."
        )

    if _has_code:
        if cfg.source in ("github", "gitlab"):
            if not cfg.git_url:
                raise ValueError(f"--url обязателен для source={cfg.source}")
            logging.info(f"[pipeline] Источник: {cfg.source} → {cfg.git_url}")
            generate.generate_from_git(
                url=cfg.git_url,
                output_file=app_bom,
                token=cfg.git_token,
                branch=cfg.git_branch,
            )
        else:
            logging.info(f"[pipeline] Источник: local → {cfg.project_dir}")
            assert cfg.project_dir is not None
            generate.generate_from_dir(cfg.project_dir, app_bom)
    else:
        # Режим только-образ: создать пустой SBOM-каркас для обогащения Clair
        logging.info("[pipeline] Исходный код не задан — создан пустой SBOM для образа")
        assert cfg.image_name is not None
        _write_empty_sbom(app_bom, cfg.image_name)

    if not cfg.skip_clair and not cfg.image_name:
        logging.warning(
            "[clair] SKIP_CLAIR=false, но IMAGE_NAME не задан — "
            "обогащение Clair пропущено. "
            "Укажите переменную окружения IMAGE_NAME=<image>:<tag>."
        )
    if not cfg.skip_clair and cfg.image_name:
        _clair_report_file = clair.run_scan_report(
            image_name=cfg.image_name,
            output_dir=cfg.clair_dir,
            clair_endpoint=cfg.clair_endpoint,
        )
        if _clair_report_file is not None:
            with open(app_bom, encoding="utf-8") as _fh:
                _app_bom_data = json.load(_fh)
            _app_bom_data = clair.enrich_sbom_with_clair_packages(
                _app_bom_data,
                _clair_report_file,
                image_name=cfg.image_name,
            )
            SbomHandler.write_json(_app_bom_data, app_bom)
            logging.info(f"[pipeline] SBOM обогащён пакетами из Clair → {app_bom}")

    # ------------------------------------------------------------------
    # 2. Дедупликация компонентов
    # ------------------------------------------------------------------
    dedup_bom = cfg.output_dir / DEDUP_BOM_FILE
    dedup.dedup_sbom(app_bom, dedup_bom)

    # ------------------------------------------------------------------
    # 3. Подпись SBOM без уязвимостей (SHA-256)
    # ------------------------------------------------------------------
    signed_dedup_bom = cfg.output_dir / SIGNED_DEDUP_BOM_FILE
    sign.sign_sbom(dedup_bom, signed_dedup_bom)

    logging.info(f"[pipeline] SBOM без уязвимостей: {signed_dedup_bom}")

    # ------------------------------------------------------------------
    # 4. Экспорт отчётов (только лист компонентов)
    # ------------------------------------------------------------------
    logging.info("[pipeline] Экспорт отчётов компонентов...")
    with open(signed_dedup_bom, encoding="utf-8") as f:
        sbom_data = json.load(f)
    _export_reports(sbom_data, [], cfg, include_vulns=False, sbom_file=SIGNED_DEDUP_BOM_FILE)

    logging.info("[pipeline] Генерация SBOM завершена.")


def run(cfg: PipelineConfig) -> None:
    """Запустить полный пайплайн."""
    cfg.ensure_output_dirs()

    if not cfg.use_cdxgen and not cfg.use_syft:
        raise ValueError("Нужно включить хотя бы один генератор SBOM: cdxgen или syft.")

    # ------------------------------------------------------------------
    # 1. Генерация SBOM
    # ------------------------------------------------------------------
    app_bom = cfg.output_dir / APP_BOM_FILE
    cdxgen_bom = cfg.output_dir / APP_BOM_CDXGEN_FILE
    syft_bom = cfg.output_dir / APP_BOM_SYFT_FILE

    _has_code = cfg.project_dir is not None or cfg.git_url is not None
    _has_image = not cfg.skip_clair and bool(cfg.image_name)

    if not _has_code and not _has_image:
        raise ValueError(
            "Не задан ни один источник. Укажите --path/--url (исходный код) "
            "и/или --image --clair (образ контейнера)."
        )

    if _has_code:
        if cfg.source in ("github", "gitlab"):
            if not cfg.git_url:
                raise ValueError(
                    f"--url обязателен для source={cfg.source}"
                )
            logging.info(f"[pipeline] Источник: {cfg.source} → {cfg.git_url}")
            generate.generate_from_git(
                url=cfg.git_url,
                output_file=app_bom,
                token=cfg.git_token,
                branch=cfg.git_branch,
            )
        else:
            logging.info(f"[pipeline] Источник: local → {cfg.project_dir}")
            assert cfg.project_dir is not None
            generate.generate_from_dir(cfg.project_dir, app_bom)
    else:
        # Режим только-образ: создать пустой SBOM-каркас для обогащения Clair
        logging.info("[pipeline] Исходный код не задан — создан пустой SBOM для образа")
        assert cfg.image_name is not None
        _write_empty_sbom(app_bom, cfg.image_name)

    # Clair: получить пакеты образа и добавить их в SBOM.
    # Уязвимости на этом этапе не разбираются — отчёт будет повторно
    # использован на шаге 4.
    _clair_report_file: Optional[Path] = None
    if not cfg.skip_clair and not cfg.image_name:
        logging.warning(
                "[clair] SKIP_CLAIR=false, но IMAGE_NAME не задан — "
                "сканирование Clair пропущено. "
                "Укажите переменную окружения IMAGE_NAME=<image>:<tag>."
            )
    if not cfg.skip_clair and cfg.image_name:
        sanitized = cfg.image_name.replace(":", "_").replace("/", "_")
        _clair_report_file = clair.run_scan_report(
            image_name=cfg.image_name,
            output_dir=cfg.clair_dir,
            clair_endpoint=cfg.clair_endpoint,
        )
        if _clair_report_file is not None:
            with open(app_bom, encoding="utf-8") as _fh:
                _app_bom_data = json.load(_fh)
            _app_bom_data = clair.enrich_sbom_with_clair_packages(
                _app_bom_data,
                _clair_report_file,
                image_name=cfg.image_name,
            )
            SbomHandler.write_json(_app_bom_data, app_bom)
            logging.info(f"[pipeline] SBOM обогащён пакетами из Clair → {app_bom}")

    # ------------------------------------------------------------------
    # 2. Дедупликация компонентов
    # ------------------------------------------------------------------
    dedup_bom = cfg.output_dir / DEDUP_BOM_FILE
    dedup.dedup_sbom(app_bom, dedup_bom)

    # ------------------------------------------------------------------
    # 3. Подпись SBOM без уязвимостей (SHA-256)
    # ------------------------------------------------------------------
    signed_dedup_bom = cfg.output_dir / SIGNED_DEDUP_BOM_FILE
    sign.sign_sbom(dedup_bom, signed_dedup_bom)

    # ------------------------------------------------------------------
    # 4. Сканирование уязвимостей
    # ------------------------------------------------------------------
    all_findings: List[VulnFinding] = []

    # Clair: разобрать уязвимости из уже сохранённого отчёта (clairctl не
    # запускается повторно — используем файл, полученный на этапе 1).
    if _clair_report_file is not None:
        all_findings += clair.parse_report_findings(
            report_file=_clair_report_file,
            clair_endpoint=cfg.clair_endpoint,
            nvd_api_key=cfg.nvd_api_key or "",
        )

    # Trivy — filesystem (только если project_dir задан явно)
    if cfg.project_dir is not None:
        all_findings += trivy.scan_filesystem(
            project_dir=cfg.project_dir,
            output_dir=cfg.trivy_dir,
        )
    else:
        logging.info("[pipeline] project_dir не задан — Trivy FS пропущен")
    # Trivy — по SBOM (используем подписанный SBOM без уязвимостей)
    all_findings += trivy.scan_sbom(
        sbom_path=signed_dedup_bom,
        output_dir=cfg.trivy_dir,
    )
    # Dependency-Check (только если project_dir задан явно)
    if cfg.project_dir is not None:
        all_findings += depcheck.scan(
            project_dir=cfg.project_dir,
            output_dir=cfg.depcheck_dir,
            data_dir=cfg.dep_check_data or Path(".dependency-check-data"),
            host_project_dir=cfg.host_project_dir,
            host_output_dir=cfg.host_dep_report_dir,
            host_data_dir=cfg.host_dep_check_data,
            nvd_api_key=cfg.nvd_api_key,
        )
    else:
        logging.info("[pipeline] project_dir не задан — Dependency-Check пропущен")

    logging.info(f"[pipeline] Всего уязвимостей из всех сканеров: {len(all_findings)}")

    # Cross-populate CVSS scores: build a CVE→best_score index from every
    # finding that already has a non-zero score, then apply it to any
    # finding that still has score == 0.0.  This fills in Clair findings
    # whose NVD enricher is not configured, using data from Trivy/depcheck.
    _cve_score: Dict[str, float] = {}
    for _f in all_findings:
        if _f.cvss_score and _f.cve_id not in _cve_score:
            _cve_score[_f.cve_id] = _f.cvss_score
        elif _f.cvss_score and _f.cvss_score > _cve_score.get(_f.cve_id, 0.0):
            _cve_score[_f.cve_id] = _f.cvss_score
    _filled = 0
    for _f in all_findings:
        if _f.cvss_score == 0.0 and _f.cve_id in _cve_score:
            _f.cvss_score = _cve_score[_f.cve_id]
            _filled += 1
    if _filled:
        logging.info(f"[pipeline] CVSS cross-populated для {_filled} уязвимостей")

    # ------------------------------------------------------------------
    # 5. Дедупликация уязвимостей
    # ------------------------------------------------------------------
    all_findings = dedup.dedup_vulns(all_findings)

    # ------------------------------------------------------------------
    # 6. Слияние уязвимостей в SBOM
    # ------------------------------------------------------------------
    with open(dedup_bom, encoding="utf-8") as f:
        sbom_data: Dict[str, Any] = json.load(f)

    if all_findings:
        sbom_data = merge_vulns_into_sbom(
            sbom_data,
            all_findings,
            enable_bdu=cfg.use_bdu,
        )

        # Сохранить нормализованный vuln-dump
        save_vuln_report(all_findings, cfg.output_dir / "vulns-normalized.json")

    # ------------------------------------------------------------------
    # 7. Подпись SBOM с уязвимостями
    # ------------------------------------------------------------------
    signed_bom = cfg.output_dir / SIGNED_BOM_FILE
    SbomHandler.write_json(sbom_data, signed_bom)
    sign.sign_sbom(signed_bom, signed_bom)

    logging.info(f"[pipeline] SBOM без уязвимостей: {signed_dedup_bom}")
    logging.info(f"[pipeline] SBOM с уязвимостями:  {signed_bom}")

    # ------------------------------------------------------------------
    # 8. Экспорт отчётов
    # ------------------------------------------------------------------
    logging.info("[pipeline] Экспорт отчётов...")

    _export_reports(sbom_data, all_findings, cfg)

    logging.info("[pipeline] Пайплайн завершён.")


def format_sboms(sbom_dir: Path, reports_dir: Path) -> None:
    """
    Ручной режим: форматировать все *.json из sbom_dir в reports_dir.
    Аналог старого manual_formatter.py.
    """
    handler = SbomHandler(sbom_dir)
    if not handler.sboms_list:
        logging.warning(f"[format] Не найдено SBOM в {sbom_dir}")
        return

    for sbom_path in handler.sboms_list:
        sbom_data = handler.readJson(sbom_path)
        if sbom_data is None:
            continue
        deps = _extract_dependencies(sbom_data, str(sbom_path))
        stem = sbom_path.stem
        exporter = Exporter(deps, sbom_path=str(sbom_path))
        exporter.exportToExcel(str(reports_dir / EXCEL_DIR / f"{stem}{EXCEL_EXTENSION}"))
        exporter.exportToDocx(str(reports_dir / DOCX_DIR / f"{stem}{DOCX_EXTENSION}"))
        exporter.exportToOdt(str(reports_dir / ODT_DIR / f"{stem}{ODT_EXTENSION}"))

    logging.info(f"[format] Обработано {len(handler.sboms_list)} SBOM")


# ------------------------------------------------------------------
# Внутренние функции
# ------------------------------------------------------------------

def _export_reports(
    sbom_data: Dict[str, Any],
    vulns: List[VulnFinding],
    cfg: PipelineConfig,
    include_components: bool = True,
    include_vulns: bool = True,
    sbom_file: str = SIGNED_BOM_FILE,
) -> None:
    stem = Path(sbom_file).stem
    excel_dir = cfg.reports_dir / EXCEL_DIR
    docx_dir = cfg.reports_dir / DOCX_DIR
    odt_dir = cfg.reports_dir / ODT_DIR

    for d in (excel_dir, docx_dir, odt_dir):
        d.mkdir(parents=True, exist_ok=True)

    deps = _extract_dependencies(sbom_data, str(cfg.output_dir / sbom_file)) if include_components else []
    exporter = Exporter(
        deps,
        vulns=vulns,
        sbom_path=str(cfg.output_dir / sbom_file),
        include_bdu=cfg.use_bdu,
    )

    exporter.exportToExcel(str(excel_dir / f"{stem}{EXCEL_EXTENSION}"), include_components=include_components, include_vulns=include_vulns)
    exporter.exportToDocx(str(docx_dir / f"{stem}{DOCX_EXTENSION}"), include_components=include_components, include_vulns=include_vulns)
    exporter.exportToOdt(str(odt_dir / f"{stem}{ODT_EXTENSION}"), include_components=include_components, include_vulns=include_vulns)

    logging.info(f"[pipeline] Отчёты → {cfg.reports_dir}")


def _extract_dependencies(sbom: Dict[str, Any], sbom_path: str) -> List[Dependency]:
    """Извлечь зависимости типа 'library' из SBOM."""
    deps: List[Dependency] = []

    # Container image from SBOM metadata (used as fallback when component has no own property)
    metadata_comp = sbom.get("metadata", {}).get("component", {})
    metadata_image = (
        metadata_comp.get("name", "")
        if metadata_comp.get("type") == "container"
        else ""
    )

    for comp in sbom.get("components", []):
        if comp.get("type") != COMPONENT_TYPE_LIBRARY:
            continue
        try:
            props = {
                p.get("name", ""): p.get("value", "")
                for p in (comp.get("properties") or [])
                if isinstance(p, dict)
            }
            # depType: collect only string-valued property names/values
            # (the full properties list contains dicts, not type strings)
            raw_props = comp.get("properties") or []
            dep_type_strings: List[str] = [
                p.get("value", "")
                for p in raw_props
                if isinstance(p, dict) and isinstance(p.get("value"), str)
            ]
            # Per-component container_image property (set by Clair enrichment) takes
            # priority; fall back to the image name from SBOM metadata.
            container_image = _find_prop(
                props,
                ("container_image", "container-image", "containerImage"),
            ) or metadata_image
            dep = Dependency(
                name=comp.get("name", ""),
                version=comp.get("version", ""),
                depType=dep_type_strings,
                purl=comp.get("purl") or "",
                pathToSbom=sbom_path,
                package_type=_purl_type(comp.get("purl") or ""),
                attack_surface=_find_prop(
                    props,
                    ("attack-surface", "attack_surface", "attackSurface", "isAttackSurface"),
                ),
                security_function=_find_prop(
                    props,
                    ("security-function", "security_function", "securityFunction", "isSecurityFunction"),
                ),
                container_image=container_image,
                container_role=_find_prop(
                    props,
                    ("container-role", "container_role", "containerRole", "cdx:docker:layer", "layer"),
                ),
                os_distribution=_find_prop(
                    props,
                    ("os_distribution", "os-distribution", "osDistribution"),
                ),
            )
            deps.append(dep)
        except Exception as e:
            logging.warning(f"[pipeline] Пропущен компонент: {e}")
    return deps


def _purl_type(purl: str) -> str:
    """Extract ecosystem type from a PURL string (pkg:<type>/...)."""
    if purl.startswith("pkg:"):
        segment = purl[4:].split("/")[0].split("@")[0].split("?")[0]
        return segment
    return ""


def _find_prop(props: Dict[str, str], keys: tuple) -> str:
    """Return value of the first matching key from a properties dict."""
    for key in keys:
        if key in props:
            return props[key]
    return ""
