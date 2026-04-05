"""
Оркестратор SBOM-пайплайна.

Шаги:
  1. Генерация SBOM             (generate.py)
  2. Дедупликация компонентов   (dedup.py)
  3. Подпись компонентов        (sign.py)  → app-bom-dedup-signed.json
  4. Сканирование уязвимостей   (scanner/trivy, clair, depcheck)
  5. Дедупликация уязвимостей   (dedup.py)
  6. Слияние уязв. в SBOM       (vuln_merger.py)
  7. Подпись с уязвимостями     (sign.py)  → merged-bom-signed.json
  8. Экспорт отчётов            (exporter.py)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from .config import PipelineConfig
from .constants import (
    APP_BOM_FILE,
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


def run(cfg: PipelineConfig) -> None:
    """Запустить полный пайплайн."""
    cfg.ensure_output_dirs()

    # ------------------------------------------------------------------
    # 1. Генерация SBOM
    # ------------------------------------------------------------------
    app_bom = cfg.output_dir / APP_BOM_FILE

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
        generate.generate_from_dir(cfg.project_dir, app_bom)

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

    # Trivy — filesystem
    all_findings += trivy.scan_filesystem(
        project_dir=cfg.project_dir,
        output_dir=cfg.trivy_dir,
    )
    # Trivy — по SBOM (используем подписанный SBOM без уязвимостей)
    all_findings += trivy.scan_sbom(
        sbom_path=signed_dedup_bom,
        output_dir=cfg.trivy_dir,
    )
    # Dependency-Check
    all_findings += depcheck.scan(
        project_dir=cfg.project_dir,
        output_dir=cfg.depcheck_dir,
        data_dir=cfg.dep_check_data or Path(".dependency-check-data"),
        host_project_dir=cfg.host_project_dir,
        host_output_dir=cfg.host_dep_report_dir,
    )
    # Clair (опционально)
    if not cfg.skip_clair and cfg.image_name:
        all_findings += clair.scan_image(
            image_name=cfg.image_name,
            output_dir=cfg.clair_dir,
            clair_endpoint=cfg.clair_endpoint,
        )

    logging.info(f"[pipeline] Всего уязвимостей из всех сканеров: {len(all_findings)}")

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
        SbomHandler.write_json(sbom_data, signed_bom)

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
) -> None:
    stem = Path(SIGNED_BOM_FILE).stem
    excel_dir = cfg.reports_dir / EXCEL_DIR
    docx_dir = cfg.reports_dir / DOCX_DIR
    odt_dir = cfg.reports_dir / ODT_DIR

    for d in (excel_dir, docx_dir, odt_dir):
        d.mkdir(parents=True, exist_ok=True)

    deps = _extract_dependencies(sbom_data, str(cfg.output_dir / SIGNED_BOM_FILE))
    exporter = Exporter(
        deps,
        vulns=vulns,
        sbom_path=str(cfg.output_dir / SIGNED_BOM_FILE),
        include_bdu=cfg.use_bdu,
    )

    exporter.exportToExcel(str(excel_dir / f"{stem}{EXCEL_EXTENSION}"))
    exporter.exportToDocx(str(docx_dir / f"{stem}{DOCX_EXTENSION}"))
    exporter.exportToOdt(str(odt_dir / f"{stem}{ODT_EXTENSION}"))

    logging.info(f"[pipeline] Отчёты → {cfg.reports_dir}")


def _extract_dependencies(sbom: Dict[str, Any], sbom_path: str) -> List[Dependency]:
    """Извлечь зависимости типа 'library' из SBOM."""
    deps: List[Dependency] = []
    for comp in sbom.get("components", []):
        if comp.get("type") != COMPONENT_TYPE_LIBRARY:
            continue
        try:
            dep = Dependency(
                name=comp.get("name", ""),
                version=comp.get("version", ""),
                depType=(
                    comp.get("properties", [])
                    if isinstance(comp.get("properties"), list)
                    else []
                ),
                purl=comp.get("purl") or "",
                pathToSbom=sbom_path,
            )
            deps.append(dep)
        except Exception as e:
            logging.warning(f"[pipeline] Пропущен компонент: {e}")
    return deps
