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

import concurrent.futures
import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

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


def _run_scanners_parallel(
    tasks: list[tuple[str, Callable[[], List[VulnFinding]]]],
) -> List[VulnFinding]:
    """
    Запустить задачи сканирования параллельно в пуле потоков.

    Каждая задача — пара (label, callable), где callable возвращает
    List[VulnFinding] и не разделяет изменяемое состояние с другими задачами.
    Результаты собираются только после завершения всех Future, поэтому
    итоговый список формируется в главном потоке без гонки данных.
    Исключение внутри задачи логируется и не прерывает остальные.
    """
    if not tasks:
        return []
    combined: List[VulnFinding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        futures: dict[concurrent.futures.Future[List[VulnFinding]], str] = {
            executor.submit(fn): label for label, fn in tasks
        }
        for future in concurrent.futures.as_completed(futures):
            label = futures[future]
            try:
                findings = future.result()
                combined.extend(findings)
                logging.info("[pipeline] [%s] найдено %d уязвимостей", label, len(findings))
            except Exception as exc:
                logging.error("[pipeline] [%s] ошибка сканирования: %s", label, exc)
    return combined


def scan_only(sbom_path: Optional[Path], cfg: PipelineConfig) -> None:
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

    if sbom_path is None:
        if cfg.skip_clair or not cfg.image_name:
            raise ValueError(
                "Укажите путь к SBOM или контейнерный образ через --clair --image."
            )
        sbom_path = cfg.output_dir / APP_BOM_FILE
        _write_empty_sbom(sbom_path, cfg.image_name)
        logging.info("[pipeline] SBOM не задан — создан пустой SBOM для образа: %s", sbom_path)

    # ------------------------------------------------------------------
    # 1. Сканирование уязвимостей
    # ------------------------------------------------------------------
    if not cfg.nvd_api_key:
        logging.error(
            "[pipeline] NVD_API_KEY не задан — Dependency-Check будет работать "
            "без аутентификации (сильно ограниченный rate-limit NVD API). "
            "Укажите переменную окружения NVD_API_KEY=<token>. "
            "Получить токен: https://nvd.nist.gov/developers/request-an-api-key"
        )

    # Собираем задачи сканирования — они будут запущены параллельно.
    if not cfg.skip_clair and not cfg.image_name:
        logging.warning(
            "[clair] SKIP_CLAIR=false, но IMAGE_NAME не задан — "
            "сканирование Clair пропущено. "
            "Укажите переменную окружения IMAGE_NAME=<image>:<tag>."
        )

    _scanner_tasks: list[tuple[str, Callable[[], List[VulnFinding]]]] = []

    if not cfg.skip_clair and cfg.image_name:
        _ci = cfg.image_name
        _cd = cfg.clair_dir
        _ce = cfg.clair_endpoint
        _nk = cfg.nvd_api_key or ""
        _nvd_cache = cfg.nvd_cache_dir

        def _task_clair_scan() -> List[VulnFinding]:
            report = clair.run_scan_report(image_name=_ci, output_dir=_cd, clair_endpoint=_ce)
            if report is None:
                return []
            return clair.parse_report_findings(
                report_file=report,
                clair_endpoint=_ce,
                nvd_api_key=_nk,
                nvd_cache_dir=_nvd_cache,
            )

        _scanner_tasks.append(("clair", _task_clair_scan))

    if cfg.project_dir is not None:
        _pd = cfg.project_dir
        _td = cfg.trivy_dir

        def _task_trivy_fs() -> List[VulnFinding]:
            return trivy.scan_filesystem(project_dir=_pd, output_dir=_td)

        _scanner_tasks.append(("trivy-fs", _task_trivy_fs))
    else:
        logging.info("[pipeline] project_dir не задан — Trivy FS пропущен")

    _sbom = sbom_path
    _tds = cfg.trivy_dir

    def _task_trivy_sbom() -> List[VulnFinding]:
        return trivy.scan_sbom(sbom_path=_sbom, output_dir=_tds)

    _scanner_tasks.append(("trivy-sbom", _task_trivy_sbom))

    if cfg.project_dir is not None:
        _pd2 = cfg.project_dir
        _dd = cfg.depcheck_dir
        _dcd = cfg.dep_check_data or Path(".dependency-check-data")
        _hpd = cfg.host_project_dir
        _hdr = cfg.host_dep_report_dir
        _hdd = cfg.host_dep_check_data
        _nk2 = cfg.nvd_api_key

        def _task_depcheck() -> List[VulnFinding]:
            return depcheck.scan(
                project_dir=_pd2, output_dir=_dd, data_dir=_dcd,
                host_project_dir=_hpd, host_output_dir=_hdr, host_data_dir=_hdd,
                nvd_api_key=_nk2,
            )

        _scanner_tasks.append(("dependency-check", _task_depcheck))
    else:
        logging.info("[pipeline] project_dir не задан — Dependency-Check пропущен")

    all_findings = _run_scanners_parallel(_scanner_tasks)
    logging.info("[pipeline] Всего уязвимостей из всех сканеров: %d", len(all_findings))

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
            bdu_cache_dir=cfg.bdu_cache_dir,
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
                raise ValueError(f"--url обязателен для source={cfg.source}")
            logging.info(f"[pipeline] Источник: {cfg.source} → {cfg.git_url}")
            generate.generate_from_git(
                url=cfg.git_url,
                output_file=app_bom,
                token=cfg.git_token,
                branch=cfg.git_branch,
                use_cdxgen=cfg.use_cdxgen,
                use_syft=cfg.use_syft,
                cdxgen_output=cdxgen_bom,
                syft_output=syft_bom,
            )
        else:
            logging.info(f"[pipeline] Источник: local → {cfg.project_dir}")
            if cfg.project_dir is None:
                raise RuntimeError("project_dir не задан — внутренняя ошибка маршрутизации источника")
            generate.generate_from_dir(
                cfg.project_dir, app_bom,
                use_cdxgen=cfg.use_cdxgen,
                use_syft=cfg.use_syft,
                cdxgen_output=cdxgen_bom,
                syft_output=syft_bom,
            )
    else:
        # Режим только-образ: создать пустой SBOM-каркас для обогащения Clair
        logging.info("[pipeline] Исходный код не задан — создан пустой SBOM для образа")
        if cfg.image_name is None:
            raise RuntimeError("image_name не задан — внутренняя ошибка режима «только образ»")
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
                use_cdxgen=cfg.use_cdxgen,
                use_syft=cfg.use_syft,
                cdxgen_output=cdxgen_bom,
                syft_output=syft_bom,
            )
        else:
            logging.info(f"[pipeline] Источник: local → {cfg.project_dir}")
            if cfg.project_dir is None:
                raise RuntimeError("project_dir не задан — внутренняя ошибка маршрутизации источника")
            generate.generate_from_dir(
                cfg.project_dir, app_bom,
                use_cdxgen=cfg.use_cdxgen,
                use_syft=cfg.use_syft,
                cdxgen_output=cdxgen_bom,
                syft_output=syft_bom,
            )
    else:
        # Режим только-образ: создать пустой SBOM-каркас для обогащения Clair
        logging.info("[pipeline] Исходный код не задан — создан пустой SBOM для образа")
        if cfg.image_name is None:
            raise RuntimeError("image_name не задан — внутренняя ошибка режима «только образ»")
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
    if not cfg.nvd_api_key:
        logging.error(
            "[pipeline] NVD_API_KEY не задан — Dependency-Check будет работать "
            "без аутентификации (сильно ограниченный rate-limit NVD API). "
            "Укажите переменную окружения NVD_API_KEY=<token>. "
            "Получить токен: https://nvd.nist.gov/developers/request-an-api-key"
        )

    # Собираем задачи сканирования — они будут запущены параллельно.
    _scanner_tasks2: list[tuple[str, Callable[[], List[VulnFinding]]]] = []

    # Clair: разобрать уязвимости из уже сохранённого отчёта (clairctl не
    # запускается повторно — используем файл, полученный на этапе 1).
    if _clair_report_file is not None:
        _crf = _clair_report_file
        _ce2 = cfg.clair_endpoint
        _nk3 = cfg.nvd_api_key or ""
        _nvd_cache2 = cfg.nvd_cache_dir

        def _task_clair_parse() -> List[VulnFinding]:
            return clair.parse_report_findings(
                report_file=_crf,
                clair_endpoint=_ce2,
                nvd_api_key=_nk3,
                nvd_cache_dir=_nvd_cache2,
            )

        _scanner_tasks2.append(("clair", _task_clair_parse))

    if cfg.project_dir is not None:
        _pd3 = cfg.project_dir
        _td3 = cfg.trivy_dir

        def _task_trivy_fs2() -> List[VulnFinding]:
            return trivy.scan_filesystem(project_dir=_pd3, output_dir=_td3)

        _scanner_tasks2.append(("trivy-fs", _task_trivy_fs2))
    else:
        logging.info("[pipeline] project_dir не задан — Trivy FS пропущен")

    # Trivy — по SBOM (используем подписанный SBOM без уязвимостей)
    _sdb2 = signed_dedup_bom
    _tds2 = cfg.trivy_dir

    def _task_trivy_sbom2() -> List[VulnFinding]:
        return trivy.scan_sbom(sbom_path=_sdb2, output_dir=_tds2)

    _scanner_tasks2.append(("trivy-sbom", _task_trivy_sbom2))

    if cfg.project_dir is not None:
        _pd4 = cfg.project_dir
        _dd2 = cfg.depcheck_dir
        _dcd2 = cfg.dep_check_data or Path(".dependency-check-data")
        _hpd2 = cfg.host_project_dir
        _hdr2 = cfg.host_dep_report_dir
        _hdd2 = cfg.host_dep_check_data
        _nk4 = cfg.nvd_api_key

        def _task_depcheck2() -> List[VulnFinding]:
            return depcheck.scan(
                project_dir=_pd4, output_dir=_dd2, data_dir=_dcd2,
                host_project_dir=_hpd2, host_output_dir=_hdr2, host_data_dir=_hdd2,
                nvd_api_key=_nk4,
            )

        _scanner_tasks2.append(("dependency-check", _task_depcheck2))
    else:
        logging.info("[pipeline] project_dir не задан — Dependency-Check пропущен")

    all_findings = _run_scanners_parallel(_scanner_tasks2)
    logging.info("[pipeline] Всего уязвимостей из всех сканеров: %d", len(all_findings))

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
            bdu_cache_dir=cfg.bdu_cache_dir,
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

    processed = 0
    for sbom_path in handler.sboms_list:
        sbom_data = handler.readJson(sbom_path)
        if sbom_data is None:
            continue
        if not _is_cyclonedx_sbom(sbom_data):
            logging.info(f"[format] Пропущен не-SBOM JSON: {sbom_path}")
            continue
        deps = _extract_dependencies(sbom_data, str(sbom_path))
        vulns = _vuln_findings_from_sbom(sbom_data)  # BUG-013: показывать уязвимости из SBOM
        stem = sbom_path.stem
        exporter = Exporter(
            deps, vulns=vulns, sbom_path=str(sbom_path),
            include_bdu=any(f.bdu_id for f in vulns),
        )
        exporter.exportToExcel(str(reports_dir / EXCEL_DIR / f"{stem}{EXCEL_EXTENSION}"))
        exporter.exportToDocx(str(reports_dir / DOCX_DIR / f"{stem}{DOCX_EXTENSION}"))
        exporter.exportToOdt(str(reports_dir / ODT_DIR / f"{stem}{ODT_EXTENSION}"))
        processed += 1

    logging.info(f"[format] Обработано {processed} SBOM")


# ------------------------------------------------------------------
# Внутренние функции
# ------------------------------------------------------------------

def _is_cyclonedx_sbom(data: Any) -> bool:
    return (
        isinstance(data, dict)
        and data.get("bomFormat") == "CycloneDX"
        and isinstance(data.get("components", []), list)
    )


def _vuln_findings_from_sbom(sbom: Dict[str, Any]) -> List[VulnFinding]:
    """Восстановить List[VulnFinding] из vulnerabilities[] готового SBOM (для format)."""
    comp_by_ref: Dict[str, Dict[str, Any]] = {}
    for c in sbom.get("components", []):
        ref = c.get("bom-ref") or f"{c.get('name', '')}@{c.get('version', '')}"
        comp_by_ref[ref] = c

    findings: List[VulnFinding] = []
    for v in sbom.get("vulnerabilities", []):
        ratings = v.get("ratings") or [{}]
        r0 = ratings[0] if isinstance(ratings[0], dict) else {}
        ref = (v.get("affects") or [{}])[0].get("ref", "")
        comp = comp_by_ref.get(ref, {})
        props = {
            p.get("name", ""): p.get("value", "")
            for p in (v.get("properties") or []) if isinstance(p, dict)
        }
        try:
            score = float(r0.get("score") or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        findings.append(VulnFinding(
            cve_id=v.get("id", ""),
            component_name=comp.get("name", ""),
            component_version=comp.get("version", ""),
            component_purl=comp.get("purl", ""),
            cvss_score=score,
            severity=(r0.get("severity") or "UNKNOWN").upper(),
            description=v.get("description", ""),
            scanner=(v.get("source") or {}).get("name", "").lower(),
            recommendation=v.get("recommendation", ""),
            acceptability_status=props.get("acceptability_status", ""),
            bdu_id=props.get("ru.fstec.bdu:id") or None,
        ))
    return findings


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
                    (
                        "attack-surface",
                        "attack_surface",
                        "attackSurface",
                        "isAttackSurface",
                        "GOST: attack_surface",
                    ),
                ),
                security_function=_find_prop(
                    props,
                    (
                        "security-function",
                        "security_function",
                        "securityFunction",
                        "isSecurityFunction",
                        "GOST: security_function",
                    ),
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
