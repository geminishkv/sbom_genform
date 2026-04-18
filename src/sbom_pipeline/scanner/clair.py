"""Clair — сканирование контейнерного образа через clairctl + Clair HTTP API."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..vuln_merger import VulnFinding

# NormalizedSeverity is serialized as an integer (claircore.Severity):
# 0=Unknown, 1=Negligible, 2=Low, 3=Medium, 4=High, 5=Critical
_SEVERITY_MAP = {
    "0": "UNKNOWN",
    "1": "LOW",
    "2": "LOW",
    "3": "MEDIUM",
    "4": "HIGH",
    "5": "CRITICAL",
    # string fallbacks (older versions)
    "Unknown": "NOT_STATED",
    "Negligible": "LOW",
    "Low": "LOW",
    "Medium": "MEDIUM",
    "High": "HIGH",
    "Critical": "CRITICAL",
}


# Default: 20 attempts × 30 s = 10 min max wait for updaters on first run.
_CLAIR_RETRIES = 20
_CLAIR_RETRY_DELAY = 30.0


def scan_image(
    image_name: str,
    output_dir: Path,
    clair_endpoint: str = "http://clair:8080",
    host_output_dir: Optional[Path] = None,
    retries: int = _CLAIR_RETRIES,
    retry_delay: float = _CLAIR_RETRY_DELAY,
    nvd_api_key: str = "",
) -> List[VulnFinding]:
    """
    Проанализировать образ через clairctl + Clair HTTP API.

    clairctl запускается локально (не через docker exec) и сам обращается
    к реестру образов за манифестом и слоями.  Clair, в свою очередь,
    самостоятельно скачивает слои по HTTPS-ссылкам, сформированным clairctl,
    — никакого общего /tmp между процессами не требуется.

    Шаг опциональный: при любой ошибке возвращает пустой список.

    При ошибке 500 (updater'ы ещё не завершили первый цикл загрузки) повторяет
    попытку каждые ``retry_delay`` секунд — до ``retries`` раз.
    """
    if not shutil.which("clairctl"):
        logging.warning(
            "[clair] clairctl не найден в PATH. "
            "Скачайте его с https://github.com/quay/clair/releases "
            "и добавьте в PATH. Шаг пропущен."
        )
        return []

    if not _clair_server_alive(clair_endpoint):
        logging.warning("[clair] Сервер Clair недоступен по адресу %s. Шаг пропущен.", clair_endpoint)
        return []

    output_dir.mkdir(parents=True, exist_ok=True)
    sanitized = image_name.replace(":", "_").replace("/", "_")
    out_file = output_dir / f"clair-{sanitized}.json"

    cmd = [
        "clairctl", "report",
        "--host", clair_endpoint,
        "--out", "json",
        image_name,
    ]
    logging.info("[clair] %s", " ".join(cmd))

    result = None
    for attempt in range(1, retries + 1):
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.stdout.strip():
            logging.debug("[clair] stdout: %s", result.stdout[:500])
        if result.stderr.strip():
            logging.debug("[clair] stderr: %s", result.stderr[:500])

        if result.returncode == 0:
            break

        is_500 = "500" in (result.stderr or "")
        if is_500 and attempt < retries:
            logging.warning(
                "[clair] Попытка %d/%d вернула 500 — updater'ы ещё загружают данные. "
                "Повтор через %ds...", attempt, retries, int(retry_delay)
            )
            time.sleep(retry_delay)
        else:
            logging.warning(
                "[clair] Шаг Clair пропущен (попытка %d/%d, код %d). stderr: %s",
                attempt, retries, result.returncode, (result.stderr or "")[:400]
            )
            return []

    if result is None or result.returncode != 0:
        return []

    if not result.stdout.strip():
        logging.warning("[clair] clairctl вернул пустой stdout")
        return []

    try:
        out_file.write_text(result.stdout, encoding="utf-8")
    except OSError as e:
        logging.error("[clair] Не удалось записать отчёт: %s", e)
        return []

    logging.info("[clair] Отчёт записан: %s (%d байт)", out_file, out_file.stat().st_size)

    findings = _parse(out_file)

    # Обогащение CVSS через Clair matcher API
    try:
        manifest_hash = _read_manifest_hash(out_file)
        if manifest_hash:
            enrichments = _fetch_enrichments_from_clair_api(clair_endpoint, manifest_hash)
            if enrichments:
                _apply_cvss_enrichments(findings, enrichments)
    except Exception as exc:
        logging.debug("[clair] enrichment step skipped: %s", exc)

    # Fallback: запросить CVSS из NVD API 2.0 для оставшихся CVE без оценки
    zero_cves = list({f.cve_id for f in findings if f.cvss_score == 0.0 and f.cve_id.startswith("CVE-")})
    if zero_cves:
        nvd_scores = _fetch_cvss_from_nvd(zero_cves, api_key=nvd_api_key)
        if nvd_scores:
            filled = 0
            for f in findings:
                if f.cvss_score == 0.0 and f.cve_id in nvd_scores:
                    f.cvss_score = nvd_scores[f.cve_id]
                    filled += 1
            logging.info("[clair] NVD fallback: заполнено %d CVSS из %d CVE", filled, len(nvd_scores))

    return findings


# ------------------------------------------------------------------
# Clair HTTP API helpers
# ------------------------------------------------------------------

def _submit_manifest(endpoint: str, image_name: str, timeout: int = 60) -> str:
    """
    Отправить запрос на индексирование образа.

    POST /indexer/api/v1/index_report
    Body: {"hash": "<manifest_hash>", "layers": [...]}

    Clair ожидает манифест в формате ClairCore Manifest. Для container
    registry-образов проще всего использовать endpoint
    POST /indexer/api/v1/index_report с телом вида:
      {"image_name": "<image>"}  (Clair v4.7+ поддерживает прямой pull)

    Если сервер Clair поддерживает прямой pull из registry (конфигурация
    indexer.airgap=false), достаточно одного запроса.
    """
    url = f"{endpoint}/indexer/api/v1/index_report"
    body = json.dumps({"image_name": image_name}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("manifest_hash") or data.get("hash") or ""


def _get_index_state(endpoint: str, manifest_hash: str, timeout: int = 30) -> str:
    """
    GET /indexer/api/v1/index_report/{manifest_hash}
    Вернуть значение поля ``state`` (например, "IndexFinished" / "IndexError").
    """
    url = f"{endpoint}/indexer/api/v1/index_report/{manifest_hash}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("state", "")


def _fetch_vuln_report(endpoint: str, manifest_hash: str, timeout: int = 60) -> Dict[str, Any]:
    """
    GET /matcher/api/v1/vulnerability_report/{manifest_hash}
    Вернуть полный отчёт об уязвимостях (claircore.VulnerabilityReport).
    """
    url = f"{endpoint}/matcher/api/v1/vulnerability_report/{manifest_hash}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ------------------------------------------------------------------
# Обнаружение контейнера Clair через Docker (удалено — используем HTTP API)
# ------------------------------------------------------------------


def _fetch_cvss_from_nvd(
    cve_ids: List[str],
    api_key: str = "",
) -> Dict[str, float]:
    """
    Запросить CVSS base score из NVD API 2.0 для списка CVE ID.

    Без ключа: лимит 5 запросов / 30 с → задержка 6.5 с между запросами.
    С ключом:  лимит 50 запросов / 30 с → задержка 0.7 с.
    Ошибки молча пропускаются (функция best-effort).
    """
    import urllib.parse

    if not cve_ids:
        return {}

    delay = 0.7 if api_key else 6.5
    headers: Dict[str, str] = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    scores: Dict[str, float] = {}
    logging.info(f"[clair] NVD fallback: запрос CVSS для {len(cve_ids)} CVE (задержка {delay}s)")

    for cve_id in cve_ids:
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?"
            + urllib.parse.urlencode({"cveId": cve_id})
        )
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status != 200:
                    continue
                data: Dict[str, Any] = json.loads(resp.read())
            vulns = data.get("vulnerabilities") or []
            if not vulns:
                continue
            metrics = (vulns[0].get("cve") or {}).get("metrics") or {}
            score = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                for entry in metrics.get(key) or []:
                    s = (entry.get("cvssData") or {}).get("baseScore", 0.0)
                    try:
                        s = float(s)
                    except (TypeError, ValueError):
                        s = 0.0
                    if s:
                        score = s
                        break
                if score:
                    break
            if score:
                scores[cve_id] = score
        except Exception as exc:
            logging.debug(f"[clair] NVD lookup failed for {cve_id}: {exc}")
        time.sleep(delay)

    return scores


# ------------------------------------------------------------------
# Проверка доступности сервера Clair
# ------------------------------------------------------------------

def _clair_server_alive(endpoint: str, timeout: int = 30) -> bool:
    """
    Убедиться, что HTTP-сервер Clair отвечает на /healthz.
    Возвращает False только если сервер совсем недоступен.
    """
    url = f"{endpoint}/healthz"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status < 500
    except urllib.error.HTTPError as e:
        # любой HTTP-ответ означает, что сервер жив
        return e.code < 500
    except Exception as e:
        logging.debug(f"[clair] healthz недоступен: {e}")
        return False


# ------------------------------------------------------------------
# Обогащение CVSS через Clair API
# ------------------------------------------------------------------

def _read_manifest_hash(report_file: Path) -> Optional[str]:
    """Вернуть manifest_hash из уже записанного JSON-отчёта."""
    try:
        with open(report_file, encoding="utf-8") as f:
            return json.load(f).get("manifest_hash", "")
    except Exception:
        return None


def _fetch_enrichments_from_clair_api(
    endpoint: str, manifest_hash: str, timeout: int = 30
) -> Optional[dict]:
    """
    Запросить Clair matcher API:
      GET /matcher/api/v1/vulnerability_report/{manifest_hash}

    Возвращает словарь ``enrichments`` из ответа или None при ошибке.
    Поле ``enrichments`` будет заполнено, только если в Clair настроен
    NVD/CVSS enricher.  При пустом словаре обогащения не применяются.
    """
    url = f"{endpoint}/matcher/api/v1/vulnerability_report/{manifest_hash}"
    logging.debug(f"[clair] fetching enrichments from {url}")
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                logging.debug(f"[clair] enrichments API returned {resp.status}")
                return None
            data = json.loads(resp.read().decode("utf-8"))
            enrichments = data.get("enrichments") or {}
            logging.info(
                f"[clair] enrichments fetched: {list(enrichments.keys()) or 'none'}"
            )
            return enrichments
    except Exception as exc:
        logging.debug(f"[clair] enrichments fetch failed: {exc}")
        return None


def _build_cvss_index(enrichments: dict) -> Dict[str, float]:
    """
    Построить словарь ``cve_name -> cvss_score`` из словаря enrichments,
    возвращённого Clair API.

    Clair v4 NVD/CVSS enricher хранит данные под одним из нескольких ключей
    (зависит от версии claircore).  Мы обрабатываем все известные форматы:

    Формат A (claircore ≥ 0.5, ключ типа "org.quay.clair/enricher/*"):
      {
        "org.quay.clair/enricher/cvss/v1": [
          {"vuln": "CVE-xxx", "data": [{"v3": {"baseScore": 7.8}, "v2": {...}}]}
        ]
      }

    Формат B (claircore < 0.5 / nvd updater, ключ "nvd"):
      {
        "nvd": [
          {"vuln": "CVE-xxx", "data": [{"cvss": {"v3Score": 7.8, "v2Score": 5.0}}]}
        ]
      }

    Формат C (flat dict, некоторые сборки):
      {
        "nvd": {"CVE-xxx": {"cvssv3BaseScore": 7.8}}
      }
    """
    index: Dict[str, float] = {}

    for enricher_key, records in enrichments.items():
        # Format C: records is a plain dict keyed by vuln name
        if isinstance(records, dict):
            for vuln_name, score_data in records.items():
                if not isinstance(score_data, dict):
                    continue
                score = _pick_score_from_flat(score_data)
                if score and vuln_name not in index:
                    index[vuln_name] = score
            continue

        # Formats A & B: records is a list of {vuln, data} objects
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            vuln_name: str = record.get("vuln", "")
            if not vuln_name:
                continue
            data_list = record.get("data") or []
            if not isinstance(data_list, list):
                data_list = [data_list]
            best: float = 0.0
            for item in data_list:
                score = _pick_score_from_item(item)
                if score and score > best:
                    best = score
            if best and vuln_name not in index:
                index[vuln_name] = best

    return index


def _pick_score_from_item(item: dict) -> float:
    """Извлечь наибольший доступный CVSS score из одного enrichment-элемента."""
    if not isinstance(item, dict):
        return 0.0
    candidates: list[float] = []

    # Format A: {"v3": {"baseScore": 7.8}, "v2": {"baseScore": 5.0}}
    for key in ("v3", "v2"):
        sub = item.get(key)
        if isinstance(sub, dict):
            val = sub.get("baseScore") or sub.get("score")
            if val:
                candidates.append(float(val))

    # Format B: {"cvss": {"v3Score": 7.8, "v2Score": 5.0}}
    cvss = item.get("cvss")
    if isinstance(cvss, dict):
        for k in ("v3Score", "v3BaseScore", "v2Score", "v2BaseScore", "baseScore"):
            val = cvss.get(k)
            if val:
                candidates.append(float(val))

    # Direct numeric score fields
    for k in ("score", "baseScore", "cvssScore"):
        val = item.get(k)
        if val:
            try:
                candidates.append(float(val))
            except (TypeError, ValueError):
                pass

    return max(candidates) if candidates else 0.0


def _pick_score_from_flat(score_data: dict) -> float:
    """Обработка плоского Format C."""
    candidates: list[float] = []
    for k in (
        "cvssv3BaseScore", "cvssV3BaseScore", "cvssv3Score",
        "cvssv2BaseScore", "cvssV2BaseScore", "cvssv2Score",
        "baseScore", "score",
    ):
        val = score_data.get(k)
        if val:
            try:
                candidates.append(float(val))
            except (TypeError, ValueError):
                pass
    return max(candidates) if candidates else 0.0


def _apply_cvss_enrichments(
    findings: List[VulnFinding], enrichments: dict
) -> None:
    """Заполнить cvss_score у findings, используя данные из enrichments."""
    cvss_index = _build_cvss_index(enrichments)
    if not cvss_index:
        logging.debug("[clair] enrichments present but contain no CVSS scores")
        return
    enriched = 0
    for f in findings:
        score = cvss_index.get(f.cve_id)
        if score and f.cvss_score == 0.0:
            f.cvss_score = score
            enriched += 1
    logging.info(f"[clair] CVSS enriched {enriched}/{len(findings)} findings")


# ------------------------------------------------------------------
# Парсинг JSON-отчёта Clair
# ------------------------------------------------------------------

def _vendor_sev_to_acceptability(vendor_severity: str) -> str:
    """
    Преобразовать сырой вендорский приоритет Clair в статус допустимости.

    Debian помечает «unimportant» уязвимости, которые команда безопасности
    считает не представляющими реальной угрозы.
    """
    sev = (vendor_severity or "").strip().lower()
    if sev == "unimportant":
        return "Неприменимо"
    return ""


def _parse(result_file: Path) -> List[VulnFinding]:
    if not result_file.exists():
        return []
    try:
        with open(result_file, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logging.error(f"[clair] Не удалось прочитать {result_file}: {e}")
        return []

    # clairctl report --out json → claircore.VulnerabilityReport
    # Top-level keys: manifest_hash, packages, vulnerabilities,
    # package_vulnerabilities, environments, distributions, repository
    packages: dict = data.get("packages") or {}
    vulnerabilities: dict = data.get("vulnerabilities") or {}
    pkg_vulns: dict = data.get("package_vulnerabilities") or {}

    findings: List[VulnFinding] = []

    if pkg_vulns:
        # Iterate (binary-package, vulnerability) pairs so we get the actual
        # installed package name and version — vuln["package"]["version"] is
        # always "" because it's a source-package reference in Clair output.
        for pkg_id, vuln_ids in pkg_vulns.items():
            pkg = packages.get(str(pkg_id)) or {}
            pkg_name = pkg.get("name", "")
            pkg_version = pkg.get("version", "")

            for vuln_id in (vuln_ids or []):
                vuln = vulnerabilities.get(str(vuln_id))
                if not vuln:
                    continue

                raw_sev = vuln.get("normalized_severity", "Unknown")
                links = vuln.get("links", "")  # string, not list
                vendor_sev = vuln.get("severity", "")

                findings.append(
                    VulnFinding(
                        cve_id=vuln.get("name", str(vuln_id)),
                        component_name=pkg_name,
                        component_version=pkg_version,
                        component_purl="",
                        cvss_score=0.0,
                        severity=_SEVERITY_MAP.get(
                            str(raw_sev),
                            vuln.get("severity", "UNKNOWN").upper(),
                        ),
                        description=vuln.get("description", ""),
                        scanner="clair",
                        fixed_version=vuln.get("fixed_in_version", ""),
                        recommendation=links,
                        acceptability_status=_vendor_sev_to_acceptability(vendor_sev),
                    )
                )
    else:
        # Fallback: package_vulnerabilities absent — iterate vulnerabilities
        # directly (component_version will be empty for source-pkg references).
        for vuln_id, vuln in vulnerabilities.items():
            pkg = vuln.get("package") or {}
            raw_sev = vuln.get("normalized_severity", "Unknown")
            links = vuln.get("links", "")
            vendor_sev = vuln.get("severity", "")

            findings.append(
                VulnFinding(
                    cve_id=vuln.get("name", vuln_id),
                    component_name=pkg.get("name", ""),
                    component_version=pkg.get("version", ""),
                    component_purl="",
                    cvss_score=0.0,
                    severity=_SEVERITY_MAP.get(
                        str(raw_sev),
                        vuln.get("severity", "UNKNOWN").upper(),
                    ),
                    description=vuln.get("description", ""),
                    scanner="clair",
                    fixed_version=vuln.get("fixed_in_version", ""),
                    recommendation=links,
                    acceptability_status=_vendor_sev_to_acceptability(vendor_sev),
                )
            )

    if not findings:
        top_keys = list(data.keys())[:10] if isinstance(data, dict) else type(data).__name__
        logging.warning(f"[clair] 0 уязвимостей. Ключи JSON: {top_keys}")

    logging.info(f"[clair] Найдено {len(findings)} уязвимостей")
    return findings


# ------------------------------------------------------------------
# Обогащение компонентов SBOM данными контейнерного образа из Clair
# ------------------------------------------------------------------

def enrich_sbom_with_clair_packages(
    sbom: Dict[str, Any],
    report_file: Path,
    image_name: str = "",
) -> Dict[str, Any]:
    """
    Обновить или добавить компоненты SBOM данными из отчёта Clair:

    • Если компонент с совпадающим (name, version) уже есть в SBOM —
      он обновляется свойствами container_image / container_role / os_distribution.
    • Если такого компонента в SBOM нет — он добавляется как новый компонент
      типа «library» с PURL, сформированным по типу пакета (deb / golang).

    Если файл отчёта не существует или не содержит валидного JSON, функция
    возвращает SBOM без изменений.
    """
    if not report_file.exists():
        logging.debug(f"[clair] enrich: файл отчёта не найден: {report_file}")
        return sbom

    try:
        with open(report_file, encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logging.warning(f"[clair] enrich: не удалось прочитать {report_file}: {e}")
        return sbom

    # ------------------------------------------------------------------
    # Построить вспомогательные индексы из отчёта Clair
    # ------------------------------------------------------------------
    packages: Dict[str, Any] = data.get("packages") or {}
    environments: Dict[str, Any] = data.get("environments") or {}
    distributions: Dict[str, Any] = data.get("distributions") or {}
    manifest_hash: str = data.get("manifest_hash") or ""

    # Имя образа: предпочтительно переданное явно, иначе manifest_hash
    effective_image = image_name or manifest_hash

    if not effective_image:
        logging.debug("[clair] enrich: не удалось определить имя образа, SBOM не изменён")
        return sbom

    # dist_id → human-readable name  (e.g. "2" → "Debian GNU/Linux 13 (trixie)")
    dist_name_index: Dict[str, str] = {
        did: (
            d.get("pretty_name")
            or f"{d.get('name', '')} {d.get('version', '')}".strip()
        )
        for did, d in distributions.items()
    }

    # (pkg_name_lower, pkg_version_lower) → {introduced_in, distribution, dist_did, pkg}
    _PkgInfo = Dict[str, Any]
    clair_index: Dict[tuple, _PkgInfo] = {}
    for pkg_id, pkg in packages.items():
        name = (pkg.get("name") or "").lower()
        version = (pkg.get("version") or "").lower()
        if not name:
            continue

        # environments[pkg_id] is a list of one or more env records
        env_list: List[Dict[str, Any]] = environments.get(str(pkg_id)) or []
        introduced_in = ""
        dist_name = ""
        dist_did = ""
        if env_list:
            env = env_list[0]
            introduced_in = env.get("introduced_in") or ""
            dist_id = env.get("distribution_id") or ""
            dist_name = dist_name_index.get(str(dist_id), "")
            dist_obj = distributions.get(str(dist_id)) or {}
            dist_did = dist_obj.get("did", "")

        clair_index[(name, version)] = {
            "introduced_in": introduced_in,
            "distribution": dist_name,
            "dist_did": dist_did,
            "pkg": pkg,
        }

    if not clair_index:
        logging.debug("[clair] enrich: индекс пакетов пуст, SBOM не изменён")
        return sbom

    # ------------------------------------------------------------------
    # Построить индекс существующих компонентов SBOM (name, version) → позиция
    # ------------------------------------------------------------------
    import copy
    sbom = copy.deepcopy(sbom)
    components: List[Dict[str, Any]] = sbom.setdefault("components", [])

    existing_index: Dict[tuple, int] = {}
    for i, comp in enumerate(components):
        cname = (comp.get("name") or "").lower()
        cversion = (comp.get("version") or "").lower()
        existing_index[(cname, cversion)] = i

    # ------------------------------------------------------------------
    # Для каждого пакета Clair: обновить существующий компонент или добавить новый
    # ------------------------------------------------------------------
    updated = 0
    added = 0

    for (pkg_name, pkg_version), info in clair_index.items():
        if (pkg_name, pkg_version) in existing_index:
            comp = components[existing_index[(pkg_name, pkg_version)]]
            props: List[Dict[str, str]] = comp.setdefault("properties", [])
            _set_prop(props, "container_image", effective_image)
            if info["introduced_in"]:
                _set_prop(props, "container_role", info["introduced_in"])
            if info["distribution"]:
                _set_prop(props, "os_distribution", info["distribution"])
            updated += 1
        else:
            new_comp = _build_component_from_clair(
                info["pkg"], info, effective_image, info["dist_did"]
            )
            components.append(new_comp)
            added += 1

    logging.info(
        f"[clair] enrich: обновлено {updated}, добавлено {added} компонентов "
        f"из образа '{effective_image}'"
    )
    return sbom


def _build_component_from_clair(
    pkg: Dict[str, Any],
    info: Dict[str, Any],
    effective_image: str,
    dist_did: str = "",
) -> Dict[str, Any]:
    """Build a minimal CycloneDX component dict from a Clair package entry."""
    name = pkg.get("name") or ""
    version = pkg.get("version") or ""
    arch = pkg.get("arch") or ""
    cpe = pkg.get("cpe") or ""
    detector = pkg.get("detector") or ""

    if "gobin" in detector:
        purl = f"pkg:golang/{name}@{version}"
    else:
        dist = dist_did or "linux"
        purl = f"pkg:deb/{dist}/{name}@{version}"
        if arch:
            purl += f"?arch={arch}"

    props: List[Dict[str, str]] = [{"name": "container_image", "value": effective_image}]
    if info.get("introduced_in"):
        props.append({"name": "container_role", "value": info["introduced_in"]})
    if info.get("distribution"):
        props.append({"name": "os_distribution", "value": info["distribution"]})

    comp: Dict[str, Any] = {
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
        "bom-ref": purl,
        "properties": props,
    }
    if cpe:
        comp["cpe"] = cpe
    return comp


def _set_prop(props: List[Dict[str, str]], name: str, value: str) -> None:
    """Установить или обновить значение property по имени."""
    for p in props:
        if p.get("name") == name:
            p["value"] = value
            return
    props.append({"name": name, "value": value})


