"""Disk-backed NVD CVE API cache."""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.parse
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from typing import Any

DEFAULT_CACHE_DIR = Path(".nvd_cache")
_CACHE_FILE_NAME = "nvd_cve_cache.json"
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def get_cvss_scores_by_cves(
    cve_ids: Iterable[str],
    api_key: str = "",
    cache_dir: Path | None = None,
) -> dict[str, float]:
    """
    Return CVE -> CVSS base score using the local NVD cache first.

    The cache stores full NVD API responses, including negative lookups. Network
    requests are only made for CVEs missing from the cache.
    """
    normalized_cves = _normalize_cves(cve_ids)
    if not normalized_cves:
        return {}

    resolved_cache_dir = cache_dir if cache_dir is not None else DEFAULT_CACHE_DIR
    cache = _load_cache(resolved_cache_dir)

    scores: dict[str, float] = {}
    to_fetch: list[str] = []
    for cve_id in normalized_cves:
        if cve_id in cache:
            score = _extract_cvss_from_nvd_response(cache[cve_id].get("response") or {})
            if score:
                scores[cve_id] = score
            logging.debug("[nvd_client] Кэш: %s -> %s", cve_id, score or "нет CVSS")
        else:
            to_fetch.append(cve_id)

    if not to_fetch:
        logging.info(
            "[nvd_client] Все %d CVE взяты из кэша NVD, сетевые запросы не нужны.",
            len(normalized_cves),
        )
        return scores

    headers: dict[str, str] = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    delay = 0.7 if api_key else 6.5
    logging.info(
        "[nvd_client] NVD API: %d CVE из кэша, %d требуют запроса (задержка %.1fs)",
        len(normalized_cves) - len(to_fetch),
        len(to_fetch),
        delay,
    )

    fetched_any = False
    for idx, cve_id in enumerate(to_fetch):
        if idx > 0:
            time.sleep(delay)
        data = _fetch_cve(cve_id, headers)
        if data is None:
            continue
        fetched_any = True
        cache[cve_id] = {
            "fetched_at": int(time.time()),
            "response": data,
        }
        score = _extract_cvss_from_nvd_response(data)
        if score:
            scores[cve_id] = score

    if fetched_any:
        _save_cache(resolved_cache_dir, cache)

    return scores


def _normalize_cves(cve_ids: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for cve in cve_ids:
        cve_id = (cve or "").strip().upper()
        if not cve_id:
            continue
        if not _CVE_ID_RE.match(cve_id):
            logging.debug("[nvd_client] Пропуск не-CVE идентификатора: %s", cve_id)
            continue
        if cve_id not in seen:
            seen.add(cve_id)
            result.append(cve_id)
    return result


def _fetch_cve(cve_id: str, headers: dict[str, str]) -> dict[str, Any] | None:
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?"
        + urllib.parse.urlencode({"cveId": cve_id})
    )
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status != 200:
                logging.debug("[nvd_client] NVD lookup %s returned HTTP %s", cve_id, resp.status)
                return None
            return json.loads(resp.read())
    except Exception as exc:
        logging.debug("[nvd_client] NVD lookup failed for %s: %s", cve_id, exc)
        return None


def _extract_cvss_from_nvd_response(data: dict[str, Any]) -> float:
    vulnerabilities = data.get("vulnerabilities") or []
    if not vulnerabilities:
        return 0.0

    metrics = (vulnerabilities[0].get("cve") or {}).get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key) or []:
            score = (entry.get("cvssData") or {}).get("baseScore", 0.0)
            try:
                score = float(score)
            except (TypeError, ValueError):
                score = 0.0
            if score:
                return score
    return 0.0


def _load_cache(cache_dir: Path) -> dict[str, dict[str, Any]]:
    cache_file = cache_dir / _CACHE_FILE_NAME
    if not cache_file.exists():
        return {}
    try:
        with open(cache_file, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return {str(k).upper(): v for k, v in data.items() if isinstance(v, dict)}
        logging.warning("[nvd_client] Кэш-файл %s имеет неожиданный формат — сброс.", cache_file)
    except Exception as exc:
        logging.warning("[nvd_client] Не удалось прочитать кэш %s: %s", cache_file, exc)
    return {}


def _save_cache(cache_dir: Path, data: dict[str, dict[str, Any]]) -> None:
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / _CACHE_FILE_NAME
        tmp_file = cache_file.with_suffix(".tmp")
        with open(tmp_file, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp_file, cache_file)
        logging.debug("[nvd_client] Кэш NVD сохранён: %s (%d записей)", cache_file, len(data))
    except Exception as exc:
        logging.warning("[nvd_client] Не удалось сохранить кэш NVD: %s", exc)
