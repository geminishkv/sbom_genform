"""Клиент BDU FSTEC: поиск BDU ID по списку CVE."""

from __future__ import annotations

import json
import logging
import os
import re
import time
import warnings
from pathlib import Path
from typing import Dict, Iterable, Optional
from urllib.parse import quote, unquote

import requests
import urllib3
from bs4 import BeautifulSoup

# bdu.fstec.ru uses a self-signed / untrusted certificate; we suppress the
# stdlib/urllib3 InsecureRequestWarning here so it never leaks to stdout.
# The intentional use of verify=False is noted in DEBUG logs instead.
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARN)

BDU_VUL_URL = "https://bdu.fstec.ru/vul"
REQUEST_TIMEOUT = (10, 60)
RATE_LIMIT_DELAY: float = 1.0

# TLS-проверка для bdu.fstec.ru (CWE-295). Сайт использует self-signed
# сертификат, поэтому по умолчанию проверка отключена (verify=False). Задайте
# переменную окружения BDU_CA_BUNDLE=/path/to/fstec-ca.pem, чтобы включить
# проверку против доверенного CA и защититься от MITM.
BDU_VERIFY: "bool | str" = os.getenv("BDU_CA_BUNDLE") or False

DEFAULT_CACHE_DIR = Path(".bdu_cache")
_CACHE_FILE_NAME = "bdu_cache.json"

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

DEFAULT_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/145.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
        "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Encoding": "gzip, deflate, br",
    "Priority": "u=0, i",
}


def get_bdu_ids_by_cves(
    cve_ids: Iterable[str],
    cache_dir: Optional[Path] = None,
) -> Dict[str, str]:
    """
    Получить соответствия CVE -> BDU-ID через bdu.fstec.ru.

    Результаты кэшируются на диске в *cache_dir* (по умолчанию `.bdu_cache`).
    При повторном вызове уже известные CVE не запрашиваются повторно — в том
    числе те, для которых BDU-ID не был найден (отрицательный результат тоже
    сохраняется, чтобы не нагружать сервер).

    Args:
        cve_ids:   список/итерируемый набор CVE идентификаторов
        cache_dir: папка для хранения кэша; если None — используется
                   DEFAULT_CACHE_DIR (.bdu_cache)

    Returns:
        Dict[str, str]: ключ — cve_id, значение — bdu_id
    """
    resolved_cache_dir = cache_dir if cache_dir is not None else DEFAULT_CACHE_DIR

    result: Dict[str, str] = {}
    normalized_cves: list[str] = []
    for cve in cve_ids:
        if not cve or not cve.strip():
            continue
        stripped = cve.strip()
        if not _CVE_ID_RE.match(stripped):
            logging.warning("[bdu_client] Пропуск не-CVE идентификатора: %s", stripped)
            continue
        normalized_cves.append(stripped)

    if not normalized_cves:
        return result

    # --- Чтение кэша ---
    cache: Dict[str, Optional[str]] = _load_cache(resolved_cache_dir)
    to_fetch: list[str] = []
    for cve_id in normalized_cves:
        if cve_id in cache:
            bdu_id = cache[cve_id]
            if bdu_id:
                result[cve_id] = bdu_id
            logging.debug("[bdu_client] Кэш: %s → %s", cve_id, bdu_id or "не найден")
        else:
            to_fetch.append(cve_id)

    if not to_fetch:
        logging.info(
            "[bdu_client] Все %d CVE взяты из кэша, сетевые запросы не нужны.",
            len(normalized_cves),
        )
        return result

    logging.debug(
        "[bdu_client] Кэш: %d CVE уже известны, %d требуют запроса к BDU.",
        len(normalized_cves) - len(to_fetch),
        len(to_fetch),
    )

    # --- Сетевые запросы только для незакэшированных CVE ---
    try:
        cookie_jar, query_token = _get_csrf_tokens()
    except Exception as exc:
        logging.warning("[bdu_client] Не удалось получить CSRF-токены: %s", exc)
        return result

    for idx, cve_id in enumerate(to_fetch):
        if idx > 0:
            time.sleep(RATE_LIMIT_DELAY)
        try:
            response = requests.get(
                BDU_VUL_URL,
                params={
                    "YII_CSRF_TOKEN": quote(query_token, safe=""),
                    "VulFilterForm[idval]": _to_bdu_search_value(cve_id),
                        "fl": "%D0%9F%D1%80%D0%B8%D0%BC%D0%B5%D0%BD%D0%B8%D1%82%D1%8C",
                },
                headers=DEFAULT_HEADERS,
                cookies=cookie_jar,
                timeout=REQUEST_TIMEOUT,
                verify=BDU_VERIFY,
            )
            response.raise_for_status()

            yii_csrf_token = response.cookies.get("YII_CSRF_TOKEN")
            phpsessid = response.cookies.get("PHPSESSID")
            if yii_csrf_token:
                cookie_jar["YII_CSRF_TOKEN"] = yii_csrf_token
            if phpsessid:
                cookie_jar["PHPSESSID"] = phpsessid

            bdu_id = _extract_bdu_id(response.text)
            # Сохраняем в кэш и None (не найден) — чтобы не запрашивать снова
            cache[cve_id] = bdu_id
            if bdu_id:
                result[cve_id] = bdu_id
                logging.debug("[bdu_client] BDU-ID найден для %s: %s", cve_id, bdu_id)
            else:
                logging.debug("[bdu_client] BDU-ID не найден для %s", cve_id)

        except requests.RequestException as exc:
            logging.warning("[bdu_client] Ошибка запроса для %s: %s", cve_id, exc)
            # Не кэшируем ошибки сети — попробуем снова при следующем запуске

    # --- Сохранение обновлённого кэша ---
    _save_cache(resolved_cache_dir, cache)

    logging.info(
        "[bdu_client] Найдено %d BDU-ID для %d CVE (%d — из кэша, %d — новых запросов)",
        len(result),
        len(normalized_cves),
        len(normalized_cves) - len(to_fetch),
        len(to_fetch),
    )
    return result

# --- Cache helpers ---

def _load_cache(cache_dir: Path) -> Dict[str, Optional[str]]:
    """Загрузить кэш CVE→BDU с диска; вернуть пустой dict при отсутствии файла."""
    cache_file = cache_dir / _CACHE_FILE_NAME
    if not cache_file.exists():
        return {}
    try:
        with open(cache_file, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data  # type: ignore[return-value]
        logging.warning("[bdu_client] Кэш-файл %s имеет неожиданный формат — сброс.", cache_file)
    except Exception as exc:
        logging.warning("[bdu_client] Не удалось прочитать кэш %s: %s", cache_file, exc)
    return {}


def _save_cache(cache_dir: Path, data: Dict[str, Optional[str]]) -> None:
    """Атомарно сохранить кэш CVE→BDU на диск."""
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / _CACHE_FILE_NAME
        tmp_file = cache_file.with_suffix(".tmp")
        with open(tmp_file, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp_file, cache_file)
        logging.debug("[bdu_client] Кэш сохранён: %s (%d записей)", cache_file, len(data))
    except Exception as exc:
        logging.warning("[bdu_client] Не удалось сохранить кэш: %s", exc)


# --- Helper functions ---

def _extract_query_token(cookie_token: str) -> str:
    """
    YII_CSRF_TOKEN обычно приходит URL-encoded и содержит токен в кавычках.
    Пример: %22abc123%22 -> "abc123" -> abc123
    """
    decoded = unquote(cookie_token or "")
    match = re.search(r'"([^"]+)"', decoded)
    if match:
        return match.group(1)
    return decoded.strip('"')


def _get_csrf_tokens() -> tuple[Dict[str, str], str]:
    logging.debug("[bdu_client] GET %s (SSL проверка отключена)", BDU_VUL_URL)
    response = requests.get(
        BDU_VUL_URL,
        timeout=REQUEST_TIMEOUT,
        verify=BDU_VERIFY,
        headers=DEFAULT_HEADERS,
    )
    response.raise_for_status()
    cookie_jar: Dict[str, str] = {}

    yii_csrf_token = response.cookies.get("YII_CSRF_TOKEN")
    phpsessid = response.cookies.get("PHPSESSID")
    if yii_csrf_token:
        cookie_jar["YII_CSRF_TOKEN"] = yii_csrf_token
    if phpsessid:
        cookie_jar["PHPSESSID"] = phpsessid

    cookie_token = response.cookies.get("YII_CSRF_TOKEN") or cookie_jar.get("YII_CSRF_TOKEN")
    if not cookie_token:
        raise RuntimeError("Не найден cookie YII_CSRF_TOKEN")

    query_token = _extract_query_token(cookie_token)
    if not query_token:
        raise RuntimeError("Не удалось извлечь query_token из YII_CSRF_TOKEN")

    return cookie_jar, query_token

def _extract_bdu_id(html: str) -> str | None:
    soup = BeautifulSoup(html, "html.parser")
    nodes = soup.select("#vuls a.confirm-vul")
    if len(nodes) != 1:
        return None

    bdu_id = nodes[0].get_text(strip=True)
    return bdu_id or None


def _to_bdu_search_value(cve_id: str) -> str:
    """Преобразовать CVE ID в формат поиска BDU: без префикса ``CVE-``."""
    normalized = cve_id.strip()
    if normalized.upper().startswith("CVE-"):
        return normalized[4:]
    return normalized
