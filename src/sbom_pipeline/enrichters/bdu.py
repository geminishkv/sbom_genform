"""Клиент BDU FSTEC: поиск BDU ID по списку CVE."""

from __future__ import annotations

import logging
import re
import time
from typing import Dict, Iterable
from urllib.parse import quote, unquote

import requests
from bs4 import BeautifulSoup

BDU_VUL_URL = "https://bdu.fstec.ru/vul"
REQUEST_TIMEOUT = (10, 60)
RATE_LIMIT_DELAY: float = 1.0

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


def get_bdu_ids_by_cves(cve_ids: Iterable[str]) -> Dict[str, str]:
    """
    Получить соответствия CVE -> BDU-ID через bdu.fstec.ru.

    Args:
        cve_ids: список/итерируемый набор CVE идентификаторов

    Returns:
        Dict[str, str]: ключ — cve_id, значение — bdu_id
    """
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

    try:
        cookie_jar, query_token = _get_csrf_tokens()
    except Exception as exc:
        logging.warning("[bdu_client] Не удалось получить CSRF-токены: %s", exc)
        return result

    for idx, cve_id in enumerate(normalized_cves):
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
                verify=False,
            )
            response.raise_for_status()

            yii_csrf_token = response.cookies.get("YII_CSRF_TOKEN")
            phpsessid = response.cookies.get("PHPSESSID")
            if yii_csrf_token:
                cookie_jar["YII_CSRF_TOKEN"] = yii_csrf_token
            if phpsessid:
                cookie_jar["PHPSESSID"] = phpsessid

            bdu_id = _extract_bdu_id(response.text)
            if bdu_id:
                result[cve_id] = bdu_id
                logging.info("[bdu_client] BDU-ID найден для %s: %s", cve_id, bdu_id)
            else:
                logging.info("[bdu_client] BDU-ID не найден для %s", cve_id)

        except requests.RequestException as exc:
            logging.warning("[bdu_client] Ошибка запроса для %s: %s", cve_id, exc)

    return result

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
    response = requests.get(
        BDU_VUL_URL,
        timeout=REQUEST_TIMEOUT,
        verify=False,
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
