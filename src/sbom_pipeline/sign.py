"""Контрольная сумма целостности SBOM через SHA-256 (metadata + .sig файл).

ВНИМАНИЕ: это контрольная сумма **целостности** (integrity), а не
криптографическая **подпись** (authenticity). SHA-256 защищает от случайной
порчи, но не от целенаправленной подмены: атакующий, изменивший SBOM, может
пересчитать хэш и `.sig`, и `verify_sbom` пройдёт. Для аутентичности и
неотрекаемости нужна криптоподпись (Ed25519/RSA) или sigstore/cosign.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def sign_sbom(input_path: Path, output_path: Path) -> Path:
    """
    Подписать SBOM:
    1. SHA-256 от канонического JSON встраивается в metadata.signature.
    2. Рядом с output_path создаётся <name>.sig с «SHA256=<hex>».
    """
    with open(input_path, encoding="utf-8") as f:
        sbom: Dict[str, Any] = json.load(f)

    signed = _embed_sha256(sbom)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(signed, f, indent=2, ensure_ascii=False)

    # .sig — хэш итогового файла для внешней проверки
    canonical = json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    sig_path = output_path.with_suffix(".sig")
    sig_path.write_text(f"SHA256={digest}\n", encoding="utf-8")

    logging.info(f"[sign] Подписан SBOM → {output_path}")
    logging.info(f"[sign] Контрольная сумма → {sig_path}")
    return output_path


def verify_sbom(sbom_path: Path) -> bool:
    """Проверить SHA-256 подпись внутри SBOM.  True — OK, False — не совпадает."""
    with open(sbom_path, encoding="utf-8") as f:
        sbom: Dict[str, Any] = json.load(f)

    sig_data = sbom.get("metadata", {}).get("signature", {})
    stored = sig_data.get("value")
    if not stored:
        logging.warning("[verify] Подпись не найдена в SBOM")
        return False

    copy_ = copy.deepcopy(sbom)
    copy_["metadata"].pop("signature", None)
    canonical = json.dumps(copy_, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    computed = hashlib.sha256(canonical.encode()).hexdigest()

    if computed == stored:
        logging.info("[verify] SHA-256 подпись верифицирована ✓")
        return True

    logging.error(
        f"[verify] SHA-256 не совпадает! stored={stored[:16]}… computed={computed[:16]}…"
    )
    return False


# ------------------------------------------------------------------
# Внутренние функции
# ------------------------------------------------------------------

def _embed_sha256(sbom: Dict[str, Any]) -> Dict[str, Any]:
    """Добавить/заменить metadata.signature с SHA-256."""
    signed = copy.deepcopy(sbom)

    if "metadata" not in signed:
        signed["metadata"] = {}
    # Убираем старую подпись перед хешированием
    signed["metadata"].pop("signature", None)

    canonical = json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode()).hexdigest()

    signed["metadata"]["signature"] = {
        "algorithm": "SHA256",
        "value": digest,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return signed
