#!/usr/bin/env python3
"""
CLI wrapper around manual_formatter for convenient report generation.

Usage:
    python run_report.py /path/to/project
    python run_report.py /path/to/project --output ./my_reports
    python run_report.py /path/to/project --output ./my_reports --sign --private-key key.pem --public-key pub.pem
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Ensure the script directory is on sys.path so sibling modules are importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from manual_formatter import process_sboms, detect_langs_from_deps
from constants import EXCEL_DIR, ODT_DIR

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()],
)

KNOWN_DEP_FILES = [
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "composer.json",
    "composer.lock",
    "Gemfile",
    "Gemfile.lock",
    "Cargo.toml",
    "Cargo.lock",
]


def find_sbom_files(target_dir: Path) -> list:
    """Recursively find SBOM JSON files inside the target directory."""
    sbom_files = []
    for root, _dirs, files in os.walk(target_dir):
        for f in files:
            if f.endswith(".json") and "sbom" in f.lower():
                sbom_files.append(os.path.join(root, f))
    return sbom_files


def find_dep_file(target_dir: Path) -> str | None:
    """Return the first known dependency file found in the target directory."""
    for name in KNOWN_DEP_FILES:
        candidate = target_dir / name
        if candidate.is_file():
            return str(candidate)
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Генерация отчётов (xlsx / odt) по SBOM для указанного проекта",
    )
    parser.add_argument(
        "target",
        help="Путь к директории проекта (содержит SBOM-файлы или файлы зависимостей)",
    )
    parser.add_argument(
        "--output",
        default="./report",
        help="Директория для сохранения отчётов (по умолчанию: ./report)",
    )
    parser.add_argument(
        "--sign",
        action="store_true",
        help="Включить подпись SBOM (RSA)",
    )
    parser.add_argument(
        "--private-key",
        dest="private_key",
        help="Путь к приватному ключу PEM",
    )
    parser.add_argument(
        "--public-key",
        dest="public_key",
        help="Путь к публичному ключу PEM",
    )
    parser.add_argument(
        "--pass",
        dest="passphrase",
        help="Пароль для приватного ключа",
    )

    args = parser.parse_args()

    target = Path(args.target).resolve()
    if not target.is_dir():
        logging.error(f"Указанный путь не является директорией: {target}")
        sys.exit(1)

    output = Path(args.output).resolve()
    excel_dir = output / EXCEL_DIR
    odt_dir = output / ODT_DIR
    excel_dir.mkdir(parents=True, exist_ok=True)
    odt_dir.mkdir(parents=True, exist_ok=True)
    logging.info(f"Директория отчётов: {output}")

    # Detect languages from dependency files in the project
    dep_file = find_dep_file(target)
    src_langs = detect_langs_from_deps(dep_file) if dep_file else []
    if dep_file:
        logging.info(f"Обнаружен файл зависимостей: {dep_file}  →  языки: {src_langs}")

    # Build signer options if requested
    signer_opts = None
    if args.sign:
        signer_opts = {
            "private_key_path": args.private_key,
            "public_key_path": args.public_key,
            "key_passphrase": args.passphrase,
        }

    # Process SBOMs found in target directory
    logging.info(f"Поиск SBOM-файлов в: {target}")
    process_sboms(
        str(target),
        str(output),
        src_langs=src_langs,
        signer_opts=signer_opts,
    )
    logging.info("Генерация отчётов завершена.")


if __name__ == "__main__":
    main()
