"""Работа с SBOM-файлами: чтение, поиск."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional


class SbomHandler:
    def __init__(self, sbom_directory: str | Path) -> None:
        self.sbom_directory = Path(sbom_directory)
        if not self.sbom_directory.is_dir():
            logging.warning(f"Директория SBOM не найдена: {sbom_directory}")
            self.sboms_list: List[Path] = []
        else:
            self.sboms_list = [
                p for p in self.sbom_directory.iterdir() if p.is_file() and p.suffix == ".json"
            ]
        logging.info(
            f"SbomHandler: {len(self.sboms_list)} файлов в {sbom_directory}"
        )

    # Для совместимости со старым кодом
    @property
    def sbomsList(self) -> List[str]:
        return [str(p) for p in self.sboms_list]

    def readJson(self, path: str | Path) -> Optional[Any]:
        """Прочитать и вернуть SBOM JSON или None при ошибке."""
        logging.info(f"Чтение SBOM: {path}")
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logging.error(f"Невалидный JSON {path}: {e}")
            return None
        except OSError as e:
            logging.error(f"Ошибка чтения {path}: {e}")
            return None

    @staticmethod
    def write_json(data: Dict[str, Any], path: str | Path, indent: int = 2) -> None:
        """Записать словарь как JSON."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        logging.info(f"Записан SBOM: {path}")
