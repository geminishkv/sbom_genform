"""
SBOM Formatter - Форматировщик SBOM файлов

Этот модуль обеспечивает обработку Software Bill of Materials (SBOM) файлов
и их экспорт в различные форматы (Excel, ODT).

Основные возможности:
- Чтение и обработка SBOM файлов в формате JSON
- Извлечение информации о зависимостях
- Экспорт отчетов в Excel и ODT форматы
- Обработка ошибок и логирование
- Командная строка для удобного использования

Автор: SBOM Generator Team
Версия: 1.0.0
"""

import sys
import logging
import argparse
from pathlib import Path
from typing import List, Optional, Dict, Any

from sbom_handler import SbomHandler
from exporter import Exporter
from dotenv import load_dotenv
from dependency import Dependency
from constants import (
    COMPONENT_TYPE_LIBRARY,
    LOG_FORMAT,
    LOG_FILE,
    EXCEL_EXTENSION,
    ODT_EXTENSION,
    EXCEL_DIR,
    ODT_DIR,
    SBOM_OUT_DIR,
    REPORTS_DIR,
)

# Constants are imported from constants.py to avoid duplication

logging.basicConfig(
    format=LOG_FORMAT,
    level=logging.INFO,
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)

try:
    load_dotenv()
except ImportError:
    logging.warning("python-dotenv не установлен. Переменные окружения из .env файлов не будут загружены.")


class SbomFormatterError(Exception):
    """Базовое исключение для ошибок форматирования SBOM."""
    pass


class SbomProcessingError(SbomFormatterError):
    """Исключение для ошибок обработки SBOM файлов."""
    pass


class FormatterConfig:
    """
    Конфигурация для форматировщика SBOM файлов.
    
    Управляет путями к директориям и настройками для обработки SBOM файлов.
    
    Attributes:
        base_dir (Path): Базовая директория скрипта
        sbom_dir (Path): Директория с SBOM файлами
        report_dir (Path): Директория для сохранения отчетов
        excel_dir (Path): Поддиректория для Excel файлов
        odt_dir (Path): Поддиректория для ODT файлов
    """
    
    def __init__(self, sbom_dir: Optional[str] = None, report_dir: Optional[str] = None):
        """
        Инициализирует конфигурацию с указанными или значениями по умолчанию.
        
        Args:
            sbom_dir: Путь к директории с SBOM файлами (опционально)
            report_dir: Путь к директории для отчетов (опционально)
        """
        self.base_dir = Path(__file__).resolve().parent
        self.sbom_dir = Path(sbom_dir) if sbom_dir else self.base_dir.parent / SBOM_OUT_DIR
        self.report_dir = Path(report_dir) if report_dir else self.base_dir.parent / REPORTS_DIR
        self.excel_dir = self.report_dir / EXCEL_DIR
        self.odt_dir = self.report_dir / ODT_DIR
    
    def ensure_directories_exist(self) -> None:
        """
        Создает необходимые директории, если они не существуют.
        
        Raises:
            SbomFormatterError: Если возникла ошибка при создании директорий
        """
        try:
            self.excel_dir.mkdir(parents=True, exist_ok=True)
            self.odt_dir.mkdir(parents=True, exist_ok=True)
            logging.info(f"Директории созданы: {self.excel_dir}, {self.odt_dir}")
        except OSError as e:
            raise SbomFormatterError(f"Ошибка создания директорий: {e}")


class SbomFormatter:
    """
    Форматировщик SBOM файлов для экспорта в различные форматы.
    
    Основной класс для обработки SBOM файлов, извлечения зависимостей
    и создания отчетов в форматах Excel и ODT.
    
    Attributes:
        config (FormatterConfig): Конфигурация форматировщика
        handler (SbomHandler): Обработчик SBOM файлов
    """
    
    def __init__(self, config: FormatterConfig):
        """
        Инициализирует форматировщик с указанной конфигурацией.
        
        Args:
            config: Конфигурация для форматировщика
        """
        self.config = config
        self.handler = SbomHandler(str(config.sbom_dir))
    
    def _extract_dependencies(self, sbom_content: Dict[str, Any], sbom_path: str) -> List[Dependency]:
        """
        Извлекает зависимости из содержимого SBOM файла.
        
        Args:
            sbom_content: Содержимое SBOM файла в виде словаря
            sbom_path: Путь к исходному SBOM файлу
            
        Returns:
            Список объектов Dependency
        """
        components = sbom_content.get("components", [])
        dependencies = []
        
        for component in components:
            if component.get("type") == COMPONENT_TYPE_LIBRARY:
                try:
                    dependency = Dependency(
                        name=component["name"],
                        version=component["version"],
                        dep_type=[],
                        purl=component.get("purl"),
                        path_to_sbom=sbom_path
                    )
                    dependencies.append(dependency)
                except KeyError as e:
                    logging.warning(f"Пропущен компонент с отсутствующим полем {e} в {sbom_path}")
                except Exception as e:
                    logging.error(f"Ошибка при создании зависимости из {sbom_path}: {e}")
        
        return dependencies
    
    def _process_single_sbom(self, sbom_path: str) -> None:
        """
        Обрабатывает один SBOM файл.
        
        Читает SBOM файл, извлекает зависимости и создает отчеты
        в форматах Excel и ODT.
        
        Args:
            sbom_path: Путь к SBOM файлу для обработки
            
        Raises:
            SbomProcessingError: Если произошла ошибка при обработке файла
        """
        try:
            sbom_content = self.handler.readJson(sbom_path)
            if sbom_content is None:
                logging.warning(f"Пропущен файл с пустым содержимым: {sbom_path}")
                return
            
            base_name = Path(sbom_path).stem
            excel_path = self.config.excel_dir / f"{base_name}{EXCEL_EXTENSION}"
            odt_path = self.config.odt_dir / f"{base_name}{ODT_EXTENSION}"
            
            dependencies = self._extract_dependencies(sbom_content, sbom_path)
            if not dependencies:
                logging.warning(f"Не найдено зависимостей в {sbom_path}")
                return
            
            exporter = Exporter(dependencies)
            exporter.exportToExcel(str(excel_path))
            exporter.exportToOdt(str(odt_path))
            
            logging.info(f"Обработан файл: {sbom_path} -> {len(dependencies)} зависимостей")
            
        except Exception as e:
            raise SbomProcessingError(f"Ошибка обработки файла {sbom_path}: {e}")
    
    def process_all_sboms(self) -> None:
        """
        Обрабатывает все SBOM файлы в директории.
        
        Находит все SBOM файлы в настроенной директории и обрабатывает их.
        Ведет статистику успешно обработанных файлов и ошибок.
        """
        if not self.handler.sbomsList:
            logging.warning(f"Не найдено SBOM файлов в директории: {self.config.sbom_dir}")
            return
        
        self.config.ensure_directories_exist()
        
        processed_count = 0
        error_count = 0
        
        for sbom_path in self.handler.sbomsList:
            try:
                self._process_single_sbom(sbom_path)
                processed_count += 1
            except SbomProcessingError as e:
                logging.error(str(e))
                error_count += 1
            except Exception as e:
                logging.error(f"Неожиданная ошибка при обработке {sbom_path}: {e}")
                error_count += 1
        
        logging.info(f"Обработка завершена. Успешно: {processed_count}, с ошибками: {error_count}")


def parse_arguments() -> argparse.Namespace:
    """
    Парсинг аргументов командной строки.
    
    Returns:
        Объект с разобранными аргументами командной строки
    """
    parser = argparse.ArgumentParser(
        description="Форматировщик SBOM файлов для экспорта в Excel и ODT форматы",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s
  %(prog)s --sbom-dir /path/to/sbom --report-dir /path/to/reports
  %(prog)s --verbose
        """
    )
    
    parser.add_argument(
        "--sbom-dir",
        type=str,
        help=f"Путь к директории с SBOM файлами (по умолчанию: ../{SBOM_OUT_DIR})"
    )
    
    parser.add_argument(
        "--report-dir",
        type=str,
        help=f"Путь к директории для отчетов (по умолчанию: ../{REPORTS_DIR})"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Подробный вывод логирования"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0"
    )
    
    return parser.parse_args()


def setup_logging(verbose: bool = False) -> None:
    """
    Настройка логирования.
    
    Args:
        verbose: Включить подробное логирование (DEBUG уровень)
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger().setLevel(log_level)


def main() -> int:
    """
    Основная функция программы.
    
    Инициализирует конфигурацию, парсит аргументы командной строки
    и запускает обработку SBOM файлов.
    
    Returns:
        Код возврата: 0 при успехе, не 0 при ошибке
    """
    try:
        args = parse_arguments()
        setup_logging(args.verbose)
        
        logging.info("Старт обработки SBOM файлов")
        
        config = FormatterConfig(args.sbom_dir, args.report_dir)
        formatter = SbomFormatter(config)
        formatter.process_all_sboms()
        
        logging.info("Обработка SBOM файлов завершена успешно")
        return 0
        
    except SbomFormatterError as e:
        logging.error(f"Ошибка форматирования: {e}")
        return 1
    except KeyboardInterrupt:
        logging.info("Операция прервана пользователем")
        return 130
    except Exception as e:
        logging.exception(f"Неожиданная ошибка: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
