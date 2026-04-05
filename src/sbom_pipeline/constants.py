"""Общие константы для всего пакета sbom_pipeline."""

# Компоненты
COMPONENT_TYPE_LIBRARY = "library"

# Логирование
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_FILE = "sbom_pipeline.log"

# Расширения
JSON_EXTENSION = ".json"
EXCEL_EXTENSION = ".xlsx"
ODT_EXTENSION = ".odt"
DOCX_EXTENSION = ".docx"
SIG_EXTENSION = ".sig"

# Имена директорий (по умолчанию)
EXCEL_DIR = "excel"
ODT_DIR = "odt"
DOCX_DIR = "docx"
SBOM_OUT_DIR = "secgensbom_out"
REPORTS_DIR = "secgensbom_reports"

# Имена файлов артефактов
APP_BOM_FILE = "app-bom-cdxgen.json"
DEDUP_BOM_FILE = "app-bom-dedup.json"
SIGNED_DEDUP_BOM_FILE = "app-bom-dedup-signed.json"   # SBOM без уязвимостей
SIGNED_BOM_FILE = "merged-bom-signed.json"            # SBOM с уязвимостями

# Субдиректории сканеров
TRIVY_DIR = "trivy"
CLAIR_DIR = "clair"
DEPCHECK_DIR = "dependency-check"

# CycloneDX
CYCLONEDX_SPEC_VERSION = "1.5"
CYCLONEDX_FORMAT = "CycloneDX"
