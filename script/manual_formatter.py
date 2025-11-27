import os
import logging
from pathlib import Path

from sbom_handler import SbomHandler
from exporter import Exporter
from dotenv import load_dotenv
from dependency import Dependency

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()],
)
load_dotenv()

DepsMemory = []

def process_sboms(sbom_dir, report_dir):
    handler = SbomHandler(sbom_dir)
    for sbom_path in handler.sbomsList:
        sbom_content = handler.readJson(sbom_path)
        if sbom_content is None:
            continue

        base = os.path.basename(sbom_path).replace(".json", "")
        excel_name = f"{report_dir}/excel/{base}.xlsx"
        odt_name = f"{report_dir}/odt/{base}.odt"

        all_dependencies = [
            Dependency(c["name"], c["version"], [], c.get("purl"), sbom_path)
            for c in sbom_content.get("components", [])
            if c.get("type") == "library"
        ]

        exporter = Exporter(all_dependencies)
        exporter.exportToExcel(excel_name)
        exporter.exportToOdt(odt_name)

if __name__ == "__main__":
    logging.info("Старт ручной обработки SBOM файлов (sbom/)")

    base_dir = Path(__file__).resolve().parent

    # demo git SBOM -> reports/git
    process_sboms(str(base_dir.parent / "sbom" / "git"),
                  str(base_dir.parent / "reports" / "git"))

    logging.info("Переходим к images")

    # demo images SBOM -> reports/images
    process_sboms(str(base_dir.parent / "sbom" / "images"),
                  str(base_dir.parent / "reports" / "images"))

    logging.info("Ручная обработка sbom/ завершена")
