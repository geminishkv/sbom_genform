import logging
import os
from dotenv import load_dotenv

from sbom_handler import SbomHandler
from exporter import Exporter
from dependency import Dependency

logging.basicConfig(
    format='%(asctime)s [%(levelname)s] %(message)s',
    level=logging.INFO,
    handlers=[logging.FileHandler('app.log'), logging.StreamHandler()]
)
load_dotenv()

DepsMemory = []

def process_sboms(sbom_dir, report_dir):
    handler = SbomHandler(sbom_dir)
    for sbom_path in handler.sbomsList:
        sbom_content = handler.readJson(sbom_path)
        if sbom_content is None:
            continue
        base = os.path.basename(sbom_path).replace('.json', '')
        excel_name = f"{report_dir}/excel/{base}.xlsx"
        odt_name = f"{report_dir}/odt/{base}.odt"
        all_dependencies = [
            Dependency(c['name'], c['version'], [], c['purl'], sbom_path)
            for c in sbom_content.get('components', []) if c.get('type') == 'library'
        ]
        exporter = Exporter(all_dependencies)
        exporter.exportToExcel(excel_name)
        exporter.exportToOdt(odt_name)

if __name__ == "__main__":
    logging.info("Старт обработки SBOM файлов")
    process_sboms("../sbom/git", "../reports/git")
    logging.info("Переходим к images")
    process_sboms("../sbom/images", "../reports/images")
    logging.info("Обработка завершена")
