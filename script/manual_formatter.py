import os
import argparse
import logging
from pathlib import Path

from sbom_handler import SbomHandler
from exporter import Exporter
from dotenv import load_dotenv
from dependency import Dependency
from constants import EXCEL_DIR, ODT_DIR

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()],
)
load_dotenv()


def process_sboms(sbom_dir, report_dir, src_langs=None, signer_opts=None):
    handler = SbomHandler(sbom_dir)
    for sbom_path in handler.sbomsList:
        sbom_content = handler.readJson(sbom_path)
        if sbom_content is None:
            continue

        base = os.path.basename(sbom_path).replace(".json", "")
        excel_name = f"{report_dir}/{EXCEL_DIR}/{base}.xlsx"
        odt_name = f"{report_dir}/{ODT_DIR}/{base}.odt"

        all_dependencies = []
        for c in sbom_content.get("components", []):
            if c.get("type") != "library":
                continue
            dep = Dependency(
                name=c.get("name", ""),
                version=c.get("version", ""),
                dep_type=c.get("properties", []) if isinstance(c.get("properties"), list) else [],
                purl=c.get("purl"),
                path_to_sbom=sbom_path,
            )
            # annotate languages if provided
            if src_langs:
                setattr(dep, 'src_langs', src_langs)
            # try to store source
            setattr(dep, 'source', c.get('purl') or c.get('supplier') or '')
            all_dependencies.append(dep)

        exporter = Exporter(
            all_dependencies,
            sbom_path=sbom_path,
            private_key_path=(signer_opts or {}).get('private_key_path'),
            public_key_path=(signer_opts or {}).get('public_key_path'),
            key_passphrase=(signer_opts or {}).get('key_passphrase'),
            sign_sbom=bool(signer_opts)
        )
        exporter.exportToExcel(excel_name)
        exporter.exportToOdt(odt_name)

def detect_langs_from_deps(deps_file: str) -> list:
    """Infer source language(s) from dependency file name.
    This is a lightweight heuristic and does not parse the file deeply.
    """
    base = os.path.basename(deps_file).lower()
    if base == 'requirements.txt' or base == 'pyproject.toml' or base.endswith('poetry.lock'):
        return ['Python']
    if base == 'package.json' or base == 'package-lock.json' or base == 'pnpm-lock.yaml' or base == 'yarn.lock':
        return ['JavaScript', 'Node.js']
    if base == 'pom.xml' or base.endswith('.gradle') or base.endswith('build.gradle.kts'):
        return ['Java']
    if base.endswith('.csproj') or base.endswith('packages.config'):
        return ['C#', '.NET']
    if base.endswith('go.mod'):
        return ['Go']
    if base.endswith('composer.json') or base.endswith('composer.lock'):
        return ['PHP']
    # default unknown
    return []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Генерация отчётов *.xlsx и *.odt по SBOM с подписью")
    parser.add_argument('--bom', dest='bom', help='Путь к SBOM JSON файлу или директории с SBOM', required=False)
    parser.add_argument('--deps', dest='deps', help='Путь к файлу зависимостей (requirements.txt, pom.xml, package.json и т.д.)', required=False)
    parser.add_argument('--out', dest='out', help='Директория для сохранения отчётов', required=False)
    parser.add_argument('--sign', dest='sign', help='Включить подпись SBOM (RSA)', action='store_true')
    parser.add_argument('--private-key', dest='private_key', help='Путь к приватному ключу PEM', required=False)
    parser.add_argument('--public-key', dest='public_key', help='Путь к публичному ключу PEM', required=False)
    parser.add_argument('--pass', dest='passphrase', help='Пароль для приватного ключа', required=False)
    parser.add_argument('--setup-env', dest='setup_env', help='Создать служебные директории для SecGenSBOM', action='store_true')
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent

    # optional environment setup for SecGenSBOM
    if args.setup_env:
        logging.info("Настройка служебных директорий SecGenSBOM...")
        try:
            from setup_secgensbom_env import main as setup_env_main
            setup_env_main()
        except Exception as e:
            logging.exception(f"Ошибка при настройке окружения SecGenSBOM: {e}")
    out_root = Path(args.out) if args.out else (base_dir.parent / 'reports' / 'manual')
    excel_dir = out_root / EXCEL_DIR
    odt_dir = out_root / ODT_DIR
    excel_dir.mkdir(parents=True, exist_ok=True)
    odt_dir.mkdir(parents=True, exist_ok=True)

    src_langs = detect_langs_from_deps(args.deps) if args.deps else []

    signer_opts = None
    if args.sign:
        signer_opts = {
            'private_key_path': args.private_key,
            'public_key_path': args.public_key,
            'key_passphrase': args.passphrase,
        }

    if args.bom:
        # If a single file is provided, process it; if a directory, process all
        if os.path.isdir(args.bom):
            logging.info(f"Обработка SBOM из директории: {args.bom}")
            process_sboms(args.bom, str(out_root), src_langs=src_langs, signer_opts=signer_opts)
        else:
            logging.info(f"Обработка единичного SBOM: {args.bom}")
            handler = SbomHandler(os.path.dirname(args.bom) or '.')
            sbom_content = handler.readJson(args.bom)
            if sbom_content:
                base = os.path.basename(args.bom).replace('.json', '')
                excel_name = str(excel_dir / f"{base}.xlsx")
                odt_name = str(odt_dir / f"{base}.odt")
                all_dependencies = []
                for c in sbom_content.get("components", []):
                    if c.get("type") != "library":
                        continue
                    dep = Dependency(
                        name=c.get("name", ""),
                        version=c.get("version", ""),
                        dep_type=c.get("properties", []) if isinstance(c.get("properties"), list) else [],
                        purl=c.get("purl"),
                        path_to_sbom=args.bom,
                    )
                    if src_langs:
                        setattr(dep, 'src_langs', src_langs)
                    setattr(dep, 'source', c.get('purl') or c.get('supplier') or '')
                    all_dependencies.append(dep)
                exporter = Exporter(
                    all_dependencies,
                    sbom_path=args.bom,
                    private_key_path=(signer_opts or {}).get('private_key_path'),
                    public_key_path=(signer_opts or {}).get('public_key_path'),
                    key_passphrase=(signer_opts or {}).get('key_passphrase'),
                    sign_sbom=bool(signer_opts)
                )
                exporter.exportToExcel(excel_name)
                exporter.exportToOdt(odt_name)
    else:
        # fallback to demo directories as before
        logging.info("Старт ручной обработки SBOM файлов (sbom/)")
        # demo git SBOM -> reports/git
        process_sboms(str(base_dir.parent / "sbom" / "git"),
                      str(base_dir.parent / "reports" / "git"), signer_opts=signer_opts)
        logging.info("Переходим к images")
        # demo images SBOM -> reports/images
        process_sboms(str(base_dir.parent / "sbom" / "images"),
                      str(base_dir.parent / "reports" / "images"), signer_opts=signer_opts)
        logging.info("Ручная обработка sbom/ завершена")
