import os
import pandas as pd
import logging
from odf.opendocument import OpenDocumentText
from odf.style import Style, TableCellProperties, TextProperties, ParagraphProperties
from odf.table import Table, TableRow, TableCell
from odf.text import P
from typing import Optional

from sbom_signer import SbomSigner

class Exporter:
    def __init__(self, externalDeps: list, sbom_path: Optional[str] = None,
                 private_key_path: Optional[str] = None,
                 public_key_path: Optional[str] = None,
                 key_passphrase: Optional[str] = None,
                 sign_sbom: bool = False):
        # List of Dependency-like objects
        self.externalDepsList = externalDeps
        # Optional SBOM path to sign
        self.sbom_path = sbom_path
        # Prepare signer if requested
        self.sign_sbom = sign_sbom and sbom_path is not None
        self._sbom_signer: Optional[SbomSigner] = None
        if self.sign_sbom:
            try:
                self._sbom_signer = SbomSigner(
                    private_key_path=private_key_path,
                    public_key_path=public_key_path,
                    key_passphrase=key_passphrase
                )
                logging.info("Инициализирован SbomSigner для подписи SBOM")
            except Exception as e:
                logging.exception(f"Не удалось инициализировать SbomSigner: {e}")
                self.sign_sbom = False
        self.columns = [
            '№ п/п',
            'Наименование компонента',
            'Версия компонента',
            'Язык (языки)',
            'Принадлежность компонента к поверхности атаки программного обеспечения и (или) к компонентам, реализующим функции безопасности',
            'Адрес веб-ресурса'
        ]
        logging.info(f"Инициализация Exporter с {len(externalDeps)} зависимостями")

    def _ensure_directory_exists(self, file_path):
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            logging.info(f"Создана директория: {directory}")

    def _sign_file(self, file_path: str):
        """Create a detached signature file next to the report.
        Default: SHA256 checksum in <file>.sig.
        Optional: If GPG signing is configured via env (GPG_KEY_ID), try gpg.
        """
        try:
            import hashlib
            sig_path = f"{file_path}.sig"
            with open(file_path, 'rb') as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            with open(sig_path, 'w', encoding='utf-8') as sf:
                sf.write(f"SHA256={digest}\n")
            logging.info(f"Создана подпись (SHA256): {sig_path}")
        except Exception as e:
            logging.exception(f"Ошибка создания подписи для {file_path}: {e}")

    def exportToExcel(self, report: str):
        try:
            logging.info(f"Экспорт в Excel: {report}")
            self._ensure_directory_exists(report)
            rows = [
                {
                    self.columns[0]: i+1,
                    self.columns[1]: getattr(c, 'name', ''),
                    self.columns[2]: getattr(c, 'version', ''),
                    self.columns[3]: ", ".join(getattr(c, 'src_langs', getattr(c, 'srcLangs', [])) or []),
                    self.columns[4]: ", ".join(
                        str(x) if not isinstance(x, dict) else f"{x.get('name', '')}={x.get('value', '')}"
                        for x in (getattr(c, 'dep_type', getattr(c, 'depType', [])) or [])
                    ),
                    self.columns[5]: getattr(c, 'source', getattr(c, 'purl', '')),
                }
                for i, c in enumerate(self.externalDepsList)
            ]
            logging.info(f"Формирование DataFrame: {len(rows)} строк")
            dataFrame = pd.DataFrame(rows, columns=self.columns)
            dataFrame.to_excel(report, index=False)
            logging.info(f"Экспорт в Excel завершен: {report}")
            # подпись отчета
            self._sign_file(report)
            # подпись исходного SBOM (если включено)
            if self.sign_sbom and self._sbom_signer and self.sbom_path:
                try:
                    signed_path = self._sbom_signer.sign_file(self.sbom_path)
                    logging.info(f"SBOM подписан: {signed_path}")
                except Exception as e:
                    logging.exception(f"Ошибка подписи SBOM {self.sbom_path}: {e}")
        except Exception as e:
            logging.exception(f"Ошибка при экспорте в Excel {report}: {e}")

    def exportToOdt(self, report: str):
        try:
            logging.info(f"Экспорт в ODT: {report}")
            self._ensure_directory_exists(report)
            doc = OpenDocumentText()
            table = Table(name="SBOM Table")

            titleStyle = Style(name="Title", family="paragraph")
            titleStyle.addElement(ParagraphProperties())
            titleStyle.addElement(TextProperties(fontsize="16pt", fontweight="bold"))
            doc.styles.addElement(titleStyle)

            doc.text.addElement(P(text="Таблица компонентов", stylename=titleStyle))

            cellStyle = Style(name="CellBorders", family="table-cell")
            cellStyle.addElement(TableCellProperties(border="0.05pt solid #808080"))
            doc.styles.addElement(cellStyle)

            headerRow = TableRow()
            for column in self.columns:
                cell = TableCell(stylename=cellStyle)
                cell.addElement(P(text=column))
                headerRow.addElement(cell)
            table.addElement(headerRow)

            for i, c in enumerate(self.externalDepsList, start=1):
                row = TableRow()
                name = getattr(c, 'name', '')
                version = getattr(c, 'version', '')
                langs = ", ".join(getattr(c, 'src_langs', getattr(c, 'srcLangs', [])) or [])
                dep_type = ", ".join(
                    str(x) if not isinstance(x, dict) else f"{x.get('name', '')}={x.get('value', '')}"
                    for x in (getattr(c, 'dep_type', getattr(c, 'depType', [])) or [])
                )
                source = getattr(c, 'source', getattr(c, 'purl', ''))
                rowData = [i, name, version, langs, dep_type, source]
                for cellValue in rowData:
                    cell = TableCell(stylename=cellStyle)
                    cell.addElement(P(text=str(cellValue)))
                    row.addElement(cell)
                table.addElement(row)

            doc.text.addElement(table)
            doc.save(report)
            logging.info(f"Экспорт в ODT завершен: {report}")
            # подпись отчета
            self._sign_file(report)
            # подпись исходного SBOM (если включено)
            if self.sign_sbom and self._sbom_signer and self.sbom_path:
                try:
                    signed_path = self._sbom_signer.sign_file(self.sbom_path)
                    logging.info(f"SBOM подписан: {signed_path}")
                except Exception as e:
                    logging.exception(f"Ошибка подписи SBOM {self.sbom_path}: {e}")
        except Exception as e:
            logging.exception(f"Ошибка при экспорте в ODT {report}: {e}")
