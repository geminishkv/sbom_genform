import os
import pandas as pd
import logging
from odf.opendocument import OpenDocumentText
from odf.style import Style, TableCellProperties, TextProperties, ParagraphProperties
from odf.table import Table, TableRow, TableCell
from odf.text import P

class Exporter:
    def __init__(self, externalDeps: list):
        self.externalDepsList = externalDeps
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

    def exportToExcel(self, report: str):
        try:
            logging.info(f"Экспорт в Excel: {report}")
            self._ensure_directory_exists(report)
            rows = [
                {
                    self.columns[0]: i+1,
                    self.columns[1]: c.name,
                    self.columns[2]: c.version,
                    self.columns[3]: ", ".join(c.srcLangs),
                    self.columns[4]: ", ".join(c.depType),
                    self.columns[5]: c.source,
                }
                for i, c in enumerate(self.externalDepsList)
            ]
            logging.info(f"Формирование DataFrame: {len(rows)} строк")
            dataFrame = pd.DataFrame(rows, columns=self.columns)
            dataFrame.to_excel(report, index=False)
            logging.info(f"Экспорт в Excel завершен: {report}")
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
                rowData = [i, c.name, c.version, ", ".join(c.srcLangs), ", ".join(c.depType), c.source]
                for cellValue in rowData:
                    cell = TableCell(stylename=cellStyle)
                    cell.addElement(P(text=str(cellValue)))
                    row.addElement(cell)
                table.addElement(row)

            doc.text.addElement(table)
            doc.save(report)
            logging.info(f"Экспорт в ODT завершен: {report}")
        except Exception as e:
            logging.exception(f"Ошибка при экспорте в ODT {report}: {e}")
