import os
import json
import logging
from os import listdir
from os.path import isfile, join

class SbomHandler:
    def __init__(self, sbomDirectory: str):
        self.sbomDirectory = sbomDirectory
        if not os.path.isdir(sbomDirectory):
            logging.warning(f"Директория SBOM не найдена: {sbomDirectory}")
            self.sbomsList = []
        else:
            self.sbomsList = [join(sbomDirectory, f) for f in listdir(sbomDirectory) if isfile(join(sbomDirectory, f))]
        logging.info(f"SbomHandler инициализирован: {len(self.sbomsList)} файлов в {sbomDirectory}")

    def readJson(self, path):
        logging.info(f"Чтение SBOM: {path}")
        try:
            with open(path, 'r', encoding='utf-8') as sbomContent:
                jsonData = json.load(sbomContent)
            return jsonData
        except json.JSONDecodeError as e:
            logging.error(f"Исходный SBOM файл {path} не соответствует формату JSON: {e}")
            return None
        except Exception as e:
            logging.exception(f"Ошибка при обработке файла {path}: {e}")
            return None
