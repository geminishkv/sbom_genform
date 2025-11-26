<div align="center">
<h1><a id="intro"> Infopage <sup></sup></a><br></h1>
<a href="https://docs.github.com/en"><img src="https://img.shields.io/static/v1?logo=github&logoColor=fff&label=&message=Docs&color=36393f&style=flat" alt="GitHub Docs"></a>
<a href="https://daringfireball.net/projects/markdown"><img src="https://img.shields.io/static/v1?logo=markdown&logoColor=fff&label=&message=Markdown&color=36393f&style=flat" alt="Markdown"></a> 
<a href="https://symbl.cc/en/unicode-table"><img src="https://img.shields.io/static/v1?logo=unicode&logoColor=fff&label=&message=Unicode&color=36393f&style=flat" alt="Unicode"></a> 
<a href="https://shields.io"><img src="https://img.shields.io/static/v1?logo=shieldsdotio&logoColor=fff&label=&message=Shields&color=36393f&style=flat" alt="Shields"></a>
<img src="https://img.shields.io/badge/Contributor-Шмаков_И._С.-8b9aff" alt="Contributor Badge"></a></div>

***

<br>Салют :wave:,</br>


<div align="center"><h3>Stay tuned ;)</h3></div> 


### Структура репозитория

```
├── assets
│   └── logotype
│       ├── logo.jpg
│       └── logo2.jpg
├── cheatsheet
│   ├── CHEATSHEET_DOCKER.md
│   ├── CHEATSHEET_DOCKERIGNORE.md
│   ├── CHEATSHEET_GH_CLI.md
│   ├── CHEATSHEET_GIT.md
│   └── CHEATSHEET_GITIGNORE.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE.md
├── NOTICE.md
├── README.md
└── SECURITY.md
```
sbom_project/
  formatter.py           # основной скрипт, точка входа
  exporter.py            # экспорт отчетов
  sbom_handler.py        # работа с SBOM-файлами
  dependency.py          # обработка зависимостей
  utils.py               # утилиты
  requirements.txt

Кратко:
	•	formatter.py: логгер, dotenv, DetsMemory, основной запуск.
	•	exporter.py: pandas+ODF для отчетов.
	•	sbom_handler.py: файловые операции, парсинг JSON.
	•	dependency.py: обработка каждой зависимости, http-запросы, BeautifulSoup и purl.
	•	utils.py: функции для парсинга, обработки строк, вспомогательные утилиты.
Такой подход — best practice для Python: читаемость, гибкость, отдельное тестирование, повторное использование функций/классов


Импортируются необходимые библиотеки, настраивается логирование, загружаются системные переменные.
— Это основа для работы со всеми файлами, API и логами.

Экспортирует собранные зависимости в Excel через pandas и ODT через odf.opendocument. Предварительно создает директорию для отчета (если надо).

В конструкторе формируется список файлов SBOM в директории.  readJson  загружает JSON-файл SBOM для дальнейшей работы.

Для каждого компонента из SBOM формируется объект. В конструкторе определяется название, версия, тип зависимости и путь.
	•	Разбирается purl, определяется источник/репозиторий.
	•	Для npm, Maven, NuGet — запросы к GitHub API для определения языков через:
	•	Для других типов — формируются дефолтные значения или используются другие API (Debian, PyPI, Maven Central).

Обходит все SBOM-файлы в директории:
	•	Читает SBOM как JSON.
	•	Извлекает только компоненты типа  library .
	•	Для каждого компонента создает объект  Dependency , определяет язык, источник и прочую инфу.
	•	Создает отчёты Excel/ODT для каждого файла.

    Скрипт проходит по двум директориям с SBOM, экспортируя для каждой отчеты.

Итого
	•	Импортируются библиотеки и настраивается логгер.
	•	Классы Exporter и SbomHandler отвечают за сборку, экспорт и обработку SBOM-файлов.
	•	Класс Dependency определяет детали и происхождение каждой зависимости через сторонние API.
	•	Весь процесс автоматизирует формирование отчетов для аудита сторонних библиотек в виде Excel/ODT, используя две указанной директории.


Работа из окружения
python3 -m venv venv 
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python formatter.py
deactivate




cdxgen -r рекурсивно сканирует директорию проекта и генерирует CycloneDX SBOM (по умолчанию JSON). 
	•	Для контейнера cdxgen  -t docker -o bom.json генерирует SBOM по установленному/локальному образу. 
	•	OWASP Dependency-Check в Docker-режиме монтирует исходники и пишет отчёты в /report. 
	•	Clair-часть сильно зависит от твоей конкретной установки (quay/clair, clairctl, интеграция в CI/CD), поэтому оставлена как условный блок.


Пример для локальной разработки:
	•	chmod +x generate_sbom_and_scan.sh
	•	docker build -t myapp:latest .
	•	PROJECT_DIR=$(pwd) IMAGE_NAME=myapp:latest ./generate_sbom_and_scan.sh
После выполнения:
	•	sbom_out/app-bom-cdxgen.json — SBOM по коду.
	•	sbom_out/image-bom-cdxgen.json — SBOM по контейнеру.
	•	sbom_out/dependency-check-report/* — HTML/XML/JSON отчёты Dependency-Check.
	•	sbom_out/clair-*.json — отчёт Clair (если настроен).



Шаги:

	•	из корня репо:
	•	docker build -t sbom-formatter:latest .
 права:
	•	cd secgensbom
	•	chmod +x *.sh

	•	из secgensbom:
	•	./pipeline.sh

	•	REPO_ROOT=/path/to/repo IMAGE_NAME=myapp:latest ./pipeline.sh
На выходе:
	•	secgensbom_out/app-bom-cdxgen.json — SBOM по коду (script/).
	•	secgensbom_out/image-bom-trivy.json — SBOM по образу.
	•	secgensbom_out/merged-bom-signed.json — общий подписанный SBOM с дедупликацией.
	•	secgensbom_out/dependency-check/* — отчёты SCA.
	•	secgensbom_out/trivy/* — отчёты Trivy по образу и SBOM.
	•	secgensbom_out/clair/* — отчёты Clair (если настроен).



***

### Сопроводительыне материалы

# SBOM Formatter

Инструмент для обработки и анализа SBOM (Software Bill of Materials) файлов с экспортом результатов в различные форматы.

## Возможности

- **Чтение SBOM файлов** в формате JSON (CycloneDX)
- **Автоматическое определение** информации о компонентах:
  - Язык программирования
  - Источник исходного кода
  - Тип компонента
  - Внешняя или внутренняя зависимость(ebp, lanit)
- **Поддержка различных пакетных менеджеров**:
  - Maven (Java)
  - PyPI (Python)
  - NPM (JavaScript)
  - Debian packages
- **Экспорт результатов** в форматы:
  - Excel (.xlsx)
  - OpenDocument Text (.odt)

## Установка и настройка

### Установка 
```bash
python -m venv .venv
source .venv/bin/activate #.\.venv\Scripts\activate Для PowerShell
pip install -r requirements.txt
```

***

### Настройка окружения

Создайте файл `.env` в корневой директории:

```env
GITHUB_TOKEN=your_github_token_here
```

GitHub токен необходим для обхода ограничений API rate limits.

## Использование

## Примеры использования

### Обработка GitLab SBOM
```bash
# Поместите SBOM файлы в sboms/gitlab/
python main.py
# Результаты будут в reports/gitlab/
```

### Обработка SBOM из образов ВМ
```bash
# Поместите SBOM файлы в sboms/images/
python main.py
# Результаты будут в reports/images/
```
В результате работы получаются два файла .odt и .xlsx:
![](imgs/excel.png)

![](imgs/odt.png)

### Интеграция с CI/CD
Пример для GitLab CI:
```yaml
sbom_processing:
  stage: post-processing
  script:
    - pip install -r requirements.txt
    - python main.py
  artifacts:
    paths:
      - reports/
```

***


Copyright (c) 2025 Elijah S Shmakov


![Logo](assets/logotype/logo.jpg)


