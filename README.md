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


	•	cd secgensbom
	•	chmod +x *.sh
	2.	Запустить только генерацию SBOM (без сканов):
	•	./sbom_generate.sh
Что произойдёт:
	•	cdxgen сгенерит SBOM по коду из script/ в файл:
	•	secgensbom_out/app-bom-cdxgen.json 
	•	Trivy сгенерит SBOM по образу (IMAGE_NAME из config.env, по умолчанию sbom-formatter:latest) в файл:
	•	secgensbom_out/image-bom-trivy.json 
Предварительно образ надо собрать, например:
	•	docker build -t sbom-formatter:latest .
Вариант B: напрямую, без пайплайна
	1.	SBOM по коду из script/ через cdxgen:
	•	cd script
	•	cdxgen -r -o ../secgensbom_out/app-bom-cdxgen.json –spec-version 1.5
	2.	SBOM по образу через Trivy:
	•	docker build -t sbom-formatter:latest .
	•	trivy image –format cyclonedx –output secgensbom_out/image-bom-trivy.json sbom-formatter:latest 
Оба файла можно потом кормить твоему formatter.py или использовать для мерджа/подписи.
2. Как подписать SBOM из терминала
Подпись делает cdxgen, ему нужны ключи и переменные окружения. 
	1.	Сгенерировать ключи (один раз, пример):
	•	mkdir -p keys
	•	openssl genrsa -out keys/sbom_sign_private.pem 4096
	•	openssl rsa -in keys/sbom_sign_private.pem -pubout -out keys/sbom_sign_public.pem
	2.	Убедиться, что в secgensbom/config.env пути совпадают:
	•	SBOM_SIGN_PRIVATE_KEY=”${REPO_ROOT}/keys/sbom_sign_private.pem”
	•	SBOM_SIGN_PUBLIC_KEY=”${REPO_ROOT}/keys/sbom_sign_public.pem”
	3.	Подписать SBOM через sbom_merge_sign.sh (он заодно мерджит и дедуплицирует):
	•	cd secgensbom
	•	./sbom_merge_sign.sh
Вход:
	•	secgensbom_out/app-bom-cdxgen.json
	•	secgensbom_out/image-bom-trivy.json
Выход:
	•	secgensbom_out/merged-bom-signed.json — общий подписанный SBOM (CycloneDX), после мерджа и дедуплицирования. 
Если хочешь подписать какой-то отдельный SBOM вручную:
	•	SBOM_SIGN_ALGORITHM=RS512  SBOM_SIGN_PRIVATE_KEY=keys/sbom_sign_private.pem  SBOM_SIGN_PUBLIC_KEY=keys/sbom_sign_public.pem  cdxgen –sign –spec-version 1.5 –input-bom secgensbom_out/app-bom-cdxgen.json –output secgensbom_out/app-bom-signed.json 
Проверка подписи (опционально):
	•	cdx-verify -i secgensbom_out/app-bom-signed.json –public-key keys/sbom_sign_public.pem 
3. Как выполнить все скрипты (полный пайплайн)
Полный цикл: генерация SBOM (код + образ) → мердж + дедуп + подпись → Dependency-Check → Trivy → Clair.
	1.	Подготовка:
	•	из корня: docker build -t sbom-formatter:latest .
	•	убедись, что стоят: cdxgen, cyclonedx-cli, trivy, docker, (опционально) clairctl. 
	•	в secgensbom/config.env IMAGE_NAME по умолчанию уже sbom-formatter:latest, PROJECT_DIR указывает на script/, REPO_ROOT вычисляется автоматически.
	2.	Один раз:
	•	cd secgensbom
	•	chmod +x *.sh
	3.	Запуск полного пайплайна:
	•	./pipeline.sh
Что сделает pipeline.sh:
	•	вызовет sbom_generate.sh
	•	создаст secgensbom_out/app-bom-cdxgen.json и secgensbom_out/image-bom-trivy.json.
	•	вызовет sbom_merge_sign.sh
	•	смерджит два SBOM, сделает дедуп, провалидирует и создаст secgensbom_out/merged-bom-signed.json (подписанный общий SBOM).
	•	вызовет scan_dependency_check.sh
	•	прогонит OWASP Dependency-Check по script/ в докере, отчёты положит в secgensbom_out/dependency-check/. 
	•	вызовет scan_trivy.sh
	•	просканирует образ sbom-formatter:latest и подписанный SBOM, отчёты в secgensbom_out/trivy/. 
	•	вызовет scan_clair.sh (если есть clairctl)
	•	просканирует образ через Clair, отчёты в secgensbom_out/clair/. 
Ключевой артефакт, который ты дальше можешь брать как “единый источник правды” для formatter.py и внешних систем:
	•	secgensbom_out/merged-bom-signed.json — общий подписанный SBOM с учётом дедуплификации.

formatter

docker build -f Dockerfile.formatter -t sbom-formatter:latest .

docker run --rm -it \
  -v "$(pwd)/sbom:/app/sbom" \
  -v "$(pwd)/reports:/app/reports" \
  sbom-formatter:latest
 

 reports/ и /sbom для скрипта форматтер, что бы туда его подложить

secgensbom (SBOM‑пайплайн)

docker build -f Dockerfile.formatter -t sbom-formatter:inside .
docker images | grep sbom-formatter
docker build -f Dockerfile.secgensbom -t secgensbom-tool:latest . 
# либо с --no-cache при возможных ошибках
docker build --no-cache -f Dockerfile.secgensbom -t secgensbom-tool:latest .

trivy image --format cyclonedx -o secgensbom_out/image-bom-trivy.json sbom-formatter:latest # с хоста, вне контейнера

rm -f secgensbom_out/*
export HOST_OUTPUT_DIR="$(pwd)/secgensbom_out"

docker run --rm -it \
  -v "$(pwd)/sbom:/app/sbom" \
  -v "$(pwd)/reports:/app/reports" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e HOST_OUTPUT_DIR="${HOST_OUTPUT_DIR}" \
  secgensbom-tool:latest \
  /app/secgensbom/pipeline.sh


mkdir -p project_inject
mkdir -p secgensbom_out
docker build --no-cache -f Dockerfile.secgensbom -t secgensbom-tool:latest .

PROJECT_SRC="/Users/you/projects/my-app"

docker run --rm -it \
  -v "${PROJECT_SRC}:/app/project_inject" \
  -v "$(pwd)/reports:/app/reports" \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e PROJECT_DIR="/app/project_inject" \
  -e HOST_PROJECT_DIR="${PROJECT_SRC}" \
  -e OUTPUT_DIR="/app/secgensbom_out" \
  secgensbom-tool:latest \
  /app/secgensbom/pipeline.sh

# Дедупликация
docker run --rm -it \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e OUTPUT_DIR="/app/secgensbom_out" \
  secgensbom-tool:latest \
  /app/secgensbom/sbom_dedup.sh



# Проверка наличия docker
docker run --rm -it secgensbom-tool:latest /bin/bash
which docker
docker --version
-e HOST_OUTPUT_DIR="${HOST_OUTPUT_DIR}" \
secgensbom-tool:latest \
env | grep HOST_OUTPUT_DIR
exit

unset HOST_OUTPUT_DIR
export HOST_OUTPUT_DIR=”$(pwd)/secgensbom_out”
env | grep HOST_OUTPUT_DIR
docker run



docker build --no-cache -f Dockerfile.secgensbom -t secgensbom-tool:latest .

mkdir -p secgensbom_out

export HOST_PROJECT_DIR="$(pwd)/script"

docker run --rm -it \
  -v "$(pwd)/sbom:/app/sbom" \
  -v "$(pwd)/reports:/app/reports" \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e HOST_PROJECT_DIR="${HOST_PROJECT_DIR}" \
  secgensbom-tool:latest \
  /app/secgensbom/pipeline.sh

# обычный порядок

mkdir -p secgensbom_out
mkdir -p "$DEP_CHECK_DATA"

export DEP_CHECK_DATA="$(pwd)/.dependency-check-data"
export HOST_OUTPUT_DIR="$(pwd)/secgensbom_out"
export HOST_PROJECT_DIR="$(pwd)/script"

docker build --no-cache -f Dockerfile.secgensbom -t secgensbom-tool:latest .

# SBOM + подпись + depcheck и т.п.
docker run --rm -it \
  -v "$(pwd)/sbom:/app/sbom" \
  -v "$(pwd)/reports:/app/reports" \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e HOST_OUTPUT_DIR="${HOST_OUTPUT_DIR}" \
  -e HOST_PROJECT_DIR="${HOST_PROJECT_DIR}" \
  -e DEP_CHECK_DATA="${DEP_CHECK_DATA}" \
  secgensbom-tool:latest \
  /app/secgensbom/pipeline.sh

 

# Сначала делаем руками и после можно автоматически так
python3 script/setup_secgensbom_env.py

vim ~/.zshrc

secgensbom_env() {
  local out
  out="$(python3 script/setup_secgensbom_env.py)"
  eval "export ${out//$'\n'/; export }"
}

source ~/.zshrc
nano ~/.bashrc
source ~/.bashrc
secgensbom_env


# Запуск и сборка

docker build -f Dockerfile.secgensbom -t secgensbom-tool:latest .

mkdir -p project_inject
mkdir -p secgensbom_out
mkdir -p secgensbom_out/dependency-check
mkdir -p secgensbom_out/trivy
mkdir -p secgensbom_out/clair
mkdir -p .dependency-check-data

# Clair на docker-compose при поднятии двух серверов

export HOST_PROJECT_DIR="$(pwd)/project_inject"
export HOST_OUTPUT_DIR="$(pwd)/secgensbom_out"
export HOST_DEP_REPORT_DIR="$(pwd)/secgensbom_out/dependency-check"
export HOST_TRIVY_REPORT_DIR="$(pwd)/secgensbom_out/trivy"
export DEP_CHECK_DATA="$(pwd)/.dependency-check-data"

# Образ, который будет сканировать Clair
export IMAGE_NAME="your-app-image:tag"

# Endpoint Clair-сервера
export CLAIR_ENDPOINT="http://clair:8080"

docker run --rm -it \
  -v "$(pwd)/project_inject:/app/project_inject" \
  -v "$(pwd)/reports:/app/reports" \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e PROJECT_DIR="/app/project_inject" \
  -e HOST_PROJECT_DIR="${HOST_PROJECT_DIR}" \
  -e HOST_OUTPUT_DIR="${HOST_OUTPUT_DIR}" \
  -e HOST_DEP_REPORT_DIR="${HOST_DEP_REPORT_DIR}" \
  -e HOST_TRIVY_REPORT_DIR="${HOST_TRIVY_REPORT_DIR}" \
  -e DEP_CHECK_DATA="${DEP_CHECK_DATA}" \
  -e OUTPUT_DIR="/app/secgensbom_out" \
  -e IMAGE_NAME="${IMAGE_NAME}" \
  -e CLAIR_ENDPOINT="${CLAIR_ENDPOINT}" \
  secgensbom-tool:latest \
  /app/secgensbom/pipeline.sh

# дедупликация
docker run --rm -it \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e OUTPUT_DIR="/app/secgensbom_out" \
  secgensbom-tool:latest \
  /app/secgensbom/sbom_dedup.sh



# Для сборки на сейчас без Clair

mkdir -p project_inject
mkdir -p secgensbom_out
mkdir -p secgensbom_out/dependency-check
mkdir -p secgensbom_out/trivy
mkdir -p .dependency-check-data

docker build -f Dockerfile.secgensbom -t secgensbom-tool:latest .

export HOST_PROJECT_DIR="$(pwd)/project_inject"
export HOST_OUTPUT_DIR="$(pwd)/secgensbom_out"
export HOST_DEP_REPORT_DIR="$(pwd)/secgensbom_out/dependency-check"
export HOST_TRIVY_REPORT_DIR="$(pwd)/secgensbom_out/trivy"
export DEP_CHECK_DATA="$(pwd)/.dependency-check-data"

docker run --rm -it \
  -v "$(pwd)/project_inject:/app/project_inject" \
  -v "$(pwd)/reports:/app/reports" \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e PROJECT_DIR="/app/project_inject" \
  -e HOST_PROJECT_DIR="${HOST_PROJECT_DIR}" \
  -e HOST_OUTPUT_DIR="${HOST_OUTPUT_DIR}" \
  -e HOST_DEP_REPORT_DIR="${HOST_DEP_REPORT_DIR}" \
  -e HOST_TRIVY_REPORT_DIR="${HOST_TRIVY_REPORT_DIR}" \
  -e DEP_CHECK_DATA="${DEP_CHECK_DATA}" \
  -e OUTPUT_DIR="/app/secgensbom_out" \
  secgensbom-tool:latest \
  /app/secgensbom/pipeline.sh

# Дедупликация
docker run --rm -it \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e OUTPUT_DIR="/app/secgensbom_out" \
  secgensbom-tool:latest \
  /app/secgensbom/sbom_dedup.sh





так Docker Desktop на macOS сам подтянет x86‑слой  cyclonedx/cyclonedx-cli:latest  и будет прогонять его через встроенную виртуализацию для amd64.




rm sbom/git/.DS_Store
find . -name ".DS_Store" -delete

git submodule init
git submodule update

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


используется как пример https://github.com/karimtariqx/HackerStories/tree/main