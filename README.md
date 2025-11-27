<div align="center">
<h1><a id="intro"> SBOM Generator & Formatter  <sup></sup></a><br></h1>
<a href="https://docs.github.com/en"><img src="https://img.shields.io/static/v1?logo=github&logoColor=fff&label=&message=Docs&color=36393f&style=flat" alt="GitHub Docs"></a>
<a href="https://daringfireball.net/projects/markdown"><img src="https://img.shields.io/static/v1?logo=markdown&logoColor=fff&label=&message=Markdown&color=36393f&style=flat" alt="Markdown"></a> 
<a href="https://symbl.cc/en/unicode-table"><img src="https://img.shields.io/static/v1?logo=unicode&logoColor=fff&label=&message=Unicode&color=36393f&style=flat" alt="Unicode"></a> 
<a href="https://shields.io"><img src="https://img.shields.io/static/v1?logo=shieldsdotio&logoColor=fff&label=&message=Shields&color=36393f&style=flat" alt="Shields"></a>
<img src="https://img.shields.io/badge/Contributor-Шмаков_И._С.-8b9aff" alt="Contributor Badge"></a>
<img src="https://img.shields.io/github/repo-size/geminishkv/sbom_genform" alt="repo size"></a>
<img src="https://img.shields.io/github/last-commit/geminishkv/sbom_genform" alt="repo size"></a>
<img src="https://img.shields.io/github/commit-activity/m/geminishkv/sbom_genform" alt="repo size"></a>
<img src="https://img.shields.io/github/issues-pr/geminishkv/sbom_genform"></a>
<img src="https://img.shields.io/github/contributors/geminishkv/sbom_genform"></a></div>


***

<br>Салют :wave:,</br>
Инструмент для обработки и анализа SBOM (Software Bill of Materials) файлов с экспортом результатов в различные форматы. Проект посвящен созданию SBOM по проекту в `project_inject` и форматирования отчетов в `.xslx`, .`odt`. 

> В отчетах дорабатывается генерация выявленных уязвимостей (**доработываеся**). **Описание будет добавлено**.

* formatter.py: логгер, dotenv, DetsMemory, основной запуск
* exporter.py: pandas+ODF для отчетов
* sbom_handler.py: файловые операции, парсинг JSON
* dependency.py: обработка каждой зависимости, http-запросы, BeautifulSoup и purl
* utils.py: функции для парсинга, обработки строк, вспомогательные утилиты
* reports/ и /sbom для скрипта, что бы подложить для проверки

В конструкторе формируется список файлов SBOM в директории. readJson  загружает JSON-файл SBOM для дальнейшей работы. Для каждого компонента из SBOM формируется объект. В конструкторе определяется название, версия, тип зависимости и путь. 

<div align="center"><h3>Stay tuned ;)</h3></div> 

***

### Структура репозитория

```bash
├── assets
│   └── logotype
│       ├── logo.jpg
│       └── logo2.jpg
├── cheatsheet
│   ├── CHEATSHEET_DOCKER.md
│   └── CHEATSHEET_DOCKERIGNORE.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── Dockerfile.formatter
├── Dockerfile.secgensbom
├── LICENSE.md
├── NOTICE.md
├── project_inject # vulnerability project to insert
│   ├── add.php
│   ├── composer.json
│   ├── composer.lock
│   ├── config
│   │   └── db_connect
│   ├── delete_story.php
│   ├── details.php
│   ├── edit_story.php
│   ├── edit.php
│   ├── en
│   ├── hackers.sql
│   ├── idea.php
│   ├── img
│   │   ├── book-4986 (1).png
│   │   ├── book-4986 (2).png
│   │   ├── book-4986.png
│   │   └── pizza.svg
│   ├── index.php
│   ├── login.php
│   ├── logout.php
│   ├── profile.php
│   ├── README.md
│   ├── reports.php
│   ├── search.php
│   ├── sign.php
│   ├── templates
│   │   ├── footer.php
│   │   └── header.php
│   ├── userSearch.php
│   └── xmlEx.xml
├── README.md
├── reports # reports by manual_formatter.py
│   ├── git
│   │   ├── excel
│   │   │   ├── sbom-git-fullstack.xlsx
│   │   │   ├── sbom-git-minimal.xlsx
│   │   │   ├── sbom-git-overlap.xlsx
│   │   │   ├── sbom-git-sample .xlsx
│   │   │   └── sbom-git-transitive.xlsx
│   │   └── odt
│   │       ├── sbom-git-fullstack.odt
│   │       ├── sbom-git-minimal.odt
│   │       ├── sbom-git-overlap.odt
│   │       ├── sbom-git-sample .odt
│   │       └── sbom-git-transitive.odt
│   └── images
│       ├── excel
│       │   ├── sbom-image-backend-multistage .xlsx
│       │   ├── sbom-image-critical.xlsx
│       │   ├── sbom-image-frontend-node.xlsx
│       │   └── sbom-image-sample.xlsx
│       └── odt
│           ├── sbom-image-backend-multistage .odt
│           ├── sbom-image-critical.odt
│           ├── sbom-image-frontend-node.odt
│           └── sbom-image-sample.odt
├── resolve # nextstep
│   └── SCA.Dockerfile
├── sbom
│   ├── git
│   │   ├── sbom-git-fullstack.json
│   │   ├── sbom-git-minimal.json
│   │   ├── sbom-git-overlap.json
│   │   ├── sbom-git-sample.json
│   │   └── sbom-git-transitive.json
│   └── images
│       ├── sbom-image-backend-multistage.json
│       ├── sbom-image-critical.json
│       ├── sbom-image-frontend-node.json
│       └── sbom-image-sample.json
├── script # formatter logic
│   ├── app.log
│   ├── dependency.py # обработка зависимостей
│   ├── exporter.py # экспорт отчетов
│   ├── formatter.py # auto
│   ├── manual_formatter.py # manual
│   ├── requirements.txt
│   ├── sbom_handler.py # работа с SBOM-файлами
│   ├── setup_secgensbom_env.py
│   └── utils.py
├── secgensbom # custom logic pipeline secgensbom
│   ├── config.env
│   ├── pipeline.sh
│   ├── sbom_dedup.sh
│   ├── sbom_generate.sh
│   ├── sbom_merge_sign.sh
│   ├── sca_entrypoint.sh
│   ├── scan_clair.sh
│   ├── scan_dependency_check.sh
│   └── scan_trivy.sh
├── secgensbom_out # artifacts by pipeline.sh
│   ├── app-bom-cdxgen.json # main SBOM
│   ├── app-bom-dedup.json # дедупликация
│   ├── clair
│   ├── dependency-check
│   │   ├── dependency-check-gitlab.json
│   │   ├── dependency-check-jenkins.html
│   │   ├── dependency-check-junit.xml
│   │   ├── dependency-check-report.csv
│   │   ├── dependency-check-report.html
│   │   ├── dependency-check-report.json
│   │   ├── dependency-check-report.sarif
│   │   └── dependency-check-report.xml
│   ├── merged-bom-signed.json # sign and dedup SBOM
│   └── trivy
│       ├── sbom-vulns.json
│       └── trivy-fs.json
├── secgensbom_reports
│   ├── excel
│   │   ├── app-bom-cdxgen.xlsx
│   │   ├── app-bom-dedup.xlsx
│   │   └── merged-bom-signed.xlsx
│   └── odt
│       ├── app-bom-cdxgen.odt
│       ├── app-bom-dedup.odt
│       └── merged-bom-signed.odt
└── SECURITY.md
```
### Tutorial

* submodules

```bash
git submodule init
git submodule update
```

* Работа из окружения

```bash
python3 -m venv venv 
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python formatter.py
deactivate
```
* Сборка Docker для formatter

```bash
docker build -f Dockerfile.formatter -t sbom-formatter:latest .

docker run --rm -it \
  -v "$(pwd)/sbom:/app/sbom" \
  -v "$(pwd)/reports:/app/reports" \
  sbom-formatter:latest
```

* Сначала делаем руками и после можно автоматически так

```bash
python3 script/setup_secgensbom_env.py
vim ~/.zshrc
vim ~/.bashrc

secgensbom_env() {
  local out
  out="$(python3 script/setup_secgensbom_env.py)"
  eval "export ${out//$'\n'/; export }"
}

source ~/.zshrc
source ~/.bashrc
```

*  secgensbom pipeline.sh

```bash
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
```

*  Без Clair - когда clairctl недоступен без docker-compose, шаг логируется как “ошибка, пропущен”

```bash
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
```

* formatter на артефакты secgensbom_out

```bash
mkdir -p secgensbom_reports/excel
mkdir -p secgensbom_reports/odt

docker build -f Dockerfile.formatter -t sbom-formatter:latest .
docker run --rm -it \
  -v "$(pwd)/script:/app/script" \
  -v "$(pwd)/sbom:/app/sbom" \
  -v "$(pwd)/reports:/app/reports" \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v "$(pwd)/secgensbom_reports:/app/secgensbom_reports" \
  sbom-formatter:latest \
  python /app/script/formatter.py
```

* manual_formatter

```bash
docker run --rm -it \
  -v "$(pwd)/script:/app/script" \
  -v "$(pwd)/sbom:/app/sbom" \
  -v "$(pwd)/reports:/app/reports" \
  sbom-formatter:latest \
  python /app/script/manual_formatter.py
```

* Очистка кеша hard

```bash
docker builder prune -af
docker system prune -af
```

***

### 4Clair

* Завести учётку на quay.io, выдать token, сделать  docker login quay.io  на хосте
* Вместо  latest  использовать конкретный тег, указаный в доке Clair ( v4.x.x  и т.д.).
    * Поднять сам Clair (Postgres + Clair) по их docker-compose
    * Настроить  CLAIR_ENDPOINT  и конфиг clairctl

***

### Troubleshooting

* Docker Desktop на macOS сам подтянет x86‑слой  cyclonedx/cyclonedx-cli:latest и будет прогонять его через встроенную виртуализацию для amd64.
* .DS_Store в каталогах, если глобально не потерт

```bash
rm sbom/git/.DS_Store
find . -name ".DS_Store" -delete
```

***

### Интеграция с CI/CD

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