<div align="center">
<h1><a id="intro"> SBOM Security Generator & Formatter  <sup></sup></a><br></h1>
<a href="https://docs.github.com/en"><img src="https://img.shields.io/static/v1?logo=github&logoColor=fff&label=&message=Docs&color=36393f&style=flat" alt="GitHub Docs"></a>
<a href="https://daringfireball.net/projects/markdown"><img src="https://img.shields.io/static/v1?logo=markdown&logoColor=fff&label=&message=Markdown&color=36393f&style=flat" alt="Markdown"></a>
<a href="https://symbl.cc/en/unicode-table"><img src="https://img.shields.io/static/v1?logo=unicode&logoColor=fff&label=&message=Unicode&color=36393f&style=flat" alt="Unicode"></a>
<a href="https://shields.io"><img src="https://img.shields.io/static/v1?logo=shieldsdotio&logoColor=fff&label=&message=Shields&color=36393f&style=flat" alt="Shields"></a>
<img src="https://img.shields.io/badge/Contributor-Шмаков_И._С.-8b9aff" alt="Contributor Badge">
</div>

<div align="center">
<img src="https://img.shields.io/github/repo-size/geminishkv/sbom_genform" alt="repo size">
<img src="https://img.shields.io/github/last-commit/geminishkv/sbom_genform" alt="last commit">
<img src="https://img.shields.io/github/commit-activity/m/geminishkv/sbom_genform" alt="commit activity">
<img src="https://img.shields.io/github/issues-pr/geminishkv/sbom_genform" alt="open PRs">
<img src="https://img.shields.io/github/contributors/geminishkv/sbom_genform" alt="contributors">
</div>

<div align="center">

[![CI](https://github.com/geminishkv/sbom_genform/actions/workflows/ci.yml/badge.svg)](https://github.com/geminishkv/sbom_genform/actions/workflows/ci.yml)
[![Docker Hub](https://img.shields.io/docker/v/geminishkvdev/sbom-pipeline?label=Docker%20Hub&logo=docker)](https://hub.docker.com/r/geminishkvdev/sbom-pipeline)
[![PyPI](https://img.shields.io/pypi/v/sbom-pipeline)](https://pypi.org/project/sbom-pipeline/)
[![Python](https://img.shields.io/pypi/pyversions/sbom-pipeline)](https://pypi.org/project/sbom-pipeline/)
[![License](https://img.shields.io/github/license/geminishkv/sbom_genform)](LICENSE.md)
[![GitHub Package](https://img.shields.io/badge/GitHub_Packages-sbom--pipeline-8b9aff)](https://github.com/geminishkv/sbom_genform/packages)

</div>

Инструмент для безопасной генерации, анализа и форматирования **Software Bill of Materials (SBOM)**.

**Что делает:**

- Генерирует SBOM из локальной директории или Git-репозитория (GitHub / GitLab)
- Дедуплицирует компоненты по PURL и уязвимости по CVE+компонент
- Создаёт **два подписанных SBOM**: без уязвимостей и с ними
- Сканирует уязвимости через **Trivy**, **OWASP Dependency-Check**, **Clair**
- Встраивает найденные уязвимости в SBOM (CycloneDX 1.5)
- Опционально обогащает уязвимости идентификаторами **БДУ ФСТЭК**
- Экспортирует читаемые отчёты: **Excel (.xlsx)**, **Word (.docx)**, **ODT (.odt)**

***

## Main CLI

![mainhelp](assets/help_main.jpg)

***

## Run help

![runhelp](assets/runhelp.png)

***

## Установка

**PyPI:**

```bash
pip install sbom-pipeline
```

**GitHub Packages:**

```bash
pip install sbom-pipeline \
  --index-url https://${GITHUB_TOKEN}@pypi.pkg.github.com/geminishkv/
```

**Исходники:**

```bash
git clone https://github.com/geminishkv/sbom_genform.git
cd sbom_genform
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
```

***

## Выходные артефакты

### SBOM JSON

| Файл                                              | Описание                                   |
| ------------------------------------------------- | ------------------------------------------ |
| `secgensbom_out/app-bom-cdxgen.json`              | Исходный SBOM                              |
| `secgensbom_out/app-bom-dedup.json`               | После дедупликации компонентов             |
| `secgensbom_out/app-bom-dedup-signed.json`        | Подписанный SBOM **без** уязвимостей       |
| `secgensbom_out/app-bom-dedup-signed.sig`         | SHA-256 контрольная сумма (без уязв.)      |
| `secgensbom_out/merged-bom-signed.json`           | Подписанный SBOM **с** уязвимостями        |
| `secgensbom_out/report_name(cert)`                | Отчет с добавлением полей GOST  |
| `secgensbom_out/merged-bom-signed.sig`            | SHA-256 контрольная сумма (с уязв.)        |
| `secgensbom_out/vulns-normalized.json`            | Нормализованные уязвимости                 |

Если включено BDU-обогащение, в `merged-bom-signed.json` идентификатор БДУ записывается в `vulnerabilities[].properties[]` как свойство с именем `ru.fstec.bdu:id`.

### Отчёты сканеров

| Путь | Сканер |
| --- | --- |
| `secgensbom_out/trivy/trivy-fs.json` | Trivy — файловая система |
| `secgensbom_out/trivy/sbom-vulns.json` | Trivy — анализ SBOM |
| `secgensbom_out/dependency-check/` | OWASP Dependency-Check |
| `secgensbom_out/clair/` | Clair (если включён) |

### Reports

| Путь                              | Формат | Содержимое                                |
| --------------------------------- | ------ | ----------------------------------------- |
| `secgensbom_reports/excel/*.xlsx` | Excel  | Лист 1: компоненты, Лист 2: уязвимости    |
| `secgensbom_reports/docx/*.docx`  | Word   | Таблица компонентов + таблица уязвимостей |
| `secgensbom_reports/odt/*.odt`    | ODT    | То же самое                               |

Если пайплайн запущен с `--bdu` или `BDU=true`, во всех форматах отчётов уязвимостей появляется отдельная колонка `BDU / ID`. Если BDU-обогащение выключено, эта колонка не выводится.

---

## BDU Enrichment

Обогащение идентификаторами БДУ ФСТЭК выключено по умолчанию.

Включение через CLI:

```bash
secsbom run --bdu
```

Включение через переменную окружения:

```bash
export BDU=true
secsbom run
```

При включённом BDU пайплайн:

- запрашивает соответствия `CVE -> BDU ID` через `bdu.fstec.ru`
- добавляет BDU ID в итоговый CycloneDX SBOM как свойство уязвимости
- выводит BDU ID в экспортируемые отчёты

Пример фрагмента SBOM:

```json
{
  "id": "CVE-2023-1234",
  "properties": [
    {
      "name": "ru.fstec.bdu:id",
      "value": "BDU:2023-01813"
    }
  ]
}
```

---

## Docker

Образ включает Python, Trivy, Docker CLI и Node.js/npx (cdxgen для non-Python проектов).
OWASP Dependency-Check запускается внутри утилиты через `docker run` (Docker-in-Docker), его Java-зависимость утяжелила бы основной образ на ~400 МБ.
Clair требует отдельного работающего HTTP-сервера — поэтому он вынесен в `docker-compose.yml`.

### Docker Hub (только Trivy, без Clair/Dependency-Check)

```bash
docker pull geminishkv/sbom-pipeline:latest

docker run --rm \
  -v "$(pwd)/examples/project_inject:/app/project_inject" \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v "$(pwd)/secgensbom_reports:/app/secgensbom_reports" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  geminishkv/sbom-pipeline:latest
```

### Docker Compose (Trivy + Dependency-Check + Clair)

Полный стек с OWASP Dependency-Check и Clair v4 запускается через `docker-compose.yml`:

```bash
docker compose up --build
```

**Порядок запуска:**
1. `clair-db` (Postgres) — база данных Clair, ожидает healthcheck
2. `clair` — HTTP-сервер уязвимостей Clair v4, ожидает готовности БД
3. `secgensbom` — основной пайплайн, стартует после того, как Clair пройдёт healthcheck

**Что происходит внутри `secgensbom`:**
- Trivy запускается напрямую (встроен в образ)
- OWASP Dependency-Check запускается через `docker run owasp/dependency-check` (Docker-in-Docker через `/var/run/docker.sock`)
- Clair сканирует образ через `clairctl`, подключаясь к `http://clair:8080`

**Переменные окружения:**

| Переменная        | По умолчанию                              | Описание                                     |
| ----------------- | ----------------------------------------- | -------------------------------------------- |
| `SOURCE`          | `local`                                   | Источник проекта: `local`, `github`, `gitlab` |
| `PROJECT_DIR`     | `/app/project_inject`                     | Путь к проекту внутри контейнера             |
| `SKIP_CLAIR`      | `false`                                   | Отключить сканирование Clair (`true`/`false`) |
| `CLAIR_ENDPOINT`  | `http://clair:8080`                       | Адрес Clair API                              |
| `IMAGE_NAME`      | —                                         | Docker-образ для сканирования Clair          |
| `BDU`             | `false`                                   | Включить обогащение идентификаторами БДУ ФСТЭК |
| `DEP_CHECK_DATA`  | `/app/.dependency-check-data`             | Кэш NVD для Dependency-Check                 |

> **Примечание:** Если `IMAGE_NAME` не задан, шаг Clair пропускается автоматически.

***

## CI/CD

### GitHub Actions

| Workflow         | Триггер              | Назначение                                              |
| ---------------- | -------------------- | ------------------------------------------------------- |
| `ci.yml`         | push / PR → main     | lint + mypy + pytest (3.11–3.13)                        |
| `secgensbom.yml` | push → main, вручную | запуск пайплайна, сохранение SBOM и отчётов             |
| `publish.yml`    | тег `v*.*.*`         | GitHub Packages + PyPI + Docker Hub + GitHub Release    |

**Публикация новой версии** — один тег запускает всё:

```bash
git tag v2.1.0
git push --tags
```

### Shared template

Файл `secgensbom/secgensbom.yml` — это **переиспользуемый шаблон CI** для GitLab. Любой другой проект в GitLab может подключить готовый SBOM-шаг одной строкой, не копируя конфигурацию:

***

## Архитектура

### Пайплайн `secsbom run`

```mermaid
flowchart TD
    IN(["Источник\nlocal / github / gitlab"]) --> GEN

    subgraph pipeline["secsbom run — этапы"]
        GEN["1 · generate.py\napp-bom-cdxgen.json"]
        GEN --> DEDUP["2 · dedup.py\napp-bom-dedup.json\nдедупликация компонентов по PURL"]
        DEDUP --> SIGN1["3 · sign.py\napp-bom-dedup-signed.json + .sig\nSHA-256 — SBOM без уязвимостей"]
        SIGN1 --> SCAN

        subgraph SCAN["4 · scanner/"]
            direction LR
            TRIVY["trivy.py\ntrivy-fs.json\nsbom-vulns.json"]
            DEPCHECK["depcheck.py\ndependency-check-report.*"]
            CLAIR["clair.py\nclair-*.json\n(если --clair)"]
        end

        TRIVY & DEPCHECK & CLAIR --> DDUP2["5 · dedup.py\nдедупликация уязвимостей\nпо CVE + компонент"]
        DDUP2 --> MERGE["6 · vuln_merger.py\nvulnerabilities[] в SBOM"]
        MERGE --> SIGN2["7 · sign.py\nmerged-bom-signed.json + .sig\nSHA-256 — SBOM с уязвимостями"]
        SIGN2 --> EXPORT["8 · exporter.py"]
    end

    EXPORT --> XLSX["secgensbom_reports/\n*.xlsx"]
    EXPORT --> DOCX["secgensbom_reports/\n*.docx"]
    EXPORT --> ODT["secgensbom_reports/\n*.odt"]
```

***

## Структура репозитория

```text
sbom_genform/
├── src/sbom_pipeline/
│   ├── cli.py            # secsbom / secsbom-pipeline (typer)
│   ├── pipeline.py       # оркестратор
│   ├── generate.py       # генерация SBOM
│   ├── dedup.py          # дедупликация
│   ├── sign.py           # SHA-256 подпись
│   ├── exporter.py       # xlsx / docx / odt
│   ├── vuln_merger.py    # встраивание уязвимостей
│   ├── config.py         # конфигурация
│   └── scanner/
│       ├── trivy.py
│       ├── depcheck.py
│       └── clair.py
├── docker/
│   └── Dockerfile.secgensbom
├── examples/project_inject/   # уязвимый PHP проект
├── secgensbom/secgensbom.yml  # GitLab CI shared template
├── .github/workflows/
│   ├── ci.yml
│   ├── secgensbom.yml
│   └── publish.yml
├── tests/test_smoke.py
├── pyproject.toml
└── .env.example
```

***

Copyright (c) 2025 Elijah S Shmakov

![Logo](assets/logo.jpg)
