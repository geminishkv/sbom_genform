# Руководство пользователя

Пошаговое руководство по работе с **sbom-pipeline** (`secsbom`) — от установки до типовых сценариев генерации, сканирования и форматирования SBOM.

> Нужен исчерпывающий справочник по всем командам, флагам и примерам вывода? — [docs/MANUAL.md](MANUAL.md).

- [Требования](#требования)
- [Установка](#установка)
- [Команды](#команды)
- [Сценарии использования](#сценарии-использования)
- [Переменные окружения](#переменные-окружения)
- [Выходные артефакты](#выходные-артефакты)
- [Docker](#docker)
- [Частые вопросы](#частые-вопросы)

***

## Требования

Сам пакет — на чистом Python (3.11–3.13). Для отдельных шагов нужны внешние инструменты; их наличие проверяется командой `secsbom status`:

| Инструмент | Для чего | Обязателен |
| --- | --- | --- |
| **Node.js + npx** | генератор SBOM **cdxgen** (любые экосистемы) | для генерации (один из двух) |
| **Syft** | генератор SBOM **syft** | для генерации (один из двух) |
| **Trivy** | сканирование уязвимостей (FS + SBOM) | для сканирования |
| **Docker** | OWASP Dependency-Check и Clair запускаются как контейнеры | для depcheck/clair |
| **clairctl** + сервер Clair | сканирование контейнерных образов | только для `--clair` |

> Утилиту нужно запускать **от обычного пользователя**. Запуск от root/администратора блокируется, чтобы не выполнять сканеры и Docker-команды с лишними привилегиями.

***

## Установка

**PyPI:**

```bash
pip install sbom-pipeline
```

**Из исходников (для разработки):**

```bash
git clone https://github.com/geminishkv/sbom_genform.git
cd sbom_genform
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
```

После установки доступны две одинаковые команды: `secsbom` и `secsbom-pipeline`. Проверка:

```bash
secsbom --version
secsbom status      # доступность внешних инструментов
```

***

## Команды

| Команда | Назначение |
| --- | --- |
| `run` | Полный пайплайн: генерация → дедуп → подпись → сканирование → отчёты |
| `gen-sbom` | Только генерация SBOM → дедуп → подпись → отчёт компонентов |
| `scan <sbom>` | Сканирование уязвимостей готового SBOM → отчёты уязвимостей |
| `format` | Форматирование готовых SBOM JSON → xlsx / docx / odt |
| `verify <file>` | Проверка SHA-256 контрольной суммы целостности |
| `info <file>` | Краткая сводка: компоненты, CVE по severity, подпись |
| `status` | Проверка доступности внешних инструментов |
| `diff <old> <new>` | Сравнение двух SBOM: новые/удалённые компоненты и CVE |
| `cert <file>` | Обогащение полями GOST/ФСТЭК для сертификации |

Справка по любой команде — флаг `-h`:

```bash
secsbom run -h
secsbom scan -h
```

***

## Сценарии использования

### 1. Локальный проект — полный цикл

Генерация SBOM, дедупликация, подпись, сканирование уязвимостей и отчёты:

```bash
secsbom run --path ./my-project
```

Артефакты появятся в `secgensbom_out/`, отчёты — в `secgensbom_reports/`.

### 2. Удалённый репозиторий (GitHub / GitLab)

```bash
# публичный репозиторий
secsbom run --url https://github.com/org/repo

# приватный — с токеном доступа
secsbom run --url https://github.com/org/repo --token ghp_xxx
secsbom run --url https://gitlab.com/org/repo --token glpat-xxx

# конкретная ветка
secsbom run --url https://github.com/org/repo --branch develop
```

Тип сервиса (GitHub/GitLab) определяется по URL автоматически. Репозиторий клонируется во временный каталог (`--depth 1`) и удаляется после генерации.

### 3. Контейнерный образ (режим «только образ»)

Без исходного кода — состав образа берётся из Clair (нужен запущенный сервер Clair, см. [Docker](#docker)):

```bash
secsbom run --clair --image nginx:latest
```

### 4. Только генерация SBOM (без сканирования)

Сгенерировать и подписать SBOM, выгрузить лист компонентов:

```bash
secsbom gen-sbom --path ./my-project
# → secgensbom_out/app-bom-dedup-signed.json
```

Управление генераторами:

```bash
secsbom gen-sbom --path ./my-project --no-syft      # только cdxgen
secsbom gen-sbom --path ./my-project --no-cdxgen    # только syft
```

### 5. Только сканирование готового SBOM

Если SBOM уже есть — прогнать по нему сканеры и собрать отчёты уязвимостей:

```bash
# по готовому SBOM
secsbom scan secgensbom_out/app-bom-dedup-signed.json

# с указанием папки проекта (включает Trivy FS и Dependency-Check)
secsbom scan secgensbom_out/app-bom-dedup-signed.json --path ./my-project

# по контейнерному образу
secsbom scan --clair --image nginx:latest
```

### 6. Обогащение БДУ ФСТЭК

Добавить идентификаторы БДУ к найденным уязвимостям (по умолчанию выключено):

```bash
secsbom run --path ./my-project --bdu
# или через окружение
export BDU=true && secsbom run --path ./my-project
```

В отчётах появится колонка `BDU / ID`, в SBOM — свойство `ru.fstec.bdu:id`.

### 7. Подготовка под требования ФСТЭК (`cert`)

Добавить в SBOM поля GOST (`GOST: attack_surface`, `GOST: security_function`) и метаданные продукта:

```bash
secsbom cert secgensbom_out/merged-bom-signed.json \
  --component-name "Мой продукт" \
  --component-version "1.0.0" \
  --manufacturer "ООО Ромашка" \
  --component-type application
# → <input>(cert).json   (или путь из --output)
```

### 8. Форматирование готовых SBOM в отчёты

Преобразовать все SBOM JSON из каталога в Excel/Word/ODT:

```bash
secsbom format --sbom-dir secgensbom_out --report-dir secgensbom_reports
```

### 9. Инспекция, проверка и сравнение

```bash
secsbom info secgensbom_out/merged-bom-signed.json     # сводка по SBOM
secsbom verify secgensbom_out/merged-bom-signed.json   # проверка целостности
secsbom diff old-bom.json new-bom.json                 # что изменилось между версиями
```

> `verify` проверяет **контрольную сумму целостности** (SHA-256), а не криптографическую подпись — она подтверждает, что файл не изменялся, но не аутентичность источника.

***

## Переменные окружения

Любой флаг можно задать через окружение (CLI-аргумент имеет приоритет). Удобно для CI/Docker.

| Переменная | Аналог флага | По умолчанию |
| --- | --- | --- |
| `PROJECT_DIR` | `--path` | — |
| `GIT_URL` / `GIT_TOKEN` / `GIT_BRANCH` | `--url` / `--token` / `--branch` | — |
| `SOURCE` | — (`local`/`github`/`gitlab`) | `local` |
| `USE_CDXGEN` / `USE_SYFT` | `--cdxgen` / `--syft` | `true` / `true` |
| `OUTPUT_DIR` / `REPORTS_DIR` | `--output-dir` / `--reports-dir` | `secgensbom_out` / `secgensbom_reports` |
| `IMAGE_NAME` | `--image` | — |
| `CLAIR_ENDPOINT` | `--clair-endpoint` | `http://clair:8080` |
| `SKIP_CLAIR` | `--no-clair` / `--clair` | `true` |
| `BDU` | `--bdu` | `false` |
| `NVD_API_KEY` | — | — |
| `DEP_CHECK_DATA` | — | `.dependency-check-data` |
| `GITHUB_TOKEN` | — (определение языков по PURL) | — |
| `BDU_CA_BUNDLE` | — (CA для TLS-проверки `bdu.fstec.ru`) | — (проверка отключена) |
| `SBOM_COMPONENT_NETWORK` | — (сетевые уточнения языков/URL) | `false` |

> `NVD_API_KEY` сильно повышает лимиты NVD API для Dependency-Check и CVSS-обогащения. Ключ — на [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key).

***

## Выходные артефакты

```text
secgensbom_out/
├── app-bom-cdxgen.json          # SBOM от cdxgen
├── app-bom-syft.json            # SBOM от syft
├── app-bom-merged.json          # объединённый
├── app-bom-dedup.json           # после дедупликации
├── app-bom-dedup-signed.json    # подписанный SBOM без уязвимостей (+ .sig)
├── merged-bom-signed.json       # подписанный SBOM с уязвимостями (+ .sig)
├── vulns-normalized.json        # нормализованный список уязвимостей
├── trivy/ · dependency-check/ · clair/   # отчёты сканеров
secgensbom_reports/
├── excel/*.xlsx   # Лист 1: компоненты, Лист 2: уязвимости
├── docx/*.docx
└── odt/*.odt
```

Подробное описание колонок отчётов и примеры — в [README](../README.md#выходные-артефакты) и [docs/RESULT_EXAMPLES.md](RESULT_EXAMPLES.md#примеры-результатов).

***

## Docker

Образ включает Python, Syft, Trivy, Docker CLI и Node.js/npx. Trivy работает «из коробки»; OWASP Dependency-Check и Clair запускаются как отдельные контейнеры.

**Быстрый запуск (только Trivy):**

```bash
docker run --rm \
  -v "$(pwd)/my-project:/app/project_inject" \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v "$(pwd)/secgensbom_reports:/app/secgensbom_reports" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  geminishkv/sbom-pipeline:latest
```

**Полный стек (Trivy + Dependency-Check + Clair)** — через `docker-compose.yml`:

```bash
docker compose up --build
```

Детали Docker/Compose, переменные и порядок запуска — в [README](../README.md#docker).

***

## Частые вопросы

- **Пустые колонки CVSS / `0.0`** — задайте `NVD_API_KEY` и используйте постоянный `DEP_CHECK_DATA`.
- **`Dependency-Check` код 13** — не скачана база NVD или нет ключа.
- **Clair `500` / долгий старт** — updater'ы Clair прогреваются до 10 минут на первом запуске.

Полный список — в [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md#troubleshooting).
