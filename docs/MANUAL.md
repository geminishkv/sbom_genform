# SBOM Pipeline — полное руководство

Исчерпывающий справочник по инструменту **sbom-pipeline** (`secsbom`): все команды, флаги, переменные окружения, сценарии и примеры вывода.

> Краткий старт — в [USAGE.md](USAGE.md#руководство-пользователя). Этот документ — детальный мануал по всему функционалу.

## Содержание

- [1. Что это и как устроено](#1-что-это-и-как-устроено)
- [2. Установка](#2-установка)
- [3. Проверка окружения](#3-проверка-окружения)
- [4. Пайплайн: 8 шагов](#4-пайплайн-8-шагов)
- [5. Справочник команд](#5-справочник-команд)
  - [run](#run--полный-пайплайн) · [gen-sbom](#gen-sbom--только-генерация) · [scan](#scan--только-сканирование) · [format](#format--форматирование) · [verify](#verify--проверка-целостности) · [info](#info--инспекция) · [status](#status--окружение) · [diff](#diff--сравнение) · [cert](#cert--поля-фстэк)
- [6. Источники SBOM](#6-источники-sbom)
- [7. Сканеры уязвимостей](#7-сканеры-уязвимостей)
- [8. Обогащение: БДУ и NVD](#8-обогащение-бду-и-nvd)
- [9. Выходные артефакты](#9-выходные-артефакты)
- [10. Отчёты и колонки](#10-отчёты-и-колонки)
- [11. Переменные окружения](#11-переменные-окружения)
- [12. Docker и Compose](#12-docker-и-compose)
- [13. End-to-end сценарии](#13-end-to-end-сценарии)
- [14. Безопасность](#14-безопасность)
- [15. Диагностика](#15-диагностика)

***

## 1. Что это и как устроено

`secsbom` — это пайплайн, который из исходного кода или контейнерного образа собирает **SBOM** (Software Bill of Materials) в формате CycloneDX 1.5, ищет в нём уязвимости несколькими сканерами, дедуплицирует и подписывает результат, а затем выгружает читаемые отчёты в Excel/Word/ODT.

Ключевые принципы:

- **Два генератора SBOM** — cdxgen (универсальный, через Node/npx) и syft — их результаты объединяются для максимального покрытия.
- **Параллельное сканирование** — Trivy, OWASP Dependency-Check и Clair запускаются одновременно.
- **Два подписанных SBOM** — отдельно «чистый» (только состав) и «с уязвимостями».
- **Опциональное обогащение** — идентификаторы БДУ ФСТЭК и CVSS из NVD.
- **Подготовка под ФСТЭК** — поля GOST через команду `cert`.

Две команды-синонима: `secsbom` и `secsbom-pipeline` (полностью эквивалентны).

***

## 2. Установка

**PyPI:**

```bash
pip install sbom-pipeline
```

**GitHub Packages:**

```bash
pip install sbom-pipeline --index-url https://${GITHUB_TOKEN}@pypi.pkg.github.com/geminishkv/
```

**Из исходников (разработка):**

```bash
git clone https://github.com/geminishkv/sbom_genform.git
cd sbom_genform
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
```

**Docker (всё в одном образе):**

```bash
docker pull geminishkv/sbom-pipeline:latest
```

***

## 3. Проверка окружения

Сам пакет — на чистом Python (3.11–3.13). Для шагов генерации и сканирования нужны внешние инструменты. Проверить их наличие:

```bash
secsbom status
```

```text
╭───────────────────────────── Статус окружения ─────────────────────────────╮
│ │  Инструмент    │  Статус      │  Версия / Детали                       │ │
│ │  Python        │  ✓ доступен  │  Python 3.13.12                        │ │
│ │  pip           │  ✓ доступен  │  pip 26.1.2 …                          │ │
│ │  Syft          │  ✓ доступен  │  Application:   syft                   │ │
│ │  Trivy         │  ✓ доступен  │  Version: 0.71.0                       │ │
│ │  Docker        │  ✓ доступен  │  Docker version 29.0.1                 │ │
│ │  Node.js       │  ✓ доступен  │  v26.3.0                               │ │
│ │  npx           │  ✓ доступен  │  11.16.0                               │ │
│ │  cyclonedx-py  │  ✓ доступен  │  7.3.0                                 │ │
╰────────────────────────────────────────────────────────────────────────────╯
```

| Инструмент | Нужен для | Если нет |
| --- | --- | --- |
| Node.js + npx | генератор cdxgen | будет использован только syft |
| Syft | генератор syft | будет использован только cdxgen |
| Trivy | сканирование FS и SBOM | шаг Trivy пропускается |
| Docker | Dependency-Check, Clair | соответствующие шаги пропускаются |
| clairctl + сервер Clair | сканирование образов | шаг Clair пропускается |

Если доступен хотя бы один генератор (cdxgen **или** syft) — базовая генерация SBOM работает.

***

## 4. Пайплайн: 8 шагов

Команда `secsbom run` выполняет полный цикл:

```text
1. Генерация       cdxgen + syft → app-bom-merged.json  (+ пакеты образа из Clair)
2. Дедуп компонент app-bom-dedup.json                   (ключ — PURL)
3. Подпись         app-bom-dedup-signed.json + .sig      (SHA-256, без уязвимостей)
4. Сканирование    Trivy FS + Trivy SBOM + Dependency-Check + Clair  (параллельно)
                   + cross-populate CVSS между сканерами
5. Дедуп уязвим.   ключ CVE-ID::компонент, оставляется максимальный CVSS
6. Слияние         vulnerabilities[] в SBOM (+ БДУ при --bdu) + vulns-normalized.json
7. Подпись         merged-bom-signed.json + .sig         (SHA-256, с уязвимостями)
8. Экспорт         reports/{excel,docx,odt}
```

Команды `gen-sbom` (шаги 1–3) и `scan` (шаги 4–8) позволяют выполнять эти фазы по отдельности.

***

## 5. Справочник команд

Общий синтаксис: `secsbom <команда> [опции]`. Справка по любой команде — флаг `-h`/`--help`. Визуальная демонстрация (гифки работы CLI) — в [demo/DEMO.md](demo/DEMO.md#демонстрация-работы-команд).

### `run` — полный пайплайн

Генерация → дедуп → подпись → сканирование → отчёты.

| Опция | env | По умолчанию | Описание |
| --- | --- | --- | --- |
| `--path PATH` | `PROJECT_DIR` | — | путь к локальному проекту |
| `--url TEXT` | `GIT_URL` | — | URL репозитория GitHub/GitLab |
| `--token TEXT` | `GIT_TOKEN` | — | токен доступа (`ghp_…`/`glpat-…`) |
| `--branch TEXT` | `GIT_BRANCH` | HEAD | ветка репозитория |
| `--cdxgen / --no-cdxgen` | `USE_CDXGEN` | вкл | генерация через cdxgen |
| `--syft / --no-syft` | `USE_SYFT` | вкл | генерация через syft |
| `--output-dir, -o PATH` | `OUTPUT_DIR` | `secgensbom_out` | каталог артефактов |
| `--reports-dir PATH` | `REPORTS_DIR` | `secgensbom_reports` | каталог отчётов |
| `--image TEXT` | `IMAGE_NAME` | — | образ для сканирования Clair |
| `--clair-endpoint TEXT` | `CLAIR_ENDPOINT` | `http://clair:8080` | адрес Clair API |
| `--no-clair / --clair` | `SKIP_CLAIR` | `--no-clair` | включить/пропустить Clair |
| `--bdu / --no-bdu` | `BDU` | `--no-bdu` | обогащение БДУ ФСТЭК |
| `--verbose, -v` | — | выкл | подробный (DEBUG) лог |

Примеры:

```bash
secsbom run --path ./my-project                       # локальный проект
secsbom run --url https://github.com/org/repo --token ghp_xxx
secsbom run --path ./app --no-syft                    # только cdxgen
secsbom run --path ./app --bdu                        # + идентификаторы БДУ
secsbom run --clair --image nginx:latest              # только контейнерный образ
secsbom run --path ./app -o out --reports-dir reports # свои каталоги
```

### `gen-sbom` — только генерация

Шаги 1–3 + отчёт компонентов. Без сканирования уязвимостей. Те же опции, что у `run`, **кроме** `--bdu`.

```bash
secsbom gen-sbom --path ./my-project
# → secgensbom_out/app-bom-dedup-signed.json + лист «Компоненты»
```

### `scan` — только сканирование

Шаги 4–8 для **готового** SBOM. Принимает путь к SBOM позиционным аргументом.

| Аргумент/опция | Описание |
| --- | --- |
| `<sbom>` | путь к готовому SBOM JSON (необязателен в режиме `--clair --image`) |
| `--path PATH` | папка проекта — включает Trivy FS и Dependency-Check |
| `--image` / `--clair` / `--clair-endpoint` | сканирование контейнерного образа |
| `--bdu / --no-bdu` | обогащение БДУ |
| `-o` / `--reports-dir` / `-v` | каталоги и лог |

```bash
secsbom scan secgensbom_out/app-bom-dedup-signed.json
secsbom scan secgensbom_out/app-bom-dedup-signed.json --path ./my-project
secsbom scan --clair --image nginx:latest             # SBOM не нужен
```

### `format` — форматирование

Преобразует все SBOM JSON из каталога в Excel/Word/ODT, без генерации и сканирования.

```bash
secsbom format --sbom-dir secgensbom_out --report-dir secgensbom_reports
```

### `verify` — проверка целостности

Проверяет SHA-256 контрольную сумму в `metadata.signature`.

```bash
secsbom verify secgensbom_out/merged-bom-signed.json
```

```text
✓ Подпись верифицирована — файл не изменялся: …/merged-bom-signed.json
```

Если файл изменён или не подписан:

```text
✗ Подпись не совпадает — файл был изменён или подпись отсутствует: …
```

> Это контрольная сумма **целостности** (integrity), а не криптоподпись: она подтверждает, что файл не менялся, но не аутентичность источника.

### `info` — инспекция

Краткая сводка SBOM: формат, проект, подпись, компоненты по экосистемам, уязвимости по severity и топ-5 CVE.

```bash
secsbom info secgensbom_out/merged-bom-signed.json
```

```text
╭──────────────── SBOM Info ────────────────╮
│  Файл               …/merged-bom-signed.json
│  Формат             CycloneDX 1.5
│  Проект             demo-app
│  Подпись (SHA-256)  не подписан
│  Компонентов        2
│  По экосистемам     pypi:2
│  Уязвимостей        1
│  По severity        CRITICAL:1  HIGH:0  MEDIUM:0  LOW:0  UNKNOWN:0
╰────────────────────────────────────────────╯

  Топ уязвимостей:
  CVE ID           Severity   Компонент   Score
  CVE-2018-18074   CRITICAL   r1          9.8
```

### `status` — окружение

Без аргументов. Проверяет доступность Python, pip, Syft, Trivy, Docker, Node.js, npx, cyclonedx-py (см. [раздел 3](#3-проверка-окружения)).

### `diff` — сравнение

Сравнивает два SBOM: добавленные/удалённые компоненты и новые/закрытые CVE.

```bash
secsbom diff old-bom.json new-bom.json
```

```text
╭──────── Diff: demo-bom.json → demo-bom-v2.json ────────╮
│ Компоненты: +2 добавлено  -2 удалено │ CVE: +0 новых  -1 закрыто
╰─────────────────────────────────────────────────────────╯

  Компоненты:
  + добавлен   pkg:pypi/django@5.0.0
  + добавлен   pkg:pypi/requests@2.32.0
  − удалён     pkg:pypi/flask@3.0.0
  − удалён     pkg:pypi/requests@2.20.0

  Уязвимости:
  ✓ закрыта   CVE-2018-18074   CRITICAL
```

### `cert` — поля ФСТЭК

Добавляет в SBOM поля GOST (`GOST: attack_surface`, `GOST: security_function` для каждого компонента) и метаданные продукта согласно информационному сообщению ФСТЭК России от 13.01.2025 № 240/24/38.

| Опция | Алиас | Описание |
| --- | --- | --- |
| `<sbom>` | | путь к исходному SBOM |
| `--component-name` | `-n` | название продукта |
| `--component-version` | | версия продукта |
| `--manufacturer` | `-m` | производитель |
| `--component-type` | `-t` | тип: `application` (по умолч.), `framework`, `library`, `operating-system`, `device-driver`, `firmware` |
| `--output` | `-o` | выходной файл (по умолч. `<input>(cert).json`) |

```bash
secsbom cert secgensbom_out/merged-bom-signed.json \
  --component-name "Demo App" --component-version "1.0.0" \
  --manufacturer "ООО Пример" --component-type application
```

```text
[INFO] Поля добавлены в 2 компонента
[INFO] SBOM обогащён → …/merged-bom-signed(cert).json
✓ Поля успешно добавлены ✓
```

### Глобальные флаги

```bash
secsbom --version        # версия и выход (-V)
secsbom --help           # общая справка (-h, либо просто `secsbom`)
```

***

## 6. Источники SBOM

Источник определяется автоматически:

| Способ | Как задаётся | Поведение |
| --- | --- | --- |
| Локальная директория | `--path ./dir` (`SOURCE=local`) | тип проекта определяется по манифестам (`requirements.txt`, `package.json`, `pom.xml`, `composer.json`, `go.mod`, `Cargo.toml` и др.) |
| GitHub | `--url https://github.com/…` | клонирование `--depth 1`, тип сервиса по домену |
| GitLab | `--url https://gitlab.com/…` | то же; токен `glpat-…` |
| Контейнерный образ | `--clair --image img:tag` без `--path`/`--url` | состав берётся из Clair, исходный код не нужен |

Приватные репозитории: токен встраивается во временный clone-URL и **не** попадает в логи (даже при ошибке клонирования он маскируется).

***

## 7. Сканеры уязвимостей

Все сканеры на шаге 4 запускаются **параллельно**; ошибка одного не прерывает остальные.

| Сканер | Что делает | Требует | Условие запуска |
| --- | --- | --- | --- |
| **Trivy FS** | сканирует файлы проекта (`vuln,secret,misconfig`) | `trivy` в PATH | задан `--path` |
| **Trivy SBOM** | сканирует сам SBOM | `trivy` в PATH | всегда |
| **Dependency-Check** | OWASP DC через `docker run` | Docker + (желательно) `NVD_API_KEY` | задан `--path` |
| **Clair** | уязвимости образа через clairctl + Clair API | `clairctl` + сервер Clair | задан `--clair --image` |

После сбора находок выполняется **cross-populate CVSS**: если один сканер дал оценку для CVE, а другой нет — пустая оценка заполняется лучшей известной.

***

## 8. Обогащение: БДУ и NVD

**БДУ ФСТЭК** (`--bdu` / `BDU=true`):

- запрашивает соответствия `CVE → BDU-ID` через `bdu.fstec.ru`;
- кэширует результаты (включая «не найдено») в `.bdu_cache/`, чтобы не нагружать сервер;
- пишет BDU-ID в SBOM как свойство `ru.fstec.bdu:id` и в колонку отчёта `BDU / ID`.

Сайт ФСТЭК использует self-signed сертификат, поэтому TLS-проверка по умолчанию отключена. Чтобы включить её против доверенного CA:

```bash
export BDU_CA_BUNDLE=/path/to/fstec-ca.pem
secsbom run --path ./app --bdu
```

**NVD API** — fallback для CVSS, когда сканер (обычно Clair) не дал оценку. Кэшируется на диске; `NVD_API_KEY` сильно повышает лимиты.

***

## 9. Выходные артефакты

```text
secgensbom_out/
├── app-bom-cdxgen.json          SBOM от cdxgen
├── app-bom-syft.json            SBOM от syft
├── app-bom-merged.json          объединённый
├── app-bom-dedup.json           после дедупликации компонентов
├── app-bom-dedup-signed.json    подписанный SBOM без уязвимостей  (+ .sig)
├── merged-bom-signed.json       подписанный SBOM с уязвимостями   (+ .sig)
├── vulns-normalized.json        нормализованный список уязвимостей
├── trivy/                       trivy-fs.json, sbom-vulns.json
├── dependency-check/            dependency-check-report.*
└── clair/                       clair-<image>.json

secgensbom_reports/
├── excel/*.xlsx                 Лист 1: Компоненты, Лист 2: Уязвимости
├── docx/*.docx
└── odt/*.odt
```

Файлы `.sig` содержат `SHA256=<hex>` для внешней проверки целостности.

***

## 10. Отчёты и колонки

**Лист «Компоненты»** (11 колонок): № п/п, наименование, версия, тип пакета (из PURL), PURL, язык(и), признак поверхности атаки, признак функций безопасности, принадлежность к образу, роль в образе, адрес веб-ресурса.

**Лист «Уязвимости»** (10 колонок, +`BDU / ID` при `--bdu`): компонент, версия, CVE/ID, CVSS, критичность, описание, сканер, исправлено в версии, рекомендация/компенсирующая мера, статус допустимости.

Уязвимые компоненты сортируются наверх (worst severity → highest CVSS).

***

## 11. Переменные окружения

CLI-флаг всегда имеет приоритет над переменной.

| Переменная | Назначение | По умолчанию |
| --- | --- | --- |
| `PROJECT_DIR` | путь к проекту (`--path`) | — |
| `GIT_URL`, `GIT_TOKEN`, `GIT_BRANCH` | удалённый репозиторий | — |
| `SOURCE` | `local` / `github` / `gitlab` | `local` |
| `USE_CDXGEN`, `USE_SYFT` | включение генераторов | `true`, `true` |
| `OUTPUT_DIR`, `REPORTS_DIR` | каталоги вывода | `secgensbom_out`, `secgensbom_reports` |
| `IMAGE_NAME`, `CLAIR_ENDPOINT`, `SKIP_CLAIR` | сканирование образов | —, `http://clair:8080`, `true` |
| `BDU`, `BDU_CACHE_DIR` | обогащение БДУ | `false`, `.bdu_cache` |
| `BDU_CA_BUNDLE` | CA для TLS-проверки `bdu.fstec.ru` | — (проверка off) |
| `NVD_API_KEY`, `NVD_CACHE_DIR` | NVD API и его кэш | — |
| `DEP_CHECK_DATA` | кэш базы NVD для Dependency-Check | `.dependency-check-data` |
| `GITHUB_TOKEN` | определение языков по PURL | — |
| `SBOM_COMPONENT_NETWORK` | сетевые уточнения языков/URL | `false` |
| `HOST_*` | хостовые пути для Docker-in-Docker | — |

***

## 12. Docker и Compose

**Один образ (только Trivy):**

```bash
docker run --rm \
  -v "$(pwd)/my-project:/app/project_inject" \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v "$(pwd)/secgensbom_reports:/app/secgensbom_reports" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  geminishkv/sbom-pipeline:latest
```

**Полный стек (Trivy + Dependency-Check + Clair)** через `docker-compose.yml`:

```bash
docker compose up --build
```

Порядок запуска: `clair-db` (Postgres, healthcheck) → `clair` (v4, ждёт БД) → `secgensbom` (стартует после готовности Clair). Отдельный сервис `scan` сканирует готовый SBOM. На первом запуске Clair прогревает updater'ы — до ~10 минут.

***

## 13. End-to-end сценарии

**Полный аудит локального проекта с отчётами:**

```bash
export NVD_API_KEY=<token>
secsbom run --path ./my-project --bdu
secsbom info secgensbom_out/merged-bom-signed.json
# отчёты: secgensbom_reports/excel/merged-bom-signed.xlsx
```

**Сертификационный цикл под ФСТЭК:**

```bash
secsbom gen-sbom --path ./product                       # 1. чистый SBOM
secsbom scan secgensbom_out/app-bom-dedup-signed.json --path ./product --bdu
secsbom cert secgensbom_out/merged-bom-signed.json \
  -n "Изделие" --component-version "2.0" -m "ООО Вендор"  # 2. поля GOST
```

**Сравнение версий (что изменилось между релизами):**

```bash
secsbom gen-sbom --path ./app-v1 -o out-v1
secsbom gen-sbom --path ./app-v2 -o out-v2
secsbom diff out-v1/app-bom-dedup-signed.json out-v2/app-bom-dedup-signed.json
```

**CI (GitHub Actions):** установить пакет + Trivy, прогнать `secsbom run --path .`, выгрузить `secgensbom_out/` и `secgensbom_reports/` как артефакты (см. `.github/workflows/secgensbom.yml`).

***

## 14. Безопасность

- **Запуск не от root** — `secsbom` отказывается работать с правами администратора/root, чтобы не выполнять сканеры и Docker-команды с лишними привилегиями.
- **Токены не утекают** — при ошибке клонирования токен из URL маскируется в сообщении.
- **Валидация `CLAIR_ENDPOINT`** — допускаются только схемы `http(s)://` (защита от `file://`/SSRF).
- **TLS для БДУ** — настраивается через `BDU_CA_BUNDLE`.
- **Целостность ≠ аутентичность** — SHA-256 защищает от случайной порчи, но не от целенаправленной подмены; для аутентичности используйте внешнюю подпись (cosign/sigstore).

***

## 15. Диагностика

Частые проблемы (пустые CVSS, код 13 у Dependency-Check, медленный старт Clair, сетевые лимиты NVD) разобраны в [TROUBLESHOOTING.md](TROUBLESHOOTING.md#troubleshooting). Для подробного лога добавьте `--verbose`:

```bash
secsbom run --path ./app --verbose
```

Лог дублируется в файл `sbom_pipeline.log` в текущем каталоге.
