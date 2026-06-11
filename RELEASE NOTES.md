# История изменений

Все значимые изменения **sbom-pipeline** документируются здесь.
Формат: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Версионирование: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.2.0]

### Исправлено

- `cli.py`: устранены дублирующие импорты внутри команды `cert`
- Команда `cert`: запуск без аргумента-файла больше не падает с `AttributeError`
- Флаги `--no-cdxgen` / `--no-syft` теперь работают — `pipeline` передаёт `use_cdxgen`/`use_syft` в генератор
- Имена промежуточных SBOM: `app-bom-cdxgen.json` / `app-bom-syft.json`
- Команда `gen-sbom`: добавлены флаги `--cdxgen` / `--syft`
- `.sig` содержит SHA-256 **записанного на диск файла** — внешняя проверка `shasum -a 256 <file>` совпадает
- `recommendation` сканера (PrimaryURL / Links / notes) попадает в SBOM `vulnerabilities[]`
- GOST-колонки отчёта берутся из явных полей `attack_surface`/`security_function`
- Clair: severity `"Unknown"` → `UNKNOWN` (был нестандартный `NOT_STATED`)
- `format` извлекает уязвимости из готового SBOM
- Регрессионные тесты на ключевые фиксы
- `secgensbom.yml`: убран несуществующий флаг `--source local` (ронял шаг прогона), добавлена установка Syft
- `ci.yml`: новый job **`docker`** — сборка образа `Dockerfile.secgensbom` (без push) + smoke-test `secsbom --version` на каждый push/PR (ловит сломанный Dockerfile до релиза)
- `Dockerfile.secgensbom`: OCI-лицензия исправлена `MIT` → `Apache-2.0`, добавлен `HEALTHCHECK`
- `Dockerfile.formatter`: исправлен запуск от root — добавлен непривилегированный `sbom` (uid 1001), иначе `is_admin`-guard блокировал запуск контейнера; добавлены OCI-метки, `HEALTHCHECK`, `COPY LICENSE.md README.md`, корректные `VOLUME`; база `python:3.13-slim`
- `docker-compose.yml`: сервисам `secgensbom` / `scan` заданы `security_opt: no-new-privileges` и `cap_drop: ALL`
- `depcheck`: логирует путь и размер используемой базы NVD — видно, переиспользуется ли существующая база или качается заново
- `PipelineConfig.from_env()` не использует `examples/project_inject` как fallback для `PROJECT_DIR`
- `pipeline.run`: Trivy FS и Dependency-Check выполняются только при наличии `cfg.project_dir`
- Описания опции `--path` в CLI и таблице help-а очищены от упоминания `examples/project_inject` как значения по умолчанию
- Trivy SBOM-сканирование теперь использует `app-bom-dedup-signed.json` вместо `app-bom-dedup.json`
- `pipeline._extract_dependencies()` обогащает объекты `Dependency` атрибутами `package_type`, `attack_surface`, `security_function`, `container_image`, `container_role` на основе данных SBOM
- `scanner/trivy.py`, `scanner/clair.py`, `scanner/depcheck.py` — парсеры заполняют `recommendation` и `acceptability_status` из соответствующих полей каждого сканера

---

### Безопасность

Проведён аудит (bandit, semgrep, pip-audit, ручной анализ), устранены находки:

- (CWE-532): git-токен больше не утекает в логи/консоль при ошибке клонирования — `clone_from` обёрнут в обработчик, токен маскируется в тексте исключения
- (CWE-345): честная терминология — SHA-256 «подпись» это контрольная сумма **целостности**, а не криптоподпись (docstring `sign.py`, README, `verify --help`)
- (CWE-295): TLS-проверка БДУ настраивается через `BDU_CA_BUNDLE` вместо жёсткого `verify=False`
- (CWE-918): валидация схемы `CLAIR_ENDPOINT` — запрет `file://` и прочих не-`http(s)` схем (защита от SSRF / чтения локальных файлов)
- Устранены молчаливое подавление исключений (`dependency.py`) и `assert` для runtime-инвариантов (`pipeline.py`)

---

### Добавлено

- Команда CLI `scan` (`secsbom scan <sbom.json>`) — сканирование уязвимостей готового SBOM (шаги 4–8 пайплайна): Clair (опционально), Trivy FS (опционально), Trivy SBOM, Dependency-Check (опционально), дедупликация, слияние, подпись → `merged-bom-signed.json`, экспорт листа уязвимостей
- Поддержка режима **только контейнерный образ** (`--image myimage:tag --clair`): `gen-sbom` и `run` без `--path`/`--url` создают SBOM из пакетов Clair без генерации по исходному коду
- Флаги `include_components` / `include_vulns` в методах `Exporter.exportToExcel`, `exportToDocx`, `exportToOdt` — управляют набором листов/секций без создания отдельных методов
- Параметры `include_components`, `include_vulns`, `sbom_file` в `pipeline._export_reports` — унифицированный экспорт для всех режимов
- **Новые колонки отчёта «Компоненты»**:
  - `Тип пакета / тип компонента` — тип экосистемы из PURL (например, `pypi`, `maven`, `npm`, `apk`)
  - `PURL / технический идентификатор компонента` — полный PURL компонента
  - `Признак принадлежности к поверхности атаки` — из свойства компонента CycloneDX (`attack-surface`, `attackSurface`, `isAttackSurface`)
  - `Признак выполнения функций безопасности` — из свойства компонента CycloneDX (`security-function`, `securityFunction`, `isSecurityFunction`)
  - `Принадлежность к контейнерному образу` — имя образа из `metadata.component` SBOM (только для контейнерного сценария)
  - `Роль компонента в составе контейнерного образа` — из свойства компонента (`container-role`, `containerRole`, `cdx:docker:layer`, `layer`)
- **Новые колонки отчёта «Уязвимости»**:
  - `Рекомендация / компенсирующая мера` — заполняется из `PrimaryURL` (Trivy), `Links[0]` (Clair), `notes` / `references[].url` (Dependency-Check); автоматически формируется «Обновить до версии X» при наличии `FixedVersion`
  - `Статус допустимости в рассматриваемой конфигурации` — из поля `Status` отчёта Trivy (`fixed`, `affected`, `will_not_fix`, `end_of_life` и др.)
- Опциональное BDU-обогащение уязвимостей через `--bdu` и переменную окружения `BDU`
- Выгрузка `BDU / ID` в Excel, Word и ODT отчёты
- Дедупликация уязвимостей (`dedup.dedup_vulns`): одна и та же CVE в одном компоненте из нескольких сканеров сводится к одной записи с наибольшим CVSS-баллом; ключ — `CVE-ID::purl` (или `CVE-ID::name@version` при отсутствии PURL)
- Два подписанных SBOM на выходе пайплайна:
  - `app-bom-dedup-signed.json` + `app-bom-dedup-signed.sig` — SBOM без уязвимостей (SHA-256 подпись после дедупликации компонентов, до сканирования)
  - `merged-bom-signed.json` + `merged-bom-signed.sig` — SBOM с уязвимостями (SHA-256 подпись после слияния)

---

## [2.1.0]

### Добавлено

- Команды CLI: `secsbom` / `secsbom-pipeline` (переименованы из `sbom` / `sbom-pipeline`)
- Кастомный help с баннером и панелями: `secsbom`, `secsbom -h`, `secsbom --help`
- Подкоманды: `info` (инспекция SBOM), `status` (проверка окружения), `diff` (сравнение SBOM)
- Мультиплатформенный Docker-образ (linux/amd64 + linux/arm64) на Docker Hub
- Единый workflow `publish.yml` — один тег публикует PyPI + GitHub Packages + Docker Hub + Release
- Диаграммы архитектуры Mermaid в README

### Изменено

- Точки входа переименованы: `secsbom = "sbom_pipeline.cli:main"`
- Публикация на PyPI: OIDC → API-токен (`PYPI_API_TOKEN`)
- `secgensbom.yml` упрощён до одного задания
- Все ссылки в репозитории: `sbom_genformatter` → `sbom_genform`

### Удалено

- `docker-publish.yml` (объединён в `publish.yml`)
- Шаг сборки Docker из `secgensbom.yml`

---

## [2.0.0]

### Добавлено

- Полный Python-пайплайн без shell-скриптов
- CLI `secsbom-pipeline run` на typer + rich: команды `run`, `format`, `verify`
- Генерация SBOM из локальной директории, GitHub и GitLab
- Автоопределение типа проекта (Python → cyclonedx-py, остальные → cdxgen)
- Дедупликация по PURL (`dedup.py`)
- SHA-256 подпись в `metadata.signature` + `.sig` (`sign.py`)
- Сканирование уязвимостей: Trivy, OWASP Dependency-Check, Clair (опционально)
- Встраивание уязвимостей в CycloneDX `vulnerabilities[]` (`vuln_merger.py`)
- Отчёты: Excel (.xlsx, 2 листа), Word (.docx), ODT (.odt)
- CI GitHub Actions: lint + тесты (Python 3.11–3.13)
- Shared-шаблон GitLab CI (`secgensbom/secgensbom.yml`)
- Docker-образы в `docker/`
- Уязвимый PHP демо-проект в `examples/project_inject/`

### Удалено

- Shell-скрипты (`pipeline.sh`, `scan_trivy.sh`, `scan_clair.sh` и др.)
- Пакет `script/`
- Сабмодули (`.gitmodules`)

### Изменено

- Путь по умолчанию: `project_inject/` → `examples/project_inject/`

---

## [1.x]

Пайплайн на shell-скриптах. История в git log.

[2.2.0]: https://github.com/geminishkv/sbom_genform/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/geminishkv/sbom_genform/releases/tag/v2.1.0
[2.0.0]: https://github.com/geminishkv/sbom_genform/releases/tag/v2.0.0
