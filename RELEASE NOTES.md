# История изменений

Все значимые изменения **sbom-pipeline** документируются здесь.
Формат: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Версионирование: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [2.2.0] — 2026-06-09

### Исправлено

- `cli.py`: устранены дублирующие импорты внутри команды `cert` (перенесены в начало модуля) — чистый `ruff F811/E402`
- Команда `cert`: запуск без аргумента-файла больше не падает с `AttributeError`, а выводит понятное сообщение об ошибке
- Команда `cert`: флаг `--output` теперь действительно задаёт путь результата (ранее игнорировался — файл всегда писался как `<input>(cert).json`)
- Команда `cert`: короткий алиас `-v` снят с `--component-version`, чтобы не конфликтовать с конвенцией `-v` = `--verbose`
- Команда `status`: внешний инструмент с ненулевым кодом возврата теперь помечается как «не найден» (раньше строка stderr выводилась как «версия»); проверка cyclonedx-py исправлена на модуль `cyclonedx_py`
- Новые smoke-тесты на `cert` (без аргумента, `--output`, путь по умолчанию) и `status` (учёт returncode)

### Добавлено

- Команда CLI `scan` (`secsbom scan <sbom.json>`) — сканирование уязвимостей готового SBOM (шаги 4–8 пайплайна): Clair (опционально), Trivy FS (опционально), Trivy SBOM, Dependency-Check (опционально), дедупликация, слияние, подпись → `merged-bom-signed.json`, экспорт листа уязвимостей
- Команда CLI `gen-sbom` (`secsbom gen-sbom`) — генерация SBOM (шаги 1–3) + экспорт листа компонентов: генерация из источника, Clair-обогащение пакетами (опционально), дедупликация, подпись → `app-bom-dedup-signed.json`
- Функция `pipeline.scan_only(sbom_path, cfg)` — оркестратор шагов 4–8
- Функция `pipeline.gen_sbom(cfg)` — оркестратор шагов 1–3 + экспорт компонентов
- Хелпер `pipeline._write_empty_sbom(path, image_name)` — создаёт минимальный CycloneDX SBOM-каркас для режима «только образ»
- Поддержка режима **только контейнерный образ** (`--image myimage:tag --clair`): `gen-sbom` и `run` без `--path`/`--url` создают SBOM из пакетов Clair без генерации по исходному коду
- Флаги `include_components` / `include_vulns` в методах `Exporter.exportToExcel`, `exportToDocx`, `exportToOdt` — управляют набором листов/секций без создания отдельных методов
- Параметры `include_components`, `include_vulns`, `sbom_file` в `pipeline._export_reports` — унифицированный экспорт для всех режимов
- Новые тесты:
  - `tests/unit/sbom_pipeline/test_scan_only.py` — 19 юнит-тестов (классы `TestScanOnlySmoke`, `TestClairSkipping`, `TestScannerCallArguments`, `TestCvssCrossPopulate`, `TestVulnReport`, `TestDeduplication`)
  - `tests/unit/sbom_pipeline/test_gen_sbom.py` — 19 юнит-тестов (классы `TestGenSbomSmoke`, `TestIntermediateArtefacts`, `TestSourceRouting`, `TestClairEnrichment`)
  - CLI smoke-тесты в `tests/test_smoke.py`: 8 тест-кейсов для команды `scan`, 6 — для `gen-sbom`

### Изменено

- `PipelineConfig.project_dir` теперь `Optional[Path] = None` (ранее — `Path("examples/project_inject")`); значение по умолчанию больше не подставляется автоматически
- `PipelineConfig.from_env()` не использует `examples/project_inject` как fallback для `PROJECT_DIR`
- `pipeline.scan_only`: Trivy FS и Dependency-Check пропускаются, если `cfg.project_dir is None`; Trivy SBOM выполняется всегда
- `pipeline.gen_sbom` и `pipeline.run`: если не задан ни один источник (нет `--path`/`--url` и нет `--image --clair`) — выбрасывается `ValueError`
- `pipeline.run`: Trivy FS и Dependency-Check выполняются только при наличии `cfg.project_dir`
- Описания опции `--path` в CLI и таблице help-а очищены от упоминания `examples/project_inject` как значения по умолчанию

---

### Добавлено

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
- BDU ID в CycloneDX SBOM теперь сохраняется в `vulnerabilities[].properties[]` как `ru.fstec.bdu:id`
- Дедупликация уязвимостей (`dedup.dedup_vulns`): одна и та же CVE в одном компоненте из нескольких сканеров сводится к одной записи с наибольшим CVSS-баллом; ключ — `CVE-ID::purl` (или `CVE-ID::name@version` при отсутствии PURL)
- Два подписанных SBOM на выходе пайплайна:
  - `app-bom-dedup-signed.json` + `app-bom-dedup-signed.sig` — SBOM без уязвимостей (SHA-256 подпись после дедупликации компонентов, до сканирования)
  - `merged-bom-signed.json` + `merged-bom-signed.sig` — SBOM с уязвимостями (SHA-256 подпись после слияния)
- Новая константа `SIGNED_DEDUP_BOM_FILE = "app-bom-dedup-signed.json"` в `constants.py`
- Пересмотренный порядок шагов пайплайна (8 шагов вместо 6):
  1. Генерация → 2. Дедупликация компонентов → 3. Подпись (без уязв.) → 4. Сканирование → 5. Дедупликация уязвимостей → 6. Слияние → 7. Подпись (с уязв.) → 8. Экспорт
- Новые тесты в `tests/test_smoke.py`:
  - `test_dedup_vulns_*` (7 тест-кейсов для `dedup_vulns`)
  - `test_sign_sig_file_named_after_output` — имя `.sig` соответствует имени выходного JSON
  - `test_two_signed_sboms_are_independent` — оба SBOM независимо верифицируемы
  - `test_two_sig_files_are_distinct` — `.sig` файлы не совпадают
- Новый файл `tests/unit/sbom_pipeline/test_dedup_vulns.py` с 18 юнит-тестами для `dedup_vulns` (классы `TestDedupByCveAndComponent`, `TestCvssSelection`, `TestFallbackKey`, базовые контракты)

### Изменено

- Trivy SBOM-сканирование теперь использует `app-bom-dedup-signed.json` вместо `app-bom-dedup.json`
- README: обновлена таблица артефактов и диаграмма Mermaid
- `pipeline._extract_dependencies()` обогащает объекты `Dependency` атрибутами `package_type`, `attack_surface`, `security_function`, `container_image`, `container_role` на основе данных SBOM
- `scanner/trivy.py`, `scanner/clair.py`, `scanner/depcheck.py` — парсеры заполняют `recommendation` и `acceptability_status` из соответствующих полей каждого сканера
- Разделена объединённая колонка «Принадлежность к поверхности атаки / функциям безопасности» на два отдельных поля
- Поля `recommendation` и `acceptability_status` добавлены в датакласс `VulnFinding`
- Вспомогательные функции `_purl_type()` и `_find_prop()` в `pipeline.py`
- Тесты `tests/test_new_columns.py` (77 cases): покрывают новые поля во всех сканерах, `_extract_dependencies()`, `Exporter._comp_rows()` / `_vuln_rows()` и Excel-экспорт

---

## [2.1.0] — 2026-03-21

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

## [2.0.0] — 2025-12-01

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

## [1.x] — устаревшая версия

Пайплайн на shell-скриптах. История в git log.

[Unreleased]: https://github.com/geminishkv/sbom_genform/compare/v2.2.0...HEAD
[2.2.0]: https://github.com/geminishkv/sbom_genform/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/geminishkv/sbom_genform/releases/tag/v2.1.0
[2.0.0]: https://github.com/geminishkv/sbom_genform/releases/tag/v2.0.0
