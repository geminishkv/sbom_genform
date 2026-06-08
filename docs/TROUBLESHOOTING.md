# Troubleshooting

## NVD API и Dependency-Check

### `NVD_API_KEY` не задан

Dependency-Check может работать без ключа, но NVD сильно ограничивает частоту запросов. Для стабильных запусков задайте ключ:

```bash
export NVD_API_KEY="<token>"
secsbom run
```

Получить ключ можно на странице NVD API. В Docker/Compose передайте переменную в окружение контейнера.

### Dependency-Check завершается с кодом 13

Чаще всего это означает, что локальная база NVD не успела скачаться или NVD отклонил запросы по rate limit.

Проверьте:

- задан `NVD_API_KEY`;
- каталог `DEP_CHECK_DATA` смонтирован как постоянный volume;
- у контейнера есть доступ к интернету;
- при повторном запуске используется тот же `DEP_CHECK_DATA`.

### CVSS у Clair остаётся `0.0`

Clair не всегда отдаёт CVSS в собственном отчёте. Пайплайн сначала пытается взять оценку из Clair enrichments, затем использует NVD fallback.

Проверьте:

- `NVD_CACHE_DIR` указывает на доступный для записи каталог;
- в логах есть строка про `[nvd_client]`;
- CVE действительно есть в NVD;
- если запускаете в Docker, каталог `NVD_CACHE_DIR` не теряется между запусками.

## Clair

### `clairctl не найден в PATH`

Установите `clairctl` и добавьте бинарный файл в `PATH`, либо используйте `docker compose up --build`, где Clair уже описан отдельным сервисом.

### `SKIP_CLAIR=false`, но Clair пропущен

Для Clair нужен образ:

```bash
export IMAGE_NAME="my-image:latest"
export SKIP_CLAIR=false
secsbom run
```

Если `IMAGE_NAME` не задан, пайплайн пропускает Clair автоматически.

### Clair возвращает 500 при первом запуске

На первом старте Clair загружает базы уязвимостей. Пайплайн повторяет запросы, но на холодном окружении это может занять несколько минут. Проверьте логи `clair` и `clair-db`.

## Trivy

### `trivy не найден в PATH`

Установите Trivy локально или используйте Docker-образ проекта. Без Trivy пайплайн продолжит работу, но результаты будут неполными.

### Trivy не может скачать базы

Проверьте доступ к `ghcr.io/aquasecurity/trivy-db` и `ghcr.io/aquasecurity/trivy-java-db`. В закрытых сетях заранее подготовьте mirror или локальный cache Trivy.

## Docker

### Dependency-Check не стартует из контейнера

Пайплайн запускает Dependency-Check через `docker run`, поэтому внутри контейнера должен быть доступен Docker socket:

```bash
-v /var/run/docker.sock:/var/run/docker.sock
```

Также проверьте, что host-пути `HOST_PROJECT_DIR`, `HOST_DEP_REPORT_DIR`, `HOST_DEP_CHECK_DATA` соответствуют реальным путям на машине, где запущен Docker.

## BDU

### BDU ID не появились

BDU-обогащение выключено по умолчанию. Запустите:

```bash
secsbom run --bdu
```

или:

```bash
export BDU=true
secsbom run
```

Если сайт БДУ недоступен или изменил HTML, пайплайн сохранит основной отчёт без BDU ID и запишет предупреждение в лог.

## Отчёты

### Пустые колонки `Признак принадлежности к поверхности атаки` и `Признак выполнения функций безопасности`

Эти поля заполняются из свойств компонента CycloneDX:

- `attack-surface`, `attack_surface`, `attackSurface`, `isAttackSurface`, `GOST: attack_surface`;
- `security-function`, `security_function`, `securityFunction`, `isSecurityFunction`, `GOST: security_function`.

Для автоматического добавления GOST-полей используйте:

```bash
secsbom cert secgensbom_out/app-bom-dedup-signed.json
```

### Экспорт компонентов стал медленным

По умолчанию экспорт не делает сетевые запросы для уточнения npm/NuGet/Debian/GitHub-данных. Если включали сетевой режим, отключите его:

```bash
unset SBOM_COMPONENT_NETWORK
```

Включать сетевой режим стоит только когда нужны дополнительные языки из GitHub:

```bash
export SBOM_COMPONENT_NETWORK=true
```
