# Примеры результатов

## Структура артефактов

После полного запуска:

```bash
secsbom run --path ./examples/project_inject --bdu
```

ожидается такая структура:

```text
secgensbom_out/
├── app-bom-merged.json
├── app-bom-dedup.json
├── app-bom-dedup-signed.json
├── app-bom-dedup-signed.sig
├── merged-bom-signed.json
├── merged-bom-signed.sig
├── vulns-normalized.json
├── dependency-check/
├── trivy/
└── clair/

secgensbom_reports/
├── excel/merged-bom-signed.xlsx
├── docx/merged-bom-signed.docx
└── odt/merged-bom-signed.odt
```

## Фрагмент SBOM без уязвимостей

`secgensbom_out/app-bom-dedup-signed.json` содержит компоненты CycloneDX и SHA-256 подпись рядом в `.sig`:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "name": "requests",
      "version": "2.31.0",
      "purl": "pkg:pypi/requests@2.31.0",
      "bom-ref": "pkg:pypi/requests@2.31.0"
    }
  ]
}
```

## Фрагмент SBOM с уязвимостями

`secgensbom_out/merged-bom-signed.json` добавляет массив `vulnerabilities`:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2023-1234",
      "source": {
        "name": "TRIVY"
      },
      "ratings": [
        {
          "score": 7.5,
          "severity": "high",
          "method": "CVSSv3"
        }
      ],
      "affects": [
        {
          "ref": "pkg:pypi/requests@2.31.0"
        }
      ],
      "properties": [
        {
          "name": "ru.fstec.bdu:id",
          "value": "BDU:2023-01813"
        }
      ]
    }
  ]
}
```

## Нормализованный отчёт уязвимостей

`secgensbom_out/vulns-normalized.json` удобен для отладки и аудита:

```json
[
  {
    "cve_id": "CVE-2023-1234",
    "bdu_id": "BDU:2023-01813",
    "component": "requests",
    "version": "2.31.0",
    "purl": "pkg:pypi/requests@2.31.0",
    "cvss": 7.5,
    "severity": "HIGH",
    "scanner": "trivy",
    "fixed_version": "2.32.0",
    "acceptability_status": "Исправлено"
  }
]
```

## Excel / Word / ODT

Отчёты содержат два основных раздела.

Лист `Компоненты`:

| № п/п | Наименование компонента | Версия компонента | Тип пакета / тип компонента | PURL / технический идентификатор компонента | Язык (языки) | Признак принадлежности к поверхности атаки | Признак выполнения функций безопасности |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | requests | 2.31.0 | pypi | pkg:pypi/requests@2.31.0 | Python | no | no |

Лист `Уязвимости`:

| Компонент | Версия | CVE / ID | BDU / ID | CVSS | Критичность | Сканер | Исправлено в версии |
| --- | --- | --- | --- | --- | --- | --- | --- |
| requests | 2.31.0 | CVE-2023-1234 | BDU:2023-01813 | 7.5 | HIGH | trivy | 2.32.0 |

Колонка `BDU / ID` появляется только при `--bdu` или `BDU=true`.

## Кэши

Повторные запуски используют локальные кэши:

```text
.dependency-check-data/
└── nvd-api-cache/
    └── nvd_cve_cache.json

.bdu_cache/
└── bdu_cache.json
```

`nvd_cve_cache.json` хранит ответы NVD API по CVE. Если Clair не вернул CVSS, пайплайн сначала проверит этот файл и только затем обратится к NVD API.
