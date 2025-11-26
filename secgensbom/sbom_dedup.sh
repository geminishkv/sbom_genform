#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

APP_SBOM="${OUTPUT_DIR}/app-bom-cdxgen.json"
DEDUP_SBOM="${OUTPUT_DIR}/app-bom-dedup.json"

HOST_OUTPUT_DIR="${HOST_OUTPUT_DIR:-${OUTPUT_DIR}}"

echo "[sbom_dedup] OUTPUT_DIR=${OUTPUT_DIR}"
echo "[sbom_dedup] HOST_OUTPUT_DIR=${HOST_OUTPUT_DIR}"
echo "[sbom_dedup] APP_SBOM=${APP_SBOM}"
echo "[sbom_dedup] DEDUP_SBOM=${DEDUP_SBOM}"

if [ ! -f "${APP_SBOM}" ]; then
  echo "[sbom_dedup] Исходный SBOM не найден: ${APP_SBOM}"
  exit 1
fi

echo "[sbom_dedup] Дедупликация через cyclonedx-cli merge (docker)..."
docker run --rm \
  --platform linux/amd64 \
  -v "${HOST_OUTPUT_DIR}:/work" \
  cyclonedx/cyclonedx-cli:latest \
  merge \
    --input-files "/work/app-bom-cdxgen.json" "/work/app-bom-cdxgen.json" \
    --output-format json \
    --output-file "/work/app-bom-dedup.json"

echo "[sbom_dedup] Валидация дедуплицированного SBOM..."
docker run --rm \
  --platform linux/amd64 \
  -v "${HOST_OUTPUT_DIR}:/work" \
  cyclonedx/cyclonedx-cli:latest \
  validate \
    --input-file "/work/app-bom-dedup.json"

echo "[sbom_dedup] Готово: ${DEDUP_SBOM}"
