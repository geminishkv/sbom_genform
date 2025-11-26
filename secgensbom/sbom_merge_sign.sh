#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

APP_SBOM="${OUTPUT_DIR}/app-bom-cdxgen.json"
SIGNED_SBOM="${OUTPUT_DIR}/merged-bom-signed.json"

command -v npx >/dev/null 2>&1 || { echo "npx не найден в PATH"; exit 1; }

echo "[sbom_merge_sign] Проверка наличия исходного SBOM..."
if [ ! -f "${APP_SBOM}" ]; then
  echo "[sbom_merge_sign] Файл ${APP_SBOM} не найден"
  exit 1
fi

echo "[sbom_merge_sign] Подпись SBOM через cdxgen (npx)..."
npx @cyclonedx/cdxgen --sign \
  --spec-version 1.5 \
  --input-bom "${APP_SBOM}" \
  --output "${SIGNED_SBOM}"

echo "[sbom_merge_sign] Подписанный SBOM -> ${SIGNED_SBOM}"
