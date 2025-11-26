set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

APP_SBOM="${OUTPUT_DIR}/app-bom-cdxgen.json"
MERGED_SBOM_RAW="${OUTPUT_DIR}/merged-bom-raw.json"
MERGED_SBOM_DEDUP="${OUTPUT_DIR}/merged-bom-dedup.json"
SIGNED_SBOM="${OUTPUT_DIR}/merged-bom-signed.json"

HOST_OUTPUT_DIR="${HOST_OUTPUT_DIR:-}"
if [ -z "${HOST_OUTPUT_DIR}" ]; then
  echo "[sbom_merge_sign] HOST_OUTPUT_DIR не задан, используем OUTPUT_DIR (${OUTPUT_DIR})"
  HOST_OUTPUT_DIR="${OUTPUT_DIR}"
fi

command -v docker >/dev/null 2>&1 || { echo "docker не найден в PATH (для cyclonedx-cli в контейнере)"; exit 1; }
# command -v cyclonedx >/dev/null 2>&1 || { echo "cyclonedx CLI (cyclonedx) не найден в PATH"; exit 1; }
command -v npx    >/dev/null 2>&1 || { echo "npx не найден в PATH"; exit 1; }

echo "[sbom_merge_sign] Подготовка исходного SBOM..."
# Пока используем только APP_SBOM, без image-BOM
# cp "${APP_SBOM}" "${HOST_OUTPUT_DIR}/merged-bom-raw.json"
cp "${APP_SBOM}" "${MERGED_SBOM_RAW}"

# echo "[sbom_merge_sign] Дедупликация компонентов..."
# cyclonedx truncate \
#   --input-file "${MERGED_SBOM_RAW}" \
#   --output-file "${MERGED_SBOM_DEDUP}"

echo "[sbom_merge_sign] Дедупликация компонентов через cyclonedx-cli merge (docker)..."
docker run --rm \
  --platform linux/amd64 \
  -v "${HOST_OUTPUT_DIR}:/work" \
  cyclonedx/cyclonedx-cli:latest \
  merge \
  --input-files "/work/merged-bom-raw.json" "/work/merged-bom-raw.json" \
  --output-format json \
  --output-file "/work/merged-bom-dedup.json"

# echo "[sbom_merge_sign] Валидация итогового SBOM..."
# cyclonedx validate \
#   --input-file "${MERGED_SBOM_DEDUP}"

echo "[sbom_merge_sign] Валидация SBOM через cyclonedx-cli (docker)..."
docker run --rm \
  --platform linux/amd64 \
  -v "${HOST_OUTPUT_DIR}:/work" \
  cyclonedx/cyclonedx-cli:latest \
  validate \
  --input-file "/work/merged-bom-dedup.json"

echo "[sbom_merge_sign] Подпись SBOM через cdxgen (npx)..."
npx @cyclonedx/cdxgen --sign \
  --spec-version 1.5 \
  --input-bom "${HOST_OUTPUT_DIR}/merged-bom-dedup.json" \
  --output "${SIGNED_SBOM}"

echo "[sbom_merge_sign] Подписанный SBOM -> ${SIGNED_SBOM}"