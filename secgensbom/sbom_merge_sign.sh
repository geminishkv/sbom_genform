set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

APP_SBOM="${OUTPUT_DIR}/app-bom-cdxgen.json"
MERGED_SBOM_RAW="${OUTPUT_DIR}/merged-bom-raw.json"
MERGED_SBOM_DEDUP="${OUTPUT_DIR}/merged-bom-dedup.json"
SIGNED_SBOM="${OUTPUT_DIR}/merged-bom-signed.json"

command -v docker >/dev/null 2>&1 || { echo "docker не найден в PATH (для cyclonedx-cli в контейнере)"; exit 1; }
# command -v cyclonedx >/dev/null 2>&1 || { echo "cyclonedx CLI (cyclonedx) не найден в PATH"; exit 1; }
command -v npx   >/dev/null 2>&1 || { echo "npx не найден в PATH"; exit 1; }

echo "[sbom_merge_sign] Подготовка единого SBOM..."
# Пока используем только APP_SBOM, без image-BOM
cp "${APP_SBOM}" "${MERGED_SBOM_RAW}"

# echo "[sbom_merge_sign] Дедупликация компонентов..."
# cyclonedx truncate \
#   --input-file "${MERGED_SBOM_RAW}" \
#   --output-file "${MERGED_SBOM_DEDUP}"

echo "[sbom_merge_sign] Дедупликация компонентов через cyclonedx-cli (docker)..."
docker run --rm \
  -v "${OUTPUT_DIR}:/work" \
  cyclonedx/cyclonedx-cli:latest \
  truncate \
  --input-file "/work/merged-bom-raw.json" \
  --output-file "/work/merged-bom-dedup.json"

# echo "[sbom_merge_sign] Валидация итогового SBOM..."
# cyclonedx validate \
#   --input-file "${MERGED_SBOM_DEDUP}"

echo "[sbom_merge_sign] Валидация итогового SBOM через cyclonedx-cli (docker)..."
docker run --rm \
  -v "${OUTPUT_DIR}:/work" \
  cyclonedx/cyclonedx-cli:latest \
  validate \
  --input-file "/work/merged-bom-dedup.json"

echo "[sbom_merge_sign] Подпись SBOM через cdxgen (npx)..."
export SBOM_SIGN_ALGORITHM SBOM_SIGN_PRIVATE_KEY SBOM_SIGN_PUBLIC_KEY

npx @cyclonedx/cdxgen --sign \
  --spec-version 1.5 \
  --input-bom "${MERGED_SBOM_DEDUP}" \
  --output "${SIGNED_SBOM}"

echo "[sbom_merge_sign] Подписанный SBOM -> ${SIGNED_SBOM}"