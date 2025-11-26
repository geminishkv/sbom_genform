set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

APP_SBOM="${OUTPUT_DIR}/app-bom-cdxgen.json"
IMG_SBOM="${OUTPUT_DIR}/image-bom-trivy.json"
MERGED_SBOM_RAW="${OUTPUT_DIR}/merged-bom-raw.json"
MERGED_SBOM_DEDUP="${OUTPUT_DIR}/merged-bom-dedup.json"
SIGNED_SBOM="${OUTPUT_DIR}/merged-bom-signed.json"

command -v cyclonedx >/dev/null 2>&1 || { echo "cyclonedx CLI (cyclonedx) не найден в PATH"; exit 1; }
command -v cdxgen    >/dev/null 2>&1 || { echo "cdxgen не найден в PATH"; exit 1; }

echo "[sbom_merge_sign] Мердж SBOM (приложение + образ)..."
cyclonedx merge \
  --output-format json \
  --output-file "${MERGED_SBOM_RAW}" \
  "${APP_SBOM}" "${IMG_SBOM}"

echo "[sbom_merge_sign] Дедупликация компонентов..."
cyclonedx truncate \
  --input-file "${MERGED_SBOM_RAW}" \
  --output-file "${MERGED_SBOM_DEDUP}"

echo "[sbom_merge_sign] Валидация итогового SBOM..."
cyclonedx validate \
  --input-file "${MERGED_SBOM_DEDUP}"

echo "[sbom_merge_sign] Подпись SBOM через cdxgen..."
export SBOM_SIGN_ALGORITHM SBOM_SIGN_PRIVATE_KEY SBOM_SIGN_PUBLIC_KEY

cdxgen --sign \
  --spec-version 1.5 \
  --input-bom "${MERGED_SBOM_DEDUP}" \
  --output "${SIGNED_SBOM}"

echo "[sbom_merge_sign] Подписанный SBOM -> ${SIGNED_SBOM}"
