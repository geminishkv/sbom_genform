set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

# APP_SBOM="${OUTPUT_DIR}/app-bom-cdxgen.json"
# IMG_SBOM="${OUTPUT_DIR}/image-bom-trivy.json"  # можно оставить переменную на будущее

echo "[sbom_generate] REPO_ROOT=${REPO_ROOT}"
echo "[sbom_generate] PROJECT_DIR=${PROJECT_DIR}"
# echo "[sbom_generate] IMAGE_NAME=${IMAGE_NAME}"
echo "[sbom_generate] OUTPUT_DIR=${OUTPUT_DIR}"

mkdir -p "${OUTPUT_DIR}"

echo "[sbom_generate] Генерация SBOM по PROJECT_DIR через cdxgen (npx)..."
npx @cyclonedx/cdxgen \
  --spec-version 1.5 \
  --no-bom-url \
  --output "${OUTPUT_DIR}/app-bom-cdxgen.json" \
  "${PROJECT_DIR}"

echo "[sbom_generate] APP SBOM -> ${OUTPUT_DIR}/app-bom-cdxgen.json"
echo "[sbom_generate] Готово."

# Второй вариант через IMAGE_NAME=”${IMAGE_NAME:-sbom-formatter:inside}” в config.env
# echo "[sbom_generate] Генерация SBOM по контейнерному образу через Trivy (CycloneDX)..."
# trivy image --quiet \
#   --format cyclonedx \
#   --output "${IMG_SBOM}" \
#   "${IMAGE_NAME}"
# echo "[sbom_generate] IMAGE SBOM -> ${IMG_SBOM}"