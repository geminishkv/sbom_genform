set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

mkdir -p "${OUTPUT_DIR}"

APP_SBOM="${OUTPUT_DIR}/app-bom-cdxgen.json"
IMG_SBOM="${OUTPUT_DIR}/image-bom-trivy.json"

echo "[sbom_generate] REPO_ROOT=${REPO_ROOT}"
echo "[sbom_generate] PROJECT_DIR=${PROJECT_DIR}"
echo "[sbom_generate] IMAGE_NAME=${IMAGE_NAME}"
echo "[sbom_generate] OUTPUT_DIR=${OUTPUT_DIR}"

command -v cdxgen >/dev/null 2>&1 || { echo "cdxgen не найден в PATH"; exit 1; }
command -v trivy  >/dev/null 2>&1 || { echo "trivy не найден в PATH"; exit 1; }

echo "[sbom_generate] Генерация SBOM по исходникам (script/) через cdxgen..."
(
  cd "${PROJECT_DIR}"
  cdxgen -r -o "${APP_SBOM}" --spec-version 1.5
)
echo "[sbom_generate] APP SBOM -> ${APP_SBOM}"

echo "[sbom_generate] Генерация SBOM по контейнерному образу через Trivy (CycloneDX)..."
trivy image --quiet \
  --format cyclonedx \
  --output "${IMG_SBOM}" \
  "${IMAGE_NAME}"
echo "[sbom_generate] IMAGE SBOM -> ${IMG_SBOM}"

echo "[sbom_generate] Готово."
