set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

echo "[pipeline] REPO_ROOT=${REPO_ROOT}"
echo "[pipeline] PROJECT_DIR=${PROJECT_DIR}"
echo "[pipeline] SBOM_DIR=${SBOM_DIR}"
echo "[pipeline] REPORTS_DIR=${REPORTS_DIR}"
echo "[pipeline] OUTPUT_DIR=${OUTPUT_DIR}"
echo "[pipeline] IMAGE_NAME=${IMAGE_NAME}"

echo "[pipeline] Старт SBOM/SCA пайплайна (secgensbom)..."

"${SCRIPT_DIR}/sbom_generate.sh"
"${SCRIPT_DIR}/sbom_merge_sign.sh"
"${SCRIPT_DIR}/scan_dependency_check.sh"
"${SCRIPT_DIR}/scan_trivy.sh"
"${SCRIPT_DIR}/scan_clair.sh" || echo "[pipeline] Clair шаг опционален, продолжаем."

echo "[pipeline] Готово. Итоговый подписанный SBOM и отчёты в secgensbom_out/."
echo "[pipeline] Итоговый SBOM: ${OUTPUT_DIR}/merged-bom-signed.json"
