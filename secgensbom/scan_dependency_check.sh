set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

HOST_PROJECT_DIR="${HOST_PROJECT_DIR:-${PROJECT_DIR}}"
DEP_REPORT_DIR="${OUTPUT_DIR}/dependency-check"

mkdir -p "${DEP_CHECK_DATA}" "${DEP_REPORT_DIR}"

echo "[depcheck] HOST_PROJECT_DIR=${HOST_PROJECT_DIR}"
echo "[depcheck] PROJECT_DIR=${PROJECT_DIR}"
echo "[depcheck] DEP_REPORT_DIR=${DEP_REPORT_DIR}"

command -v docker >/dev/null 2>&1 || { echo "docker не найден в PATH"; exit 1; }

echo "[depcheck] Запуск OWASP Dependency-Check (Docker) по script/..."
docker run --rm \
  -v "${PROJECT_DIR}:/src:ro" \
  -v "${DEP_CHECK_DATA}:/usr/share/dependency-check/data" \
  -v "${DEP_REPORT_DIR}:/report" \
  owasp/dependency-check:latest \
  --scan /src \
  --format "ALL" \
  --project "secgensbom-project" \
  --out /report

echo "[depcheck] Отчёты -> ${DEP_REPORT_DIR}"