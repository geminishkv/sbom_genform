set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

DEP_REPORT_DIR="${OUTPUT_DIR}/dependency-check"
mkdir -p "${DEP_REPORT_DIR}"
# mkdir -p "${DEP_CHECK_DATA}" "${DEP_REPORT_DIR}"

HOST_PROJECT_DIR="${HOST_PROJECT_DIR:-${PROJECT_DIR}}"
HOST_DEP_REPORT_DIR="${HOST_DEP_REPORT_DIR:-${DEP_REPORT_DIR}}"

# DEP_CHECK_DATA="${DEP_CHECK_DATA:-$HOME/.dependency-check}"

echo "[depcheck] HOST_PROJECT_DIR=${HOST_PROJECT_DIR}"
echo "[depcheck] PROJECT_DIR=${PROJECT_DIR}"
echo "[depcheck] DEP_REPORT_DIR=${DEP_REPORT_DIR}"
echo "[depcheck] HOST_DEP_REPORT_DIR=${HOST_DEP_REPORT_DIR}"
echo "[depcheck] DEP_CHECK_DATA=${DEP_CHECK_DATA}"

mkdir -p "${HOST_DEP_REPORT_DIR}"
mkdir -p "${DEP_CHECK_DATA}"

docker run --rm \
  --platform linux/amd64 \
  -v "${HOST_PROJECT_DIR}:/src" \
  -v "${DEP_CHECK_DATA}:/usr/share/dependency-check/data" \
  -v "${HOST_DEP_REPORT_DIR}:/report" \
  owasp/dependency-check:latest \
  --scan /src \
  --format "ALL" \
  --out /report