set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

CLAIR_REPORT_DIR="${OUTPUT_DIR}/clair"
mkdir -p "${CLAIR_REPORT_DIR}"

IMAGE_TO_SCAN="${IMAGE_NAME:-sbom-formatter:inside}"
SANITIZED_IMAGE="${IMAGE_TO_SCAN//[:\/]/_}"

# Поднять Clair и Postgres
echo "[clair] Анализ образа через Clair (clairctl container): ${IMAGE_TO_SCAN}..."
echo "[clair] CLAIR_REPORT_DIR=${CLAIR_REPORT_DIR}"

set +e
docker run --rm \
  --platform linux/amd64 \
  -v "${CLAIR_REPORT_DIR}:/reports" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CLAIR_ENDPOINT="${CLAIR_ENDPOINT:-http://clair:8080}" \
  quay.io/projectclair/clairctl:latest \
  report \
    --log-level info \
    --format json \
    --output "/reports/clair-${SANITIZED_IMAGE}.json" \
    "${IMAGE_TO_SCAN}"
status=$?
set -e

# после docker-compose пофиксить 
if [ $status -ne 0 ]; then
  echo "[clair] Ошибка при запуске clairctl (код $status). Шаг Clair пропущен."
  exit 0
fi

echo "[clair] Отчёт -> ${CLAIR_REPORT_DIR}/clair-${SANITIZED_IMAGE}.json"

# if ! command -v clairctl >/dev/null 2>&1; then
#   echo "[clair] clairctl не найден, шаг Clair пропускается."
#   exit 0
# fi

# SANITIZED_IMAGE="${IMAGE_NAME//[:\/]/_}"

# echo "[clair] Анализ образа через Clair: ${IMAGE_NAME}..."
# clairctl report \
#   --log-level info \
#   --format json \
#   --output "${CLAIR_REPORT_DIR}/clair-${SANITIZED_IMAGE}.json" \
#   "${IMAGE_NAME}"

№ echo "[clair] Отчёт -> ${CLAIR_REPORT_DIR}/clair-${SANITIZED_IMAGE}.json"