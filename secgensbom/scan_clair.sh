set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

CLAIR_REPORT_DIR="${OUTPUT_DIR}/clair"
mkdir -p "${CLAIR_REPORT_DIR}"

if ! command -v clairctl >/dev/null 2>&1; then
  echo "[clair] clairctl не найден, шаг Clair пропускается."
  exit 0
fi

SANITIZED_IMAGE="${IMAGE_NAME//[:\/]/_}"

echo "[clair] Анализ образа через Clair: ${IMAGE_NAME}..."
clairctl report \
  --log-level info \
  --format json \
  --output "${CLAIR_REPORT_DIR}/clair-${SANITIZED_IMAGE}.json" \
  "${IMAGE_NAME}"

echo "[clair] Отчёт -> ${CLAIR_REPORT_DIR}/clair-${SANITIZED_IMAGE}.json"
