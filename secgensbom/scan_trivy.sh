#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

SIGNED_SBOM="${OUTPUT_DIR}/merged-bom-signed.json"
TRIVY_REPORT_DIR="${OUTPUT_DIR}/trivy"

mkdir -p "${TRIVY_REPORT_DIR}"

command -v trivy >/dev/null 2>&1 || { echo "[trivy] trivy не найден в PATH"; exit 1; }

echo "[trivy] Сканирование контейнерного образа ${IMAGE_NAME}..."
trivy image --quiet \
  --format json \
  --output "${TRIVY_REPORT_DIR}/image-vulns.json" \
  "${IMAGE_NAME}"

echo "[trivy] Сканирование итогового SBOM..."
trivy sbom --quiet \
  --format json \
  --output "${TRIVY_REPORT_DIR}/sbom-vulns.json" \
  "${SIGNED_SBOM}"

echo "[trivy] Отчёты -> ${TRIVY_REPORT_DIR}"
