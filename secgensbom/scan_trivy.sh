#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

TRIVY_REPORT_DIR="${OUTPUT_DIR}/trivy"
mkdir -p "${TRIVY_REPORT_DIR}"

HOST_TRIVY_REPORT_DIR="${HOST_TRIVY_REPORT_DIR:-${TRIVY_REPORT_DIR}}"
mkdir -p "${HOST_TRIVY_REPORT_DIR}"

echo "[trivy] PROJECT_DIR=${PROJECT_DIR}"
echo "[trivy] HOST_TRIVY_REPORT_DIR=${HOST_TRIVY_REPORT_DIR}"

echo "[trivy] Сканирование контейнерного образа ${IMAGE_NAME}..."
trivy fs --scanners vuln,secret,config \
  --exit-code 0 \
  --format json \
  --output "${TRIVY_REPORT_DIR}/trivy-fs.json" \
  "${PROJECT_DIR}"

echo "[trivy] Отчёт fs -> ${TRIVY_REPORT_DIR}/trivy-fs.json"

SIGNED_SBOM="${OUTPUT_DIR}/merged-bom-signed.json"

if [ -f "${SIGNED_SBOM}" ]; then
  echo "[trivy] Сканирование итогового SBOM..."
  trivy sbom --quiet \
    --format json \
    --output "${TRIVY_REPORT_DIR}/sbom-vulns.json" \
    "${SIGNED_SBOM}"
  echo "[trivy] Отчёт sbom -> ${TRIVY_REPORT_DIR}/sbom-vulns.json"
else
  echo "[trivy] Подписанный SBOM не найден (${SIGNED_SBOM}), шаг trivy sbom пропущен."
fi