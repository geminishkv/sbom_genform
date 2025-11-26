set -euo pipefail

TARGET_DIR="${TARGET_DIR:-/workspace}"          
IMAGE_NAME="${IMAGE_NAME:-sbom-formatter:latest}" # Trivy/Clair
DEP_CHECK_DATA="${DEP_CHECK_DATA:-/workspace/.dependency-check-data}"
REPORT_DIR="${REPORT_DIR:-/workspace/sca_reports}"

mkdir -p "${DEP_CHECK_DATA}" "${REPORT_DIR}"

echo "[sca] TARGET_DIR=${TARGET_DIR}"
echo "[sca] IMAGE_NAME=${IMAGE_NAME}"
echo "[sca] REPORT_DIR=${REPORT_DIR}"

if command -v dependency-check >/dev/null 2>&1; then # Dependency-Check
  echo "[sca] Запуск OWASP Dependency-Check..."
  dependency-check \
    --scan "${TARGET_DIR}" \
    --format "ALL" \
    --project "secgensbom-sca" \
    --data "${DEP_CHECK_DATA}" \
    --out "${REPORT_DIR}/dependency-check"
  echo "[sca] Отчёты Dependency-Check -> ${REPORT_DIR}/dependency-check"
else
  echo "[sca] dependency-check не найден, шаг пропущен."
fi

if command -v trivy >/dev/null 2>&1; then # Trivy
  mkdir -p "${REPORT_DIR}/trivy"

  echo "[sca] Trivy: сканирование образа ${IMAGE_NAME}..."
  trivy image --quiet \
    --format json \
    --output "${REPORT_DIR}/trivy/image-vulns.json" \
    "${IMAGE_NAME}" || echo "[sca] Trivy image scan завершился с ошибкой, продолжаем."

  if [ -f "${TARGET_DIR}/secgensbom_out/merged-bom-signed.json" ]; then
    echo "[sca] Trivy: сканирование итогового SBOM..."
    trivy sbom --quiet \
      --format json \
      --output "${REPORT_DIR}/trivy/sbom-vulns.json" \
      "${TARGET_DIR}/secgensbom_out/merged-bom-signed.json" || echo "[sca] Trivy sbom scan завершился с ошибкой, продолжаем."
  else
    echo "[sca] Итоговый SBOM не найден (${TARGET_DIR}/secgensbom_out/merged-bom-signed.json), шаг Trivy sbom пропущен."
  fi

  echo "[sca] Отчёты Trivy -> ${REPORT_DIR}/trivy"
else
  echo "[sca] trivy не найден, шаг Trivy пропущен."
fi

if command -v clairctl >/dev/null 2>&1; then # Clair
  mkdir -p "${REPORT_DIR}/clair"
  SAN="${IMAGE_NAME//[:\/]/_}"
  echo "[sca] Clair: анализ образа ${IMAGE_NAME}..."
  clairctl report \
    --log-level info \
    --format json \
    --output "${REPORT_DIR}/clair/clair-${SAN}.json" \
    "${IMAGE_NAME}" || echo "[sca] Clair scan завершился с ошибкой, продолжаем."
  echo "[sca] Отчёт Clair -> ${REPORT_DIR}/clair/clair-${SAN}.json"
else
  echo "[sca] clairctl не найден, шаг Clair пропущен."
fi

echo "[sca] SCA завершён."
