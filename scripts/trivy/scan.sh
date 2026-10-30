#!/usr/bin/env bash
set -euo pipefail

# The HTML report and PR comment cover every vulnerability, regardless of severity or fix state
if [ "${GENERATE_REPORT}" = "true" ] || [ "${GENERATE_JSON}" = "true" ];
then
  trivy sbom \
    --scanners vuln \
    --exit-code 0 \
    --format json \
    --output "${REPORT_DIR}/trivy.json" \
    "${SBOM_PATH}"
  echo "json_path=${REPORT_DIR}/trivy.json" >> "${GITHUB_OUTPUT}"

  if [ "${GENERATE_REPORT}" = "true" ];
  then
    trivy convert --format template --template "@/usr/local/bin/contrib/html.tpl" \
      --output "${REPORT_DIR}/trivy.html" "${REPORT_DIR}/trivy.json"
    echo "report_path=${REPORT_DIR}/trivy.html" >> "${GITHUB_OUTPUT}"
  fi
fi

# SARIF only covers fixable critical/high vulnerabilities, to keep code scanning actionable.
# trivy convert can't drop unfixed results, so it gets its own filtered scan.
if [ "${GENERATE_SARIF}" = "true" ];
then
  trivy sbom \
    --scanners vuln \
    --severity "CRITICAL,HIGH" \
    --ignore-unfixed \
    --exit-code 0 \
    --format sarif \
    --output "${REPORT_DIR}/trivy.sarif" \
    "${SBOM_PATH}"
  echo "sarif_path=${REPORT_DIR}/trivy.sarif" >> "${GITHUB_OUTPUT}"
fi
