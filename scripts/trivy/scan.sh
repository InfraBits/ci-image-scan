#!/usr/bin/env bash
set -euo pipefail

# trivy only reads CycloneDX/SPDX, so convert the syft SBOM after dropping packages owned by
# OS packages (see os-owned.jq) and adding the source package details it needs (see source.jq)
scan_sbom="$(mktemp "${RUNNER_TEMP}/scan.XXXXXX.cdx.json")"
jq -f "${GITHUB_ACTION_PATH}/scripts/os-owned.jq" "${SBOM_PATH}" \
  | syft convert - -o cyclonedx-json \
  | jq -f "${GITHUB_ACTION_PATH}/scripts/trivy/source.jq" > "${scan_sbom}"

# The HTML report covers every vulnerability, regardless of severity or fix state.
# The PR comment only lists fixable ones, filtered when it is built from the JSON.
if [ "${GENERATE_REPORT}" = "true" ] || [ "${GENERATE_JSON}" = "true" ];
then
  trivy sbom \
    --scanners vuln \
    --exit-code 0 \
    --format json \
    --output "${REPORT_DIR}/trivy.json" \
    "${scan_sbom}"
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
    "${scan_sbom}"
  echo "sarif_path=${REPORT_DIR}/trivy.sarif" >> "${GITHUB_OUTPUT}"
fi
