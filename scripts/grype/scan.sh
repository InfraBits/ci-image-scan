#!/usr/bin/env bash
set -euo pipefail

# The text report and PR comment cover every vulnerability, regardless of severity or fix state
if [ "${GENERATE_REPORT}" = "true" ] || [ "${GENERATE_JSON}" = "true" ];
then
  outputs=()

  if [ "${GENERATE_REPORT}" = "true" ];
  then
    outputs+=(-o table="${REPORT_DIR}/grype.txt")
    echo "report_path=${REPORT_DIR}/grype.txt" >> "${GITHUB_OUTPUT}"
  fi

  if [ "${GENERATE_JSON}" = "true" ];
  then
    outputs+=(-o json="${REPORT_DIR}/grype.json")
    echo "json_path=${REPORT_DIR}/grype.json" >> "${GITHUB_OUTPUT}"
  fi

  grype "sbom:${SBOM_PATH}" "${outputs[@]}"
fi

# SARIF only covers fixable vulnerabilities, to keep code scanning actionable
if [ "${GENERATE_SARIF}" = "true" ];
then
  grype "sbom:${SBOM_PATH}" --only-fixed -o sarif="${REPORT_DIR}/grype.sarif"
  echo "sarif_path=${REPORT_DIR}/grype.sarif" >> "${GITHUB_OUTPUT}"
fi
