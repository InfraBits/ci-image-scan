#!/usr/bin/env bash
set -euo pipefail

# Scan without packages owned by OS packages (see os-owned.jq)
scan_sbom="$(mktemp "${RUNNER_TEMP}/scan.XXXXXX.syft.json")"
jq -f "${GITHUB_ACTION_PATH}/scripts/os-owned.jq" "${SBOM_PATH}" > "${scan_sbom}"

# The text report covers every vulnerability, regardless of severity or fix state.
# The PR comment only lists fixable ones, filtered when it is built from the JSON.
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

  grype "sbom:${scan_sbom}" "${outputs[@]}"
fi

# SARIF only covers fixable vulnerabilities, to keep code scanning actionable
if [ "${GENERATE_SARIF}" = "true" ];
then
  grype "sbom:${scan_sbom}" --only-fixed -o sarif="${REPORT_DIR}/grype.sarif"
  echo "sarif_path=${REPORT_DIR}/grype.sarif" >> "${GITHUB_OUTPUT}"
fi
