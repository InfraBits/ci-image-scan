#!/usr/bin/env bash
set -euo pipefail

syft scan "${IMAGE}" \
  --select-catalogers "+sbom-cataloger" \
  -o syft-json="${SBOM_DIR}/sbom.syft.json" \
  -o cyclonedx-json="${SBOM_DIR}/sbom.cdx.json"

{
  echo "syft_path=${SBOM_DIR}/sbom.syft.json"
  echo "cdx_path=${SBOM_DIR}/sbom.cdx.json"
} >> "${GITHUB_OUTPUT}"
