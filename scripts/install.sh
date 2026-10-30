#!/usr/bin/env bash
set -euo pipefail

# renovate: datasource=github-releases depName=anchore/syft
SYFT_VERSION="1.55.0"
# renovate: datasource=github-releases depName=anchore/grype
GRYPE_VERSION="0.121.0"
# renovate: datasource=github-releases depName=aquasecurity/trivy
TRIVY_VERSION="0.76.1"

case "${RUNNER_ARCH}" in
  X64)   anchore_arch="amd64"; trivy_arch="64bit" ;;
  ARM64) anchore_arch="arm64"; trivy_arch="ARM64" ;;
  *)
    echo "::error::Unsupported runner architecture: ${RUNNER_ARCH}"
    exit 1
    ;;
esac

install() {
  local repo="$1" version="$2" tarball="$3" checksums="$4"
  shift 4

  local dir
  dir="$(mktemp -d "${RUNNER_TEMP}/install.XXXXXX")"
  local base="https://github.com/${repo}/releases/download/v${version}"

  echo "Installing ${repo} v${version}"
  curl -fsSL -o "${dir}/${tarball}" "${base}/${tarball}"
  curl -fsSL -o "${dir}/checksums.txt" "${base}/${checksums}"
  (cd "${dir}" && grep " ${tarball}\$" checksums.txt | sha256sum -c -)

  sudo tar -C /usr/local/bin/ --no-same-owner -xzf "${dir}/${tarball}" "$@"
  rm -rf "${dir}"
}

install anchore/syft "${SYFT_VERSION}" \
  "syft_${SYFT_VERSION}_linux_${anchore_arch}.tar.gz" \
  "syft_${SYFT_VERSION}_checksums.txt" \
  syft

case "${SCANNER}" in
  grype)
    install anchore/grype "${GRYPE_VERSION}" \
      "grype_${GRYPE_VERSION}_linux_${anchore_arch}.tar.gz" \
      "grype_${GRYPE_VERSION}_checksums.txt" \
      grype
    ;;
  trivy)
    install aquasecurity/trivy "${TRIVY_VERSION}" \
      "trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz" \
      "trivy_${TRIVY_VERSION}_checksums.txt" \
      trivy contrib/html.tpl
    ;;
esac
