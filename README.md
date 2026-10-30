# Image scan

Scan container images for vulnerabilities.

Uses `syft` to build a SBOM and then scans using `grype` or `trivy`.

## Example Usage

```
  scan-container:
    runs-on: ubuntu-latest
    steps:
      - uses: infrabits/ci-image-scan@main
        with:
          image: ghcr.io/${{ github.repository }}:${{ github.sha }}
          github_token: ${{ secrets.GITHUB_TOKEN }}
```
