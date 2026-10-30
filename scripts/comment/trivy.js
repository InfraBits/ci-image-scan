// Build the PR comment summary from a trivy JSON report.
const fs = require('fs');
const table = require('./table');

const severityIcon = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', UNKNOWN: '⚪' };

// Targets are prefixed with the temporary SBOM path, e.g. "/home/runner/.../sbom.cdx.json (ubuntu 22.04)",
// which means nothing to a reader. Drop it, keeping any detail trivy adds after it.
function heading(result, sbomPath) {
  const target = result.Target.replace(sbomPath, '').trim().replace(/^\((.*)\)$/, '$1');
  return target || result.Type || 'packages';
}

module.exports = function build(reportPath) {
  const data = JSON.parse(fs.readFileSync(reportPath, 'utf8'));

  const sections = [];
  for (const result of (data.Results || [])) {
    const vulns = result.Vulnerabilities || [];
    if (vulns.length === 0) {
      continue;
    }
    sections.push({
      heading: heading(result, data.ArtifactName),
      table: table(vulns.map(v => ({
        pkg: v.PkgName,
        version: v.InstalledVersion,
        severity: v.Severity,
        id: v.VulnerabilityID,
        url: v.PrimaryURL,
        fixed: (v.FixedVersion || '').split(/,\s*/),
      })), severityIcon),
    });
  }

  if (!sections.length) {
    return '_No vulnerabilities found._';
  }
  // A single result needs no heading to tell it apart
  if (sections.length === 1) {
    return sections[0].table;
  }
  return sections.map(s => `### ${s.heading}\n${s.table}`).join('\n\n');
};
