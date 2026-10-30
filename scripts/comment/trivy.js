// Build the PR comment summary from a trivy JSON report.
const fs = require('fs');
const table = require('./table');
const { unfixedNote } = table;

const severityIcon = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', UNKNOWN: '⚪' };

// Targets are prefixed with the temporary SBOM path, e.g. "/home/runner/.../sbom.cdx.json (ubuntu 22.04)",
// which means nothing to a reader. Drop it, keeping any detail trivy adds after it.
function heading(result, sbomPath) {
  const target = result.Target.replace(sbomPath, '').trim().replace(/^\((.*)\)$/, '$1');
  return target || result.Type || 'packages';
}

module.exports = function build(reportPath) {
  const data = JSON.parse(fs.readFileSync(reportPath, 'utf8'));

  // Only fixable vulnerabilities are listed, so the comment stays actionable; the rest are counted
  const sections = [];
  let hidden = 0;
  for (const result of (data.Results || [])) {
    const all = result.Vulnerabilities || [];
    const vulns = all.filter(v => v.FixedVersion);
    hidden += all.length - vulns.length;
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

  const note = unfixedNote(hidden).trim();
  if (!sections.length) {
    return `_No fixable vulnerabilities found._${note ? ' ' + note : ''}`;
  }
  const prefix = note ? `${note}\n\n` : '';
  // A single result needs no heading to tell it apart
  if (sections.length === 1) {
    return prefix + sections[0].table;
  }
  return prefix + sections.map(s => `### ${s.heading}\n${s.table}`).join('\n\n');
};
