// Build the PR comment summary from a grype JSON report.
const fs = require('fs');
const table = require('./table');
const { unfixedNote } = table;

const severityIcon = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🔵', Negligible: '⚪', Unknown: '⚪' };
const severityOrder = Object.keys(severityIcon);

// The same issue can be matched under a GHSA/distro ID and its CVE alias; report it
// under the CVE so both collapse into one entry
function canonical(m) {
  const v = m.vulnerability;
  if (v.id.startsWith('CVE-')) {
    return { id: v.id, url: v.dataSource };
  }
  const cve = (m.relatedVulnerabilities || []).find(r => r.id?.startsWith('CVE-'));
  return cve ? { id: cve.id, url: cve.dataSource || v.dataSource } : { id: v.id, url: v.dataSource };
}

module.exports = function build(reportPath, image) {
  const data = JSON.parse(fs.readFileSync(reportPath, 'utf8'));

  // Keep the highest severity when the same vulnerability is matched more than once
  const rank = s => (severityOrder.includes(s) ? severityOrder.indexOf(s) : severityOrder.length);
  // Only fixable vulnerabilities are listed, so the comment stays actionable; the rest are counted
  const unique = new Map();
  const unfixed = new Set();
  for (const m of (data.matches || [])) {
    const v = m.vulnerability;
    const a = m.artifact;
    const { id, url } = canonical(m);
    const key = `${id}/${a.name}/${a.version}`;
    if (v.fix?.state !== 'fixed') {
      unfixed.add(key);
    } else if (!unique.has(key) || rank(v.severity) < rank(unique.get(key).v.severity)) {
      unique.set(key, { v, a, id, url });
    }
  }
  const vulns = [...unique.values()];
  const hidden = [...unfixed].filter(key => !unique.has(key)).length;
  const note = unfixedNote(hidden);
  if (!vulns.length) {
    return '_No fixable vulnerabilities found._' + note;
  }

  const byType = {};
  for (const entry of vulns) {
    (byType[entry.a.type] ||= []).push(entry);
  }

  const sections = [];
  for (const [type, entries] of Object.entries(byType).sort()) {
    sections.push(`### ${type} packages\n` + table(entries.map(({ v, a, id, url }) => ({
      pkg: a.name,
      version: a.version,
      severity: v.severity,
      id,
      url,
      fixed: v.fix?.versions || [],
    })), severityIcon));
  }

  const counts = severityOrder
    .map(s => [s, vulns.filter(e => e.v.severity === s).length])
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${severityIcon[s]} ${n} ${s.toLowerCase()}`);
  const packages = new Set(vulns.map(e => e.a.name)).size;

  return `Found ${counts.join(', ')} fixable ${vulns.length === 1 ? 'vulnerability' : 'vulnerabilities'} ` +
    `across ${packages} ${packages === 1 ? 'package' : 'packages'} in \`${image}\`.${note}\n\n` +
    sections.join('\n\n');
};
