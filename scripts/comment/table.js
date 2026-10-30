// Condense vulnerabilities into a markdown table with one row per package name, merging
// installed versions and listing each vulnerability ID once at its highest severity.
// entries: [{ pkg, version, severity, id, url, fixed: [versions] }]
// severityIcon: { severity: icon }, in most to least severe order.
const escape = s => String(s ?? '').replace(/\|/g, '\\|');

module.exports = function table(entries, severityIcon) {
  const order = Object.keys(severityIcon);
  const rank = s => (order.includes(s) ? order.indexOf(s) : order.length);
  const label = s => (severityIcon[s] ? `${severityIcon[s]} ${s}` : s);

  const packages = new Map();
  for (const e of entries) {
    if (!packages.has(e.pkg)) {
      packages.set(e.pkg, { pkg: e.pkg, versions: new Set(), vulns: new Map(), fixed: new Set() });
    }
    const p = packages.get(e.pkg);
    p.versions.add(e.version);
    const existing = p.vulns.get(e.id);
    if (!existing || rank(e.severity) < rank(existing.severity)) {
      p.vulns.set(e.id, { ...e, url: e.url || existing?.url });
    }
    for (const f of e.fixed) {
      if (f) {
        p.fixed.add(f);
      }
    }
  }

  const rows = [...packages.values()]
    .map(p => {
      const vulns = [...p.vulns.values()].sort((x, y) => rank(x.severity) - rank(y.severity) || x.id.localeCompare(y.id));
      return { ...p, vulns, top: vulns[0].severity };
    })
    .sort((x, y) => rank(x.top) - rank(y.top) || x.pkg.localeCompare(y.pkg))
    .map(p => {
      // Vulnerabilities are listed most severe first, with the icon marking where each severity starts
      let previous;
      const ids = p.vulns.map(v => {
        const id = v.url ? `[${v.id}](${v.url})` : v.id;
        const icon = v.severity !== previous && severityIcon[v.severity] ? `${severityIcon[v.severity]} ` : '';
        previous = v.severity;
        return icon + id;
      });
      return `| ${label(p.top)} | ${escape(p.pkg)} | ${escape([...p.versions].join(', '))} | ${escape([...p.fixed].join(', ')) || '—'} | ${ids.join(', ')} |`;
    });

  return `| Severity | Package | Installed | Fixed | Vulnerabilities |\n` +
    `|----------|---------|-----------|-------|-----------------|\n` +
    rows.join('\n');
};

// Note how many vulnerabilities were left out of the comment for having no fix available
module.exports.unfixedNote = function unfixedNote(count) {
  if (!count) {
    return '';
  }
  return ` ${count} ${count === 1 ? 'vulnerability' : 'vulnerabilities'} with no fix available ` +
    `${count === 1 ? 'is' : 'are'} not listed.`;
};
