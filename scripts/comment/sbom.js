// Build the PR comment listing installed software from a syft-json SBOM.
const fs = require('fs');

const escape = s => String(s ?? '').replace(/\|/g, '\\|');

// Internal packages: OS packages from the base image, plus the jars and Go modules
// bundled inside runtimes and tools. Everything else (language packages, runtimes
// installed into buildpack layers) is what the app brings in
const systemTypes = new Set([
  'deb', 'rpm', 'apk', 'alpm', 'portage', 'linux-kernel', 'linux-kernel-module',
  'java-archive', 'go-module',
]);

module.exports = function build(sbomPath, image) {
  const data = JSON.parse(fs.readFileSync(sbomPath, 'utf8'));

  const seen = new Set();
  const byType = {};
  for (const a of (data.artifacts || [])) {
    const key = `${a.type}/${a.name}/${a.version}`;
    if (!seen.has(key)) {
      seen.add(key);
      (byType[a.type] ||= []).push(a);
    }
  }
  if (!seen.size) {
    return '_No packages found._';
  }

  // App packages are listed first and expanded; system packages are collapsed,
  // as OS package lists alone can run to hundreds of rows
  const types = Object.keys(byType).sort((x, y) =>
    systemTypes.has(x) - systemTypes.has(y) || x.localeCompare(y));
  const sections = types.map(type => {
    const artifacts = byType[type];
    artifacts.sort((x, y) => x.name.localeCompare(y.name) || String(x.version).localeCompare(String(y.version)));
    const rows = artifacts.map(a => `| ${escape(a.name)} | ${escape(a.version) || '—'} |`);
    return `<details${systemTypes.has(type) ? '' : ' open'}><summary>${type} (${artifacts.length})</summary>\n\n` +
      `| Package | Version |\n` +
      `|---------|---------|\n` +
      rows.join('\n') +
      `\n\n</details>`;
  });

  const distro = data.distro?.prettyName ? ` Base OS: ${data.distro.prettyName}.` : '';
  return `Found ${seen.size} ${seen.size === 1 ? 'package' : 'packages'} across ${types.length} ${types.length === 1 ? 'type' : 'types'} ` +
    `in \`${image}\`.${distro}\n\n` +
    sections.join('\n\n');
};
