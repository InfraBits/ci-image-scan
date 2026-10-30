# Drop packages whose files belong to an OS package (e.g. a jar shipped inside a deb) from a
# syft-json SBOM. Distros backport fixes without bumping the upstream version, so matching these
# against upstream advisories reports issues the OS package has already patched. The OS package
# itself is still scanned against the distro's own advisories.
([.artifacts[] | select(.type | IN("deb", "rpm", "apk")) | {key: .id, value: true}] | from_entries) as $os
| ([.artifactRelationships[] | select(.type == "ownership-by-file-overlap" and $os[.parent]) | {key: .child, value: true}] | from_entries) as $owned
| .artifacts |= map(select($owned[.id] | not))
| .artifactRelationships |= map(select(($owned[.parent] or $owned[.child]) | not))
