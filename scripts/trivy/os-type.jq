# Keep only one type of OS package in a syft-json SBOM, as trivy refuses SBOMs mixing them
# (e.g. a stray rpm database in a Debian image). The type matching the image's distro is kept,
# falling back to the most common one. Foreign OS packages can't be matched against the distro's
# advisories anyway.
def os_type:
  if IN("alpine", "wolfi", "chainguard") then "apk"
  elif IN("debian", "ubuntu") then "deb"
  elif IN("rhel", "fedora", "centos", "rocky", "almalinux", "amzn", "ol", "suse", "opensuse", "sles", "photon", "mariner", "azurelinux") then "rpm"
  else empty end;

[.artifacts[] | select(.type | IN("deb", "rpm", "apk")) | .type] as $types
| if ($types | unique | length) <= 1 then . else
    (first(.distro.id // empty, (.distro.idLike // [])[] | os_type | select(IN($types[])))
      // ($types | group_by(.) | max_by(length) | first)) as $keep
    | ([.artifacts[] | select(.type | IN("deb", "rpm", "apk")) | select(.type != $keep) | {key: .id, value: true}] | from_entries) as $drop
    | .artifacts |= map(select($drop[.id] | not))
    | .artifactRelationships |= map(select(($drop[.parent] or $drop[.child]) | not))
  end
