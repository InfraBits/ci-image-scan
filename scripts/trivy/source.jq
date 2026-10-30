# Add trivy's source package properties to the deb components of a syft CycloneDX SBOM.
# Ubuntu/Debian advisories are keyed on the source package (e.g. curl for libcurl4t64) and its
# version, but trivy only reads those from its own properties, not syft's. Without them any
# package named differently from its source is silently never matched.
def prop($name): first(.properties[]? | select(.name == $name and .value != "") | .value) // null;

.components |= map(
  if prop("syft:package:type") == "deb" then
    # Split [epoch:]version[-release], as trivy compares them as separate fields
    (prop("syft:metadata:sourceVersion") // .version) as $full
    | ($full | if test(":") then {epoch: sub(":.*$"; ""), rest: sub("^[^:]*:"; "")} else {epoch: "0", rest: .} end) as $e
    | ($e.rest | if test("-") then {version: sub("-[^-]*$"; ""), release: sub("^.*-"; "")} else {version: ., release: ""} end) as $v
    | .properties += [
        {name: "aquasecurity:trivy:SrcName", value: (prop("syft:metadata:source") // .name)},
        {name: "aquasecurity:trivy:SrcVersion", value: $v.version},
        {name: "aquasecurity:trivy:SrcRelease", value: $v.release},
        {name: "aquasecurity:trivy:SrcEpoch", value: $e.epoch}
      ]
  else . end
)
