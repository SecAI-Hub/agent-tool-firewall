#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <strict-semver-tag>" >&2
  exit 64
fi

tag="$1"
semver_pattern='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'

if [[ ! "$tag" =~ $semver_pattern ]]; then
  echo "release tag is not strict SemVer with a leading v" >&2
  exit 65
fi

# OCI tags cannot contain '+'. Strict SemVer cannot contain '_', so this
# substitution is reversible and collision-free within the accepted tag set.
oci_tag="${tag//+/_}"
if [[ "${#oci_tag}" -gt 128 || ! "$oci_tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]]; then
  echo "derived OCI tag is invalid or longer than 128 characters" >&2
  exit 65
fi

printf '%s\n' "$oci_tag"
