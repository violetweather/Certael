#!/usr/bin/env bash
set -euo pipefail

output=${1:?Usage: package-cyclonedx-sbom.sh OUTPUT.tar.gz}
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$workspace"
cargo cyclonedx --format json --spec-version 1.5 --target all

list=$(mktemp)
staging=$(mktemp -d)
trap 'rm -f "$list"; rm -rf "$staging"' EXIT
find . -path ./target -prune -o -name '*.cdx.json' -type f -print0 > "$list"
if [[ ! -s "$list" ]]; then
  echo "cargo-cyclonedx produced no component SBOMs" >&2
  exit 1
fi
while IFS= read -r -d '' sbom; do
  jq -e '.bomFormat == "CycloneDX" and .metadata.component.name != null' "$sbom" >/dev/null
  destination="$staging/${sbom#./}"
  mkdir -p "$(dirname "$destination")"
  cp "$sbom" "$destination"
done < "$list"
mkdir -p "$(dirname "$output")"
tar -C "$staging" -czf "$output" .
if [[ $(wc -c < "$output") -le 100 ]] || ! tar -tzf "$output" | grep -q '\.cdx\.json$'; then
  echo "generated CycloneDX archive is empty or invalid" >&2
  exit 1
fi
while IFS= read -r -d '' sbom; do rm -f "$sbom"; done < "$list"
