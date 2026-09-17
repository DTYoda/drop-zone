#!/usr/bin/env bash
#
# After tagging a release, print the Homebrew stable stanza for drop-zone.rb.
#
# Usage: packaging/homebrew/fill-stable.sh v1.0.0
#
# Homebrew-core and a personal tap need an immutable tarball URL and its
# SHA-256. GitHub publishes that archive automatically for every tag.

set -euo pipefail

if [[ "${1:-}" == "" ]]; then
  echo "usage: $0 vX.Y.Z" >&2
  exit 1
fi

tag="$1"
repo="${DROP_ZONE_GITHUB_REPO:-DTYoda/drop-zone}"
url="https://github.com/${repo}/archive/refs/tags/${tag}.tar.gz"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

echo "fetching ${url}" >&2
curl -fsSL "$url" -o "$tmp"

if command -v sha256sum >/dev/null 2>&1; then
  sha="$(sha256sum "$tmp" | awk '{print $1}')"
else
  sha="$(shasum -a 256 "$tmp" | awk '{print $1}')"
fi

cat <<EOF
  url "${url}"
  sha256 "${sha}"
  license "MIT"
  head "https://github.com/${repo}.git", branch: "main"

  livecheck do
    url :stable
    strategy :github_latest
  end
EOF
