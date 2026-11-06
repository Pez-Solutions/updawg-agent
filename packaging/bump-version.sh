#!/bin/sh
# Bump the agent's version: major or minor (semver).
#
#   sh packaging/bump-version.sh minor     # 0.2.x -> 0.3.0
#
# Updates [workspace.package] version in Cargo.toml and Cargo.lock.
#
# There's no patch: packaging/version.sh counts it, one higher every
# release, and starts it at 0 again from the commit that bumps this. Minor
# for a notable set of features, major when old agents can no longer talk to
# the server. updawg-protocol is versioned separately.
set -eu
level=${1:?major or minor}
cd "$(dirname "$0")/.."
current=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
IFS=. read -r major minor patch <<EOV
$current
EOV
case $level in
  major) next="$((major + 1)).0.0" ;;
  minor) next="$major.$((minor + 1)).0" ;;
  *) echo "bump-version.sh: major or minor, not $level (version.sh counts the patch)" >&2; exit 2 ;;
esac
# Only the workspace version; the protocol crate has its own.
awk -v next_version="$next" '
  /^\[workspace.package\]/ { in_pkg = 1 }
  /^\[/ && !/^\[workspace.package\]/ { in_pkg = 0 }
  in_pkg && /^version = / { print "version = \"" next_version "\""; next }
  { print }
' Cargo.toml > Cargo.toml.new && mv Cargo.toml.new Cargo.toml
cargo update --workspace --offline >/dev/null 2>&1 || cargo update --workspace >/dev/null
echo "$current -> $next"
echo "commit Cargo.toml and Cargo.lock: \"Version $next\""
