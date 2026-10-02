#!/bin/sh
# Bump the agent's version: major, minor or patch (semver).
#
#   sh packaging/bump-version.sh minor     # 0.2.3 -> 0.3.0
#
# Edits [workspace.package] version in Cargo.toml and the lock file, and
# says what to commit. Open a pull request with it like any change: CI checks
# the version never goes backwards (ci.yml), and every build after the merge
# is <version>-<time>.g<sha>, which sorts above every build of the version
# before it.
#
# When: minor for a feature, patch for a fix, major when an agent of the old
# major cannot talk to the server any more. updawg-protocol has its own
# version (crates/updawg-protocol), bumped when the wire format changes and
# published separately.
set -eu
level=${1:?major, minor or patch}
cd "$(dirname "$0")/.."
current=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
IFS=. read -r major minor patch <<EOV
$current
EOV
case $level in
  major) next="$((major + 1)).0.0" ;;
  minor) next="$major.$((minor + 1)).0" ;;
  patch) next="$major.$minor.$((patch + 1))" ;;
  *) echo "bump-version.sh: major, minor or patch, not $level" >&2; exit 2 ;;
esac
# Only the [workspace.package] line: crates with their own version (the
# protocol) are not this script's.
awk -v next_version="$next" '
  /^\[workspace.package\]/ { in_pkg = 1 }
  /^\[/ && !/^\[workspace.package\]/ { in_pkg = 0 }
  in_pkg && /^version = / { print "version = \"" next_version "\""; next }
  { print }
' Cargo.toml > Cargo.toml.new && mv Cargo.toml.new Cargo.toml
cargo update --workspace --offline >/dev/null 2>&1 || cargo update --workspace >/dev/null
echo "$current -> $next"
echo "commit Cargo.toml and Cargo.lock: \"Version $next\""
