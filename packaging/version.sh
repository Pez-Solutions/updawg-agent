#!/bin/sh
# Prints the agent's version for HEAD, as the binaries and packages report it.
#
# Major and minor are Cargo.toml's. The patch counts the commits on main's
# first-parent line since that version was last changed there, so every
# release, one merge to main, is one higher than the one before without a
# commit to bump it. `bump-version.sh minor` (or major) starts it at 0 again.
#
# Needs the whole history: a shallow clone can't count, and a wrong count
# would be a wrong version.
set -eu
cd "$(dirname "$0")/.."
if [ "$(git rev-parse --is-shallow-repository)" = true ]; then
  echo "version.sh: a shallow clone can't count commits; check out with fetch-depth: 0" >&2
  exit 1
fi
current=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
IFS=. read -r major minor patch <<EOV
$current
EOV
since=$(git log -1 --format=%H -G '^version = "' -- Cargo.toml)
[ -n "$since" ] || { echo "version.sh: no commit sets the version in Cargo.toml" >&2; exit 1; }
count=$(git rev-list --count --first-parent "$since..HEAD")
echo "$major.$minor.$((patch + count))"
