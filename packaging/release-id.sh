#!/bin/sh
# Prints the package release for HEAD (the part after the version), used for
# the .deb/.rpm and as UPDAWG_BUILD in the binaries (see
# crates/updawg-agent-core/build.rs).
#
# Commit time + hash, so builds always sort in order. Tagged builds use it
# too; a release like `1` would sort below earlier builds of the same version.
set -eu
echo "$(TZ=UTC0 git log -1 --date=format-local:%Y%m%d%H%M%S --format=%cd).g$(git rev-parse --short=7 HEAD)"
