#!/bin/sh
# The package release of the commit checked out: what follows the version in
# the .deb and .rpm names, and what the binaries report (UPDAWG_BUILD, see
# crates/updawg-agent-core/build.rs). One place, so the two cannot disagree.
#
# Always the commit's UTC time and hash, tags included, so every build sorts
# after the one before it for apt and dnf alike. A tag used to be release 1,
# which sorts *below* every earlier build of the same version
# (0.2.0-1 < 0.2.0-20261002…): a tagged release would have looked older than
# the builds before it, and hosts would never have moved to it.
set -eu
echo "$(TZ=UTC0 git log -1 --date=format-local:%Y%m%d%H%M%S --format=%cd).g$(git rev-parse --short=7 HEAD)"
