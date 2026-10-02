#!/bin/sh
# The package release of the commit checked out: what follows the version in
# the .deb and .rpm names, and what the binaries report (UPDAWG_BUILD, see
# crates/updawg-agent-core/build.rs). One place, so the two cannot disagree.
#
# A tag is release 1. Anything else is the commit's UTC time and hash, so
# every build of main sorts after the one before it for apt and dnf alike.
set -eu
if [ "${GITHUB_REF_TYPE:-}" = tag ]; then
  echo 1
else
  echo "$(TZ=UTC0 git log -1 --date=format-local:%Y%m%d%H%M%S --format=%cd).g$(git rev-parse --short=7 HEAD)"
fi
