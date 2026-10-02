#!/bin/sh
# Make get.updawg.net what stable holds (DAWG-44, DAWG-46).
#
#   publish-get.sh VERSION DIR
#
# DIR holds <target>/updawgd and <target>/updawgctl for both targets: the
# promoted build's binaries, from bin/pool/. Served by Caddy from the packages
# bucket's get/ (updawg-infra), with / as install.sh:
#
#   get/install.sh                    curl -fsSL https://get.updawg.net | sh
#   get/agent/latest/updawgd          x86_64, at the top, where older
#   get/agent/latest/updawgctl        installers look
#   get/agent/latest/aarch64/…        aarch64 (DAWG-41)
#   get/agent/latest/updawgd.service  the unit for a manual install
#   get/agent/latest/install.sh       the same installer, beside its files
#   get/agent/latest/SHA256SUMS       over all of the above, relative paths
#   get/agent/latest/REVISION         the commit
#
# The installer and the unit come from the commit checked out (main, which
# Promote runs from); the binaries from the build being promoted. Files
# first, SHA256SUMS next, the installer at the root last: a host that fetches
# mid-publish never gets a script whose files are not there yet.
#
# Needs: BUCKET, gcloud with release-signer's credential.
set -eu
version=${1:?version}
dir=${2:?directory}
printf '%s' "$version" | grep -Eq '^[0-9][0-9A-Za-z.+~-]*$' ||
  { echo "publish-get.sh: not a version: $version" >&2; exit 2; }
: "${BUCKET:?}"
gs="gs://$BUCKET/get"
FRESH="no-cache"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/latest/aarch64"
cp "$dir/x86_64-unknown-linux-musl/updawgd" "$dir/x86_64-unknown-linux-musl/updawgctl" "$work/latest/"
cp "$dir/aarch64-unknown-linux-musl/updawgd" "$dir/aarch64-unknown-linux-musl/updawgctl" "$work/latest/aarch64/"
cp packaging/systemd/updawgd.service packaging/install.sh "$work/latest/"
chmod 0755 "$work/latest/updawgd" "$work/latest/updawgctl" "$work/latest/aarch64/updawgd" "$work/latest/aarch64/updawgctl"
# The commit the build is from: what follows `.g` in its version.
echo "$version" | sed -n 's/.*\.g\([0-9a-f]*\)$/\1/p' > "$work/latest/REVISION"
(
  cd "$work/latest"
  sha256sum updawgd updawgctl aarch64/updawgd aarch64/updawgctl updawgd.service install.sh > SHA256SUMS
)
cat "$work/latest/SHA256SUMS"

up() { gcloud storage cp --cache-control="$FRESH" "$@"; }
up "$work/latest/updawgd" "$work/latest/updawgctl" "$work/latest/updawgd.service" "$work/latest/REVISION" "$gs/agent/latest/"
up "$work/latest/aarch64/updawgd" "$work/latest/aarch64/updawgctl" "$gs/agent/latest/aarch64/"
up --content-type="text/plain; charset=utf-8" "$work/latest/install.sh" "$gs/agent/latest/install.sh"
up --content-type="text/plain; charset=utf-8" "$work/latest/SHA256SUMS" "$gs/agent/latest/SHA256SUMS"
up --content-type="text/plain; charset=utf-8" "$work/latest/install.sh" "$gs/install.sh"
echo "get.updawg.net is $version"
