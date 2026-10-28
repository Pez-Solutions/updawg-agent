#!/bin/sh
# Update get.updawg.net to the current stable build.
#
#   publish-get.sh VERSION DIR
#
# DIR holds <target>/updawgd and <target>/updawgctl for both targets: the
# promoted build's binaries, from bin/pool/. Bucket layout (/ serves
# install.sh):
#
#   get/install.sh                    curl -fsSL https://get.updawg.net | sh
#   get/agent/latest/updawgd          x86_64, at the top, where older
#   get/agent/latest/updawgctl        installers look
#   get/agent/latest/aarch64/...       aarch64
#   get/agent/latest/updawgd.service  the unit for a manual install
#   get/agent/latest/install.sh       the same installer, beside its files
#   get/agent/latest/SHA256SUMS       over all of the above, relative paths
#   get/agent/latest/REVISION         the commit
#
# The installer and unit come from the checked-out commit, the binaries from
# the promoted build. Uploaded files first, then SHA256SUMS, then the root
# installer, so a fetch mid-publish never sees missing files.
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
# Commit hash, from the `.g` part of the version.
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
