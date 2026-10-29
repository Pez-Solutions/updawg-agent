#!/bin/sh
# One architecture's .deb and .rpm from its binaries, the same bytes
# every time for the same commit and binaries:
#
#   sh packaging/nfpm/package.sh amd64|arm64 BIN_DIR OUT_DIR [RELEASE]
#
# BIN_DIR holds updawgd and updawgctl for that architecture. RELEASE is
# packaging/release-id.sh's unless given (the upgrade test's "one release on"
# passes its own). NFPM is the nfpm binary, .nfpm/nfpm by default.
#
# Every file's time is the commit's (SOURCE_DATE_EPOCH, which nfpm also reads
# for what it makes itself): a checkout's files carry the time of the
# checkout, and a package records them.
set -eu

arch=${1:?arch}
bin=${2:?binaries}
out=${3:?output directory}
RELEASE=${4:-$(sh packaging/release-id.sh)}
NFPM=${NFPM:-.nfpm/nfpm}
VERSION=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export VERSION RELEASE SOURCE_DATE_EPOCH

# nfpm expands the environment in fields like version and arch but not in a
# file's source path, so the files go through a fixed directory.
rm -rf stage && mkdir stage
install -m 0755 "$bin/updawgd" "$bin/updawgctl" stage/
# A package installs under /usr, install.sh under /usr/local.
sed 's|^ExecStart=/usr/local/bin/updawgd$|ExecStart=/usr/bin/updawgd|' \
  packaging/systemd/updawgd.service > stage/updawgd.service
grep -q '^ExecStart=/usr/bin/updawgd$' stage/updawgd.service
chmod 0644 stage/updawgd.service
touch -d "@$SOURCE_DATE_EPOCH" stage/* packaging/agent.toml packaging/nfpm/*.sh

mkdir -p "$out"
for fmt in deb rpm; do
  ARCH=$arch "$NFPM" package -f packaging/nfpm/nfpm.yaml -p "$fmt" -t "$out/"
done
