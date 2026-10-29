#!/bin/sh
# One release target's binaries, exactly as Release builds them:
#
#   sh packaging/build.sh x86_64-unknown-linux-musl|aarch64-unknown-linux-musl OUT
#
# The same commit built with this script gives the same bytes, wherever it is
# checked out and whenever it runs. That is what lets anybody rebuild what
# runs as root on their hosts and compare it with what we published, and the
# Release workflow proves it on every build by doing just that.
#
# What has to be the same, and where it is pinned:
#   the compiler        rust-toolchain.toml
#   the dependencies    Cargo.lock (--locked)
#   C toolchain, linker Cross.toml's images, by digest
#   and strip
#   the build id        packaging/release-id.sh: the commit's time and hash
#   timestamps          SOURCE_DATE_EPOCH, the commit's time
#   paths               --remap-path-prefix below: the checkout is /build and
#                       cargo's home /cargo, whatever they really are
#
# Needs: git, rustup, cross (release.yml installs a pinned one) and Docker.
set -eu

target=${1:?target}
out=${2:?output directory}
case $target in
  x86_64-unknown-linux-musl) strip=x86_64-linux-musl-strip want='x86-64' ;;
  aarch64-unknown-linux-musl) strip=aarch64-linux-musl-strip want='ARM aarch64' ;;
  *) echo "build.sh: not a release target: $target" >&2; exit 2 ;;
esac

here=$(pwd -P)
cargo_home=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)

# The version it reports is the packages'.
UPDAWG_BUILD=$(sh packaging/release-id.sh)
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
# Both the host's paths and cross's mount points: which of them the compiler
# sees depends on how cross mounted the checkout, and either way the binary
# should say /build.
RUSTFLAGS="--remap-path-prefix=$here=/build --remap-path-prefix=/project=/build --remap-path-prefix=$cargo_home=/cargo"
export UPDAWG_BUILD SOURCE_DATE_EPOCH RUSTFLAGS

cross build --locked --release --target "$target" --bin updawgd --bin updawgctl

mkdir -p "$out"
for b in updawgd updawgctl; do
  cp "target/$target/release/$b" "$out/$b"
done

# Stripped with the image's own binutils, not the runner's: what strip leaves
# behind is part of the bytes.
image=$(sed -n "/^\[target\.$target\]/,/^\[/s/^image = \"\(.*\)\"$/\1/p" Cross.toml)
[ -n "$image" ] || { echo "build.sh: no image for $target in Cross.toml" >&2; exit 1; }
out_abs=$(cd "$out" && pwd -P)
docker run --rm -v "$out_abs:/out" "$image" "$strip" /out/updawgd /out/updawgctl
sudo chown -R "$(id -u):$(id -g)" "$out_abs" 2>/dev/null || chown -R "$(id -u):$(id -g)" "$out_abs"
chmod 0755 "$out/updawgd" "$out/updawgctl"

file "$out/updawgd" | tee /dev/stderr | grep -Eq "$want.*(statically linked|static-pie linked)"
if [ "$target" = x86_64-unknown-linux-musl ]; then
  "$out/updawgctl" --version | grep -F -- "-$UPDAWG_BUILD"
fi
(cd "$out" && sha256sum updawgd updawgctl)
