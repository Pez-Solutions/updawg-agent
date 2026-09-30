#!/bin/sh
# Put packages on a channel of pkg.updawg.net (DAWG-45).
#
#   publish.sh beta|stable FILE.deb|FILE.rpm...
#
# The bucket behind pkg.updawg.net, as this writes it:
#
#   apt/pool/<file>.deb        added once, never replaced (IAM says so)
#   rpm/pool/<file>.rpm        the same
#   apt/dists/<channel>/       Packages for amd64 and arm64, Release,
#                              InRelease, Release.gpg
#   rpm/<channel>/repodata/    createrepo_c's, repomd.xml.asc beside it
#   channels/<channel>.txt     the pool files the channel's indexes name
#   updawg.asc                 the public key the indexes are signed with
#
# Order is what keeps a client from seeing an index that names a file not
# there yet: pool first, then each index, then what signs it, then the list.
#
# Needs: BUCKET, SIGN (updawg-release-sign), UPDAWG_RELEASE_KEY and
# GOOGLE_OAUTH_ACCESS_TOKEN for it, gcloud, apt-ftparchive, createrepo_c.
set -eu

channel=${1:?channel}
shift
case $channel in
  beta | stable) ;;
  *) echo "publish.sh: the channel is beta or stable, not $channel" >&2; exit 2 ;;
esac
[ $# -gt 0 ] || { echo "publish.sh: no packages" >&2; exit 2; }
: "${BUCKET:?}" "${SIGN:?}" "${UPDAWG_RELEASE_KEY:?}"
BASE_URL=${BASE_URL:-https://pkg.updawg.net}
# Pool files a channel's indexes name: the newest, four to a build (deb and
# rpm, two architectures). Older ones stay in the pool; they drop out of the
# index, so apt and dnf are not handed a history to read on every refresh.
KEEP=${KEEP:-40}

gs="gs://$BUCKET"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
IMMUTABLE="public, max-age=31536000, immutable"
FRESH="no-cache"

md5() { openssl md5 -binary "$1" | base64; }

# 1. The pool. --no-clobber, so a file already there is left as it is — and
#    then it had better be the same file.
: > "$work/new"
for f in "$@"; do
  case $f in
    *.deb) object="apt/pool/$(basename "$f")" ;;
    *.rpm) object="rpm/pool/$(basename "$f")" ;;
    *) echo "publish.sh: not a package: $f" >&2; exit 2 ;;
  esac
  gcloud storage cp --no-clobber --cache-control="$IMMUTABLE" "$f" "$gs/$object"
  there=$(gcloud storage objects describe "$gs/$object" --format='value(md5_hash)')
  if [ "$there" != "$(md5 "$f")" ]; then
    echo "publish.sh: $object is already published and is a different file" >&2
    exit 1
  fi
  echo "$object" >> "$work/new"
done

# 2. What the channel holds now.
gcloud storage cat "$gs/channels/$channel.txt" > "$work/old" 2> /dev/null || : > "$work/old"
cat "$work/old" "$work/new" | awk '!seen[$0]++' | tail -n "$KEEP" > "$work/list"
echo "$channel: $(wc -l < "$work/list") pool files"

# 3. Those files, here, where the index builders can read them.
mkdir -p "$work/apt/pool" "$work/rpm/$channel"
grep '^apt/pool/' "$work/list" | sed "s|^|$gs/|" |
  gcloud storage cp --read-paths-from-stdin "$work/apt/pool/"
grep '^rpm/pool/' "$work/list" | sed "s|^|$gs/|" |
  gcloud storage cp --read-paths-from-stdin "$work/rpm/$channel/"

# 4. apt: `deb [signed-by=…] https://pkg.updawg.net/apt <channel> main`.
(
  cd "$work/apt"
  dist="dists/$channel"
  for arch in amd64 arm64; do
    mkdir -p "$dist/main/binary-$arch"
    apt-ftparchive --arch "$arch" packages pool > "$dist/main/binary-$arch/Packages"
    gzip -9nk "$dist/main/binary-$arch/Packages"
  done
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=Updawg \
    -o APT::FTPArchive::Release::Label=Updawg \
    -o APT::FTPArchive::Release::Suite="$channel" \
    -o APT::FTPArchive::Release::Codename="$channel" \
    -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
    -o APT::FTPArchive::Release::Components=main \
    -o APT::FTPArchive::Release::Description="The Updawg agent, $channel" \
    release "$dist" > "$work/Release"
  mv "$work/Release" "$dist/Release"
  "$SIGN" clear "$dist/Release" > "$dist/InRelease"
  "$SIGN" detach "$dist/Release" > "$dist/Release.gpg"
)

# 5. dnf: baseurl=https://pkg.updawg.net/rpm/<channel>, repo_gpgcheck=1. The
#    packages stay in rpm/pool/, named from repodata through xml:base.
createrepo_c --quiet --baseurl "$BASE_URL/rpm/pool/" "$work/rpm/$channel"
"$SIGN" detach "$work/rpm/$channel/repodata/repomd.xml" > "$work/rpm/$channel/repodata/repomd.xml.asc"

# 6. Indexes before what signs them.
for arch in amd64 arm64; do
  gcloud storage cp --cache-control="$FRESH" \
    "$work/apt/dists/$channel/main/binary-$arch/Packages" \
    "$work/apt/dists/$channel/main/binary-$arch/Packages.gz" \
    "$gs/apt/dists/$channel/main/binary-$arch/"
done
gcloud storage cp --cache-control="$FRESH" \
  "$work/apt/dists/$channel/Release" "$work/apt/dists/$channel/InRelease" \
  "$work/apt/dists/$channel/Release.gpg" "$gs/apt/dists/$channel/"

# repodata's files are named by their hash: the new ones first, then the
# repomd.xml naming them and its signature, then the old ones go.
gcloud storage rsync --cache-control="$FRESH" \
  --exclude='^repomd\.xml' "$work/rpm/$channel/repodata" "$gs/rpm/$channel/repodata"
gcloud storage cp --cache-control="$FRESH" \
  "$work/rpm/$channel/repodata/repomd.xml" "$work/rpm/$channel/repodata/repomd.xml.asc" \
  "$gs/rpm/$channel/repodata/"
gcloud storage rsync --delete-unmatched-destination-objects --cache-control="$FRESH" \
  "$work/rpm/$channel/repodata" "$gs/rpm/$channel/repodata"

# 7. The key, and last the list, which is what the next run starts from.
"$SIGN" public-key > "$work/updawg.asc"
gcloud storage cp --cache-control="$FRESH" "$work/updawg.asc" "$gs/updawg.asc"
gcloud storage cp --cache-control="$FRESH" "$work/list" "$gs/channels/$channel.txt"
echo "published $(wc -l < "$work/new") file(s) to $channel"
