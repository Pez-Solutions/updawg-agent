#!/bin/sh
# Upload a build's binaries to pkg.updawg.net and make it a channel's
# self-update release.
#
#   publish-bin.sh beta|stable VERSION DIR
#
# DIR holds <target>/updawgd and <target>/updawgctl for both targets. As the
# bucket has it:
#
#   bin/pool/<version>/<target>/<name>   added once, never replaced (IAM)
#   bin/<channel>.json                   the channel's manifest, signed by the
#                                        release key; replaced on each run
#
# Pool first, then the manifest, so the manifest never names a missing file.
#
# Needs: BUCKET, SIGN (updawg-release-sign), UPDAWG_RELEASE_KEY and
# GOOGLE_OAUTH_ACCESS_TOKEN for it, gcloud.
set -eu
channel=${1:?channel}
version=${2:?version}
dir=${3:?directory}
case $channel in
  beta | stable) ;;
  *) echo "publish-bin.sh: the channel is beta or stable, not $channel" >&2; exit 2 ;;
esac
printf '%s' "$version" | grep -Eq '^[0-9][0-9A-Za-z.+~-]*$' ||
  { echo "publish-bin.sh: not a version: $version" >&2; exit 2; }
: "${BUCKET:?}" "${SIGN:?}" "${UPDAWG_RELEASE_KEY:?}"
BASE_URL=${BASE_URL:-https://pkg.updawg.net}
gs="gs://$BUCKET"
IMMUTABLE="public, max-age=31536000, immutable"
md5() { openssl md5 -binary "$1" | base64; }

for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  for name in updawgd updawgctl; do
    f="$dir/$target/$name"
    [ -f "$f" ] || { echo "publish-bin.sh: missing $f" >&2; exit 2; }
    object="bin/pool/$version/$target/$name"
    gcloud storage cp --no-clobber --cache-control="$IMMUTABLE" "$f" "$gs/$object"
    there=$(gcloud storage objects describe "$gs/$object" --format='value(md5_hash)')
    if [ "$there" != "$(md5 "$f")" ]; then
      echo "publish-bin.sh: $object is already published and is a different file" >&2
      exit 1
    fi
  done
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
"$SIGN" manifest --channel "$channel" --version "$version" --dir "$dir" \
  --base-url "$BASE_URL/bin/pool/$version" > "$work/$channel.json"
cat "$work/$channel.json"
gcloud storage cp --cache-control="no-cache" --content-type=application/json \
  "$work/$channel.json" "$gs/bin/$channel.json"
echo "bin/$channel.json is $version"
