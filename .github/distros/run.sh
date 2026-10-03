#!/bin/sh
# The distro matrix (DAWG-40), on one runner: one fake gateway, then the real
# agent in a container of each distribution at once — enrolled with
# updawgctl, then updawgd until the gateway has its first inventory — then
# what the gateway recorded for each, checked.
#
#   .github/distros/run.sh <image> <expected os-release ID> [<image> <ID> ...]
#
# One job rather than one per distribution: each check is half a minute of
# work, and twelve jobs held twelve runner slots, which is what starved main's
# release jobs ("not acquired by Runner"). The gateway already keys what it
# records by enrollment token, so one serves them all.
#
# Expects mbin/updawgd and mbin/updawgctl (x86_64 musl, built with
# insecure-extra-root) and mbin/fake_gateway.
set -eu
[ $# -ge 2 ] && [ $(($# % 2)) -eq 0 ] || { echo "usage: $0 <image> <id> [<image> <id> ...]" >&2; exit 2; }

gw=$PWD/gw
rm -rf "$gw" && mkdir -p "$gw"
chmod 0755 mbin/*

token_of() { echo "$1" | tr -c 'a-zA-Z0-9\n' 'x'; }

containers=
mbin/fake_gateway "$gw" 2> "$gw/gateway.log" &
gateway=$!
trap 'kill $gateway 2>/dev/null || true; [ -z "$containers" ] || docker rm -f $containers >/dev/null 2>&1 || true' EXIT
for _ in $(seq 50); do [ -s "$gw/ca.pem" ] && break; sleep 0.1; done

# In each container: a machine id if the image has none (a container image
# usually doesn't, and enrollment sends it), an observe-mode agent.toml, the
# enrollment, then the daemon in the foreground.
# Split again below with set -- $pairs: image names have no spaces.
pairs="$*"
while [ $# -gt 0 ]; do
  image=$1 token=$(token_of "$1")
  shift 2
  containers="$containers agent-$token"
  docker run -d --name "agent-$token" --add-host gateway.test:host-gateway \
    -v "$PWD/mbin:/u:ro" -v "$gw:/gw:ro" -e TOKEN="$token" "$image" sh -c '
      set -e
      [ -s /etc/machine-id ] || cat /proc/sys/kernel/random/uuid | tr -d - > /etc/machine-id
      mkdir -p /etc/updawg
      printf "server = \"https://gateway.test:8443\"\nmode = \"observe\"\n" > /etc/updawg/agent.toml
      /u/updawgctl --insecure-extra-root /gw/ca.pem enroll --token "$TOKEN"
      exec /u/updawgd --insecure-extra-root /gw/ca.pem
    ' >/dev/null
done

# Until every host's inventory is in, or one has stopped, or six minutes
# (dnf fetches its metadata first, which is most of it, and here six
# distributions fetch at once).
has_inventory() {
  [ -s "$gw/results.json" ] && jq -e --arg t "$1" '.[$t].inventory' "$gw/results.json" >/dev/null
}
for _ in $(seq 360); do
  waiting=
  # shellcheck disable=SC2086
  set -- $pairs
  while [ $# -gt 0 ]; do
    token=$(token_of "$1")
    shift 2
    has_inventory "$token" && continue
    [ "$(docker inspect -f '{{.State.Running}}' "agent-$token")" = true ] && waiting=yes
  done
  [ -n "$waiting" ] || break
  sleep 1
done

failed=
# shellcheck disable=SC2086
set -- $pairs
while [ $# -gt 0 ]; do
  image=$1 want=$2 token=$(token_of "$1")
  shift 2
  echo "::group::$image"
  echo "--- the agent"; docker logs "agent-$token" 2>&1 | tail -40
  echo "--- the gateway recorded"; jq --arg t "$token" '.[$t]' "$gw/results.json" 2>/dev/null || cat "$gw/gateway.log"
  echo "::endgroup::"
  if ! has_inventory "$token"; then
    echo "FAIL: no inventory from $image"
    failed="$failed $image"
    continue
  fi
  case "$want" in debian | ubuntu) ecosystem=deb ;; *) ecosystem=rpm ;; esac
  jq -e -r --arg t "$token" --arg want "$want" --arg image "$image" --arg ecosystem "$ecosystem" '
    .[$t] as $h
    | if ($h.facts.distro != $want) then error("\($image): enrolled as distro \($h.facts.distro), not \($want)")
      elif ($h.checkins < 1) then error("\($image): never checked in with its certificate")
      elif ($h.inventory.kind != "full") then error("\($image): the first inventory was not a full one")
      elif ($h.inventory.packages < 20) then error("\($image): only \($h.inventory.packages) packages")
      # Not the repository count: apt in a fresh container has no package lists,
      # so none, and that says nothing about the agent.
      elif ($h.inventory.facts.ecosystem != $ecosystem) then error("\($image): reported \($h.inventory.facts.ecosystem) packages, not \($ecosystem)")
      elif (($h.inventory.sample.name // "") == "" or ($h.inventory.sample.version // "") == "") then error("\($image): a package with no name or version")
      else "ok: \($image) enrolled as \($h.host_id) (\($h.facts.distro) \($h.facts.version)), checked in \($h.checkins)x, inventory of \($h.inventory.packages) \($ecosystem) packages, \($h.inventory.repositories) repositories"
      end' "$gw/results.json" || failed="$failed $image"
done

[ -z "$failed" ] || { echo "FAILED:$failed"; exit 1; }
