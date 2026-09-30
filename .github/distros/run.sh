#!/bin/sh
# One distribution in the matrix (DAWG-40), on the runner: the fake gateway,
# then the real agent in a container of that distribution — enrolled with
# updawgctl, then updawgd until the gateway has its first inventory — then
# what the gateway recorded, checked.
#
#   .github/distros/run.sh <image> <expected os-release ID>
#
# Expects mbin/updawgd and mbin/updawgctl (x86_64 musl, built with
# insecure-extra-root) and mbin/fake_gateway.
set -eu
image=$1
want=$2
token=$(echo "$image" | tr -c 'a-zA-Z0-9\n' 'x')
gw=$PWD/gw
rm -rf "$gw" && mkdir -p "$gw"
chmod 0755 mbin/*

mbin/fake_gateway "$gw" 2> "$gw/gateway.log" &
gateway=$!
trap 'kill $gateway 2>/dev/null || true; docker rm -f "agent-$token" >/dev/null 2>&1 || true' EXIT
for _ in $(seq 50); do [ -s "$gw/ca.pem" ] && break; sleep 0.1; done

# In the container: a machine id if the image has none (a container image
# usually doesn't, and enrollment sends it), an observe-mode agent.toml, the
# enrollment, then the daemon in the foreground.
docker run -d --name "agent-$token" --add-host gateway.test:host-gateway \
  -v "$PWD/mbin:/u:ro" -v "$gw:/gw:ro" -e TOKEN="$token" "$image" sh -c '
    set -e
    [ -s /etc/machine-id ] || cat /proc/sys/kernel/random/uuid | tr -d - > /etc/machine-id
    mkdir -p /etc/updawg
    printf "server = \"https://gateway.test:8443\"\nmode = \"observe\"\n" > /etc/updawg/agent.toml
    /u/updawgctl --insecure-extra-root /gw/ca.pem enroll --token "$TOKEN"
    exec /u/updawgd --insecure-extra-root /gw/ca.pem
  ' >/dev/null

# Until the gateway has this host's inventory, or four minutes (dnf fetches
# its metadata first, which is most of that).
ok=
for _ in $(seq 240); do
  if [ -s "$gw/results.json" ] && jq -e --arg t "$token" '.[$t].inventory' "$gw/results.json" >/dev/null; then
    ok=yes
    break
  fi
  if [ "$(docker inspect -f '{{.State.Running}}' "agent-$token")" != true ]; then
    break
  fi
  sleep 1
done
echo "--- the agent"; docker logs "agent-$token" 2>&1 | tail -40
echo "--- the gateway recorded"; jq --arg t "$token" '.[$t]' "$gw/results.json" 2>/dev/null || cat "$gw/gateway.log"
[ -n "$ok" ] || { echo "FAIL: no inventory from $image"; exit 1; }

case "$want" in debian | ubuntu) ecosystem=deb ;; *) ecosystem=rpm ;; esac
jq -e -r --arg t "$token" --arg want "$want" --arg image "$image" --arg ecosystem "$ecosystem" '
  .[$t] as $h
  | if ($h.facts.distro != $want) then error("enrolled as distro \($h.facts.distro), not \($want)")
    elif ($h.checkins < 1) then error("never checked in with its certificate")
    elif ($h.inventory.kind != "full") then error("the first inventory was not a full one")
    elif ($h.inventory.packages < 20) then error("only \($h.inventory.packages) packages")
    # Not the repository count: apt in a fresh container has no package lists,
    # so none, and that says nothing about the agent.
    elif ($h.inventory.facts.ecosystem != $ecosystem) then error("reported \($h.inventory.facts.ecosystem) packages, not \($ecosystem)")
    elif (($h.inventory.sample.name // "") == "" or ($h.inventory.sample.version // "") == "") then error("a package with no name or version")
    else "ok: \($image) enrolled as \($h.host_id) (\($h.facts.distro) \($h.facts.version)), checked in \($h.checkins)x, inventory of \($h.inventory.packages) \($ecosystem) packages, \($h.inventory.repositories) repositories"
    end' "$gw/results.json"
