#!/bin/sh
# Install the Updawg agent and enroll this host. Served at https://get.updawg.net.
#
#   curl -fsSL https://get.updawg.net | sudo UPDAWG_TOKEN=enr_... sh
#
# To read it first:
#   curl -fsSL https://get.updawg.net | less
#
# Checks the OS and CPU are supported, adds the signed apt or dnf repository
# from https://pkg.updawg.net, installs the updawg-agent package and enrolls
# if UPDAWG_TOKEN is set. After that the agent is updated by the package
# manager like everything else. An existing /etc/updawg/agent.toml is kept.
#
# Optional:
#   UPDAWG_CHANNEL=beta     every build that passes tests (default: stable)
#   UPDAWG_SERVER=https://agents.us.updawg.net
#                           a different region's gateway
#   UPDAWG_ORG_KEY=<key>    your organization's own signing key (from
#                           `updawgctl keygen`), written to agent.toml as
#                           trusted_org_key before enrolling
#
# Manual install steps: https://docs.updawg.net/install/
set -eu

PKG="${UPDAWG_PKG:-https://pkg.updawg.net}"
CHANNEL="${UPDAWG_CHANNEL:-stable}"

say() { printf 'updawg: %s\n' "$*"; }
fail() { printf 'updawg: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- platform
[ "$(uname -s)" = Linux ] || fail "Linux only; this is $(uname -s)."
[ "$(id -u)" -eq 0 ] || fail "run as root: curl -fsSL https://get.updawg.net | sudo UPDAWG_TOKEN=... sh"

case "$(uname -m)" in
  x86_64 | amd64 | aarch64 | arm64) ;;
  *) fail "no agent build for $(uname -m) (only x86_64 and aarch64 are). Nothing was changed." ;;
esac
case "$CHANNEL" in
  stable | beta) ;;
  *) fail "UPDAWG_CHANNEL is stable or beta, not $CHANNEL. Nothing was changed." ;;
esac
ORG_KEY="${UPDAWG_ORG_KEY:-}"
case "$ORG_KEY" in
  *[!A-Za-z0-9+/=:]*) fail "UPDAWG_ORG_KEY is not a public key (base64, as updawgctl keygen prints it). Nothing was changed." ;;
esac

[ -r /etc/os-release ] || fail "no /etc/os-release, so the distribution cannot be identified. Nothing was changed."
# shellcheck source=/dev/null
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
  *" debian "* | *" ubuntu "*) family=apt ;;
  *" rhel "* | *" fedora "* | *" centos "*) family=dnf ;;
  *) fail "${PRETTY_NAME:-this distribution} is not supported (Debian, Ubuntu and the RHEL family are). Nothing was changed." ;;
esac
[ "$family" = apt ] || command -v dnf >/dev/null 2>&1 \
  || fail "the RHEL family's agent package installs with dnf, and there is no dnf. Nothing was changed."

command -v systemctl >/dev/null 2>&1 || fail "the agent runs as a systemd service, and there is no systemctl. Nothing was changed."

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q --https-only -O "$2" "$1"; }
else
  fail "neither curl nor wget is installed. Nothing was changed."
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fetch "$PKG/updawg.asc" "$tmp/updawg.asc" || fail "could not download $PKG/updawg.asc. Nothing was changed."

# -------------------------------------------------------------- repository
# The key is only trusted for this repository.
say "adding the $CHANNEL channel of $PKG for ${PRETTY_NAME:-Linux}"
if [ "$family" = apt ]; then
  install -d -m 0755 /etc/apt/keyrings
  install -m 0644 "$tmp/updawg.asc" /etc/apt/keyrings/updawg.asc
  echo "deb [signed-by=/etc/apt/keyrings/updawg.asc] $PKG/apt $CHANNEL main" > /etc/apt/sources.list.d/updawg.list
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq -o Dir::Etc::sourcelist=sources.list.d/updawg.list \
    -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
  # confold keeps an agent.toml from an older install.sh.
  apt-get install -y -qq -o Dpkg::Options::=--force-confold updawg-agent
else
  rpm --import "$tmp/updawg.asc"
  cat > /etc/yum.repos.d/updawg.repo <<REPO
[updawg]
name=Updawg ($CHANNEL)
baseurl=$PKG/rpm/$CHANNEL
enabled=1
repo_gpgcheck=1
gpgcheck=0
gpgkey=$PKG/updawg.asc
REPO
  dnf install -y -q updawg-agent
fi
say "installed $(updawgctl --version)"

# Older install.sh versions put a unit in /etc that overrides the package's
# and runs /usr/local/bin/updawgd. Remove those; identity and config stay.
if grep -qs /usr/local/bin/updawgd /etc/systemd/system/updawgd.service; then
  rm -f /etc/systemd/system/updawgd.service /usr/local/bin/updawgd /usr/local/bin/updawgctl
  say "replaced the agent an earlier install.sh put in /usr/local/bin"
fi

# --------------------------------------------------------- trusted org key
# Must happen before enrolling, which pins the key. A host that already
# trusts a different key is left alone.
if [ -n "$ORG_KEY" ]; then
  conf=/etc/updawg/agent.toml
  have=$(sed -n 's/^trusted_org_key *= *"\(.*\)"/\1/p' "$conf")
  if [ -z "$have" ]; then
    # Prepend so it isn't inside a [table].
    { printf 'trusted_org_key = "%s"\n' "$ORG_KEY"; cat "$conf"; } > "$tmp/agent.toml"
    cat "$tmp/agent.toml" > "$conf"
    say "this host trusts only your organization's key from now on (trusted_org_key in $conf)"
  elif [ "$have" != "$ORG_KEY" ]; then
    fail "$conf already trusts a different organization key; not changing it. Edit trusted_org_key by hand if that is intended."
  fi
fi

# ------------------------------------------------------------------ enroll
# Pass the token via the environment; arguments are visible in `ps`.
if [ -n "${UPDAWG_TOKEN:-}" ]; then
  UPDAWG_TOKEN="$UPDAWG_TOKEN" updawgctl enroll
else
  say "no UPDAWG_TOKEN, so not enrolling. Later: sudo updawgctl enroll --token enr_..."
fi

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable updawgd.service >/dev/null 2>&1
  # restart so it picks up the new identity and binary.
  systemctl restart updawgd.service
  say "updawgd is running. Check it with: sudo updawgctl status"
fi
