#!/bin/sh
# Install the Updawg agent and enroll this host. Served at https://get.updawg.net.
#
#   curl -fsSL https://get.updawg.net | sudo UPDAWG_TOKEN=enr_... sh
#
# It is piped into a root shell, so it is short enough to read first:
#   curl -fsSL https://get.updawg.net | less
#
# What it does: checks this is a supported Linux on a supported CPU, downloads
# updawgd and updawgctl and checks them against the published SHA256SUMS,
# installs them to /usr/local/bin, writes /etc/updawg/agent.toml only if there
# is none, installs and starts updawgd.service, and enrolls if UPDAWG_TOKEN is
# set. It never overwrites an existing agent.toml: local config always wins.
#
# The manual path, if you would rather not pipe anything to a shell: fetch the
# same files from https://get.updawg.net/agent/latest/, verify them against
# SHA256SUMS there, and run `updawgctl enroll` yourself.
#
# ⚠️ Interim (DAWG-44): the design adds a signed apt/yum repository here instead
# of downloading binaries. That repository does not exist yet (DAWG-42).
set -eu

BASE="${UPDAWG_BASE:-https://get.updawg.net}/agent/latest"
BIN=/usr/local/bin
CONF=/etc/updawg/agent.toml

say() { printf 'updawg: %s\n' "$*"; }
fail() { printf 'updawg: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- platform
[ "$(uname -s)" = Linux ] || fail "Linux only; this is $(uname -s)."
[ "$(id -u)" -eq 0 ] || fail "run as root: curl -fsSL https://get.updawg.net | sudo UPDAWG_TOKEN=... sh"

case "$(uname -m)" in
  x86_64 | amd64) ;;
  *) fail "no agent build for $(uname -m) yet — only x86_64. Nothing was changed." ;;
esac

[ -r /etc/os-release ] || fail "no /etc/os-release, so the distribution cannot be identified. Nothing was changed."
# shellcheck source=/dev/null
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
  *" debian "* | *" ubuntu "* | *" rhel "* | *" fedora "* | *" centos "*) ;;
  *) fail "${PRETTY_NAME:-this distribution} is not supported — Debian, Ubuntu and the RHEL family are. Nothing was changed." ;;
esac

command -v systemctl >/dev/null 2>&1 || fail "the agent runs as a systemd service, and there is no systemctl. Nothing was changed."
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is needed to check the download. Nothing was changed."

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q --https-only -O "$2" "$1"; }
else
  fail "neither curl nor wget is installed. Nothing was changed."
fi

# ---------------------------------------------------------------- download
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

say "downloading the agent for ${PRETTY_NAME:-Linux} ($(uname -m))"
for f in SHA256SUMS updawgd updawgctl updawgd.service; do
  fetch "$BASE/$f" "$tmp/$f" || fail "could not download $BASE/$f. Nothing was changed."
done

# Every file, checked before any of them is installed. `--ignore-missing`
# because SHA256SUMS also lists install.sh, which this is.
(cd "$tmp" && sha256sum --check --ignore-missing --quiet SHA256SUMS) \
  || fail "the download does not match SHA256SUMS. Nothing was changed."

# ----------------------------------------------------------------- install
install -m 0755 "$tmp/updawgd" "$tmp/updawgctl" "$BIN/"
install -m 0644 "$tmp/updawgd.service" /etc/systemd/system/updawgd.service
say "installed $("$BIN/updawgctl" --version)"

if [ -e "$CONF" ]; then
  say "keeping the existing $CONF"
else
  install -d -m 0755 /etc/updawg
  cat > "$CONF" <<'TOML'
# Updawg agent configuration. Written once by install.sh and never again.
#
# Local configuration always wins: the server can narrow what this agent does,
# never widen it past this file. `observe` reports and changes nothing; see
# https://github.com/Pez-Solutions/updawg-agent for `managed` and permissions.
server = "https://agents.updawg.net"
mode = "observe"
TOML
  say "wrote $CONF (observe mode: reports, changes nothing)"
fi

# ------------------------------------------------------------------ enroll
# The token reaches updawgctl through its environment, which only root can read,
# rather than its arguments, which every user on the host can see in `ps`.
if [ -n "${UPDAWG_TOKEN:-}" ]; then
  UPDAWG_TOKEN="$UPDAWG_TOKEN" "$BIN/updawgctl" enroll
else
  say "no UPDAWG_TOKEN, so not enrolling. Later: sudo updawgctl enroll --token enr_..."
fi

systemctl daemon-reload
systemctl enable updawgd.service >/dev/null 2>&1
# restart, not start: on a re-run it picks up the binary just installed.
systemctl restart updawgd.service
say "updawgd is running. Check it with: updawgctl status"
