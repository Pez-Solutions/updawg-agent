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
# If you would rather not pipe anything to a shell: the signed apt and dnf
# repositories at https://pkg.updawg.net, or these same files from
# https://get.updawg.net/agent/latest/ checked against SHA256SUMS there.
# Both are at https://docs.updawg.net/install/.
set -eu

BASE="${UPDAWG_BASE:-https://get.updawg.net}/agent/latest"
BIN=/usr/local/bin
CONF=/etc/updawg/agent.toml

say() { printf 'updawg: %s\n' "$*"; }
fail() { printf 'updawg: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- platform
[ "$(uname -s)" = Linux ] || fail "Linux only; this is $(uname -s)."
[ "$(id -u)" -eq 0 ] || fail "run as root: curl -fsSL https://get.updawg.net | sudo UPDAWG_TOKEN=... sh"

# x86_64's binaries at the top, aarch64's in aarch64/ (DAWG-41).
case "$(uname -m)" in
  x86_64 | amd64) dir= ;;
  aarch64 | arm64) dir=aarch64/ ;;
  *) fail "no agent build for $(uname -m) — only x86_64 and aarch64. Nothing was changed." ;;
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
mkdir -p "$tmp/aarch64"
for f in SHA256SUMS "${dir}updawgd" "${dir}updawgctl" updawgd.service; do
  fetch "$BASE/$f" "$tmp/$f" || fail "could not download $BASE/$f. Nothing was changed."
done

# Every file, checked before any of them is installed. `--ignore-missing`
# because SHA256SUMS also lists install.sh, which this is.
(cd "$tmp" && sha256sum --check --ignore-missing --quiet SHA256SUMS) \
  || fail "the download does not match SHA256SUMS. Nothing was changed."

# ----------------------------------------------------------------- install
install -m 0755 "$tmp/${dir}updawgd" "$tmp/${dir}updawgctl" "$BIN/"
install -m 0644 "$tmp/updawgd.service" /etc/systemd/system/updawgd.service
say "installed $("$BIN/updawgctl" --version)"

if [ -e "$CONF" ]; then
  say "keeping the existing $CONF"
else
  install -d -m 0755 /etc/updawg
  cat > "$CONF" <<'TOML'
# Updawg agent configuration. Your edits are kept: neither install.sh nor a
# package upgrade ever rewrites this file.
#
# Local configuration always wins: the server can narrow what this agent does,
# never widen it past this file.
#
# `managed` runs jobs your organization approved and signed, but only the
# kinds allowed below. For a host that must only report, set mode = "observe".
server = "https://agents.updawg.net"
mode = "managed"

[permissions]
# Every kind of job. Each one still has to be approved and signed by your
# organization first. Take a kind out, or add it to deny, to keep this host
# from ever doing it whatever is approved: "reboot" for a host nobody may
# restart, "dist_upgrade" for one that stays on its release.
allow = ["refresh", "preflight", "apply_patch", "dist_upgrade", "reboot", "snapshot", "self_update"]
deny  = []
TOML
  say "wrote $CONF (managed: runs any approved job, reboots included)"
fi

# ------------------------------------------------------------------ enroll
# The token reaches updawgctl through its environment, which only root can read,
# rather than its arguments, which every user on the host can see in `ps`.
if [ -n "${UPDAWG_TOKEN:-}" ]; then
  UPDAWG_TOKEN="$UPDAWG_TOKEN" "$BIN/updawgctl" enroll
else
  say "no UPDAWG_TOKEN, so not enrolling. Later: sudo $BIN/updawgctl enroll --token enr_..."
fi

systemctl daemon-reload
systemctl enable updawgd.service >/dev/null 2>&1
# restart, not start: on a re-run it picks up the binary just installed.
systemctl restart updawgd.service
# The full path: sudo's secure_path leaves /usr/local/bin out on the RHEL family.
say "updawgd is running. Check it with: sudo $BIN/updawgctl status"
