#!/bin/sh
# After installing or upgrading updawg-agent. One script for both formats:
#   deb: configure [<version upgraded from>]
#   rpm: 1 on an install, 2 on an upgrade
set -e

case "$1" in
  configure) if [ -n "${2:-}" ]; then upgrade=yes; else upgrade=; fi ;;
  1) upgrade= ;;
  2) upgrade=yes ;;
  *) exit 0 ;;
esac

# A unit left in /etc by an older install.sh overrides ours. Warn about it
# but don't delete files in /etc.
if [ -f /etc/systemd/system/updawgd.service ] \
  && grep -q '/usr/local/bin/updawgd' /etc/systemd/system/updawgd.service; then
  echo "updawg-agent: /etc/systemd/system/updawgd.service (from install.sh) overrides this package's unit and runs /usr/local/bin/updawgd." >&2
  echo "updawg-agent: to run the packaged agent, remove it and /usr/local/bin/updawgd and /usr/local/bin/updawgctl, then: systemctl daemon-reload && systemctl restart updawgd" >&2
fi

# No systemd (container, chroot).
[ -d /run/systemd/system ] || exit 0

# If updawgd is our ancestor (it's running a job that upgrades itself), don't
# restart it here or we'd kill the package manager mid-run. The agent restarts
# itself after reporting (see crates/updawg-agent-core/src/restart.rs). We
# check the process tree because the old agent doesn't set any env var.
under_agent() {
  pid=$$
  while [ "$pid" -gt 1 ] 2>/dev/null; do
    [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = updawgd ] && return 0
    # ppid is field 4; field 2 (comm) can contain spaces, so cut after ')'.
    pid=$(sed 's/.*) [A-Za-z] \([0-9]*\).*/\1/' "/proc/$pid/stat" 2>/dev/null) || return 1
  done
  return 1
}

systemctl daemon-reload || true
if [ -n "$upgrade" ]; then
  if under_agent; then
    echo "updawg-agent: upgraded by updawgd itself; it restarts once its job is reported."
  else
    # Restart if running; leave it stopped otherwise.
    systemctl try-restart updawgd.service || true
  fi
else
  systemctl enable updawgd.service >/dev/null 2>&1 || true
  systemctl start updawgd.service || true
  echo "updawg-agent: updawgd is running. Enroll this host with: sudo updawgctl enroll --token enr_..."
fi
