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

# install.sh's copy of the unit, in /etc, outranks the package's in /usr/lib
# and runs /usr/local/bin/updawgd. Said rather than removed: it is the
# administrator's file.
if [ -f /etc/systemd/system/updawgd.service ] \
  && grep -q '/usr/local/bin/updawgd' /etc/systemd/system/updawgd.service; then
  echo "updawg-agent: /etc/systemd/system/updawgd.service (from install.sh) overrides this package's unit and runs /usr/local/bin/updawgd." >&2
  echo "updawg-agent: to run the packaged agent, remove it and /usr/local/bin/updawgd and /usr/local/bin/updawgctl, then: systemctl daemon-reload && systemctl restart updawgd" >&2
fi

# Not booted with systemd (a container, a chroot): nothing to start.
[ -d /run/systemd/system ] || exit 0

# Whether updawgd itself is installing this: an apply_updates or a release
# upgrade, run by the agent as its child. Restarting it from here would kill
# the package manager part-way through, and the job with it; the agent
# restarts itself once the job is reported (crates/updawg-agent-core/src/
# restart.rs). Found by walking up the process tree, not by an environment
# variable: the agent running this is the *old* one, which sets nothing.
under_agent() {
  pid=$$
  while [ "$pid" -gt 1 ] 2>/dev/null; do
    [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = updawgd ] && return 0
    # Field 4 of /proc/<pid>/stat is the parent; field 2, the name, is in
    # parentheses and may hold spaces, so cut after its closing one.
    pid=$(sed 's/.*) [A-Za-z] \([0-9]*\).*/\1/' "/proc/$pid/stat" 2>/dev/null) || return 1
  done
  return 1
}

systemctl daemon-reload || true
if [ -n "$upgrade" ]; then
  if under_agent; then
    echo "updawg-agent: upgraded by updawgd itself; it restarts once its job is reported."
  else
    # Running already: pick up the new binary. Stopped on purpose: stay stopped.
    systemctl try-restart updawgd.service || true
  fi
else
  systemctl enable updawgd.service >/dev/null 2>&1 || true
  systemctl start updawgd.service || true
  echo "updawg-agent: updawgd is running. Enroll this host with: sudo updawgctl enroll --token enr_..."
fi
