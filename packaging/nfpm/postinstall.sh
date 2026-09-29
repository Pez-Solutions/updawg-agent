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

systemctl daemon-reload || true
if [ -n "$upgrade" ]; then
  # Running already: pick up the new binary. Stopped on purpose: stay stopped.
  systemctl try-restart updawgd.service || true
else
  systemctl enable updawgd.service >/dev/null 2>&1 || true
  systemctl start updawgd.service || true
  echo "updawg-agent: updawgd is running. Enroll this host with: sudo updawgctl enroll --token enr_..."
fi
