#!/bin/sh
# Before removing updawg-agent. One script for both formats:
#   deb: remove | upgrade <new version> | deconfigure | failed-upgrade
#   rpm: 0 on a removal, 1 on an upgrade (the old package's scripts run last)
set -e

case "$1" in
  remove | 0) ;;
  *) exit 0 ;;
esac

[ -d /run/systemd/system ] || exit 0
systemctl disable --now updawgd.service >/dev/null 2>&1 || true
