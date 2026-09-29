#!/bin/sh
# After removing updawg-agent. One script for both formats:
#   deb: remove | purge | upgrade <new version> | ...
#   rpm: 0 on a removal, 1 on an upgrade
set -e

case "$1" in
  remove | 0 | purge) ;;
  *) exit 0 ;;
esac

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi

# Only a deb purge takes the host's identity with it: its key, certificate
# and pinned signing keys. A removal keeps it, so reinstalling needs no new
# enrolment, and rpm has no purge.
if [ "$1" = purge ]; then
  rm -rf /var/lib/updawg
  rmdir /etc/updawg 2>/dev/null || true
fi
