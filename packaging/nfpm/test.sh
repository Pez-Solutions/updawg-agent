#!/bin/sh
# The packages' whole life on one distribution, in a container of it, as root:
# install, a local edit to agent.toml, an upgrade, a removal and (deb) a purge.
#
#   docker run --rm -v "$PWD:/w" -w /w debian:13 \
#     sh packaging/nfpm/test.sh out/updawg-agent_*_amd64.deb next/updawg-agent_*_amd64.deb
#
# There is no systemd in a container, so the scripts' systemd half is not
# run here; the rest of them is: what they do on each argument dpkg and rpm
# pass them, and that they do not fail an install, an upgrade or a removal.
set -eu

old=$1
new=$2
case "$old" in
  *.deb) fmt=deb ;;
  *.rpm) fmt=rpm ;;
  *) echo "neither a .deb nor an .rpm: $old" >&2; exit 2 ;;
esac

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
install_pkg() {
  if [ $fmt = deb ]; then dpkg -i "$1" </dev/null; else rpm -Uvh "$1"; fi
}
version() {
  if [ $fmt = deb ]; then dpkg-query -W -f '${Version}' updawg-agent
  else rpm -q --qf '%{VERSION}-%{RELEASE}' updawg-agent; fi
}
conf=/etc/updawg/agent.toml

install_pkg "$old"
[ -x /usr/bin/updawgd ] && [ -x /usr/bin/updawgctl ] || fail "binaries not installed"
/usr/bin/updawgctl --version >/dev/null || fail "updawgctl does not run"
grep -q '^ExecStart=/usr/bin/updawgd$' /usr/lib/systemd/system/updawgd.service \
  || fail "the unit does not run /usr/bin/updawgd"
[ "$(cat "$conf")" = "$(cat packaging/agent.toml)" ] || fail "$conf is not the default"
ok "installed $(version)"

echo '# edited on this host' >> "$conf"
mkdir -p /var/lib/updawg && echo identity > /var/lib/updawg/marker
first=$(version)

install_pkg "$new"
[ "$(version)" != "$first" ] || fail "the upgrade did not change the version"
grep -q '^# edited on this host$' "$conf" || fail "the upgrade replaced the edited $conf"
[ ! -e "$conf.dpkg-new" ] && [ ! -e "$conf.rpmnew" ] || fail "an unchanged default was set aside as new"
[ -f /var/lib/updawg/marker ] || fail "the upgrade touched /var/lib/updawg"
ok "upgraded to $(version), the edit kept"

if [ $fmt = deb ]; then dpkg -r updawg-agent; else rpm -e updawg-agent; fi
[ ! -e /usr/bin/updawgd ] && [ ! -e /usr/bin/updawgctl ] || fail "binaries left behind"
[ ! -e /usr/lib/systemd/system/updawgd.service ] || fail "the unit left behind"
[ -f /var/lib/updawg/marker ] || fail "a removal took the host's identity"
if [ $fmt = deb ]; then
  grep -q '^# edited on this host$' "$conf" || fail "a removal took the edited $conf"
else
  grep -q '^# edited on this host$' "$conf.rpmsave" || fail "rpm did not keep the edited $conf as .rpmsave"
fi
ok "removed; the identity and the edited configuration kept"

if [ $fmt = deb ]; then
  dpkg -P updawg-agent
  [ ! -e /etc/updawg ] || fail "a purge left /etc/updawg"
  [ ! -e /var/lib/updawg ] || fail "a purge left /var/lib/updawg"
  ok "purged: nothing left"
fi
