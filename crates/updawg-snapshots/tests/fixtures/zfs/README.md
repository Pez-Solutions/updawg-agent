Captured from OpenZFS 2.2.2 (zfsutils-linux, kmod 2.4.1) on Ubuntu 24.04,
2026-09-28, against a file-backed pool laid out as Ubuntu lays out a root:
`tank/ROOT/ubuntu` mounted at `/srv/zroot/sys`, with `var` and `var/lib` as
child datasets.

- `findmnt.txt`: `findmnt -n -o SOURCE,FSTYPE /srv/zroot/sys`
- `list.txt`: `zfs list -H -p -t snapshot -d 1 -o name,creation,updawg:job -s creation tank/ROOT/ubuntu`,
  with the agent's snapshot and an administrator's (`-` for the property)
- `list-recursive.txt`: the same with `-r -o name,updawg:job`
- `diff-root.txt`, `diff-varlib.txt`: `zfs diff -H <dataset>@updawg-job_x`
  after an "install" changed a file, removed one, added one, and added a
  kernel's modules directory
- `available.txt`: `zfs get -H -p -o value available tank/ROOT/ubuntu`

`tests/zfs_live.rs` runs the same commands against a real pool.
