Captured from LVM 2.03.16 on Ubuntu 24.04, 2026-09-28, against a thin pool
on a loop device: `testvg/pool`, a thin volume `testvg/root` with XFS
mounted at `/srv/lvroot`, the agent's snapshot `updawg_job_x` (tags
`updawg`, `updawg_job_x`) and an administrator's `admins_own`.

- `findmnt.txt`: `findmnt -n -o SOURCE,FSTYPE /srv/lvroot`
- `lvs-all.json`: `lvs --reportformat json -o vg_name,lv_name,segtype,pool_lv,origin,lv_tags,lv_dm_path,lv_time,lv_size,data_percent --units b --nosuffix`
- `lvs-ours.json`: `lvs --reportformat json -o vg_name,lv_name,origin,lv_tags,lv_time,lv_attr -S lv_tags=updawg testvg`
- `pool.json`: `lvs --reportformat json --units b --nosuffix -o lv_size,data_percent,metadata_percent testvg/pool`
- `merge-deferred.txt`: `lvconvert --merge testvg/updawg_job_x` with the
  origin mounted, as when rolling back a running root.

On the same host, files written into the snapshot (activated with `-K`,
mounted with `nouuid`) before a deferred merge were present on the origin
after it. The agent relies on this to carry its state across a rollback.
`tests/lvm_live.rs` runs the same steps against a real thin pool.
