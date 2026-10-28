Captured from snapper 0.10.6 (libsnapper 7.2.0) on Debian 13, with
`LC_ALL=C snapper --jsonout -c data ...` against a configuration on a
loop-mounted btrfs, on 2026-09-28. `list.json` holds the agent's snapshot
(userdata `updawg=job_x`), an administrator's (`admin's own`, no userdata)
and snapper's number 0, the live filesystem. `tests/snapper_live.rs` runs
the same commands against a real snapper.

`df.txt` is `LC_ALL=C df -P /srv/bt` on the same host.

`status-kernel.txt` is `LC_ALL=C snapper -c five status N..0` on Ubuntu
24.04 (snapper 0.10.6), after a kernel modules directory was created under
`/srv/bt5`.
