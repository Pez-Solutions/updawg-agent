Captured from snapper 0.10.6 (libsnapper 7.2.0) on Debian 13, with
`LC_ALL=C snapper --jsonout -c data …` against a configuration on a
loop-mounted btrfs, on 2026-09-28. Not hand-written: `list.json` is the
agent's snapshot (userdata `updawg=job_x`), an administrator's (`admin's
own`, no userdata) and snapper's number 0, the live filesystem.
`tests/snapper_live.rs` runs the same commands for real.
