# updawg-agent

The Updawg agent: the `updawgd` daemon and `updawgctl` CLI that run on customer
Linux hosts, plus the shared `updawg-protocol` wire-types crate.

See [PLAN.md](./PLAN.md) for what this repo is and how it fits with the rest of
Updawg.

> **Status: early.** Configuration, durable local state and the scheduler are
> real (DAWG-19, DAWG-29). The collectors, backends, executors and transport are
> stubs that return "not implemented yet" and name the ticket that fills them
> in, so `updawgd` starts, schedules, and says plainly that it is not connected
> to anything yet.

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

cargo run --bin updawgd -- --config ./examples/agent.toml --check-config
cargo run --bin updawgd -- --config ./examples/agent.toml --state-dir /tmp/updawg
cargo run --bin updawgctl -- status
```

## Layout

| Crate | Responsibility |
|---|---|
| `crates/updawg-protocol` | Wire types shared with the server. **Published to crates.io** — this repo owns the Agent API contract. |
| `crates/updawg-crypto` | Signature verification, key pinning, CSR generation |
| `crates/updawg-collectors` | os-release, kernel, reboot state, services, repositories |
| `crates/updawg-backends` | apt and dnf, behind one `PackageBackend` trait |
| `crates/updawg-snapshots` | snapper, ZFS, LVM thin, behind one `SnapshotProvider` trait |
| `crates/updawg-executor` | Job handlers and health checks |
| `crates/updawg-agent-core` | Scheduler, transport, local state, config |
| `bin/updawgd` | The daemon |
| `bin/updawgctl` | Local CLI: enroll, status, `--print-inventory` |

## The three rules this code exists to enforce

1. **Pull, never push.** Outbound HTTPS only. No listener, no inbound port, no
   SSH. It works behind NAT and strict egress firewalls.
2. **Closed set of actions.** `JobKind` is a closed enum with no "run this
   script" variant, so full control of the Updawg control plane still cannot run
   arbitrary commands on a customer host. Adding a variant is a security
   decision.
3. **Local config always wins.** The server may narrow what the agent will do
   and can never widen it beyond `/etc/updawg/agent.toml`. This is enforced by
   `Permissions::intersect` and covered by tests that assert the server cannot
   grant a permission the local config withholds.

Permissions also **fail closed**: an empty allow list permits nothing, and `mode`
defaults to `observe`, so a truncated or malformed config leaves the agent
reporting rather than acting.

## Why the backends shell out

Binaries are statically linked against musl for `x86_64` and `aarch64` so one
build runs on every supported distro. That rules out linking `libapt` or
`libdnf`, so the backends drive the package managers through their command-line
tools in machine-readable modes instead. It is a deliberate trade.

## Local state

Durable state lives in `/var/lib/updawg`, mode `0700`. Three things have to
survive a restart, each for a different reason:

| File | Why it must persist |
|---|---|
| `identity.json` | Host id, client certificate, and the organization signing keys **pinned at enrollment**. Every job is verified against these, not against whatever the server currently claims. |
| `seen-jobs.json` | Replay protection. A job must not run twice, and "twice" includes "once before a reboot and once after". Bounded ring, so it cannot grow without limit. |
| `pending-reboot.json` | A job that reboots the machine cannot report its own result. The agent writes down what it was doing, reboots, and finishes the report on the way back up. |

Every write is atomic — temp file, fsync, rename. A half-written identity file
on a host that lost power mid-write is worse than no file at all: the agent
would refuse to start rather than simply re-enrolling.

## Scheduling

Check-in, inventory and metadata refresh run concurrently on their own cadences,
each driven through a trait so the scheduler is testable without a network.

Two behaviours exist because of how this fails at scale:

- **Startup jitter.** A fleet that loses power and comes back together would
  otherwise check in in lockstep forever. Every periodic task waits a fraction
  of its interval before its first run.
- **Backoff on failure.** A gateway having a bad day should not be hit harder by
  every agent in the fleet retrying instantly.

## Logging

`UPDAWG_LOG` controls filtering. When systemd has connected stderr to the
journal it sets `JOURNAL_STREAM`, and the agent then drops its own timestamps
and colour — journald adds a timestamp itself, and printing a second one wrapped
in escape codes helps nobody.
