# updawg-agent

The Updawg agent: the `updawgd` daemon and `updawgctl` CLI that run on customer
Linux hosts, plus the shared `updawg-protocol` wire-types crate.

See [PLAN.md](./PLAN.md) for what this repo is and how it fits with the rest of
Updawg.

> **Status: scaffold.** The workspace, crate boundaries and trait surfaces are
> in place (DAWG-19). The collectors, backends, executors and transport are
> stubs that return "not implemented yet" and name the ticket that fills them
> in. It builds, lints and tests clean, so feature work can start in parallel
> across crates.

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

cargo run --bin updawgd -- --config ./examples/agent.toml --check-config
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
