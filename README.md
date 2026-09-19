# updawg-agent

The Updawg agent: the `updawgd` daemon and `updawgctl` CLI that run on customer
Linux hosts, plus the shared `updawg-protocol` wire-types crate.

See [PLAN.md](./PLAN.md) for what this repo is and how it fits with the rest of
Updawg.

> **Status: early.** Configuration, durable local state, the scheduler,
> enrollment, the authenticated transport and the fact collectors are real
> (DAWG-19, DAWG-29, DAWG-30, DAWG-31, DAWG-33). A host can generate its key,
> exchange a CSR for a certificate, pin its organization's signing keys, talk to
> the gateway over mTLS with its certificate renewing itself, and read what it
> is and what is true about it. The package backends and executors are stubs
> that return "not implemented yet" and name the ticket that fills them in, so
> `updawgd` starts, reads the host, renews, schedules, and says plainly that it
> is not checking in yet.

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
| `agent.key` | The host's Ed25519 private key, mode `0600`. Generated locally and never sent anywhere. A loose mode is tightened on load and logged. |
| `identity.json` | Host id, client certificate, and the organization signing keys **pinned at enrollment**. Every job is verified against these, not against whatever the server currently claims. |
| `seen-jobs.json` | Replay protection. A job must not run twice, and "twice" includes "once before a reboot and once after". Bounded ring, so it cannot grow without limit. |
| `pending-reboot.json` | A job that reboots the machine cannot report its own result. The agent writes down what it was doing, reboots, and finishes the report on the way back up. |

Every write is atomic — temp file, fsync, rename. A half-written identity file
on a host that lost power mid-write is worse than no file at all: the agent
would refuse to start rather than simply re-enrolling.

## Enrollment

`updawgctl enroll --token ...` generates a key pair, sends a CSR to
`POST /agent/v1/enroll`, and writes down what came back. The order is the point:
nothing is written until the response has been validated, so

- a failed enrollment leaves a working host working, and
- a response that could never verify a job — a malformed organization key, no
  active key, an empty CA chain — is refused rather than pinned and discovered
  at the first job.

Re-enrolling is deliberately not automatic. An enrolled host reports that and
does nothing; `--force` replaces the identity. If the organization signing key
on offer is not the one this host pinned, `--force` is *still* refused and names
both fingerprints — following a key change because the server asked is exactly
what pinning exists to prevent. `--accept-new-org-key` is how an operator says
they know about the rotation.

What got pinned is printed by `enroll` and by `updawgctl status`, so it can be
compared against the portal. Pinning nobody can check is pinning nobody trusts.

## Transport and certificate renewal

Every request after enrollment presents the client certificate. They last thirty
days, so a host that is decommissioned or revoked leaves the fleet on its own
rather than having to be chased.

That only works if renewal does. Renewal begins when a third of the
certificate's life remains — ten days for a thirty-day certificate — which
leaves room for a host to be powered off for a week, a gateway outage, and a
retry schedule, all at once. The window is a *fraction* of the lifetime rather
than a fixed number of days, so changing certificate duration on the server
cannot silently leave every agent renewing too late.

Each host takes a stable offset into that window, derived from its certificate
serial. A fleet enrolled in one afternoon would otherwise all renew in the same
hour a month later, and deriving the offset from a clock would give a host that
keeps restarting a new renewal time on every boot.

The private key is **not** rotated at renewal. Replacing it means two files that
must both land or neither, and a crash between them leaves a host that can
neither authenticate nor renew. The certificate is the short-lived credential;
keeping the key makes replacing it one atomic write.

Three failures worth telling apart, because they need different actions:

| What happened | What the agent says |
|---|---|
| The gateway returned 401 or 403 | The certificate was rejected, with its subject and serial, and the `--force` re-enrollment that fixes it |
| The local certificate has expired | Says so directly — that failure shows up as a TLS handshake error, not a status code, so guessing from alert strings is not the answer |
| Anything else | The whole error source chain, because `reqwest`'s own message is only the URL you already typed |

## What the agent collects

Platform facts — distro, version, codename, kernel, architecture,
virtualization, machine id, hostname, FQDN — plus volatile state on every
check-in: boot id, uptime, whether a reboot is pending, services running against
replaced libraries, load, memory and root filesystem free space.

It never collects file contents, environment variables, process arguments, user
data or credentials. That list is exhaustive and `updawgctl --print-inventory`
exists to make it checkable.

**Package questions belong to the backends, not here.** Installed packages,
available updates, configured repositories and held packages are all
`PackageBackend`'s. "Held" in particular looks like host state but is not: it
means `apt-mark showhold` on one family and `dnf versionlock` on another, and
splitting that across two crates would mean maintaining it twice.

### "I could not tell" is a third answer

Whether a reboot is pending is the most consequential thing collected, and the
mechanisms are uneven: Debian and Ubuntu drop a flag file and usually have
`needrestart`; Red Hat wants `needs-restarting` from `dnf-utils`, which is often
not installed. A host where the question cannot be answered is not a host where
the answer is no, so the collector returns `Yes`, `No` or `Unknown`, and
`Unknown` survives all the way up rather than being flattened into `false`
somewhere quiet.

Where `needrestart` is present its verdict beats the flag file, because it
computes the answer instead of trusting a hook to have written one — a kernel
upgraded by something that skipped the hook still shows up. A flag file that
does exist wins over everything: the system has already said it wants a reboot.

### Collecting from a machine you are not on

Every collector reads under a root that tests redirect, so the suite covers
Ubuntu, Debian, Red Hat-family and Amazon Linux from one machine that is none of
them. A fixture root never shells out — otherwise a test on a laptop reports the
laptop and passes while proving nothing.

The parsers are additionally tested against output captured from live hosts, not
only hand-written fixtures: real `needrestart`, `df` and `/proc/meminfo` output
carries fields and column widths that invented examples make suspiciously
uniform.

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
