# updawg-agent

The Updawg agent: the `updawgd` daemon and `updawgctl` CLI that run on customer
Linux hosts, plus the shared `updawg-protocol` wire-types crate.

See [PLAN.md](./PLAN.md) for what this repo is and how it fits with the rest of
Updawg.

> **Status: the client side is complete.** A host generates its key, exchanges a
> CSR for a certificate, pins its organization's signing keys, reads what it is
> and what is true about it, and checks in over mTLS on a long poll with its
> certificate renewing itself (DAWG-19, DAWG-29, DAWG-30, DAWG-31, DAWG-32,
> DAWG-33).
>
> **There is nothing to talk to yet.** The gateway does not exist, so every one
> of those paths has been exercised against a test gateway and never a real one.
> Jobs that arrive are reported and not run — verifying and executing one is
> DAWG-38 — and the package backends are still stubs that name the ticket that
> fills them in.

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

Permissions also **fail closed**: an empty allow list permits nothing, so a
truncated or malformed config leaves the agent reporting rather than acting.
`mode` defaults to `managed` — an agent is installed to act on what its
organization approves — and `install.sh` writes `managed` with every
permission allowed, `reboot` and `dist_upgrade` included: what a host does is
decided by what its organization approves and signs. Narrow the allow list, or
add to `deny`, for a host that must never reboot or change release, and set
`mode = "observe"` for one that must only report.

## Why the backends shell out

Binaries are statically linked against musl for `x86_64` and `aarch64` so one
build runs on every supported distro. That rules out linking `libapt` or
`libdnf`, so the backends drive the package managers through their command-line
tools in machine-readable modes instead. It is a deliberate trade.

**Machine-readable is the load-bearing word.** Both package managers have a
command a person runs and a command a program runs, and they are not the same
command. `dnf check-update` prints a padded table that wraps a package whose
`name.arch` is too wide for the first column onto two lines, and `dnf repolist`
truncates a repository name to the terminal width — a parser taking three fields
per line drops the first silently, and a name cut off mid-word matches nothing.
So the dnf backend asks `dnf repoquery --qf` and `dnf repolist -v`, which emit
the fields asked for and nothing else. The offline tests still cross-check the
two against each other, because the day they stop agreeing is the day the query
stopped meaning what it used to.

### Security is not in the same place on both families

apt names the pocket a candidate comes from, so an update from `noble-security`
carries its own hint. The RHEL family has no security pocket — a security fix
and a routine rebuild are both published to `baseos` — and keeps the answer in a
separate `updateinfo` database. That is why `security_updates` is a method on
the backend rather than a filter the caller applies: the filter that is right
for apt returns **zero on every RHEL host, for ever**, and nothing anywhere
would look wrong.

The advisory dnf names now travels too, on `AvailableUpdate::advisories`
(DAWG-231): the id, the vendor's severity word unnormalised, and the type. It is
a hint and stays one — Rocky says `Moderate` where Amazon Linux says `Medium`
for the same band, and deciding they are the same is the server's call against a
feed it can re-read. A guess made on the host cannot be corrected later.

### An upgrade that removes something says so

`dnf upgrade` sometimes installs a differently-named package and removes the
original, and `apt` does the same through `Conflicts` and `Replaces`. An
`AvailableUpdate` has one name and two versions, so it can describe an upgrade
and not a replacement — squeezing one in would be a lie with a name and a
version in it. They travel as their own list instead
(`InventoryUpload::removals`, DAWG-232). dnf names what replaces the package;
**apt does not**, which is why the replacement is optional, and which was
settled by building the case in a container rather than by reading the manual.

### Amazon Linux 2023 reports nothing, correctly

AL2023 does deterministic upgrades: `$releasever` is pinned to a dated snapshot,
and `dnf check-update` finds nothing at all until somebody moves it. A fleet of
those hosts is genuinely at zero outstanding updates and will stay there. The
agent does not pass `--releasever=latest` to make the number look more
interesting, because that would report updates the host is not going to install.

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

## Running against a gateway you control

The agent verifies the gateway against the platform trust store, which is the
right default and means it cannot talk to a gateway with a certificate the
platform has never heard of — including one you started yourself. That is what
the `insecure-extra-root` feature is for, and **a release build does not have
it**: with the feature off clap has never heard of `--insecure-extra-root`, so
the binary people install answers `unexpected argument` rather than warning and
complying.

```sh
cargo build --bin updawgd --bin updawgctl \
  --features updawgd/insecure-extra-root,updawgctl/insecure-extra-root

updawgctl --insecure-extra-root ./local-ca.crt enroll --token enr_...
updawgd   --insecure-extra-root ./local-ca.crt
```

Every use prints what it gives away, in full, with no way to suppress it: anyone
holding that CA's key can impersonate the gateway to this host and read what it
reports. They still cannot make it install anything, because jobs are signed by
the organization key pinned at enrollment, which is not this CA. It takes no
environment variable on purpose — every other option here does, and this is the
one that should not arrive from a parent process.

**The gateway's certificate needs its own CA.** A single self-signed
`openssl req -x509` certificate has `CA:TRUE`, and rustls refuses a CA
certificate presented as an end-entity — `invalid peer certificate:
Other(OtherError(CaUsedAsEndEntity))`. `curl` accepts one, which is how the
gateway came to be verified end to end without this ever being noticed. Sign a
leaf with `CA:FALSE` from a local root and trust the root:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -pkeyopt ec_param_enc:named_curve -nodes -keyout local-ca.key -out local-ca.crt \
  -days 1 -subj "/CN=local dev CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -pkeyopt ec_param_enc:named_curve -nodes -keyout server.key -out server.csr \
  -subj "/CN=localhost"

printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > server.ext

openssl x509 -req -in server.csr -CA local-ca.crt -CAkey local-ca.key \
  -CAcreateserial -out server.crt -days 1 -extfile server.ext
```

`ec_param_enc:named_curve` is not optional either: openssl defaults to explicit
curve parameters, aws-lc-rs will not load those, and rustls reports it as
`KeyMismatch` — which sends you looking for a mismatched pair.

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

The same applies to the package backends. `tests/fixtures/apt/` and
`tests/fixtures/dnf/` are the literal output of the real tools inside official
container images — Ubuntu 20.04, 22.04 and 24.04, Debian 11 and 12, Rocky 8 and
9, Amazon Linux 2023 — and `tests/apt_live.rs` and `tests/dnf_live.rs`
re-capture them from live containers on demand:

```sh
cargo test -p updawg-backends --test dnf_live -- --ignored --nocapture
```

Those two are the canary for a format drifting under us. They are ignored by
default because they need Docker, and `UPDAWG_REQUIRE_DOCKER=1` turns "no
Docker, so this quietly did nothing" into a failure.

## Checking in

One request held open against the gateway for up to fifty-five seconds. The
gateway answers the moment a job appears, so delivery is near-instant without
anyone holding a socket per host or the agent polling every few seconds. At
fleet scale that is roughly nine hundred requests a second, which is why the
body is small and nothing expensive happens per check-in.

### Networks that kill idle connections

A long poll spends almost all of its life looking like an idle connection, and a
great deal of corporate networking equipment exists to kill those. The agent
sees a connection error indistinguishable, at a glance, from the gateway being
down — and treating it as an outage means backing off, which is exactly wrong.

So a connection failure on a poll that had already been waiting a while is read
as a trimmed idle connection: the agent polls straight back instead of backing
off. A gateway that is genuinely down fails fast — refused, DNS, a handshake
that never completes — and that still counts as a failure.

What the agent deliberately does **not** do is shorten its own timeout to fit.
That was the first thing tried here and it is wrong: the gateway decides how
long it holds, and an agent that gives up earlier just abandons polls the
gateway was about to answer. It spirals — once the timeout is below the hold,
every poll ends in its own timeout, which reads as another trim and shortens it
again.

So it **asks** instead (DAWG-205). Once something has actually trimmed a poll,
`CheckinRequest::max_hold_s` carries two thirds of the limit the agent observed,
and the gateway clamps that and honours it. The agent's own request timeout
stays at the gateway's full hold whatever it asked for, because a gateway too
old to know about the field holds for its own default and answers perfectly
well — and an agent whose timeout had followed its request would abandon every
one of those. A host on a network that never trims anything asks for nothing.

### What the server is told the agent may do

`/etc/updawg/agent.toml` is the ceiling and the server may only ever narrow it,
which means the server has to know where the ceiling is. Every check-in carries
the agent's mode and the job kinds the file permits (DAWG-223), so the product
can say a host will refuse `dist_upgrade` *before* somebody approves a proposal
that targets it rather than one refused job at a time.

What travels is the answer, not the rules: the allow and deny lists, and the
fact that `snapshot` covers two job kinds, stay here. A second implementation of
those rules somewhere that cannot be audited is exactly what this design is
trying not to have. The mode travels separately from the permissions, so a host
in observe mode with `apply_patch` written down reads as exactly that — the
operator has not deleted the permission, they have switched the mode off.

### Fleet-scale behaviour

- **Mass restart.** Ten thousand hosts that boot together would otherwise open
  their first check-in in the same instant, so the first one is spread across a
  short window. After that the long poll spreads them on its own, because they
  finish at different times.
- **Backoff jitter.** A gateway coming back from an outage is met by a fleet
  that has been failing in lockstep, and retrying in lockstep is how it goes
  down again immediately. Retries wait somewhere in the upper half of the
  current backoff — half to full rather than full jitter, which would quietly
  halve the effective backoff and make a long outage noisier than the constants
  say.

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
