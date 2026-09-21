# updawg-agent

> *What's Updawg? Not much. Your servers are up to date.*

The Updawg agent: the `updawgd` daemon and `updawgctl` CLI that run on customer
Linux hosts, plus the shared `updawg-protocol` wire-types crate.

**Language:** Rust · **Intended licence:** Apache-2.0 · **Currently:** private

> The design document calls for this repository to be **public** so customers
> can audit what runs as root on their servers. It is private for now while the
> product is pre-launch; flipping it to public is a Phase 0/1 decision, and
> everything in it should be written as if it were already public — no
> internal hostnames, no customer names, no secrets, no unreleased pricing.

---

## 1. Why this repo exists

Updawg is "Renovate for your servers": an agent on each Linux host reports its
packages, pending updates and release status; the Updawg service turns that into
reviewable update proposals, applies them under policy with staged rollouts, and
warns teams long before a distro release reaches EOL.

This repository is the part that runs **on customer machines**. That makes it the
highest-trust, highest-blast-radius component in the system, and it drives three
non-negotiable design rules:

1. **Pull, never push.** The agent only makes outbound HTTPS connections. No
   inbound ports, no SSH, no callback listener. It must work behind NAT and
   strict egress firewalls.
2. **Closed set of actions.** There is no "run this script" job. Every job is one
   of a fixed enum of typed operations. Full compromise of the Updawg control
   plane must not translate into arbitrary command execution on customer hosts.
3. **Local config always wins.** The server may *narrow* what the agent is
   allowed to do; it can never *widen* it beyond `/etc/updawg/agent.toml`.

## 2. How it fits with the other repos

```
                      updawg-protocol crate (lives HERE, published to crates.io)
                                │
                 ┌──────────────┴──────────────┐
                 ▼                             ▼
          updawg-agent  ── mTLS long-poll ─►  updawg-server (services/gateway)
        (customer host)                       (Updawg cloud)

  updawg-infra   → builds/hosts pkg.updawg.net + get.updawg.net that ship this agent
  updawg-docs    → install guides + agent config reference documenting this repo
  updawg-portal  → renders the install one-liner and the state this agent reports
```

| Repo | Relationship |
|---|---|
| `updawg-server` | **The contract partner.** The gateway (`services/gateway`) is the only thing this agent talks to. Both sides depend on the `updawg-protocol` crate defined here — this repo owns the Agent API wire format. |
| `updawg-infra` | Owns `pkg.updawg.net` (signed apt/yum repos) and `get.updawg.net`. This repo *produces* the `.deb`/`.rpm` and `install.sh`; infra *publishes* them. |
| `updawg-docs` | Per-distro install guides, the `agent.toml` reference and the security whitepaper describe this repo's behaviour. Changing a config key or a job kind is a docs PR too. |
| `updawg-portal` | Shows the install command and every fact this agent collects. New collected fields need a portal story before they are worth collecting. |

**Contract rule:** `updawg-protocol` is the single source of truth for the Agent
API. Server-side changes to agent-facing types happen *here first*, are released
to crates.io, and `updawg-server` bumps the dependency. Never redefine an agent
wire type inside `updawg-server`.

## 3. Repository layout

```
updawg-agent/
├── Cargo.toml                 # workspace
├── crates/
│   ├── updawg-protocol/        # wire types, published to crates.io (shared with server)
│   ├── updawg-crypto/          # signature verification, key pinning, CSR generation
│   ├── updawg-collectors/      # os-release, kernel, reboot, services, repos
│   ├── updawg-backends/        # apt, dnf (later zypper, apk, pacman)
│   ├── updawg-snapshots/       # snapper, zfs, lvm
│   ├── updawg-executor/        # job handlers, health checks
│   └── updawg-agent-core/      # scheduler, transport, local state
├── bin/
│   ├── updawgd/                # daemon
│   └── updawgctl/              # CLI
├── packaging/
│   ├── systemd/updawgd.service
│   ├── nfpm.yaml              # builds .deb and .rpm
│   └── install.sh             # served at get.updawg.net
└── tests/
    └── distros/               # container and VM integration tests per distro
```

Key crates: `tokio`, `reqwest` (rustls), `serde`, `ed25519-dalek`, `rcgen`,
`zstd`, `clap`, `tracing`, `toml`.

## 4. Internal architecture

```
Scheduler (tokio)
 ├─► Check-in loop ──► Job runner ──► signature + permission check ──► Executors ──► Health checks
 ├─► Inventory collector ──► Collectors ──► PackageBackend (apt, dnf)
 │                                      └─► System facts (os-release, kernel, reboot, services, repos)
 └─► Transport (reqwest + rustls mTLS) ──► Updawg Gateway
       Executors ──► Snapshot providers (snapper, zfs, lvm)
       Job runner ──► local state (/var/lib/updawg)
```

Distro support is a trait, not a fork:

```rust
#[async_trait]
pub trait PackageBackend: Send + Sync {
    fn ecosystem(&self) -> Ecosystem;                       // Deb, Rpm, ...
    async fn installed(&self) -> Result<Vec<InstalledPackage>>;
    async fn refresh_metadata(&self) -> Result<()>;         // apt-get update / dnf makecache
    async fn available_updates(&self) -> Result<Vec<AvailableUpdate>>;
    async fn repositories(&self) -> Result<Vec<Repository>>;
    async fn held_packages(&self) -> Result<Vec<String>>;   // apt-mark showhold / versionlock
    async fn security_updates(&self, updates: &[AvailableUpdate]) -> Result<BTreeSet<String>>;
    async fn apply(&self, plan: &ApplyPlan, log: &LogSink) -> Result<ApplyOutcome>;
}
```

Adding a distro family = implementing this trait + a row in the integration
test matrix. Nothing else in the agent should need to change.

**Why CLI tools, not libraries.** Binaries are statically linked against musl for
`x86_64` and `aarch64` so one build runs everywhere. That rules out linking
`libapt`/`libdnf`, so the backends shell out to package managers in
machine-readable modes:

- **apt:** installed from `dpkg-query -W` with a tab-separated format string;
  candidates from a simulated `apt-get -s dist-upgrade`; repository origin (e.g.
  the `-security` pocket) from `apt-cache policy`.
- **dnf:** installed from `rpm -qa --qf`; candidates from `dnf repoquery
  --upgrades --latest-limit=1 --qf`, **not** `dnf check-update`, whose output is
  a terminal table that wraps a long package name onto two lines; repositories
  from `dnf repolist --all -v`, whose plain form truncates a name to the terminal
  width; advisories from `dnf updateinfo list`; holds from `dnf versionlock
  list`.

Security classification is *refined server-side* by matching versions against
advisory data — the agent reports what it sees, the server decides what it means.

**`security_updates` is on the trait because the two families keep the answer in
different places.** apt puts it on the update itself, as the `-security` pocket.
The RHEL family has no security pocket at all — a fix and a rebuild are published
to the same `baseos` — and keeps it in a separate `updateinfo` database that has
to be asked. Filtering on the pocket gives the right answer on Debian and zero on
every RHEL host in the fleet.

## 5. What it collects (and what it must never collect)

| Category | Examples | Frequency |
|---|---|---|
| Identity | machine-id, hostname, FQDN, cloud instance ID and region | Enrollment, then on change |
| Platform | distro, version, codename, kernel, architecture, virtualization | Every inventory |
| Packages | name, version, architecture, source repository | Full every 6h, and after every job |
| Updates | candidate versions, repository, origin | Every inventory, plus after `refresh` jobs |
| Repositories | configured apt sources and yum repos, including third-party | Every inventory |
| State | reboot required, services needing restart, held packages | Every check-in (small) |
| Health | uptime, load, memory, root disk free space | Every check-in |

**Never collected:** file contents, environment variables, process arguments,
user data, credentials. `updawgctl --print-inventory` must show byte-for-byte what
would be sent — treat that flag as a contract with the customer, and test it.

## 6. Configuration (`/etc/updawg/agent.toml`)

```toml
server = "https://agents.updawg.net"

# "observe": report only, never change anything.
# "managed": execute signed jobs permitted below.
mode = "managed"

[permissions]
allow = ["refresh", "apply_security", "apply_patch", "apply_kernel", "reboot", "snapshot"]
deny  = ["dist_upgrade"]

[schedule]
inventory_interval = "6h"
refresh_metadata   = "1h"

[snapshots]
provider = "auto"          # auto | snapper | zfs | lvm | none
keep     = 3

[[health_check]]
name = "nginx running"
type = "systemd"
unit = "nginx.service"

[[health_check]]
name = "app responds"
type = "http"
url  = "http://127.0.0.1:8080/healthz"
expect_status = 200
timeout = "5s"
```

`GET /config` returns server-side config, but it is **intersected** with the local
file, never unioned. A test must assert that a server response cannot grant a
permission the local `deny` list forbids.

## 7. Job kinds and execution

| Kind | Effect |
|---|---|
| `refresh_inventory` | Refresh package metadata and upload a full inventory. |
| `run_preflight` | Checks for a proposed change (disk space, locks, held packages, repo readiness) without changing anything. |
| `apply_updates` | Install an exact list of package versions. Fails if the candidate differs from what was approved. |
| `dist_upgrade` | Upgrade to a named target release via the distro's supported tool (`do-release-upgrade`, `leapp`, or sources rewrite + `apt full-upgrade`). |
| `reboot` | Reboot, optionally only if required, with delay and wall message. |
| `snapshot` / `rollback` | Create or roll back to a snapshot. |
| `self_update` | Install a specific signed agent release. |

Execution flow:

1. Job arrives in a check-in response.
2. Verify the Ed25519 signature against the org key **pinned at enrollment**;
   check `host_id` matches, `expires_at` has not passed, and the job ID has not
   been seen before (replay protection).
3. Check `mode` and `[permissions]`. A denied job reports `rejected_by_host` with
   a reason — it is a normal outcome, not an error.
4. Ack, snapshot if requested, run the executor non-interactively
   (`DEBIAN_FRONTEND=noninteractive`, conffile policy = keep local changes, hard
   timeout).
5. Stream log lines in batches; record package changes.
6. Run health checks; report the result including whether a reboot is now needed.
7. If the job requested a reboot: persist state, reboot, and on restart report
   the reboot completed and re-run health checks.

**Only one mutating job at a time.** Respect package manager locks and wait (with
a timeout) for `unattended-upgrades` and friends to finish.

## 8. Agent API surface (served by `updawg-server`'s gateway)

`https://agents.updawg.net/agent/v1`

| Method and path | Purpose |
|---|---|
| `POST /enroll` | Exchange an enrollment token and CSR for a host identity. The only endpoint that doesn't require a client certificate. |
| `POST /checkin` | Heartbeat and long-poll for jobs. Held open up to 55 seconds. |
| `PUT /inventory` | Upload a full inventory or a delta. |
| `POST /jobs/{job_id}/ack` | Report a job started (or was rejected by the host). |
| `POST /jobs/{job_id}/logs` | Append a batch of log lines (NDJSON). |
| `POST /jobs/{job_id}/complete` | Final result, package changes, health checks. |
| `POST /cert/renew` | Renew the client certificate before expiry. |
| `GET /config` | Server-side config, capped by local config. |
| `GET /releases/{channel}` | Signed manifest of agent releases for self-update. |

## 9. Installation

```bash
curl -fsSL https://get.updawg.net | sudo UPDAWG_TOKEN=enr_7Kq... sh
```

`install.sh` detects the distro, adds the signed `pkg.updawg.net` repository,
installs the `updawg-agent` package, writes the token to `/etc/updawg/enroll.token`
and starts the systemd unit. It must stay **short and readable** — people will
audit it before piping it to a root shell. Alternative paths that must keep
working: manual repo add, Ansible/Puppet/Chef, cloud-init, golden image +
`updawgctl enroll --token ...` later.

The systemd unit runs as root (package installation requires it) with hardening
that does not break package management: `ProtectHome=read-only`,
`PrivateTmp=yes`, `NoNewPrivileges=no` (maintainer scripts need it), restricted
address families.

## 10. Supported platforms

Initial: Ubuntu 20.04+, Debian 11+, RHEL/Alma/Rocky/Oracle 8+, current Fedora,
Amazon Linux 2023. SUSE, Alpine and Arch follow behind the same collector trait.

## 11. Security posture

- Per-host key pair, generated **locally**; the private key never leaves the host.
- Short-lived client certificate; decommissioning revokes it at the gateway.
- Jobs signed with the org's Ed25519 key; verified against the key pinned at
  enrollment. Rotation works by the old key endorsing the new one, so the agent
  follows rotation without blindly trusting the server.
- Reproducible builds with SLSA provenance. Packages and self-update manifests
  signed (minisign for manifests, GPG for apt/yum). Published checksums.

## 12. CI/CD

- `clippy`, `rustfmt`, `cargo test`, `cargo audit`, `cargo deny` on every PR.
- Integration tests in containers and lightweight VMs **per supported distro** —
  this is the expensive matrix that justifies the trait design.
- Tagged releases cross-compile static musl binaries for `x86_64` and `aarch64`,
  build `.deb` and `.rpm` via `nfpm`, sign them, and hand artifacts to
  `updawg-infra` for publication to `pkg.updawg.net`.
- A `updawg-protocol` publish job to crates.io on version bump.

## 13. Build order

| Phase | Work |
|---|---|
| **0 — Visibility** (wk 1-6) | `updawg-protocol`, crypto/enrollment, check-in loop, apt + dnf collectors, inventory upload, **observe mode only**. Packaging + install script. No executors. |
| **1 — Proposals** (wk 7-12) | Job runner, signature + permission verification, `apply_updates` and `reboot` executors, log streaming, health checks. |
| **2 — Safe automation** (wk 13-20) | Snapshot providers (snapper, zfs, lvm), `rollback`, `self_update`, richer preflight. |
| **3 — Lifecycle** (wk 21+) | `dist_upgrade` per distro family, third-party repo readiness probing, then zypper/apk/pacman backends. |

## 14. Open questions

- Long-poll vs. push-on-idle under aggressive corporate proxies that kill idle
  connections before 55s — needs a real-world measurement, may need a tunable.
- How much preflight can honestly run without mutating state on RHEL-family
  (`leapp` wants to do a lot of it itself).
- Whether `self_update` should ever be automatic, or always an explicit job.
