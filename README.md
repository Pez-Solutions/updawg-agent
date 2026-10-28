# updawg-agent

The agent for [Updawg](https://updawg.net): `updawgd`, the daemon that runs on
each Linux host, and `updawgctl`, its local CLI. The `updawg-protocol` crate,
which defines the wire format between the agent and the server, also lives
here and is published to crates.io.

The agent runs as root on your servers, so the source is public so you can
read what it does.

Install instructions and the config reference are at
[docs.updawg.net](https://docs.updawg.net).

## Building

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

cargo run --bin updawgd -- --config ./examples/agent.toml --check-config
cargo run --bin updawgd -- --config ./examples/agent.toml --state-dir /tmp/updawg
cargo run --bin updawgctl -- status
```

Release binaries are statically linked against musl for `x86_64` and
`aarch64`, so one build runs on every supported distro.

## Layout

| Crate | What it does |
|---|---|
| `crates/updawg-protocol` | Wire types shared with the server, published to crates.io |
| `crates/updawg-crypto` | Signature verification, key pinning, CSR generation |
| `crates/updawg-collectors` | os-release, kernel, reboot state, services, repositories |
| `crates/updawg-backends` | apt and dnf, behind a `PackageBackend` trait |
| `crates/updawg-snapshots` | snapper, ZFS and LVM thin, behind a `SnapshotProvider` trait |
| `crates/updawg-executor` | Job handlers and health checks |
| `crates/updawg-agent-core` | Scheduler, transport, local state, config |
| `bin/updawgd` | The daemon |
| `bin/updawgctl` | CLI: enroll, status, `print-inventory` |
| `tools/release-sign` | Signs release manifests in CI |

## Design constraints

1. **Outbound only.** The agent makes HTTPS requests to the gateway and
   nothing else. No listening socket, no SSH. It works behind NAT and strict
   egress firewalls.
2. **A fixed set of actions.** `JobKind` is a closed enum and has no "run this
   command" variant. Someone with full control of the Updawg control plane
   still can't run arbitrary commands on a host. Adding a variant is a
   security decision.
3. **Local config wins.** The server can narrow what the agent is allowed to
   do but never widen it beyond `/etc/updawg/agent.toml`. See
   `Permissions::intersect` and its tests.

Permissions fail closed: an empty allow list permits nothing, so a truncated
or broken config leaves the agent reporting but not acting. `mode` defaults to
`managed`, and `install.sh` writes a config with every permission allowed,
including `reboot` and `dist_upgrade`, because jobs only run if the
organization approved and signed them. To restrict a host, narrow the allow
list or add to `deny`. `mode = "observe"` makes it report only.

Each check-in tells the server the agent's mode and which job kinds its config
allows, so the portal can show that a host will refuse a job before anyone
approves it. Only the result is sent; the rules themselves are evaluated here.

## Package backends

Since the binaries are static, they can't link `libapt` or `libdnf`. The
backends run the package managers' CLI tools instead, and only in their
machine-readable modes. For example, `dnf check-update` wraps long package
names onto two lines and `dnf repolist` truncates names to the terminal width,
so the dnf backend uses `dnf repoquery --qf` and `dnf repolist -v`. The
offline tests still cross-check the two outputs.

Some differences between the two families:

- **Security updates.** apt tells you the pocket a candidate comes from
  (`noble-security`). RHEL-family distros publish security fixes to the same
  repos as everything else and keep the classification in `updateinfo`. That's
  why `security_updates` is a backend method and not a filter the caller
  applies. dnf's advisory id, severity and type are sent on
  `AvailableUpdate::advisories` as reported; the server normalises severities
  (Rocky says `Moderate` where Amazon Linux says `Medium`).
- **Replacements.** Both `dnf upgrade` and apt (via `Conflicts`/`Replaces`)
  can remove a package and install a differently named one. These are sent
  separately as `InventoryUpload::removals`. dnf names the replacement; apt
  doesn't, so that field is optional.
- **Module streams.** On RHEL-family hosts an installed package includes its
  module stream as `name:stream`, taken from rpm's `MODULARITYLABEL`.
- **Amazon Linux 2023** pins `$releasever` to a dated snapshot, so
  `dnf check-update` usually finds nothing. The agent reports that as is and
  doesn't pass `--releasever=latest`, since the host wouldn't install those
  updates.

## Local state

State lives in `/var/lib/updawg`, mode `0700`:

| File | Purpose |
|---|---|
| `agent.key` | The host's Ed25519 private key, mode `0600`. Generated locally, never sent. A looser mode is fixed on load and logged. |
| `identity.json` | Host id, client certificate, and the organization signing keys pinned at enrollment. Jobs are verified against these. |
| `seen-jobs.json` | Replay protection, so a job never runs twice (including across a reboot). Bounded in size. |
| `pending-reboot.json` | A job that reboots the host can't report its own result, so the agent records it and finishes the report after boot. |

Writes are atomic (temp file, fsync, rename).

## Enrollment

`updawgctl enroll --token ...` generates a key pair, sends a CSR to
`POST /agent/v1/enroll` and stores the result. Nothing is written until the
response has been validated, so a failed enrollment leaves an existing
identity intact, and a response that couldn't verify jobs (bad organization
key, no active key, empty CA chain) is rejected up front.

An already-enrolled host won't re-enroll unless you pass `--force`. If the
organization signing key in the response differs from the pinned one,
`--force` is still refused and both fingerprints are printed; pass
`--accept-new-org-key` if you know the key was rotated.

`enroll` and `updawgctl status` print the pinned keys so you can compare them
with the portal.

## Transport and certificate renewal

Every request after enrollment uses mTLS with the client certificate. Certs
last 30 days, so a decommissioned or revoked host drops off on its own.

Renewal starts when a third of the certificate's lifetime is left (10 days for
a 30-day cert), which allows for a host being off for a week plus a gateway
outage. Each host picks a stable point in that window based on its certificate
serial, so a fleet enrolled at the same time doesn't renew at the same time.
The private key is kept across renewals so that renewal is a single atomic
write.

Error messages distinguish between a rejected certificate (401/403, with the
subject, serial and the `--force` command to fix it), an expired local
certificate, and everything else (with the full error chain).

## Check-ins

The agent holds one long-poll request open against the gateway for up to 55
seconds. The gateway responds as soon as there's a job for the host.

Some networks kill connections that look idle. If a poll fails with a
connection error after it has been open for a while, the agent treats that as
the connection being cut and polls again immediately instead of backing off.
Fast failures (refused, DNS, TLS handshake) still count as failures. Once the
agent has seen a poll cut, it sends `CheckinRequest::max_hold_s` (two thirds
of the observed limit) and the gateway holds for that long instead. The agent's
own request timeout stays at the full hold time, so it still works with a
gateway that ignores the field.

Other timing details:

- The first check-in after start is delayed by a random amount, so a fleet
  that boots at once doesn't hit the gateway together.
- Retries back off with jitter between half and all of the current backoff.
- Check-in, inventory and metadata refresh run on separate schedules, each
  with startup jitter and backoff on failure.

## What the agent collects

Platform facts (distro, version, codename, kernel, architecture,
virtualization, machine id, hostname, FQDN), plus on each check-in: boot id,
uptime, whether a reboot is pending, services running on replaced libraries,
load, memory and root filesystem free space. Package data comes from the
backends: installed packages, available updates, repositories and held
packages. Third-party repositories include their URL with credentials, query
string and fragment stripped (see `updawg_protocol::public_url`); a secret in
the URL path can't be detected and is sent as is.

It never collects file contents, environment variables, process arguments,
user data or credentials. The full list is at
[docs.updawg.net/agent/collected-data](https://docs.updawg.net/agent/collected-data/),
and `updawgctl print-inventory --json` prints exactly what would be uploaded.

"Reboot pending" is `Yes`, `No` or `Unknown`. Red Hat hosts often lack
`needs-restarting`, and a host where we can't tell is reported as unknown
rather than as not needing a reboot. Where `needrestart` is installed its
answer takes precedence over the flag file, except that an existing flag file
always means yes.

Collectors read from a configurable root, so the tests cover several distros
from one machine. Parser fixtures are real output captured from Ubuntu 20.04,
22.04, 24.04, Debian 11 and 12, Rocky 8 and 9, and Amazon Linux 2023
containers. The `*_live` tests re-capture them and need Docker:

```sh
cargo test -p updawg-backends --test dnf_live -- --ignored --nocapture
```

They're ignored by default. Set `UPDAWG_REQUIRE_DOCKER=1` to make them fail
when Docker isn't available instead of skipping.

## Logging

`UPDAWG_LOG` sets the filter (`tracing` env-filter syntax). Under systemd
(`JOURNAL_STREAM` set) the agent leaves out timestamps and colours, since
journald adds its own.

## Testing against a local gateway

The agent only trusts the platform's root store. For development, build with
the `insecure-extra-root` feature to add a CA of your own:

```sh
cargo build --bin updawgd --bin updawgctl \
  --features updawgd/insecure-extra-root,updawgctl/insecure-extra-root

updawgctl --insecure-extra-root ./local-ca.crt enroll --token enr_...
updawgd   --insecure-extra-root ./local-ca.crt
```

Release builds don't include the feature, so the flag doesn't exist there. It
also has no environment variable equivalent. Every use prints a warning. Note
that whoever holds that CA's key can impersonate the gateway and read what the
host reports, but still can't make it run anything, since jobs are signed by
the organization key pinned at enrollment.

The gateway needs a leaf certificate signed by a CA. rustls rejects a
self-signed `CA:TRUE` cert used as a server cert (`CaUsedAsEndEntity`), even
though curl accepts it. Also use `ec_param_enc:named_curve`: openssl defaults
to explicit curve parameters, which aws-lc-rs can't load, and the error you get
is a misleading `KeyMismatch`.

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

## Versions and releases

Every build of `main` is versioned `<version>-<UTC time>.g<commit>`, for
example `0.2.0-20261002200000.gabcdef0`. That's the package version, the output
of `updawgctl --version`, and the `agent_version` reported to the server.
`<version>` comes from `Cargo.toml`, the rest from `packaging/release-id.sh`.

- Bump with `sh packaging/bump-version.sh minor` (or `major`, `patch`).
  `updawg-protocol` is versioned separately and changes with the wire format.
- Releases are made by promoting a beta build to stable. A `v*` tag, if used,
  has to match `Cargo.toml`.
- Versions only go up. CI rejects a PR that lowers the version, and publishing
  rejects a build that sorts below the current beta (using dpkg ordering).

## License

Apache-2.0. See [LICENSE](./LICENSE).
