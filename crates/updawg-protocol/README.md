# updawg-protocol

Wire types for the [Updawg](https://updawg.net) agent API: the contract between
the Updawg agent (`updawgd`) and its gateway.

Updawg runs an agent on each Linux host that reports its packages, pending
updates and release status. The service turns that into update proposals that
get reviewed and then applied under policy, with staged rollouts.

Both the open-source agent and the server depend on this crate, so there is
one definition of the format.

```toml
[dependencies]
updawg-protocol = "0.12"
```

## Jobs are a closed set

`JobKind` and `JobSpec` are closed enums. No variant carries a script, a
command line or a free-form string for the agent to execute. Every job says
what should happen, with explicit parameters:

```rust
use updawg_protocol::{JobSpec, ApplyUpdates, PackagePin, SnapshotPolicy, RebootPolicy};

let spec = JobSpec::ApplyUpdates(ApplyUpdates {
    packages: vec![PackagePin {
        name: "openssl".into(),
        arch: "amd64".into(),
        from: "3.0.13-0ubuntu3.3".into(),
        to: "3.0.13-0ubuntu3.4".into(),
    }],
    snapshot: SnapshotPolicy::IfAvailable,
    reboot: RebootPolicy::Never,
    timeout_s: 3600,
});
```

So even full control of the control plane can't run arbitrary commands on a
host. Versions are pinned exactly: if a host's candidate has moved on since a
change was approved, the agent refuses the job instead of installing something
nobody reviewed.

Adding a variant to either enum is a security decision.

## Signing

Jobs are signed with the organization's Ed25519 key and verified by the agent
against a key pinned at enrollment. `Job::document` produces the canonical
document (the job's JSON without `signature`), and `Job::signing_bytes` the
exact bytes a signature covers. The signer and the agent both use these.

An organization key signs two kinds of message, so every signature is
prefixed with a label:

```text
label || 0x00 || message

updawg-job-v1
updawg-endorsement-v1
```

Labels are ASCII with no NUL, so a message under one label can never be read
as a message under the other. Before 0.3 the only difference was that a job
document starts with `{`.

## Key rotation

An agent never has to take the server's word for a new key. The outgoing key
signs an `EndorsementStatement` naming the organization, both keys (by
material and id) and when it was issued, and the agent follows the chain from
a key it already holds.

The statement travels as the exact string that was signed, next to the
signature. The agent can't rebuild it, since it has no way to know
`issued_at`, and a re-serialised document isn't guaranteed to be
byte-identical.

## Transport

Mutual TLS. The agent generates a key pair locally at enrollment, sends a CSR,
and receives a short-lived client certificate; the private key never leaves the
host. Every request carries an `Updawg-Protocol` header, and the gateway accepts
the current and previous version.

The agent only makes outbound connections. There is no listener and no inbound
port, so it works behind NAT and strict egress firewalls.

## Endpoints these types cover

| Path | Types |
|---|---|
| `POST /enroll` | `EnrollRequest`, `EnrollResponse` |
| `POST /checkin` | `CheckinRequest`, `CheckinResponse` |
| `PUT /inventory` | `InventoryUpload` |
| `POST /jobs/{id}/ack` | `JobAck` |
| `POST /jobs/{id}/logs` | `LogLine` (NDJSON) |
| `POST /jobs/{id}/complete` | `JobComplete` |
| `POST /cert/renew` | `CertRenewRequest`, `CertRenewResponse` |
| `GET /config` | `ServerConfig` |
| `GET /releases/{channel}` | `ReleaseManifest` |

## Local configuration

`/etc/updawg/agent.toml` sets the most an agent will do, and the server can
only narrow it. `CheckinRequest::local_policy` reports the mode and the job
kinds the file permits on every check-in, since the file can change at any
time. An agent too old to report it sends nothing, which means unknown, not
"nothing permitted".

## Advisory hints

`AvailableUpdate::advisories` carries what the host's own package manager says
about an update: the vendor's advisory id, its severity word as given, and the
type. On the RHEL family, fixes and routine rebuilds both go to `baseos`, so
this is the only local signal for security updates.

It's only a hint. The server classifies updates against advisory feeds,
because local metadata is only as complete as the vendor made it.

## Stability

Pre-1.0. The wire format is versioned separately through the `Updawg-Protocol`
header (currently `1`), and the gateway accepts the current and previous
protocol version. Adding an optional field doesn't change the header: new
fields are optional in both directions, so older peers keep working.

## Changes

### 0.9 to 0.12

- 0.9: `CheckinRequest::install` (`AgentInstall`, `InstallMethod`): how the
  agent was installed and which channel it follows.
- 0.10: `InstalledPackage::module` and `InventoryUpload::modules_reported`,
  for RHEL-family module streams.
- 0.11: `CheckinRequest::pinned_keys`, the signing keys the agent holds.
- 0.12: `CheckinResponse::renew_certificate`, asking the agent to renew early
  so it picks up a new signing key.

### 0.5 to 0.8

- 0.5: `JobComplete::preflight`.
- 0.6: `Repository::url`, for third-party repositories only, with credentials
  stripped.
- 0.7: `AvailableUpdate::source`, the candidate's own source package.
- 0.8: `InventoryUpload::frozen`, what pins a host's package sources in time.

All optional in both directions.

### 0.4.0

Breaking: `HostStateReport::reboot_required` is now `RebootRequired` (`yes`,
`no`, `unknown`) instead of a `bool`, so a host that can't tell is no longer
reported as not needing a reboot. A 0.4 reader still accepts `true`/`false`,
but a 0.3 reader doesn't accept the words, so upgrade the gateway before the
agents. Also adds `CheckinRequest::snapshots` and `InstalledPackage::source`,
both optional.

### 0.3.0

Breaking, to what is signed. A 0.2 signature over a job doesn't verify under
0.3, and `OrgSigningKey::endorsement` is now an `Endorsement` instead of a bare
signature string that couldn't be verified. A mismatched peer fails at the
first signature or enrollment.

### 0.2.0

- `CheckinRequest::max_hold_s`: the check-in hold the agent would like, for
  networks that cut idle connections before a long poll completes. The gateway
  clamps it via `CheckinRequest::hold_seconds`.
- `CheckinRequest::local_policy`: `LocalPolicy` and `AgentMode`, what
  `/etc/updawg/agent.toml` permits.
- `AvailableUpdate::advisories`: `AdvisoryHint`, what the host's package
  manager says an update fixes.
- `InventoryUpload::removals`: `PendingRemoval` and `Replacement`, packages an
  upgrade would remove.
- `JobKind::ALL`.

Every field is optional in both directions.

### 0.1.2

Sets the crate's own MSRV (1.85). `0.1.1` inherited the agent workspace's
`rust-version = 1.88`, which consumers on 1.85 couldn't resolve.

### 0.1.1

The wire structs are no longer `#[non_exhaustive]`, which had made them
impossible to construct outside this crate. Superseded by `0.1.2`.

### 0.1.0

First release. Unusable because of the `#[non_exhaustive]` structs.

## License

Apache-2.0
