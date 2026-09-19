# updawg-protocol

Wire types for the [Updawg](https://updawg.net) agent API — the contract between
the Updawg agent (`updawgd`) and its gateway.

Updawg is "Renovate for your servers": an agent on each Linux host reports its
packages, pending updates and release status, and the service turns that into
reviewable update proposals applied under policy with staged rollouts.

This crate is published so that both sides of that contract — the open-source
agent and the server — depend on one definition rather than two that drift.

```toml
[dependencies]
updawg-protocol = "0.1"
```

## The property this crate exists to preserve

`JobKind` and `JobSpec` are **closed enums**. There is no variant carrying a
script, a command line, or a free-form string for the agent to execute. Every
job names *what* should happen, with explicit parameters, never *how*:

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

That is what makes "even full control of the control plane cannot run arbitrary
commands on a customer's host" a property of the type system rather than a
promise in a document. Versions are pinned exactly, so if a host's candidate has
moved on since a change was approved, the agent refuses the job rather than
installing something nobody reviewed.

Adding a variant to either enum is a security decision, not a routine change.

## Signing

Jobs are signed with the organization's Ed25519 key and verified by the agent
against a key pinned at enrollment. `Job::signing_bytes` produces the exact
bytes a signature covers — this job's JSON with `signature` removed — so the
signer and the agent cannot disagree about what was signed.

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

## Stability

Pre-1.0. The wire format is versioned independently of this crate through the
`Updawg-Protocol` header (currently `1`), and the gateway accepts the current
and previous protocol version.

## License

Apache-2.0
