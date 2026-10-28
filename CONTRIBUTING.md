# Contributing

Changes go through pull requests against `main`, which are squash-merged. CI
(fmt, clippy, tests, cargo deny, and the distro and packaging tests) has to
pass first. Keep PR titles short and descriptive, e.g. `Retry check-ins after
a 503 with Retry-After`.

For anything security-sensitive, please email security@updawg.net instead of
opening an issue.

## Changing what the agent collects

What the agent sends about a host is documented at
[docs.updawg.net/agent/collected-data](https://docs.updawg.net/agent/collected-data/),
with every field listed at [/agent/fields](https://docs.updawg.net/agent/fields/).
A few things keep the code and the docs in sync:

- `crates/updawg-protocol/tests/collected.rs` builds every message the agent
  sends and compares the fields with `collected-fields.txt`. Adding a field
  fails this test until the file is regenerated.
- `updawgctl print-inventory --json` prints the exact upload body, using the
  same function as the upload (`transport::inventory_body`).
- PRs that touch `collected-fields.txt` or `crates/updawg-collectors/` fail
  the privacy review check until a maintainer adds the `privacy-reviewed`
  label. The agent must never collect file contents, environment variables,
  process lists or command lines, users and logins, credentials, network
  configuration or cloud metadata.

The same applies to changes that put new content into an existing field
(log lines, error messages, health check details), even though nothing
checks for it automatically.
