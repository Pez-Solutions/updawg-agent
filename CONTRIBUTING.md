# Contributing

The conventions for every Updawg repository — protected `main`, squash merges,
how to title a pull request, Dependabot, CODEOWNERS — are written down once, in
[updawg-infra/docs/repository-conventions.md](https://github.com/Pez-Solutions/updawg-infra/blob/main/docs/repository-conventions.md).

In short: a pull request for every change, CI green before merging, and a title
that says what changes in plain words with the Jira ticket in parentheses —
`Serve the OpenAPI document at /openapi.json (DAWG-132)`.

## Changing what the agent collects

What the agent sends about a host is a promise, written at
[docs.updawg.net/agent/collected-data](https://docs.updawg.net/agent/collected-data/)
and field by field at [/agent/fields](https://docs.updawg.net/agent/fields/)
(DAWG-171). Three things hold it to the code:

- `crates/updawg-protocol/tests/collected.rs` builds every message the agent
  sends and compares its fields with `collected-fields.txt`. A new field fails
  it until the file is regenerated, and the docs site does not build until the
  page describes the field.
- `updawgctl print-inventory --json` prints the bytes the upload sends, from
  the same function (`transport::inventory_body`); a transport test holds the
  wire to it.
- A pull request that changes `collected-fields.txt` or anything in
  `crates/updawg-collectors/` fails the **Privacy review** check until it is
  labelled `privacy-reviewed`. Pez applies the label after reading the change
  against the page: nothing from the "Never" list (file contents, environment,
  process lists or command lines, users and logins, credentials, network
  configuration, cloud metadata), and anything new described on the page.

A change elsewhere that puts new content into an existing field — a log line,
an error message, a health-check detail — needs the same reading, even though
nothing forces it.
