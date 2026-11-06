//! Sets `UPDAWG_VERSION` to `<version>-<build>`.
//!
//! The release workflow sets `UPDAWG_AGENT_VERSION` to the version
//! `packaging/version.sh` counts (Cargo.toml's major and minor, a patch one
//! higher every release) and `UPDAWG_BUILD` to the package release (something
//! like `20260930183310.g8c53d52`), so the agent reports the same version apt
//! and dnf show. Without them it is the crate's version, and the build `dev`.

fn main() {
    println!("cargo:rerun-if-env-changed=UPDAWG_AGENT_VERSION");
    println!("cargo:rerun-if-env-changed=UPDAWG_BUILD");
    let version = std::env::var("UPDAWG_AGENT_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());
    let parts: Vec<&str> = version.split('.').collect();
    assert!(
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())),
        "UPDAWG_AGENT_VERSION is not major.minor.patch: {version:?}"
    );
    let build = std::env::var("UPDAWG_BUILD").ok().filter(|b| !b.is_empty());
    let build = build.as_deref().unwrap_or("dev");
    assert!(
        build
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '~')),
        "UPDAWG_BUILD is not a package release: {build:?}"
    );
    println!("cargo:rustc-env=UPDAWG_VERSION={version}-{build}");
}
