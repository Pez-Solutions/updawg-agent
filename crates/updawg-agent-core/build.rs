//! `UPDAWG_VERSION`: the crate version and the build, as the packages name it.
//!
//! The release workflow exports `UPDAWG_BUILD` — the package release, e.g.
//! `20260930183310.g8c53d52`, or `1` for a tag — so the agent reports exactly
//! the version apt and dnf show for it (see `VERSION` in lib.rs).

fn main() {
    println!("cargo:rerun-if-env-changed=UPDAWG_BUILD");
    let crate_version = env!("CARGO_PKG_VERSION");
    let build = std::env::var("UPDAWG_BUILD").ok().filter(|b| !b.is_empty());
    let build = build.as_deref().unwrap_or("dev");
    assert!(
        build
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '~')),
        "UPDAWG_BUILD is not a package release: {build:?}"
    );
    println!("cargo:rustc-env=UPDAWG_VERSION={crate_version}-{build}");
}
