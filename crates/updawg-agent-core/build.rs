//! Sets `UPDAWG_VERSION` to `<crate version>-<build>`.
//!
//! The release workflow sets `UPDAWG_BUILD` to the package release (something
//! like `20260930183310.g8c53d52`, or `1` for a tag), so the agent reports the
//! same version apt and dnf show. Without it the build is `dev`.

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
