//! Fake hosts to collect from.
//!
//! The collectors read files under a root, so a "host" is a directory. That is
//! what lets the suite cover Ubuntu, Debian, Red Hat-family and Amazon Linux
//! from one machine that is none of them — and, more usefully, lets a test say
//! "this host has no `/proc/meminfo`" without anyone having to build one.
//!
//! The fixtures are real `/etc/os-release` contents, not approximations. The
//! whole point of the family detection they feed is that it matches what is
//! actually on those distributions.

// A fixture that cannot be written is a broken test environment, not a
// condition to handle: every caller is a test that is about to assert on the
// files this writes. The workspace denies `expect` because the agent runs as
// root on other people's servers — that reasoning does not reach here.
#![allow(clippy::expect_used)]

use crate::platform::Root;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A directory that looks enough like a Linux host to collect from.
#[derive(Debug)]
pub struct FakeHost {
    dir: PathBuf,
}

impl FakeHost {
    /// A host with nothing on it at all.
    #[must_use]
    pub fn empty() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("updawg-host-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self { dir }
    }

    /// The common shape: `/proc`, a machine id, a hostname, a kernel.
    #[must_use]
    fn linux() -> Self {
        let host = Self::empty();
        host.write("etc/machine-id", "3f2a9c1d4e5b6a7c8d9e0f1a2b3c4d5e\n");
        host.write("proc/sys/kernel/hostname", "web-03\n");
        host.write("proc/sys/kernel/osrelease", "6.12.0-amd64\n");
        host.write(
            "proc/sys/kernel/random/boot_id",
            "b81e5c7a-1f2d-4c3b-9a8e-0d1f2a3b4c5d\n",
        );
        host.write("proc/uptime", "864000.42 3456789.01\n");
        host.write("proc/loadavg", "0.42 0.51 0.48 2/431 12345\n");
        host.write(
            "proc/meminfo",
            "MemTotal:       16777216 kB\nMemFree:         1048576 kB\nMemAvailable:   12582912 kB\n",
        );
        host
    }

    #[must_use]
    pub fn debian() -> Self {
        let host = Self::linux();
        host.write(
            "etc/os-release",
            "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n\
             NAME=\"Debian GNU/Linux\"\n\
             VERSION_ID=\"13\"\n\
             VERSION=\"13 (trixie)\"\n\
             VERSION_CODENAME=trixie\n\
             ID=debian\n",
        );
        host.write("usr/bin/dpkg", "");
        host
    }

    #[must_use]
    pub fn ubuntu() -> Self {
        let host = Self::linux();
        host.write(
            "etc/os-release",
            "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n\
             NAME=\"Ubuntu\"\n\
             VERSION_ID=\"24.04\"\n\
             VERSION=\"24.04.1 LTS (Noble Numbat)\"\n\
             VERSION_CODENAME=noble\n\
             ID=ubuntu\n\
             ID_LIKE=debian\n",
        );
        host.write("usr/bin/dpkg", "");
        host
    }

    #[must_use]
    pub fn rocky() -> Self {
        let host = Self::linux();
        host.write(
            "etc/os-release",
            "NAME=\"Rocky Linux\"\n\
             VERSION=\"9.4 (Blue Onyx)\"\n\
             ID=\"rocky\"\n\
             ID_LIKE=\"rhel centos fedora\"\n\
             VERSION_ID=\"9.4\"\n\
             PLATFORM_ID=\"platform:el9\"\n",
        );
        host.write("usr/bin/rpm", "");
        host
    }

    #[must_use]
    pub fn amazon() -> Self {
        let host = Self::linux();
        host.write(
            "etc/os-release",
            "NAME=\"Amazon Linux\"\n\
             VERSION=\"2023\"\n\
             ID=\"amzn\"\n\
             ID_LIKE=\"fedora\"\n\
             VERSION_ID=\"2023\"\n\
             PLATFORM_ID=\"platform:al2023\"\n",
        );
        host.write("usr/bin/rpm", "");
        host
    }

    /// Write a file, creating parent directories.
    ///
    /// # Panics
    /// If the file cannot be written, which in a temp directory means the test
    /// environment is broken and there is nothing useful to continue to.
    pub fn write(&self, rel: &str, contents: &str) {
        let path = self.dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("fixture parent dir");
        }
        std::fs::write(path, contents).expect("fixture file");
    }

    #[must_use]
    pub fn root(&self) -> Root {
        Root::new(&self.dir)
    }

    #[must_use]
    pub fn path(&self) -> &PathBuf {
        &self.dir
    }
}

impl Drop for FakeHost {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}
