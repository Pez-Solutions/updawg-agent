//! Applying exact versions against real dnf in a container.
//!
//! Ignored by default since it needs Docker. Run with
//!
//! ```text
//! cargo test -p updawg-backends --test dnf_apply_live -- --ignored --nocapture
//! ```
//!
//! The command lines come from [`install_args`], [`simulate_args`] and
//! [`query_args`], so this tests what the agent actually runs. It uses the
//! distribution's own `openssl` packages, since every image has them and the
//! repositories keep several versions. The third newest is installed and the
//! job is approved for the second newest; the newest must not get installed.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    unreachable_pub
)]

use updawg_backends::{
    BackendError, Pin,
    apt::Ran,
    dnf::{
        changes, check_transaction, install_args, parse_versions, query_args, simulate_args,
        still_to_do,
    },
};

const IMAGES: &[&str] = &[
    "rockylinux/rockylinux:9",
    "rockylinux/rockylinux:8",
    "amazonlinux:2023",
];

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("run docker")
}

struct Container(String);

impl Container {
    fn start(image: &str) -> Self {
        let out = docker(&["run", "-d", "--rm", image, "sleep", "900"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        Self(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }

    fn exec(&self, tool: &str, args: &[String]) -> Ran {
        let mut all = vec!["exec", "-e", "LC_ALL=C", "-e", "LANG=C", &self.0, tool];
        all.extend(args.iter().map(String::as_str));
        let out = docker(&all);
        Ran {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn sh(&self, script: &str) -> Ran {
        self.exec("bash", &["-c".into(), script.into()])
    }

    fn versions(&self, pins: &[Pin]) -> std::collections::BTreeMap<String, Vec<String>> {
        parse_versions(&self.exec("rpm", &query_args(pins)).stdout)
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", &self.0]);
    }
}

/// Every `%{evr}` offered for `openssl-libs`, oldest first.
fn offered(c: &Container) -> Vec<String> {
    let out =
        c.sh("dnf -q repoquery --showduplicates --qf '%{evr}' openssl-libs 2>/dev/null | sort -uV");
    out.stdout
        .lines()
        .map(str::to_owned)
        .filter(|l| !l.is_empty())
        .collect()
}

/// Shell script that downgrades every installed openssl package to `version`
/// in one transaction. On Amazon Linux `openssl-fips-provider-latest` is
/// locked to `openssl-libs`, so moving one alone won't resolve.
fn back_to(version: &str) -> String {
    format!(
        "set -e; dnf -q -y --setopt=install_weak_deps=False install openssl >/dev/null 2>&1 || true; \
         pkgs=''; for p in $(rpm -qa --qf '%{{NAME}}\\n' 'openssl*'); do \
           dnf -q repoquery \"$p-{version}\" 2>/dev/null | grep -q . && pkgs=\"$pkgs $p-{version}\"; done; \
         dnf -q -y --setopt=install_weak_deps=False downgrade $pkgs"
    )
}

/// Pins for whichever openssl packages this image offers at `to`.
fn family(c: &Container, arch: &str, from: &str, to: &str) -> Vec<Pin> {
    ["openssl", "openssl-libs"]
        .iter()
        .map(|name| Pin {
            name: (*name).into(),
            arch: arch.into(),
            from: from.into(),
            to: to.into(),
        })
        .filter(|p| {
            !c.sh(&format!(
                "dnf -q repoquery '{}-{}.{}' 2>/dev/null",
                p.name, p.to, p.arch
            ))
            .stdout
            .trim()
            .is_empty()
        })
        .collect()
}

#[test]
#[ignore = "needs Docker; run with --ignored"]
fn the_approved_version_is_installed_and_not_the_newest() {
    for image in IMAGES {
        let c = Container::start(image);
        let arch = c.sh("uname -m").stdout.trim().to_owned();
        let versions = offered(&c);
        assert!(
            versions.len() >= 3,
            "{image}: need three versions, have {versions:?}"
        );
        let n = versions.len();
        // Not the oldest: Amazon Linux still offers a 2022 openssl that
        // nothing current can be installed alongside.
        let (oldest, approved, newest) = (&versions[n - 3], &versions[n - 2], &versions[n - 1]);

        // Move the rest of the family (fips providers etc.) to `oldest` too.
        let setup = c.sh(&back_to(oldest));
        assert_eq!(setup.code, 0, "{image}: {}{}", setup.stdout, setup.stderr);

        // Approve the family plus whatever dnf says moves with it. The first
        // simulation tells us what that is.
        let mut pins = family(&c, &arch, oldest, approved);
        let probe = c.exec("dnf", &simulate_args(&pins.iter().collect::<Vec<_>>()));
        for row in updawg_backends::dnf::parse_transaction(&probe.stdout) {
            if row.section == "Upgrading" && !pins.iter().any(|p| p.name == row.name) {
                pins.push(Pin {
                    name: row.name,
                    arch: row.arch,
                    from: oldest.clone(),
                    to: row.version,
                });
            }
        }

        let before = c.versions(&pins);
        let todo =
            still_to_do(&pins, &before).unwrap_or_else(|e| panic!("{image}: {e} with {before:?}"));
        let simulated = c.exec("dnf", &simulate_args(&todo));
        check_transaction(&todo, &simulated)
            .unwrap_or_else(|e| panic!("{image}: {e}\n{}", simulated.stdout));

        let installed = c.exec("dnf", &install_args(&todo));
        assert_eq!(
            installed.code, 0,
            "{image}: {}{}",
            installed.stdout, installed.stderr
        );
        let after = c.versions(&pins);
        let changed = changes(&todo, &after).expect("at the approved version");
        for change in &changed {
            assert_eq!(&change.to, approved, "{image}: {}", change.name);
        }
        eprintln!(
            "{image}: {} package(s) {oldest} -> {approved}, with {newest} on offer",
            changed.len()
        );
        assert!(still_to_do(&pins, &after).expect("done").is_empty());
    }
}

#[test]
#[ignore = "needs Docker; run with --ignored"]
fn half_an_approval_and_a_version_that_is_gone_are_refused_before_anything_changes() {
    for image in IMAGES {
        let c = Container::start(image);
        let arch = c.sh("uname -m").stdout.trim().to_owned();
        let versions = offered(&c);
        let n = versions.len();
        let (oldest, approved) = (&versions[n - 3], &versions[n - 2]);
        let setup = c.sh(&back_to(oldest));
        assert_eq!(setup.code, 0, "{image}: {}{}", setup.stdout, setup.stderr);
        let before = c.sh("rpm -qa | sort").stdout;

        // openssl-libs alone: dnf also moves openssl, which isn't approved.
        let half = [Pin {
            name: "openssl-libs".into(),
            arch: arch.clone(),
            from: oldest.clone(),
            to: approved.clone(),
        }];
        let todo = still_to_do(&half, &c.versions(&half)).expect("todo");
        match check_transaction(&todo, &c.exec("dnf", &simulate_args(&todo))) {
            Err(BackendError::Refused(why)) => {
                assert!(why.contains("nobody approved"), "{image}: {why}");
                eprintln!("{image}: refused: {why}");
            }
            other => panic!("{image}: {other:?}"),
        }

        let gone = [Pin {
            to: "1:0.0.1-1".into(),
            ..half[0].clone()
        }];
        let todo = still_to_do(&gone, &c.versions(&gone)).expect("todo");
        match check_transaction(&todo, &c.exec("dnf", &simulate_args(&todo))) {
            Err(BackendError::Refused(why)) => {
                assert!(why.contains("cannot be installed"), "{image}: {why}");
            }
            other => panic!("{image}: {other:?}"),
        }

        assert_eq!(
            c.sh("rpm -qa | sort").stdout,
            before,
            "{image}: something changed"
        );
    }
}
