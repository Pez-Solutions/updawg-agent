//! Applying exact versions against real apt, in a container (DAWG-102).
//!
//! `#[ignore]`d like the other Docker canaries; run with
//!
//! ```text
//! cargo test -p updawg-backends --test apt_apply_live -- --ignored --nocapture
//! ```
//!
//! The command lines are the ones [`install_args`] builds — not a hand-written
//! copy — so what is tested here is what the agent will run. The packages are
//! made up with `dpkg-deb` in a local repository, so the scenarios do not
//! depend on what the image happens to be behind on: `updawgtest` 1.0 is
//! installed, and the repository offers 2.0 **and** 3.0. A job approved for
//! 1.0 → 2.0 must install 2.0, not the newer 3.0. That is the whole point.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    unreachable_pub
)]

use updawg_backends::{
    BackendError, Pin,
    apt::{
        Ran, changes, check_simulation, install_args, parse_versions, simulate_args, still_to_do,
    },
};

const IMAGES: &[&str] = &["debian:13", "debian:12", "ubuntu:24.04"];

const SETUP: &str = r#"
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq dpkg-dev >/dev/null 2>&1
mk() {
  d=/tmp/build/$1-$2
  rm -rf "$d"; mkdir -p "$d/DEBIAN"
  { echo "Package: $1"; echo "Version: $2"; echo "Architecture: all"
    echo "Maintainer: t <t@example.com>"; echo "Description: t"
    shift 2; for l in "$@"; do echo "$l"; done
  } > "$d/DEBIAN/control"
  dpkg-deb -b "$d" /tmp/repo/$(basename $d).deb >/dev/null
}
mkdir -p /tmp/repo /tmp/build
mk updawgtest 1.0
mk updawgtest 2.0
mk updawgtest 3.0
mk updawgdep 1.0
mk updawgpulls 1.0
mk updawgpulls 2.0 "Depends: updawgdep"
dpkg -i /tmp/repo/updawgtest-1.0.deb /tmp/repo/updawgpulls-1.0.deb >/dev/null
cd /tmp/repo
rm -f updawgtest-1.0.deb updawgpulls-1.0.deb
# `-m`: every version, not only the newest — the test is about choosing.
dpkg-scanpackages -m . /dev/null > Packages 2>/dev/null
echo "deb [trusted=yes] file:/tmp/repo ./" > /etc/apt/sources.list.d/local.list
apt-get update -qq >/dev/null 2>&1
"#;

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("run docker")
}

fn docker_available() -> bool {
    docker(&["version", "--format", "{{.Server.Version}}"])
        .status
        .success()
}

struct Container(String);

impl Container {
    fn start(image: &str) -> Self {
        let out = docker(&["run", "-d", "--rm", image, "sleep", "600"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let id = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        let c = Self(id);
        let setup = c.exec("bash", &["-c".into(), SETUP.into()]);
        assert_eq!(
            setup.code, 0,
            "setup failed: {}{}",
            setup.stdout, setup.stderr
        );
        c
    }

    fn exec(&self, tool: &str, args: &[String]) -> Ran {
        let mut all = vec![
            "exec",
            "-e",
            "DEBIAN_FRONTEND=noninteractive",
            "-e",
            "LC_ALL=C",
            &self.0,
            tool,
        ];
        all.extend(args.iter().map(String::as_str));
        let out = docker(&all);
        Ran {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn versions(&self, names: &[&str]) -> std::collections::BTreeMap<String, String> {
        let mut args = vec![
            "-W".to_owned(),
            "-f=${Package}:${Architecture}\t${Version}\t${db:Status-Status}\n".to_owned(),
        ];
        args.extend(names.iter().map(|&n| n.to_owned()));
        parse_versions(&self.exec("dpkg-query", &args).stdout)
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", &self.0]);
    }
}

fn pin(name: &str, from: &str, to: &str) -> Pin {
    Pin {
        name: name.into(),
        arch: "all".into(),
        from: from.into(),
        to: to.into(),
    }
}

#[test]
#[ignore = "needs Docker; run with --ignored"]
fn the_approved_version_is_installed_and_not_the_newest() {
    assert!(docker_available(), "docker is not available");
    for image in IMAGES {
        let c = Container::start(image);
        let pins = [pin("updawgtest", "1.0", "2.0")];

        let before = c.versions(&["updawgtest"]);
        let todo = still_to_do(&pins, &before).expect("at its from version");
        let simulated = c.exec("apt-get", &simulate_args(&todo));
        check_simulation(&todo, &simulated)
            .unwrap_or_else(|e| panic!("{image}: {e}\n{}", simulated.stdout));

        let installed = c.exec("apt-get", &install_args(&todo));
        assert_eq!(
            installed.code, 0,
            "{image}: {}{}",
            installed.stdout, installed.stderr
        );
        let after = c.versions(&["updawgtest"]);
        let changed = changes(&todo, &after).expect("at the approved version");
        assert_eq!(
            changed[0].to, "2.0",
            "{image}: installed the newest rather than the approved"
        );
        eprintln!("{image}: updawgtest 1.0 -> 2.0, with 3.0 on offer");

        // And a second run finds nothing to do.
        assert!(still_to_do(&pins, &after).expect("done").is_empty());
    }
}

#[test]
#[ignore = "needs Docker; run with --ignored"]
fn what_apt_would_do_beyond_the_approval_is_refused_before_anything_changes() {
    assert!(docker_available(), "docker is not available");
    for image in IMAGES {
        let c = Container::start(image);

        // The approved version is not in the archive.
        let gone = [pin("updawgtest", "1.0", "4.0")];
        let todo = still_to_do(&gone, &c.versions(&["updawgtest"])).expect("todo");
        match check_simulation(&todo, &c.exec("apt-get", &simulate_args(&todo))) {
            Err(BackendError::Refused(why)) => {
                assert!(why.contains("cannot be installed"), "{image}: {why}");
            }
            other => panic!("{image}: {other:?}"),
        }

        // The upgrade drags in a package nobody approved.
        let pulls = [pin("updawgpulls", "1.0", "2.0")];
        let todo = still_to_do(&pulls, &c.versions(&["updawgpulls"])).expect("todo");
        match check_simulation(&todo, &c.exec("apt-get", &simulate_args(&todo))) {
            Err(BackendError::Refused(why)) => {
                assert!(why.contains("updawgdep"), "{image}: {why}");
            }
            other => panic!("{image}: {other:?}"),
        }

        // Nothing changed.
        let now = c.versions(&["updawgtest", "updawgpulls", "updawgdep"]);
        assert_eq!(now.get("updawgtest").map(String::as_str), Some("1.0"));
        assert_eq!(now.get("updawgpulls").map(String::as_str), Some("1.0"));
        assert!(!now.contains_key("updawgdep"), "{image}");
        eprintln!(
            "{image}: refused a missing version and an unapproved dependency, changed nothing"
        );
    }
}
