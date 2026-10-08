//! Volatile host state: what is true right now.
//!
//! Small on purpose. This rides on every check-in, which at fleet scale is
//! roughly nine hundred a second, so nothing goes in here that is not worth
//! that.
//!
//! # "I could not tell" is a third answer
//!
//! Whether a reboot is pending is the most consequential thing in this module,
//! and the mechanisms for answering it are uneven across distributions: Debian
//! and Ubuntu drop a file, Red Hat wants a tool from `dnf-utils` that is often
//! not installed. A host where the question cannot be answered is not a host
//! where the answer is no, so [`RebootRequired`] has three variants and the
//! unknown one survives all the way up rather than being flattened into
//! `false` somewhere quiet.

use crate::{Collector, Result, StateCollector as StateCollectorTrait, platform};
use async_trait::async_trait;
use platform::Root;
use updawg_protocol::HostMetrics;
/// Whether this host needs a reboot: the wire's own three values since
/// protocol 0.4 (DAWG-210), so nothing between here and the database
/// flattens `Unknown`.
pub use updawg_protocol::RebootRequired;

/// Cheap state, collected on every check-in.
#[derive(Debug, Clone)]
pub struct HostState {
    pub boot_id: String,
    pub uptime_s: u64,
    pub reboot_required: RebootRequired,
    pub services_needing_restart: Vec<String>,
    pub metrics: HostMetrics,
}

impl Default for HostState {
    fn default() -> Self {
        Self {
            boot_id: String::new(),
            uptime_s: 0,
            reboot_required: RebootRequired::default(),
            services_needing_restart: Vec::new(),
            // Written out rather than derived: `HostMetrics` comes from the
            // published protocol crate and does not implement `Default`.
            metrics: HostMetrics {
                load1: 0.0,
                mem_used_pct: 0.0,
                root_free_bytes: 0,
            },
        }
    }
}

/// Reads volatile host state.
#[derive(Debug, Clone, Default)]
pub struct SystemState {
    root: Root,
    /// Family, decided once. Choosing the reboot-required mechanism means
    /// knowing the distribution, and re-reading `/etc/os-release` every
    /// fifty-five seconds to learn something that cannot change is waste.
    family: Family,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Family {
    Debian,
    Rhel,
    #[default]
    Unknown,
}

impl SystemState {
    /// # Errors
    /// Fails if `/etc/os-release` cannot be read. Everything else degrades.
    pub fn new(root: Root) -> Result<Self> {
        let family = match platform::os_release(&root) {
            Ok(os) if os.is_debian_like() => Family::Debian,
            Ok(os) if os.is_rhel_like() => Family::Rhel,
            _ => Family::Unknown,
        };
        Ok(Self { root, family })
    }

    /// Gather the current state.
    ///
    /// # Errors
    /// Fails only if the boot id cannot be read, which would mean `/proc` is
    /// not mounted and nothing else here is trustworthy either.
    pub fn gather(&self) -> Result<HostState> {
        // One `needrestart` run answers both questions, and it scans `/proc` —
        // not free, and this runs on every check-in. Asking twice would be
        // twice the cost for the same answer.
        let report = self.needrestart();

        Ok(HostState {
            boot_id: platform::boot_id(&self.root)?,
            uptime_s: self.uptime_s().unwrap_or_default(),
            reboot_required: self.reboot_required(report.as_ref()),
            services_needing_restart: report.map(|r| r.services).unwrap_or_default(),
            metrics: self.metrics(),
        })
    }

    /// Run `needrestart -b` once, if this is a host that has it.
    fn needrestart(&self) -> Option<NeedRestart> {
        if !self.root.is_live() {
            return None;
        }
        match self.family {
            Family::Debian => platform::run("needrestart", &["-b"]).map(|o| parse_needrestart(&o)),
            Family::Rhel => platform::run("needs-restarting", &["-s"]).map(|o| NeedRestart {
                kernel_status: None,
                services: parse_needs_restarting(&o),
            }),
            Family::Unknown => None,
        }
    }

    /// Whether a reboot is pending.
    ///
    /// Debian and Ubuntu are easy: the file either exists or it does not, and
    /// that is a complete answer. Red Hat needs `needs-restarting`, which ships
    /// in `dnf-utils` and is frequently absent — in which case the honest
    /// answer is that we do not know.
    fn reboot_required(&self, report: Option<&NeedRestart>) -> RebootRequired {
        // The file check is cheap, harmless, and right on any host that has it,
        // so it is worth trying regardless of what family we think we are.
        if self.root.exists("run/reboot-required") || self.root.exists("var/run/reboot-required") {
            return RebootRequired::Yes;
        }

        // `needrestart` computes the answer rather than trusting a flag file an
        // apt hook was supposed to write, so where both exist it is the better
        // signal — a kernel upgraded by something that skipped the hook still
        // shows up here.
        if let Some(status) = report.and_then(|r| r.kernel_status) {
            return match status {
                // 0 is "could not tell", which is not "no".
                0 => RebootRequired::Unknown,
                1 => RebootRequired::No,
                // 2 is an ABI-compatible kernel upgrade, 3 a version upgrade.
                _ => RebootRequired::Yes,
            };
        }

        if self.family == Family::Debian {
            return RebootRequired::No;
        }

        if self.family == Family::Rhel && self.root.is_live() {
            // `needs-restarting -r` answers in exit codes: 0 no, 1 yes.
            return match platform::run_status("needs-restarting", &["-r"]) {
                Some(0) => RebootRequired::No,
                Some(1) => RebootRequired::Yes,
                _ => {
                    tracing::debug!(
                        "needs-restarting is unavailable; cannot tell whether a reboot is pending"
                    );
                    RebootRequired::Unknown
                }
            };
        }

        RebootRequired::Unknown
    }

    fn uptime_s(&self) -> Option<u64> {
        let raw = self.root.read("proc/uptime")?;
        let seconds: f64 = raw.split_whitespace().next()?.parse().ok()?;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Some(seconds as u64)
    }

    fn metrics(&self) -> HostMetrics {
        HostMetrics {
            load1: self.load1().unwrap_or_default(),
            mem_used_pct: self.mem_used_pct().unwrap_or_default(),
            root_free_bytes: self.root_free_bytes().unwrap_or_default(),
        }
    }

    fn load1(&self) -> Option<f32> {
        self.root
            .read("proc/loadavg")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    }

    /// Used memory as a percentage, from `MemAvailable` rather than `MemFree`.
    ///
    /// `MemFree` counts the page cache as used, which on a healthy server that
    /// has been up for a month reads as 98% and means nothing. `MemAvailable`
    /// is the kernel's own estimate of what a new allocation could actually
    /// get, which is the number an operator wants.
    fn mem_used_pct(&self) -> Option<f32> {
        let raw = self.root.read("proc/meminfo")?;
        let total = meminfo_kb(&raw, "MemTotal")?;
        let available = meminfo_kb(&raw, "MemAvailable")?;
        if total == 0 {
            return None;
        }
        #[allow(clippy::cast_precision_loss)]
        Some(((total.saturating_sub(available)) as f32 / total as f32) * 100.0)
    }

    /// Free bytes on the root filesystem.
    ///
    /// Through `df` rather than `statvfs`: the workspace forbids `unsafe`, so
    /// calling the syscall directly would mean taking on a dependency for one
    /// number. `df -P` output is specified by POSIX, and this runs once per
    /// check-in.
    fn root_free_bytes(&self) -> Option<u64> {
        if !self.root.is_live() {
            return None;
        }
        parse_df(&platform::run("df", &["-P", "/"])?)
    }
}

/// What `needrestart -b` had to say.
///
/// Services running against libraries that have been replaced on disk, plus its
/// own verdict on the kernel. Both tools this module uses are optional, and an
/// empty list from a host with neither is indistinguishable from an empty list
/// from a host that is fine — a real weakness, but reimplementing a scan of
/// `/proc/*/maps` here would duplicate what these tools exist to do, badly.
#[derive(Debug, Clone, Default)]
struct NeedRestart {
    /// `NEEDRESTART-KSTA`: 0 unknown, 1 current, 2 ABI upgrade pending,
    /// 3 version upgrade pending.
    kernel_status: Option<u8>,
    services: Vec<String>,
}

/// Parse the batch-mode output: `KEY: value` lines, most of which we ignore.
fn parse_needrestart(output: &str) -> NeedRestart {
    let mut services = Vec::new();
    let mut kernel_status = None;

    for line in output.lines() {
        let line = line.trim();
        if let Some(svc) = line.strip_prefix("NEEDRESTART-SVC:") {
            let svc = svc.trim();
            if is_reportable_service(svc) {
                services.push(svc.to_string());
            }
        } else if let Some(ksta) = line.strip_prefix("NEEDRESTART-KSTA:") {
            kernel_status = ksta.trim().parse().ok();
        }
    }

    services.sort();
    services.dedup();
    NeedRestart {
        kernel_status,
        services,
    }
}

/// One service name per line, sometimes with a leading `1 : ` counter.
fn parse_needs_restarting(output: &str) -> Vec<String> {
    let mut services: Vec<String> = output
        .lines()
        .map(|l| l.rsplit(" : ").next().unwrap_or(l).trim())
        .filter(|l| !l.starts_with("Updating") && is_reportable_service(l))
        .map(ToString::to_string)
        .collect();
    services.sort();
    services.dedup();
    services
}

/// Whether a unit needing a restart is reported (DAWG-171).
///
/// System services only. `user@1000.service` is somebody's session manager:
/// it names a user who is logged in, which the agent promises never to send,
/// and it is not Updawg's to restart either — it goes when they log out.
fn is_reportable_service(unit: &str) -> bool {
    unit.ends_with(".service")
        && !unit.starts_with("user@")
        && !unit.starts_with("user-runtime-dir@")
}

/// Pull a `MemTotal:  16316816 kB` value out of `/proc/meminfo`.
fn meminfo_kb(raw: &str, key: &str) -> Option<u64> {
    raw.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.strip_prefix(':')?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

/// The `Available` column of `df -P`, in 1024-byte blocks.
fn parse_df(output: &str) -> Option<u64> {
    let line = output.lines().nth(1)?;
    let blocks: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
    Some(blocks.saturating_mul(1024))
}

#[async_trait]
impl Collector for SystemState {
    fn name(&self) -> &'static str {
        "system-state"
    }

    async fn is_available(&self) -> bool {
        platform::boot_id(&self.root).is_ok()
    }
}

#[async_trait]
impl StateCollectorTrait for SystemState {
    async fn state(&self) -> Result<HostState> {
        self.gather()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeHost;

    #[tokio::test]
    async fn a_debian_host_reports_its_state() {
        let host = FakeHost::debian();
        let state = SystemState::new(host.root())
            .unwrap()
            .state()
            .await
            .unwrap();

        assert_eq!(state.boot_id, "b81e5c7a-1f2d-4c3b-9a8e-0d1f2a3b4c5d");
        assert_eq!(state.uptime_s, 864_000);
        assert_eq!(state.reboot_required, RebootRequired::No);
        assert!((state.metrics.load1 - 0.42).abs() < 0.001);
    }

    #[tokio::test]
    async fn the_reboot_required_flag_file_is_honoured() {
        let host = FakeHost::debian();
        host.write("run/reboot-required", "*** System restart required ***\n");
        let state = SystemState::new(host.root())
            .unwrap()
            .state()
            .await
            .unwrap();
        assert_eq!(state.reboot_required, RebootRequired::Yes);
        assert!(state.reboot_required.is_yes());
    }

    #[tokio::test]
    async fn the_older_var_run_path_still_works() {
        let host = FakeHost::debian();
        host.write("var/run/reboot-required", "x\n");
        let state = SystemState::new(host.root())
            .unwrap()
            .state()
            .await
            .unwrap();
        assert_eq!(state.reboot_required, RebootRequired::Yes);
    }

    /// The point of the tri-state. A Red Hat host without `needs-restarting`
    /// cannot answer, and saying "no reboot needed" would be a lie that reads
    /// exactly like good news.
    #[tokio::test]
    async fn a_rhel_host_that_cannot_answer_says_unknown_not_no() {
        let host = FakeHost::rocky();
        let state = SystemState::new(host.root())
            .unwrap()
            .state()
            .await
            .unwrap();
        assert_eq!(state.reboot_required, RebootRequired::Unknown);
        assert!(!state.reboot_required.is_known());
        assert!(!state.reboot_required.is_yes());
    }

    /// DAWG-171: a user's session manager names a logged-in user, and is
    /// never reported, from either tool.
    #[test]
    fn a_users_session_manager_is_not_reported() {
        let report = parse_needrestart(
            "NEEDRESTART-KSTA: 1\nNEEDRESTART-SVC: nginx.service\n\
             NEEDRESTART-SVC: user@1000.service\nNEEDRESTART-SVC: user-runtime-dir@1000.service\n",
        );
        assert_eq!(report.services, vec!["nginx.service".to_owned()]);
        assert_eq!(
            parse_needs_restarting("sshd.service\nuser@1000.service\n"),
            vec!["sshd.service".to_owned()]
        );
    }

    #[test]
    fn unknown_is_the_default_so_a_dropped_field_fails_safe() {
        assert_eq!(RebootRequired::default(), RebootRequired::Unknown);
        assert_eq!(
            HostState::default().reboot_required,
            RebootRequired::Unknown
        );
    }

    #[tokio::test]
    async fn memory_is_measured_from_what_is_available_not_what_is_free() {
        let host = FakeHost::debian();
        // 16 GB total, 12 GB available: 25% used. Measuring from MemFree
        // (1 GB) would report 94% and panic somebody for no reason.
        host.write(
            "proc/meminfo",
            "MemTotal:       16777216 kB\nMemFree:         1048576 kB\nMemAvailable:   12582912 kB\n",
        );
        let state = SystemState::new(host.root())
            .unwrap()
            .state()
            .await
            .unwrap();
        assert!(
            (state.metrics.mem_used_pct - 25.0).abs() < 0.01,
            "got {}",
            state.metrics.mem_used_pct
        );
    }

    #[tokio::test]
    async fn a_missing_source_degrades_to_a_default_rather_than_failing() {
        let host = FakeHost::debian();
        std::fs::remove_file(host.root().join("proc/meminfo")).unwrap();
        std::fs::remove_file(host.root().join("proc/loadavg")).unwrap();
        std::fs::remove_file(host.root().join("proc/uptime")).unwrap();

        let state = SystemState::new(host.root())
            .unwrap()
            .state()
            .await
            .unwrap();
        assert_eq!(state.uptime_s, 0);
        assert!(state.metrics.mem_used_pct.abs() < f32::EPSILON);
        // The boot id is still there, so the check-in is still worth sending.
        assert!(!state.boot_id.is_empty());
    }

    #[tokio::test]
    async fn without_proc_there_is_nothing_worth_reporting() {
        let host = FakeHost::debian();
        std::fs::remove_file(host.root().join("proc/sys/kernel/random/boot_id")).unwrap();
        assert!(
            SystemState::new(host.root())
                .unwrap()
                .state()
                .await
                .is_err()
        );
        assert!(!SystemState::new(host.root()).unwrap().is_available().await);
    }

    /// Real `needrestart -b` output, captured from an Ubuntu 24.04 host —
    /// including the microcode lines a hand-written fixture would have missed.
    /// Nothing needed restarting there, which is the ordinary case and the one
    /// most likely to be got wrong by a parser that only ever saw a failure.
    #[test]
    fn real_needrestart_output_with_nothing_to_do_is_read_as_nothing_to_do() {
        let output = "NEEDRESTART-VER: 3.6\n\
                      NEEDRESTART-KCUR: 6.8.0-139-generic\n\
                      NEEDRESTART-KEXP: 6.8.0-139-generic\n\
                      NEEDRESTART-KSTA: 1\n\
                      NEEDRESTART-UCSTA: 1\n\
                      NEEDRESTART-UCCUR: 0x08701034\n\
                      NEEDRESTART-UCEXP: 0x08701034\n";
        let report = parse_needrestart(output);
        assert!(report.services.is_empty());
        assert_eq!(report.kernel_status, Some(1));
    }

    #[test]
    fn needrestart_output_is_parsed_into_service_names() {
        let output = "NEEDRESTART-VER: 3.6\n\
                      NEEDRESTART-KSTA: 1\n\
                      NEEDRESTART-SVC: nginx.service\n\
                      NEEDRESTART-SVC: ssh.service\n\
                      NEEDRESTART-SVC: nginx.service\n";
        let report = parse_needrestart(output);
        assert_eq!(report.services, vec!["nginx.service", "ssh.service"]);
    }

    /// `needrestart` computes the kernel answer rather than trusting a flag
    /// file an apt hook was supposed to write. A kernel upgraded by something
    /// that skipped the hook is exactly the case the flag file misses.
    #[test]
    fn a_pending_kernel_upgrade_is_a_reboot_even_without_the_flag_file() {
        let host = FakeHost::ubuntu();
        let collector = SystemState::new(host.root()).unwrap();

        for (status, expected) in [
            (0, RebootRequired::Unknown),
            (1, RebootRequired::No),
            (2, RebootRequired::Yes),
            (3, RebootRequired::Yes),
        ] {
            let report = NeedRestart {
                kernel_status: Some(status),
                services: vec![],
            };
            assert_eq!(
                collector.reboot_required(Some(&report)),
                expected,
                "KSTA {status}"
            );
        }
    }

    /// The flag file is a definite yes and is checked first, so a stale
    /// `needrestart` verdict cannot talk us out of a reboot the system already
    /// knows it wants.
    #[test]
    fn the_flag_file_wins_over_a_needrestart_all_clear() {
        let host = FakeHost::ubuntu();
        host.write("run/reboot-required", "*** System restart required ***\n");
        let collector = SystemState::new(host.root()).unwrap();
        let report = NeedRestart {
            kernel_status: Some(1),
            services: vec![],
        };
        assert_eq!(
            collector.reboot_required(Some(&report)),
            RebootRequired::Yes
        );
    }

    #[test]
    fn needs_restarting_output_is_parsed_into_service_names() {
        let output = "Updating Subscription Management repositories.\n\
                      1 : /usr/lib/systemd/systemd --switched-root\n\
                      sshd.service\n\
                      nginx.service\n";
        assert_eq!(
            parse_needs_restarting(output),
            vec!["nginx.service", "sshd.service"]
        );
    }

    /// Real output from two live hosts: an Ubuntu 24.04 server and a Debian 13
    /// Raspberry Pi. Device names, block counts and column widths all differ,
    /// which is the part a hand-written fixture quietly gets uniform.
    #[test]
    fn real_df_and_meminfo_output_parses() {
        let ubuntu_df = "Filesystem     1024-blocks      Used Available Capacity Mounted on\n\
                         /dev/sdm2        487283712 213757104 269177904      45% /\n";
        assert_eq!(parse_df(ubuntu_df), Some(269_177_904 * 1024));

        let pi_df = "Filesystem     1024-blocks    Used Available Capacity Mounted on\n\
                     /dev/mmcblk0p2   122379116 6379760 110981144       6% /\n";
        assert_eq!(parse_df(pi_df), Some(110_981_144 * 1024));

        // A 64 GB host, with the Buffers and Cached lines that follow in real
        // /proc/meminfo and must not be mistaken for the fields we want.
        let meminfo = "MemTotal:       65785580 kB\n\
                       MemFree:         5810464 kB\n\
                       MemAvailable:   22695772 kB\n\
                       Buffers:            1356 kB\n\
                       Cached:         17449068 kB\n";
        assert_eq!(meminfo_kb(meminfo, "MemTotal"), Some(65_785_580));
        assert_eq!(meminfo_kb(meminfo, "MemAvailable"), Some(22_695_772));
        assert_eq!(meminfo_kb(meminfo, "MemFree"), Some(5_810_464));
    }

    #[test]
    fn df_output_is_read_as_bytes() {
        let output = "Filesystem     1024-blocks     Used Available Capacity Mounted on\n\
                      /dev/sda1         41020640 12345678  26584962      32% /\n";
        assert_eq!(parse_df(output), Some(26_584_962 * 1024));
        assert_eq!(parse_df("Filesystem\n"), None);
    }

    #[test]
    fn meminfo_values_are_read_in_kilobytes() {
        let raw = "MemTotal:       16777216 kB\nMemAvailable:   12582912 kB\n";
        assert_eq!(meminfo_kb(raw, "MemTotal"), Some(16_777_216));
        assert_eq!(meminfo_kb(raw, "MemAvailable"), Some(12_582_912));
        assert_eq!(meminfo_kb(raw, "Nonsense"), None);
    }
}
