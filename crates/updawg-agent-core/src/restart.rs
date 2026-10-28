//! Restarting after a job that replaced the agent's own executable.
//!
//! When a job upgrades `updawg-agent`, apt or dnf runs as a child of `updawgd`
//! in its control group, so a `systemctl try-restart` from the package scripts
//! would kill the package manager mid-install, along with the unreported job.
//! The scripts (`packaging/nfpm/postinstall.sh`) therefore skip the restart
//! when `updawgd` is one of their ancestors, and the agent restarts itself
//! once the job has been reported.

/// Exit code used to get restarted: `EX_TEMPFAIL`. Any non-zero code works
/// with `Restart=on-failure`; this one is recognisable in `systemctl status`.
pub const EXIT_TO_RESTART: i32 = 75;

/// Whether `/proc/self/exe`, as read, names a file that has been replaced.
///
/// dpkg and rpm install a new file by renaming it over the old one, so the
/// running process is left holding an unlinked inode, which the kernel shows
/// as the old path with ` (deleted)` after it.
#[must_use]
pub fn is_replaced(exe_link: &str) -> bool {
    exe_link.ends_with(" (deleted)")
}

/// Whether this process's own executable has been replaced on disk.
#[must_use]
pub fn executable_replaced() -> bool {
    std::fs::read_link("/proc/self/exe").is_ok_and(|path| is_replaced(&path.to_string_lossy()))
}

/// Exits so the new binary gets started, if the executable was replaced.
///
/// Only under systemd (detected via `INVOCATION_ID`); elsewhere nothing would
/// start the agent again.
pub fn restart_if_replaced() {
    if !executable_replaced() {
        return;
    }
    if std::env::var_os("INVOCATION_ID").is_none() {
        tracing::warn!(
            "the agent's executable was replaced and nothing would start the new one; restart updawgd to run it"
        );
        return;
    }
    tracing::info!("the agent's executable was replaced; exiting so systemd starts the new one");
    std::process::exit(EXIT_TO_RESTART);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unlinked_executable_reads_as_replaced() {
        assert!(is_replaced("/usr/bin/updawgd (deleted)"));
        assert!(!is_replaced("/usr/bin/updawgd"));
        assert!(!is_replaced("/opt/deleted/updawgd"));
    }
}
