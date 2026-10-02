//! Restarting after a job that replaced the agent's own executable.
//!
//! ⚠️ The package's own scripts used to restart `updawgd` on an upgrade, which
//! is right from a shell and fatal from inside a job: apt or dnf runs as a
//! child of `updawgd`, in its control group, so `systemctl try-restart`
//! killed the package manager part-way through installing the agent — and
//! the job with it, unreported. An `apply_updates` that included
//! `updawg-agent`, or any release upgrade (`apt full-upgrade` takes the agent
//! along from pkg.updawg.net), would have done it.
//!
//! So the scripts leave a running agent alone when they find `updawgd` among
//! their ancestors (packaging/nfpm/postinstall.sh), and the agent restarts
//! itself instead — after the job is reported, which is the part that has to
//! survive.

/// What the process exits with to be restarted: `EX_TEMPFAIL`. Anything
/// non-zero restarts under the unit's `Restart=on-failure`; this one says why
/// in `systemctl status`.
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

/// Exit to be started again as the new binary, if there is one and something
/// will start it.
///
/// Only under systemd, which sets `INVOCATION_ID` for every service it runs:
/// anywhere else an exit is just a stopped agent.
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
        // A path that merely mentions the word is not one.
        assert!(!is_replaced("/opt/deleted/updawgd"));
    }
}
