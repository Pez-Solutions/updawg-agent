//! Health checks, run after every mutating job (DAWG-104).
//!
//! These are what halt a rollout, so **a check that cannot run fails**: a
//! missing `systemctl`, a refused connection, a command that is not there or
//! that runs past its timeout. "I could not tell" and "it is fine" are very
//! different answers, and only one of them lets the next host go ahead.
//!
//! Every check comes from the host's own `agent.toml`. Nothing the server
//! sends can add one, which is what keeps `command` checks from being a way to
//! run arbitrary code on a host: the server can make an agent run the checks
//! its operator wrote, and nothing else.

use std::time::{Duration, Instant};

/// One check, as `agent.toml` configured it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub kind: CheckKind,
    /// Enforced here, not trusted to the thing being checked: a hung service
    /// is exactly when a check would otherwise hang too.
    pub timeout: Duration,
}

/// The three types `[[health_check]]` supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckKind {
    /// `systemctl is-active` says `active`.
    Systemd { unit: String },
    /// A GET answers with exactly `expect_status`. Redirects are not
    /// followed and no proxy is used: a health check asks the service, not
    /// whatever sits in front of it.
    Http { url: String, expect_status: u16 },
    /// The program exits 0. An argument vector, never a shell string.
    Command { argv: Vec<String> },
}

/// How one check went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub duration: Duration,
    /// Why it failed, or what it saw. Short: it is shown to a person.
    pub detail: Option<String>,
}

/// Run every check, in the order configured, one at a time.
///
/// One at a time because a check can be the load that tips a struggling
/// service over, and because the order an operator wrote is often the order
/// that makes the failures readable: database, then the app that needs it.
pub async fn run_all(checks: &[Check]) -> Vec<CheckResult> {
    let mut results = Vec::with_capacity(checks.len());
    for check in checks {
        results.push(run(check).await);
    }
    results
}

/// Run one check under its timeout.
pub async fn run(check: &Check) -> CheckResult {
    let started = Instant::now();
    let outcome = tokio::time::timeout(check.timeout, attempt(&check.kind)).await;
    let (passed, detail) = match outcome {
        Ok(Ok(detail)) => (true, detail),
        Ok(Err(why)) => (false, Some(why)),
        Err(_) => (
            false,
            Some(format!("no answer within {}s", check.timeout.as_secs_f32())),
        ),
    };
    CheckResult {
        name: check.name.clone(),
        passed,
        duration: started.elapsed(),
        detail,
    }
}

/// `Ok` with an optional note on success, `Err` with why on failure.
async fn attempt(kind: &CheckKind) -> Result<Option<String>, String> {
    match kind {
        CheckKind::Systemd { unit } => {
            // `is-active` prints the state and exits 0 only for `active`.
            let out = output("systemctl", &["is-active".to_owned(), unit.clone()]).await?;
            let state = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if out.status.success() {
                Ok(None)
            } else {
                Err(format!(
                    "{unit} is {}",
                    if state.is_empty() {
                        "not active"
                    } else {
                        &state
                    }
                ))
            }
        }
        CheckKind::Http { url, expect_status } => {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .map_err(|e| format!("could not build an HTTP client: {e}"))?;
            let response = client
                .get(url)
                .send()
                .await
                .map_err(|e| format!("{url}: {}", short(&e)))?;
            let status = response.status().as_u16();
            if status == *expect_status {
                Ok(None)
            } else {
                Err(format!("{url} answered {status}, expected {expect_status}"))
            }
        }
        CheckKind::Command { argv } => {
            let Some((program, args)) = argv.split_first() else {
                return Err("the command is empty".to_owned());
            };
            let out = output(program, args).await?;
            if out.status.success() {
                Ok(None)
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let last = stderr.lines().rev().find(|l| !l.trim().is_empty());
                Err(match (out.status.code(), last) {
                    (Some(code), Some(line)) => format!("exited {code}: {}", line.trim()),
                    (Some(code), None) => format!("exited {code}"),
                    (None, _) => "killed by a signal".to_owned(),
                })
            }
        }
    }
}

/// Run a program to completion. `kill_on_drop`, so the timeout around this
/// actually stops it rather than leaving it running behind the agent.
async fn output(program: &str, args: &[String]) -> Result<std::process::Output, String> {
    tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| format!("could not run {program}: {e}"))
}

/// reqwest's errors carry a chain; the innermost cause is the useful part
/// ("Connection refused"), and the full chain is too long for a report.
fn short(error: &reqwest::Error) -> String {
    let mut source: &dyn std::error::Error = error;
    while let Some(next) = source.source() {
        source = next;
    }
    source.to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn command(argv: &[&str], timeout_ms: u64) -> Check {
        Check {
            name: "t".into(),
            kind: CheckKind::Command {
                argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            },
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    #[tokio::test]
    async fn a_command_that_exits_zero_passes_and_one_that_does_not_says_how() {
        assert!(run(&command(&["true"], 5_000)).await.passed);
        let failed = run(&command(&["sh", "-c", "echo broken >&2; exit 3"], 5_000)).await;
        assert!(!failed.passed);
        assert_eq!(failed.detail.as_deref(), Some("exited 3: broken"));
    }

    #[tokio::test]
    async fn a_check_that_hangs_fails_at_its_timeout() {
        let started = Instant::now();
        let hung = run(&command(&["sleep", "30"], 200)).await;
        assert!(!hung.passed);
        assert!(hung.detail.unwrap().starts_with("no answer within"));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the timeout was not enforced"
        );
    }

    #[tokio::test]
    async fn a_check_that_cannot_run_fails_rather_than_passing() {
        let missing = run(&command(&["/nonexistent/updawg-check"], 5_000)).await;
        assert!(!missing.passed);
        assert!(missing.detail.unwrap().starts_with("could not run"));
        let empty = run(&command(&[], 5_000)).await;
        assert!(!empty.passed);
    }

    #[tokio::test]
    async fn an_http_check_wants_exactly_the_status_it_was_told() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0_u8; 1024];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let status = if request.starts_with("GET /ok ") {
                    "200 OK"
                } else {
                    "503 Service Unavailable"
                };
                let _ = socket
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
            }
        });
        let http = |path: &str| Check {
            name: "http".into(),
            kind: CheckKind::Http {
                url: format!("http://127.0.0.1:{port}{path}"),
                expect_status: 200,
            },
            timeout: Duration::from_secs(5),
        };
        assert!(run(&http("/ok")).await.passed);
        let down = run(&http("/down")).await;
        assert!(!down.passed);
        assert!(down.detail.unwrap().ends_with("answered 503, expected 200"));
    }

    #[tokio::test]
    async fn a_refused_connection_fails_with_the_reason() {
        // Bind and drop, so the port is very probably closed.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let refused = run(&Check {
            name: "http".into(),
            kind: CheckKind::Http {
                url: format!("http://127.0.0.1:{port}/"),
                expect_status: 200,
            },
            timeout: Duration::from_secs(5),
        })
        .await;
        assert!(!refused.passed);
    }

    #[tokio::test]
    async fn checks_run_in_the_order_written() {
        let results = run_all(&[command(&["true"], 1_000), command(&["false"], 1_000)]).await;
        assert_eq!(
            results.iter().map(|r| r.passed).collect::<Vec<_>>(),
            [true, false]
        );
    }
}
