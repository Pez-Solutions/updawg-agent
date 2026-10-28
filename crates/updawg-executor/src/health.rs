//! Health checks, run after every mutating job.
//!
//! A failed check halts a rollout, so a check that can't run counts as
//! failed: missing `systemctl`, connection refused, command not found, or a
//! timeout.
//!
//! Checks are only read from the host's `agent.toml`; the server can't add
//! any. Otherwise `command` checks would let the server run arbitrary code.

use std::time::{Duration, Instant};

/// A check from `agent.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub kind: CheckKind,
    /// Enforced by the agent, since a hung service tends to hang its check.
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckKind {
    /// `systemctl is-active` says `active`.
    Systemd { unit: String },
    /// A GET returns exactly `expect_status`. Redirects aren't followed and
    /// proxies aren't used, so the service itself is what gets checked.
    Http { url: String, expect_status: u16 },
    /// The program exits 0. Run directly from argv, not through a shell.
    Command { argv: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub duration: Duration,
    /// Short, human-readable reason or note.
    pub detail: Option<String>,
}

/// Runs the checks sequentially, in config order. Running them in parallel
/// could add load to a service that is already struggling.
pub async fn run_all(checks: &[Check]) -> Vec<CheckResult> {
    let mut results = Vec::with_capacity(checks.len());
    for check in checks {
        results.push(run(check).await);
    }
    results
}

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

async fn attempt(kind: &CheckKind) -> Result<Option<String>, String> {
    match kind {
        CheckKind::Systemd { unit } => {
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
            // the detail is sent to the server, so strip secrets from the URL
            let shown = shown_url(url);
            let response = client
                .get(url)
                .send()
                .await
                .map_err(|e| format!("{shown}: {}", short(&e)))?;
            let status = response.status().as_u16();
            if status == *expect_status {
                Ok(None)
            } else {
                Err(format!(
                    "{shown} answered {status}, expected {expect_status}"
                ))
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

/// `kill_on_drop` so that hitting the timeout actually kills the process.
async fn output(program: &str, args: &[String]) -> Result<std::process::Output, String> {
    tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| format!("could not run {program}: {e}"))
}

/// The URL with `user:password@`, `?query` and `#fragment` removed, since
/// that is where health endpoint tokens usually go. Safe to send off the
/// host.
fn shown_url(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let shown = if scheme.is_empty() {
        format!("{host}/{path}")
    } else {
        format!("{scheme}://{host}/{path}")
    };
    shown.trim_end_matches('/').to_owned()
}

/// Innermost cause of a reqwest error (like "Connection refused"). The full
/// chain is too long for a report.
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

    #[test]
    fn a_failed_http_check_names_its_url_without_credentials() {
        assert_eq!(
            shown_url("https://ops:hunter2@127.0.0.1:8080/health?token=abc#x"),
            "https://127.0.0.1:8080/health"
        );
        assert_eq!(shown_url("http://localhost/"), "http://localhost");
        assert_eq!(
            shown_url("localhost:9000/ready?k=v"),
            "localhost:9000/ready"
        );
    }

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
        // bind and drop, so the port is almost certainly closed
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
