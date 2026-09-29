//! Third-party repository readiness for a release upgrade (DAWG-149).
//!
//! The failure this catches is the quiet one: a repository the host uses
//! publishes nothing for the release it is moving to, so the upgrade either
//! stops on a missing `Release` file or carries on and leaves that
//! repository's packages behind — old, unmaintained, sometimes removed by the
//! new release's dependencies.
//!
//! For each third-party repository ([`updawg_backends::RepoSource`]), the
//! suite is renamed from this release's codename to the target's —
//! `cloud-sdk-trixie` becomes `cloud-sdk-forky` — and the repository is asked
//! for `dists/<suite>/InRelease`, then `Release`. A suite that does not name a
//! release (`stable`) carries over as it is. Reading a file over HTTP is the
//! only thing this does: it changes nothing on the host, as a preflight must
//! not.
//!
//! Distribution repositories are left to the upgrade itself, which rewrites
//! them; only third-party ones are asked.

use std::time::Duration;
use updawg_protocol::{CheckStatus, PreflightCheck};

/// How long one repository gets to answer. A preflight asks every
/// third-party repository in turn, and a slow mirror must not hold it for
/// minutes.
const TIMEOUT: Duration = Duration::from_secs(15);

/// How many packages to name per repository before saying how many more.
const NAMED: usize = 8;

/// One third-party repository, asked about the target release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub uri: String,
    pub suite: String,
    /// The suite it would be for the target, when the suite names a release.
    pub target_suite: Option<String>,
    pub answer: Answer,
    /// Installed packages that came from it.
    pub packages: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The target's suite exists.
    Published,
    /// It does not: 404 for both `InRelease` and `Release`.
    Missing,
    /// The suite names no release, so it is used as it is.
    NotReleaseSpecific,
    /// Could not find out, and why.
    Unknown(String),
}

pub use updawg_backends::release::{codename_for, target_suite};

/// This host's release codename, from `/etc/os-release`.
fn current_codename(os_release: &str) -> Option<String> {
    let value = |key: &str| {
        os_release.lines().find_map(|l| {
            l.strip_prefix(key)
                .and_then(|v| v.strip_prefix('='))
                .map(|v| v.trim().trim_matches('"').to_owned())
                .filter(|v| !v.is_empty())
        })
    };
    value("VERSION_CODENAME").or_else(|| value("UBUNTU_CODENAME"))
}

/// Ask every third-party repository about `target`.
///
/// # Errors
/// Why no repository could be asked: the package manager could not list
/// them, or either release's codename is unknown.
pub async fn gather(
    backend: Option<&dyn updawg_backends::PackageBackend>,
    target: &str,
) -> Result<Vec<Repo>, String> {
    let backend = backend.ok_or("this host has no package manager the agent can drive")?;
    let os_release = tokio::fs::read_to_string("/etc/os-release")
        .await
        .map_err(|e| format!("reading /etc/os-release: {e}"))?;
    let current =
        current_codename(&os_release).ok_or("/etc/os-release names no release codename")?;
    let wanted = codename_for(target)
        .ok_or_else(|| format!("{target} is not a release this agent knows the codename of"))?;
    let sources = backend.release_sources().await.map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(|e| format!("preparing an HTTP client: {e}"))?;

    let mut repos = Vec::new();
    for source in sources.into_iter().filter(|s| s.third_party) {
        let target_suite = target_suite(&source.suite, &current, &wanted);
        let answer = match &target_suite {
            None => Answer::NotReleaseSpecific,
            Some(suite) => probe(&client, &source.uri, suite).await,
        };
        repos.push(Repo {
            uri: source.uri,
            suite: source.suite,
            target_suite,
            answer,
            packages: source.packages,
        });
    }
    Ok(repos)
}

/// Whether `uri` publishes `suite`: its signed index, or failing that its
/// unsigned one.
async fn probe(client: &reqwest::Client, uri: &str, suite: &str) -> Answer {
    if !(uri.starts_with("https://") || uri.starts_with("http://")) {
        return Answer::Unknown(format!("{uri} is not an HTTP repository"));
    }
    for file in ["InRelease", "Release"] {
        let url = format!("{}/dists/{suite}/{file}", uri.trim_end_matches('/'));
        match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => return Answer::Published,
            // Not this file; the other may be there.
            Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {}
            Ok(r) => return Answer::Unknown(format!("{url} answered {}", r.status())),
            Err(e) => return Answer::Unknown(format!("{url}: {e}")),
        }
    }
    Answer::Missing
}

/// The `third_party_repos` check, from what [`gather`] found.
#[must_use]
pub fn check(target: &str, found: &Result<Vec<Repo>, String>) -> PreflightCheck {
    let repos = match found {
        Err(why) => {
            return build(
                CheckStatus::Warn,
                format!("Third-party repositories were not checked for {target}: {why}."),
                vec![],
            );
        }
        Ok(repos) if repos.is_empty() => {
            return build(
                CheckStatus::Pass,
                "No third-party repositories.".to_owned(),
                vec![],
            );
        }
        Ok(repos) => repos,
    };

    let missing = repos.iter().filter(|r| r.answer == Answer::Missing).count();
    let unknown = repos
        .iter()
        .filter(|r| matches!(r.answer, Answer::Unknown(_)))
        .count();
    let items = items(repos);
    let one = |n: usize, singular: &'static str, plural: &'static str| {
        if n == 1 { singular } else { plural }
    };

    if missing > 0 {
        build(
            CheckStatus::Fail,
            format!(
                "{missing} third-party {} nothing for {target} yet. Upgrading now would leave what came from {} behind; wait for {}, or remove {} first.",
                one(missing, "repository publishes", "repositories publish"),
                one(missing, "it", "them"),
                one(missing, "it", "them"),
                one(missing, "it and its packages", "them and their packages"),
            ),
            items,
        )
    } else if unknown > 0 {
        build(
            CheckStatus::Warn,
            format!(
                "Could not tell whether {unknown} third-party {} for {target}.",
                one(unknown, "repository publishes", "repositories publish"),
            ),
            items,
        )
    } else {
        build(
            CheckStatus::Pass,
            format!("Every third-party repository has something for {target}."),
            items,
        )
    }
}

/// One line per repository, the ones in the way first.
fn items(repos: &[Repo]) -> Vec<String> {
    let mut items = Vec::new();
    let missing = repos.iter().filter(|r| r.answer == Answer::Missing);
    let unknown = repos
        .iter()
        .filter(|r| matches!(r.answer, Answer::Unknown(_)));
    for r in missing {
        let from = named(&r.packages);
        items.push(format!(
            "{} {}: no {} yet{}",
            r.uri,
            r.suite,
            r.target_suite.as_deref().unwrap_or("?"),
            if from.is_empty() {
                String::new()
            } else {
                format!(" — installed from it: {from}")
            }
        ));
    }
    for r in unknown {
        if let Answer::Unknown(why) = &r.answer {
            items.push(format!("{} {}: {why}", r.uri, r.suite));
        }
    }
    for r in repos {
        match r.answer {
            Answer::Published => items.push(format!(
                "{} {}: {} is published",
                r.uri,
                r.suite,
                r.target_suite.as_deref().unwrap_or("?")
            )),
            Answer::NotReleaseSpecific => items.push(format!(
                "{} {}: not named after a release, used as it is",
                r.uri, r.suite
            )),
            _ => {}
        }
    }
    items
}

/// Some of the packages, sorted, and how many more.
fn named(packages: &[String]) -> String {
    let mut packages = packages.to_vec();
    packages.sort();
    let more = packages.len().saturating_sub(NAMED);
    packages.truncate(NAMED);
    let list = packages.join(", ");
    if more > 0 {
        format!("{list} and {more} more")
    } else {
        list
    }
}

fn build(status: CheckStatus, summary: String, items: Vec<String>) -> PreflightCheck {
    PreflightCheck {
        name: "third_party_repos".to_owned(),
        status,
        summary,
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_release_is_named_by_version_or_codename() {
        assert_eq!(codename_for("14").as_deref(), Some("forky"));
        assert_eq!(codename_for("24.04").as_deref(), Some("noble"));
        assert_eq!(codename_for("Forky").as_deref(), Some("forky"));
        assert_eq!(codename_for("99.10"), None);
        assert_eq!(codename_for(""), None);
    }

    #[test]
    fn a_suite_is_renamed_only_where_it_names_the_release() {
        assert_eq!(
            target_suite("cloud-sdk-trixie", "trixie", "forky").as_deref(),
            Some("cloud-sdk-forky")
        );
        assert_eq!(
            target_suite("google-compute-engine-trixie-stable", "trixie", "forky").as_deref(),
            Some("google-compute-engine-forky-stable")
        );
        assert_eq!(
            target_suite("trixie", "trixie", "forky").as_deref(),
            Some("forky")
        );
        assert_eq!(target_suite("stable", "trixie", "forky"), None);
        // A word that only contains the codename is not it.
        assert_eq!(target_suite("trixiefied", "trixie", "forky"), None);
    }

    #[test]
    fn the_codename_comes_from_os_release() {
        assert_eq!(
            current_codename("NAME=\"Debian GNU/Linux\"\nVERSION_CODENAME=trixie\n").as_deref(),
            Some("trixie")
        );
        assert_eq!(
            current_codename("VERSION_CODENAME=\nUBUNTU_CODENAME=noble\n").as_deref(),
            Some("noble")
        );
        assert_eq!(current_codename("ID=rocky\n"), None);
    }

    fn repo(suite: &str, answer: Answer, packages: &[&str]) -> Repo {
        Repo {
            uri: "https://packages.cloud.google.com/apt".into(),
            suite: suite.into(),
            target_suite: target_suite(suite, "trixie", "forky"),
            answer,
            packages: packages.iter().map(|p| (*p).to_owned()).collect(),
        }
    }

    #[test]
    fn a_repository_with_nothing_for_the_target_fails_and_names_its_packages() {
        let c = check(
            "14",
            &Ok(vec![
                repo("cloud-sdk-trixie", Answer::Missing, &["google-cloud-cli"]),
                repo("stable", Answer::NotReleaseSpecific, &[]),
            ]),
        );
        assert_eq!(c.status, CheckStatus::Fail);
        assert!(
            c.summary
                .starts_with("1 third-party repository publishes nothing for 14")
        );
        assert_eq!(
            c.items[0],
            "https://packages.cloud.google.com/apt cloud-sdk-trixie: no cloud-sdk-forky yet — installed from it: google-cloud-cli"
        );
        assert!(c.items[1].contains("not named after a release"));
    }

    #[test]
    fn could_not_look_is_a_warning_never_a_pass() {
        let c = check(
            "14",
            &Ok(vec![repo(
                "cloud-sdk-trixie",
                Answer::Unknown("timed out".into()),
                &[],
            )]),
        );
        assert_eq!(c.status, CheckStatus::Warn);
        let c = check("14", &Err("apt-cache failed".into()));
        assert_eq!(c.status, CheckStatus::Warn);
        let c = check(
            "14",
            &Ok(vec![repo("cloud-sdk-trixie", Answer::Published, &[])]),
        );
        assert_eq!(c.status, CheckStatus::Pass);
        assert_eq!(check("14", &Ok(vec![])).status, CheckStatus::Pass);
    }

    #[test]
    fn a_long_package_list_is_cut_short_and_says_how_many_more() {
        let many: Vec<String> = (0..11).map(|i| format!("pkg{i:02}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let c = check(
            "14",
            &Ok(vec![repo("cloud-sdk-trixie", Answer::Missing, &many)]),
        );
        assert!(c.items[0].ends_with("pkg07 and 3 more"), "{}", c.items[0]);
    }
}
