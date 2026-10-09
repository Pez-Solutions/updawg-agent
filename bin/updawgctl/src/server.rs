//! `updawgctl enroll --server` (DAWG-296): which region's gateway this host
//! reports to.
//!
//! An organization outside the EU is served by its own region's gateway, so
//! the portal's install command for one carries `UPDAWG_SERVER`, and `sudo`
//! hands it through install.sh to here. It is written to `agent.toml` as
//! `server`, before enrolling, because enrolling is the first thing that talks
//! to it.
//!
//! Only the `server` line changes: comments, order and every other setting
//! are left exactly as they were, because this file is the host owner's.

use anyhow::{Context, Result, bail};

/// Where an agent reports when nobody said otherwise: the EU region.
pub(crate) const DEFAULT_SERVER: &str = "https://agents.updawg.net";

/// `url` if it is an `https://` origin, without a trailing slash.
pub(crate) fn origin(url: &str) -> Result<String> {
    let url = url.trim().trim_end_matches('/');
    let Some(host) = url.strip_prefix("https://") else {
        bail!("--server is an https:// address such as https://agents.us.updawg.net, not {url}");
    };
    let ok = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
    if !ok {
        bail!("--server is an origin such as https://agents.us.updawg.net, not {url}");
    }
    Ok(url.to_owned())
}

/// The config `text` with `server` set to `server`: its `server` line
/// replaced, or one added at the top when there is none.
pub(crate) fn with_server(text: &str, server: &str) -> String {
    let line = format!("server = \"{server}\"");
    let mut replaced = false;
    let mut out: Vec<String> = text
        .lines()
        .map(|l| {
            let key = l.split('=').next().unwrap_or_default().trim();
            if !replaced && key == "server" && !l.trim_start().starts_with('#') {
                replaced = true;
                line.clone()
            } else {
                l.to_owned()
            }
        })
        .collect();
    if !replaced {
        // First, so it is a top-level key and not part of a [table].
        out.insert(0, line);
    }
    let mut joined = out.join("\n");
    if text.ends_with('\n') || text.is_empty() {
        joined.push('\n');
    }
    joined
}

/// Point this host at `server` in the config at `path`, unless it already
/// reports somewhere else that is not the default — then only with `force`,
/// because moving a host to another region by accident would be silent.
/// Returns whether the file changed.
pub(crate) fn point_at(path: &str, current: &str, server: &str, force: bool) -> Result<bool> {
    let server = origin(server)?;
    if current.trim_end_matches('/') == server {
        return Ok(false);
    }
    if current.trim_end_matches('/') != DEFAULT_SERVER && !force {
        bail!(
            "{path} already reports to {current}; not changing it to {server}. \
             Pass --force if this host is moving."
        );
    }
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    let updated = with_server(&text, &server);
    // Through a file beside it and a rename, so a crash leaves the old
    // config or the new one, never half of one.
    let tmp = format!("{path}.updawgctl-new");
    std::fs::write(&tmp, updated).with_context(|| format!("writing {tmp}"))?;
    if let Ok(meta) = std::fs::metadata(path) {
        std::fs::set_permissions(&tmp, meta.permissions()).ok();
    }
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {path}"))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_origin_is_https_and_nothing_else() {
        assert_eq!(
            origin("https://agents.us.updawg.net/").unwrap(),
            "https://agents.us.updawg.net"
        );
        assert!(origin("http://agents.us.updawg.net").is_err());
        assert!(origin("https://agents.us.updawg.net/path").is_err());
        assert!(origin("https://x\";rm").is_err());
        assert!(origin("https://").is_err());
    }

    #[test]
    fn only_the_server_line_changes() {
        let text = "# mine\nserver = \"https://agents.updawg.net\"\nmode = \"observe\"\n\n[updates]\nx = 1\n";
        assert_eq!(
            with_server(text, "https://agents.us.updawg.net"),
            "# mine\nserver = \"https://agents.us.updawg.net\"\nmode = \"observe\"\n\n[updates]\nx = 1\n"
        );
    }

    #[test]
    fn a_config_without_one_gets_it_at_the_top() {
        assert_eq!(
            with_server("# server = \"x\"\n[updates]\n", "https://a.example"),
            "server = \"https://a.example\"\n# server = \"x\"\n[updates]\n"
        );
    }

    #[test]
    fn a_host_pointed_elsewhere_is_not_moved_without_force() {
        let dir = std::env::temp_dir().join(format!("updawgctl-server-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.toml");
        let path = path.to_str().unwrap();
        std::fs::write(path, "server = \"https://agents.dev.updawg.net\"\n").unwrap();

        let refused = point_at(
            path,
            "https://agents.dev.updawg.net",
            "https://agents.us.updawg.net",
            false,
        );
        assert!(refused.is_err());
        assert!(
            point_at(
                path,
                "https://agents.dev.updawg.net",
                "https://agents.us.updawg.net",
                true
            )
            .unwrap()
        );
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "server = \"https://agents.us.updawg.net\"\n"
        );
        assert!(
            !point_at(
                path,
                "https://agents.us.updawg.net",
                "https://agents.us.updawg.net",
                false
            )
            .unwrap()
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
