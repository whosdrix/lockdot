use anyhow::{Context, Result, bail};

use crate::keys::Recipient;

/// Fetches a GitHub user's public SSH keys that age can encrypt to.
pub fn fetch_keys(user: &str) -> Result<Vec<(String, Recipient)>> {
    if user.is_empty() || !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        bail!("`{user}` is not a valid GitHub username");
    }
    let base = std::env::var("LOCKDOT_GITHUB_URL").unwrap_or_else(|_| "https://github.com".into());
    let url = format!("{}/{user}.keys", base.trim_end_matches('/'));
    let body = ureq::get(&url)
        .set("User-Agent", concat!("lockdot/", env!("CARGO_PKG_VERSION")))
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(404, _) => anyhow::anyhow!("GitHub user `{user}` not found"),
            other => anyhow::anyhow!("fetching {url}: {other}"),
        })?
        .into_string()
        .context("reading GitHub response")?;
    Ok(parse_keys(&body))
}

pub fn parse_keys(body: &str) -> Vec<(String, Recipient)> {
    body.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("ssh-ed25519 ") || l.starts_with("ssh-rsa "))
        .filter_map(|l| Recipient::parse(l).ok().map(|r| (r.to_string(), r)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_supported_keys_only() {
        let body = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN\n\
                    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY=\n\
                    sk-ssh-ed25519@openssh.com AAAA\n\n";
        let keys = parse_keys(body);
        assert_eq!(keys.len(), 1);
        assert!(keys[0].0.starts_with("ssh-ed25519 "));
    }
}
