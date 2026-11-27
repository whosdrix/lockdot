use std::fs;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, anyhow, bail};

#[derive(Clone, Debug)]
pub enum Recipient {
    X25519(age::x25519::Recipient),
    Ssh(age::ssh::Recipient),
}

impl Recipient {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.starts_with("age1") {
            return s
                .parse::<age::x25519::Recipient>()
                .map(Recipient::X25519)
                .map_err(|e| anyhow!("invalid age public key: {e}"));
        }
        if s.starts_with("ssh-") {
            let without_comment: Vec<&str> = s.split_whitespace().take(2).collect();
            return without_comment
                .join(" ")
                .parse::<age::ssh::Recipient>()
                .map(Recipient::Ssh)
                .map_err(|e| anyhow!("unsupported SSH public key: {e:?}"));
        }
        bail!("`{s}` is not an age public key (age1...) or an SSH public key (ssh-ed25519 ...)")
    }

    pub fn as_dyn(&self) -> &dyn age::Recipient {
        match self {
            Recipient::X25519(r) => r,
            Recipient::Ssh(r) => r,
        }
    }
}

impl std::fmt::Display for Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Recipient::X25519(r) => write!(f, "{r}"),
            Recipient::Ssh(r) => write!(f, "{r}"),
        }
    }
}

pub fn config_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(dir).join("lockdot");
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("lockdot")
}

pub fn identity_path() -> PathBuf {
    match std::env::var_os("LOCKDOT_IDENTITY_FILE").filter(|v| !v.is_empty()) {
        Some(p) => PathBuf::from(p),
        None => config_dir().join("identity.txt"),
    }
}

pub struct Keyring {
    pub identities: Vec<Box<dyn age::Identity>>,
    pub public: Option<String>,
    pub sources: Vec<String>,
}

impl Keyring {
    pub fn iter(&self) -> impl Iterator<Item = &dyn age::Identity> {
        self.identities.iter().map(|i| i.as_ref())
    }
}

/// Collects every private key lockdot may use, in priority order:
/// `LOCKDOT_KEY`, the lockdot identity file, then the user's SSH keys.
pub fn load_keyring() -> Result<Keyring> {
    let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();
    let mut public = None;
    let mut sources = Vec::new();

    if let Ok(secret) = std::env::var("LOCKDOT_KEY")
        && !secret.trim().is_empty()
    {
        for (n, line) in secret
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .enumerate()
        {
            let id = line
                .parse::<age::x25519::Identity>()
                .map_err(|e| anyhow!("LOCKDOT_KEY line {} is not an age secret key: {e}", n + 1))?;
            public.get_or_insert_with(|| id.to_public().to_string());
            identities.push(Box::new(id));
        }
        sources.push("LOCKDOT_KEY".into());
    }

    let path = identity_path();
    if path.exists() {
        let file = age::IdentityFile::from_file(path.to_string_lossy().into_owned())
            .with_context(|| format!("reading {}", path.display()))?;
        let text = fs::read_to_string(&path)?;
        for line in text.lines().map(str::trim) {
            if let Ok(id) = line.parse::<age::x25519::Identity>() {
                public.get_or_insert_with(|| id.to_public().to_string());
            }
        }
        identities.extend(
            file.into_identities()
                .map_err(|e| anyhow!("{}: {e}", path.display()))?,
        );
        sources.push(path.display().to_string());
    }

    if std::env::var_os("LOCKDOT_NO_SSH").is_none()
        && let Some(home) = dirs::home_dir()
    {
        for name in ["id_ed25519", "id_rsa"] {
            let p = home.join(".ssh").join(name);
            if let Some(id) = load_ssh_identity(&p) {
                identities.push(id);
                sources.push(p.display().to_string());
            }
        }
    }

    Ok(Keyring {
        identities,
        public,
        sources,
    })
}

fn load_ssh_identity(path: &Path) -> Option<Box<dyn age::Identity>> {
    let file = fs::File::open(path).ok()?;
    let id =
        age::ssh::Identity::from_buffer(BufReader::new(file), Some(path.display().to_string()))
            .ok()?;
    match id {
        age::ssh::Identity::Unencrypted(_) => Some(Box::new(id)),
        age::ssh::Identity::Encrypted(_) => {
            Some(Box::new(id.with_callbacks(age::cli_common::UiCallbacks)))
        }
        age::ssh::Identity::Unsupported(_) => None,
    }
}

pub fn ssh_public_key() -> Option<String> {
    let home = dirs::home_dir()?;
    ["id_ed25519.pub", "id_rsa.pub"].iter().find_map(|name| {
        let text = fs::read_to_string(home.join(".ssh").join(name)).ok()?;
        let key: Vec<&str> = text.split_whitespace().take(2).collect();
        (key.len() == 2).then(|| key.join(" "))
    })
}

/// Creates a new age identity file. Returns the public key.
pub fn generate_identity(path: &Path) -> Result<String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let id = age::x25519::Identity::generate();
    let public = id.to_public().to_string();

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    writeln!(
        file,
        "# lockdot identity. Keep this file private and backed up."
    )?;
    writeln!(file, "# public key: {public}")?;
    writeln!(file, "{}", id.to_string().expose_secret())?;
    Ok(public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_recipients() {
        let id = age::x25519::Identity::generate();
        let pk = id.to_public().to_string();
        assert!(matches!(
            Recipient::parse(&pk).unwrap(),
            Recipient::X25519(_)
        ));

        let ssh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@laptop";
        let r = Recipient::parse(ssh).unwrap();
        assert!(matches!(r, Recipient::Ssh(_)));
        assert!(!r.to_string().contains("alice"));

        assert!(Recipient::parse("hello").is_err());
        assert!(Recipient::parse("age1nope").is_err());
    }
}
