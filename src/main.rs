use std::collections::BTreeSet;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand, ValueEnum};

use lockdot::dotenv;
use lockdot::github;
use lockdot::keys::{self, Keyring, Recipient};
use lockdot::vault::{Changes, Member, NotAMember, Unlocked, Vault};

#[derive(Parser)]
#[command(
    name = "lockdot",
    version,
    about = "Encrypted .env files you can commit to git and share with your team.",
    after_help = "Get started:\n  lockdot init\n  lockdot set DATABASE_URL postgres://localhost/app\n  lockdot run -- npm run dev"
)]
struct Cli {
    /// Environment name: `-e prod` uses .env.prod.lockdot
    #[arg(short, long, global = true, env = "LOCKDOT_ENV")]
    env: Option<String>,

    /// Path to the encrypted file (overrides --env)
    #[arg(short, long, global = true)]
    file: Option<PathBuf>,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create your key (if needed) and a new encrypted file
    Init {
        /// Encrypt an existing .env file into it
        #[arg(long, value_name = "PATH")]
        from: Option<PathBuf>,
    },
    /// Print your public key, to share with a teammate
    Whoami,
    /// Set a variable (reads the value from stdin when omitted)
    Set { name: String, value: Option<String> },
    /// Print one decrypted value
    Get { name: String },
    /// Remove a variable
    #[command(alias = "rm")]
    Unset { names: Vec<String> },
    /// List variable names (no key needed)
    #[command(alias = "ls")]
    List,
    /// Open the decrypted file in $EDITOR and re-encrypt on save
    Edit,
    /// Run a command with the variables in its environment
    Run {
        /// Let file values replace variables already set in the environment
        #[arg(long)]
        r#override: bool,
        #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// Print all decrypted variables
    Export {
        #[arg(long, value_enum, default_value_t = Format::Dotenv)]
        format: Format,
    },
    /// Merge variables from a plaintext .env file
    Import { path: PathBuf },
    /// Give someone access: age1..., ssh-ed25519 ..., or github:username
    AddMember {
        key: String,
        /// Label shown in `lockdot members`
        #[arg(long)]
        name: Option<String>,
    },
    /// Revoke access and rotate the data key
    RemoveMember { who: String },
    /// List who can decrypt the file (no key needed)
    Members,
    /// Fail if variables from .env.example are missing (for CI)
    Check {
        /// File listing the required names
        #[arg(long, value_name = "PATH")]
        example: Option<PathBuf>,
        /// Also decrypt everything and verify integrity
        #[arg(long)]
        decrypt: bool,
    },
    /// Print a decrypted view of a file for `git diff` (see README)
    #[command(hide = true)]
    Textconv { path: PathBuf },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Dotenv,
    Json,
    Shell,
}

struct Ui {
    color: bool,
}

impl Ui {
    fn new() -> Self {
        Ui {
            color: io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        }
    }
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn ok(&self, msg: &str) {
        eprintln!("{} {msg}", self.paint("32", "✓"));
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    fn changes(&self, c: &Changes) {
        for k in &c.added {
            eprintln!("  {} {k}", self.paint("32", "+"));
        }
        for k in &c.changed {
            eprintln!("  {} {k}", self.paint("33", "~"));
        }
        for k in &c.removed {
            eprintln!("  {} {k}", self.paint("31", "-"));
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let ui = Ui::new();
    match run(cli, &ui) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{} {err:#}", ui.paint("31;1", "error:"));
            if err.downcast_ref::<NotAMember>().is_some() {
                hint_not_member(&ui);
            }
            ExitCode::FAILURE
        }
    }
}

fn hint_not_member(ui: &Ui) {
    let public = keys::load_keyring()
        .ok()
        .and_then(|k| k.public)
        .or_else(keys::ssh_public_key);
    match public {
        Some(pk) => eprintln!(
            "\nAsk a member to run:\n  {}",
            ui.bold(&format!("lockdot add-member {pk}"))
        ),
        None => eprintln!(
            "\nRun {} to create a key, then ask a member to add you.",
            ui.bold("lockdot whoami")
        ),
    }
}

fn file_path(cli: &Cli) -> PathBuf {
    if let Some(f) = &cli.file {
        return f.clone();
    }
    match cli.env.as_deref() {
        None | Some("") => PathBuf::from(".env.lockdot"),
        Some(name) => PathBuf::from(format!(".env.{name}.lockdot")),
    }
}

fn read_vault(path: &Path) -> Result<Vault> {
    let text = fs::read_to_string(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            anyhow!(
                "{} not found. Run `lockdot init` to create it",
                path.display()
            )
        } else {
            anyhow!("reading {}: {e}", path.display())
        }
    })?;
    Vault::parse(&text).with_context(|| format!("{}", path.display()))
}

fn open(path: &Path) -> Result<Unlocked> {
    let keyring = keys::load_keyring()?;
    if keyring.identities.is_empty() {
        bail!("no key found. Run `lockdot init` or `lockdot whoami` to create one");
    }
    read_vault(path)?
        .unlock(&keyring)
        .with_context(|| format!("{}", path.display()))
}

fn save(path: &Path, unlocked: &mut Unlocked) -> Result<()> {
    let text = unlocked.render();
    let tmp = path.with_extension("lockdot.tmp");
    fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn ensure_identity(ui: &Ui) -> Result<(Keyring, String)> {
    let keyring = keys::load_keyring()?;
    if let Some(pk) = keyring.public.clone() {
        return Ok((keyring, pk));
    }
    let path = keys::identity_path();
    let pk = keys::generate_identity(&path)?;
    ui.ok(&format!("Created your key at {}", path.display()));
    eprintln!(
        "  {}",
        ui.dim("Back it up. Without it you cannot decrypt anything.")
    );
    Ok((keys::load_keyring()?, pk))
}

fn default_label() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "me".into());
    sanitize_label(&user)
}

fn sanitize_label(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| if c.is_whitespace() { '-' } else { c })
        .collect();
    if out.is_empty() { "member".into() } else { out }
}

fn run(cli: Cli, ui: &Ui) -> Result<ExitCode> {
    let path = file_path(&cli);
    match cli.command {
        Cmd::Init { from } => {
            if path.exists() {
                bail!("{} already exists", path.display());
            }
            let (_, pk) = ensure_identity(ui)?;
            let mut unlocked = Unlocked::create(vec![Member {
                label: default_label(),
                key: pk,
            }])?;
            if let Some(src) = &from {
                let text = fs::read_to_string(src)
                    .with_context(|| format!("reading {}", src.display()))?;
                let changes = unlocked
                    .replace_from_plaintext(&text)
                    .with_context(|| format!("{}", src.display()))?;
                save(&path, &mut unlocked)?;
                ui.ok(&format!(
                    "Encrypted {} variables into {}",
                    changes.added.len(),
                    path.display()
                ));
                eprintln!(
                    "  {}",
                    ui.dim(&format!(
                        "You can now delete {} or keep it in .gitignore.",
                        src.display()
                    ))
                );
            } else {
                save(&path, &mut unlocked)?;
                ui.ok(&format!("Created {}", path.display()));
            }
            eprintln!("\nNext:");
            eprintln!(
                "  lockdot set API_KEY sk_live_...    {}",
                ui.dim("# add a secret")
            );
            eprintln!(
                "  lockdot run -- npm run dev         {}",
                ui.dim("# use it")
            );
            eprintln!(
                "  lockdot add-member github:alice    {}",
                ui.dim("# share it")
            );
            eprintln!("  git add {}", path.display());
        }

        Cmd::Whoami => {
            let (keyring, pk) = ensure_identity(ui)?;
            println!("{pk}");
            if io::stderr().is_terminal() {
                eprintln!(
                    "{}",
                    ui.dim(&format!("keys: {}", keyring.sources.join(", ")))
                );
            }
        }

        Cmd::Set { name, value } => {
            let value = match value {
                Some(v) => v,
                None => {
                    if io::stdin().is_terminal() {
                        eprint!("{name}: ");
                        io::stderr().flush()?;
                        let mut line = String::new();
                        io::stdin().read_line(&mut line)?;
                        line.trim_end_matches(['\n', '\r']).to_string()
                    } else {
                        let mut buf = String::new();
                        io::stdin().read_to_string(&mut buf)?;
                        buf.strip_suffix('\n').unwrap_or(&buf).to_string()
                    }
                }
            };
            let mut unlocked = open(&path)?;
            let existed = unlocked.vault.sealed(&name).is_some();
            if unlocked.set(&name, &value)? {
                save(&path, &mut unlocked)?;
                ui.ok(&format!(
                    "{} {name}",
                    if existed { "Updated" } else { "Added" }
                ));
            } else {
                ui.ok(&format!("{name} unchanged"));
            }
        }

        Cmd::Get { name } => {
            let unlocked = open(&path)?;
            match unlocked.get(&name)? {
                Some(v) => println!("{}", v.as_str()),
                None => bail!("`{name}` is not set in {}", path.display()),
            }
        }

        Cmd::Unset { names } => {
            let mut unlocked = open(&path)?;
            let mut removed = Vec::new();
            for n in &names {
                if unlocked.unset(n) {
                    removed.push(n.clone());
                } else {
                    eprintln!("{} `{n}` was not set", ui.dim("·"));
                }
            }
            if !removed.is_empty() {
                save(&path, &mut unlocked)?;
                ui.ok(&format!("Removed {}", removed.join(", ")));
            }
        }

        Cmd::List => {
            let vault = read_vault(&path)?;
            for k in vault.keys() {
                println!("{k}");
            }
        }

        Cmd::Edit => {
            let mut unlocked = open(&path)?;
            let dir = tempfile::Builder::new().prefix("lockdot-").tempdir()?;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().trim_end_matches(".lockdot").to_string())
                .unwrap_or_else(|| ".env".into());
            let tmp = dir.path().join(name);
            write_private(&tmp, unlocked.to_plaintext()?.as_bytes())?;

            let changes = loop {
                open_editor(&tmp)?;
                let text = fs::read_to_string(&tmp)?;
                match unlocked.replace_from_plaintext(&text) {
                    Ok(c) => break c,
                    Err(e) => {
                        eprintln!("{} {e:#}", ui.paint("31;1", "error:"));
                        if !confirm("Re-open the editor?")? {
                            bail!("no changes saved");
                        }
                    }
                }
            };
            if changes.is_empty() && unlocked.render() == fs::read_to_string(&path)? {
                ui.ok("No changes");
            } else {
                save(&path, &mut unlocked)?;
                ui.ok(&format!("Saved {}", path.display()));
                ui.changes(&changes);
            }
        }

        Cmd::Run {
            r#override,
            command,
        } => {
            let unlocked = open(&path)?;
            let mut cmd = Command::new(&command[0]);
            cmd.args(&command[1..]);
            for (k, v) in unlocked.vars()? {
                if r#override || std::env::var_os(&k).is_none() {
                    cmd.env(&k, v.as_str());
                }
            }
            drop(unlocked);
            return exec(cmd, &command[0]);
        }

        Cmd::Export { format } => {
            let unlocked = open(&path)?;
            let vars = unlocked.vars()?;
            let mut out = io::stdout().lock();
            match format {
                Format::Dotenv => {
                    for (k, v) in &vars {
                        writeln!(out, "{k}={}", dotenv::quote(v))?;
                    }
                }
                Format::Shell => {
                    for (k, v) in &vars {
                        writeln!(out, "export {k}='{}'", v.replace('\'', r"'\''"))?;
                    }
                }
                Format::Json => {
                    writeln!(out, "{{")?;
                    for (i, (k, v)) in vars.iter().enumerate() {
                        let comma = if i + 1 < vars.len() { "," } else { "" };
                        writeln!(out, "  {}: {}{comma}", json_string(k), json_string(v))?;
                    }
                    writeln!(out, "}}")?;
                }
            }
        }

        Cmd::Import { path: src } => {
            let text =
                fs::read_to_string(&src).with_context(|| format!("reading {}", src.display()))?;
            let incoming =
                dotenv::parse_vars(&text).with_context(|| format!("{}", src.display()))?;
            let mut unlocked = open(&path)?;
            let mut changes = Changes::default();
            for (k, v) in incoming {
                let existed = unlocked.vault.sealed(&k).is_some();
                if unlocked.set(&k, &v)? {
                    if existed {
                        changes.changed.push(k);
                    } else {
                        changes.added.push(k);
                    }
                }
            }
            if changes.is_empty() {
                ui.ok("Nothing new to import");
            } else {
                save(&path, &mut unlocked)?;
                ui.ok(&format!("Imported into {}", path.display()));
                ui.changes(&changes);
            }
        }

        Cmd::AddMember { key, name } => {
            let new: Vec<Member> = if let Some(user) = key.strip_prefix("github:") {
                let found = github::fetch_keys(user)?;
                if found.is_empty() {
                    bail!(
                        "github.com/{user} has no ed25519 or RSA SSH keys. Ask them for their `lockdot whoami` key instead"
                    );
                }
                let label = sanitize_label(name.as_deref().unwrap_or(&format!("github:{user}")));
                found
                    .into_iter()
                    .map(|(key, _)| Member {
                        label: label.clone(),
                        key,
                    })
                    .collect()
            } else {
                let r = Recipient::parse(&key)?;
                let label = name.map(|n| sanitize_label(&n)).unwrap_or_else(|| {
                    key.split_whitespace()
                        .nth(2)
                        .map(sanitize_label)
                        .unwrap_or_else(|| short_key(&r.to_string()))
                });
                vec![Member {
                    label,
                    key: r.to_string(),
                }]
            };
            let mut unlocked = open(&path)?;
            let added = unlocked.add_members(new)?;
            if added.is_empty() {
                ui.ok("Already a member");
            } else {
                save(&path, &mut unlocked)?;
                for m in &added {
                    ui.ok(&format!(
                        "Added {} {}",
                        ui.bold(&m.label),
                        ui.dim(&short_key(&m.key))
                    ));
                }
                eprintln!(
                    "  {}",
                    ui.dim(&format!(
                        "Commit {} so they can decrypt it.",
                        path.display()
                    ))
                );
            }
        }

        Cmd::RemoveMember { who } => {
            let mut unlocked = open(&path)?;
            let removed = unlocked.remove_members(&who)?;
            if removed.is_empty() {
                bail!("no member matches `{who}`. See `lockdot members`");
            }
            save(&path, &mut unlocked)?;
            for m in &removed {
                ui.ok(&format!(
                    "Removed {} and rotated the data key",
                    ui.bold(&m.label)
                ));
            }
            eprintln!(
                "  {}",
                ui.dim(
                    "They may still have old values from git history. Rotate the real secrets too."
                )
            );
        }

        Cmd::Members => {
            let vault = read_vault(&path)?;
            let width = vault
                .members
                .iter()
                .map(|m| m.label.len())
                .max()
                .unwrap_or(0);
            for m in &vault.members {
                println!("{:width$}  {}", m.label, short_key(&m.key));
            }
        }

        Cmd::Check { example, decrypt } => {
            let vault = read_vault(&path)?;
            let names: BTreeSet<String> = vault.keys().map(String::from).collect();
            let example = example.or_else(|| {
                let p = PathBuf::from(".env.example");
                p.exists().then_some(p)
            });
            let mut failed = false;
            if let Some(ex) = &example {
                let text =
                    fs::read_to_string(ex).with_context(|| format!("reading {}", ex.display()))?;
                let required =
                    dotenv::parse_vars(&text).with_context(|| format!("{}", ex.display()))?;
                let missing: Vec<&str> = required
                    .iter()
                    .map(|(k, _)| k.as_str())
                    .filter(|k| !names.contains(*k))
                    .collect();
                if missing.is_empty() {
                    ui.ok(&format!(
                        "{} has every variable in {}",
                        path.display(),
                        ex.display()
                    ));
                } else {
                    failed = true;
                    eprintln!(
                        "{} {} is missing {} from {}:",
                        ui.paint("31;1", "✗"),
                        path.display(),
                        missing.len(),
                        ex.display()
                    );
                    for k in missing {
                        eprintln!("  {} {k}", ui.paint("31", "-"));
                    }
                }
            } else {
                ui.ok(&format!(
                    "{} is a valid lockdot file ({} variables)",
                    path.display(),
                    names.len()
                ));
            }
            if decrypt {
                let unlocked = open(&path)?;
                unlocked.vars()?;
                ui.ok("All values decrypt and the integrity check passes");
            }
            if failed {
                return Ok(ExitCode::FAILURE);
            }
        }

        Cmd::Textconv { path: p } => {
            let text = fs::read_to_string(&p)?;
            let shown = keys::load_keyring()
                .ok()
                .and_then(|k| Vault::parse(&text).ok()?.unlock(&k).ok())
                .and_then(|u| u.to_plaintext().ok());
            match shown {
                Some(plain) => print!("{plain}"),
                None => print!("{text}"),
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn short_key(key: &str) -> String {
    let body = key.split_whitespace().last().unwrap_or(key);
    let kind = if key.starts_with("ssh-") {
        key.split_whitespace().next().unwrap_or("")
    } else {
        ""
    };
    let short = if body.len() > 20 {
        format!("{}…{}", &body[..12], &body[body.len() - 6..])
    } else {
        body.to_string()
    };
    if kind.is_empty() {
        short
    } else {
        format!("{kind} {short}")
    }
}

fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(data)?;
    Ok(())
}

fn open_editor(path: &Path) -> Result<()> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                "notepad".into()
            } else {
                "vi".into()
            }
        });
    let status = if cfg!(windows) {
        Command::new("cmd")
            .arg("/C")
            .arg(format!("{editor} \"{}\"", path.display()))
            .status()
    } else {
        Command::new("sh")
            .arg("-c")
            .arg(format!("{editor} \"$1\""))
            .arg("lockdot")
            .arg(path)
            .status()
    }
    .with_context(|| format!("starting editor `{editor}`"))?;
    if !status.success() {
        bail!("editor `{editor}` exited with {status}; no changes saved");
    }
    Ok(())
}

fn confirm(question: &str) -> Result<bool> {
    if !io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("{question} [Y/n] ");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(!line.trim().eq_ignore_ascii_case("n"))
}

#[cfg(unix)]
fn exec(mut cmd: Command, program: &str) -> Result<ExitCode> {
    use std::os::unix::process::CommandExt;
    let err = cmd.exec();
    Err(anyhow!("could not run `{program}`: {err}"))
}

#[cfg(not(unix))]
fn exec(mut cmd: Command, program: &str) -> Result<ExitCode> {
    let status = cmd
        .status()
        .with_context(|| format!("could not run `{program}`"))?;
    Ok(ExitCode::from(
        status.code().unwrap_or(1).clamp(0, 255) as u8
    ))
}
