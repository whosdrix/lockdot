use std::fs;
use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

struct Env {
    dir: TempDir,
    home: TempDir,
}

impl Env {
    fn new() -> Self {
        Env {
            dir: TempDir::new().unwrap(),
            home: TempDir::new().unwrap(),
        }
    }

    fn cmd(&self) -> Command {
        self.cmd_as(self.home.path())
    }

    fn cmd_as(&self, home: &Path) -> Command {
        let mut c = Command::cargo_bin("lockdot").unwrap();
        c.current_dir(self.dir.path())
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("LOCKDOT_NO_SSH", "1")
            .env("NO_COLOR", "1")
            .env_remove("LOCKDOT_KEY")
            .env_remove("LOCKDOT_ENV")
            .env_remove("LOCKDOT_IDENTITY_FILE");
        c
    }

    fn file(&self, name: &str) -> String {
        fs::read_to_string(self.dir.path().join(name)).unwrap()
    }
}

#[test]
fn init_set_get_run() {
    let e = Env::new();
    e.cmd()
        .arg("init")
        .assert()
        .success()
        .stderr(predicate::str::contains("Created"));
    e.cmd()
        .args(["set", "API_KEY", "sk_live_abc"])
        .assert()
        .success();
    e.cmd()
        .args(["set", "GREETING", "hello world"])
        .assert()
        .success();

    let text = e.file(".env.lockdot");
    assert!(text.contains("API_KEY=lockdot:v1:"));
    assert!(!text.contains("sk_live_abc"));

    e.cmd()
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("sk_live_abc\n");
    e.cmd()
        .arg("ls")
        .assert()
        .success()
        .stdout("API_KEY\nGREETING\n");
    e.cmd()
        .args(["run", "--", "sh", "-c", "echo $API_KEY-$GREETING"])
        .assert()
        .success()
        .stdout("sk_live_abc-hello world\n");
}

#[test]
fn run_respects_existing_env_unless_override() {
    let e = Env::new();
    e.cmd().arg("init").assert().success();
    e.cmd().args(["set", "MODE", "file"]).assert().success();
    e.cmd()
        .env("MODE", "shell")
        .args(["run", "--", "sh", "-c", "echo $MODE"])
        .assert()
        .stdout("shell\n");
    e.cmd()
        .env("MODE", "shell")
        .args(["run", "--override", "--", "sh", "-c", "echo $MODE"])
        .assert()
        .stdout("file\n");
}

#[test]
fn run_passes_exit_code() {
    let e = Env::new();
    e.cmd().arg("init").assert().success();
    e.cmd()
        .args(["run", "--", "sh", "-c", "exit 7"])
        .assert()
        .code(7);
}

#[test]
fn set_from_stdin_and_unchanged() {
    let e = Env::new();
    e.cmd().arg("init").assert().success();
    e.cmd()
        .args(["set", "CERT"])
        .write_stdin("line1\nline2\n")
        .assert()
        .success();
    e.cmd()
        .args(["get", "CERT"])
        .assert()
        .stdout("line1\nline2\n");

    let before = e.file(".env.lockdot");
    e.cmd()
        .args(["set", "CERT"])
        .write_stdin("line1\nline2\n")
        .assert()
        .stderr(predicate::str::contains("unchanged"));
    assert_eq!(before, e.file(".env.lockdot"));
}

#[test]
fn init_from_existing_env_and_export() {
    let e = Env::new();
    fs::write(
        e.dir.path().join(".env"),
        "# db\nDB=postgres://x\nQUOTE='its'\nJ=\"a\\\"b\"\n",
    )
    .unwrap();
    e.cmd().args(["init", "--from", ".env"]).assert().success();
    e.cmd()
        .args(["export"])
        .assert()
        .stdout("DB=postgres://x\nQUOTE=its\nJ=\"a\\\"b\"\n");
    e.cmd()
        .args(["export", "--format", "json"])
        .assert()
        .stdout("{\n  \"DB\": \"postgres://x\",\n  \"QUOTE\": \"its\",\n  \"J\": \"a\\\"b\"\n}\n");
    e.cmd()
        .args(["export", "--format", "shell"])
        .assert()
        .stdout(predicate::str::contains("export J='a\"b'"));
}

#[test]
fn environments_use_separate_files() {
    let e = Env::new();
    e.cmd().args(["-e", "prod", "init"]).assert().success();
    e.cmd()
        .args(["-e", "prod", "set", "A", "1"])
        .assert()
        .success();
    assert!(e.dir.path().join(".env.prod.lockdot").exists());
    assert!(!e.dir.path().join(".env.lockdot").exists());
    e.cmd()
        .env("LOCKDOT_ENV", "prod")
        .args(["get", "A"])
        .assert()
        .stdout("1\n");
}

#[test]
fn edit_with_scripted_editor() {
    let e = Env::new();
    e.cmd().arg("init").assert().success();
    e.cmd().args(["set", "KEEP", "same"]).assert().success();
    e.cmd().args(["set", "OLD", "x"]).assert().success();
    let keep_line = |t: &str| {
        t.lines()
            .find(|l| l.starts_with("KEEP="))
            .unwrap()
            .to_string()
    };
    let before = keep_line(&e.file(".env.lockdot"));

    let script = e.dir.path().join("ed.sh");
    fs::write(
        &script,
        "#!/bin/sh\nprintf 'KEEP=same\\n# new\\nNEW=\"v 1\"\\n' > \"$1\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }
    e.cmd()
        .env("EDITOR", &script)
        .env_remove("VISUAL")
        .arg("edit")
        .assert()
        .success()
        .stderr(predicate::str::contains("+ NEW").and(predicate::str::contains("- OLD")));

    assert_eq!(before, keep_line(&e.file(".env.lockdot")));
    e.cmd().args(["get", "NEW"]).assert().stdout("v 1\n");
    e.cmd().args(["get", "OLD"]).assert().failure();
}

#[test]
fn sharing_with_a_teammate() {
    let e = Env::new();
    let bob = TempDir::new().unwrap();

    e.cmd().arg("init").assert().success();
    e.cmd().args(["set", "SECRET", "s3"]).assert().success();

    let bob_key =
        String::from_utf8(e.cmd_as(bob.path()).arg("whoami").output().unwrap().stdout).unwrap();
    let bob_key = bob_key.trim();
    assert!(bob_key.starts_with("age1"));

    e.cmd_as(bob.path())
        .args(["get", "SECRET"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("none of your keys").and(predicate::str::contains(bob_key)),
        );

    e.cmd()
        .args(["add-member", bob_key, "--name", "bob"])
        .assert()
        .success();
    e.cmd()
        .arg("members")
        .assert()
        .stdout(predicate::str::contains("bob"));
    e.cmd_as(bob.path())
        .args(["get", "SECRET"])
        .assert()
        .stdout("s3\n");

    e.cmd().args(["remove-member", "bob"]).assert().success();
    e.cmd_as(bob.path())
        .args(["get", "SECRET"])
        .assert()
        .failure();
    e.cmd().args(["get", "SECRET"]).assert().stdout("s3\n");
}

#[test]
fn ci_key_from_env() {
    let e = Env::new();
    e.cmd().arg("init").assert().success();
    e.cmd().args(["set", "A", "1"]).assert().success();
    let identity = fs::read_to_string(e.home.path().join(".config/lockdot/identity.txt")).unwrap();
    let secret = identity
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .unwrap();

    let empty_home = TempDir::new().unwrap();
    e.cmd_as(empty_home.path())
        .env("LOCKDOT_KEY", secret)
        .args(["get", "A"])
        .assert()
        .stdout("1\n");
}

#[test]
fn check_against_example() {
    let e = Env::new();
    e.cmd().arg("init").assert().success();
    e.cmd().args(["set", "A", "1"]).assert().success();
    fs::write(e.dir.path().join(".env.example"), "A=\nB=\nC=\n").unwrap();

    let other_home = TempDir::new().unwrap();
    e.cmd_as(other_home.path())
        .arg("check")
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing 2").and(predicate::str::contains("- B")));

    e.cmd().args(["set", "B", "2"]).assert().success();
    e.cmd().args(["set", "C", "3"]).assert().success();
    e.cmd().args(["check", "--decrypt"]).assert().success();
}

#[test]
fn hand_edited_files_are_rejected() {
    let e = Env::new();
    e.cmd().arg("init").assert().success();
    e.cmd().args(["set", "A", "1"]).assert().success();
    let path = e.dir.path().join(".env.lockdot");

    let mut text = e.file(".env.lockdot");
    text.push_str("PLAIN=oops\n");
    fs::write(&path, &text).unwrap();
    e.cmd()
        .args(["get", "A"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not encrypted"));

    let text = e.file(".env.lockdot").replace("PLAIN=oops\n", "");
    let a = text
        .lines()
        .find(|l| l.starts_with("A="))
        .unwrap()
        .to_string();
    fs::write(&path, text.replace(&a, &a.replacen("A=", "B=", 1))).unwrap();
    e.cmd().args(["get", "B"]).assert().failure();
}

#[test]
fn textconv_falls_back_to_raw() {
    let e = Env::new();
    e.cmd().arg("init").assert().success();
    e.cmd().args(["set", "A", "1"]).assert().success();
    e.cmd()
        .args(["textconv", ".env.lockdot"])
        .assert()
        .stdout("A=1\n");
    let stranger = TempDir::new().unwrap();
    e.cmd_as(stranger.path())
        .args(["textconv", ".env.lockdot"])
        .assert()
        .stdout(predicate::str::contains("lockdot:v1:"));
}
