//! The `.lockdot` file format.
//!
//! A file holds one random 256-bit data key, wrapped with age for every member.
//! Each value is sealed with XChaCha20-Poly1305 under a key derived from the
//! data key, with the variable name as associated data so ciphertexts cannot be
//! moved between names. An HMAC over the members and all name/ciphertext pairs
//! detects added, removed or swapped lines.

use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::dotenv::{self, Item};
use crate::keys::{Keyring, Recipient};

pub const VERSION: &str = "v1";
const VALUE_PREFIX: &str = "lockdot:v1:";
const HEADER: &str = "# This file is encrypted with lockdot. Names are readable, values are not.\n# Edit it with `lockdot edit` or `lockdot set NAME value`.";
const PAD_BLOCK: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub label: String,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    Blank,
    Comment(String),
    Var { key: String, sealed: String },
}

/// A parsed file. Reading names and members needs no key.
#[derive(Clone, Debug)]
pub struct Vault {
    pub members: Vec<Member>,
    wrapped_key: String,
    mac: String,
    pub lines: Vec<Line>,
}

/// A vault together with its data key.
pub struct Unlocked {
    pub vault: Vault,
    data_key: Zeroizing<[u8; 32]>,
}

impl Vault {
    pub fn parse(text: &str) -> Result<Self> {
        let mut version = None;
        let mut members = Vec::new();
        let mut wrapped_key = None;
        let mut mac = None;
        let mut lines = Vec::new();
        let mut in_header = true;

        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if let Some(meta) = line.strip_prefix("#@") {
                let (tag, rest) = meta.split_once(' ').unwrap_or((meta, ""));
                let rest = rest.trim();
                match tag {
                    "lockdot" => version = Some(rest.to_string()),
                    "member" => {
                        let (label, key) = rest
                            .split_once(' ')
                            .ok_or_else(|| anyhow!("line {}: malformed member", n + 1))?;
                        members.push(Member {
                            label: label.to_string(),
                            key: key.trim().to_string(),
                        });
                    }
                    "datakey" => wrapped_key = Some(rest.to_string()),
                    "mac" => mac = Some(rest.to_string()),
                    other => bail!("line {}: unknown lockdot field `{other}`", n + 1),
                }
                continue;
            }
            if in_header && (line.is_empty() || (line.starts_with('#') && HEADER.contains(line))) {
                continue;
            }
            in_header = false;

            if line.is_empty() {
                lines.push(Line::Blank);
            } else if let Some(c) = line.strip_prefix('#') {
                lines.push(Line::Comment(c.to_string()));
            } else {
                let (key, sealed) = line
                    .split_once('=')
                    .ok_or_else(|| anyhow!("line {}: expected NAME=value", n + 1))?;
                let key = key.trim();
                if !dotenv::is_valid_key(key) {
                    bail!("line {}: invalid variable name `{key}`", n + 1);
                }
                let sealed = sealed.trim();
                if !sealed.starts_with(VALUE_PREFIX) {
                    bail!(
                        "line {}: `{key}` is not encrypted. Use `lockdot set {key} ...` instead of editing the file by hand",
                        n + 1
                    );
                }
                lines.push(Line::Var {
                    key: key.to_string(),
                    sealed: sealed.to_string(),
                });
            }
        }

        while matches!(lines.last(), Some(Line::Blank)) {
            lines.pop();
        }

        match version.as_deref() {
            Some(VERSION) => {}
            Some(v) => bail!("this file uses lockdot format {v}; upgrade lockdot to read it"),
            None => bail!("not a lockdot file (missing `#@lockdot` header)"),
        }

        Ok(Vault {
            members,
            wrapped_key: wrapped_key.ok_or_else(|| anyhow!("missing `#@datakey` line"))?,
            mac: mac.ok_or_else(|| anyhow!("missing `#@mac` line"))?,
            lines,
        })
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.lines.iter().filter_map(|l| match l {
            Line::Var { key, .. } => Some(key.as_str()),
            _ => None,
        })
    }

    pub fn sealed(&self, key: &str) -> Option<&str> {
        self.lines.iter().rev().find_map(|l| match l {
            Line::Var { key: k, sealed } if k == key => Some(sealed.as_str()),
            _ => None,
        })
    }

    pub fn unlock(self, keyring: &Keyring) -> Result<Unlocked> {
        let wrapped = B64
            .decode(&self.wrapped_key)
            .context("`#@datakey` is not valid base64")?;
        let decryptor =
            age::Decryptor::new(&wrapped[..]).context("`#@datakey` is not an age payload")?;
        let mut reader = match decryptor.decrypt(keyring.iter()) {
            Ok(r) => r,
            Err(age::DecryptError::NoMatchingKeys) => return Err(NotAMember.into()),
            Err(e) => return Err(anyhow!("could not unwrap the data key: {e}")),
        };
        let mut buf = Zeroizing::new(Vec::new());
        reader.read_to_end(&mut buf)?;
        if buf.len() != 32 {
            bail!("data key has the wrong length");
        }
        let mut data_key = Zeroizing::new([0u8; 32]);
        data_key.copy_from_slice(&buf);

        let unlocked = Unlocked {
            vault: self,
            data_key,
        };
        let actual = B64.decode(&unlocked.vault.mac).unwrap_or_default();
        let mut verifier = unlocked.mac_state();
        verifier.update(&unlocked.mac_input());
        if verifier.verify_slice(&actual).is_err() {
            bail!(
                "integrity check failed: the file was changed without lockdot (a line was added, removed or swapped by hand)"
            );
        }
        Ok(unlocked)
    }
}

#[derive(Debug)]
pub struct NotAMember;

impl std::fmt::Display for NotAMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("none of your keys can open this file")
    }
}

impl std::error::Error for NotAMember {}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub added: Vec<String>,
    pub changed: Vec<String>,
    pub removed: Vec<String>,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.changed.is_empty() && self.removed.is_empty()
    }
}

impl Unlocked {
    pub fn create(members: Vec<Member>) -> Result<Self> {
        if members.is_empty() {
            bail!("a lockdot file needs at least one member");
        }
        let mut data_key = Zeroizing::new([0u8; 32]);
        getrandom::fill(data_key.as_mut()).map_err(|e| anyhow!("no randomness: {e}"))?;
        let mut unlocked = Unlocked {
            vault: Vault {
                members,
                wrapped_key: String::new(),
                mac: String::new(),
                lines: Vec::new(),
            },
            data_key,
        };
        unlocked.rewrap()?;
        Ok(unlocked)
    }

    fn subkey(&self, info: &[u8]) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(None, self.data_key.as_ref());
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(info, out.as_mut())
            .expect("32 bytes is a valid HKDF length");
        out
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(self.subkey(b"lockdot v1 values").as_ref())
            .expect("32-byte key")
    }

    fn mac_state(&self) -> Hmac<Sha256> {
        <Hmac<Sha256> as KeyInit>::new_from_slice(self.subkey(b"lockdot v1 mac").as_ref())
            .expect("HMAC accepts any key length")
    }

    fn mac_input(&self) -> Vec<u8> {
        let mut input = format!("lockdot {VERSION}\n");
        for m in &self.vault.members {
            input.push_str(&format!("member {} {}\n", m.label, m.key));
        }
        let mut vars: Vec<(&str, &str)> = self
            .vault
            .lines
            .iter()
            .filter_map(|l| match l {
                Line::Var { key, sealed } => Some((key.as_str(), sealed.as_str())),
                _ => None,
            })
            .collect();
        vars.sort();
        for (k, v) in vars {
            input.push_str(&format!("var {k}={v}\n"));
        }
        input.into_bytes()
    }

    fn compute_mac(&self) -> String {
        let mut mac = self.mac_state();
        mac.update(&self.mac_input());
        B64.encode(mac.finalize().into_bytes())
    }

    fn seal(&self, key: &str, value: &str) -> Result<String> {
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|e| anyhow!("no randomness: {e}"))?;
        let padded = Zeroizing::new(pad(value.as_bytes()));
        let aad = format!("{VALUE_PREFIX}{key}");
        let ct = self
            .cipher()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &padded,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("encryption failed"))?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ct);
        Ok(format!("{VALUE_PREFIX}{}", B64.encode(blob)))
    }

    fn open(&self, key: &str, sealed: &str) -> Result<Zeroizing<String>> {
        let blob = sealed
            .strip_prefix(VALUE_PREFIX)
            .and_then(|b| B64.decode(b).ok())
            .filter(|b| b.len() > 24)
            .ok_or_else(|| anyhow!("`{key}` has a malformed value"))?;
        let (nonce, ct) = blob.split_at(24);
        let aad = format!("{VALUE_PREFIX}{key}");
        let mut padded = self
            .cipher()
            .decrypt(
                &XNonce::try_from(nonce).expect("24-byte nonce"),
                Payload {
                    msg: ct,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("`{key}` could not be decrypted (wrong key or tampered value)"))?;
        let value = unpad(&padded)
            .and_then(|v| String::from_utf8(v.to_vec()).ok())
            .ok_or_else(|| anyhow!("`{key}` has invalid padding"));
        padded.zeroize();
        value.map(Zeroizing::new)
    }

    pub fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>> {
        self.vault
            .sealed(key)
            .map(|s| self.open(key, s))
            .transpose()
    }

    /// Returns all variables in file order.
    pub fn vars(&self) -> Result<Vec<(String, Zeroizing<String>)>> {
        let mut out = Vec::new();
        for line in &self.vault.lines {
            if let Line::Var { key, sealed } = line {
                out.push((key.clone(), self.open(key, sealed)?));
            }
        }
        Ok(out)
    }

    /// Sets a value. Returns false when the value was already there, in which
    /// case the existing ciphertext is kept so the file does not change.
    pub fn set(&mut self, key: &str, value: &str) -> Result<bool> {
        if !dotenv::is_valid_key(key) {
            bail!("`{key}` is not a valid variable name");
        }
        if let Some(existing) = self.get(key)?
            && existing.as_str() == value
        {
            return Ok(false);
        }
        let sealed = self.seal(key, value)?;
        let slot = self.vault.lines.iter_mut().rev().find_map(|l| match l {
            Line::Var { key: k, sealed } if k == key => Some(sealed),
            _ => None,
        });
        match slot {
            Some(s) => *s = sealed,
            None => self.vault.lines.push(Line::Var {
                key: key.to_string(),
                sealed,
            }),
        }
        Ok(true)
    }

    pub fn unset(&mut self, key: &str) -> bool {
        let before = self.vault.lines.len();
        self.vault
            .lines
            .retain(|l| !matches!(l, Line::Var { key: k, .. } if k == key));
        before != self.vault.lines.len()
    }

    /// Plaintext dotenv text, comments included, for `edit` and `export`.
    pub fn to_plaintext(&self) -> Result<String> {
        let mut items = Vec::new();
        for line in &self.vault.lines {
            items.push(match line {
                Line::Blank => Item::Blank,
                Line::Comment(c) => Item::Comment(c.clone()),
                Line::Var { key, sealed } => Item::Var {
                    key: key.clone(),
                    value: self.open(key, sealed)?.to_string(),
                },
            });
        }
        Ok(dotenv::render(&items))
    }

    /// Replaces the contents with parsed plaintext, re-using ciphertext for
    /// values that did not change.
    pub fn replace_from_plaintext(&mut self, text: &str) -> Result<Changes> {
        let items = dotenv::parse(text)?;
        let old: Vec<(String, Zeroizing<String>)> = self.vars()?;
        let mut changes = Changes::default();
        let mut lines = Vec::new();
        let mut seen: Vec<String> = Vec::new();

        let mut deduped: Vec<Item> = Vec::new();
        for item in items.into_iter().rev() {
            if let Item::Var { key, .. } = &item {
                if seen.contains(key) {
                    continue;
                }
                seen.push(key.clone());
            }
            deduped.push(item);
        }
        deduped.reverse();

        for item in deduped {
            lines.push(match item {
                Item::Blank => Line::Blank,
                Item::Comment(c) => Line::Comment(c),
                Item::Var { key, value } => {
                    let previous = old.iter().find(|(k, _)| *k == key);
                    let sealed = match previous {
                        Some((_, v)) if v.as_str() == value => {
                            self.vault.sealed(&key).expect("key exists").to_string()
                        }
                        Some(_) => {
                            changes.changed.push(key.clone());
                            self.seal(&key, &value)?
                        }
                        None => {
                            changes.added.push(key.clone());
                            self.seal(&key, &value)?
                        }
                    };
                    Line::Var { key, sealed }
                }
            });
        }
        for (k, _) in &old {
            if !seen.contains(k) {
                changes.removed.push(k.clone());
            }
        }
        while matches!(lines.last(), Some(Line::Blank)) {
            lines.pop();
        }
        self.vault.lines = lines;
        Ok(changes)
    }

    pub fn add_members(&mut self, new: Vec<Member>) -> Result<Vec<Member>> {
        let mut added = Vec::new();
        for m in new {
            if self.vault.members.iter().any(|e| e.key == m.key) {
                continue;
            }
            self.vault.members.push(m.clone());
            added.push(m);
        }
        if !added.is_empty() {
            self.rewrap()?;
        }
        Ok(added)
    }

    /// Removes members whose label or key matches, then rotates the data key
    /// and re-encrypts every value so old wrapped keys stop working for new data.
    pub fn remove_members(&mut self, who: &str) -> Result<Vec<Member>> {
        let (removed, kept): (Vec<Member>, Vec<Member>) =
            self.vault.members.drain(..).partition(|m| {
                m.label == who || m.key == who || (who.len() >= 12 && m.key.starts_with(who))
            });
        self.vault.members = kept;
        if removed.is_empty() {
            return Ok(removed);
        }
        if self.vault.members.is_empty() {
            self.vault.members = removed;
            bail!("refusing to remove the last member; nobody could open the file");
        }
        self.rotate()?;
        Ok(removed)
    }

    pub fn rotate(&mut self) -> Result<()> {
        let vars = self.vars()?;
        getrandom::fill(self.data_key.as_mut()).map_err(|e| anyhow!("no randomness: {e}"))?;
        let resealed: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| Ok((k.clone(), self.seal(k, v)?)))
            .collect::<Result<_>>()?;
        for line in self.vault.lines.iter_mut() {
            if let Line::Var { key, sealed } = line {
                *sealed = resealed
                    .iter()
                    .find(|(k, _)| k == key)
                    .expect("var exists")
                    .1
                    .clone();
            }
        }
        self.rewrap()
    }

    fn rewrap(&mut self) -> Result<()> {
        let recipients = self
            .vault
            .members
            .iter()
            .map(|m| Recipient::parse(&m.key).with_context(|| format!("member `{}`", m.label)))
            .collect::<Result<Vec<_>>>()?;
        let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_dyn()))
            .map_err(|e| anyhow!("{e}"))?;
        let mut out = Vec::new();
        let mut writer = encryptor.wrap_output(&mut out)?;
        writer.write_all(self.data_key.as_ref())?;
        writer.finish()?;
        self.vault.wrapped_key = B64.encode(out);
        Ok(())
    }

    pub fn render(&mut self) -> String {
        self.vault.mac = self.compute_mac();
        let v = &self.vault;
        let mut out = String::new();
        out.push_str(HEADER);
        out.push('\n');
        out.push_str(&format!("#@lockdot {VERSION}\n"));
        for m in &v.members {
            out.push_str(&format!("#@member {} {}\n", m.label, m.key));
        }
        out.push_str(&format!("#@datakey {}\n", v.wrapped_key));
        out.push_str(&format!("#@mac {}\n", v.mac));
        if !v.lines.is_empty() {
            out.push('\n');
        }
        for line in &v.lines {
            match line {
                Line::Blank => {}
                Line::Comment(c) => {
                    out.push('#');
                    out.push_str(c);
                }
                Line::Var { key, sealed } => {
                    out.push_str(key);
                    out.push('=');
                    out.push_str(sealed);
                }
            }
            out.push('\n');
        }
        out
    }
}

/// ISO/IEC 7816-4 padding to a multiple of 32 bytes, so ciphertext length only
/// reveals a value's length to the nearest 32 bytes.
fn pad(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.push(0x80);
    while !out.len().is_multiple_of(PAD_BLOCK) {
        out.push(0);
    }
    out
}

fn unpad(data: &[u8]) -> Option<&[u8]> {
    let end = data.iter().rposition(|&b| b != 0)?;
    (data[end] == 0x80).then(|| &data[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyring() -> (Keyring, Member) {
        let id = age::x25519::Identity::generate();
        let member = Member {
            label: "me".into(),
            key: id.to_public().to_string(),
        };
        (
            Keyring {
                identities: vec![Box::new(id)],
                public: None,
                sources: vec![],
            },
            member,
        )
    }

    #[test]
    fn padding_roundtrip() {
        for len in 0..100 {
            let data = vec![7u8; len];
            let p = pad(&data);
            assert_eq!(p.len() % PAD_BLOCK, 0);
            assert_eq!(unpad(&p).unwrap(), &data[..]);
        }
        assert_eq!(pad(b"").len(), 32);
        assert_eq!(pad(&[0u8; 31]).len(), 32);
        assert_eq!(pad(&[0u8; 32]).len(), 64);
    }

    #[test]
    fn roundtrip_through_text() {
        let (kr, me) = keyring();
        let mut u = Unlocked::create(vec![me]).unwrap();
        u.set("API_KEY", "sk_live_123").unwrap();
        u.set("MULTI", "a\nb \"c\"").unwrap();
        let text = u.render();
        assert!(!text.contains("sk_live_123"));

        let u2 = Vault::parse(&text).unwrap().unlock(&kr).unwrap();
        assert_eq!(u2.get("API_KEY").unwrap().unwrap().as_str(), "sk_live_123");
        assert_eq!(u2.get("MULTI").unwrap().unwrap().as_str(), "a\nb \"c\"");
        assert!(u2.get("MISSING").unwrap().is_none());
    }

    #[test]
    fn unchanged_values_keep_ciphertext() {
        let (kr, me) = keyring();
        let mut u = Unlocked::create(vec![me]).unwrap();
        u.set("A", "1").unwrap();
        u.set("B", "2").unwrap();
        let before = u.render();

        let mut u = Vault::parse(&before).unwrap().unlock(&kr).unwrap();
        assert!(!u.set("A", "1").unwrap());
        let changes = u.replace_from_plaintext("A=1\nB=3\nC=4\n").unwrap();
        assert_eq!(changes.changed, vec!["B"]);
        assert_eq!(changes.added, vec!["C"]);
        let after = u.render();

        let a_line = |t: &str| t.lines().find(|l| l.starts_with("A=")).unwrap().to_string();
        assert_eq!(a_line(&before), a_line(&after));
    }

    #[test]
    fn detects_tampering() {
        let (kr, me) = keyring();
        let mut u = Unlocked::create(vec![me]).unwrap();
        u.set("A", "1").unwrap();
        u.set("B", "2").unwrap();
        let text = u.render();

        let a = text.lines().find(|l| l.starts_with("A=")).unwrap();
        let b = text.lines().find(|l| l.starts_with("B=")).unwrap();
        let swapped = text
            .replace(a, &format!("A={}", &b[2..]))
            .replace(b, &format!("B={}", &a[2..]));
        assert!(Vault::parse(&swapped).unwrap().unlock(&kr).is_err());

        let dropped = text.replace(&format!("{b}\n"), "");
        let err = Vault::parse(&dropped).unwrap().unlock(&kr).err().unwrap();
        assert!(err.to_string().contains("integrity"));
    }

    #[test]
    fn wrong_key_is_not_a_member() {
        let (_, me) = keyring();
        let (other, _) = keyring();
        let mut u = Unlocked::create(vec![me]).unwrap();
        let text = u.render();
        let err = Vault::parse(&text).unwrap().unlock(&other).err().unwrap();
        assert!(err.downcast_ref::<NotAMember>().is_some());
    }

    #[test]
    fn members_and_rotation() {
        let (kr_a, a) = keyring();
        let (kr_b, mut b) = keyring();
        b.label = "bob".into();
        let mut u = Unlocked::create(vec![a]).unwrap();
        u.set("SECRET", "x").unwrap();
        u.add_members(vec![b.clone()]).unwrap();
        let text = u.render();
        Vault::parse(&text).unwrap().unlock(&kr_b).unwrap();

        let mut u = Vault::parse(&text).unwrap().unlock(&kr_a).unwrap();
        let old_sealed = u.vault.sealed("SECRET").unwrap().to_string();
        let removed = u.remove_members("bob").unwrap();
        assert_eq!(removed, vec![b]);
        let text = u.render();
        assert!(Vault::parse(&text).unwrap().unlock(&kr_b).is_err());
        let u = Vault::parse(&text).unwrap().unlock(&kr_a).unwrap();
        assert_ne!(u.vault.sealed("SECRET").unwrap(), old_sealed);
        assert_eq!(u.get("SECRET").unwrap().unwrap().as_str(), "x");
    }

    #[test]
    fn cannot_remove_last_member() {
        let (_, a) = keyring();
        let mut u = Unlocked::create(vec![a]).unwrap();
        assert!(u.remove_members("me").is_err());
        assert_eq!(u.vault.members.len(), 1);
    }

    #[test]
    fn comments_survive() {
        let (kr, me) = keyring();
        let mut u = Unlocked::create(vec![me]).unwrap();
        u.replace_from_plaintext("# Stripe\nSTRIPE_KEY=sk\n\n# DB\nDB=x\n")
            .unwrap();
        let text = u.render();
        let u = Vault::parse(&text).unwrap().unlock(&kr).unwrap();
        assert_eq!(
            u.to_plaintext().unwrap(),
            "# Stripe\nSTRIPE_KEY=sk\n\n# DB\nDB=x\n"
        );
    }
}
