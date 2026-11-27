# Security

## Reporting a vulnerability

Please don't open a public issue. Use [GitHub's private vulnerability reporting](https://github.com/whosdrix/lockdot/security/advisories/new) instead. You'll get a reply within a few days.

## Threat model

lockdot protects secret **values** in a file that is stored somewhere you don't fully trust, usually a git repository that more people can read than should see production credentials.

### What lockdot protects against

- **Someone who can read the repo but isn't a member.** They see variable names, comments, member labels and public keys. They don't see values.
- **Tampering by someone who isn't a member.** Every file carries an HMAC-SHA256 over the members and every name/ciphertext pair, keyed from the data key. Adding, removing, reordering into other names or replaying a value under a different name makes `lockdot` refuse the file.
- **Guessing secrets by length.** Values are padded to a multiple of 32 bytes before encryption.
- **Plaintext left on disk.** `lockdot run` passes values straight into the child process. `lockdot edit` writes to a temp file with mode `0600` inside a private temp directory and deletes it afterwards.

### What lockdot does not protect against

- **Members.** Anyone who can decrypt the file can copy every value. Removing a member rotates the data key so they can't read future values, but they keep whatever they saw, and old versions remain in git history. Rotate the real credentials when someone leaves.
- **A compromised machine.** If an attacker can read your identity file or your unencrypted SSH key, they are you.
- **Members tampering.** A member holds the data key and can write a valid file. Review changes to `.lockdot` files in pull requests like any other code, including changes to the `#@member` lines.
- **Metadata.** Variable names, comments, the number of variables and approximate value lengths are visible by design. Don't put secrets in names or comments.
- **Rollback.** A file can be replaced with an older valid version of itself. Git history is the source of truth here.

## Cryptography

| Part | Choice |
|---|---|
| Data key | 32 random bytes from the OS, one per file |
| Key wrapping | [age](https://age-encryption.org/v1) (X25519, or ssh-ed25519 / ssh-rsa recipients) via the `age` crate |
| Key derivation | HKDF-SHA256 from the data key, with separate `info` strings for values and the MAC |
| Values | XChaCha20-Poly1305, random 192-bit nonce, associated data `lockdot:v1:<NAME>` |
| Padding | ISO/IEC 7816-4 to a multiple of 32 bytes |
| Integrity | HMAC-SHA256 over the version, members and sorted `NAME=ciphertext` pairs |

lockdot uses audited RustCrypto and age implementations and doesn't implement any primitives itself.

When a value is set to what it already was, the old ciphertext is kept. This reveals that the value didn't change, which is the point of readable diffs. A changed value always gets a new nonce.
