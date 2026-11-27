# Contributing

Thanks for helping out. Bug reports, ideas and pull requests are all welcome.

## Setup

```sh
git clone https://github.com/whosdrix/lockdot
cd lockdot
cargo test
```

Before opening a pull request:

```sh
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

## Guidelines

- Keep the file format backwards compatible. A change to the format needs a new version tag (`#@lockdot v2`) and code that still reads v1.
- Anything touching cryptography needs a test and a short note in the PR on why it's safe.
- Use conventional commit messages: `feat:`, `fix:`, `docs:`, `test:`, `chore:`.

## Releasing

1. Update the version in `Cargo.toml` and add a section to `CHANGELOG.md`.
2. Commit, then tag and push: `git tag v0.1.0 && git push --tags`.

The release workflow builds binaries for macOS, Linux and Windows, creates the GitHub release with installers, and updates the Homebrew formula in `whosdrix/homebrew-tap` (needs the `HOMEBREW_TAP_TOKEN` secret).
