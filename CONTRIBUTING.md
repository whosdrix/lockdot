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
