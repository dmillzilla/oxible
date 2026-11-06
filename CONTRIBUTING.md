# Contributing to Oxible

Oxible is an experimental native Rust Ansible linter. Its ansible-lint
compatibility is incomplete. Reproducible bug reports and focused fixes are welcome.

## Build and check

Install Rust through rustup; `rust-toolchain.toml` pins the development toolchain.
Linux is the currently observed development platform. macOS and Windows are
unverified. Run from the repository root:

```sh
cargo build --locked
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
python3 scripts/collect_dependency_notices.py --check
python3 -m unittest discover -s scripts -p 'test_*.py'
```

The Python maintenance scripts require Python 3.11 or later. Python is not needed
by the shipped linter. Most native tests use only Rust and local fixtures; tests
that exercise Git transport need Git. See the test output for explicit skips.

For the editor client, install Node.js 22 or later, then run:

```sh
cd editors/vscode
npm ci --ignore-scripts
npm run check
npm test
```

The optional `npm run test:live` needs a release binary and downloads the pinned
VS Code test host. Linux CI uses Xvfb. See the [editor README](editors/vscode/README.md).

## Report a bug or propose a change

Use [GitHub issues](https://github.com/dmillzilla/oxible/issues) for nonsecurity
bugs. Include `oxible --version`, operating system, command, a minimal synthetic
playbook/config, expected behavior, actual output and analysis notices. For a
compatibility issue, include the ansible-lint/ansible-core versions and the
reference output. Remove credentials and private infrastructure information.
Report security vulnerabilities privately through [SECURITY.md](SECURITY.md).

Keep changes focused and add a regression for meaningful behavioral fixes.
Prefer small fixtures that exercise the actual CLI or loading path. Preserve
native Rust production checking, existing checks, analysis visibility and safe
fix behavior. Do not turn an upstream crash or omitted finding into a passing
comparison or disable a check to match it. Verified differences need bounded
evidence; unreviewed differences remain visible.

## Licensing and releases

Contributions are distributed under GPL-3.0-or-later, consistent with
[LICENSE](LICENSE). Retain upstream attribution and per-file notices. Dependency
changes must update `Cargo.lock` and the notice inventory; run
`python3 scripts/collect_dependency_notices.py`, then its `--check` mode.
Do not substitute a new license expression for a missing upstream notice.

The initial public version is 0.1.0. Later changes use new version
numbers and changelog entries. Creating a tag, publishing packages or uploading
release assets is outside ordinary contribution validation. See
[distribution procedure](docs/distribution.md).
