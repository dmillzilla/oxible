# Changelog

## 0.1.1 — Unreleased

- Correct Jinja syntax-error messages after an `else` branch to report only the
  remaining closing tag, matching the pinned ansible-lint behavior.

## 0.1.0 — 2026-11-06

Initial public release.

- Native Rust Ansible linting, with experimental compatibility against pinned
  ansible-lint builtin workflows.
- Text, JSON, Code Climate and SARIF output; compatible CLI/configuration,
  baselines and suppression support within documented limits.
- Source-preserving fixes with rechecks and explicit refusals, plus a stdio
  language server and an unpublished VS Code client.
- Native static module metadata, bounded project loading, Vault input and
  dependency preparation with visible unavailable/dynamic analysis.
- GPL-3.0-or-later licensing, upstream/dependency attribution and corresponding
  source packaging.

Compatibility is experimental; full ansible-lint drop-in parity is not claimed.
Linux x86-64/glibc 2.39 is the initial binary target. macOS/Windows remain
unverified.
