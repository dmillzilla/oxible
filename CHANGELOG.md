# Changelog

## Unreleased

- Resolve role-relative task includes with Ansible role and playbook fallbacks,
  including targets already prefixed with `tasks/`.
- Keep quoted text and shell comments from faking an enabled `pipefail`.
- Exempt Jinja blocks and comments from `no-tabs` while preserving Jinja checks.
- Check commands supplied through `_raw_params` for module recommendations.

## 0.1.2 — 2026-11-06

- Check templated `ignore_errors` settings while preserving the check-mode and
  registered-result exceptions.
- Detect shell pipelines around Jinja expressions, blocks and comments without
  mistaking filter operators or template text for shell syntax and pipefail.
- Correct missing-closing-tag diagnostics for Jinja capture blocks whose filters
  use keyword arguments, including capture blocks nested inside other blocks.

## 0.1.1 — 2026-11-06

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
