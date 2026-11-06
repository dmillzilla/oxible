# Oxible

**Ansible checks, forged in Rust.**

Oxible 0.1.1 is an experimental Ansible linter written in Rust, with safe fixes,
a language server, and text/JSON/SARIF/Code Climate output. Production checking
needs no Python or Ansible installation and does not execute playbooks.
Compatible CLI workflows prepare declared dependencies online; use `--offline`
to skip downloads. See [native preparation](docs/native-preparation.md).

Oxible is experimental and is not yet a drop-in replacement for ansible-lint.
Review its findings and analysis notices on your project before replacing an
existing CI gate. Production checks remain native Rust, with no Python backend.

The initial binary target is Linux x86-64 with glibc 2.39 or later, validated
on Ubuntu 24.04 userspace and the local Linux host. macOS, Windows and musl
are unverified. The VS Code client is available as source and is not published
to the Marketplace.

## Get started

Download the Linux archive and checksums from the
[0.1.1 release](https://github.com/dmillzilla/oxible/releases/tag/v0.1.1),
or build from source:

```sh
cargo build --release --locked
./target/release/oxible check examples/good.yml
./target/release/oxible check examples/bad.yml
./target/release/oxible rules
```

The good example passes. The bad example produces six findings and exits 1.
Source builds use pinned Rust 1.99.1. Install with
`cargo install --path . --locked`; installed executables need no Rust toolchain.

## Daily use

```sh
oxible check . --profile safety
oxible check site.yml roles/web/tasks
oxible check . --select metadata,syntax
oxible check . --enable role-argument-spec
oxible check . --skip package-latest --exclude 'vendor/**'
oxible check . --select all --format sarif
oxible check playbook.yml --diff
oxible check playbook.yml --fix
oxible check . --generate-ignore
oxible check . --strict --no-cache
oxible profiles
oxible tags
```

Defaults follow the pinned upstream rule tags, opt-ins and warning list.
`--select` replaces the defaults or profile; `--enable` adds opt-in rules.
Selectors accept family IDs, registered subrules and category tags. Six progressive
profiles use the upstream rule lists, omitting unimplemented upstream placeholders.

Native module resolution and traversal of available imports/roles run by default.
`--no-syntax-check` disables module validation for isolated rule analysis;
`--no-follow-imports` limits checking to the input files. A rule selection can
exclude schema validation, matching upstream; schema failures that are reported
are fatal. Syntax errors and reported schema errors cannot be hidden with
`noqa`, skips, warning lists or baselines.

Task comments support `# noqa` and `# noqa: rule,other-rule`. YAML lint rules use
`# yamllint disable-line rule:...` and block directives, as upstream does.
`.yamllint` files support rule options, severity, ignore paths and inherited
configuration. The bundled default is the pinned ansible-lint YAML policy.

Baseline findings remain visible and do not fail unless `--strict` is used; an
entry ending in `skip` hides that finding. `--generate-ignore` overwrites the
working-directory baseline. Baseline findings are not automatically fixed.

Pipe buffers to `oxible check - --stdin-filename tasks/new.yml`; stdin supports
diagnostics and `--diff`. Scans respect Git ignores and exclusions. Configuration
exclusions use the configuration directory; CLI exclusions use cwd. Ordered upstream
file patterns protect templates and identify metadata, vars, tasks and playbooks.
Generic YAML receives YAML checks; use `--kind tasks` or configured `kinds` for
ambiguous standalone task lists.

## Configuration and collections

Oxible searches for `.oxible.yml`/`.yaml`, `.ansible-lint` variants and
`.config/ansible-lint.yml`/`.yaml`, stopping at the Git boundary. Unsupported
Oxible keys are errors. Unsupported ansible-lint keys/rules produce warnings.

```yaml
profile: safety
skip_list: [package-latest]
warn_list: [experimental, 'jinja[spacing]', 'fqcn[deep]']
enable_list: [role-argument-spec]
exclude_paths: [vendor/]
max_tasks: 100
max_block_depth: 20
var_naming_pattern: '^[a-z_][a-z0-9_]*$'
loop_var_prefix: '^(__|{role}_)'
kinds:
  - tasks: '**/*.ansible'
mock_modules: [acme.tools.unavailable]
mock_roles: [unavailable_role]
extra_vars: {environment: staging}
# module_metadata: modules.json
```

Filesystem collection routing resolves local modules, declared collections,
`meta/runtime.yml` redirects, local library overrides and collection roles.
`ANSIBLE_COLLECTIONS_PATH`, `ANSIBLE_LIBRARY` and `ANSIBLE_ROLES_PATH` are honored.
Installed Python module files are parsed as metadata using Rust; never imported
or executed. Documentation fragments, literal constructor specs, shared module_utils
constants, simple spec factories and declarative helper classes are supported.
Bounded native template evaluation resolves simple include paths using play/task
vars and `extra_vars`. Paths requiring Ansible lookups, custom filters or runtime
facts remain unresolved.

Builtin metadata is pinned to ansible-core 2.21.5. Declarative constructor
specifications cover required arguments, aliases, types, choices, nested options
and required-if/one-of/together/by constraints. Controller actions and dynamically
computed specifications have explicit limits. Installed collection options are
loaded automatically; an export is optional for overriding or supplying metadata
that cannot be read statically. Create an export in a development environment:

```sh
ansible-doc -j acme.tools.widget > modules.json
```

Set `module_metadata: modules.json`; raw ansible-doc output or a compact FQCN map
with `options` is accepted. Exports may also provide `argument_spec` and declarative
constraints. Consuming the file needs no Ansible installation. Unrelated collection
modules never receive builtin semantics merely because their names share a suffix.

## Fixes, CI and editors

Safe edits remove conditional wrappers, normalize boolean keywords and format
single-line Jinja expressions using native Rust parsers. They preserve comments
and permissions, refuse stale or overlapping edits, reparse and recheck output,
and protect anchors, inherited values and multiline scalars. Unsupported structural
rewrites remain diagnostics.

`oxible check` exits 0 (clean/warn-only), 1 (policy findings/diff), or 2
(syntax/I/O/configuration failure). Its JSON is a native report object.
`--format codeclimate` emits Code Climate issues. Implicit invocation supports
common ansible-lint workflows, emits Code Climate JSON and uses policy exit 2:

```sh
oxible site.yml -f json -t name -x 'name[casing]' --offline
oxible . --profile production -i .ansible-lint-ignore
oxible --list-rules
oxible site.yml -f json --analysis-report coverage.json
```

Run `oxible server` for stdio LSP diagnostics, incremental UTF-16 edits and
versioned quick fixes/fix-all. The [VS Code client](editors/vscode/README.md) and
[editor guide](docs/editors.md) describe setup. Source, settings, metadata and build
inputs key the cache; module and role resolution is revalidated on cache hits.
Incomplete static metadata and unresolved dynamic imports produce stderr notices.
The analysis sidecar records their scope; native report JSON and SARIF also carry
these records. Incomplete static analysis is reported explicitly; a clean result
does not establish that a playbook will execute successfully.

## Development and distribution

```sh
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
python3 scripts/package.py
```

Production lint checks run in Rust. Optional Git dependency transport and explicitly
configured Vault credential providers launch bounded external processes; see
[native preparation](docs/native-preparation.md) and [Vault scope](docs/native-vault.md).
Packaging creates
native and vendored-source archives and verifies an offline source rebuild.
Artifacts are not published automatically. This independent project is
GPL-3.0-or-later; [NOTICE](NOTICE) retains upstream attribution.


Contributions and compatibility reproductions are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md), and
[SECURITY.md](SECURITY.md). See [distribution](docs/distribution.md) for source,
license and release-artifact verification.
