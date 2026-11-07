# Source and attribution for distributions

Oxible's combined native application is GPL-3.0-or-later. [LICENSE](../LICENSE)
and [upstream attribution](attributions.md) retain the project license and upstream adaptations.
Dependencies retain their original licenses and notices; collecting them does
not change those licenses or constitute legal approval.

The repository keeps upstream attributions in `docs/attributions.md` and the
small set of retained upstream/override texts in `licenses/`. Exact dependency
notices are consolidated in `docs/third-party-notices.txt`; the inventory records
byte ranges and hashes for every locked package. Regeneration uses the locked
crate sources, and CI verifies the committed bundle without downloading crates.
Both binary and source archives include these documents. Vendored source also
retains the dependencies' own license files. No published release is rewritten.

## Check the selected source and notices

```sh
python3 scripts/collect_dependency_notices.py --check
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/source_manifest.py \
  --stage target/source-review \
  --report target/source-review-manifest.json
```

The stage directory must be empty or absent. The shared source selection in
`scripts/source_manifest.py` is used by packaging and initial repository review.
It includes code, build inputs, lockfiles, examples, tests, development scripts,
documentation, workflow files, contribution/security guidance and retained
third-party texts. It excludes build outputs, caches, downloaded reference
checkouts and editor dependencies. Symlinks and credential-like paths inside
selected source trees fail visibly. Run a dedicated secret scanner against the
staged contents and the final commit; the path checks alone are not a secret scan.

Run `gitleaks dir target/source-review --redact=100 --ignore-gitleaks-allow`
before committing, and `gitleaks git . --redact=100 --ignore-gitleaks-allow`
afterward. Review findings before distributing the selected source.

The locked Rust inventory is [dependency-notices.json](dependency-notices.json).
Verification fails on unresolved notices, missing/duplicate registry package
entries, changed crate checksums, changed/missing notice bytes or escaping paths.
For a dependency update, regenerate with
`python3 scripts/collect_dependency_notices.py` and review the resulting diff
before checking it. Workspace fallback sources and hashes are recorded in
[dependency-license-overrides.json](dependency-license-overrides.json); the
seahash distributor-curated notice is identified explicitly.

## Build corresponding source alongside binaries

When the release validation gate is complete:

```sh
python3 scripts/package.py
```

Packaging checks notices, builds the executable, stages the selected source,
vendors locked Rust dependency sources, and verifies a fresh offline release
build from that source with an empty Cargo home. The rebuilt executable must
pass the bounded release smoke suite. A clean committed source tree is required,
and existing versioned artifacts are never overwritten. The source bundle contains the vendor configuration and
build scripts; the toolchain and platform build prerequisites must be installed.
It then creates binary/source archives and SHA-256 sums in `dist/`. It does not
publish anything. Source and binaries must come from the same reviewed revision.
Do not rename old artifacts or overwrite a previously released version.
Both archives carry source/build provenance; the external release JSON records
their hashes and the offline rebuild/smoke result.

Offer corresponding source next to each downloadable binary release, including
the locked dependency source and retained notices, with clear download links.
Keep that source available for as long as the corresponding binary is offered.
Record the commit, toolchain, target, checksums, supported Linux baseline and
validation results in the release notes. Artifact builds and offline verification are performed by the packaging script.

## Editor distributions

The editor source and lockfile are included, but the native source archive does
not vendor Node.js dependencies. A VSIX is a separate optional artifact. Before
distributing one, verify its runtime dependency notices and matching source,
inspect the exact VSIX contents and rerun its live-host check. Do not assume the
Rust notice inventory covers npm packages or Marketplace distribution. The
current local historical VSIX is not a release artifact.
