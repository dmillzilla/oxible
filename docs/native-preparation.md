# Native dependency preparation

The compatible `oxible playbook.yml` entry point prepares declared project
requirements before checking. `--offline` skips requirement downloads and SCM
transport; `--no-offline` enables them. The last CLI flag wins, then the config
`offline` value, then the entry-point default. Explicit `oxible check` defaults
to offline. Listing commands never prepare dependencies. Checking remains Rust.

The six pinned requirements locations are the project root, `roles/`,
`collections/`, `tests/`, `tests/integration/` and `tests/unit/`. Root list syntax
declares roles; mapping syntax accepts roles and collections. The nearer lint
configuration marks a project root inside an enclosing Git checkout.

Implemented collection inputs include configured Galaxy v3 registries, exact and
range SemVer requirements, transitive dependencies with bounded backtracking,
local directories, tar/gzip archives, HTTP artifacts and Git repositories with
revisions/fragments. Source repositories can contain a root collection or direct
child collections. Local project `galaxy.yml` dependencies are prepared online;
the project's own plugins remain directly visible through its local alias.
Role inputs include local directories/archives, HTTP artifacts, Git repositories
and Galaxy role repository discovery, with metadata dependency traversal.

Registry artifacts are checked against their advertised SHA-256 and collection
identity/version. Installation uses staging and atomic directory replacement;
failed checksums preserve existing versions. Archive paths and links cannot
escape the installation root. Resolution, archive size/expansion, directory
depth, HTTP time, Git time and concurrent-install waits have explicit budgets.
An unsupported input fails visibly. No Python/Ansible installer is invoked. A configured
Galaxy GPG keyring causes new collection installation to fail explicitly because
native signature verification is unavailable. Installed/offline checking still
works; an explicit `disable_gpg_verify` setting follows the controller policy.
Checksums are verified independently and are not presented as signature checks.

HTTP, authentication, resolution and extraction are Rust. Configured registries
support static `Token`, Basic, OAuth refresh and client-credential authentication;
secrets are excluded from serialization/debug output and HTTP error bodies.
Tokens are sent only to the configured server's origin. Git is an optional
external data transport, run without shell interpolation, stdin or repository
hooks, with bounded execution. It never performs lint checks.

Online isolated installations use the project's `.ansible` cache. Custom
Ansible path environments use the configured controller home cache, which remains
visible during offline checks and after requirements removal. The custom-cache
collection and role controls match complete issue fields and collection paths.
Broader cache/version conventions, all legacy Galaxy role/version conventions,
cryptographic signature verification, platform-specific transport behavior and broader authenticated
registry coverage remain acceptance work. Do not infer complete dependency
parity from a parser or successful single download.

Native integration tests exercise offline/no-network behavior, flag/config precedence,
source changes, dependency transports, checksum failures and escaping links.
Unsupported preparation requests fail explicitly.
