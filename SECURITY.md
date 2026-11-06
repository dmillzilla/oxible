# Security policy

## Reporting a vulnerability

Email **[hello@davidaustinmiller.com](mailto:hello@davidaustinmiller.com)** with
the subject `Oxible security report`. Do not post exploit details or secrets in
a public issue. Include the affected version/commit, operating system, impact
and a minimal synthetic reproduction. Do not send real Vault passwords, registry
tokens, private playbooks or other credentials. Request a secure transfer method
before sending sensitive material. No encrypted-email key or response-time SLA
is currently offered.

## Supported versions

Security fixes target the latest published version and the development branch.
The current supported release is 0.1.1. Older pre-1.0 versions will not receive
separate backports. Release notes identify fixes and the affected scope.

## Trust boundaries

Lint checks are native Rust and do not execute playbooks or import Python
checking plugins. An incomplete or clean lint result is not a guarantee that a
playbook is safe to run. Project configuration, source files and dependencies
can be untrusted; retain analysis notices and compatibility warnings.

The compatible invocation prepares dependencies online by default. Use
`--offline` to skip downloads and Git transport. Explicitly configured executable
Vault credential providers can run even in offline mode; review credential
configuration before using an untrusted project. Git transport and credential
providers are bounded external processes, distinct from lint checking.

Use disposable copies when evaluating fixes against unfamiliar source. Keep
credentials outside the repository. Archive extraction, credential disclosure,
unexpected code execution, unsafe writes and bypasses of parser/resource limits
are examples of security issues to report privately. Ordinary lint compatibility
differences belong in the bug tracker.
