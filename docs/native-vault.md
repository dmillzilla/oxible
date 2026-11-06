# Native Vault checking

Oxible reads Ansible Vault 1.1/1.2 AES256 envelopes in Rust. The reader derives
keys using the format's PBKDF2-HMAC-SHA256 parameters, authenticates ciphertext
before AES256-CTR decryption and verifies padding. RustCrypto provides the
cryptographic primitives. Neither Python nor Ansible performs production checks.

Supported controller settings are `vault_password_file`, `vault_identity_list`,
`vault_identity` and `vault_id_match` in `[defaults]` of the selected Ansible
configuration. Their `ANSIBLE_VAULT_*` environment equivalents take precedence.
Configuration-relative paths, environment-relative paths, matching identity
labels, fallback secrets and strict identity matching have native controls.
Whole-file data, inline `!vault` scalars, static `vars_files`, role defaults/vars
and imported task loading use the same native reader. Decrypted scalar nodes
retain their encrypted source identity and cannot supply scalar edits.

An executable explicitly selected as a password source supplies credentials;
it never performs checking. Native process handling forwards no stdin, bounds
stdout to 1 MiB and imposes a 10 second deadline. Provider output/errors are not
logged. A filename ending in `-client` receives `--vault-id LABEL`, as in core.
Non-executable password files are bounded to 1 MiB. Interactive prompts are
unavailable and fail explicitly. Executable-provider behavior is verified on
Linux; other platform execution remains an unobserved platform gate.

Whole-file encrypted transforms and YAML formatting for any encrypted source
remain unavailable explicitly. Safe ordinary source edits beside inline Vault
scalars are allowed; encrypted scalar edits and handler renames that would also
require changing an encrypted notification decline visibly. Ciphertext stays
byte-for-byte unchanged, and findings remain visible. Cache reuse/writes
are disabled for encrypted inputs and whenever Vault sources are configured, so
password changes cannot reuse old successful results or persist decrypted
diagnostic content. Whole-file findings retain logical plaintext positions and
an editor source position at the encrypted header. This is a checking milestone;
encrypted transform parity is still open.

[Rust regression fixtures](../tests/fixtures/vault.json) contain only a declared
public synthetic password and deterministic ciphertext. Tests verify known-value
checks, errors, identity selection, import propagation, ciphertext preservation,
provider error redaction and absence of stale password-dependent cache results.
The format reference is the pinned [ansible-core Vault reader](https://github.com/ansible/ansible/blob/v2.21.5/lib/ansible/parsing/vault/__init__.py).
