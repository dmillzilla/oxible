// SPDX-License-Identifier: GPL-3.0-or-later
//! Native Ansible Vault 1.1/1.2 AES256 reader. Authentication precedes decryption.
use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct Config {
    pub sources: Vec<(String, PathBuf)>,
    pub require_identity_match: bool,
    pub default_identity: String,
}

pub(crate) struct ParseError {
    pub position: crate::yaml::Position,
    pub message: String,
    pub encrypted: bool,
    pub detail: String,
}

pub(crate) fn whole_file(source: &str) -> bool {
    source
        .trim_start_matches('\u{feff}')
        .starts_with("$ANSIBLE_VAULT;")
}

pub(crate) fn contains(source: &str) -> bool {
    source.contains("$ANSIBLE_VAULT;") || source.contains("!vault")
}

fn hex(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if !bytes.len().is_multiple_of(2) || bytes.len() > MAX_BYTES {
        return Err("Invalid or oversized Vault hexadecimal payload".into());
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            Ok(
                digit(pair[0]).ok_or("Invalid Vault hexadecimal payload")? * 16
                    + digit(pair[1]).ok_or("Invalid Vault hexadecimal payload")?,
            )
        })
        .collect()
}

impl Config {
    pub fn configured(&self) -> bool {
        !self.sources.is_empty()
    }

    pub fn parse(
        &self,
        source: &str,
        single: bool,
    ) -> Result<Vec<crate::yaml::Node>, Vec<ParseError>> {
        let decrypted = if whole_file(source) {
            Some(self.decrypt(source).map_err(|message| {
                vec![ParseError {
                    position: crate::yaml::Position { line: 1, column: 1 },
                    message,
                    encrypted: true,
                    detail: String::new(),
                }]
            })?)
        } else {
            None
        };
        let source = decrypted.as_deref().map(String::as_str).unwrap_or(source);
        let mut documents = if single {
            crate::yaml::parse_lint_single(source)
        } else {
            crate::yaml::parse_lint(source)
        }
        .map_err(|errors| {
            errors
                .into_iter()
                .map(|e| ParseError {
                    position: e.position,
                    message: crate::yaml::ansible_error(source, &e),
                    encrypted: false,
                    detail: {
                        let reason = e
                            .message
                            .rsplit_once(" at byte ")
                            .map_or(e.message.as_str(), |(reason, _)| reason);
                        reason
                            .split_once(", ")
                            .map_or(reason, |(_, problem)| problem)
                            .to_owned()
                    },
                })
                .collect::<Vec<_>>()
        })?;
        let mut errors = Vec::new();
        for root in &mut documents {
            self.values(root, &mut errors);
        }
        if errors.is_empty() {
            Ok(documents)
        } else {
            Err(errors
                .into_iter()
                .map(|(position, message)| ParseError {
                    position,
                    message,
                    encrypted: true,
                    detail: String::new(),
                })
                .collect())
        }
    }

    pub fn decrypt(&self, source: &str) -> Result<Zeroizing<String>, String> {
        if source.len() > MAX_BYTES {
            return Err("Vault content exceeds the 64 MiB byte budget".into());
        }
        let mut lines = source.trim_start_matches('\u{feff}').lines();
        let header: Vec<_> = lines
            .next()
            .unwrap_or_default()
            .trim_end()
            .split(';')
            .collect();
        if header.len() < 3
            || header[0] != "$ANSIBLE_VAULT"
            || !matches!(header[1], "1.1" | "1.2")
            || header[2] != "AES256"
            || header.len() != if header[1] == "1.2" { 4 } else { 3 }
        {
            return Err(
                "Unsupported or malformed Ansible Vault header (expected 1.1/1.2 AES256)".into(),
            );
        }
        let label = header
            .get(3)
            .copied()
            .unwrap_or(if self.default_identity.is_empty() {
                "default"
            } else {
                &self.default_identity
            });
        let body: Vec<u8> = lines.flat_map(|line| line.trim().bytes()).collect();
        let payload = hex(&body)?;
        let parts: Vec<_> = payload.split(|&b| b == b'\n').collect();
        if parts.len() != 3 {
            return Err("Malformed Ansible Vault payload".into());
        }
        let salt = hex(parts[0])?;
        let signature = hex(parts[1])?;
        let ciphertext = hex(parts[2])?;
        if signature.len() != 32 || ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
            return Err(
                "Malformed Ansible Vault salt, authentication code or ciphertext length".into(),
            );
        }
        if !self.configured() {
            return Err("No Vault password source configured; set ANSIBLE_VAULT_PASSWORD_FILE or vault_password_file/vault_identity_list".into());
        }
        let mut provider_error = None;
        // Core tries matching labels first, then other configured secrets unless
        // vault_id_match is enabled. A label is a hint, not authentication.
        for (identity, path) in self.sources.iter().filter(|(id, _)| id == label).chain(
            self.sources
                .iter()
                .filter(|(id, _)| id != label && !self.require_identity_match),
        ) {
            let password = match password(path, identity) {
                Ok(value) => value,
                Err(error) => {
                    provider_error = Some(error);
                    continue;
                }
            };
            let mut key = Zeroizing::new([0_u8; 80]);
            pbkdf2::pbkdf2_hmac::<Sha256>(&password, &salt, 10_000, &mut *key);
            let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&key[32..64])
                .expect("fixed HMAC key");
            mac.update(&ciphertext);
            if mac.verify_slice(&signature).is_err() {
                continue;
            }
            let mut plain = Zeroizing::new(ciphertext.clone());
            let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&key[..32], &key[64..])
                .expect("fixed AES key and IV");
            cipher
                .try_apply_keystream(&mut plain)
                .map_err(|_| "Vault counter limit exceeded")?;
            let padding = usize::from(*plain.last().expect("nonempty authenticated ciphertext"));
            if !(1..=16).contains(&padding)
                || plain[plain.len() - padding..]
                    .iter()
                    .any(|&b| usize::from(b) != padding)
            {
                return Err("Invalid authenticated Vault padding".into());
            }
            let length = plain.len() - padding;
            plain.truncate(length);
            return String::from_utf8(std::mem::take(&mut *plain))
                .map(Zeroizing::new)
                .map_err(|_| "Decrypted Vault value is not UTF-8".into());
        }
        Err(provider_error.unwrap_or_else(|| {
            "Vault decryption failed: no configured secret authenticated this content".into()
        }))
    }

    /// Decode scalar values in place, retaining ciphertext source positions.
    /// Errors leave opaque nodes intact so unrelated known checks still run.
    pub fn values(
        &self,
        node: &mut crate::yaml::Node,
        errors: &mut Vec<(crate::yaml::Position, String)>,
    ) {
        use crate::yaml::Kind;
        if node.is_encrypted() {
            if !self.configured() {
                return;
            }
            match self.decrypt(node.scalar().unwrap_or_default()) {
                Ok(value) => {
                    node.kind = Kind::Scalar {
                        value: value.to_string(),
                        plain: false,
                        block: false,
                        vault: crate::yaml::VaultState::Decrypted,
                    };
                    node.editable = false;
                }
                Err(error) => errors.push((node.position, error)),
            }
        } else {
            match &mut node.kind {
                Kind::Sequence(values) => {
                    for value in values {
                        self.values(value, errors);
                    }
                }
                Kind::Mapping(values) => {
                    for (key, value) in values {
                        self.values(key, errors);
                        self.values(value, errors);
                    }
                }
                _ => {}
            }
        }
    }
}

fn bounded_password(input: impl Read) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut value = Zeroizing::new(Vec::new());
    input
        .take(1024 * 1024 + 1)
        .read_to_end(&mut value)
        .map_err(|_| "Cannot read Vault password source".to_owned())?;
    if value.len() > 1024 * 1024 {
        return Err("Vault password source exceeds the 1 MiB byte budget".into());
    }
    Ok(value)
}

fn password(path: &Path, identity: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let metadata = fs::metadata(path)
        .map_err(|e| format!("Cannot read Vault password file {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err("Vault password source must be a regular file or executable provider".into());
    }
    if !executable(path) {
        return trim_password(
            bounded_password(fs::File::open(path).map_err(|e| {
                format!("Cannot read Vault password file {}: {e}", path.display())
            })?)?,
            false,
        );
    }
    // This is an explicitly configured credential provider, never a checking
    // backend. Do not run a shell, forward stdin, log output or write secrets.
    use std::{
        process::{Command, Stdio},
        sync::mpsc,
        time::{Duration, Instant},
    };
    let mut command = Command::new(path);
    if path
        .file_name()
        .is_some_and(|s| s.to_string_lossy().ends_with("-client"))
    {
        command.args(["--vault-id", identity]);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Cannot start configured Vault password provider".to_owned())?;
    let output = child.stdout.take().expect("piped provider stdout");
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = send.send(bounded_password(output));
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut status = None;
    let result = loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(value) => status = value,
                Err(_) => break Err("Cannot observe Vault password provider status".into()),
            }
        }
        match receive.try_recv() {
            Ok(Err(error)) => break Err(error),
            Ok(Ok(value)) => {
                // EOF may precede process exit; wait within the same deadline.
                while status.is_none() && Instant::now() < deadline {
                    status = child.try_wait().ok().flatten();
                    if status.is_none() {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                match status {
                    Some(exit) if exit.success() => break Ok(value),
                    Some(_) => {
                        break Err("Vault password provider returned a nonzero exit status".into());
                    }
                    None => {
                        break Err(
                            "Vault password provider exceeded its 10 second time budget".into()
                        );
                    }
                }
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                break Err("Vault password provider output unavailable".into());
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if Instant::now() >= deadline {
            break Err("Vault password provider exceeded its 10 second time budget".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if status.is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
    trim_password(result?, true)
}

fn trim_password(
    mut value: Zeroizing<Vec<u8>>,
    script: bool,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let trim = |b: &u8| {
        if script {
            matches!(b, b'\r' | b'\n')
        } else {
            b.is_ascii_whitespace()
        }
    };
    let start = value.iter().position(|b| !trim(b)).unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| !trim(b))
        .map_or(start, |i| i + 1);
    let password = Zeroizing::new(value[start..end].to_vec());
    use zeroize::Zeroize;
    value.zeroize();
    if password.is_empty() {
        return Err("Vault password source returned an empty password".into());
    }
    Ok(password)
}

#[cfg(unix)]
fn executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}
#[cfg(not(unix))]
fn executable(_: &std::path::Path) -> bool {
    false
}
