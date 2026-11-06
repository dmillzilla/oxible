// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{FileResult, LintOptions};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

pub struct Cache {
    directory: PathBuf,
    settings: [u8; 32],
}
impl Cache {
    pub fn new(directory: PathBuf, options: &LintOptions) -> Self {
        Self {
            directory,
            settings: *blake3::hash(&serde_json::to_vec(options).expect("lint options serialize"))
                .as_bytes(),
        }
    }
    fn entry(&self, path: &Path, source: &str) -> PathBuf {
        let mut hash = blake3::Hasher::new();
        let role = crate::static_rules::role_name(path).unwrap_or_default();
        for part in [
            env!("CARGO_PKG_VERSION").as_bytes(),
            env!("OXIBLE_BUILD_HASH").as_bytes(),
            b"cache-schema-1",
            path.as_os_str().as_encoded_bytes(),
            &self.settings,
            source.as_bytes(),
            role.as_bytes(),
        ] {
            hash.update(&(part.len() as u64).to_le_bytes());
            hash.update(part);
        }
        self.directory
            .join(format!("{}.json", hash.finalize().to_hex()))
    }
    pub fn get(&self, path: &Path, source: &str) -> Option<FileResult> {
        let data = fs::read(self.entry(path, source)).ok()?;
        let result: FileResult = serde_json::from_slice(&data).ok()?;
        // Cache entries are advisory. Reject obviously inconsistent paths or
        // offsets rather than ever applying an edit to unexpected content.
        if result.diagnostics.iter().any(|item| {
            item.path != path.to_string_lossy()
                || item
                    .fix
                    .iter()
                    .chain(&item.additional_fixes)
                    .any(|fix| source.get(fix.start..fix.end) != Some(fix.expected.as_str()))
        }) {
            return None;
        }
        Some(result)
    }
    pub fn put(&self, path: &Path, source: &str, result: &FileResult) {
        let write = || -> Result<(), Box<dyn std::error::Error>> {
            fs::create_dir_all(&self.directory)?;
            let mut file = tempfile::NamedTempFile::new_in(&self.directory)?;
            serde_json::to_writer(&mut file, result)?;
            file.flush()?;
            file.persist(self.entry(path, source))?;
            Ok(())
        };
        // Read-only directories and corrupted caches never block linting.
        let _ = write();
    }
}
