// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    fs,
    path::{Path, PathBuf},
};

fn collect(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).expect("read source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            collect(&path, files);
        } else {
            files.push(path);
        }
    }
}

fn main() {
    for path in ["src", "assets", "Cargo.toml", "Cargo.lock", "build.rs"] {
        println!("cargo:rerun-if-changed={path}");
    }
    let mut files = vec![
        PathBuf::from("Cargo.toml"),
        PathBuf::from("Cargo.lock"),
        PathBuf::from("build.rs"),
    ];
    collect(Path::new("src"), &mut files);
    collect(Path::new("assets"), &mut files);
    files.sort();
    let mut hasher = blake3::Hasher::new();
    for file in files {
        let data = fs::read(file).expect("read build input");
        hasher.update(&(data.len() as u64).to_le_bytes());
        hasher.update(&data);
    }
    println!(
        "cargo:rustc-env=OXIBLE_BUILD_HASH={}",
        hasher.finalize().to_hex()
    );
}
