#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Select and optionally stage the source distribution. Never publishes."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DOCS = (
    "docs/native-preparation.md", "docs/native-vault.md", "docs/editors.md",
    "docs/distribution.md", "docs/dependency-notices.json",
    "docs/dependency-license-overrides.json",
)
SOURCE_PATHS = (
    "Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml", "mise.toml",
    "LICENSE", "NOTICE", "README.md", "CONTRIBUTING.md", "SECURITY.md",
    "CHANGELOG.md", ".gitignore", ".github/workflows/ci.yml",
    ".github/workflows/artifacts.yml", ".github/ISSUE_TEMPLATE/bug_report.yml",
    "THIRD_PARTY_LICENSES", "src", "assets", "tests", "examples",
    "scripts/source_manifest.py", "scripts/package.py", "scripts/release_smoke.py",
    "scripts/collect_dependency_notices.py", "scripts/test_distribution.py",
    "editors/vscode", *PUBLIC_DOCS,
)
EXCLUDED_DIRECTORIES = {
    "node_modules", "target", "dist", ".git", ".oxible_cache", "__pycache__",
    ".ansible", ".venv", ".vscode-test",
}


def source_files(root, paths=SOURCE_PATHS):
    """Return regular source files; reject symlinks and credential-like paths."""
    files = []

    def visit(path):
        relative = path.relative_to(root)
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root and root in parent.parents):
            raise ValueError(f"Source selection contains a symlink: {relative}")
        if path.is_dir():
            if path.name in EXCLUDED_DIRECTORIES:
                return
            for child in sorted(path.iterdir()):
                visit(child)
        elif path.is_file():
            if path.suffix in {".vsix", ".pyc"} or path.name == ".DS_Store":
                return
            if (path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example")
                    or path.suffix in {".pem", ".key"} or path.name in {"id_rsa", "id_ed25519"}):
                raise ValueError(f"Review credential-like source path: {relative}")
            files.append(relative.as_posix())
        else:
            raise ValueError(f"Missing or nonregular source input: {relative}")

    for name in paths:
        path = Path(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Source roots must stay inside the repository")
        visit(root / path)
    return sorted(set(files))


def stage_source(root, destination, files=None):
    files = source_files(root) if files is None else files
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("Source staging directory must be empty")
    destination.mkdir(parents=True, exist_ok=True)
    for relative in files:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / relative, target)


def manifest(root, files):
    return {
        "scope": "Explicit public source/build/user docs and retained third-party notices; internal planning and comparison records are not selected.",
        "files": [{"path": relative,
                   "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
                   "mode": (root / relative).stat().st_mode & 0o777}
                  for relative in files],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    files = source_files(ROOT)
    if args.stage:
        stage_source(ROOT, args.stage, files)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(manifest(ROOT, files), indent=2) + "\n")
    print(json.dumps({"source_files": len(files), "staged": bool(args.stage)}))


if __name__ == "__main__":
    main()
