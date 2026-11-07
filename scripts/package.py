#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build local native/source archives. Does not upload or publish anything."""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile

from source_manifest import PUBLIC_DOCS, manifest, source_files, stage_source

ROOT = pathlib.Path(__file__).resolve().parents[1]


def archive(directory, destination, prefix):
    if destination.suffix == ".zip":
        with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as output:
            for file in sorted(directory.rglob("*")):
                if file.is_file():
                    output.write(file, str(pathlib.PurePosixPath(prefix) / file.relative_to(directory).as_posix()))
    else:
        with tarfile.open(destination, "w:gz") as output:
            output.add(directory, arcname=prefix)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def glibc_requirement(binary):
    if platform.system() != "Linux":
        return None
    output = subprocess.check_output(["readelf", "--version-info", str(binary)], text=True)
    versions = {tuple(map(int, text.split("."))) for text in re.findall(r"GLIBC_([0-9.]+)", output)}
    return ".".join(map(str, max(versions))) if versions else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "dist")
    parser.add_argument("--maximum-glibc", default="2.39", help="Reject Linux binaries requiring a newer glibc")
    parser.add_argument("--jobs", type=int, default=2, help="Maximum concurrent Cargo build jobs")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise SystemExit("Commit the reviewed source before packaging; working tree must be clean")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    # Resolve installed toolchain binaries before isolating Cargo's home. A
    # tool-manager shim may otherwise try to reinstall Rust in the empty cache.
    cargo = pathlib.Path(subprocess.check_output(["rustup", "which", "cargo"], cwd=ROOT, text=True).strip())
    rustc = cargo.with_name("rustc" + (".exe" if os.name == "nt" else ""))
    rustdoc = cargo.with_name("rustdoc" + (".exe" if os.name == "nt" else ""))
    subprocess.run([os.sys.executable, "scripts/collect_dependency_notices.py", "--check"], cwd=ROOT, check=True)
    subprocess.run([str(cargo), "build", "--release", "--locked", "--jobs", str(args.jobs)], cwd=ROOT, check=True)
    architecture = {"amd64": "x86_64", "arm64": "aarch64"}.get(platform.machine().lower(), platform.machine().lower())
    tag = f"{platform.system().lower()}-{architecture}"
    stem = f"oxible-{version}-{tag}"
    binary_name = "oxible.exe" if os.name == "nt" else "oxible"
    executable = ROOT / "target/release" / binary_name
    requirement = glibc_requirement(executable)
    if requirement and tuple(map(int, requirement.split("."))) > tuple(map(int, args.maximum_glibc.split("."))):
        raise SystemExit(f"Binary requires glibc {requirement}, newer than declared baseline {args.maximum_glibc}")
    binary_archive = destination / (stem + (".zip" if os.name == "nt" else ".tar.gz"))
    source_archive = destination / f"oxible-{version}-source-{tag}.tar.gz"
    receipt_path = destination / f"{stem}-release.json"
    checksums = destination / f"{stem}-SHA256SUMS"
    if any(path.exists() for path in (binary_archive, source_archive, receipt_path, checksums)):
        raise SystemExit("Refusing to overwrite versioned artifacts; choose an empty output directory")
    source_paths = source_files(ROOT)
    source_manifest = manifest(ROOT, source_paths)
    build_info = {
        "version": version, "commit": revision, "target": tag,
        "rustc": subprocess.check_output([str(rustc), "--version"], text=True).strip(),
        "host": platform.platform(), "minimum_glibc": requirement,
        "binary_sha256": sha256(executable),
        "source_manifest_sha256": hashlib.sha256(json.dumps(source_manifest, sort_keys=True).encode()).hexdigest(),
    }
    # Vendored dependencies plus a fresh release build can exceed /tmp quotas.
    staging = ROOT / "target/package-staging"
    staging.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="oxible-package-", dir=staging) as temporary:
        temporary = pathlib.Path(temporary)
        binary = temporary / "binary"
        binary.mkdir()
        for name in ("LICENSE", "README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md"):
            shutil.copy2(ROOT / name, binary / name)
        shutil.copytree(ROOT / "licenses", binary / "licenses")
        for name in PUBLIC_DOCS:
            target = binary / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        shutil.copytree(ROOT / "examples", binary / "examples")
        shutil.copy2(executable, binary / binary_name)
        source = temporary / "source"
        stage_source(ROOT, source)
        (source / ".cargo").mkdir()
        vendor = subprocess.run([str(cargo), "vendor", "--locked", "vendor"], cwd=source, capture_output=True, text=True, check=False)
        if vendor.returncode:
            raise SystemExit("Cargo vendoring failed:\n" + "\n".join(vendor.stderr.splitlines()[-20:]))
        (source / ".cargo/config.toml").write_text(vendor.stdout)
        # Prove that this source bundle is complete without the registry or
        # existing build outputs. The verification target is not archived.
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = str(temporary / "verify-target")
        environment["CARGO_HOME"] = str(temporary / "empty-cargo-home")
        environment["CARGO_NET_OFFLINE"] = "true"
        environment["RUSTC"] = str(rustc)
        environment["RUSTDOC"] = str(rustdoc)
        environment["PATH"] = str(cargo.parent) + os.pathsep + environment.get("PATH", "")
        subprocess.run([str(cargo), "build", "--release", "--locked", "--offline", "--jobs", str(args.jobs)], cwd=source, env=environment, check=True)
        rebuilt = temporary / "verify-target/release" / binary_name
        if subprocess.check_output([str(rebuilt), "--version"], text=True).strip() != f"oxible {version}":
            raise SystemExit("Rebuilt executable does not match the packaged version")
        smoke_report = temporary / "offline-rebuild-smoke.json"
        subprocess.run([os.sys.executable, str(ROOT / "scripts/release_smoke.py"), "--oxible", str(rebuilt), "--report", str(smoke_report)], check=True)
        build_info["offline_rebuilt_binary_sha256"] = sha256(rebuilt)
        smoke = json.loads(smoke_report.read_text())
        build_info["offline_rebuild_smoke"] = {
            "status": smoke["status"], "checks_passed": len(smoke["checks"]),
            "binary_sha256": smoke["binary_sha256"],
        }
        build_info["source_build_verified_offline"] = True
        for directory in (binary, source):
            (directory / "BUILD-INFO.json").write_text(json.dumps(build_info, indent=2) + "\n")
            (directory / "SOURCE-MANIFEST.json").write_text(json.dumps(source_manifest, indent=2) + "\n")
        archive(binary, binary_archive, stem)
        archive(source, source_archive, f"oxible-{version}-source")
    receipt = {**build_info, "artifacts": [{"name": path.name, "sha256": sha256(path), "bytes": path.stat().st_size} for path in (binary_archive, source_archive)]}
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    checksums.write_text("".join(f"{sha256(file)}  {file.name}\n" for file in (binary_archive, source_archive, receipt_path)))
    print(json.dumps({"binary": str(binary_archive), "source": str(source_archive), "checksums": str(checksums), "receipt": str(receipt_path), "source_build_verified_offline": True}, indent=2))


if __name__ == "__main__":
    main()
