#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Collect exact locked dependency declarations and available upstream notices.

No license expression is rewritten or treated as legal approval. Missing source
notices remain visible in the inventory. Workspace fallbacks have pinned hashes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def legal(path):
    name = path.name.lower()
    return name in ('authors', 'authors.md', 'authors.txt') or any(part in name for part in ('license', 'licence', 'copying', 'copyright', 'notice'))


def verify_inventory(root, report):
    if report.get('unresolved') != []:
        raise ValueError('Dependency inventory has unresolved notice entries')
    lock_bytes = (root / 'Cargo.lock').read_bytes()
    if report['cargo_lock_sha256'] != sha(lock_bytes):
        raise ValueError('Dependency inventory does not match Cargo.lock')
    lock = tomllib.loads(lock_bytes.decode())
    key = lambda package: (package['name'], package['version'], package['source'])
    expected = {key(p): p for p in lock['package'] if p.get('source', '').startswith('registry+')}
    recorded = report['packages']
    if len({key(p) for p in recorded}) != len(recorded):
        raise ValueError('Dependency inventory contains duplicate packages')
    if {key(p) for p in recorded} != set(expected):
        raise ValueError('Dependency inventory package coverage differs from Cargo.lock')
    for package in recorded:
        if package['crate_checksum'] != expected[key(package)]['checksum']:
            raise ValueError('Dependency inventory has a mismatched crate checksum')
        if not package.get('license') or not package.get('files'):
            raise ValueError('Dependency inventory is missing a license declaration or notice')
        for entry in package['files']:
            relative = Path(entry['path'])
            if (relative.is_absolute() or '..' in relative.parts
                    or not relative.parts or relative.parts[0] != 'THIRD_PARTY_LICENSES'):
                raise ValueError('Dependency notice path must be inside THIRD_PARTY_LICENSES')
            file = root / relative
            if not file.resolve().is_relative_to((root / 'THIRD_PARTY_LICENSES').resolve()):
                raise ValueError('Dependency notice symlink escapes THIRD_PARTY_LICENSES')
            if sha(file.read_bytes()) != entry['sha256']:
                raise ValueError('Changed dependency notice: ' + relative.as_posix())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Verify the recorded inventory without regenerating it')
    args = parser.parse_args()
    report_path = ROOT / 'docs/dependency-notices.json'
    if args.check:
        report = json.loads(report_path.read_text())
        try:
            verify_inventory(ROOT, report)
        except (ValueError, KeyError, OSError) as error:
            raise SystemExit('Dependency notice verification failed: ' + str(error)) from None
        print(json.dumps({'verified_packages': len(report['packages']), 'unresolved': report['unresolved']}))
        return
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--offline', '--format-version', '1'], cwd=ROOT))
    overrides = json.loads((ROOT / 'docs/dependency-license-overrides.json').read_text())
    lock = tomllib.loads((ROOT / 'Cargo.lock').read_text())
    checksums = {(p['name'], p['version'], p.get('source')): p.get('checksum') for p in lock['package']}
    destination = ROOT / 'THIRD_PARTY_LICENSES/registry'
    staging = ROOT / 'target/dependency-notice-staging'
    if staging.exists(): shutil.rmtree(staging)
    staging.mkdir(parents=True)
    packages = []
    unresolved = []
    for package in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
        if not package.get('source'): continue
        name, version = package['name'], package['version']
        directory = Path(package['manifest_path']).parent
        files = []
        source_files = [file for file in directory.rglob('*') if file.is_file() and legal(file)]
        for file in sorted(source_files):
            relative = file.relative_to(directory)
            target = staging / f'{name}-{version}' / relative
            target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(file, target)
            path = Path('THIRD_PARTY_LICENSES/registry') / f'{name}-{version}' / relative
            files.append({'path': path.as_posix(), 'sha256': sha(file.read_bytes()), 'source': 'Published locked crate: ' + relative.as_posix()})
        fallback = overrides.get(name) if not files else None
        if fallback:
            for entry in fallback['files']:
                file = ROOT / entry['path']
                if sha(file.read_bytes()) != entry['sha256']: raise SystemExit('Changed workspace license: ' + str(file))
                files.append(entry)
        if not files:
            # Preserve the published declaration for review rather than inventing
            # a copyright notice that the distributed package did not contain.
            relative = Path(f'{name}-{version}') / 'Cargo.toml.orig'
            target = staging / relative; target.parent.mkdir(parents=True, exist_ok=True)
            source = directory / 'Cargo.toml.orig'; shutil.copyfile(source, target)
            files.append({'path': (Path('THIRD_PARTY_LICENSES/registry') / relative).as_posix(), 'sha256': sha(source.read_bytes()), 'source': 'Published package license/authors declaration; no standalone notice found'})
            unresolved.append({'name': name, 'version': version, 'reason': 'Published crate and pinned upstream source do not supply a collected standalone license notice; declaration retained.'})
        packages.append({'name': name, 'version': version, 'license': package.get('license'), 'repository': package.get('repository'),
                         'source': package['source'], 'crate_checksum': checksums.get((name, version, package['source'])),
                         'authors': package.get('authors', []), 'files': files, **({'workspace_basis': fallback['basis']} if fallback else {})})
    if destination.exists(): shutil.rmtree(destination)
    shutil.copytree(staging, destination)
    report = {'scope': 'All locked registry packages, including build and cross-platform dependencies. Collected texts/declarations are inventory evidence, not legal approval.',
              'cargo_lock_sha256': sha((ROOT / 'Cargo.lock').read_bytes()), 'packages': packages, 'unresolved': unresolved}
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'packages': len(packages), 'unresolved': unresolved}))


if __name__ == '__main__':
    main()
