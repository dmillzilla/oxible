# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression checks for release inventory and source-selection failures."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from collect_dependency_notices import legal, verify_inventory
import package
from source_manifest import PUBLIC_DOCS, source_files, stage_source


class DistributionChecks(unittest.TestCase):
    def test_public_selection_excludes_internal_records_and_keeps_build_source(self):
        root = Path(__file__).resolve().parents[1]
        files = set(source_files(root))
        self.assertEqual({p for p in files if p.startswith('docs/')}, set(PUBLIC_DOCS))
        self.assertNotIn('PARITY_PLAN.md', files)
        self.assertNotIn('.github/workflows/parity.yml', files)
        self.assertFalse(any(p.startswith('scripts/compare_') for p in files))
        self.assertTrue({'Cargo.toml', 'Cargo.lock', 'build.rs', 'src/main.rs', 'LICENSE', 'docs/attributions.md'} <= files)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        lock = '''version = 4
[[package]]
name = "example"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "fixture-checksum"
'''
        (self.root / 'Cargo.lock').write_text(lock)
        notice = self.root / 'licenses/example/LICENSE'
        notice.parent.mkdir(parents=True)
        notice.write_text('Synthetic test license text')
        self.report = {
            'cargo_lock_sha256': hashlib.sha256(lock.encode()).hexdigest(),
            'unresolved': [],
            'packages': [{'name': 'example', 'version': '1.0.0',
                          'source': 'registry+https://github.com/rust-lang/crates.io-index',
                          'crate_checksum': 'fixture-checksum', 'license': 'MIT',
                          'files': [{'path': 'licenses/example/LICENSE',
                                     'sha256': hashlib.sha256(notice.read_bytes()).hexdigest()}]}],
        }

    def test_library_name_is_not_a_license_notice(self):
        self.assertFalse(legal(Path('libwinapi_oemlicense.a')))
        self.assertTrue(legal(Path('LICENSE-MIT')))

    def test_complete_inventory(self):
        verify_inventory(self.root, self.report)

    def test_unresolved_notice_fails(self):
        self.report['unresolved'] = [{'name': 'example'}]
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            verify_inventory(self.root, self.report)

    def test_missing_package_fails_even_with_matching_lock_hash(self):
        self.report['packages'] = []
        with self.assertRaisesRegex(ValueError, 'coverage'):
            verify_inventory(self.root, self.report)

    def test_duplicate_package_fails(self):
        self.report['packages'] *= 2
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            verify_inventory(self.root, self.report)

    def test_changed_notice_fails(self):
        (self.root / self.report['packages'][0]['files'][0]['path']).write_text('changed')
        with self.assertRaisesRegex(ValueError, 'Changed'):
            verify_inventory(self.root, self.report)

    def test_checksum_mismatch_fails(self):
        self.report['packages'][0]['crate_checksum'] = 'wrong'
        with self.assertRaisesRegex(ValueError, 'checksum'):
            verify_inventory(self.root, self.report)

    def test_notice_cannot_escape_distribution(self):
        self.report['packages'][0]['files'][0]['path'] = '../outside'
        with self.assertRaisesRegex(ValueError, 'inside licenses'):
            verify_inventory(self.root, self.report)

    def test_notice_symlink_cannot_escape(self):
        outside = self.root / 'outside'
        outside.write_text('outside')
        notice = self.root / 'licenses/link'
        try:
            notice.symlink_to(outside)
        except OSError:
            self.skipTest('Symlink creation is unavailable')
        self.report['packages'][0]['files'][0]['path'] = 'licenses/link'
        with self.assertRaisesRegex(ValueError, 'escapes'):
            verify_inventory(self.root, self.report)

    def make_bundle(self):
        data = (self.root / 'licenses/example/LICENSE').read_bytes()
        (self.root / 'docs').mkdir()
        (self.root / 'docs/third-party-notices.txt').write_bytes(data)
        self.report['bundle'] = {'path': 'docs/third-party-notices.txt', 'sha256': hashlib.sha256(data).hexdigest()}
        self.report['packages'][0]['files'][0]['bundle'] = {'offset': 0, 'length': len(data)}

    def test_bundle_verifies_exact_bytes(self):
        self.make_bundle()
        verify_inventory(self.root, self.report)

    def test_bundle_corruption_fails(self):
        self.make_bundle()
        (self.root / 'docs/third-party-notices.txt').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'Changed dependency notice bundle'):
            verify_inventory(self.root, self.report)

    def test_bundle_ranges_cannot_escape(self):
        self.make_bundle()
        self.report['packages'][0]['files'][0]['bundle']['offset'] = -1
        with self.assertRaisesRegex(ValueError, 'range'):
            verify_inventory(self.root, self.report)

    def test_bundling_does_not_hide_changed_retained_license(self):
        self.make_bundle()
        (self.root / 'licenses/example/LICENSE').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'Changed retained notice'):
            verify_inventory(self.root, self.report)

    def test_selection_excludes_outputs_and_retains_build_inputs(self):
        scripts = self.root / 'scripts'
        scripts.mkdir()
        (scripts / 'build.py').write_text('print("fixture")')
        (scripts / '__pycache__').mkdir()
        (scripts / '__pycache__/output.pyc').write_bytes(b'ignored')
        files = source_files(self.root, ['scripts', 'Cargo.lock'])
        self.assertEqual(files, ['Cargo.lock', 'scripts/build.py'])
        destination = self.root / 'target/staged'
        stage_source(self.root, destination, files)
        self.assertEqual((destination / 'Cargo.lock').read_bytes(), (self.root / 'Cargo.lock').read_bytes())
        self.assertFalse((destination / 'scripts/__pycache__').exists())

    def test_source_rejects_credential_file(self):
        scripts = self.root / 'scripts'
        scripts.mkdir()
        (scripts / '.env').write_text('synthetic fixture')
        with self.assertRaisesRegex(ValueError, 'credential-like'):
            source_files(self.root, ['scripts'])

    def test_source_rejects_symlinks(self):
        link = self.root / 'link'
        try:
            link.symlink_to(self.root / 'Cargo.lock')
        except OSError:
            self.skipTest('Symlink creation is unavailable')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            source_files(self.root, ['link'])

    def test_staging_cannot_retain_unreviewed_old_files(self):
        destination = self.root / 'staged'
        destination.mkdir()
        (destination / 'unreviewed').write_text('old')
        with self.assertRaisesRegex(ValueError, 'must be empty'):
            stage_source(self.root, destination, ['Cargo.lock'])

    def test_linux_baseline_uses_highest_numeric_symbol_version(self):
        with patch.object(package.platform, 'system', return_value='Linux'), patch.object(
            package.subprocess, 'check_output', return_value='GLIBC_2.9 GLIBC_2.39 GLIBC_2.17'
        ):
            self.assertEqual(package.glibc_requirement(Path('fixture')), '2.39')

    def test_packaging_rejects_uncommitted_source_before_building(self):
        (self.root / 'Cargo.toml').write_text('[package]\nversion = "0.1.0"\n')
        with patch.object(package, 'ROOT', self.root), patch.object(
            package.subprocess, 'check_output', return_value=b' M src/lib.rs\n'
        ), patch.object(package.subprocess, 'run') as build, patch(
            'sys.argv', ['package.py', '--output', str(self.root / 'dist')]
        ):
            with self.assertRaisesRegex(SystemExit, 'working tree must be clean'):
                package.main()
            build.assert_not_called()

    def test_source_archive_preserves_notice_bytes_and_build_metadata(self):
        staged = self.root / 'source'
        stage_source(self.root, staged, ['Cargo.lock', 'licenses/example/LICENSE'])
        (staged / 'BUILD-INFO.json').write_text('{"version":"0.1.0"}\n')
        archive = self.root / 'source.tar.gz'
        package.archive(staged, archive, 'oxible-0.1.0-source')
        import tarfile
        with tarfile.open(archive) as contents:
            self.assertEqual(
                contents.extractfile('oxible-0.1.0-source/licenses/example/LICENSE').read(),
                (staged / 'licenses/example/LICENSE').read_bytes(),
            )
            self.assertIn('oxible-0.1.0-source/Cargo.lock', contents.getnames())
            self.assertIn('oxible-0.1.0-source/BUILD-INFO.json', contents.getnames())


if __name__ == '__main__':
    unittest.main()
