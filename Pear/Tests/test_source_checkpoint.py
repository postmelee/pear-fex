# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
import hashlib
from pathlib import Path
import tempfile
import unittest

from Pear.Tools.check_source import verify_files

class SourceCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / 'source.cpp'
        self.source.write_bytes(b'original\n')
        self.source.chmod(0o644)
        self.row = {'path': 'source.cpp', 'sha256': hashlib.sha256(b'original\n').hexdigest(),
                    'size_bytes': 9, 'git_mode': '100644', 'kind': 'regular'}

    def test_exact_bytes_and_mode(self):
        self.assertEqual(verify_files(self.root, [self.row]), 1)

    def test_changed_same_size_source_is_rejected(self):
        self.source.write_bytes(b'changed!\n')
        with self.assertRaisesRegex(ValueError, 'source_identity'):
            verify_files(self.root, [self.row])

    def test_changed_mode_is_rejected(self):
        self.source.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'source_mode'):
            verify_files(self.root, [self.row])

    def test_identical_bytes_through_symlink_are_rejected(self):
        link = self.root / 'link.cpp'
        link.symlink_to(self.source.name)
        with self.assertRaisesRegex(ValueError, 'source_symlink'):
            verify_files(self.root, [{**self.row, 'path': link.name}])

    def test_parent_symlink_is_rejected(self):
        folder = self.root / 'alias'
        folder.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'source_symlink'):
            verify_files(self.root, [{**self.row, 'path': 'alias/source.cpp'}])

    def test_traversal_and_duplicates_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'source_path'):
            verify_files(self.root, [{**self.row, 'path': '../source.cpp'}])
        with self.assertRaisesRegex(ValueError, 'duplicate_source'):
            verify_files(self.root, [self.row, self.row])

    def test_missing_source_is_rejected(self):
        with self.assertRaises(FileNotFoundError):
            verify_files(self.root, [{**self.row, 'path': 'missing.cpp'}])
