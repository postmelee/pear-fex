#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify the imported FEX source checkpoint without building or executing it."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess

PIN = '59f85d6b7df4eb053d2cc1b9d33411b4f31bfbaa'
TREE = '7509ab443d32692ac72ee51c0697ccf86d0a66af'

def digest(data):
    return hashlib.sha256(data).hexdigest()

def verify_files(root, rows):
    """Reject changed bytes, modes, duplicate paths and symlink indirection."""
    root = Path(root).absolute()
    seen = set()
    for row in rows:
        rel = PurePosixPath(row['path'])
        if rel.is_absolute() or '..' in rel.parts or not rel.parts or str(rel) != row['path']:
            raise ValueError('source_path')
        if str(rel) in seen:
            raise ValueError('duplicate_source')
        seen.add(str(rel))
        target = root / rel
        if any(p.is_symlink() for p in (target, *target.parents) if p == root or root in p.parents):
            raise ValueError('source_symlink')
        info = target.stat()
        if not stat.S_ISREG(info.st_mode) or row['kind'] != 'regular':
            raise ValueError('source_kind')
        if row['git_mode'] != '100644' or stat.S_IMODE(info.st_mode) != 0o644:
            raise ValueError('source_mode')
        raw = target.read_bytes()
        if len(raw) != row['size_bytes'] or digest(raw) != row['sha256']:
            raise ValueError('source_identity')
    return len(seen)

def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, check=True)
    return result.stdout

def verify_checkout(root, runtime_root=None, wine_root=None):
    root = Path(root).resolve()
    manifest = json.loads((root / 'Pear/Provenance/source-manifest.json').read_text())
    rows = manifest['files'] + manifest['generic_payloads']
    if len(manifest['files']) != 83 or len(manifest['generic_payloads']) != 16:
        raise ValueError('selected_set')
    count = verify_files(root, rows)
    if git(root, 'rev-parse', '--is-shallow-repository').strip() != b'false':
        raise ValueError('shallow_history')
    git(root, 'merge-base', '--is-ancestor', PIN, 'HEAD')
    if git(root, 'rev-parse', PIN + '^{tree}').decode().strip() != TREE:
        raise ValueError('upstream_tree')
    tracked = {p.decode() for p in git(root, 'ls-files', '-z').split(b'\0') if p}
    if not {r['path'] for r in rows}.issubset(tracked):
        raise ValueError('untracked_selected_source')
    if any(PurePosixPath(p).name == 'PearPhaseSelection.h' for p in tracked):
        raise ValueError('tracked_private_selector')
    upstream_readme = git(root, 'show', PIN + ':Readme.md')
    if not (root / 'Readme.md').read_bytes().startswith(upstream_readme):
        raise ValueError('upstream_readme_changed')
    external = []
    for owner, bound in (('pear-runtime', runtime_root), ('pear-wine', wine_root)):
        item = next(x for x in manifest['external_inputs'] if x['owner'] == owner)
        if bound is None:
            external.append({'owner': owner, 'status': 'not_checked_no_root_binding'})
            continue
        path = Path(bound).resolve() / item['path']
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != item['sha256']:
            raise ValueError('shared_input_identity:' + owner)
        external.append({'owner': owner, 'status': 'exact_hash_match', 'sha256': item['sha256']})
    return {'selected_files_verified': count, 'upstream_ancestry': True, 'nonshallow': True,
            'private_selector_tracked': False, 'shared_inputs': external,
            'build_performed': False, 'runtime_qualification': False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--runtime-root', type=Path)
    parser.add_argument('--wine-root', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify_checkout(args.root, args.runtime_root, args.wine_root), indent=2))

if __name__ == '__main__':
    main()
