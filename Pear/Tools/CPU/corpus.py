#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Inventory a pinned CPU corpus. This tool never executes or qualifies guests."""
from pathlib import Path
import argparse
import collections
import hashlib
import os
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from pear_runtime.assembly._common import read_relative, decode_json, encoded, load_json
from pear_runtime.errors import Error, need

CONTRACT_ROOT = Path(__file__).resolve().parents[2] / 'Tests/CPU'
GPRS = set('RAX RBX RCX RDX RSI RDI RBP RSP R8 R9 R10 R11 R12 R13 R14 R15'.split())
POLICY = {name: '1' for name in ('FEX_TSOENABLED', 'FEX_VECTORTSOENABLED',
          'FEX_MEMCPYSETTSOENABLED', 'FEX_HALFBARRIERTSOENABLED')}
CATEGORIES = {'partial_register', 'flags', 'simd', 'float', 'memory', 'atomic',
              'ordering', 'tls', 'callback', 'abi', 'fault', 'seh', 'guard', 'code_change'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def keys(value, names, code):
    need(type(value) is dict and set(value) == set(names.split()), code)


def number(value):
    need(type(value) is str and re.fullmatch(r'(?:0x[0-9a-fA-F]+|[0-9]+)', value), 'integer_encoding')
    result = int(value, 16 if value.startswith('0x') else 10)
    need(0 <= result < 1 << 64, 'integer_range')
    return result


def config(raw):
    need(len(raw) <= 1024 * 1024, 'asm_size')
    text = raw.decode('utf-8')
    blocks = re.findall(r'^%ifdef\s+CONFIG\s*\n(.*?)^%endif\s*$', text, re.M | re.S)
    need(len(blocks) == 1, 'config_block')
    result = decode_json(blocks[0].encode())
    need(type(result) is dict, 'config_type')
    return result


def contract(cfg):
    """Explicit selected subset; never ignore a field the runner cannot model."""
    need(not set(cfg) - {'RegData', 'HostFeatures', 'MemoryRegions', 'MemoryData', 'Env'},
         'unsupported_config_key')
    env = cfg.get('Env', {})
    need(type(env) is dict and all(k in POLICY and v == POLICY[k] for k, v in env.items()),
         'conflicting_environment')
    features = cfg.get('HostFeatures', [])
    need(type(features) is list and len(features) == len(set(features)) and
         all(type(f) is str and re.fullmatch(r'[A-Za-z0-9_.]+', f) for f in features), 'feature_list')
    regs = cfg.get('RegData')
    need(type(regs) is dict and regs, 'empty_expectations')
    outcomes = []
    for reg, value in sorted(regs.items()):
        is_vector = re.fullmatch(r'XMM(?:[0-9]|1[0-5])', reg) is not None
        need(reg in GPRS or is_vector, 'unsupported_register')
        values = value if type(value) is list else [value]
        allowed = (2, 4) if is_vector and 'AVX' in features else ((2,) if is_vector else (1,))
        need(len(values) in allowed, 'register_width')
        for lane, item in enumerate(values):
            outcomes.append(dict(register=reg, lane=lane, value=f'0x{number(item):016x}'))
    regions = []
    need(type(cfg.get('MemoryRegions', {})) is dict, 'memory_regions')
    for start, size in cfg.get('MemoryRegions', {}).items():
        start, size = number(start), number(size)
        need(start % 4096 == 0 and size % 4096 == 0 and 0 < size <= 16 * 1024 * 1024
             and start + size < 1 << 47, 'memory_region_range')
        need(all(start + size <= r['address'] or r['address'] + r['size'] <= start for r in regions),
             'memory_region_overlap')
        regions.append(dict(address=start, size=size))
    initial = []
    need(type(cfg.get('MemoryData', {})) is dict, 'memory_data')
    for address, value in cfg.get('MemoryData', {}).items():
        address = number(address)
        need(type(value) is str and re.fullmatch(r'[0-9a-fA-F]{2}(?: [0-9a-fA-F]{2})*', value), 'memory_data_encoding')
        data = bytes.fromhex(value)
        need(any(r['address'] <= address and address + len(data) <= r['address'] + r['size'] for r in regions),
             'memory_data_outside_region')
        initial.append(dict(address=address, bytes=data.hex()))
    return dict(expectations=outcomes, features=features, regions=sorted(regions, key=lambda r:r['address']),
                initial_memory=sorted(initial, key=lambda r:r['address']), environment=env)


def inventory(source):
    asm = source / 'unittests/ASM'
    need(asm.is_dir() and not asm.is_symlink(), 'asm_root')
    rows, configs, size = [], {}, 0
    for folder, dirs, files in os.walk(asm, followlinks=False):
        need(not any((Path(folder)/n).is_symlink() for n in dirs + files), 'source_symlink')
        for name in sorted(files):
            if not name.endswith('.asm'):
                continue
            path = (Path(folder)/name).relative_to(source).as_posix()
            raw = read_relative(source, path, limit=1024*1024)
            size += len(raw)
            need(len(rows) < 5000 and size <= 64*1024*1024, 'inventory_bounds')
            try:
                cfg, error = config(raw), None
            except Error as exc:
                cfg, error = None, exc.code
            configs[path] = cfg
            rows.append(dict(path=path, sha256=digest(raw),
                             config_sha256=digest(encoded(cfg)) if cfg is not None else None,
                             config_error=error))
    need(rows, 'empty_inventory')
    return sorted(rows, key=lambda r:r['path']), configs


def assess(source, manifest, sources, *, contract_root, boundary_root):
    keys(manifest, 'version scope sources_sha256 cases boundaries unsupported', 'manifest_fields')
    need(type(manifest['version']) is int and manifest['version'] == 1 and manifest['scope'] == 'cpu_corpus_contract', 'manifest_scope')
    need(manifest['sources_sha256'] == digest(encoded(sources)), 'sources_lock_changed')
    keys(sources, 'version fex reviews selection_ids', 'sources_fields')
    need(type(sources['version']) is int and sources['version'] == 1, 'sources_version')
    fex = sources['fex']
    keys(fex, 'repository revision inventory_count inventory_sha256 files', 'fex_source_fields')
    need(re.fullmatch(r'[0-9a-f]{40}', fex['revision']) and fex['repository'] == 'https://github.com/FEX-Emu/FEX', 'fex_identity')
    for path, sha in fex['files'].items():
        need(digest(read_relative(source, path)) == sha, 'reviewed_source_changed')
    if 'LICENSE' in fex['files']:
        need(digest(read_relative(contract_root, 'LICENSES/FEX-MIT.txt')) == fex['files']['LICENSE'],
             'retained_notice_changed')
    rows, configs = inventory(source)
    need(len(rows) == fex['inventory_count'] and digest(encoded(rows)) == fex['inventory_sha256'], 'inventory_changed')
    by_path = {r['path']: r for r in rows}
    need(type(manifest['cases']) is list and manifest['cases'], 'missing_cases')
    ids, selected, categories = set(), set(), set()
    for case in manifest['cases']:
        keys(case, 'id path sha256 config_sha256 categories requirement contract masks setup reference', 'case_fields')
        need(type(case['id']) is str and re.fullmatch('[a-z0-9-]+', case['id']) and case['id'] not in ids, 'duplicate_case')
        ids.add(case['id'])
        path = case['path']
        need(path not in selected and path in by_path, 'case_path')
        selected.add(path)
        need(case['sha256'] == by_path[path]['sha256'] and case['config_sha256'] == by_path[path]['config_sha256'], 'case_source_changed')
        need(by_path[path]['config_error'] is None, 'selected_config_invalid')
        actual = contract(configs[path])
        need(actual == case['contract'], 'case_contract_changed')
        need(case['requirement'] == ('required_if_exposed' if actual['features'] else 'required'), 'feature_requirement')
        need(type(case['categories']) is list and case['categories'] and set(case['categories']) <= CATEGORIES, 'case_categories')
        categories.update(case['categories'])
        need(case['reference'] == 'native_windows_x64_same_pe_unavailable', 'reference_not_observed')
        keys(case['setup'], 'scratch_address scratch_size mxcsr x87_control entry termination', 'setup_fields')
        setup = case['setup']
        need(setup == dict(scratch_address=0xe0000000, scratch_size=65536, mxcsr=0x1f80,
                          x87_control=0x37f, entry='zero_gprs_vectors_preserve_native_abi_owned_stack',
                          termination='capture_at_hlt_without_flag_changes'), 'setup_contract')
        need(type(case['masks']) is list and len(case['masks']) == len(actual['expectations']), 'missing_masks')
        for mask in case['masks']:
            keys(mask, 'bits reason', 'mask_fields')
            need(number(mask['bits']) > 0 and type(mask['reason']) is str and mask['reason'].strip(), 'empty_mask')
    need(type(manifest['boundaries']) is list and manifest['boundaries'], 'missing_boundaries')
    for boundary in manifest['boundaries']:
        keys(boundary, 'id categories stage source expected status', 'boundary_fields')
        need(boundary['id'] not in ids, 'duplicate_case'); ids.add(boundary['id'])
        need(boundary['stage'] in (2, 3) and boundary['status'] == 'unperformed', 'boundary_scope')
        need(type(boundary['expected']) is str and boundary['expected'].strip(), 'boundary_expectation')
        need(boundary['categories'] and set(boundary['categories']) <= CATEGORIES, 'boundary_categories')
        categories.update(boundary['categories'])
        if boundary['source'] is not None:
            keys(boundary['source'], 'path sha256', 'boundary_source')
            need(digest(read_relative(boundary_root, boundary['source']['path'])) == boundary['source']['sha256'], 'boundary_source_changed')
    need(categories == CATEGORIES, 'missing_required_category')
    need(sorted(ids) == sources['selection_ids'], 'missing_selected_case')
    need(type(manifest['unsupported']) is dict and manifest['unsupported'].get('i386'), 'missing_unsupported')
    census = []
    for row in rows:
        if row['config_error'] is not None:
            reason = row['config_error']
        elif row['path'] in selected:
            reason = 'selected_unperformed'
        else:
            try:
                parsed = contract(configs[row['path']])
                reason = 'outside_selected_feature_corpus' if parsed['features'] else 'outside_selected_finite_corpus'
            except Error as exc:
                reason = exc.code
        census.append(dict(row, classification=reason))
    return dict(scope='source_inventory_only', inventory_valid=True, guest_execution=False,
                cpu_qualified=False, reference_status='unavailable', selected=len(selected),
                required_boundaries=len(manifest['boundaries']), categories=sorted(categories),
                census_count=len(census), census_sha256=digest(encoded(census)),
                classification_counts=dict(sorted(collections.Counter(r['classification'] for r in census).items())),
                census=census)


def canonical_root(value):
    path = Path(value).absolute()
    need(path.is_dir() and path.resolve(strict=True) == path, 'cpu_root_alias')
    return path


def fresh_output(value):
    path = Path(value).absolute()
    need(path.parent.is_dir() and path.parent.resolve(strict=True) == path.parent,
         'output_parent_alias')
    need(not path.exists() and not path.is_symlink(), 'output_exists')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--boundary-root', type=Path, required=True)
    parser.add_argument('--contract-root', type=Path, default=CONTRACT_ROOT)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = canonical_root(args.source_root)
    contract_root = canonical_root(args.contract_root)
    boundary_root = canonical_root(args.boundary_root)
    manifest = load_json(contract_root/'corpus.json')
    sources = load_json(contract_root/'sources.json')
    result = assess(source, manifest, sources, contract_root=contract_root,
                    boundary_root=boundary_root)
    output = fresh_output(args.output)
    output.mkdir()
    census = result.pop('census')
    (output/'census.json').write_bytes(encoded(census))
    result.update(manifest_sha256=digest(encoded(manifest)), sources_sha256=digest(encoded(sources)))
    (output/'control.json').write_bytes(encoded(result))
    print(encoded(result).decode(), end='')


if __name__ == '__main__':
    try:
        main()
    except (Error, OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
        print('CPU corpus rejected: '+(exc.code if isinstance(exc, Error) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
