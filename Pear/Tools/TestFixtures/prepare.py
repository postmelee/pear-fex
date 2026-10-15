#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later AND MIT
"""Prepare exact component controls and command plans without executing them.

The extraction boundaries retain the original Pear MIT source-control recipes.
New input/output admission follows Pear's GPL source-tool policy. Historical
builders are provenance only. No patch, compiler, tool discovery or runtime is
invoked by this module. A prepared command plan is not a build admission.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat

MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
ROOTS = {'fex', 'wine', 'runtime'}
RECIPE_FIELDS = {'schema_version', 'kind', 'source_basis', 'inputs', 'cases', 'policy'}
CASE_FIELDS = {'inputs', 'fixture', 'generator', 'copies', 'generated', 'commands',
               'native_input_gaps', 'oracle', 'source_correspondence'}


def need(value, code):
    if not value:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def canonical(path, *, directory=False):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'path_alias_or_relative')
    need(path.is_dir() if directory else path.is_file(), 'path_kind')
    return path


def relative(value):
    need(type(value) is str, 'relative_path_type')
    path = PurePosixPath(value)
    need(path.parts and not path.is_absolute() and '..' not in path.parts and
         str(path) == value and '\\' not in value, 'relative_path')
    return path


def read_file(path):
    path = canonical(path)
    need(stat.S_ISREG(path.stat().st_mode) and path.stat().st_size <= MAX_FILE, 'file_bound')
    with path.open('rb') as stream:
        raw = stream.read(MAX_FILE + 1)
    need(len(raw) <= MAX_FILE, 'file_bound')
    return raw


def read_json(path):
    return json.loads(read_file(path), object_pairs_hook=pairs)


def ref(path, raw):
    return {'path': str(path), 'sha256': digest(raw), 'size_bytes': len(raw)}


def input_row(row):
    need(type(row) is dict and set(row) == {'root', 'path', 'sha256', 'size_bytes', 'mode'}, 'input_shape')
    need(row['root'] in ROOTS and type(row['size_bytes']) is int and
         0 <= row['size_bytes'] <= MAX_FILE and row['mode'] == '100644', 'input_shape')
    need(type(row['sha256']) is str and len(row['sha256']) == 64 and
         all(c in '0123456789abcdef' for c in row['sha256']), 'input_digest')
    relative(row['path'])


def admit(recipe_path, roots, case_id):
    recipe_path = canonical(recipe_path)
    raw = read_file(recipe_path)
    recipe = json.loads(raw, object_pairs_hook=pairs)
    need(type(recipe) is dict and set(recipe) == RECIPE_FIELDS and
         type(recipe['schema_version']) is int and recipe['schema_version'] == 1 and
         recipe['kind'] == 'pear_fex_component_source_preparation', 'recipe_shape')
    need(type(recipe['cases']) is dict and case_id in recipe['cases'], 'unknown_control')
    case = recipe['cases'][case_id]
    need(type(case) is dict and set(case) == CASE_FIELDS, 'case_shape')
    need(type(recipe['inputs']) is dict and 0 < len(recipe['inputs']) <= 128, 'input_table')
    paths = set()
    for row in recipe['inputs'].values():
        input_row(row)
        key = row['root'], row['path']
        need(key not in paths, 'duplicate_input_path')
        paths.add(key)
    need(type(case['inputs']) is list and 0 < len(case['inputs']) <= 64 and
         len(set(case['inputs'])) == len(case['inputs']), 'case_inputs')
    need(all(key in recipe['inputs'] for key in case['inputs']), 'missing_input_definition')
    required = {recipe['inputs'][key]['root'] for key in case['inputs']}
    need(type(roots) is dict and not set(roots) - ROOTS and required <= set(roots), 'required_root')
    bound = {name: canonical(path, directory=True) for name, path in roots.items()}
    need(len(set(bound.values())) == len(bound), 'root_overlap')
    data, refs = {}, {}
    for key in case['inputs']:
        row = recipe['inputs'][key]
        path = bound[row['root']] / relative(row['path'])
        value = read_file(path)
        need(stat.S_IMODE(path.stat().st_mode) == 0o644, 'input_mode')
        need(len(value) == row['size_bytes'] and digest(value) == row['sha256'], 'input_identity')
        data[key], refs[key] = value, ref(path, value)
    need(sum(map(len, data.values())) <= MAX_TOTAL, 'input_total_bound')
    need(case['fixture'] in data, 'fixture_input')
    return recipe, case, bound, data, refs, ref(recipe_path, raw)


def block(text, start, end):
    need(text.count(start) == 1, 'extract_unique_start')
    begin = text.index(start)
    need(end in text[begin:], 'extract_end')
    return text[begin:text.index(end, begin)]


def balanced(text, signature, semi=False):
    """Original bounded extraction, guarded by the whole-file recipe identity."""
    need(text.count(signature) == 1, 'extract_unique_start')
    start = text.index(signature)
    end = text.index('{', start) + 1
    depth = 1
    while depth and end < len(text):
        if text[end] == '{': depth += 1
        if text[end] == '}': depth -= 1
        end += 1
    need(depth == 0, 'extract_unclosed_body')
    return text[start:end] + (';' if semi else '') + '\n'


def resource(text):
    return ('namespace fextl { namespace pmr {\n' +
            block(text, '  class named_monotonic_page_buffer_resource final', '\n  /**') + '\n} }\n')


def attach(text):
    predicates = (block(text, 'static bool SameBinding(', 'static bool SameAllocation(') +
                  block(text, 'static bool ThreadFieldsMatch(', 'static void RetainCleanup('))
    body = (block(text, 'static Result BindActual(', '\n} // namespace') +
            block(text, 'static Result RegisterActualExecutor(', '\n} // namespace'))
    wrapper = 'Result RegisterExecutor(uint32_t SourceRole) { return RegisterActualExecutor(SourceRole,false); }'
    need(text.count(wrapper) == 1, 'attach_register_wrapper')
    start = ('static Result AttachAllocatedThreadImpl(' if 'static Result AttachAllocatedThreadImpl(' in text
             else 'Result SourceLifecycle::AttachAllocatedThread(')
    return predicates + '\n' + body + '\n' + wrapper + '\n' + block(text, start, '\nnamespace {\nstatic bool CanRelease')


ALLOCATOR_SHIM = (b'// SPDX-License-Identifier: MIT\n'
    b'// Original emitter-control allocator declaration shim.\n'
    b'#pragma once\n#include <cstddef>\n'
    b'namespace FEXCore::Allocator { void* aligned_alloc(size_t,size_t); void aligned_free(void*); }\n')
FINITE_PROVIDER = (b'// SPDX-FileCopyrightText: 2026 Pear contributors\n'
    b'// SPDX-License-Identifier: GPL-3.0-or-later\n'
    b'// Test allocation provider for the unchanged FEX vector/allocator types.\n'
    b'#include <FEXCore/fextl/vector.h>\n'
    b'namespace FEXCore::Allocator {\n'
    b'inline void* aligned_alloc(size_t a,size_t n) { void* p=nullptr;\n'
    b'  if (posix_memalign(&p,a<sizeof(void*)?sizeof(void*):a,n)) std::abort(); return p; }\n'
    b'inline void aligned_free(void* p) { std::free(p); }\n}\n')
DERIVED_MIT = (b'// SPDX-License-Identifier: MIT\n'
               b'// Exact selected FEX source excerpt; origin and body hash are in prepare.json.\n')


def _derive(case, data):
    result = {}
    need(type(case['copies']) is dict, 'copy_table')
    for target, key in case['copies'].items():
        relative(target); need(key in data, 'copy_input')
        result[target] = data[key]
    copied = set(result)
    text = lambda key: data[key].decode('utf-8')
    kind = case['generator']
    if kind == 'pmr':
        result['candidate/resource_under_test.inc'] = resource(text('memory_resource')).encode()
    elif kind == 'checked':
        source = text('alloc')
        result['checked_data_memory_under_test.inc'] = (balanced(source, 'NTSTATUS AllocateVirtualChecked(') +
            'namespace FEXCore::Allocator {\n' + balanced(source, 'FEXCore::Utils::PearFEXMemory::Result ReservePearData(') +
            balanced(source, 'FEXCore::Utils::PearFEXMemory::Result ReleasePearData(') + '}\n').encode()
    elif kind == 'storage':
        source = text('empty_storage')
        need(source.count('namespace {\nstruct alignas(4096)') == 1, 'storage_start')
        result['empty_object_storage_under_test.inc'] = ('#ifdef PEAR_FEX_MEMORY_OWNER\n' +
            source[source.index('namespace {\nstruct alignas(4096)'):source.rindex('}')]).encode()
    elif kind == 'owner':
        result['owner_preparation_under_test.inc'] = block(text('memory'), 'Result PrepareOwnerMetadata(', 'Result Init(void* NtDll').encode()
    elif kind == 'finite':
        selected = (balanced(text('shared_code'), 'template<typename T> struct PearControlAllocator', True) +
            'namespace ARMEmitter {\n' + balanced(text('emitter'), 'struct ForwardLabel {', True) +
            balanced(text('emitter'), 'static inline void AddLocationToLabel(') + '}\n' +
            'namespace FEXCore::CPUID {\n' + balanced(text('cpuid_header'), 'struct FunctionResults {', True) +
            '}\nusing Result=FEXCore::CPUID::FunctionResults;\n' +
            balanced(text('cpuid'), 'FEXCore::CPUID::FunctionResults CopyCPUBrandChunk('))
        result['finite-selected-body.inc'] = selected.encode()
        result['finite_construction_under_test.inc'] = FINITE_PROVIDER + b'#include "finite-selected-body.inc"\n'
        result['shim/FEXCore/Utils/AllocatorHooks.h'] = ALLOCATOR_SHIM
    elif kind == 'attach':
        result['observed-attach-functions.inc'] = attach(text('memory')).encode()
    elif kind == 'emitter':
        result['shim/FEXCore/Utils/AllocatorHooks.h'] = ALLOCATOR_SHIM
    else:
        need(kind == 'copies_only', 'unknown_generator')
    for name in set(result) - copied:
        if name.endswith('.inc') and name != 'finite_construction_under_test.inc':
            result[name] = DERIVED_MIT + result[name]
    return result


def generate(case, data):
    result = _derive(case, data)
    need(set(result) == set(case['generated']), 'generated_set')
    for name, raw in result.items():
        expected = case['generated'][name]
        need(type(expected) is dict and set(expected) == {'sha256', 'size_bytes'} and
             digest(raw) == expected['sha256'] and len(raw) == expected['size_bytes'], 'generated_identity')
    need(sum(map(len, result.values())) <= MAX_TOTAL, 'generated_total_bound')
    return result


def tools_record(bindings_path):
    """Check explicitly supplied tool identities without discovery or execution.

    A compiler alias is preserved as an explicit lexical path plus a verified
    resolved-file identity. This does not admit SDK headers or implicit libraries.
    """
    if bindings_path is None:
        return {'status': 'not_supplied', 'required': ['compiler', 'sdk_inventory_ref']}
    value = read_json(bindings_path)
    need(type(value) is dict and set(value) == {'compiler', 'sdk_root', 'sdk_inventory_ref'}, 'tool_bindings_shape')
    item = value['compiler']
    need(type(item) is dict and set(item) == {'path', 'resolved_path', 'sha256', 'size_bytes'}, 'compiler_ref_shape')
    need(type(item['path']) is str and type(item['resolved_path']) is str and
         type(item['size_bytes']) is int and 0 <= item['size_bytes'] <= 512 * 1024 * 1024 and
         type(item['sha256']) is str and len(item['sha256']) == 64 and
         all(c in '0123456789abcdef' for c in item['sha256']), 'compiler_ref_shape')
    lexical = Path(item['path'])
    need(lexical.is_absolute() and str(lexical) == item['path'], 'compiler_path')
    resolved = canonical(item['resolved_path'])
    need(lexical.resolve(strict=True) == resolved, 'compiler_target')
    raw = read_file(resolved) if resolved.stat().st_size <= MAX_FILE else None
    if raw is None:
        # Tool payloads may exceed source bounds; cap and stream their identity.
        need(resolved.stat().st_size <= 512 * 1024 * 1024, 'compiler_size_bound')
        checksum = hashlib.sha256()
        size = 0
        with resolved.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                size += len(chunk)
                need(size <= 512 * 1024 * 1024, 'compiler_size_bound')
                checksum.update(chunk)
        need(size == resolved.stat().st_size, 'compiler_changed_during_read')
        actual_digest = checksum.hexdigest()
    else:
        actual_digest, size = digest(raw), len(raw)
    need(actual_digest == item['sha256'] and size == item['size_bytes'], 'compiler_identity')
    need(type(value['sdk_root']) is str, 'sdk_root_shape')
    sdk = canonical(value['sdk_root'], directory=True)
    inventory = value['sdk_inventory_ref']
    need(type(inventory) is dict and set(inventory) == {'path', 'sha256', 'size_bytes'}, 'sdk_inventory_ref')
    need(type(inventory['path']) is str and type(inventory['size_bytes']) is int and
         0 <= inventory['size_bytes'] <= MAX_FILE and type(inventory['sha256']) is str and
         len(inventory['sha256']) == 64 and all(c in '0123456789abcdef' for c in inventory['sha256']), 'sdk_inventory_ref')
    contents = read_file(inventory['path'])
    need(digest(contents) == inventory['sha256'] and len(contents) == inventory['size_bytes'], 'sdk_inventory_identity')
    return {'status': 'explicit_identity_recorded_only', 'compiler': item, 'sdk_root': str(sdk),
            'sdk_inventory_ref': inventory, 'sdk_entries_or_implicit_libraries_admitted': False,
            'bindings_ref': ref(canonical(bindings_path), read_file(bindings_path))}


def prepare(recipe_path, roots, case_id, output, *, tool_bindings=None):
    producer_path = canonical(Path(__file__))
    producer_ref = ref(producer_path, read_file(producer_path))
    recipe, case, bound, data, refs, recipe_ref = admit(recipe_path, roots, case_id)
    generated = generate(case, data)
    tools = tools_record(tool_bindings)
    output = Path(output)
    need(output.is_absolute() and not output.exists() and not output.is_symlink(), 'fresh_output')
    parent = canonical(output.parent, directory=True)
    need(parent / output.name == output and output.name not in ('.', '..'), 'output_path')
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in bound.values()), 'output_source_overlap')
    # Native/build admission is deliberately absent; these are source files and
    # unresolved command templates, never executable authority.
    record = {'schema_version': 1, 'scope': 'component_source_preparation', 'case': case_id,
              'recipe_ref': recipe_ref, 'producer_ref': producer_ref, 'roots': {k: str(v) for k, v in bound.items()},
              'inputs': refs, 'outputs': {}, 'tool_bindings': tools,
              'derived_source_bodies': {name: {'sha256': digest(raw[len(DERIVED_MIT):]),
                  'size_bytes': len(raw)-len(DERIVED_MIT)} for name, raw in generated.items() if raw.startswith(DERIVED_MIT)},
              'command_templates': case['commands'], 'native_input_gaps': case['native_input_gaps'],
              'oracle': case['oracle'], 'source_correspondence': case['source_correspondence'],
              'prepared': False, 'commands_executed': [], 'compiled': False, 'native_executed': False,
              'build_input_closure_complete': False, 'native_execution_admitted': False}
    output.mkdir(mode=0o700)
    primary = None
    try:
        for name, raw in generated.items():
            target = output / relative(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream: stream.write(raw)
            target.chmod(0o644)
            record['outputs'][name] = ref(target, raw)
        # Recheck every read input, including the recipe, after materialization.
        for key, item in refs.items():
            need(ref(Path(item['path']), read_file(item['path'])) == item, 'source_changed_during_prepare')
        need(ref(Path(recipe_ref['path']), read_file(recipe_ref['path'])) == recipe_ref, 'recipe_changed_during_prepare')
        need(ref(producer_path, read_file(producer_path)) == producer_ref, 'producer_changed_during_prepare')
        record['prepared'] = True
    except BaseException as exc:
        primary = exc
        record['error'] = {'type': type(exc).__name__, 'detail': str(exc)}
        raise
    finally:
        try:
            (output / 'prepare.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
        except BaseException as evidence_error:
            if primary is None:
                raise
            primary.add_note('prepare_receipt_write_failed: ' + str(evidence_error))
    return record


def main(argv=None, *, fixed_case=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--wine-root', type=Path)
    parser.add_argument('--runtime-root', type=Path)
    parser.add_argument('--recipe', required=True, type=Path)
    if fixed_case is None: parser.add_argument('--case', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--tool-bindings', type=Path)
    args = parser.parse_args(argv)
    roots = {'fex': args.source_root}
    if args.wine_root is not None: roots['wine'] = args.wine_root
    if args.runtime_root is not None: roots['runtime'] = args.runtime_root
    result = prepare(args.recipe, roots, fixed_case or args.case, args.output, tool_bindings=args.tool_bindings)
    print(json.dumps({key: result[key] for key in ('case', 'prepared', 'compiled', 'native_executed', 'native_execution_admitted')}))


if __name__ == '__main__':
    main()
