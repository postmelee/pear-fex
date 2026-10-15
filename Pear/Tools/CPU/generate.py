#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Adapted from Madeira tests/x64/gen_asmconf.py by Will Faust, revision
# 48f976429c189f8396e23d251d8a82f43c705922. See tests/cpu/LICENSES/.
# Pear changes: isolated PE cases, strict CONFIG admission, complete vector/ABI
# preservation, explicit FP/flag initialization and fixed-address data mappings.
"""Generate source-bound, single-case PE inputs; no test execution."""
from pathlib import Path
import argparse
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from Pear.Tools.CPU.corpus import CONTRACT_ROOT, assess, digest, canonical_root, fresh_output
from Pear.Tools.CPU.adapt import effective_case, adapt_body, rules
from pear_runtime.assembly._common import read_relative, load_json, encoded
from pear_runtime.errors import need

GPRS = 'RAX RBX RCX RDX RSI RDI RBP RSP R8 R9 R10 R11 R12 R13 R14 R15'.split()
NONVOLATILE = 'RSP RBX RBP RSI RDI R12 R13 R14 R15'.split()


def assembly(case, raw, adaptation_rules=None):
    text = raw.decode('utf-8')
    body, count = re.subn(r'^%ifdef\s+CONFIG\s*\n.*?^%endif\s*$', '', text, flags=re.M | re.S)
    need(count == 1, 'config_block')
    need(not re.search(r'^\s*(?:section|segment|global|extern|%include|incbin)\b', body, re.M | re.I), 'external_asm_input')
    need('pear_' not in body, 'reserved_symbol')
    body = adapt_body(case, body, adaptation_rules)
    body, stops = re.subn(r'^\s*hlt\s*(?:;[^\n]*)?$', '    jmp pear_capture', body, flags=re.M | re.I)
    need(stops > 0, 'missing_termination')
    avx = case['contract']['features'] == ['AVX']
    need(not case['contract']['features'] or avx, 'unimplemented_feature')
    a = ['; SPDX-License-Identifier: GPL-3.0-or-later',
         '; Capture wrapper adapted from Madeira; enclosed FEX body is MIT.',
         '; See retained notices and source hashes in build.json.',
         'BITS 64', 'DEFAULT REL', 'section .text code align=32', 'global pear_case',
         'pear_case:']
    # Save outside the guest stack: selected bodies can reposition RSP.
    a += [f'    mov [rel pear_saved + {i*8}], {r.lower()}' for i, r in enumerate(NONVOLATILE)]
    a += ['    pushfq', '    pop qword [rel pear_saved + 72]',
          '    fxsave64 [rel pear_fp]', '    fninit', '    ldmxcsr [rel pear_mxcsr]']
    a += [f'    {"vxorps ymm"+str(i)+", ymm"+str(i)+", ymm"+str(i) if avx else "pxor xmm"+str(i)+", xmm"+str(i)}' for i in range(16)]
    a += ['    push qword 2', '    popfq']
    a += [f'    mov {r.lower()}, 0' for r in GPRS if r != 'RSP']
    # A local FEX label must bind to the case entry, not to our epilogue.
    a += [body, 'pear_capture:']
    a += [f'    mov [rel pear_registers + {i*8}], {r.lower()}' for i, r in enumerate(GPRS)]
    a += [f'    {"vmovdqu" if avx else "movdqu"} [rel pear_registers + {128+i*32}], {"ymm" if avx else "xmm"}{i}' for i in range(16)]
    a += ['    mov rsp, [rel pear_saved]', '    pushfq',
          '    pop qword [rel pear_registers + 640]']
    if avx:
        a += ['    vzeroupper']
    a += ['    fxrstor64 [rel pear_fp]', '    push qword [rel pear_saved + 72]', '    popfq']
    a += [f'    mov {r.lower()}, [rel pear_saved + {i*8}]' for i, r in enumerate(NONVOLATILE) if r != 'RSP']
    a += ['    ret', 'section .data data align=32', 'global pear_registers',
          'pear_registers: times 648 db 0', 'align 16', 'pear_saved: times 80 db 0',
          'align 16', 'pear_fp: times 512 db 0', 'pear_mxcsr: dd 0x1f80']
    return '\n'.join(a)+'\n'


def reservations(case):
    regions = [dict(address=case['setup']['scratch_address'], size=case['setup']['scratch_size'])]
    regions += case['contract']['regions']
    # Windows reserves on 64 KiB boundaries; commit only the requested 4 KiB
    # data pages. Do not relocate absolute operands or make data executable.
    spans = sorted((r['address'] & ~65535, (r['address']+r['size']+65535) & ~65535) for r in regions)
    merged = []
    for lo, hi in spans:
        if merged and lo <= merged[-1][1]:
            merged[-1][1] = max(hi, merged[-1][1])
        else:
            merged.append([lo, hi])
    return merged, regions


def header(case, manifest_hash, adaptation_rules=None):
    case = effective_case(case, adaptation_rules)
    expected = case['contract']['expectations']
    h = ['/* Generated contract: FEX MIT expectations, Pear capture layout. */',
         f'#define PEAR_CASE_ID "{case["id"]}"', f'#define PEAR_MANIFEST "{manifest_hash}"',
         f'#define PEAR_REQUIRES_AVX {int(bool(case["contract"]["features"]))}',
         'typedef struct { unsigned offset; uint64_t value, mask; } Expectation;',
         'static const Expectation expectations[] = {']
    for row, mask in zip(expected, case['masks']):
        reg = row['register']
        offset = GPRS.index(reg)*8 if reg in GPRS else 128+int(reg[3:])*32+row['lane']*8
        h.append(f'    {{{offset}, {row["value"]}ULL, {mask["bits"]}ULL}},')
    h += ['};', f'#define PEAR_EXPECTATIONS {len(expected)}',
          'static int map_data(void) {']
    reserves, commits = reservations(case)
    for lo, hi in reserves:
        h += [f'    if (VirtualAlloc((void *)(uintptr_t){lo}ULL, {hi-lo}, MEM_RESERVE, PAGE_NOACCESS) != (void *)(uintptr_t){lo}ULL) return 0;']
    for region in commits:
        lo, size = region['address'], region['size']
        h += [f'    if (VirtualAlloc((void *)(uintptr_t){lo}ULL, {size}, MEM_COMMIT, PAGE_READWRITE) != (void *)(uintptr_t){lo}ULL) return 0;']
    for item in case['contract']['initial_memory']:
        for i, value in enumerate(bytes.fromhex(item['bytes'])):
            h += [f'    *(volatile unsigned char *)(uintptr_t){item["address"]+i}ULL = {value};']
    h += ['    return 1;', '}']
    return '\n'.join(h)+'\n'


def generate(source, output, *, boundary_root, contract_root=CONTRACT_ROOT):
    source = canonical_root(source)
    boundary_root = canonical_root(boundary_root)
    contract_root = canonical_root(contract_root)
    output = fresh_output(output)
    manifest = load_json(contract_root/'corpus.json')
    sources = load_json(contract_root/'sources.json')
    adaptations = rules(contract_root)
    assess(source, manifest, sources, contract_root=contract_root, boundary_root=boundary_root)
    need(not output.exists() and not output.is_symlink(), 'output_exists')
    output.mkdir(parents=True)
    rows = []
    for case in manifest['cases']:
        folder = output/case['id']; folder.mkdir()
        raw = read_relative(source, case['path'])
        (folder/'upstream.asm').write_bytes(raw)
        (folder/'case.asm').write_text(assembly(case, raw, adaptations))
        (folder/'case.h').write_text(header(case, digest(encoded(manifest)), adaptations))
        rows.append(dict(id=case['id'], source_sha256=digest(raw),
                         assembly_sha256=digest((folder/'case.asm').read_bytes()),
                         header_sha256=digest((folder/'case.h').read_bytes())))
    for name in ('FEX-MIT.txt', 'Madeira-GPL-3.0.txt', 'Madeira-EXCEPTION.md'):
        (output/name).write_bytes(read_relative(contract_root, 'LICENSES/'+name))
    result = dict(scope='cpu_generated_sources', manifest_sha256=digest(encoded(manifest)),
                  generator_sha256=digest(Path(__file__).read_bytes()), adaptations_sha256=digest(encoded(adaptations)), cases=rows,
                  guest_execution=False, cpu_qualified=False)
    (output/'generated.json').write_bytes(encoded(result))
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', required=True, type=Path)
    p.add_argument('--boundary-root', required=True, type=Path)
    p.add_argument('--contract-root', type=Path, default=CONTRACT_ROOT)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    print(encoded(generate(args.source_root, args.output, boundary_root=args.boundary_root, contract_root=args.contract_root)).decode())
