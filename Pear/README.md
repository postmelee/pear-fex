# Pear FEX component

This private downstream checkout carries the accepted Pear FEX layers and the
owner-approved Task #11 D36 source candidate. The source is editable here;
historical patch/generator records are frozen provenance, not an alternate
implementation to regenerate over current edits. Source authority cutover from
the original task is a separate handoff.

The upstream base is FEX commit
`59f85d6b7df4eb053d2cc1b9d33411b4f31bfbaa`. Its full history, original authors,
root README, licenses and contribution policy are preserved. This downstream
work does not authorize an AI-generated contribution to FEX upstream.

## Source and ownership

`Provenance/accepted-source.json` records the accepted Task #5, #6 and #8 layers.
`Provenance/source-manifest.json` records the exact 83 selected source files,
16 component-owned generic diagnostic payloads, historical patch edges and
external provider identities. `Diagnostics/include/` contains the canonical
generic payloads. Files with no inherited inline notice are identified in
`Provenance/import-notices.json`; their exact source bytes were preserved, and
no new license was inferred from the destination directory.

[pear-wine](https://github.com/postmelee/pear-wine) owns the memory/lifecycle ABI
at `include/wine/pear_fex_memory.h`. FEX consumes its pinned export.
[pear-runtime](https://github.com/postmelee/pear-runtime) owns the shared abort
schema and `include/PearAbortObservation.h`, pairing, immutable inputs, portable
build recipes and cross-component fixtures.
[pear-dxmt](https://github.com/postmelee/pear-dxmt) owns rendering, while
[Pear](https://github.com/postmelee/pear) owns the manager and integration plans.
The component repositories require collaborator access.

The game-derived `PearPhaseSelection.h` is an explicit external private input.
It must never be committed, including to a private repository. A synthetic
selector used by controls is a different input and does not reproduce the
original private diagnostic configuration. Game files, prefixes, credentials,
saves, signing material and private diagnostic logs are also excluded.

## Verification and build status

From this repository root, with Python 3 and Git:

```sh
python3 -B Pear/Tools/check_source.py
PYTHONPATH=../pear-runtime python3 -B -m unittest discover -s Pear/Tests -p 'test_*.py' -v
```

To validate shared provider bytes, also supply explicit checkouts:

```sh
python3 -B Pear/Tools/check_source.py --runtime-root ../pear-runtime --wine-root ../pear-wine
```

[Test ownership](Provenance/test-ownership.json) records exact original test
identities, one canonical destination per file, dependencies and pending Stage 4
adoption/run status. It also distinguishes already imported synthetic tests
from adopted CPU source controls and paired runtime tests whose remaining
execution/adoption status is recorded per file.

The source check verifies the imported checkpoint, file modes, ancestry and
tracked private-selector exclusion. Omitting provider roots reports those
checks as unperformed. The Python tests exercise synthetic construction,
attachment, binding census and lifecycle diagnostics, including malformed and
missing observations; they do not execute FEX or prove native thread liveness.
The checkpoint manifest intentionally fails after implementation changes until
an approved new source identity is recorded. It is not a perpetual runtime lock.

Portable developer reconstruction is owned by `pear-runtime` Task #56 Stage 3.
Until that recipe is delivered, there is no supported standalone Pear candidate
build command in this fork. The bounded recipe will use explicitly pinned
objects, archives, generated configuration and tools, rebuild the current
Core/Module/memory units, and relink into a fresh output. Shared headers and
the selected private configuration are required inputs. It will not establish
a clean rebuild of all historical lower layers. The original upstream build
instructions describe upstream FEX, not this Pear candidate.

No new build, host execution, no-Rosetta process coverage, gameplay, Steam,
input/audio/save or ordinary-user distribution qualification is claimed by
this source import. Cross-component acceptance still requires the seven
runtime fixtures and the corresponding owner checks.

## CPU fixture sources

`Tests/CPU/` owns the selected CPU corpus, adaptations, capture driver and
retained notices; `Tools/CPU/` owns its source inventory and generator.
The 12 upstream ASM cases remain at their original `unittests/ASM/` paths.
`pear-runtime` owns the nine ABI/boundary/ordering C/ASM sources and the original
ABI/SEH assembly generator. [CPU import provenance](Provenance/cpu-source-import.json)
records every source identity and the exact ownership split.

The CPU tools require the sibling runtime Python package for its canonical
bounded byte/JSON readers and errors. Supply it explicitly with `PYTHONPATH`;
there is no fallback to a historical Pear worktree. From this FEX root, use a
canonical absolute runtime path and a fresh output whose parent already exists:

```sh
PYTHONPATH=.:../pear-runtime python3 -B -m pear_runtime.recipes.cpu_sources \
  --fex-root "$PWD" --runtime-root /absolute/path/to/pear-runtime \
  --output /absolute/path/to/new-cpu-sources
```

This revalidates the pinned 2,270-file ASM census, generates 12 single-case
ASM/header inputs plus ABI/SEH assembly, and copies the nine runtime fixture
sources. The imported original corpus/refusal tests remain runnable through
the component test command above. Task #56 compared all 50 generated/copied
artifacts byte-for-byte with the retained fixture build; no compiler or guest
execution is performed by this command.

The runtime recipe `recipes/cpu/sources-v1.json` records the historical compiler
arguments and exact source inputs. The original hosted tool/header/library
closure was not fully captured. Compiling new PEs requires an explicitly admitted
toolchain and output comparison; changed bytes require renewed native Windows
reference evidence. Modify canonical sources and the reviewed versioned recipe
for future experiments, rather than treating the imported hashes as permanent
implementation restrictions. Runtime contract snapshots are derived inputs,
not another editable corpus authority.

## Notices

The upstream [MIT license](../LICENSE) and file-specific terms remain intact.
Imported diagnostic payloads/readers retain their original MIT or unmarked
legacy notice state; the lifecycle test retains GPL-3.0-or-later. New Pear
verification code is GPL-3.0-or-later, with its license text in [COPYING](COPYING).
`Provenance/auxiliary-source.json` records copied/adapted test and reader origins
and the limited import-path adaptations. This is a mixed-notice repository;
moving a file here does not convert its license.
