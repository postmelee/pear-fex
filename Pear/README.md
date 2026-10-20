# Pear FEX component

This public downstream checkout carries the accepted Pear FEX layers and the
owner-approved Task #11 D36 source candidate. The source is editable here;
historical patch/generator records are frozen provenance, not an alternate
implementation to regenerate over current edits. The
[accepted source-owner handoff](https://github.com/postmelee/pear-runtime/blob/codex/task56/provenance/source-cutover-task56.json)
records this fork as the future editing authority for the exact imported scope.
Original source, patch and recovery inputs remain retained under their recorded
consumer obligations.

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
The four component source repositories are publicly readable.

The game-derived `PearPhaseSelection.h` is an explicit external private input.
It must never be committed, including to a private repository. A synthetic
selector used by controls is a different input and does not reproduce the
original private diagnostic configuration. Game files, prefixes, credentials,
saves, signing material and private diagnostic logs are also excluded.

## Verification and build status

From this repository root, with Python 3 and Git. Bind `RUNTIME_SOURCE_ROOT` and
`WINE_SOURCE_ROOT` to explicit canonical development checkouts before commands
that consume them. Their current tool/test revisions are distinct from the
historical component build roots:

```sh
python3 -B Pear/Tools/check_source.py
PYTHONPATH="$RUNTIME_SOURCE_ROOT" python3 -B -m unittest discover -s Pear/Tests -p 'test_*.py' -v
```

To validate shared provider bytes, also supply explicit checkouts:

```sh
python3 -B Pear/Tools/check_source.py --runtime-root "$RUNTIME_SOURCE_ROOT" --wine-root "$WINE_SOURCE_ROOT"
```

[Test ownership](Provenance/test-ownership.json) records exact original test
identities, canonical destinations, dependencies and per-file execution limits.
The selected component-control exports and explicit source-preparation adapters
are present; unperformed compilation/native controls remain unperformed. Runtime
owns the [accepted 196-method reconciliation](https://github.com/postmelee/pear-runtime/blob/codex/task56/provenance/paired-memory-methods.json).
A source disposition or new hash does not qualify a changed implementation.
The Stage 4 metadata amendment was originally published privately at
`a8ba1cbd0148b46817842f3b7307689d4b2acbd7`; [its report](../mydocs/working/task_m1_56_stage4.md)
retains the exact limits. The runtime development entrypoints are recorded at
`6f0202b457f0e585c5c7621a63d203e77d07386d`. Source-owner acceptance covers the
recorded imported range; runtime activation and the historical build/tool pins
retain their separate identities.

The source check verifies the imported checkpoint, file modes, ancestry and
tracked private-selector exclusion. Omitting provider roots reports those
checks as unperformed. The Python tests exercise synthetic construction,
attachment, binding census and lifecycle diagnostics, including malformed and
missing observations; they do not execute FEX or prove native thread liveness.
The checkpoint manifest intentionally fails after implementation changes until
an approved new source identity is recorded. It is not a perpetual runtime lock.

The [runtime-owned FEX recipe](https://github.com/postmelee/pear-runtime/blob/c8887f9edaba57dffe7772cc26fd19aa9571d451/recipes/fex/README.md)
was exercised in Stage 3. It compiles the selected Core/Module/memory units,
replaces the declared archive member and links a fresh DLL using exact retained
objects, generated configuration and tools. Shared provider headers and the
selected private configuration remain explicit inputs. The upstream instructions
above still describe upstream FEX; this bounded candidate is not a complete clean
rebuild of its historical lower layers.

From the pinned `pear-runtime` checkout, with reviewed canonical local bindings:

```sh
python3 -B -m pear_runtime.recipes.fex \
  --recipe recipes/fex/selected-v1.json \
  --bindings "$FEX_BINDINGS" \
  --private-manifest "$FEX_PRIVATE_MANIFEST" \
  --output "$FRESH_FEX_OUTPUT"
```

The selected build commit remains `c62ed75aa6a33809ddb76c7f40aabbe4f4fbdda6`.
The later CPU fixture-source export is `9c9b602c07b57a08500862abfdf62e1bac351640`. Those revisions have different
roles; the later test commit does not relabel the old built DLL. Runtime builder
`c8887f9edaba57dffe7772cc26fd19aa9571d451` and seven-fixture checkpoint `c13c7030ec3b780df12373cb9e0460bbcb5b0652` are separate pins as well.
Use the [revision and recovery guide](https://github.com/postmelee/pear-runtime/blob/codex/task56/docs/development.md) for exact source acquisition and
input binding. Original receipts are immutable.

Candidate3 assembly and the fifteen Stage 4 controls passed: four native
controls, three bootstrap controls, seven D36 cases and eighteen-frame
presentation. After the Stage 5.1 runtime checkpoint, all seven D36 cases passed
again through Pear's separate development selector. Metadata-only game
preparation, selection, inspection and recovery also passed; no game was copied
or launched. Independent release evidence is retained for every fresh operation.
Accepted CPU/ordering and other candidate2 reuse retains the original exact
source/reference/operation identities; the AVX case stays unsupported/exit 77.
These results do not establish gameplay, Steam integration, complete no-Rosetta
coverage or ordinary-user distribution. The accepted source-management handoff
does not extend those execution claims.

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
PYTHONPATH="$PWD:$RUNTIME_SOURCE_ROOT" python3 -B -m pear_runtime.recipes.cpu_sources \
  --fex-root "$PWD" --runtime-root "$RUNTIME_SOURCE_ROOT" \
  --output "$FRESH_CPU_SOURCE_OUTPUT"
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

The [adjacent notice for three diagnostic headers](Diagnostics/include/NOTICE.md)
binds their exact outputs to retained MIT-marked templates and records the absent
original holder notice. It supplements the historical inline-notice inventory
without changing the frozen headers, manifests or build inputs.
