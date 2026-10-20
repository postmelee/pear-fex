# Task #75 Stage 4 — Generated-header provenance and MIT terms

GitHub Issue: [#75](https://github.com/postmelee/pear/issues/75)
Implementation plan: Pear `task_m1_75_impl.md`, approved Stage4 extension.
Stage: 4

## Stage Purpose

Complete the recorded adjacent-notice condition for three frozen diagnostic
headers at published FEX commit `4ae26ddf9a21b52cd50d096504c4d0ea5ab49204`.
The exact retained generators and schemas select MIT; their leading notices
omit a copyright holder, and their generated outputs omit inline notices.
Record that provenance and the existing MIT permission, condition and warranty
text without inventing authorship or changing the headers.

Context used: the explicit Task75 Stage4 approval and location decision, the
unchanged upstream `AGENTS.md`, original import inventory, retained Task11 origin
proof, Pear source-notice rules, stage-report template/procedure and artifact
retention guide. This is downstream documentation, with no upstream code
contribution or new generator implementation.

## Artifacts

| File | Change summary |
|---|---|
| `Pear/Diagnostics/include/NOTICE.md` | Exact three output hashes, six source/template/schema identities, generation joins and unchanged MIT clauses |
| `Pear/README.md` | Link the adjacent notice and distinguish it from historical inline-notice metadata |
| `mydocs/working/task_m1_75_stage4.md` | Verification, claim limits and retention handoff |

## Body Change Scope / Lossless Preservation

Only these Markdown files change. The headers, generators, source manifests,
import-notice inventory, test ownership and source/build/tool pins remain
unchanged. The existing upstream README, license, contribution policy and source
notice exceptions remain exact. The first known FEX import is not relabeled as
an original generator-authoring commit; the original untracked source captures
have no demonstrated introducing Pear Git commit. Source-owner acceptance is
not treated as a copyright transfer.

The notice reproduces the existing MIT permission, condition and warranty
clauses exactly, while preserving the upstream copyright line in `LICENSE`
without attributing it to the Pear templates. No replacement holder line,
license conversion or additional grant is asserted. The target header's later
56-byte writer-template addition is included in its provenance.

## Verification Results

Source/document checks ran on the existing macOS development host with Python
3.13.5. Runtime and Wine provider roots were explicitly bound to
`6f0202b457f0e585c5c7621a63d203e77d07386d` and
`007291b81de386fd8886770c33b5d385c078635d` respectively. These existing roots were
read-only. From the isolated FEX worktree:

```sh
python3 -B Pear/Tools/check_source.py \
  --runtime-root "$RUNTIME_SOURCE_ROOT" --wine-root "$WINE_SOURCE_ROOT"
python3 -B "$PEAR_CHECKOUT/tools/check_source_notices.py" \
  --base 4ae26ddf9a21b52cd50d096504c4d0ea5ab49204
git diff --check
```

- Existing source verification passed for all 99 imported source/payload files,
  including exact modes, nonshallow upstream ancestry, no tracked private
  selector and both shared-provider hashes.
- The exact three headers, all ten `Pear/Provenance` files, upstream README,
  upstream license, upstream policy and notice-exception policy remain unchanged.
- The origin-proof reuse was bound to unchanged bytes: 42 retained references and
  all 99 selected Git blobs were rehashed. Literal/template-data conclusions
  retain their original source-only scope; no original generator was executed.
- Incremental notice checking passed with zero executable-source candidates;
  Markdown notice content received separate manual review. This is not an
  automated license-clearance claim.
- Added local links, documentation modes, exact change scope, whitespace and
  bounded privacy review passed. No private absolute paths, raw selectors,
  proprietary payload or credential material was added.
- Independent review verified the six original MIT-marked sources, three exact
  outputs, writer literal and target-header addition, missing holder disclosure,
  unchanged MIT clauses and frozen metadata. Its receipt SHA-256 is
  `0f065c2a5c0e84ab0e59d26acd33f8b143280f671bea64e8691896e30fb1dc80`.

The pre-report verification receipt is SHA-256
`19515458798dea24c419d27597f1b1edecc29bca1e6d797ef3b33162d2c374fd`.
The original retained origin proof remains SHA-256
`e9bc1efef2b586704e0506ce0ff7c7c18a259372eebd6bf7e00c61368740caee`.
The final three-file scope and report are reviewed again before the bundled
commit. No behavioral tests or builds are repeated for this Markdown-only
change; no compiler, native fixture, guest, game, installation or signing runs.
Previous runtime/fixture results keep their original input and claim boundaries.

## Artifact Disposition

| Artifact/root | State and consumer | Retain/release condition |
|---|---|---|
| Three documentation files and isolated Task75 checkout | Retained for component PR and later publication review | Keep through review/merge and dependency check |
| Exact origin proof, retained source captures and preparation receipts | Historical licensing/provenance evidence | Preserve for audit and successor source review; no release in this stage |
| Original imported headers, manifests and selected build/tool roots | Unchanged inputs of existing consumers | Preserve under existing consumer obligations |
| Private verification/review records | Retained Task75 evidence | Keep until accepted successor evidence and review completion |

Material build storage is not applicable: this stage adds small text documents
and verification records, shares existing Git objects and copies no toolchain,
runtime, prefix or game. The approved sparse-checkout/text allowance is 32 MiB;
actual final accounting is retained with the private commit handoff. No existing
file, artifact, branch or worktree is deleted; no recovered-space claim is made.

## Residual Risks

The missing original holder notice remains explicitly disclosed, not resolved by
assumption. This correction addresses the specific adjacent-documentation finding;
it is not exhaustive legal clearance. Later source changes require their own
notice/provenance review. Retained build inputs, game qualification and ordinary
user distribution remain separate limitations.

## Impact on Publication

The notice correction is ready for the authorized Task75 review PR after the
final delta check and bundled commit. Existing repository visibility, default
branch, selected runtime and source ownership remain unchanged. The coordinating
Pear report records exact publication refs and the bounded readiness decision.

## Approval Record

The requester explicitly authorized this notice correction, verification and
continuous progression to PR publication on 2026-10-21. This component stage does
not authorize merging, visibility conversion, gameplay or artifact cleanup.
