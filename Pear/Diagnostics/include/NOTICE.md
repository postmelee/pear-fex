# Notices for three retained Pear diagnostic headers

This notice accompanies only the three exact generated outputs below. Their
retained Pear source templates and schema files expressly carry
`SPDX-License-Identifier: MIT`. The emitted headers contain no inline copyright
or license notice. This adjacent record supplies the documented provenance and
MIT permission, condition and warranty text without changing those frozen bytes.

The retained source notices do not state a copyright holder. No holder, year of
original authorship, copyright transfer or additional permission is inferred from
FEX's upstream license, a sibling file, an agent identity or source-owner
acceptance. This notice records the existing template terms; it does not relicense
other files or claim blanket legal clearance. Preserve any further original
notice if it is recovered.

## Exact covered outputs

Paths are relative to this notice. SHA-256 covers the complete file; all three
files have Git mode `100644` and remain byte-identical to their first known FEX
import, commit `52fd8a95955ad33cc589bcd8c5837b84cb21705e`, and the reviewed published
checkpoint `4ae26ddf9a21b52cd50d096504c4d0ea5ab49204`.

| File | Bytes | SHA-256 |
|---|---:|---|
| [PearMismatchObservation.h](PearMismatchObservation.h) | 2981 | `466ff7a0a5d67580c295465decf5c21121901f7015bc825415fab0b6e5f40f5e` |
| [PearTargetObservation.h](PearTargetObservation.h) | 3348 | `99e29c2f5ab72731864b7a4e8d0fed0113f8d5362e36e946213cdf6958f6f4a2` |
| [PearWriterObservation.h](PearWriterObservation.h) | 865 | `5087c8a87de6aac1ce8fefc89e2990c3bc88812de4e27ccce3a47fce5d5d1a1f` |

## Retained source and generation provenance

The following paths identify retained Task #11 Pear source captures, relative to
that original Pear checkout. They are provenance labels, not paths supplied by
this FEX repository. The original files were untracked; no introducing Pear Git
commit is demonstrated. Their exact bytes, preparation receipts and output copies
remain retained privately. The FEX import commit above is not an original
generator-authoring commit.

Each listed source begins with `SPDX-License-Identifier: MIT`; none of those
leading notices supplies a copyright holder or full permission text.

| Retained source | Bytes | SHA-256 |
|---|---:|---|
| `tools/steam/mismatch_source.py` | 6046 | `a3386badc5cea238afbff019ec2d6002aff7ae0d3e29b4320cf0b7d476f02fe6` |
| `tools/steam/mismatch_observation.py` | 4345 | `05b0763b4451e13834f481af0122220f48a341fbc9d9d43224e24be75c8b7452` |
| `tools/steam/target_value2_source.py` | 11056 | `79d88092193e2d609148e3524fa4906af178fd9c733c0c855a75c51528e87bfd` |
| `tools/steam/target_observation.py` | 3337 | `5f2574ae04e1bbd2d1d963cc4c308b5d98b7a2e99f6638ae1b233541dce4caf8` |
| `tools/steam/writer_source.py` | 13061 | `ca46e5986420e62342cc149a95c0f9c1f3675b2408cacd340bee99d0328026f2` |
| `tools/steam/abort_observation.py` | 5349 | `5061529b0d983b1d2450a6135597a1e0c505dc3baae5fa5dc3d9e94492f0cfe3` |

- `PearMismatchObservation.h` comes from `mismatch_source.py`'s header template,
  the field declarations in `mismatch_observation.py`, and the shared field list
  in `abort_observation.py`. Its D29 output equals the selected D36 copy.
- `PearTargetObservation.h` comes from `target_value2_source.py`'s header template,
  `target_observation.py` and `abort_observation.py`, followed by the single
  declared addition in `writer_source.py`. The D31 source3 template is 3,292 bytes;
  that 56-byte addition produces the selected 3,348-byte D32/D36 output. Omitting
  this later source step would not identify the covered header.
- `PearWriterObservation.h` is the complete literal header returned by
  `writer_source.py`; the D32 output equals the selected D36 copy.

The review reconstructed only literal/template data and declared field lists;
no original generator was imported or executed. The selected D36 copies equal
the imported FEX blobs. The retained source-only origin proof is SHA-256
`e9bc1efef2b586704e0506ce0ff7c7c18a259372eebd6bf7e00c61368740caee`
(29,245 bytes). It records exact source/output identities, preparation receipts
and the distinction between source-management acceptance and licensing evidence.

The historical [import notice inventory](../../Provenance/import-notices.json)
continues to describe the files' original inline-notice state. This document
supplements that record; it does not rewrite the inventory, source manifest,
private configuration, generator, build input or compiled artifact. The original
source captures remain provenance, not a second editable implementation or a
clean-clone reconstruction promise.

## MIT permission, condition and warranty

The following clauses are reproduced unchanged from the standard MIT text in
FEX's existing [LICENSE](../../../LICENSE), from its permission paragraph through
the final warranty sentence. That file's upstream copyright line is preserved
there and is not attributed to these Pear templates. The missing original holder
line is disclosed above; no replacement line is invented here. The license
selection is evidenced by the exact source templates, not by their destination.

```text
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
