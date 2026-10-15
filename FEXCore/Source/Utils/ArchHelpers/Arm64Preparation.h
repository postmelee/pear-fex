// SPDX-License-Identifier: MIT
// Source-equivalent finite NX instruction preparation; no delivered handler,
// ThreadState, owner, VM, guest-memory access, execution or lifecycle authority.
#pragma once
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include "Arm64InstructionConstants.h"
#include <algorithm>
#ifdef PEAR_FEX_MEMORY_OWNER
namespace FEXCore::ArchHelpers::Arm64::UnalignedPreparation {
inline PreparedUnalignedPatch PrepareSnapshot(UnalignedHandlerType HandleType,
  std::span<const uint32_t, 13> Snapshot) {
  PreparedUnalignedPatch Result;
  std::copy(Snapshot.begin(), Snapshot.end(), Result.Expected.begin());
  Result.Next = Result.Expected;
  if (HandleType != UnalignedHandlerType::HalfBarrier && HandleType != UnalignedHandlerType::NonAtomic) return Result;
  const auto Instr = Snapshot[1];
  const uint32_t Size = (Instr >> 30) & 3;
  const uint32_t Addr = (Instr >> 5) & 31;
  const uint32_t Data = Instr & 31;
  const bool HalfBarrier = HandleType != UnalignedHandlerType::NonAtomic;
  const auto Store = [&Result](uint8_t Index, uint32_t Value) {
    Result.Next[Index] = Value;
    Result.StoreOrder[Result.StoreCount++] = Index;
  };
  // Reuse the exact upstream masks, register fields and barrier-before-access
  // release-store order. NX preparation performs no store to executable code.
  if ((Instr & LDAXR_MASK) == LDAR_INST || (Instr & LDAXR_MASK) == LDAPR_INST) {
    if (HalfBarrier) Store(2, DMB_LD);
    Store(1, LDR_INST | Size << 30 | Addr << 5 | Data);
    Result.Kind = UnalignedPatchKind::Candidate; Result.ResumeDelta = 0;
  } else if ((Instr & LDAXR_MASK) == STLR_INST) {
    if (HalfBarrier) Store(0, DMB);
    Store(1, STR_INST | Size << 30 | Addr << 5 | Data);
    Result.Kind = UnalignedPatchKind::Candidate; Result.ResumeDelta = -4;
  } else if ((Instr & RCPC2_MASK) == LDAPUR_INST) {
    if (HalfBarrier) Store(2, DMB_LD);
    Store(1, LDUR_INST | Size << 30 | Addr << 5 | Data | (Instr & (0x1ff << 12)));
    Result.Kind = UnalignedPatchKind::Candidate; Result.ResumeDelta = 0;
  } else if ((Instr & RCPC2_MASK) == STLUR_INST) {
    if (HalfBarrier) Store(0, DMB);
    Store(1, STUR_INST | Size << 30 | Addr << 5 | Data | (Instr & (0x1ff << 12)));
    Result.Kind = UnalignedPatchKind::Candidate; Result.ResumeDelta = -4;
  } else if ((Instr & CASPAL_MASK) == CASPAL_INST || (Instr & CASAL_MASK) == CASAL_INST ||
             (Instr & ATOMIC_MEM_MASK) == ATOMIC_MEM_INST ||
             (Instr & LDAXR_MASK) == LDAXR_INST || (Instr & LDAXP_MASK) == LDAXP_INST) {
    // Actual guest-data emulation retains the original private implementation;
    // it requires a real source thread, copied GPR/exclusive state and coherent
    // ACTIVE snapshot. This finite code decoder does not substitute a no-op.
    Result.Kind = UnalignedPatchKind::DataEmulationRequired;
  } else if (((Instr & LDSTREGISTER_MASK) == LDR_INST || (Instr & LDSTUNSCALED_MASK) == LDUR_INST) &&
             (!HalfBarrier || Snapshot[2] == DMB_LD)) {
    Result.Kind = UnalignedPatchKind::AlreadyPatched; Result.ResumeDelta = 0;
  } else if (((Instr & LDSTREGISTER_MASK) == STR_INST || (Instr & LDSTUNSCALED_MASK) == STUR_INST) &&
             (!HalfBarrier || Snapshot[0] == DMB)) {
    Result.Kind = UnalignedPatchKind::AlreadyPatched; Result.ResumeDelta = HalfBarrier ? -4 : 0;
  } else if (Instr == DMB && (Snapshot[2] & LDSTP_MASK) == STP_INST && Snapshot[3] == DMB) {
    Result.Kind = UnalignedPatchKind::AlreadyPatched; Result.ResumeDelta = 0;
  }
  return Result;
}
} // namespace FEXCore::ArchHelpers::Arm64::UnalignedPreparation
#endif
