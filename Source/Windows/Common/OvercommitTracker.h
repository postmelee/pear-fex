// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/IntervalList.h>
#include <ntstatus.h>
#include <winternl.h>
#include <thread>
#include <shared_mutex>


namespace FEX::Windows {
/**
 * @brief Emulates memory overcommit of reserved regions with exceptions
 */
class OvercommitTracker {
private:
  bool IsWine;
  FEXCore::IntervalList<uint64_t> OvercommitIntervals;
  std::shared_mutex OvercommitIntervalsMutex;

public:
  OvercommitTracker(bool IsWine)
    : IsWine {IsWine} {}

  void MarkRange(uint64_t Start, uint64_t Length) {
    std::unique_lock Lock {OvercommitIntervalsMutex};
    OvercommitIntervals.Insert({Start, Start + Length});
  }

  void UnmarkRange(uint64_t Start, uint64_t Length) {
    std::unique_lock Lock {OvercommitIntervalsMutex};
    OvercommitIntervals.Remove({Start, Start + Length});
  }

  bool HandleAccessViolation(uint64_t FaultAddress, NTSTATUS* Failure = nullptr) {
    if (Failure) *Failure = 0;
    std::shared_lock Lock {OvercommitIntervalsMutex};
    auto Query = OvercommitIntervals.Query(FaultAddress);

    if (Query.Enclosed) {
      if (IsWine) {
        MEMORY_BASIC_INFORMATION Info {};
        SIZE_T Returned {};
        auto Status = NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(FaultAddress),
                                          MemoryBasicInformation, &Info, sizeof(Info), &Returned);
        if (Status) { if (Failure) *Failure = Status; return false; }
        const auto Base = reinterpret_cast<uint64_t>(Info.BaseAddress);
        const auto Allocation = reinterpret_cast<uint64_t>(Info.AllocationBase);
        // Retain upstream Wine's allocation-prefix commit, but only inside the
        // registered ordinary RW data interval. Never turn an arbitrary access
        // violation, executable page or failed allocation into handled success.
        if (Returned != sizeof(Info) || Info.Type != MEM_PRIVATE || Info.State != MEM_RESERVE ||
            Info.AllocationProtect != PAGE_READWRITE || Allocation < Query.Interval.Offset ||
            Base < Allocation || Base > FaultAddress || Base >= Query.Interval.End ||
            !Info.RegionSize || Info.RegionSize > Query.Interval.End - Base || FaultAddress - Base >= Info.RegionSize) {
          if (Failure) *Failure = STATUS_INVALID_PARAMETER;
          return false;
        }
        SIZE_T Size = Base - Allocation + Info.RegionSize;
        const auto ExpectedSize = Size;
        void* Address = Info.AllocationBase;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
        if (Status) { if (Failure) *Failure = Status; return false; }
        if (Address != Info.AllocationBase || Size != ExpectedSize) {
          if (Failure) *Failure = STATUS_INVALID_PARAMETER;
          return false;
        }
      } else {
        static constexpr size_t MaxFaultCommitSize = 1024 * 64;
        const auto AlignedFaultAddress = reinterpret_cast<void*>(FaultAddress & FEXCore::Utils::FEX_PAGE_MASK);
        VirtualAlloc(AlignedFaultAddress, std::min<size_t>(Query.Size, MaxFaultCommitSize), MEM_COMMIT, PAGE_READWRITE);
      }
      return true;
    }
    return false;
  }
};
} // namespace FEX::Windows
