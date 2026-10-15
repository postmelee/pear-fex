// SPDX-License-Identifier: MIT
// Original Pear bounded detached-retirement bookkeeping. No owner call occurs
// in this metadata ledger; native gate callers perform the checked operation.
#pragma once
#include <FEXCore/Utils/PearFEXMemory.h>
#include <array>
#include <atomic>
#include <cstring>
#include <optional>

namespace FEXCore::Utils::PearFEXMemory::Retirement {
inline constexpr size_t CAPACITY = PEAR_FEX_MEMORY_MAX_EXTENTS;
struct Failure {
  Allocation Target {};
  Result Outcome {};
  bool Present {};
  bool HasAllocation {};
};
struct Work {
  Allocation Target {};
  size_t Index {};
  uint64_t Ticket {};
  bool Quarantined {};
  Result OriginalFailure {};
};
// This type is also consumed by finite metadata-only controls. Injected
// outcomes in those controls are not observed native owner retirements.
class DetachedLedger {
public:
  DetachedLedger() = default;
  DetachedLedger(const DetachedLedger&) = delete;
  DetachedLedger& operator=(const DetachedLedger&) = delete;
  bool AdmissionOpen() const { return !Closed.load(std::memory_order_acquire); }
  Result PoisonSourceAdmission(Result Outcome) {
    Guard Lock {Mutex};
    if (!FirstFailure.Present) FirstFailure = {{}, Outcome, true, false};
    Closed.store(true, std::memory_order_release);
    return Outcome;
  }
  Failure FirstFailureSnapshot() const { Guard Lock {Mutex}; return FirstFailure; }
  size_t OccupiedCount() const {
    Guard Lock {Mutex}; size_t Count {};
    for (const auto& Item : Records) Count += Item.Ticket != 0;
    return Count;
  }
  Failure FailureSnapshot(size_t Index) const {
    Guard Lock {Mutex};
    if (Index >= Records.size() || !Records[Index].Ticket) return {};
    return {Records[Index].Target, Records[Index].LastFailure, Records[Index].Failed, true};
  }
  Result EnqueueDetached(const Allocation& Target) {
    Guard Lock {Mutex};
    if (!IdentityShape(Target)) return Poison(Target, {PEAR_FEX_INVALID_REQUEST, 0, 0});
    const bool Quarantined = !Retirable(Target);
    const Result Original = Target.Status == PEAR_FEX_OK ? Result {PEAR_FEX_UNAVAILABLE, 0, 0} :
      Result {Target.Status, Target.ErrorDomain, Target.ErrorCode};
    Record* Empty {};
    for (auto& Item : Records) {
      if (Item.Ticket && Item.Target.Token.owner_pid == Target.Token.owner_pid &&
          Item.Target.Token.allocation_id == Target.Token.allocation_id && Item.Target.Token.generation == Target.Token.generation) {
        if (!Same(Item.Target, Target)) return Poison(Target, {PEAR_FEX_STALE_IDENTITY, 0, 0});
        return Item.Quarantined ? Item.LastFailure : Result {PEAR_FEX_OK, 0, 0};
      }
      if (!Item.Ticket && !Empty) Empty = &Item;
    }
    if (!Empty || NextTicket == UINT64_MAX) return Poison(Target, {PEAR_FEX_CAPACITY, 0, 0});
    // Existing objects may still detach after a poison closes new admission.
    // Preserve their exact records instead of dropping cleanup facts.
    Empty->Target = Target; Empty->Ticket = ++NextTicket;
    Empty->Quarantined = Quarantined;
    if (Quarantined) {
      // Retain every structurally known partial identity in its own occupied
      // record. No fabricated positive lifecycle can authorize a retire call.
      Empty->LastFailure = Original; Empty->Failed = true;
      return Poison(Target, Original);
    }
    return {PEAR_FEX_OK, 0, 0};
  }
  std::optional<Work> Take(size_t Index) {
    Guard Lock {Mutex};
    if (Index >= Records.size()) return std::nullopt;
    auto& Item = Records[Index];
    if (!Item.Ticket || Item.InFlight) return std::nullopt;
    Item.InFlight = true;
    return Work {Item.Target, Index, Item.Ticket, Item.Quarantined, Item.LastFailure};
  }
  Result Complete(const Work& Taken, Result Outcome, const Allocation& Observed) {
    Guard Lock {Mutex};
    if (Taken.Index >= Records.size()) return Poison(Taken.Target, {PEAR_FEX_INVALID_REQUEST, 0, 0});
    auto& Item = Records[Taken.Index];
    if (!Item.Ticket || !Item.InFlight || Item.Ticket != Taken.Ticket || !Same(Item.Target, Taken.Target)) {
      Poison(Taken.Target, {PEAR_FEX_STALE_IDENTITY, 0, 0});
      return Outcome ? Result {PEAR_FEX_STALE_IDENTITY, 0, 0} : Outcome;
    }
    Item.InFlight = false;
    if (Item.Quarantined) {
      // This record never issued a qualified Retire. A caller-selected success
      // or retired-looking metadata cannot recover/erase its failed identity.
      Poison(Taken.Target, Item.LastFailure);
      return Item.LastFailure;
    }
    if (!Outcome) {
      // A refusal/timeout/native failure never releases an occupied slot or
      // replaces its target. The exact original status/domain/code is retained.
      Item.LastFailure = Outcome; Item.Failed = true;
      // A failed observed drain closes every new source admission even when
      // its target facts stayed unchanged. Preserve the original error first.
      Poison(Taken.Target, Outcome);
      if (!Same(Observed, Taken.Target)) Poison(Taken.Target, {PEAR_FEX_STALE_IDENTITY, 0, 0});
      return Outcome;
    }
    if (!Retired(Taken.Target, Observed)) {
      Item.LastFailure = {PEAR_FEX_VERSION_MISMATCH, 0, 0}; Item.Failed = true;
      return Poison(Taken.Target, Item.LastFailure);
    }
    // Release only after the exact source adapter returned observed retirement
    // for this never-reused identity/generation, with NONE and no Base.
    Item = {};
    return Outcome;
  }
private:
  struct Record {
    Allocation Target {};
    Result LastFailure {};
    uint64_t Ticket {};
    bool InFlight {};
    bool Failed {};
    bool Quarantined {};
  };
  struct Guard {
    std::atomic_flag& Flag;
    explicit Guard(std::atomic_flag& Flag) : Flag(Flag) { while (Flag.test_and_set(std::memory_order_acquire)) {} }
    ~Guard() { Flag.clear(std::memory_order_release); }
  };
  static bool Same(const Allocation& A, const Allocation& B) {
    return A.Base == B.Base && A.Status == B.Status && A.ErrorDomain == B.ErrorDomain && A.ErrorCode == B.ErrorCode &&
           std::memcmp(&A.Token, &B.Token, sizeof(A.Token)) == 0;
  }
  static bool IdentityShape(const Allocation& A) {
    return A.Token.version == PEAR_FEX_MEMORY_VERSION && A.Token.size == sizeof(A.Token) &&
           !A.Token.opcode && !A.Token.flags && !A.Token.executor_id && !A.Token.continuation_id &&
           !A.Token.operation_offset && !A.Token.operation_size && !A.Token.reserved0 && !A.Token.reserved1 && !A.Token.reserved2 &&
           A.Token.owner_pid && A.Token.allocation_id && A.Token.generation && A.Token.extent_size &&
           !(A.Token.extent_offset & (PEAR_FEX_MEMORY_PAGE_BYTES-1)) && !(A.Token.extent_size & (PEAR_FEX_MEMORY_PAGE_BYTES-1)) &&
           (A.Token.allocation_class == PEAR_FEX_CLASS_SHARED || A.Token.allocation_class == PEAR_FEX_CLASS_DISPATCHER) &&
           (A.Token.ec_role == PEAR_FEX_ROLE_ARM64EC || A.Token.ec_role == PEAR_FEX_ROLE_NATIVE) &&
           (A.Token.expected_state == PEAR_FEX_RESERVED_NONE || A.Token.expected_state == PEAR_FEX_WRITING_RW_NX ||
            A.Token.expected_state == PEAR_FEX_PUBLISHED_RX);
  }
  static bool Retirable(const Allocation& A) {
    return A.Status == PEAR_FEX_OK && !A.ErrorDomain && !A.ErrorCode &&
      (A.Token.expected_state == PEAR_FEX_RESERVED_NONE ||
       (A.Token.expected_state == PEAR_FEX_PUBLISHED_RX && A.Base && A.Token.write_epoch));
  }
  static bool Retired(const Allocation& Expected, const Allocation& Observed) {
    auto Required = Expected;
    Required.Base = nullptr; Required.Status = PEAR_FEX_STALE_IDENTITY;
    Required.Token.expected_state = PEAR_FEX_RETIRED_NONE;
    return Same(Required, Observed);
  }
  Result Poison(const Allocation& Target, Result Outcome) {
    if (!FirstFailure.Present) FirstFailure = {Target, Outcome, true, true};
    Closed.store(true, std::memory_order_release);
    return Outcome;
  }
  std::array<Record, CAPACITY> Records {};
  Failure FirstFailure {};
  uint64_t NextTicket {};
  mutable std::atomic_flag Mutex = ATOMIC_FLAG_INIT;
  std::atomic<bool> Closed {false};
};
static_assert(sizeof(DetachedLedger) <= 24576, "Bounded source detached-retirement metadata plus first-poison diagnostic");
bool AdmissionOpen();
// Preserve an unresolved source registration/cleanup failure without inventing
// an allocation. The first diagnostic's HasAllocation discriminator is false.
Result PoisonSourceAdmission(Result);
Result EnqueueDetached(const Allocation&);
Result DrainAtNativeGate();
Failure FirstFailureSnapshot();
} // namespace FEXCore::Utils::PearFEXMemory::Retirement
