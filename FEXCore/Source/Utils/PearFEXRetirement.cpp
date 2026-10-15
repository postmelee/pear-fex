// SPDX-License-Identifier: MIT
// Original Pear source native-gate draining; no engine initialization.
#include <FEXCore/Utils/PearFEXRetirement.h>
#include <FEXCore/Utils/LogManager.h>

namespace FEXCore::Utils::PearFEXMemory::Retirement {
namespace {
DetachedLedger Ledger {};
}
bool AdmissionOpen() { return Ledger.AdmissionOpen(); }
Result PoisonSourceAdmission(Result Outcome) { return Ledger.PoisonSourceAdmission(Outcome); }
Result EnqueueDetached(const Allocation& Target) { return Ledger.EnqueueDetached(Target); }
Failure FirstFailureSnapshot() { return Ledger.FirstFailureSnapshot(); }
Result DrainAtNativeGate() {
  // Source callers must be at the qualified native gate, with no invalidation,
  // lookup, list, Latest or ThreadCreation lock. This creates no registration.
  if (!CurrentExecutor()) return {PEAR_FEX_UNAVAILABLE, 0, 0};
  Result FirstError {PEAR_FEX_OK, 0, 0};
  for (size_t Index = 0; Index < CAPACITY; ++Index) {
    const auto Taken = Ledger.Take(Index);
    if (!Taken) continue;
    auto Observed = Taken->Target;
    // Take released the metadata lock before this owner call can close the
    // global gate or wait for an actual cooperative native acknowledgement.
    // A failed abort/partial writer is retained without inventing clean NONE
    // or RX facts. Its exact original error prevents source Context release.
    const auto Outcome = Taken->Quarantined ? Taken->OriginalFailure : SourceLifecycle::RetireDetachedAtCleanupGate(Observed);
    const auto Completed = Ledger.Complete(*Taken, Outcome, Observed);
    if (!Completed) {
      if (FirstError) FirstError = Completed;
      LogMan::Msg::EFmt("Pear detached retirement retained: status {}, domain {}, code {}",
                        Completed.Status, Completed.ErrorDomain, Completed.ErrorCode);
    }
  }
  if (FirstError && Ledger.OccupiedCount()) {
    const auto First = Ledger.FirstFailureSnapshot();
    return First.Present ? First.Outcome : Result {PEAR_FEX_UNAVAILABLE, 0, 0};
  }
  return FirstError;
}
} // namespace FEXCore::Utils::PearFEXMemory::Retirement
