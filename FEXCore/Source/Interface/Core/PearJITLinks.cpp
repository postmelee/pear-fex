// SPDX-License-Identifier: MIT
// Original finite actual-source link transactions. No engine initialization.
#include "Interface/Core/PearJITLinks.h"
#include <FEXCore/Debug/InternalThreadState.h>
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/SharedCodeBufferManager.h"
#include <FEXCore/Utils/LogManager.h>
#include <cstdlib>
#include <mutex>
#include <new>

extern "C" bool PearLinkObservationEnabled();
extern "C" void PearLinkObservation(uint32_t, uint32_t, uint64_t, uint64_t);

namespace FEXCore::CPU::PearJITLinks {
namespace Memory = FEXCore::Utils::PearFEXMemory;
struct Registry {
  struct Slot { std::optional<SourceDescriptor> Source; };
  struct BatchWrite {
    std::optional<Memory::SourceMutationTurn> Mutation;
    Ticket First {};
    Memory::Allocation Before {}, Transaction {};
    // Guard and its referenced transaction have one stable registry lifetime.
    std::optional<Memory::WriteGuard> Writer;
    std::optional<Memory::Links::ReservedBarrierTarget> Reserved;
    std::optional<CPUBackend::PearManagedWindow> Published;
  };
  std::mutex Mutex;
  TicketLedger Ledger;
  struct EntryIdentity {
    const FEXCore::Context::Context* Context {};
    const FEXCore::Core::InternalThreadState* Thread {};
    uint64_t Executor {}, SourceSerial {};
  };
  std::array<EntryIdentity,ENTRY_CAPACITY> Entries {};
  std::atomic<uint32_t> EntryWord {};
  void Changed() {
    EntryWord.fetch_add(1,std::memory_order_release);
    Memory::NotifySourceEntryChange(EntryWord);
  }
  static EntryIdentity Capture(const Memory::SourceLifetime& Life) {
    return {Life.ActualContext(),Life.ActualThread(),Life.Executor(),Life.Identity()};
  }
  static bool Same(const EntryIdentity& A,const EntryIdentity& B) {
    return A.Context && A.Thread && A.Executor && A.SourceSerial && A.Context==B.Context &&
      A.Thread==B.Thread && A.Executor==B.Executor && A.SourceSerial==B.SourceSerial;
  }
  std::array<Slot,CAPACITY> Slots {};
  FEXCore::Context::ContextImpl* BatchContext {};
  FEXCore::Core::InternalThreadState* BatchThread {};
  uint64_t BatchExecutor {};
  std::optional<BatchWrite> Held;
  Memory::Result First {PEAR_FEX_OK,0,0};
  Memory::Result Poison(Memory::Result E) {
    if (E) E={PEAR_FEX_UNAVAILABLE,0,0};
    { std::lock_guard L {Mutex}; Ledger.Close(); if (First) First=E; }
    Changed();
    return Memory::Retirement::PoisonSourceAdmission(E);
  }
  static bool ThreadMatches(FEXCore::Context::ContextImpl* C, FEXCore::Core::InternalThreadState* T) {
    return C && T && T->CTX==C && T->CPUBackend && T->CurrentFrame && T->CurrentFrame->Thread==T &&
      Memory::CurrentExecutor() && Memory::CurrentSourceRole()==PEAR_SOURCE_CODE_ROLE;
  }
  static bool Identity(const SourceDescriptor& D, const Memory::Allocation& A) {
    return D && A && A.Base==D.Owner->GetBufferBase() && A.Token.owner_pid==D.OwnerPID &&
      A.Token.allocation_id==D.AllocationID && A.Token.generation==D.Generation &&
      A.Token.allocation_class==PEAR_FEX_CLASS_SHARED && A.Token.ec_role==PEAR_SOURCE_CODE_ROLE &&
      A.Token.expected_state==PEAR_FEX_PUBLISHED_RX && A.Token.write_epoch &&
      D.Layout.WriteOffset<=D.Owner->UsableSize() && D.Layout.WriteSize<=D.Owner->UsableSize()-D.Layout.WriteOffset;
  }
  static std::optional<Memory::Links::ReservedBarrierTarget> ReservedSource(FEXCore::Core::InternalThreadState* T) {
    return T && T->CPUBackend ? T->CPUBackend->FindPearReservedBarrierTarget() : std::nullopt;
  }
  static bool SameReserved(const Memory::Links::ReservedBarrierTarget& T,const Memory::Allocation& A,
                           const FEXCore::Core::InternalThreadState* Thread) {
    return T && T.ActualThread==Thread && T.Owner && A && !A.Base &&
      A.Token.expected_state==PEAR_FEX_RESERVED_NONE && A.Token.ec_role==PEAR_SOURCE_CODE_ROLE &&
      A.Token.owner_pid==T.Captured.Token.owner_pid && A.Token.allocation_id==T.Captured.Token.allocation_id &&
      A.Token.generation==T.Captured.Token.generation && A.Token.write_epoch==T.Captured.Token.write_epoch &&
      A.Token.extent_offset==T.Captured.Token.extent_offset && A.Token.extent_size==T.Captured.Token.extent_size &&
      A.Token.allocation_class==PEAR_FEX_CLASS_SHARED && T.Owner->UsableSize()>=16 && T.Owner->GetBufferBase();
  }
  static uint8_t* ReservedNumericBase(const Memory::Links::ReservedBarrierTarget& T) { return T.Owner->GetBufferBase(); }
  static Memory::Allocation ReservedSnapshot(const Memory::Links::ReservedBarrierTarget& T) { return T.Owner->GetPearSnapshot(); }
  Memory::Result AbortReserved(BatchWrite& Work) {
    const auto Aborted=Work.Writer->Abort();
    const bool Updated=Work.Reserved->Owner->ComparePearUpdate(Work.Before,Work.Transaction);
    if (!Aborted) return Poison(Aborted);
    if (!Updated) return Poison({PEAR_FEX_STALE_IDENTITY,0,0});
    if (Work.Transaction.Base || Work.Transaction.Token.expected_state!=PEAR_FEX_RESERVED_NONE ||
        Work.Transaction.Token.write_epoch<=Work.Before.Token.write_epoch) return Poison({PEAR_FEX_VERSION_MISMATCH,0,0});
    return Aborted;
  }
  static bool Matches(const SourceDescriptor& D, const Memory::WriteGuard& W) {
    return W.Matches(D.Layout.ThunkOffset-D.Layout.WriteOffset,D.Thunk) &&
      W.Matches(D.Layout.MarkerOffset-D.Layout.WriteOffset,D.Caller);
  }
  static void Apply(SourceDescriptor& D, Memory::WriteGuard& W, bool Restore) {
    const auto Word=Restore ? D.Instructions.RestoreWord : D.Instructions.PatchedWord;
    const auto Offset=D.Instructions.Direct ? D.Layout.CallerOffset : D.Layout.ThunkOffset;
    if (!Restore && !D.Instructions.Direct) {
      const auto H=D.Layout.RecordOffset+offsetof(FEXCore::Context::ExitFunctionLinkData,HostCode);
      // Source-qualified RWNX bytes only. Owner publication supplies the real
      // cache/protection synchronization after the original instruction formula.
      std::memcpy(W.Data()+H-D.Layout.WriteOffset,&D.HostDestination,sizeof(D.HostDestination));
      std::memcpy(D.Thunk.data()+H-D.Layout.ThunkOffset,&D.HostDestination,sizeof(D.HostDestination));
    }
    std::memcpy(W.Data()+Offset-D.Layout.WriteOffset,&Word,sizeof(Word));
    // Source snapshots may overlap at a bounded call/thunk footprint. Keep
    // every intersecting NX byte consistent with the one actual RWNX store.
    const auto Refresh=[&](size_t Begin,auto& Bytes) {
      const auto Start=std::max(Begin,Offset),End=std::min(Begin+Bytes.size(),Offset+sizeof(Word));
      if (Start<End) std::memcpy(Bytes.data()+Start-Begin,reinterpret_cast<const uint8_t*>(&Word)+Start-Offset,End-Start);
    };
    Refresh(D.Layout.MarkerOffset,D.Caller); Refresh(D.Layout.ThunkOffset,D.Thunk);
  }
  Memory::Result Publish(SourceDescriptor& D, Memory::Allocation& Before, Memory::Allocation& A, Memory::WriteGuard& W) {
    const auto P=W.Publish();
    if (!P) {
      const auto Aborted=W.Abort();
      if (!Aborted) LogMan::Msg::EFmt("Pear link abort retained: status {}, domain {}, code {}",
                                     Aborted.Status,Aborted.ErrorDomain,Aborted.ErrorCode);
      D.Owner->ComparePearUpdate(Before,A);
      return Poison(P);
    }
    if (!D.Owner->ComparePearUpdate(Before,A)) return Poison({PEAR_FEX_STALE_IDENTITY,0,0});
    return P;
  }
  // On a source/expected-byte refusal, no executable bytes are changed. Restore
  // observed RX publication and its token before keeping the original refusal.
  Memory::Result RefuseOpen(SourceDescriptor& D, Memory::Allocation& Before, Memory::Allocation& A,
                            Memory::WriteGuard& W, Memory::Result Original) {
    const auto Restored=Publish(D,Before,A,W);
    if (!Restored) LogMan::Msg::EFmt("Pear refused-link RX cleanup retained: status {}, domain {}, code {}",
                                    Restored.Status,Restored.ErrorDomain,Restored.ErrorCode);
    return Poison(Original);
  }
};
static_assert(sizeof(Registry)+sizeof(Memory::WriteGuard)+sizeof(void*)<=32*1024*1024,"Fixed link NX metadata budget");
namespace {
// Fixed private NX storage avoids implicit DLL/global teardown owner calls or
// releasing uncertain actual source refs after the retirement ledger lifetime.
// Normal native-gate completion explicitly releases every successful record.
// Failed/pending records remain bounded and retained until process teardown.
alignas(Registry) std::byte Storage[sizeof(Registry)];
Registry& StateRegistry() {
  static Registry* const Address=::new (Storage) Registry;
  return *Address;
}
}

std::optional<Ticket> Prepare(SourceDescriptor D) {
  auto& R=StateRegistry();
  std::optional<Ticket> Result;
  const bool Observe=PearLinkObservationEnabled();
  uint32_t Reason {};
  size_t Occupied {};
  {
    std::lock_guard L {R.Mutex};
    Result = [&]() -> std::optional<Ticket> {
      if (!D) { Reason=1; return std::nullopt; }
      // Preserve the original short-circuit order and optional-link policy.
      if (R.Ledger.HasSealedEntries()) { Reason=2; return std::nullopt; }
      if (R.Ledger.Occupied()==CAPACITY) { Reason=3; return std::nullopt; }
      const auto T=R.Ledger.Prepare();
      if (!T) { Reason=4; return std::nullopt; }
      R.Slots[T->Index].Source.emplace(std::move(D));
      Reason=5; return T;
    }();
    if (Observe) Occupied=R.Ledger.Occupied();
  }
  // Emit after releasing the registry mutex; this snapshot grants no authority.
  if (Observe) PearLinkObservation(2,Reason,Occupied,CAPACITY);
  return Result;
}
Memory::Result CancelPrepared(Ticket T) {
  auto& R=StateRegistry();
  std::optional<SourceDescriptor> Detached;
  bool Okay {};
  { std::lock_guard L {R.Mutex};
    Okay=R.Ledger.CancelPrepared(T);
    if (Okay) Detached.swap(R.Slots[T.Index].Source);
  }
  // Last strong reference/destructor runs after the short metadata lock.
  R.Changed();
  return Okay ? Memory::Result{PEAR_FEX_OK,0,0} : R.Poison({PEAR_FEX_STALE_IDENTITY,0,0});
}
Memory::Result Commit(Ticket T) {
  auto& R=StateRegistry();
  bool Okay {};
  { std::lock_guard L {R.Mutex}; Okay=R.Ledger.Commit(T); }
  R.Changed();
  return Okay ? Memory::Result{PEAR_FEX_OK,0,0} : R.Poison({PEAR_FEX_STALE_IDENTITY,0,0});
}
Memory::Result PatchPrepared(Ticket T, FEXCore::Core::InternalThreadState* Thread, uint64_t Revision) {
  auto& R=StateRegistry();
  std::optional<SourceDescriptor> D;
  { std::lock_guard L {R.Mutex};
    if (T.Index<CAPACITY && R.Ledger.GetState(T.Index)==State::Prepared && R.Ledger.GetTicket(T.Index)==T.Value)
      D=R.Slots[T.Index].Source;
  }
  auto Life=Memory::AcquireCurrentSourceLifetime(D ? D->SourceContext : nullptr);
  if (!D || !Life || Life.ActualThread()!=Thread || !Registry::ThreadMatches(D->SourceContext,Thread))
    { LogMan::Msg::EFmt("Pear link refusal: source identity"); return R.Poison({PEAR_FEX_STALE_IDENTITY,0,0}); }
  const auto Bound=Memory::BindSourceThread(Thread); if (!Bound) return R.Poison(Bound);
  auto Before=D->Owner->GetPearSnapshot(), A=Before;
  if (!Registry::Identity(*D,A)) { LogMan::Msg::EFmt("Pear link refusal: allocation identity"); return R.Poison({PEAR_FEX_STALE_IDENTITY,0,0}); }
  // All invalidation/lookup/list/Latest/ThreadCreation locks are absent here.
  Memory::WriteGuard W {A,D->Layout.WriteOffset,D->Layout.WriteSize};
  if (!W) { LogMan::Msg::EFmt("Pear link refusal: write guard status {}",W.Status().Status); return R.Poison(W.Status()); }
  bool Valid {};
  {
    auto Invalidation=GuardSignalDeferringSection<std::shared_lock>(D->SourceContext->CodeInvalidationMutex,Thread);
    auto Lookup=Thread->LookupCache->AcquireWriteLock();
    const auto Found=Thread->LookupCache->Shared->BlockList.find(D->GuestDestination);
    Valid=Registry::ThreadMatches(D->SourceContext,Thread) && D->SourceContext->GetPearInvalidationRevision()==Revision &&
      Thread->LookupCache->Shared==D->Owner->LookupCache.get() && Found!=Thread->LookupCache->Shared->BlockList.end() &&
      Found->second.HostCode==D->HostDestination && Registry::Matches(*D,W);
    if (!Valid) LogMan::Msg::EFmt("Pear link validation thread={} revision={} map={} found={} host={} bytes={} guest={:x}",
      Registry::ThreadMatches(D->SourceContext,Thread),D->SourceContext->GetPearInvalidationRevision()==Revision,
      Thread->LookupCache->Shared==D->Owner->LookupCache.get(),Found!=Thread->LookupCache->Shared->BlockList.end(),
      Found!=Thread->LookupCache->Shared->BlockList.end() && Found->second.HostCode==D->HostDestination,
      Registry::Matches(*D,W),D->GuestDestination);
    if (Valid) Registry::Apply(*D,W,false);
  }
  if (!Valid) return R.RefuseOpen(*D,Before,A,W,{PEAR_FEX_STALE_IDENTITY,0,0});
  // Prepared ticket blocks real invalidation preflight and new managed entry
  // while these locks are released for native publication/token replacement.
  const auto Published=R.Publish(*D,Before,A,W); if (!Published) return Published;
  bool Stored {};
  { std::lock_guard L {R.Mutex};
    Stored=R.Ledger.GetState(T.Index)==State::Prepared && R.Ledger.GetTicket(T.Index)==T.Value && R.Slots[T.Index].Source.has_value();
    if (Stored) {
      R.Slots[T.Index].Source->Thunk=D->Thunk; R.Slots[T.Index].Source->Caller=D->Caller;
    }
  }
  return Stored ? Published : R.Poison({PEAR_FEX_STALE_IDENTITY,0,0});
}
// Failure-only opt-in observation; the original transaction result is retained.
static std::atomic<unsigned> BatchFailureObservations {};
static void ObserveBatchFailure(const char* Phase, Memory::Result Failure) {
  const char* Enabled=std::getenv("PEAR_FEX_BATCH_OBSERVE");
  if (!Enabled || Enabled[0]!='1' || Enabled[1]) return;
  auto Sequence=BatchFailureObservations.load(std::memory_order_relaxed);
  while (Sequence<8 && !BatchFailureObservations.compare_exchange_weak(
           Sequence,Sequence+1,std::memory_order_relaxed)) {}
  if (Sequence<8)
    LogMan::Msg::EFmt("PEAR_BATCH phase={} seq={} status={} domain={} code={}",
                     Phase,Sequence,Failure.Status,Failure.ErrorDomain,Failure.ErrorCode);
}
Memory::Result BeginBatch(FEXCore::Context::ContextImpl* C,FEXCore::Core::InternalThreadState* Thread) {
  auto& R=StateRegistry();
  auto Life=Memory::AcquireCurrentSourceLifetime(C);
  if (!Life || Life.ActualThread()!=Thread || !Registry::ThreadMatches(C,Thread)) return {PEAR_FEX_STALE_IDENTITY,0,0};
  const auto Bound=Memory::BindSourceThread(Thread); if (!Bound) return Bound;
  Memory::SourceMutationTurn Mutation {Life};
  if (!Mutation) { const auto Failure=Mutation.Status(); ObserveBatchFailure("mutation",Failure); return Failure; }
  std::optional<SourceDescriptor> First;
  auto Reserved=Registry::ReservedSource(Thread);
  auto Published=Thread->CPUBackend->FindPearPublishedBarrierTarget();
  Ticket T {};
  {
    std::lock_guard L {R.Mutex};
    // No link-owned target may use only an actual source reserved current A.
    // Its real guard/Abort remains distinct from published/callable code.
    for (size_t I=0;I<CAPACITY;++I) if (R.Ledger.GetState(I)==State::Linked && R.Slots[I].Source &&
      R.Slots[I].Source->SourceContext==C) { First=R.Slots[I].Source; T={I,R.Ledger.GetTicket(I)}; break; }
    if (!First && !Reserved && !Published) { LogMan::Msg::EFmt("Pear batch has no actual linked, reserved or published source target"); return {PEAR_FEX_UNAVAILABLE,0,0}; }
    if (!R.Ledger.BeginBatch()) { LogMan::Msg::EFmt("Pear batch ledger refused: sealed {}, occupied {}, entry-open {}",R.Ledger.HasSealedEntries(),R.Ledger.Occupied(),R.Ledger.EntryAdmissionOpen()); return {PEAR_FEX_UNAVAILABLE,0,0}; }
    R.BatchContext=C; R.BatchThread=Thread; R.BatchExecutor=Memory::CurrentExecutor();
  }
  // Admission is closed before constructing the guard. Keep its referenced
  // Transaction at this stable address through publish/abort and destruction.
  Registry::BatchWrite* Work;
  { std::lock_guard L {R.Mutex}; R.Held.emplace(); Work=&*R.Held; Work->First=T; Work->Mutation.emplace(std::move(Mutation)); }
  if (First) {
    Work->Before=First->Owner->GetPearSnapshot(); Work->Transaction=Work->Before;
    if (!Registry::Identity(*First,Work->Before)) return R.Poison({PEAR_FEX_STALE_IDENTITY,0,0});
    Work->Writer.emplace(Work->Transaction,First->Layout.WriteOffset,First->Layout.WriteSize);
    if (!*Work->Writer) { const auto Failure=Work->Writer->Status(); ObserveBatchFailure("writer-linked",Failure); return R.Poison(Failure); }
    if (!Registry::Matches(*First,*Work->Writer)) return R.RefuseOpen(*First,Work->Before,Work->Transaction,*Work->Writer,{PEAR_FEX_STALE_IDENTITY,0,0});
  } else if (Published) {
    Work->Published=std::move(Published);
    Work->Before=Work->Published->Owner->GetPearSnapshot(); Work->Transaction=Work->Before;
    const auto& A=Work->Before;
    if (!A || A.Base!=Work->Published->Owner->GetBufferBase() || A.Token.expected_state!=PEAR_FEX_PUBLISHED_RX ||
        A.Token.allocation_class!=PEAR_FEX_CLASS_SHARED || A.Token.ec_role!=PEAR_SOURCE_CODE_ROLE)
      return R.Poison({PEAR_FEX_STALE_IDENTITY,0,0});
    // A real target write gate supplies quiescence even when the translator has
    // emitted code but no link descriptor. No code bytes are changed here.
    Work->Writer.emplace(Work->Transaction,0,16);
    if (!*Work->Writer) { const auto Failure=Work->Writer->Status(); ObserveBatchFailure("writer-published",Failure); return R.Poison(Failure); }
  } else {
    Work->Reserved=std::move(Reserved); Work->Before=Registry::ReservedSnapshot(*Work->Reserved); Work->Transaction=Work->Before;
    if (!Registry::SameReserved(*Work->Reserved,Work->Before,Thread)) return R.Poison({PEAR_FEX_STALE_IDENTITY,0,0});
    Work->Writer.emplace(Work->Transaction,0,16);
    if (!*Work->Writer) { const auto Failure=Work->Writer->Status(); ObserveBatchFailure("writer-reserved",Failure); return R.Poison(Failure); }
    if (Work->Writer->Data()!=Registry::ReservedNumericBase(*Work->Reserved)) {
      const auto Cleanup=R.AbortReserved(*Work);
      if (!Cleanup) LogMan::Msg::EFmt("Pear reserved barrier abort retained: status {}, domain {}, code {}",
                                     Cleanup.Status,Cleanup.ErrorDomain,Cleanup.ErrorCode);
      return R.Poison({PEAR_FEX_STALE_IDENTITY,0,0});
    }
  }
  // Actual owned RWNX admission has parked every cooperative participant. This
  // observed target guard, not the marker, precedes the caller's guest mutation.
  return {PEAR_FEX_OK,0,0};
}
Memory::Result Queue(Ticket T) {
  auto& R=StateRegistry();
  bool Okay {};
  { std::lock_guard L {R.Mutex}; Okay=R.BatchContext && R.Held && R.BatchExecutor==Memory::CurrentExecutor() && T.Index<CAPACITY &&
      R.Slots[T.Index].Source && R.Slots[T.Index].Source->SourceContext==R.BatchContext && R.Ledger.Queue(T); }
  return Okay ? Memory::Result{PEAR_FEX_OK,0,0} : R.Poison({PEAR_FEX_STALE_IDENTITY,0,0});
}
Memory::Result FinishBatch(FEXCore::Context::ContextImpl* C,FEXCore::Core::InternalThreadState* Thread) {
  auto& R=StateRegistry();
  auto Life=Memory::AcquireCurrentSourceLifetime(C);
  if (!Life || Life.ActualThread()!=Thread || !Registry::ThreadMatches(C,Thread)) return R.Poison({PEAR_FEX_STALE_IDENTITY,0,0});
  Registry::BatchWrite* Held {};
  std::optional<SourceDescriptor> First;
  {
    std::lock_guard L {R.Mutex};
    if (R.BatchContext!=C || R.BatchThread!=Thread || R.BatchExecutor!=Memory::CurrentExecutor() || !R.Held)
      return {PEAR_FEX_STALE_IDENTITY,0,0};
    Held=&*R.Held; if (!Held->Reserved && !Held->Published) First=R.Slots[Held->First.Index].Source;
  }
  if (!First && !Held->Reserved && !Held->Published) return R.Poison({PEAR_FEX_STALE_IDENTITY,0,0});
  Memory::Result FinishedFirst;
  if (Held->Published) {
    FinishedFirst=Held->Writer->Publish();
    if (!FinishedFirst) return R.Poison(FinishedFirst);
    if (!Held->Published->Owner->ComparePearUpdate(Held->Before,Held->Transaction))
      return R.Poison({PEAR_FEX_STALE_IDENTITY,0,0});
  } else FinishedFirst=Held->Reserved ? R.AbortReserved(*Held) : R.Publish(*First,Held->Before,Held->Transaction,*Held->Writer);
  Held->Writer.reset();
  if (!FinishedFirst) return FinishedFirst;
  for (size_t I=0;I<CAPACITY;++I) {
    std::optional<Ticket> Taken; std::optional<SourceDescriptor> D;
    { std::lock_guard L {R.Mutex}; Taken=R.Ledger.Take(I); if (Taken) D=R.Slots[I].Source; }
    if (!Taken) continue;
    Memory::Result Outcome {PEAR_FEX_STALE_IDENTITY,0,0};
    if (D && D->SourceContext==C) {
      auto Before=D->Owner->GetPearSnapshot(), A=Before;
      if (Registry::Identity(*D,A)) {
        Memory::WriteGuard W {A,D->Layout.WriteOffset,D->Layout.WriteSize};
        if (W) {
          if (Registry::Matches(*D,W)) { Registry::Apply(*D,W,true); Outcome=R.Publish(*D,Before,A,W); }
          else Outcome=R.RefuseOpen(*D,Before,A,W,{PEAR_FEX_STALE_IDENTITY,0,0});
        } else Outcome=W.Status();
      }
    }
    std::optional<SourceDescriptor> Detached; bool Complete {};
    { std::lock_guard L {R.Mutex}; Complete=R.Ledger.Complete(*Taken,!!Outcome); if (Complete) Detached.swap(R.Slots[I].Source); }
    if (!Outcome || !Complete) return R.Poison(!Outcome ? Outcome : Memory::Result{PEAR_FEX_STALE_IDENTITY,0,0});
  }
  bool Complete {};
  { std::lock_guard L {R.Mutex};
    Complete=R.Ledger.FinishBatch();
    if (Complete) { R.Held.reset(); R.BatchContext=nullptr; R.BatchThread=nullptr; R.BatchExecutor=0; }
  }
  R.Changed();
  return Complete ? Memory::Result{PEAR_FEX_OK,0,0} : R.Poison({PEAR_FEX_UNAVAILABLE,0,0});
}
} // namespace FEXCore::CPU::PearJITLinks
namespace FEXCore::Utils::PearFEXMemory::Links {
namespace {
using Registry=FEXCore::CPU::PearJITLinks::Registry;
using Ledger=FEXCore::CPU::PearJITLinks::TicketLedger;
static bool MatchesEntry(Registry& R,Ledger::Entry E,const Registry::EntryIdentity& Actual) {
  return R.Ledger.MatchEntry(E) && Registry::Same(R.Entries[E.Index],Actual);
}
}
SealedEntry::SealedEntry(SealedEntry&& Other) noexcept : Value(std::exchange(Other.Value,0)),Index(Other.Index) {}
SealedEntry::~SealedEntry() { Release(); }
Result TrySealEntry(const SourceLifetime& Life,SealedEntry& Out) {
  if (Out || !Life.Validate()) return {PEAR_FEX_STALE_IDENTITY,0,0};
  const auto Actual=Registry::Capture(Life);
  if (!Actual.Context || !Actual.Thread || !Actual.Executor || !Actual.SourceSerial) return {PEAR_FEX_STALE_IDENTITY,0,0};
  auto& R=FEXCore::CPU::PearJITLinks::StateRegistry();
  { std::lock_guard L {R.Mutex};
    if (!R.First) return R.First;
    const auto E=R.Ledger.SealEntry(); if (!E) return {PEAR_FEX_UNAVAILABLE,0,0};
    R.Entries[E->Index]=Actual; Out.Index=static_cast<uint32_t>(E->Index); Out.Value=E->Value;
  }
  // No source/registry mutex is nested with actual lifetime validation.
  const auto Current=Life.Validate();
  if (!Current) { const auto Released=Out.Release(); (void)Released; return R.Poison(Current); }
  return Out.Validate(Life);
}
Result SealedEntry::Validate(const SourceLifetime& Life) const {
  const auto Current=Life.Validate(); if (!Current) return Current;
  const auto Actual=Registry::Capture(Life);
  auto& R=FEXCore::CPU::PearJITLinks::StateRegistry(); std::lock_guard L {R.Mutex};
  if (!R.First) return R.First;
  return {MatchesEntry(R,{Index,Value},Actual) && R.Ledger.EntryAdmissionOpen() ? PEAR_FEX_OK : PEAR_FEX_STALE_IDENTITY,0,0};
}
Result SealedEntry::Release() {
  if (!Value) return {PEAR_FEX_OK,0,0};
  auto& R=FEXCore::CPU::PearJITLinks::StateRegistry(); bool Okay {};
  Registry::EntryIdentity Captured;
  bool Matched {};
  { std::lock_guard L {R.Mutex};
    Matched=R.Ledger.MatchEntry({Index,Value});
    if (Matched) Captured=R.Entries[Index];
  }
  if (!Matched) return R.Poison({PEAR_FEX_STALE_IDENTITY,0,0});
  auto Life=AcquireCurrentSourceLifetime(Captured.Context);
  // An unresolved owner/source identity retains the seal and exact source
  // pointers; do not release it from an unrelated native thread or after ABA.
  if (!Life || !Registry::Same(Captured,Registry::Capture(Life))) return R.Poison({PEAR_FEX_STALE_IDENTITY,0,0});
  { std::lock_guard L {R.Mutex};
    Okay=MatchesEntry(R,{Index,Value},Captured) && R.Ledger.ReleaseEntry({Index,Value});
    if (Okay) { R.Entries[Index]={}; Value=0; }
  }
  R.Changed();
  return Okay ? Result{PEAR_FEX_OK,0,0} : R.Poison({PEAR_FEX_STALE_IDENTITY,0,0});
}
bool EntryResumeAdmitted(const SourceLifetime& Life) {
  if (!Life.Validate()) return false;
  const auto Actual=Registry::Capture(Life);
  auto& R=FEXCore::CPU::PearJITLinks::StateRegistry(); std::lock_guard L {R.Mutex};
  if (!R.First || !R.Ledger.EntryAdmissionOpen()) return false;
  for (size_t I=0;I<FEXCore::CPU::PearJITLinks::ENTRY_CAPACITY;++I) {
    if (R.Ledger.HasSealedEntries() && Registry::Same(R.Entries[I],Actual)) return true;
  }
  return false;
}
uint32_t EntrySequence() {
  return FEXCore::CPU::PearJITLinks::StateRegistry().EntryWord.load(std::memory_order_acquire);
}
Result WaitForEntryChange(uint32_t Expected,uint32_t Milliseconds) {
  return WaitSourceEntryChange(FEXCore::CPU::PearJITLinks::StateRegistry().EntryWord,Expected,Milliseconds);
}
bool EntryAdmissionOpen() { auto& R=FEXCore::CPU::PearJITLinks::StateRegistry(); std::lock_guard L {R.Mutex}; return R.Ledger.EntryAdmissionOpen(); }
Result FirstFailureSnapshot() { auto& R=FEXCore::CPU::PearJITLinks::StateRegistry(); std::lock_guard L {R.Mutex}; return R.First; }
bool HasOutstanding(const FEXCore::Context::Context* C) {
  auto& R=FEXCore::CPU::PearJITLinks::StateRegistry(); std::lock_guard L {R.Mutex};
  if (R.BatchContext==C) return true;
  for (const auto& E:R.Entries) if (E.Context==C) return true;
  for (const auto& S:R.Slots) if (S.Source && S.Source->SourceContext==C) return true;
  return false;
}
bool HasOutstanding(const FEXCore::Context::Context* C, const FEXCore::Core::InternalThreadState* T) {
  auto& R=FEXCore::CPU::PearJITLinks::StateRegistry(); std::lock_guard L {R.Mutex};
  if (R.BatchContext==C && R.BatchThread==T) return true;
  for (const auto& E:R.Entries) if (E.Context==C && E.Thread==T) return true;
  return false;
}
bool MutationAdmitted(const FEXCore::Context::Context* C) {
  auto& R=FEXCore::CPU::PearJITLinks::StateRegistry(); std::lock_guard L {R.Mutex};
  return R.BatchContext==C && R.BatchExecutor==CurrentExecutor() && R.Held && R.Held->Writer &&
    static_cast<bool>(*R.Held->Writer);
}
}
