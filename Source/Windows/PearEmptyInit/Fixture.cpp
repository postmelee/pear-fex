// SPDX-License-Identifier: MIT
// Original finite ordinary ARM64 source-init fixture. Its proof selection is
// closed by default; build flags and caller-supplied data cannot open it.
#include <FEXCore/Utils/AllocatorHooks.h>
#include "CheckedCRT.h"
#include "Interface/Context/Context.h"
#include "Interface/Core/Dispatcher/Dispatcher.h"
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/PearJITLinks.h"
#include <FEXCore/Debug/InternalThreadState.h>
#include "PearEmptyInitProof.h"
#include "Common/Allocator.h"
#include "Common/CPUFeatures.h"
#include "Common/DarwinConfigPolicy.h"
#include "Common/Priv.h"
#include "CommonTools/DummyHandlers.h"
#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Utils/PearFEXMemory.h>
#include <FEXCore/Utils/PearDataMemory.h>
#include <FEXCore/Utils/PearFEXRetirement.h>
#include <atomic>
#include <memory>
#include <cstddef>
#include <ntstatus.h>
#if !defined(_WIN32) || !defined(ARCHITECTURE_arm64) || defined(ARCHITECTURE_arm64ec) || !defined(PEAR_FEX_MEMORY_OWNER)
#error The finite source-init fixture requires the selected ordinary ARM64 owner target.
#endif
extern "C" uint32_t PearFiniteCheckpoint;
namespace FEX::Windows::PearEmptyInit {
namespace {
namespace Memory=FEXCore::Utils::PearFEXMemory;
struct State {
  CRTPlan Plan {};
  Report Observed {};
  fextl::unique_ptr<FEX::DummyHandlers::DummySignalDelegator> Signal;
  fextl::unique_ptr<FEXCore::HLE::SyscallHandler> Syscall;
  FEXCore::Context::PearContextOwner Context;
  FEXCore::Core::InternalThreadState* Thread {};
  bool ConfigInitialized {};
  bool ObjectStorageInitialized {};
};
static_assert(sizeof(State)<=8192,"One finite retained state; whole aggregate proof remains separate");
alignas(State) static std::byte Storage[sizeof(State)];
static std::atomic<uint32_t> Invoked {0};
static State* Retained {};
Outcome Good(Phase P) { return {Status::OK,P,Domain::None,0,0,0}; }
Outcome Refused(Phase P) { return {Status::Unavailable,P,Domain::None,0,0,0}; }
Outcome Source(Phase P,Memory::Result R) {
  if (R) return Refused(P);
  return {Status::SourceFailure,P,Domain::OwnerWire,R.ErrorCode,R.Status,R.ErrorDomain};
}
// These are observation-only records. An actual OK cleanup result is not an
// unavailable sentinel; attempts and both phases stay distinct even on refusal.
void ObserveConstructionCleanup(Report& R,Memory::Result Original) {
  R.ConstructionCleanupAttempted=1;
  R.ConstructionCleanup=Original ? Good(Phase::Cleanup) : Source(Phase::Cleanup,Original);
  R.Cleanup=R.ConstructionCleanup;
}
void ObserveFinalCleanup(Report& R,Outcome Actual) {
  R.FinalCleanup=Actual;
  // Keep the first actual failure, but a successful earlier cleanup must never
  // suppress a later failure. No status value alone implies an attempted call.
  if (!R.ConstructionCleanupAttempted || R.ConstructionCleanup) R.Cleanup=Actual;
}
// The exported caller can supply only an output record, never source object
// identities, permission flags, features, callback tables or proof decisions.
bool WritableReport(Report* Output) {
  if (!Output) return false;
  const auto Start=reinterpret_cast<uintptr_t>(Output);
  if (Start>UINTPTR_MAX-sizeof(*Output)) return false;
  MEMORY_BASIC_INFORMATION M {};SIZE_T Returned {};
  const auto S=NtQueryVirtualMemory(NtCurrentProcess(),Output,MemoryBasicInformation,&M,sizeof(M),&Returned);
  const auto B=reinterpret_cast<uintptr_t>(M.BaseAddress);
  return !S && Returned==sizeof(M) && M.State==MEM_COMMIT && M.Protect==PAGE_READWRITE &&
    M.RegionSize && B<=Start && B<=UINTPTR_MAX-M.RegionSize && Start+sizeof(*Output)<=B+M.RegionSize;
}
Outcome Cleanup(State& S) {
  auto& R=S.Observed;Memory::Result Original;
  if (S.Thread) {
    if (!S.Context->PreparePearThreadCleanup(S.Thread,Original)) return Source(Phase::Cleanup,Original);
    bool Destroyed {},Freed {};
    const auto Complete=S.Context->DestroyPearThreadChecked(S.Thread,Original,Destroyed,Freed);
    R.ThreadDestroyed=Destroyed;R.ThreadAllocatorCompleted=Freed;
    if (Destroyed) S.Thread=nullptr; // Never dereference destroyed backing again.
    if (!Complete || !Destroyed || !Freed) return Source(Phase::Cleanup,Original);
  }
  if (S.Context) {
    bool Destroyed {},Freed {};
    const auto Complete=FEXCore::Context::Context::DestroyPearContextChecked(S.Context,Original,Destroyed,Freed);
    R.ContextDestroyed=Destroyed;R.ContextAllocatorCompleted=Freed;
    if (!Complete || !Destroyed || !Freed) return Source(Phase::Cleanup,Original);
  }
  // An unresolved actual source allocation may not be finalized just because
  // its factory returned nullptr. Context preparation closes any failed Thread
  // quarantine before its checked deletion; admission/metadata proofs remain.
  if ((R.ContextCreated && !R.ContextAllocatorCompleted) || (R.ThreadCreated && !R.ThreadAllocatorCompleted)) return Refused(Phase::Cleanup);
  S.Syscall.reset();S.Signal.reset();
  if (S.ObjectStorageInitialized) {
    if (!FEXCore::Allocator::ShutdownPearEmptyObjectStorage()) return Refused(Phase::Cleanup);
    S.ObjectStorageInitialized=false;
  }
  if (S.ConfigInitialized) {
    if (!FEXCore::Config::ShutdownPearEmpty()) return Refused(Phase::Cleanup);
    S.ConfigInitialized=false;R.ConfigShutdown=1;
  }
  return FinalizeCheckedThread(S.Plan,R);
}
Outcome Construct(State& S) {
  auto& R=S.Observed;
  R.Primary=InitializeCheckedProcess(S.Plan,R);if (!R.Primary) return R.Primary;
  R.Primary=InitializeCheckedThread(S.Plan,R);if (!R.Primary) return R.Primary;
  if (!FEXCore::Config::InitializePearEmpty(S.ConfigInitialized)) return Refused(Phase::Context);
  // The real empty MetaLayer has already loaded no file/application/env layers.
  if (!FEX::Windows::DarwinPolicy::Apply()) return Refused(Phase::Context);
  FEXCore::Config::Set(FEXCore::Config::CONFIG_INTERPRETER_INSTALLED,"0");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE,"0");
  if (!FEXCore::Config::SealPearEmpty()) return Refused(Phase::Context);
  uint32_t Count {},PageSize {};
  R.Primary=ObserveHostBasics(Count,PageSize);if (!R.Primary) return R.Primary;
  FEX::Windows::Allocator::SetupHooks(S.Plan.NtDll);
  const auto Owner=Memory::Init(S.Plan.NtDll,S.Plan.NativeOwnerPID);
  if (!Owner) return Source(Phase::Owner,Owner);
  // Original helpers create actual dependencies. Their checked allocation and
  // constructor contracts are a separately closed proof before any invocation.
  Memory::Result Original;
  S.Signal=FEX::DummyHandlers::CreatePearSignalDelegator(Original);
  if (!S.Signal || !Original) return Source(Phase::Context,Original);
  S.Syscall=FEX::DummyHandlers::CreatePearSyscallHandler(Original);
  if (!S.Syscall || !Original) return Source(Phase::Context,Original);
  auto Features=FEX::Windows::CPUFeatures::FetchHostFeatures(true,FEXCore::HostFeatures::HostTypeEnum::Wow64,S.Plan.NativeOwnerPID);
  if (Features.HostCPUCount!=Count || Features.ProcessPID!=S.Plan.NativeOwnerPID || !Features.CPUMIDRs.empty()) return Refused(Phase::HostBasics);
  if (!FEXCore::Allocator::InitializePearEmptyObjectStorage()) return Refused(Phase::Context);
  S.ObjectStorageInitialized=true;
  R.ContextAttempted=1;
  S.Context=FEXCore::Context::Context::CreatePearContext(Features,Original);
  if (!S.Context || !Original) return Source(Phase::Context,Original);
  R.ContextCreated=1;
  S.Context->SetSignalDelegator(S.Signal.get());S.Context->SetSyscallHandler(S.Syscall.get());
  Original=Memory::BindBootstrapContext(S.Context.get());if (!Original) return Source(Phase::Context,Original);
  Original=Memory::RegisterExecutor(PEAR_FEX_ROLE_NATIVE);if (!Original) return Source(Phase::Owner,Original);
  R.CoreAttempted=1;
  if (!S.Context->InitPearCore(Original) || !Original) return Source(Phase::Context,Original);
  R.CoreCreated=1;R.ThreadAttempted=1;
  Memory::Result ThreadCleanup;bool ThreadCleanupAttempted {};
  S.Thread=S.Context->CreatePearThread(nullptr,Original,&ThreadCleanup,&ThreadCleanupAttempted);
  if (!S.Thread || !Original) {
    if (ThreadCleanupAttempted) ObserveConstructionCleanup(R,ThreadCleanup);
    return Source(Phase::Thread,Original);
  }
  R.ThreadCreated=1;
  // A separately selected finite ordinary ARM64 transfer uses the actual
  // source objects. The volatile local preserves its closed candidate body.
  volatile bool TransferSelected=Proof::FiniteTransfer;
  if (TransferSelected) {
    auto* Actual=static_cast<FEXCore::Context::ContextImpl*>(S.Context.get());
    // Exercise the actual empty reserved-target invalidation barrier before
    // any generated metadata page is populated. No guest mutation is performed.
    PearFiniteCheckpoint=48;
    auto Life=Memory::AcquireCurrentSourceLifetime(Actual);
    if (!Life) return Refused(Phase::Thread);
    const auto Begun=FEXCore::CPU::PearJITLinks::BeginBatch(Actual,S.Thread);
    if (!Begun) return Source(Phase::Thread,Begun);
    Memory::Links::SealedEntry Entry;
    const auto Closed=Memory::Links::TrySealEntry(Life,Entry);
    if (Closed || Closed.Status!=PEAR_FEX_UNAVAILABLE || Entry)
      return Source(Phase::Thread,{PEAR_FEX_STALE_IDENTITY,0,0});
    const auto Finished=FEXCore::CPU::PearJITLinks::FinishBatch(Actual,S.Thread);
    if (!Finished) return Source(Phase::Thread,Finished);
    const auto ReleasedBarrierLife=Life.Release();
    if (!ReleasedBarrierLife) return Source(Phase::Thread,ReleasedBarrierLife);
    PearFiniteCheckpoint=49;
    const auto Prepared=S.Thread->CPUBackend->PreparePearFiniteCode();
    if (!Prepared) return Source(Phase::Thread,Prepared);
    const auto Transfer=Actual->Dispatcher->ExecutePearFiniteTransfer(S.Thread->CurrentFrame);
    S.Thread->CurrentFrame->State.InlineJITBlockHeader=0;
    if (!Transfer) return Source(Phase::Thread,Transfer);
    // Terminal source closure is irreversible: test only after the last resume.
    // A genuine retained lifetime must block deletion without detaching backing.
    PearFiniteCheckpoint=32;
    auto Held=Memory::AcquireCurrentSourceLifetime(Actual);
    if (!Held) return Refused(Phase::Thread);
    auto* Backend=S.Thread->CPUBackend.get();
    auto* Lookup=S.Thread->LookupCache.get();
    Memory::Result Refusal;
    const bool Ready=Actual->PreparePearThreadCleanup(S.Thread,Refusal);
    if (Ready || Refusal.Status!=PEAR_FEX_UNAVAILABLE || Refusal.ErrorDomain || Refusal.ErrorCode ||
        S.Thread->CPUBackend.get()!=Backend || S.Thread->LookupCache.get()!=Lookup ||
        !Held.Validate(false) || Held.Validate(true) || Memory::AcquireCurrentSourceLifetime(Actual))
      return Source(Phase::Thread,{PEAR_FEX_STALE_IDENTITY,0,0});
    const auto Released=Held.Release();
    if (!Released) return Source(Phase::Thread,Released);
    PearFiniteCheckpoint=33;
    // The ordinary checked cleanup below must now drain and delete this tree.

  }
  // No CompileRIP, guest dispatch, delivered handler or guest invocation.
  return Good(Phase::Thread);
}
} // namespace
} // namespace FEX::Windows::PearEmptyInit
extern "C" uint32_t WINAPI PearEmptySourceInit(FEX::Windows::PearEmptyInit::Report* Output) {
  namespace E=FEX::Windows::PearEmptyInit;
  if (!E::WritableReport(Output)) return static_cast<uint32_t>(E::Status::Invalid);
  if (Output->Version!=1 || Output->Size!=sizeof(*Output)) return static_cast<uint32_t>(E::Status::Invalid);
  E::Report Refused;Refused.OutputOnly=1;
  if (!E::Proof::Ready()) { Refused.Primary=E::Refused(E::Phase::Proof);*Output=Refused;return static_cast<uint32_t>(Refused.Primary.State); }
  uint32_t Expected {};
  if (!E::Invoked.compare_exchange_strong(Expected,1)) {
    Refused.OneShotRefused=1;Refused.Primary=E::Refused(E::Phase::Proof);*Output=Refused;return static_cast<uint32_t>(Refused.Primary.State);
  }
  // Constant-initialized raw storage prevents automatic dependency destruction
  // after an uncertain cleanup. Exactly one source state persists in this DLL.
  auto* S=std::construct_at(reinterpret_cast<E::State*>(E::Storage));E::Retained=S;
  S->Observed.Primary=E::InspectBeforeInitialization(S->Plan,S->Observed);
  if (S->Observed.Primary) S->Observed.Primary=E::Construct(*S);
  if (S->Plan.ThreadReturned) {
    S->Observed.FinalCleanupAttempted=1;
    const auto Actual=E::Cleanup(*S);
    E::ObserveFinalCleanup(S->Observed,Actual);
  }
  *Output=S->Observed;
  return static_cast<uint32_t>(S->Observed.Primary ? S->Observed.Cleanup.State : S->Observed.Primary.State);
}
