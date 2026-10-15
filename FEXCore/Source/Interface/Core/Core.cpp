#include "PearSlotLifetime.h"
#include "PearAttachObservation.h"
#include "PearWriterObservation.h"
#include "PearTargetObservation.h"
#include "PearMismatchObservation.h"
#include "PearAbortObservation.h"

#include <cstdint>
#ifdef PEAR_PHASE_OBSERVE
extern "C" void PearThreadCreateFailed(uint32_t,uint64_t,uint64_t,uint64_t,uint32_t,uint32_t,int32_t);
extern "C" void PearThreadCreateAttachFailed(uint64_t,uint64_t,uint64_t,uint32_t,uint32_t,int32_t,const PearAttach::Diagnostic*);
#endif

#include <cstdint>
#ifdef PEAR_PHASE_OBSERVE
extern "C" bool PearPhaseSelected(uint64_t);
#endif
// SPDX-License-Identifier: MIT
/*
$info$
category: glue ~ Logic that binds various parts together
meta: glue|driver ~ Emulation mainloop related glue logic
tags: glue|driver
desc: Glues Frontend, OpDispatcher and IR Opts & Compilation, LookupCache, Dispatcher and provides the Execution loop entrypoint
$end_info$
*/

#include <FEXCore/Utils/PearSourceGuard.h>
#include <cstdint>
#ifdef ZYDIS_DISASSEMBLER
#include <Zydis/Zydis.h>
#endif
#include "Interface/Core/ArchHelpers/Arm64Emitter.h"
#include "Interface/Core/LookupCache.h"
#ifdef PEAR_FEX_MEMORY_OWNER
#include "Interface/Core/PearJITLinks.h"
#endif
#ifdef PEAR_FEX_MEMORY_OWNER
#include <ranges>
#include "Interface/Core/PearJITMetadata.h"
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#endif
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/CPUID.h"
#include "Interface/Core/Frontend.h"
#include "Interface/Core/OpcodeDispatcher.h"
#include "Interface/Core/JIT/JITClass.h"
#include "Interface/Core/Dispatcher/Dispatcher.h"
#include "Interface/Core/X86Tables/X86Tables.h"
#include <Interface/GDBJIT/GDBJIT.h>
#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"
#include "Interface/IR/Passes.h"
#include "Interface/IR/PassManager.h"
#include "Interface/IR/RegisterAllocationData.h"
#include "Utils/Allocator.h"
#include "Utils/Allocator/HostAllocator.h"
#include "Utils/crc32.h"
#include <FEXCore/Utils/SpinWaitLock.h>
#include "Utils/variable_length_integer.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/Thunks.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/HLE/SourcecodeResolver.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/Event.h>
#include <FEXCore/Utils/File.h>
#include <FEXCore/Utils/LogManager.h>
#include "FEXCore/Utils/SignalScopeGuards.h"
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/SHMStats.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/sstream.h>
#include <FEXCore/fextl/vector.h>
#include <FEXHeaderUtils/Syscalls.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#ifdef PEAR_FEX_MEMORY_OWNER
#include <FEXCore/Utils/PearDataMemory.h>
#endif
#include <functional>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <signal.h>
#include <stdio.h>
#include <string_view>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <xxhash.h>

namespace FEXCore::Context {
#ifdef PEAR_FEX_MEMORY_OWNER
FEXCore::Utils::PearFEXMemory::Result Context::EnterPearEC(Core::InternalThreadState* Thread, bool FillState) {
  return EnterPearEC(Thread, FillState, nullptr);
}
FEXCore::Utils::PearFEXMemory::Result Context::EnterPearEC(Core::InternalThreadState* Thread, bool FillState,
    FEXCore::Utils::PearFEXMemory::EntryDiagnostic* Diagnostic) {
  namespace M = FEXCore::Utils::PearFEXMemory;
  auto Life = M::AcquireCurrentSourceLifetime(this);
  if (!Life || !Thread || Life.ActualThread() != Thread || Thread->CTX != this || !Thread->CurrentFrame ||
      Thread->CurrentFrame->Thread != Thread) return M::EntryFailure(Diagnostic, 2, {PEAR_FEX_STALE_IDENTITY, 0, 0});
  M::SourceMutationTurn EntryTurn {Life,false,Diagnostic};
  if (!EntryTurn) return EntryTurn.Status();
  auto* Impl = static_cast<ContextImpl*>(this);
  if (!Impl->Dispatcher) return M::EntryFailure(Diagnostic, 3, {PEAR_FEX_UNAVAILABLE, 0, 0});
  const auto Facts = Impl->Dispatcher->GetPearSnapshot();
  const auto Base = reinterpret_cast<uintptr_t>(Facts.Base);
  const auto& Pointers = Thread->CurrentFrame->Pointers;
  const auto Entry = FillState ? Pointers.DispatcherLoopTopEnterECFillSRA : Pointers.DispatcherLoopTopEnterEC;
  if (!Facts || Facts.Token.allocation_class != PEAR_FEX_CLASS_DISPATCHER ||
      Facts.Token.ec_role != PEAR_FEX_ROLE_ARM64EC || Facts.Token.expected_state != PEAR_FEX_PUBLISHED_RX ||
      !Base || Entry < Base || (Entry & 3) || Entry - Base > Facts.Token.extent_size ||
      4 > Facts.Token.extent_size - (Entry - Base)) return M::EntryFailure(Diagnostic, 4, {PEAR_FEX_UNAVAILABLE, 0, 0});
  // The owner waits for every managed executor before ANY write/retirement.
  // Retain D as the global execution lease while upstream branches to shared
  // code; compiler/linker native gates already hand off/resume this exact D.
  return M::Enter(Facts, Entry - Base, 0, Diagnostic);
}
FEXCore::Utils::PearFEXMemory::Result Context::ExitPearEC(Core::InternalThreadState* Thread, bool Required) {
  namespace M = FEXCore::Utils::PearFEXMemory;
  auto Life = M::AcquireCurrentSourceLifetime(this);
  if (!Life || !Thread || Life.ActualThread() != Thread || Thread->CTX != this)
    return {PEAR_FEX_STALE_IDENTITY, 0, 0};
  Life.ObserveWakeCheckpoint(3);
  const auto Finish=[&](M::Result R) { Life.ObserveWakeCheckpoint(4,R); return R; };
  auto* Impl = static_cast<ContextImpl*>(this);
  if (!Impl->Dispatcher) return Finish({PEAR_FEX_UNAVAILABLE, 0, 0});
  const auto Facts = Impl->Dispatcher->GetPearSnapshot();
  const bool Active = M::HasManagedActive(Facts);
  // check_target_ec also reaches ExitFunctionEC without entering generated
  // code. It must neither fabricate nor consume an execution lease.
  if (!Required) return Finish({Active ? PEAR_FEX_STALE_IDENTITY : PEAR_FEX_OK, 0, 0});
  if (!Active) return Finish({PEAR_FEX_UNAVAILABLE, 0, 0});
  return Finish(M::Exit(Facts));
}
FEXCore::Utils::PearFEXMemory::Result Context::ObservePearInstruction(Core::InternalThreadState* Thread, uintptr_t PC, uint32_t& Word) {
  namespace M=FEXCore::Utils::PearFEXMemory;
  auto Life=M::AcquireCurrentSourceLifetime(this);
  auto* Impl=static_cast<ContextImpl*>(this);
  if (!Life || Life.ActualThread()!=Thread || !Thread || !Thread->CPUBackend || !Impl->Dispatcher || (PC&3))
    return {PEAR_FEX_STALE_IDENTITY,0,0};
  const auto D=Impl->Dispatcher->GetPearSnapshot();
  if (!M::HasManagedActive(D)) return {PEAR_FEX_UNAVAILABLE,0,0};
  std::span<uint8_t> Bytes {reinterpret_cast<uint8_t*>(&Word),sizeof(Word)};
  const auto Base=reinterpret_cast<uintptr_t>(D.Base);
  if (Base && PC>=Base && PC-Base<D.Token.extent_size && sizeof(Word)<=D.Token.extent_size-(PC-Base))
    return M::CopyManagedRX(D,Thread,PC-Base,Bytes).Outcome;
  const auto W=Thread->CPUBackend->FindPearManagedWindow(PC);
  const auto T=Thread->CPUBackend->FindPearRetainedTarget(PC);
  if (!W || !T) return {PEAR_FEX_STALE_IDENTITY,0,0};
  return M::CopyManagedRXUnderGlobalLease(D,*T,Thread,W->Offset,Bytes).Outcome;
}

extern "C" void PearRepairObservation(uint32_t, uint64_t, uint64_t, uint64_t, uint64_t);
// A cooperative native-gate wait may admit another qualified writer. Retain
// allocation identity, published state and monotonic epochs; actual instruction
// bytes are still compared under the new WriteGuard before any store.
static bool PearRepairSnapshotCompatible(const FEXCore::Utils::PearFEXMemory::Allocation& X,
                                         const FEXCore::Utils::PearFEXMemory::Allocation& Y) {
  return X.Base==Y.Base && X.Token.owner_pid==Y.Token.owner_pid &&
    X.Token.allocation_id==Y.Token.allocation_id && X.Token.generation==Y.Token.generation &&
    X.Token.extent_offset==Y.Token.extent_offset && X.Token.extent_size==Y.Token.extent_size &&
    X.Token.allocation_class==Y.Token.allocation_class && X.Token.ec_role==Y.Token.ec_role &&
    X.Token.expected_state==Y.Token.expected_state && X.Token.write_epoch &&
    Y.Token.write_epoch>=X.Token.write_epoch;
}

// Called from the compiled Windows exception reset path, never a raw Darwin
// signal callback. Retain actual source objects across the native mutation turn.
FEXCore::Utils::PearFEXMemory::Result Context::RepairPearUnaligned(
    Core::InternalThreadState* Thread, uintptr_t PC, bool& Handled, int32_t& ResumeDelta) {
  namespace M=FEXCore::Utils::PearFEXMemory;
  namespace A=FEXCore::ArchHelpers::Arm64;
  Handled=false;ResumeDelta=0;
  auto Life=M::AcquireCurrentSourceLifetime(this);
  auto* Impl=static_cast<ContextImpl*>(this);
  if (!Life || !Thread || Life.ActualThread()!=Thread || Thread->CTX!=this ||
      !Thread->CPUBackend || !Impl->Dispatcher || (PC&3) || PC<4)
    return {PEAR_FEX_STALE_IDENTITY,0,0};
  const auto D=Impl->Dispatcher->GetPearSnapshot();
  if (!M::HasManagedActive(D)) return {PEAR_FEX_UNAVAILABLE,0,0};
  auto Window=Thread->CPUBackend->FindPearManagedWindow(PC-4);
  auto Target=Thread->CPUBackend->FindPearRetainedTarget(PC-4);
  if (!Window || !Target) return {PEAR_FEX_STALE_IDENTITY,0,0};
  const auto Captured=Window->Owner->GetPearSnapshot();
  std::array<uint32_t,13> Words {};
  auto Bytes=std::span<uint8_t>{reinterpret_cast<uint8_t*>(Words.data()),sizeof(Words)};
  PearReadIdentity ReadIdentity {};
  M::ManagedReadResult Read {};
  {
    PearReadIdentityScope ObserveRead{PearAbortEnabled(),&ReadIdentity,Thread,Bytes.data(),Window->Offset,Bytes.size()};
    Read=M::CopyManagedRXUnderGlobalLease(D,*Target,Thread,Window->Offset,Bytes);
  }
  if (!Read) return Read.Outcome;
  const auto Prepared=A::PrepareUnalignedPatchSnapshot(A::UnalignedHandlerType::HalfBarrier,Words);
  if (Prepared.Kind!=A::UnalignedPatchKind::Candidate && Prepared.Kind!=A::UnalignedPatchKind::AlreadyPatched)
    return {PEAR_FEX_OK,0,0}; // Preserve the actual guest exception for unsupported families.
  if (Prepared.ResumeDelta!=0 && Prepared.ResumeDelta!=-4) return {PEAR_FEX_INVALID_REQUEST,0,0};
  if (Prepared.Kind==A::UnalignedPatchKind::AlreadyPatched) {
    Handled=true;ResumeDelta=Prepared.ResumeDelta;return {PEAR_FEX_OK,0,0};
  }
  // Upstream reserves a barrier slot beside scalar TSO accesses. Do not patch
  // an arbitrary neighbouring instruction even if the access opcode matches.
  for (uint32_t I=0;I<Prepared.StoreCount;++I) {
    const auto Index=Prepared.StoreOrder[I];
    if (Index>2 || (Index!=1 && Words[Index]!=0xd503201f && Words[Index]!=Prepared.Next[Index]))
      return {PEAR_FEX_INVALID_REQUEST,0,0};
  }
  // No generated instruction runs while idle. The exact source CodeBuffer,
  // Context and Thread remain held; the original native register context is
  // untouched. Revalidate identity/epoch and exact bytes after the wait.
  auto Outcome=ExitPearEC(Thread,true);if (!Outcome) return Outcome;
  M::SourceMutationTurn Turn{Life,true};if (!Turn) return Turn.Status();
  auto Transaction=Window->Owner->GetPearSnapshot();
  const auto CurrentDispatcher=Impl->Dispatcher->GetPearSnapshot();
  const auto Observe=[&](uint32_t Reason) {
    PearRepairObservation(Reason,Captured.Token.write_epoch,Transaction.Token.write_epoch,
                          D.Token.write_epoch,CurrentDispatcher.Token.write_epoch);
  };
  if (!PearRepairSnapshotCompatible(Captured,Transaction) || !PearRepairSnapshotCompatible(D,CurrentDispatcher)) {
    Observe(2);
    return M::Retirement::PoisonSourceAdmission({PEAR_FEX_STALE_IDENTITY,0,0});
  }
  const bool Advanced=Captured.Token.write_epoch!=Transaction.Token.write_epoch || D.Token.write_epoch!=CurrentDispatcher.Token.write_epoch;
  const auto Before=Transaction;
  {
    M::WriteGuard Write{Transaction,Window->Offset,sizeof(Words)};
    if (!Write) return Write.Status();
    const bool OriginalMatches=Write.Matches(0,{reinterpret_cast<const uint8_t*>(Words.data()),sizeof(Words)});
    bool AlreadyRepaired=false;
    if (!OriginalMatches && Before.Token.write_epoch>Captured.Token.write_epoch &&
        Write.Matches(0,{reinterpret_cast<const uint8_t*>(Prepared.Next.data()),sizeof(Prepared.Next)})) {
      // Another retained source thread may have completed this exact repair
      // while this thread left ACTIVE and waited for the mutation turn.
      // The existing successful guard and identity checks remain authoritative.
      std::array<uint32_t,13> CurrentWords {};
      memcpy(CurrentWords.data(),Write.Data(),sizeof(CurrentWords));
      const auto Again=A::PrepareUnalignedPatchSnapshot(A::UnalignedHandlerType::HalfBarrier,CurrentWords);
      AlreadyRepaired=CurrentWords==Prepared.Next && Again.Kind==A::UnalignedPatchKind::AlreadyPatched &&
        Again.Next==CurrentWords && Again.ResumeDelta==Prepared.ResumeDelta;
    }
    if (!OriginalMatches && !AlreadyRepaired) {
      Observe(3);
      const bool AbortObserved=PearAbortEnabled();
      const auto AbortBegin=Transaction.Token;
      PearAbortRecord d {};
      if (AbortObserved) {
        d.guard=reinterpret_cast<uintptr_t>(&Write); d.life=Life.Identity();
        d.allocation=AbortBegin.allocation_id; d.generation=AbortBegin.generation;
        d.extent=AbortBegin.extent_offset; d.size=AbortBegin.extent_size;
        d.aclass=AbortBegin.allocation_class; d.role=AbortBegin.ec_role;
        d.continuation=0; // This exact constructor uses its original default zero.
        d.epoch=AbortBegin.write_epoch; d.expected=AbortBegin.expected_state;
        d.begin_state=AbortBegin.expected_state;
        d.before_epoch=Before.Token.write_epoch; d.before_state=Before.Token.expected_state;
        d.call=PearAbortBegin(&d);
        // Copy while the existing successful guard is still open, before Abort.
        // This later copy does not claim atomicity with the failed memcmp.
        if (d.call==1) {
          PearMismatchRecord m {}; m.abort=d;
          m.pc=PC; m.offset=Window->Offset;
          m.window_owner=reinterpret_cast<uintptr_t>(Window->Owner.get());
          m.window_base=Window->Begin; m.window_size=Window->Size;
          m.data=reinterpret_cast<uintptr_t>(Write.Data());
          m.captured_epoch=Captured.Token.write_epoch;
          m.kind=static_cast<unsigned>(Prepared.Kind); m.count=Prepared.StoreCount;
          m.store0=Prepared.StoreOrder[0]; m.store1=Prepared.StoreOrder[1];
          m.delta=Prepared.ResumeDelta;
          memcpy(m.original,Words.data(),sizeof(m.original));
          memcpy(m.actual,Write.Data(),sizeof(m.actual));
          memcpy(m.next,Prepared.Next.data(),sizeof(m.next));
          PearMismatchEmit(&m);
          PearTargetRecord t {};t.abort=d;t.read=ReadIdentity;
          t.write_owner=reinterpret_cast<uintptr_t>(Window->Owner.get());
          t.write_state=reinterpret_cast<uintptr_t>(&Window->Owner->GetPearTokenState());
          t.write_base=Window->Begin;t.write_offset=Window->Offset;t.write_bytes=sizeof(Words);
          PearTargetEmit(&t);
          PearWriterBatch batch{};
          PearWriterSnapshot(Thread,Life.Identity(),&batch);
          PearWriterEmit(&t,&batch);
        }
      }
      const auto Aborted=Write.Abort();
      if (AbortObserved) {
        d.status=Aborted.Status; d.domain=Aborted.ErrorDomain; d.code=Aborted.ErrorCode;
        PearAbortEmit(1,&d);
      }
      Window->Owner->ComparePearUpdate(Before,Transaction);
      return M::Retirement::PoisonSourceAdmission(Aborted ? M::Result{PEAR_FEX_STALE_IDENTITY,0,0} : Aborted);
    }
    if (Advanced) Observe(1);
    PearWriterRecord writer{};
    writer.owner=reinterpret_cast<uintptr_t>(Window->Owner.get());
    writer.state=reinterpret_cast<uintptr_t>(&Window->Owner->GetPearTokenState());
    writer.allocation=Before.Token.allocation_id;writer.generation=Before.Token.generation;
    writer.extent=Before.Token.extent_offset;writer.size=Before.Token.extent_size;
    writer.base=Window->Begin;writer.aclass=Before.Token.allocation_class;writer.role=Before.Token.ec_role;
    writer.offset=Window->Offset;writer.bytes=sizeof(Words);
    writer.before_epoch=Before.Token.write_epoch;writer.write_epoch=Transaction.Token.write_epoch;
    writer.original0=Words[0];writer.original1=Words[1];writer.original2=Words[2];
    writer.next0=Prepared.Next[0];writer.next1=Prepared.Next[1];writer.next2=Prepared.Next[2];
    for(uint32_t i=0;!AlreadyRepaired && i<Prepared.StoreCount;++i){
      const auto index=Prepared.StoreOrder[i];writer.store_mask|=uint64_t{1}<<index;
      if(Words[index]!=Prepared.Next[index])writer.changed_mask|=uint64_t{1}<<index;
    }
    // Arm before the first store. Every exit, including failed Publish/Abort, terminates or loses this attempt.
    PearWriterScope ObserveWriter{PearAbortEnabled() && !AlreadyRepaired,&writer,Thread,Life.Identity()};
    if (!AlreadyRepaired) {
      for (uint32_t I=0;I<Prepared.StoreCount;++I) {
        const auto Index=Prepared.StoreOrder[I];
        std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(Write.Data()+4*Index)).store(Prepared.Next[Index],std::memory_order_release);
      }
      ObserveWriter.stored=true;
    }
    // Even with zero stores, close this write turn through normal publication,
    // source-token update and managed re-entry/readback below. Never Abort or
    // return success while the target remains writable and non-executable.
    Outcome=Write.Publish();
    ObserveWriter.status=Outcome.Status;ObserveWriter.domain=Outcome.ErrorDomain;ObserveWriter.code=Outcome.ErrorCode;
    ObserveWriter.published=static_cast<bool>(Outcome);
    if (!Outcome) {
      const auto Aborted=Write.Abort();
      if (!Window->Owner->ComparePearUpdate(Before,Transaction) || !Aborted)
        M::Retirement::PoisonSourceAdmission(!Aborted ? Aborted : M::Result{PEAR_FEX_STALE_IDENTITY,0,0});
      return Outcome;
    }
    if (!Window->Owner->ComparePearUpdate(Before,Transaction))
      return M::Retirement::PoisonSourceAdmission({PEAR_FEX_STALE_IDENTITY,0,0});
    ObserveWriter.updated=true;
  }
  // The same mutation turn spans exit, publish and re-entry, so neither another
  // writer nor source invalidation can change this retained target between them.
  // There is no pending native pin to discard or replace with a fresh ENTRY.
  Outcome=EnterPearEC(Thread,false);if (!Outcome) return Outcome;
  auto Fresh=Thread->CPUBackend->FindPearRetainedTarget(PC-4);
  if (!Fresh) return M::Retirement::PoisonSourceAdmission({PEAR_FEX_STALE_IDENTITY,0,0});
  Read=M::CopyManagedRXUnderGlobalLease(Impl->Dispatcher->GetPearSnapshot(),*Fresh,Thread,Window->Offset,Bytes);
  if (!Read || Words!=Prepared.Next) {
    const auto Failure=Read ? M::Result{PEAR_FEX_STALE_IDENTITY,0,0} : Read.Outcome;
    const auto Exited=ExitPearEC(Thread,true);(void)Exited;
    return M::Retirement::PoisonSourceAdmission(Failure);
  }
  Handled=true;ResumeDelta=Prepared.ResumeDelta;
  return {PEAR_FEX_OK,0,0};
}

#endif

ContextImpl::ContextImpl(const FEXCore::HostFeatures& Features)
  : HostFeatures {Features}
  , CPUID {this}
  , CodeCache {*this} {
  if (!Config.Is64BitMode()) {
    // When operating in 32-bit mode, the virtual memory we care about is only the lower 32-bits.
    Config.VirtualMemSize = 1ULL << 32;
  }

  if (Config.BlockJITNaming() || Config.GlobalJITNaming() || Config.LibraryJITNaming()) {
    // Only initialize symbols file if enabled. Ensures we don't pollute /tmp with empty files.
    Symbols.InitFile(Features.ProcessPID);
  }

  uint64_t FrequencyCounter = FEXCore::GetCycleCounterFrequency();
  if (FrequencyCounter && FrequencyCounter < FEXCore::Context::TSC_SCALE_MAXIMUM && Config.SmallTSCScale()) {
    // Scale TSC until it is at the minimum required.
    while (FrequencyCounter < FEXCore::Context::TSC_SCALE_MAXIMUM) {
      FrequencyCounter <<= 1;
      ++Config.TSCScale;
    }
  }

  // Track atomic TSO emulation configuration.
  UpdateAtomicTSOEmulationConfig();

#ifndef _WIN32
  // Check if the kernel supports getrandom().
  uint64_t Probe {};
  HostRNGAvailable = FHU::Syscalls::getrandom(&Probe, sizeof(Probe), 0) == sizeof(Probe);
#else
  HostRNGAvailable = true;
#endif

  DiskCache.Init(this);
#ifdef PEAR_FEX_MEMORY_OWNER
  PearLifetimeCreation=FEXCore::Utils::PearFEXMemory::SourceLifecycle::Allocated(this);
#endif
}

#ifdef PEAR_FEX_MEMORY_OWNER
static FEXCore::Utils::PearFEXMemory::SourceLifetime RequirePearSourceThread(
    const ContextImpl* Context,const FEXCore::Core::InternalThreadState* Expected) {
  namespace Memory=FEXCore::Utils::PearFEXMemory;
  auto Life=Memory::AcquireCurrentSourceLifetime(Context);
  const bool Good=Life && Life.ActualThread()==Expected && Life.Validate();
  if (!Good) {
    auto Original=Memory::Result{PEAR_FEX_STALE_IDENTITY,0,0};
    const auto First=Memory::Retirement::FirstFailureSnapshot();
    if (First.Present) Original=First.Outcome;
    Memory::Retirement::PoisonSourceAdmission(Original);
    PEAR_FEX_REQUIRE_RESULT(false, "Pear source lifetime refused: status {}, domain {}, code {}", Original);
  }
  return Life;
}
struct PearFrameBlockSnapshot {
  FEXCore::Utils::PearFEXMemory::SourceLifetime Lifetime;
  FEXCore::Utils::PearFEXMemory::Allocation Protection;
  // Numeric arithmetic only. The opaque retained target below is the one
  // actual source lifetime/TokenState reference; this range grants no lease.
  struct NumericRange { uintptr_t Begin {}; size_t Size {}; size_t Offset {}; } Window;
  std::optional<FEXCore::Utils::PearFEXMemory::RetainedManagedTarget> Target;
  CPU::CPUBackend::JITCodeHeader Header {};
  CPU::CPUBackend::JITCodeTail Tail {};
  FEXCore::Core::InternalThreadState* Thread {};
  uintptr_t BlockBegin {};
};
static_assert(sizeof(PearFrameBlockSnapshot) <= 512, "Bounded private header/tail and retained source references");
static FEXCore::Utils::PearFEXMemory::Result GetPearFrameBlockInfo(
    ContextImpl* Context, FEXCore::Core::InternalThreadState* ExpectedThread, PearFrameBlockSnapshot& Out) {
  namespace Memory = FEXCore::Utils::PearFEXMemory;
  Out.Lifetime=Memory::AcquireCurrentSourceLifetime(Context);
  auto* Thread=Out.Lifetime ? Out.Lifetime.ActualThread() : nullptr;
  if (!Thread || Thread!=ExpectedThread) return {PEAR_FEX_STALE_IDENTITY,0,0};
  auto* Frame=Thread->CurrentFrame;
  if (!Thread || !Context || !Frame || Frame->Thread!=Thread || Frame != Thread->CurrentFrame || !Thread->CPUBackend || !Context->Dispatcher)
    return {PEAR_FEX_UNAVAILABLE, 0, 0};
  Out.Thread = Thread; Out.BlockBegin = Frame->State.InlineJITBlockHeader;
  if (!Out.BlockBegin) return {PEAR_FEX_UNAVAILABLE, 0, 0};
  Out.Protection = Context->Dispatcher->GetPearSnapshot();
  if (!Memory::HasManagedActive(Out.Protection)) return {PEAR_FEX_UNAVAILABLE, 0, 0};
  {
    auto Window = Thread->CPUBackend->FindPearManagedWindow(Out.BlockBegin);
    Out.Target = Thread->CPUBackend->FindPearRetainedTarget(Out.BlockBegin);
    if (!Window || !Out.Target || Window->Offset > Window->Size || sizeof(Out.Header) > Window->Size-Window->Offset)
      return {PEAR_FEX_UNAVAILABLE, 0, 0};
    Out.Window = {Window->Begin, Window->Size, Window->Offset};
    // Release the duplicate metadata/reference before any source-page copy.
    // Out.Target still retains the exact actual CodeBuffer and TokenState.
  }
  auto Read = Memory::CopyManagedRXUnderGlobalLease(Out.Protection, *Out.Target, Thread, Out.Window.Offset,
    {reinterpret_cast<uint8_t*>(&Out.Header), sizeof(Out.Header)});
  if (!Read) return Read.Outcome;
  if (!CPU::PearJITMetadata::HeaderRange(Out.Header, Out.Window.Size-Out.Window.Offset))
    return {PEAR_FEX_INVALID_REQUEST, 0, 0};
  std::array<uint8_t, sizeof(Out.Tail)> TailBytes {};
  Read = Memory::CopyManagedRXUnderGlobalLease(Out.Protection, *Out.Target, Thread,
    Out.Window.Offset+Out.Header.OffsetToBlockTail, TailBytes);
  if (!Read) return Read.Outcome;
  if (TailBytes[offsetof(CPU::CPUBackend::JITCodeTail, SingleInst)] > 1) return {PEAR_FEX_INVALID_REQUEST, 0, 0};
  std::memcpy(&Out.Tail, TailBytes.data(), TailBytes.size());
  if (!CPU::PearJITMetadata::TailRange(Out.Header, Out.Tail, Out.Window.Size-Out.Window.Offset) ||
      Frame->Thread != Thread || Frame != Thread->CurrentFrame || Frame->State.InlineJITBlockHeader != Out.BlockBegin ||
      !Memory::HasManagedActive(Out.Protection)) return {PEAR_FEX_STALE_IDENTITY, 0, 0};
  return {PEAR_FEX_OK, 0, 0};
}
static void RequirePearFrameSnapshot(FEXCore::Utils::PearFEXMemory::Result Outcome) {
  if (!Outcome) FEXCore::Utils::PearFEXMemory::Retirement::PoisonSourceAdmission(Outcome);
  PEAR_FEX_REQUIRE_RESULT(!!Outcome, "Pear managed metadata snapshot refused: status {}, domain {}, code {}", Outcome);
}
bool ContextImpl::IsAddressInCurrentBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint64_t Size) {
  PearFrameBlockSnapshot Snapshot;
  RequirePearFrameSnapshot(GetPearFrameBlockInfo(this, Thread, Snapshot));
  return Size <= UINT64_MAX-Address && Address+Size > Snapshot.Tail.RIP &&
    Address < Snapshot.Tail.RIP+Snapshot.Tail.GuestSize;
}
bool ContextImpl::IsCurrentBlockSingleInst(FEXCore::Core::InternalThreadState* Thread) {
  PearFrameBlockSnapshot Snapshot;
  RequirePearFrameSnapshot(GetPearFrameBlockInfo(this, Thread, Snapshot));
  return Snapshot.Tail.SingleInst;
}
uint64_t ContextImpl::GetGuestBlockEntry(FEXCore::Core::InternalThreadState* Thread) {
  PearFrameBlockSnapshot Snapshot;
  RequirePearFrameSnapshot(GetPearFrameBlockInfo(this, Thread, Snapshot));
  return Snapshot.Tail.RIP;
}
uint64_t ContextImpl::RestoreRIPFromHostPC(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC) {
  namespace Memory = FEXCore::Utils::PearFEXMemory;
  PearFrameBlockSnapshot Snapshot;
  RequirePearFrameSnapshot(GetPearFrameBlockInfo(this, Thread, Snapshot));
  if (HostPC < Snapshot.BlockBegin || HostPC-Snapshot.BlockBegin >= Snapshot.Tail.Size)
    return Thread->CurrentFrame->State.rip;
  const auto EndHost = Snapshot.BlockBegin+Snapshot.Tail.Size;
  // Upstream reconstruction permits signed jumps between multiblock guest
  // entries. Their RIP range need not be the tail's coarse GuestSize interval.
  const uint64_t EndGuest = Config.Is64BitMode ? UINT64_MAX : UINT32_MAX;
  size_t Cursor = Snapshot.Header.OffsetToBlockTail+Snapshot.Tail.OffsetToRIPEntries;
  uint64_t CurrentHost = Snapshot.BlockBegin, CurrentGuest = Snapshot.Tail.RIP;
  // Private NX bytes remain local to this reconstruction and its existing
  // global execution lease. Every refill uses the original admitted copy.
  std::array<uint8_t, 4096> MetadataWindow {};
  static_assert(CPU::PearJITMetadata::MAX_PAIR_BYTES <= MetadataWindow.size());
  size_t WindowBegin {}, WindowBytes {};
  auto ReadPairBytes = [&](size_t Size) -> std::span<const uint8_t> {
    if (Cursor < WindowBegin || Cursor-WindowBegin > WindowBytes || Size > WindowBytes-(Cursor-WindowBegin)) {
      WindowBegin = Cursor;
      WindowBytes = std::min(MetadataWindow.size(), Snapshot.Tail.Size-Cursor);
      const auto Read = Memory::CopyManagedRXUnderGlobalLease(Snapshot.Protection, *Snapshot.Target, Thread,
        Snapshot.Window.Offset+Cursor, {MetadataWindow.data(), WindowBytes});
      RequirePearFrameSnapshot(Read.Outcome);
    }
    return {MetadataWindow.data()+(Cursor-WindowBegin), Size};
  };
  for (uint32_t I = 0; I < Snapshot.Tail.NumberOfRIPEntries; ++I) {
    if (Cursor >= Snapshot.Tail.Size) { RequirePearFrameSnapshot({PEAR_FEX_INVALID_REQUEST, 0, 0}); break; }
    const auto Size = CPU::PearJITMetadata::PairSize(ReadPairBytes(1).front());
    if (!Size || Size > Snapshot.Tail.Size-Cursor) { RequirePearFrameSnapshot({PEAR_FEX_INVALID_REQUEST, 0, 0}); break; }
    const auto Pair = CPU::PearJITMetadata::DecodePair(ReadPairBytes(Size));
    uint64_t NextHost {}, NextGuest {};
    if (!Pair || !CPU::PearJITMetadata::Advance(CurrentHost, Pair->IntegerARMPC, Snapshot.BlockBegin, EndHost, NextHost) ||
        !CPU::PearJITMetadata::Advance(CurrentGuest, Pair->IntegerX86RIP, 0, EndGuest, NextGuest)) {
      RequirePearFrameSnapshot({PEAR_FEX_INVALID_REQUEST, 0, 0}); break;
    }
    Cursor += Size;
    if (HostPC < NextHost) break;
    CurrentHost = NextHost; CurrentGuest = NextGuest;
  }
  if (Thread->CurrentFrame->State.InlineJITBlockHeader != Snapshot.BlockBegin || !Memory::HasManagedActive(Snapshot.Protection))
    RequirePearFrameSnapshot({PEAR_FEX_STALE_IDENTITY, 0, 0});
  return CurrentGuest;
}
#else
struct GetFrameBlockInfoResult {
  const CPU::CPUBackend::JITCodeHeader* InlineHeader;
  const CPU::CPUBackend::JITCodeTail* InlineTail;
};
static GetFrameBlockInfoResult GetFrameBlockInfo(FEXCore::Core::CpuStateFrame* Frame) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Source exception/callback gates capture bounded header/tail facts before
  // handoff. The generic raw reader cannot assert a still-active owner lease.
  LOGMAN_THROW_A_FMT(false, "Pear raw managed header/tail read is unavailable without a source lease descriptor");
  return {nullptr, nullptr};
#endif
  const uint64_t BlockBegin = Frame->State.InlineJITBlockHeader;
  auto InlineHeader = reinterpret_cast<const CPU::CPUBackend::JITCodeHeader*>(BlockBegin);

  if (InlineHeader) {
    auto InlineTail = reinterpret_cast<const CPU::CPUBackend::JITCodeTail*>(Frame->State.InlineJITBlockHeader + InlineHeader->OffsetToBlockTail);
    return {InlineHeader, InlineTail};
  }

  return {InlineHeader, nullptr};
}

bool ContextImpl::IsAddressInCurrentBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint64_t Size) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail && (Address + Size > InlineTail->RIP && Address < InlineTail->RIP + InlineTail->GuestSize);
}

bool ContextImpl::IsCurrentBlockSingleInst(FEXCore::Core::InternalThreadState* Thread) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail && InlineTail->SingleInst;
}

uint64_t ContextImpl::GetGuestBlockEntry(FEXCore::Core::InternalThreadState* Thread) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail ? InlineTail->RIP : 0;
}

uint64_t ContextImpl::RestoreRIPFromHostPC(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC) {
  const auto Frame = Thread->CurrentFrame;
  const uint64_t BlockBegin = Frame->State.InlineJITBlockHeader;
  auto [InlineHeader, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);

  if (InlineHeader) {
    // Check if the host PC is currently within a code block.
    // If it is then RIP can be reconstructed from the beginning of the code block.
    // This is currently as close as FEX can get RIP reconstructions.
    if (HostPC >= reinterpret_cast<uint64_t>(BlockBegin) && HostPC < reinterpret_cast<uint64_t>(BlockBegin + InlineTail->Size)) {

      auto RIPEntry =
        reinterpret_cast<const uint8_t*>(Frame->State.InlineJITBlockHeader + InlineHeader->OffsetToBlockTail + InlineTail->OffsetToRIPEntries);

      // Reconstruct RIP from JIT entries for this block.
      uint64_t StartingHostPC = BlockBegin;
      uint64_t StartingGuestRIP = InlineTail->RIP;

      for (uint32_t i = 0; i < InlineTail->NumberOfRIPEntries; ++i) {
        auto Offset = FEXCore::Utils::vl64pair::Decode(RIPEntry);
        RIPEntry += Offset.Size;
        if (HostPC >= (StartingHostPC + Offset.IntegerARMPC)) {
          // We are beyond this entry, keep going forward.
          StartingHostPC += Offset.IntegerARMPC;
          StartingGuestRIP += Offset.IntegerX86RIP;
        } else {
          // Passed where the Host PC is at. Break now.
          break;
        }
      }
      return StartingGuestRIP;
    }
  }

  // Fallback to what is stored in the RIP currently.
  return Frame->State.rip;
}

#endif

uint32_t ContextImpl::ReconstructCompactedEFLAGS(FEXCore::Core::InternalThreadState* Thread, bool WasInJIT, const uint64_t* HostGPRs,
                                                 uint64_t PSTATE) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=RequirePearSourceThread(this,Thread);
#endif

  const auto Frame = Thread->CurrentFrame;
  uint32_t EFLAGS {};

  // Currently these flags just map 1:1 inside of the resulting value.
  for (size_t i = 0; i < FEXCore::Core::CPUState::NUM_EFLAG_BITS; ++i) {
    switch (i) {
    case X86State::RFLAG_CF_RAW_LOC:
    case X86State::RFLAG_PF_RAW_LOC:
    case X86State::RFLAG_AF_RAW_LOC:
    case X86State::RFLAG_TF_RAW_LOC:
    case X86State::RFLAG_ZF_RAW_LOC:
    case X86State::RFLAG_SF_RAW_LOC:
    case X86State::RFLAG_OF_RAW_LOC:
    case X86State::RFLAG_DF_RAW_LOC:
      // Intentionally do nothing.
      // These contain multiple bits which can corrupt other members when compacted.
      break;
    default: EFLAGS |= uint32_t {Frame->State.flags[i]} << i; break;
    }
  }

  uint32_t Packed_NZCV {};
  if (WasInJIT) {
    // If we were in the JIT then NZCV is in the CPU's PSTATE object.
    // Packed in to the same bit locations as RFLAG_NZCV_LOC.
    Packed_NZCV = PSTATE;

    // If we were in the JIT then PF and AF are in registers.
    // Move them to the CPUState frame now.
    Frame->State.pf_raw = HostGPRs[CPU::REG_PF.Idx()];
    Frame->State.af_raw = HostGPRs[CPU::REG_AF.Idx()];
  } else {
    // If we were not in the JIT then the NZCV state is stored in the CPUState RFLAG_NZCV_LOC.
    // SF/ZF/CF/OF are packed in a 32-bit value in RFLAG_NZCV_LOC.
    memcpy(&Packed_NZCV, &Frame->State.flags[X86State::RFLAG_NZCV_LOC], sizeof(Packed_NZCV));
  }

  uint32_t OF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_OF_RAW_LOC)) & 1;
  uint32_t CF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_CF_RAW_LOC)) & 1;
  uint32_t ZF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_ZF_RAW_LOC)) & 1;
  uint32_t SF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_SF_RAW_LOC)) & 1;

  // CF is inverted in our representation, undo the invert here.
  CF ^= 1;

  // Pack in to EFLAGS
  EFLAGS |= OF << X86State::RFLAG_OF_RAW_LOC;
  EFLAGS |= CF << X86State::RFLAG_CF_RAW_LOC;
  EFLAGS |= ZF << X86State::RFLAG_ZF_RAW_LOC;
  EFLAGS |= SF << X86State::RFLAG_SF_RAW_LOC;

  // PF calculation is deferred, calculate it now.
  // Popcount the 8-bit flag and then extract the lower bit.
  uint32_t PFByte = Frame->State.pf_raw & 0xff;
  uint32_t PF = std::popcount(PFByte ^ 1) & 1;
  EFLAGS |= PF << X86State::RFLAG_PF_RAW_LOC;

  // AF calculation is deferred, calculate it now.
  // XOR with PF byte and extract bit 4.
  uint32_t AF = ((Frame->State.af_raw ^ PFByte) & (1 << 4)) ? 1 : 0;
  EFLAGS |= AF << X86State::RFLAG_AF_RAW_LOC;

  uint8_t TFByte = Frame->State.flags[X86State::RFLAG_TF_RAW_LOC];
  EFLAGS |= (TFByte & 1) << X86State::RFLAG_TF_RAW_LOC;

  // DF is pretransformed, undo the transform from 1/-1 back to 0/1
  uint8_t DFByte = Frame->State.flags[X86State::RFLAG_DF_RAW_LOC];
  if (DFByte & 0x80) {
    EFLAGS |= 1 << X86State::RFLAG_DF_RAW_LOC;
  }

  return EFLAGS;
}

void ContextImpl::ReconstructXMMRegisters(const FEXCore::Core::InternalThreadState* Thread, __uint128_t* XMM_Low, __uint128_t* YMM_High) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=RequirePearSourceThread(this,Thread);
#endif

  const size_t MaximumRegisters = Config.Is64BitMode ? FEXCore::Core::CPUState::NUM_XMMS : 8;

  if (YMM_High != nullptr && HostFeatures.SupportsAVX) {
    const bool SupportsConvergedRegisters = HostFeatures.SupportsSVE256;

    if (SupportsConvergedRegisters) {
      ///< Output wants to de-interleave
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&XMM_Low[i], &Thread->CurrentFrame->State.xmm.avx.data[i][0], sizeof(__uint128_t));
        memcpy(&YMM_High[i], &Thread->CurrentFrame->State.xmm.avx.data[i][2], sizeof(__uint128_t));
      }
    } else {
      ///< Matches what FEX wants with non-converged registers
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&XMM_Low[i], &Thread->CurrentFrame->State.xmm.sse.data[i][0], sizeof(__uint128_t));
        memcpy(&YMM_High[i], &Thread->CurrentFrame->State.avx_high[i][0], sizeof(__uint128_t));
      }
    }
  } else {
    // Only support SSE, no AVX here, even if requested.
    memcpy(XMM_Low, Thread->CurrentFrame->State.xmm.sse.data, MaximumRegisters * sizeof(__uint128_t));
  }
}

void ContextImpl::SetXMMRegistersFromState(FEXCore::Core::InternalThreadState* Thread, const __uint128_t* XMM_Low, const __uint128_t* YMM_High) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=RequirePearSourceThread(this,Thread);
#endif

  const size_t MaximumRegisters = Config.Is64BitMode ? FEXCore::Core::CPUState::NUM_XMMS : 8;
  if (YMM_High != nullptr && HostFeatures.SupportsAVX) {
    const bool SupportsConvergedRegisters = HostFeatures.SupportsSVE256;

    if (SupportsConvergedRegisters) {
      ///< Output wants to de-interleave
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&Thread->CurrentFrame->State.xmm.avx.data[i][0], &XMM_Low[i], sizeof(__uint128_t));
        memcpy(&Thread->CurrentFrame->State.xmm.avx.data[i][2], &YMM_High[i], sizeof(__uint128_t));
      }
    } else {
      ///< Matches what FEX wants with non-converged registers
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&Thread->CurrentFrame->State.xmm.sse.data[i][0], &XMM_Low[i], sizeof(__uint128_t));
        memcpy(&Thread->CurrentFrame->State.avx_high[i][0], &YMM_High[i], sizeof(__uint128_t));
      }
    }
  } else {
    // Only support SSE, no AVX here, even if requested.
    memcpy(Thread->CurrentFrame->State.xmm.sse.data, XMM_Low, MaximumRegisters * sizeof(__uint128_t));
  }
}

void ContextImpl::SetFlagsFromCompactedEFLAGS(FEXCore::Core::InternalThreadState* Thread, uint32_t EFLAGS) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=RequirePearSourceThread(this,Thread);
#endif

  const auto Frame = Thread->CurrentFrame;
  for (size_t i = 0; i < FEXCore::Core::CPUState::NUM_EFLAG_BITS; ++i) {
    switch (i) {
    case X86State::RFLAG_OF_RAW_LOC:
    case X86State::RFLAG_CF_RAW_LOC:
    case X86State::RFLAG_ZF_RAW_LOC:
    case X86State::RFLAG_SF_RAW_LOC:
      // Intentionally do nothing.
      break;
    case X86State::RFLAG_AF_RAW_LOC:
      // AF stored in bit 4 in our internal representation. It is also
      // XORed with byte 4 of the PF byte, but we write that as zero here so
      // we don't need any special handling for that.
      Frame->State.af_raw = (EFLAGS & (1U << i)) ? (1 << 4) : 0;
      break;
    case X86State::RFLAG_PF_RAW_LOC:
      // PF is inverted in our internal representation.
      Frame->State.pf_raw = (EFLAGS & (1U << i)) ? 0 : 1;
      break;
    case X86State::RFLAG_DF_RAW_LOC:
      // DF is encoded as 1/-1
      Frame->State.flags[i] = (EFLAGS & (1U << i)) ? 0xff : 1;
      break;
    default: Frame->State.flags[i] = (EFLAGS & (1U << i)) ? 1 : 0; break;
    }
  }

  // Calculate packed NZCV. Note CF is inverted.
  uint32_t Packed_NZCV {};
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_OF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_OF_RAW_LOC) : 0;
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_CF_RAW_LOC)) ? 0 : 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_CF_RAW_LOC);
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_ZF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_ZF_RAW_LOC) : 0;
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_SF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_SF_RAW_LOC) : 0;
  memcpy(&Frame->State.flags[X86State::RFLAG_NZCV_LOC], &Packed_NZCV, sizeof(Packed_NZCV));

  // Reserved, Read-As-1, Write-as-1
  Frame->State.flags[X86State::RFLAG_RESERVED_LOC] = 1;
  // Interrupt Flag. Can't be written by CPL-3 userland.
  Frame->State.flags[X86State::RFLAG_IF_LOC] = 1;
}

bool ContextImpl::InitCore() {
#ifdef PEAR_FEX_MEMORY_OWNER
  FEXCore::Utils::PearFEXMemory::Result Outcome;
  return InitPearCore(Outcome);
#else

  if (CodeCache.IsGeneratingCache || FEXCore::Config::Get_ENABLECODECACHINGWIP()) {
    // Start with a larger code buffer to avoid resizes that would discard code
    StartMaximalCodeBuffer();
  }

  // Initialize the CPU core signal handlers & DispatcherConfig
  Dispatcher = FEXCore::CPU::Dispatcher::Create(this);

  // Set up the SignalDelegator config since core is initialized.
  SignalDelegation->SetConfig(Dispatcher->MakeSignalDelegatorConfig());

  if (Config.GdbServer) {
    // If gdbserver is enabled then this needs to be enabled.
    Config.NeedsPendingInterruptFaultCheck = true;
  }

  if constexpr (BLOCK_DEBUGGING) {
    // If the developer wants to do any single-stepping points or watch points.
    // Add them here.
    //
    // eg:
    // BlockDebuggerTracker.AllTargetSingleStep();
    // BlockDebuggerTracker.AddSingleStepTarget(0x14000'0000ULL);
    // BlockDebuggerTracker.AddWriteWatchPoint(0x420BA5ED);
  }

  return true;
#endif
}

#ifdef PEAR_FEX_MEMORY_OWNER
bool ContextImpl::InitPearCore(FEXCore::Utils::PearFEXMemory::Result& Outcome) {
  namespace Memory = FEXCore::Utils::PearFEXMemory;
  if (!PearLifetimeCreation) { Outcome=PearLifetimeCreation; return false; }
  auto ContextHold=Memory::SourceLifecycle::HoldContext(this);
  if (!ContextHold) { Outcome={PEAR_FEX_UNAVAILABLE,0,0}; return false; }
  if (CodeCache.IsGeneratingCache || FEXCore::Config::Get_ENABLECODECACHINGWIP() ||
      FEXCore::Config::Get_ENABLELAZYCODECACHINGWIP() || FEXCore::Config::Get_ENABLECODECACHEVALIDATION() || Dispatcher) {
    Outcome = {PEAR_FEX_UNAVAILABLE, 0, 0}; return false;
  }
  // The module bound the real Context on its actual native thread. Only that
  // matching admitted bootstrap can construct the owned dispatcher.
  Outcome = Memory::BindBootstrapContext(this);
  if (!Outcome) return false;
  if (!Memory::CurrentExecutor()) { Outcome = {PEAR_FEX_UNAVAILABLE, 0, 0}; return false; }
  Dispatcher = FEXCore::CPU::Dispatcher::CreatePear(this, Outcome);
  if (!Dispatcher) return false;
  SignalDelegation->SetConfig(Dispatcher->MakeSignalDelegatorConfig());
  if (Config.GdbServer) Config.NeedsPendingInterruptFaultCheck = true;
  return true;
}
bool ContextImpl::PreparePearConstructionCleanup(FEXCore::Utils::PearFEXMemory::Result& Outcome) {
  namespace Memory = FEXCore::Utils::PearFEXMemory;
  if (PearDeletionReady) { Outcome={PEAR_FEX_OK,0,0}; return true; }
  {
    std::scoped_lock Lock {PearConstruction.Mutex};
    if (PearConstruction.Slots || PearConstruction.PublishedThreads) { Outcome = {PEAR_FEX_UNAVAILABLE, 0, 0}; return false; }
    PearConstruction.StartupCleanupPending = true;
  }
  Outcome=Memory::SourceLifecycle::CloseContext(this);
  if (!Outcome) return false;
  if (Memory::Links::HasOutstanding(this)) { Outcome={PEAR_FEX_QUARANTINED,0,0}; return false; }
  if (Dispatcher || HasPearLatest() || Memory::CurrentExecutor()) {
    // Thread deletion may have consumed the original bootstrap. Establish a
    // real cleanup-only participant on the original construction thread; it
    // permits retirement/unregister, never new allocation, publication or entry.
    Outcome=Memory::SourceLifecycle::EnsureContextCleanupExecutor(this); if (!Outcome) return false;
    Dispatcher.reset(); DetachPearLatest();
    Outcome=Memory::DrainPendingRetirements(); if (!Outcome) return false;
    Outcome=Memory::UnregisterExecutor(); if (!Outcome) return false;
  } else if (!Memory::SourceContextCanRelease(this)) {
    Outcome={PEAR_FEX_UNAVAILABLE,0,0}; return false;
  }
  if (!Memory::SourceContextCanRelease(this)) { Outcome={PEAR_FEX_STALE_IDENTITY,0,0}; return false; }
  Outcome=Memory::SourceLifecycle::SealContextDelete(this); if (!Outcome) return false;
  PearDeletionReady=true; return true;
}
bool ContextImpl::PreparePearThreadCleanup(FEXCore::Core::InternalThreadState* Thread,
                                         FEXCore::Utils::PearFEXMemory::Result& Outcome) {
  namespace Memory=FEXCore::Utils::PearFEXMemory;
  auto ContextHold=Memory::SourceLifecycle::HoldContext(this);
  if (!ContextHold) { Outcome={PEAR_FEX_UNAVAILABLE,0,0}; return false; }
  // Close by exact recorded identity before dereferencing any caller Thread.
  Outcome=Memory::SourceLifecycle::CloseThread(this,Thread); if (!Outcome) return false;
  if (!Thread || Thread->CTX != this || Thread->CurrentFrame->Thread != Thread || Memory::Links::HasOutstanding(this,Thread)) {
    Outcome={PEAR_FEX_STALE_IDENTITY,0,0}; return false;
  }
  Outcome=Memory::CheckThreadCleanup(Thread); if (!Outcome) return false;
  // No source locks or lifetime readers remain. Detach every actual backend
  // and lookup holder before the native retirement drain/unregister.
  Thread->CPUBackend.ResetAtPearNativeGate();
  if (Thread->LookupCache) {
    Outcome=Thread->LookupCache->ReleasePearBacking();
    if (!Outcome) return false;
  }
  Thread->LookupCache.ResetAtPearNativeGate();
  Outcome=Memory::DrainPendingRetirements(); if (!Outcome) return false;
  Outcome=Memory::UnregisterExecutor(); if (!Outcome) return false;
  if (!Memory::SourceBindingCanRelease(Thread)) { Outcome={PEAR_FEX_UNAVAILABLE,0,0}; return false; }
  return true;
}
#endif

void ContextImpl::HandleCallback(FEXCore::Core::InternalThreadState* Thread, uint64_t RIP) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=RequirePearSourceThread(this,Thread);
#endif

  static_cast<ContextImpl*>(Thread->CTX)->Dispatcher->ExecuteJITCallback(Thread->CurrentFrame, RIP);
}

void ContextImpl::ExecuteThread(FEXCore::Core::InternalThreadState* Thread) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=RequirePearSourceThread(this,Thread);
#endif

  // Update the thread pointer for Thunk return to the latest.
  Thread->CurrentFrame->Pointers.ThunkCallbackRet = SignalDelegation->GetThunkCallbackRET();

  Dispatcher->ExecuteDispatch(Thread->CurrentFrame);

  // If it is the parent thread that died then just leave
  // TODO: This doesn't make sense when the parent thread doesn't outlive its children
}

#ifdef PEAR_FEX_MEMORY_OWNER
FEXCore::Utils::PearFEXMemory::Result
#else
void
#endif
ContextImpl::InitializeCompiler(FEXCore::Core::InternalThreadState* Thread
#ifdef PEAR_FEX_MEMORY_OWNER
  , fextl::shared_ptr<FEXCore::CPU::CodeBuffer> InitialBuffer
#endif
) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=RequirePearSourceThread(this,Thread);
#endif

#ifdef PEAR_FEX_MEMORY_OWNER
  namespace Memory=FEXCore::Utils::PearFEXMemory;
  Thread->OpDispatcher=FEXCore::Allocator::TryMakePearObject<FEXCore::IR::OpDispatchBuilder>(this,Thread);
  if (!Thread->OpDispatcher) return {PEAR_FEX_UNAVAILABLE,0,0};
  Thread->OpDispatcher->SetMultiblock(Config.Multiblock);
  Memory::Result Outcome;
  Thread->LookupCache=FEXCore::LookupCache::CreatePear(this,Outcome);
  if (!Thread->LookupCache) return Outcome;
  Thread->FrontendDecoder=FEXCore::Allocator::TryMakePearObject<FEXCore::Frontend::Decoder>(Thread);
  if (!Thread->FrontendDecoder) return {PEAR_FEX_UNAVAILABLE,0,0};
  Thread->PassManager=FEXCore::IR::PassManager::CreatePear(this,Outcome);
  if (!Thread->PassManager) return Outcome;
#else
  Thread->OpDispatcher = fextl::make_unique<FEXCore::IR::OpDispatchBuilder>(this, Thread);
  Thread->OpDispatcher->SetMultiblock(Config.Multiblock);
  Thread->LookupCache = fextl::make_unique<FEXCore::LookupCache>(this);
  Thread->FrontendDecoder = fextl::make_unique<FEXCore::Frontend::Decoder>(Thread);
  Thread->PassManager = fextl::make_unique<FEXCore::IR::PassManager>(this);
#endif

  Thread->CurrentFrame->State.L1Pointer = Thread->LookupCache->GetL1Pointer();
  Thread->CurrentFrame->State.L1Mask = Thread->LookupCache->GetScaledL1PointerMask();

  Thread->CurrentFrame->Pointers.L2Pointer = Thread->LookupCache->GetPagePointer();

  Dispatcher->InitThreadPointers(Thread);

  // Create CPU backend
#ifdef PEAR_FEX_MEMORY_OWNER
  Thread->CPUBackend = FEXCore::CPU::CreatePearArm64JITCore(this, Thread, std::move(InitialBuffer));
  if (!Thread->CPUBackend) return {PEAR_FEX_UNAVAILABLE,0,0};
#else
  Thread->CPUBackend = FEXCore::CPU::CreateArm64JITCore(this, Thread);
#endif

  // We finalize *after* the CPU backend is initialized, as the CPU backend will
  // provide necessary register information to the register allocation pass.
  Thread->PassManager->Finalize();
#ifdef PEAR_FEX_MEMORY_OWNER
  return {PEAR_FEX_OK,0,0};
#endif
}

FEXCore::Core::InternalThreadState* ContextImpl::CreateThread(const FEXCore::Core::CPUState* NewThreadState) {
#ifdef PEAR_FEX_MEMORY_OWNER
  FEXCore::Utils::PearFEXMemory::Result Outcome;
  return CreatePearThread(NewThreadState, Outcome);
#else
  FEXCore::Core::InternalThreadState* Thread = new FEXCore::Core::InternalThreadState {
    .CTX = this,
  };
  FEXCore::Allocator::VirtualName("FEXMem_ThreadState", Thread, sizeof(*Thread));

  // Copy over the new thread state to the new object
  if (NewThreadState) {
    memcpy(&Thread->CurrentFrame->State, NewThreadState, sizeof(FEXCore::Core::CPUState));
  }

  // Set up the thread manager state
  Thread->CurrentFrame->Thread = Thread;

  InitializeCompiler(Thread);

  Thread->CurrentFrame->State.DeferredSignalRefCount.Store(0);

  if (Config.BlockJITNaming() || Config.GlobalJITNaming() || Config.LibraryJITNaming()) {
    // Allocate a JIT symbol buffer only if enabled.
    Thread->SymbolBuffer = JITSymbols::AllocateBuffer();
  }

  return Thread;
#endif
}

#ifdef PEAR_FEX_MEMORY_OWNER
std::optional<size_t> ContextImpl::AcquirePearConstructionSlot() {
  std::scoped_lock Lock {PearConstruction.Mutex};
  if (PearConstruction.StartupCleanupPending) return std::nullopt;
  for (size_t I = 0; I < PearConstruction.Quarantined.size(); ++I) {
    const auto Bit = uint64_t {1} << I;
    if (!(PearConstruction.Slots & Bit)) { PearConstruction.Slots |= Bit; return I; }
  }
  return std::nullopt;
}
void ContextImpl::FinishPearConstructionSlot(size_t Index, FEXCore::Core::InternalThreadState* Retained, bool Published, bool Destroyed) {
  std::scoped_lock Lock {PearConstruction.Mutex};
  PearConstruction.Quarantined[Index] = Retained;
  if (Destroyed) PearConstruction.DestroyedBackings |= uint64_t{1}<<Index;
  if (!Retained) PearConstruction.Slots &= ~(uint64_t {1} << Index);
  if (Published) ++PearConstruction.PublishedThreads;
}
FEXCore::Core::InternalThreadState* ContextImpl::FailPearThreadConstruction(size_t Slot,
    FEXCore::Core::InternalThreadState* Thread, FEXCore::Utils::PearFEXMemory::Result Primary,
    FEXCore::Utils::PearFEXMemory::Result* Cleanup, bool* CleanupAttempted) {
  namespace Memory = FEXCore::Utils::PearFEXMemory;
  Memory::Result Cleaned = Memory::GetCleanupOutcome(Thread);
  bool CalledCleanup = Memory::CleanupWasAttempted(Thread);
  // No backend exists at an attach/initial-buffer failure. Keep the real
  // source object until detached cleanup and observed unregistration finish.
  const auto IdleCleanup = Memory::CheckThreadCleanup(Thread);
  // Capture actual bridge-called proof before a successful UNREGISTER clears
  // the binding. No status code is used to infer that cleanup was attempted.
  CalledCleanup |= Memory::CleanupWasAttempted(Thread);
  if (IdleCleanup) {
    Cleaned = Memory::DrainPendingRetirements();
    if (Cleaned) Cleaned = Memory::UnregisterExecutor();
  } else if (CalledCleanup) {
    Cleaned = Memory::GetCleanupOutcome(Thread);
  }
  CalledCleanup |= Memory::CleanupWasAttempted(Thread);
  if (!CalledCleanup) Cleaned = {}; // Explicitly unperformed, not an inferred refusal.
  if (CleanupAttempted) *CleanupAttempted = CalledCleanup;
  if (Cleanup) *Cleanup = Cleaned;
  Memory::SourceLifecycle::CloseThread(this,Thread);
  const auto DeleteSealed=Memory::SourceLifecycle::SealThreadDelete(Thread);
  if (DeleteSealed && Memory::SourceBindingCanRelease(Thread)) {
    std::destroy_at(Thread);
    const auto Deleted=Memory::SourceLifecycle::DeletedThread(Thread);
    if (!Deleted) {
      // The object destructor ran; keep only its non-reusable backing identity.
      FinishPearConstructionSlot(Slot,Thread,false,true);
      Memory::Retirement::PoisonSourceAdmission(Deleted); return nullptr;
    }
    FEXCore::Allocator::aligned_free(Thread);
    FinishPearConstructionSlot(Slot, nullptr, false);
  } else {
    FinishPearConstructionSlot(Slot, Thread, false);
    Memory::Retirement::PoisonSourceAdmission(Primary);
  }
  return nullptr;
}
FEXCore::Core::InternalThreadState* ContextImpl::CreatePearThread(const FEXCore::Core::CPUState* NewThreadState,
    FEXCore::Utils::PearFEXMemory::Result& Outcome, FEXCore::Utils::PearFEXMemory::Result* Cleanup, bool* CleanupAttempted) {
  namespace Memory = FEXCore::Utils::PearFEXMemory;
  Outcome = {PEAR_FEX_UNAVAILABLE, 0, 0};
  auto ObserveFailure = [&](uint32_t Stage, const void* Thread) {
#ifdef PEAR_PHASE_OBSERVE
    PearThreadCreateFailed(Stage,reinterpret_cast<uint64_t>(static_cast<const FEXCore::Context::Context*>(this)),reinterpret_cast<uint64_t>(Thread),
                           reinterpret_cast<uint64_t>(&Outcome),Outcome.Status,Outcome.ErrorDomain,Outcome.ErrorCode);
#else
    (void)Stage; (void)Thread;
#endif
  };
  if (Cleanup) *Cleanup = {};
  if (CleanupAttempted) *CleanupAttempted = false;
  auto ContextHold=Memory::SourceLifecycle::HoldContext(this);
  if (!ContextHold) { ObserveFailure(1,nullptr); return nullptr; }
  if (!Dispatcher || !Memory::Retirement::AdmissionOpen()) {
    const auto First = Memory::Retirement::FirstFailureSnapshot();
    if (First.Present) Outcome = First.Outcome;
    ObserveFailure(2,nullptr);
    return nullptr;
  }
  const auto Slot = AcquirePearConstructionSlot();
  if (!Slot) { Outcome = {PEAR_FEX_CAPACITY, 0, 0}; ObserveFailure(3,nullptr); return nullptr; }
  FEXCore::Core::InternalThreadState* Thread {};
  auto* ThreadStorage=FEXCore::Allocator::aligned_alloc(alignof(FEXCore::Core::InternalThreadState),sizeof(FEXCore::Core::InternalThreadState));
  if (!ThreadStorage) {
    ObserveFailure(4,nullptr);
    FinishPearConstructionSlot(*Slot,nullptr,false);
    Outcome={PEAR_FEX_UNAVAILABLE,0,0};
    Memory::Retirement::PoisonSourceAdmission(Outcome); return nullptr;
  }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
  try {
    Thread = ::new (ThreadStorage) FEXCore::Core::InternalThreadState {.CTX = this};
  } catch (...) {
    FEXCore::Allocator::aligned_free(ThreadStorage);
    FinishPearConstructionSlot(*Slot, nullptr, false);
    throw; // Preserve the upstream NX allocation exception when supported.
  }
#else
  // The pinned target disables C++ unwinding. Preserve that upstream policy;
  // typed-return cleanup/normal exits remain checked, allocator termination is
  // not a recoverable or qualified cleanup path.
  Thread = ::new (ThreadStorage) FEXCore::Core::InternalThreadState {.CTX = this};
#endif
  struct ConstructionGuard {
    ContextImpl& Owner;
    size_t Slot;
    FEXCore::Core::InternalThreadState* Thread;
    bool Released {};
    ~ConstructionGuard() {
      if (!Released) {
        // No owner call during unwinding. Retain the actual object and close
        // new admission; the original upstream exception propagates unchanged.
        Owner.FinishPearConstructionSlot(Slot, Thread, false);
        Memory::Retirement::PoisonSourceAdmission({PEAR_FEX_UNAVAILABLE, 0, 0});
      }
    }
  } Guard {*this, *Slot, Thread};
  FEXCore::Allocator::VirtualName("FEXMem_ThreadState", Thread, sizeof(*Thread));
  if (NewThreadState) memcpy(&Thread->CurrentFrame->State, NewThreadState, sizeof(FEXCore::Core::CPUState));
  Thread->CurrentFrame->Thread = Thread;
#ifdef PEAR_PHASE_OBSERVE
  PearAttach::Diagnostic AttachDiagnostic {};
  const bool ObserveAttach=PearAttachObservationEnabled();
  Outcome = ObserveAttach ? Memory::AttachAllocatedThreadObserved(this,Thread,FEXCore::CPU::PEAR_SOURCE_CODE_ROLE,&AttachDiagnostic) :
    Memory::SourceLifecycle::AttachAllocatedThread(this,Thread,FEXCore::CPU::PEAR_SOURCE_CODE_ROLE);
#else
  Outcome = Memory::SourceLifecycle::AttachAllocatedThread(this,Thread,FEXCore::CPU::PEAR_SOURCE_CODE_ROLE);
#endif
  if (!Outcome) {
#ifdef PEAR_PHASE_OBSERVE
    if (ObserveAttach) PearThreadCreateAttachFailed(reinterpret_cast<uint64_t>(static_cast<const FEXCore::Context::Context*>(this)),
      reinterpret_cast<uint64_t>(Thread),reinterpret_cast<uint64_t>(&Outcome),Outcome.Status,Outcome.ErrorDomain,Outcome.ErrorCode,&AttachDiagnostic);
    else ObserveFailure(5,Thread);
#else
    ObserveFailure(5,Thread);
#endif
    auto* Failed = FailPearThreadConstruction(*Slot, Thread, Outcome, Cleanup, CleanupAttempted);
    Guard.Released = true; return Failed;
  }
  // This may wait at the native owner gate. It precedes compiler/lookup/list
  // locks and ensures the JIT constructor needs no hidden owner allocation.
  auto InitialBuffer = GetPearLatest(Outcome);
  if (!InitialBuffer) {
    ObserveFailure(6,Thread);
    auto* Failed = FailPearThreadConstruction(*Slot, Thread, Outcome, Cleanup, CleanupAttempted);
    Guard.Released = true; return Failed;
  }
  Outcome=InitializeCompiler(Thread,std::move(InitialBuffer));
  if (!Outcome) {
    ObserveFailure(7,Thread);
    // The compiler can now be partially constructed. Retain the entire actual
    // Thread/Context tree on refusal; never use the pre-compiler deletion path.
    Memory::Result Released;
    const bool Prepared=PreparePearThreadCleanup(Thread,Released);
    if (CleanupAttempted) *CleanupAttempted=true;
    if (Cleanup) *Cleanup=Released;
    if (Prepared) {
      const auto Sealed=Memory::SourceLifecycle::SealThreadDelete(Thread);
      if (Sealed && Memory::SourceBindingCanRelease(Thread)) {
        std::destroy_at(Thread);
        const auto Deleted=Memory::SourceLifecycle::DeletedThread(Thread);
        if (Deleted) {
          FEXCore::Allocator::aligned_free(Thread);
          FinishPearConstructionSlot(*Slot,nullptr,false);
        } else {
          FinishPearConstructionSlot(*Slot,Thread,false,true);
          if (Cleanup) *Cleanup=Deleted;
        }
      } else {
        FinishPearConstructionSlot(*Slot,Thread,false);
        if (Cleanup) *Cleanup=Sealed ? Memory::Result{PEAR_FEX_UNAVAILABLE,0,0} : Sealed;
      }
    } else FinishPearConstructionSlot(*Slot,Thread,false);
    Memory::Retirement::PoisonSourceAdmission(Outcome);
    Guard.Released=true;return nullptr;
  }
  Thread->CurrentFrame->State.DeferredSignalRefCount.Store(0);
  if (Config.BlockJITNaming() || Config.GlobalJITNaming() || Config.LibraryJITNaming())
    Thread->SymbolBuffer = JITSymbols::AllocateBuffer();
  Outcome = {PEAR_FEX_OK, 0, 0};
  FinishPearConstructionSlot(*Slot, nullptr, true);
  Guard.Released = true;
  LogMan::Msg::EFmt("Pear CPU policy state={:x} scalar={} vector={} memcpy={}",
    reinterpret_cast<uintptr_t>(Thread), IsAtomicTSOEnabled(),
    IsVectorAtomicTSOEnabled(), IsMemcpyAtomicTSOEnabled());
  return Thread;
}
#endif

#ifdef PEAR_FEX_MEMORY_OWNER
bool ContextImpl::DestroyPearThreadChecked(FEXCore::Core::InternalThreadState* Thread,
    FEXCore::Utils::PearFEXMemory::Result& Outcome,bool& Destroyed,bool& Freed) {
  PearSlot::Scope PearObservation(PearSlot::Stage::Destroy,this,Thread);
  const auto PearOriginalBody=[&]() -> bool {
  namespace Memory=FEXCore::Utils::PearFEXMemory;
  Destroyed=false; Freed=false;
  auto ContextHold=Memory::SourceLifecycle::HoldContext(this);
  if (!ContextHold) { Outcome={PEAR_FEX_UNAVAILABLE,0,0}; Memory::Retirement::PoisonSourceAdmission(Outcome); return false; }
  const auto Closed=Memory::SourceLifecycle::CloseThread(this,Thread);
  if (!Closed || !Memory::SourceBindingCanRelease(Thread)) {
    const auto Original=Closed ? Memory::GetOriginalAttachFailure(Thread) : Closed;
    // A successful old attach result is not a deletion refusal. Preserve a
    // genuine failure; otherwise label the actual local release denial.
    Outcome=Original ? Memory::Result {PEAR_FEX_UNAVAILABLE,0,0} : Original;
    Memory::Retirement::PoisonSourceAdmission(Outcome); return false;
  }
  // Native cleanup must already have detached backend/lookup before owner
  // unregister. A bare source predicate cannot perform teardown implicitly.
  if (Thread->CTX != this || Thread->CPUBackend || Thread->LookupCache) {
    Outcome={PEAR_FEX_UNAVAILABLE,0,0}; Memory::Retirement::PoisonSourceAdmission(Outcome); return false;
  }
  const auto DeleteSealed=Memory::SourceLifecycle::SealThreadDelete(Thread);
  if (!DeleteSealed) { Outcome=DeleteSealed; Memory::Retirement::PoisonSourceAdmission(DeleteSealed); return false; }
  std::destroy_at(Thread); Destroyed=true;
  const auto Deleted=Memory::SourceLifecycle::DeletedThread(Thread);
  if (!Deleted) { Outcome=Deleted; Memory::Retirement::PoisonSourceAdmission(Deleted); return false; }
  { std::scoped_lock Lock {PearConstruction.Mutex}; if (PearConstruction.PublishedThreads) --PearConstruction.PublishedThreads; }
  FEXCore::Allocator::aligned_free(Thread); Freed=true;
  Outcome=Deleted; return true;
  };
  const bool PearReturned=PearOriginalBody();
  PearObservation.Return(2,Outcome.Status,Outcome.ErrorDomain,Outcome.ErrorCode,PearReturned,Destroyed,Freed);
  return PearReturned;
}
#endif
void ContextImpl::DestroyThread(FEXCore::Core::InternalThreadState* Thread) {
#ifdef PEAR_FEX_MEMORY_OWNER
  FEXCore::Utils::PearFEXMemory::Result Outcome;
  bool Destroyed {},Freed {};
  (void)DestroyPearThreadChecked(Thread,Outcome,Destroyed,Freed);
#else
  FEXCore::Allocator::VirtualProtect(&Thread->InterruptFaultPage, sizeof(Thread->InterruptFaultPage),
                                     Allocator::ProtectOptions::Read | Allocator::ProtectOptions::Write);
  delete Thread;
#endif
}

#ifndef _WIN32
void ContextImpl::UnlockAfterFork(FEXCore::Core::InternalThreadState* LiveThread, bool Child) {
  Allocator::UnlockAfterFork(LiveThread, Child);

  Profiler::PostForkAction(Child);
  if (Child) {
    if (CodeMapWriter) {
      CodeMapWriter->ResetAfterFork();
    }

    CodeInvalidationMutex.StealAndDropActiveLocks();
    if (Config.StrictInProcessSplitLocks) {
      StrictSplitLockMutex = 0;
    }
  } else {
    CodeInvalidationMutex.unlock();
    if (Config.StrictInProcessSplitLocks) {
      FEXCore::Utils::SpinWaitLock::unlock(&StrictSplitLockMutex);
    }
  }
}

void ContextImpl::LockBeforeFork(FEXCore::Core::InternalThreadState* Thread) {
  CodeInvalidationMutex.lock();
  Allocator::LockBeforeFork(Thread);
  if (Config.StrictInProcessSplitLocks) {
    FEXCore::Utils::SpinWaitLock::lock(&StrictSplitLockMutex);
  }
}
#endif

void ContextImpl::OnCodeBufferAllocated(const fextl::shared_ptr<CPU::CodeBuffer>& Buffer) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearContextHold=FEXCore::Utils::PearFEXMemory::SourceLifecycle::HoldContext(this);
  PEAR_FEX_REQUIRE(!!PearContextHold,"Pear actual Context lifetime is unavailable");
#endif

  if (Config.GlobalJITNaming()) {
    Symbols.RegisterJITSpace(Buffer->GetBufferBase(), Buffer->TotalAllocationSize());
  }

  {
    std::scoped_lock lk {CodeBufferListLock};
    CodeBufferList.emplace_back(Buffer);
  }
}

void ContextImpl::ClearCodeCache(FEXCore::Core::InternalThreadState* Thread, bool NewCodeBuffer) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=RequirePearSourceThread(this,Thread);
#endif

  FEXCORE_PROFILE_INSTANT("ClearCodeCache");

  if (NewCodeBuffer) {
    // Allocate new CodeBuffer + L3 LookupCache and clear L1+L2 caches
    Thread->CPUBackend->ClearCache();
  } else {
    // Clear L1+L2 cache of this thread, and clear L3 cache across any threads using it
    auto lk = Thread->LookupCache->AcquireWriteLock();
    Thread->LookupCache->ClearCache(lk);
  }
  Allocator::VirtualDontNeed(Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
}

static void IRDumper(FEXCore::Core::InternalThreadState* Thread, IR::IREmitter* IREmitter, uint64_t GuestRIP) {
  FEXCore::File::File FD = FEXCore::File::File::GetStdERR();
  fextl::ostringstream out;
  auto NewIR = IREmitter->ViewIR();
  FEXCore::IR::Dump(&out, &NewIR);
  fextl::fmt::print(FD, "IR-ShouldDump-{} 0x{:x}:\n{}\n@@@@@\n", NewIR.PostRA() ? "post" : "pre", GuestRIP, out.str());
}

bool ContextImpl::CheckIfBlockIsCacheable(FEXCore::Core::InternalThreadState& Thread, uint64_t GuestRIP, uint64_t MaxInst) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=RequirePearSourceThread(this,&Thread);
#endif

  return Thread.FrontendDecoder->CheckIfCacheable(Thread, reinterpret_cast<const uint8_t*>(GuestRIP), GuestRIP, MaxInst);
}

ContextImpl::GenerateIRResult
ContextImpl::GenerateIR(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, bool ExtendedDebugInfo, uint64_t MaxInst) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=RequirePearSourceThread(this,Thread);
#endif

  FEXCORE_PROFILE_SCOPED("GenerateIR");

  Thread->OpDispatcher->ResetWorkingList();

  uint64_t TotalInstructions {0};
  uint64_t TotalInstructionsLength {0};

  bool HasCustomIR {};

  bool WantsDiskCachePatching = DiskCache.IsReadingDiskCache() || DiskCache.IsWritingDiskCache();

  if (HasCustomIRHandlers.load(std::memory_order_relaxed)) {
    std::shared_lock lk(CustomIRMutex);
    auto Handler = CustomIRHandlers.find(GuestRIP);
    if (Handler != CustomIRHandlers.end()) {
      TotalInstructions = 1;
      TotalInstructionsLength = 1;
      Handler->second.Handler(GuestRIP, Thread->OpDispatcher.get());
      HasCustomIR = true;
    }
  }

  if (!HasCustomIR) {
    const auto* GuestCode = reinterpret_cast<const uint8_t*>(GuestRIP);

    Thread->FrontendDecoder->DecodeLoop(GuestCode);

    const auto* BlockInfo = Thread->FrontendDecoder->GetDecodedBlockInfo();
    const auto& CodeBlocks = BlockInfo->Blocks;

    Thread->OpDispatcher->BeginFunction(GuestRIP, &CodeBlocks, BlockInfo->TotalInstructionCount, BlockInfo->Is64BitMode,
                                        AreMonoHacksActive() && MonoBackpatcherBlock.load(std::memory_order_relaxed) == GuestRIP);

    const auto GPRSize = Thread->OpDispatcher->GetGPROpSize();

#ifdef ZYDIS_DISASSEMBLER
    const auto ZydisMachineMode = Config.Is64BitMode ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    if (FEXCore::Config::Get_X86DISASSEMBLE()) {
      const uint64_t DecodedMin = Thread->FrontendDecoder->DecodedMinAddress;
      const uint64_t DecodedMax = Thread->FrontendDecoder->DecodedMaxAddress;
      LogMan::Msg::IFmt("Guest x86 Begin (RIP={:#x}, {:#x}-{:#x})", GuestRIP, DecodedMin, DecodedMax);
    }
#endif

    for (size_t j = 0; j < CodeBlocks.size(); ++j) {
      const auto& Block = CodeBlocks[j];

      // Dispatch failures and invalid instructions terminate only the decoded
      // block that contains them. Other block targets in the same multiblock
      // compilation unit are independent entry paths.
      bool HadDispatchError {false};
      bool HadInvalidInst {false};

#ifdef ZYDIS_DISASSEMBLER
      if (FEXCore::Config::Get_X86DISASSEMBLE() && CodeBlocks.size() > 1) {
        LogMan::Msg::IFmt("  Block {} Entry={:#x} NumInsts={}", j, Block.Entry, Block.NumInstructions);
      }
#endif

      bool BlockInForceTSOValidRange = false;
      auto InstForceTSOIt = ForceTSOInstructions.end();
      if (ForceTSOValidRanges.Contains({Block.Entry, Block.Entry + Block.Size})) {
        if (auto It = ForceTSOInstructions.lower_bound(Block.Entry); It != ForceTSOInstructions.end() && *It < Block.Entry + Block.Size) {
          InstForceTSOIt = It;
          BlockInForceTSOValidRange = true;
        }
      }

      // Set the block entry point
      Thread->OpDispatcher->SetNewBlockIfChanged(Block.Entry);

      // Reset any block-specific state
      Thread->OpDispatcher->StartNewBlock();

      const uint64_t InstsInBlock = Block.NumInstructions;
      if (InstsInBlock == 0) {
        // Special case for an empty instruction block.
        Thread->OpDispatcher->ExitFunction(Thread->OpDispatcher->_InlineEntrypointOffset(GPRSize, Block.Entry - GuestRIP));
      }

      uint64_t BlockInstructionsLength {};
      for (size_t i = 0; i < InstsInBlock; ++i) {
        uint64_t InstAddress = Block.Entry + BlockInstructionsLength;
        const FEXCore::X86Tables::X86InstInfo* TableInfo {nullptr};
        const FEXCore::X86Tables::DecodedInst* DecodedInfo {nullptr};

        TableInfo = Block.DecodedInstructions[i].TableInfo;
        DecodedInfo = &Block.DecodedInstructions[i];

#ifdef ZYDIS_DISASSEMBLER
        if (FEXCore::Config::Get_X86DISASSEMBLE()) {
          const uint8_t* InstBytes = reinterpret_cast<const uint8_t*>(InstAddress);
          ZydisDisassembledInstruction ZydisInst;
          if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZydisMachineMode, InstAddress, InstBytes, DecodedInfo->InstSize, &ZydisInst))) {
            LogMan::Msg::IFmt("    {:#x}: {}", InstAddress, ZydisInst.text);
          } else {
            LogMan::Msg::IFmt("    {:#x}: (decode failed, {} bytes)", InstAddress, DecodedInfo->InstSize);
          }
        }
#endif

        bool IsLocked = DecodedInfo->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_LOCK;

        // Do a partial register cache flush before every instruction. This
        // prevents cross-instruction static register caching, while allowing
        // context load/stores to be optimized within a block. Theoretically,
        // this flush is not required for correctness, all mandatory flushes are
        // included in instruction-specific handlers. Instead, this is a blunt
        // heuristic to make the register cache less aggressive, as the current
        // RA generates bad code in common cases with tied registers otherwise.
        //
        // However, it makes our exception handling behaviour more predictable.
        // It is potentially correctness bearing in that sense, but that is a
        // side effect here and (if that behaviour is required) we should handle
        // that more explicitly later.
        Thread->OpDispatcher->FlushRegisterCache(true);

        if (ExtendedDebugInfo ||
#ifdef PEAR_PHASE_OBSERVE
            PearPhaseSelected(InstAddress) ||
#endif
            Thread->OpDispatcher->CanHaveSideEffects(TableInfo, DecodedInfo)) {
          Thread->OpDispatcher->_GuestOpcode(InstAddress - GuestRIP);
        }

        if (Config.SMCChecks == FEXCore::Config::CONFIG_SMC_FULL || Block.ForceFullSMCDetection) {
          auto ExistingCodePtr = reinterpret_cast<uint8_t*>(Block.Entry + BlockInstructionsLength);
          auto InstAddressReg = Thread->OpDispatcher->_EntrypointOffset(GPRSize, InstAddress - GuestRIP);

          auto Value = FEXCore::Utils::crc32(ExistingCodePtr, DecodedInfo->InstSize);
          auto CRC = WantsDiskCachePatching ?
                       Thread->OpDispatcher->_PatchableGuestCRC(IR::OpSize::i64Bit, Value, (int64_t)ExistingCodePtr, DecodedInfo->InstSize) :
                       Thread->OpDispatcher->Constant(Value);
          auto CodeChanged = Thread->OpDispatcher->_ValidateCode(CRC, InstAddressReg, DecodedInfo->InstSize);

          auto InvalidateCodeCond = Thread->OpDispatcher->CondJump(CodeChanged);

          auto CurrentBlock = Thread->OpDispatcher->GetCurrentBlock();
          auto CodeWasChangedBlock = Thread->OpDispatcher->CreateNewCodeBlockAtEnd();
          Thread->OpDispatcher->SetTrueJumpTarget(InvalidateCodeCond, CodeWasChangedBlock);

          Thread->OpDispatcher->SetCurrentCodeBlock(CodeWasChangedBlock);
          Thread->OpDispatcher->StartNewBlock();

          // Generate a relocatable entry for invalidation purposes.
          auto EntryToInvalidate = Thread->OpDispatcher->_EntrypointOffset(GPRSize, 0);
          auto NewRIP = Thread->OpDispatcher->_EntrypointOffset(GPRSize, InstAddress - GuestRIP);
          // Invalidate and exit the function
          Thread->OpDispatcher->_ThreadRemoveCodeEntry(EntryToInvalidate, NewRIP);

          auto NextOpBlock = Thread->OpDispatcher->CreateNewCodeBlockAfter(CurrentBlock);

          Thread->OpDispatcher->SetFalseJumpTarget(InvalidateCodeCond, NextOpBlock);
          Thread->OpDispatcher->SetCurrentCodeBlock(NextOpBlock);
          Thread->OpDispatcher->StartNewBlock();
        }

        if (TableInfo && TableInfo->OpcodeDispatcher.OpDispatch) {
          auto Fn = TableInfo->OpcodeDispatcher.OpDispatch;
          Thread->OpDispatcher->ResetHandledLock();
          Thread->OpDispatcher->ResetDecodeFailure();
          IR::ForceTSOMode ForceTSO = IR::ForceTSOMode::NoOverride;
          if (BlockInForceTSOValidRange) {
            if (InstForceTSOIt != ForceTSOInstructions.end() && *InstForceTSOIt == InstAddress) {
              ForceTSO = IR::ForceTSOMode::ForceEnabled;
            } else {
              ForceTSO = IR::ForceTSOMode::ForceDisabled;
            }
          } else if (DecodedInfo->Flags & X86Tables::DecodeFlags::FLAG_FORCE_TSO) {
            ForceTSO = IR::ForceTSOMode::ForceEnabled;
          }

          Thread->OpDispatcher->SetForceTSO(ForceTSO);
          std::invoke(Fn, Thread->OpDispatcher, DecodedInfo);
          if (Thread->OpDispatcher->HadDecodeFailure()) {
            HadDispatchError = true;
          } else {
            if (Thread->OpDispatcher->HasHandledLock() != IsLocked) {
              HadDispatchError = true;
              LogMan::Msg::EFmt("Missing LOCK HANDLER at 0x{:x}{{'{}'}}", InstAddress, TableInfo->Name ?: "UND");
            }
            BlockInstructionsLength += DecodedInfo->InstSize;
            TotalInstructionsLength += DecodedInfo->InstSize;
            ++TotalInstructions;

            // Walk InstForceTSOIt forward past the handled instruction
            InstForceTSOIt =
              std::find_if(InstForceTSOIt, ForceTSOInstructions.end(), [&](auto Val) { return Val >= Block.Entry + BlockInstructionsLength; });
          }
        } else {
          // Invalid instruction
          if (!BlockInstructionsLength) {
            // SMC can modify block contents and patch invalid instructions to valid ones inline.
            // End blocks upon encountering them and only emit an invalid opcode exception if there are no prior instructions in the block (that could have modified it to be valid).

            if (TableInfo) {
              LogMan::Msg::EFmt("Invalid or Unknown instruction: {} 0x{:x}", TableInfo->Name ?: "UND", Block.Entry - GuestRIP);
            }

            if (Block.BlockStatus == Frontend::Decoder::DecodedBlockStatus::INVALID_INST ||
                Block.BlockStatus == Frontend::Decoder::DecodedBlockStatus::BAD_RELOCATION) {
              Thread->OpDispatcher->InvalidOp(DecodedInfo);
            } else if (Block.BlockStatus == Frontend::Decoder::DecodedBlockStatus::UNIMPLEMENTED_INST) {
              Thread->OpDispatcher->UnimplementedOp(DecodedInfo);
            } else {
              Thread->OpDispatcher->NoExecOp(DecodedInfo);
            }
          }

          HadInvalidInst = true;
        }

        const bool NeedsBlockEnd = (HadDispatchError && TotalInstructions > 0) ||
                                   (Thread->OpDispatcher->NeedsBlockEnder() && i + 1 == InstsInBlock) || HadInvalidInst;

        // If we had a dispatch error then leave early
        if (HadDispatchError && TotalInstructions == 0) {
          // Couldn't handle any instruction in op dispatcher
          Thread->OpDispatcher->DelayedDisownBuffer();
          return {std::nullopt, 0, 0, 0, 0};
        }

        if (NeedsBlockEnd) {
          // We had some instructions. Early exit
          Thread->OpDispatcher->ExitFunction(
            Thread->OpDispatcher->_InlineEntrypointOffset(GPRSize, Block.Entry + BlockInstructionsLength - GuestRIP));
          break;
        }


        if (Thread->OpDispatcher->FinishOp(DecodedInfo->PC + DecodedInfo->InstSize, i + 1 == InstsInBlock)) {
          break;
        }
      }
    }

#ifdef ZYDIS_DISASSEMBLER
    if (FEXCore::Config::Get_X86DISASSEMBLE()) {
      LogMan::Msg::IFmt("Guest x86 End");
    }
#endif

    Thread->OpDispatcher->Finalize();
  }

  Thread->FrontendDecoder->DelayedDisownBuffer();

  IR::IREmitter* IREmitter = Thread->OpDispatcher.get();

  auto ShouldDump = Thread->OpDispatcher->ShouldDumpIR();
  // Debug
  if (ShouldDump) {
    IRDumper(Thread, IREmitter, GuestRIP);
  }

  // Run the passmanager over the IR from the dispatcher
  Thread->PassManager->Run(IREmitter);

  // Debug
  if (ShouldDump) {
    IRDumper(Thread, IREmitter, GuestRIP);
  }

  return {
    .IRView = IREmitter->ViewIR(),
    .TotalInstructions = TotalInstructions,
    .TotalInstructionsLength = TotalInstructionsLength,
    .StartAddr = Thread->FrontendDecoder->DecodedMinAddress,
    .Length = Thread->FrontendDecoder->DecodedMaxAddress - Thread->FrontendDecoder->DecodedMinAddress,
    .NeedsAddGuestCodeRanges = !HasCustomIR,
  };
}

ContextImpl::CompileCodeResult ContextImpl::CompileCode(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, uint64_t MaxInst) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=RequirePearSourceThread(this,Thread);
#endif

  if (SourcecodeResolver && Config.GDBSymbols()) {
    auto MappedSection = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);
    if (MappedSection) {
      MappedSection->FileInfo.SourcecodeMap =
        SourcecodeResolver->GenerateMap(MappedSection->FileInfo.Filename, CodeMap::GetBaseFilename(MappedSection->FileInfo, false));
    }
  }

  // Generate IR + Meta Info
  auto [IRView, TotalInstructions, TotalInstructionsLength, StartAddr, Length, NeedsAddGuestCodeRanges] =
    GenerateIR(Thread, GuestRIP, Config.GDBSymbols(), MaxInst);
  if (!IRView) {
    Thread->FrontendDecoder->ValidateDisownedOrFree();
    Thread->OpDispatcher->ValidateDisownedOrFree();
    // OpDispatcher IR already released in this case.
    return {{}, nullptr, 0, 0, false};
  }

  // Attempt to get the CPU backend to compile this code
  // Re-check if another thread raced us in compiling this block.
  // We could lock CodeBufferWriteMutex earlier to prevent this from happening,
  // but this would increase lock contention. Redundant frontend runs aren't
  // as expensive and are easily reverted.
  if (MaxInst != 1) {
    if (auto Block = Thread->LookupCache->FindBlock(Thread, GuestRIP)) {
      // Raced to compile, release the OpDispatcher IR.
      Thread->OpDispatcher->DelayedDisownBuffer();
      Thread->FrontendDecoder->ValidateDisownedOrFree();
      Thread->OpDispatcher->ValidateDisownedOrFree();
      return {.CompiledCode = {.BlockBegin = reinterpret_cast<uint8_t*>(Block), .EntryPoints = {{GuestRIP, reinterpret_cast<uint8_t*>(Block)}}},
              .DebugData = nullptr,
              .StartAddr = 0,
              .Length = 0,
              .NeedsAddGuestCodeRanges = false};
    }
  }

  auto DebugData = fextl::make_unique<FEXCore::Core::DebugData>();

  // If the trap flag is set we generate single instruction blocks that each check to generate a single step exception.
  bool TFSet = Thread->CurrentFrame->State.flags[X86State::RFLAG_TF_RAW_LOC];

  auto CompiledCode = Thread->CPUBackend->CompileCode(GuestRIP, Length, TotalInstructions == 1, &*IRView, DebugData.get(), TFSet);

  // Release the IR
  Thread->OpDispatcher->DelayedDisownBuffer();

  Thread->FrontendDecoder->ValidateDisownedOrFree();
  Thread->OpDispatcher->ValidateDisownedOrFree();
  return {
    .CompiledCode = std::move(CompiledCode),
    .DebugData = std::move(DebugData),
    .StartAddr = StartAddr,
    .Length = Length,
    .NeedsAddGuestCodeRanges = NeedsAddGuestCodeRanges,
  };
}

#ifdef PEAR_FEX_MEMORY_OWNER
FEXCore::Utils::PearFEXMemory::Result ContextImpl::BeginPearDispatcherGate(
  FEXCore::Core::CpuStateFrame* Frame, uintptr_t ResumePC, PearDispatcherGate& Gate) {
  namespace Memory = FEXCore::Utils::PearFEXMemory;
  auto Life=Memory::AcquireCurrentSourceLifetime(this);
  auto* Thread=Life ? Life.ActualThread() : nullptr;
  const auto Executor=Life ? Life.Executor() : 0;
  // Frame is not dereferenced until the actual protected Thread identifies it.
  if (Gate.Open || !Life || !Dispatcher || !Thread || !Thread->CPUBackend || Thread->CTX != this ||
      Frame != Thread->CurrentFrame || Frame->Thread != Thread || !Executor || !Dispatcher->IsPearNativeResume(ResumePC))
    return {PEAR_FEX_UNAVAILABLE, 0, 0};
  // An already registered binding cannot be replaced by this call. It verifies
  // this exact real Frame/Thread against the actual TEB/source-state binding.
  const auto Bound = Memory::BindSourceThread(Thread);
  if (!Bound) return Bound;
  const auto Facts = Dispatcher->GetPearSnapshot();
  const auto Base = reinterpret_cast<uintptr_t>(Facts.Base);
  if (!Facts || Facts.Token.allocation_class != PEAR_FEX_CLASS_DISPATCHER ||
      Facts.Token.expected_state != PEAR_FEX_PUBLISHED_RX || ResumePC < Base ||
      ResumePC-Base > Facts.Token.extent_size || 4 > Facts.Token.extent_size-(ResumePC-Base) ||
      (ResumePC & 3) || !Memory::HasManagedActive(Facts)) return {PEAR_FEX_UNAVAILABLE, 0, 0};
  Gate = {};
  Gate.Facts = Facts; Gate.Frame = Frame; Gate.Lifetime=std::move(Life);
  Gate.OriginalPinEpoch = Facts.Token.write_epoch; Gate.ResumeOffset = ResumePC-Base;
  // Copy the original return instruction into this bounded NX source record
  // while the exact D lease is still ACTIVE, before any native handoff.
  const auto Read = Memory::CopyManagedRX(Facts, Thread, Gate.ResumeOffset, Gate.ResumeWord);
  if (!Read) return Read.Outcome;
  Gate.Lifetime.ObserveWakeCheckpoint(5);
  const auto Handed = Memory::Handoff(Facts, Gate.ResumeOffset, Gate.Continuation);
  Gate.Lifetime.ObserveWakeCheckpoint(6,Handed);
  if (!Handed) return Handed;
  Gate.Open = true;
  return {PEAR_FEX_OK, 0, 0};
}
FEXCore::Utils::PearFEXMemory::Result ContextImpl::FinishPearDispatcherGate(PearDispatcherGate& Gate) {
  namespace Memory=FEXCore::Utils::PearFEXMemory;
  const auto Life=Gate.Lifetime.Validate(); if (!Life) return Life;
  auto* Thread=Gate.Lifetime.ActualThread();
  if (!Gate.Open || !Gate.Continuation || !Gate.OriginalPinEpoch || !Dispatcher || !Thread ||
      Gate.Frame!=Thread->CurrentFrame || Gate.Frame->Thread!=Thread || Thread->CTX!=this ||
      Memory::CurrentExecutor()!=Gate.Lifetime.Executor()) return {PEAR_FEX_STALE_IDENTITY,0,0};
  Memory::SourceMutationTurn EntryTurn {Gate.Lifetime,false};
  if (!EntryTurn) return EntryTurn.Status();
  Memory::Links::SealedEntry Entry;
  Memory::Result Sealed {PEAR_FEX_UNAVAILABLE,0,0};
  // At most four source polls and four 50-ms ntdll waits. Each owner poll has
  // the existing finite quiescence bound. Keep the exact original C/epoch and
  // actual source lifetime on every refusal; no code read occurs while pinned.
  for (uint32_t Attempt=0;Attempt<4;++Attempt) {
    const auto Sequence=Memory::Links::EntrySequence();
    Sealed=Memory::Links::TrySealEntry(Gate.Lifetime,Entry);
    if (Sealed) break;
    if (Sealed.Status!=PEAR_FEX_UNAVAILABLE) return Sealed;
    const auto Poll=Memory::Poll(Gate.Facts,Gate.ResumeOffset,Gate.Continuation,Gate.OriginalPinEpoch);
    if (!Poll) return Poll;
    const auto Wait=Memory::Links::WaitForEntryChange(Sequence,50);
    if (!Wait && Wait.Status!=PEAR_FEX_QUIESCENCE_TIMEOUT) return Wait;
    if (!Wait && Attempt==3) return Wait; // Preserve the final actual NTSTATUS.
  }
  if (!Sealed) return Sealed;
  const auto Fresh=Dispatcher->GetPearSnapshot();
  if (!Fresh || Fresh.Base!=Gate.Facts.Base || Fresh.Token.owner_pid!=Gate.Facts.Token.owner_pid ||
      Fresh.Token.allocation_id!=Gate.Facts.Token.allocation_id || Fresh.Token.generation!=Gate.Facts.Token.generation ||
      Fresh.Token.extent_offset!=Gate.Facts.Token.extent_offset || Fresh.Token.extent_size!=Gate.Facts.Token.extent_size ||
      Fresh.Token.allocation_class!=PEAR_FEX_CLASS_DISPATCHER || Fresh.Token.ec_role!=Gate.Facts.Token.ec_role ||
      Fresh.Token.write_epoch<Gate.OriginalPinEpoch || Fresh.Token.expected_state!=PEAR_FEX_PUBLISHED_RX)
    return {PEAR_FEX_STALE_IDENTITY,0,0};
  const auto Stable=Entry.Validate(Gate.Lifetime); if (!Stable) return Stable;
  // The original sole pin/descriptor is consumed atomically by owner op14;
  // never split this transition into UNPIN followed by a fresh ENTRY.
  const auto Resumed=Memory::Resume(Fresh,Gate.ResumeOffset,Gate.Continuation,Gate.OriginalPinEpoch);
  if (!Resumed) return Resumed;
  Gate.Continuation=0;
  std::array<uint8_t,4> ResumeWord {};
  const auto Read=Memory::CopyManagedRX(Fresh,Thread,Gate.ResumeOffset,ResumeWord);
  if (!Read || ResumeWord!=Gate.ResumeWord) {
    const auto Exited=Memory::Exit(Fresh);
    if (!Exited) LogMan::Msg::EFmt("Pear failed-resume cleanup refused: status {}, domain {}, code {}",
                                Exited.Status,Exited.ErrorDomain,Exited.ErrorCode);
    const auto Original=Read ? Memory::Result{PEAR_FEX_STALE_IDENTITY,0,0} : Read.Outcome;
    return Memory::Retirement::PoisonSourceAdmission(Original);
  }
  const auto Released=Entry.Release();
  if (!Released) return Released;
  Gate.Open=false;
  return {PEAR_FEX_OK,0,0};
}

extern "C" { uint32_t PearFiniteCheckpoint {}; }

static FEXCore::Utils::PearFEXMemory::Result ExecutePearFinitePatchMatrix(
    FEXCore::Core::CpuStateFrame* Frame, uintptr_t ResumePC) {
  namespace M=FEXCore::Utils::PearFEXMemory;
  namespace A=FEXCore::ArchHelpers::Arm64;
  auto Life=M::AcquireCurrentSourceLifetime();
  auto* Thread=Life ? Life.ActualThread() : nullptr;
  auto* C=Life ? const_cast<ContextImpl*>(static_cast<const ContextImpl*>(Life.ActualContext())) : nullptr;
  if (!Thread || !C || !Thread->CPUBackend || !C->Dispatcher || Frame!=Thread->CurrentFrame ||
      Frame->Thread!=Thread || !M::HasManagedActive(C->Dispatcher->GetPearSnapshot())) return {PEAR_FEX_UNAVAILABLE,0,0};
  // Five selected source opcode families, four widths, both finite preparation
  // policies. The instruction words are data; no unaligned access is executed.
  constexpr uint32_t ExpectedBase[]={0x387f6800,0x387f6800,0x383f6800,0x38400000,0x38000000};
  for (uint32_t I=0;I<40;++I) {
    PearFiniteCheckpoint=256+I;
    const uint32_t Kind=(I/4)%5,Width=I%4,Addr=I%29+1,Data=(I*3)%31;
    const bool Half=I<20,Store=Kind==2 || Kind==4;
    const auto Mode=Half ? A::UnalignedHandlerType::HalfBarrier : A::UnalignedHandlerType::NonAtomic;
    const size_t Offset=1536+64*I;
    auto Window=Thread->CPUBackend->FindPearManagedWindow(Frame->State.InlineJITBlockHeader);
    if (!Window) return {PEAR_FEX_UNAVAILABLE,0,0};
    auto Target=Thread->CPUBackend->FindPearRetainedTarget(Window->Begin+Offset);
    if (!Target) return {PEAR_FEX_UNAVAILABLE,0,0};
    std::array<uint32_t,13> Words {};
    auto Read=M::CopyManagedRXUnderGlobalLease(C->Dispatcher->GetPearSnapshot(),*Target,Thread,Offset,
      {reinterpret_cast<uint8_t*>(Words.data()),sizeof(Words)});
    if (!Read) return Read.Outcome;
    const auto Prepared=A::PrepareUnalignedPatchSnapshot(Mode,Words);
    const uint32_t Immediate=Kind>=3 ? ((I&1) ? 0x1ff : 0xff)<<12 : 0;
    const uint32_t Expected=ExpectedBase[Kind]|(Width<<30)|(Addr<<5)|Data|Immediate;
    if (Prepared.Kind!=A::UnalignedPatchKind::Candidate || Prepared.StoreCount!=(Half ? 2 : 1) ||
        Prepared.StoreOrder[Prepared.StoreCount-1]!=1 || Prepared.Next[1]!=Expected ||
        Prepared.ResumeDelta!=(Store ? -4 : 0) ||
        (Half && (Prepared.StoreOrder[0]!=(Store ? 0 : 2) ||
          Prepared.Next[Store ? 0 : 2]!=(Store ? 0xd5033bbf : 0xd5033dbf))))
      return {PEAR_FEX_INVALID_REQUEST,0,0};
    ContextImpl::PearDispatcherGate Gate {};
    auto Outcome=C->BeginPearDispatcherGate(Frame,ResumePC,Gate);if (!Outcome) return Outcome;
    auto Transaction=Window->Owner->GetPearSnapshot();const auto Before=Transaction;
    {
      M::WriteGuard Write{Transaction,Offset,sizeof(Words)};
      if (!Write) return Write.Status();
      const auto ExpectedBytes=std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(Words.data()),sizeof(Words)};
      if (!Write.Matches(0,ExpectedBytes)) {
        const auto Aborted=Write.Abort();
        if (!Window->Owner->ComparePearUpdate(Before,Transaction) || !Aborted)
          return M::Retirement::PoisonSourceAdmission(!Aborted ? Aborted : M::Result{PEAR_FEX_STALE_IDENTITY,0,0});
        return {PEAR_FEX_STALE_IDENTITY,0,0};
      }
      for (uint32_t N=0;N<Prepared.StoreCount;++N) {
        const auto Index=Prepared.StoreOrder[N];
        std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(Write.Data()+4*Index)).store(Prepared.Next[Index],std::memory_order_release);
      }
      Outcome=Write.Publish();
      if (!Outcome) {
        const auto Aborted=Write.Abort();
        if (!Window->Owner->ComparePearUpdate(Before,Transaction) || !Aborted)
          M::Retirement::PoisonSourceAdmission(!Aborted ? Aborted : M::Result{PEAR_FEX_STALE_IDENTITY,0,0});
        return Outcome;
      }
      if (!Window->Owner->ComparePearUpdate(Before,Transaction)) return M::Retirement::PoisonSourceAdmission({PEAR_FEX_STALE_IDENTITY,0,0});
    }
    Outcome=C->FinishPearDispatcherGate(Gate);if (!Outcome) return Outcome;
    auto Fresh=Thread->CPUBackend->FindPearRetainedTarget(Window->Begin+Offset);
    if (!Fresh) return {PEAR_FEX_UNAVAILABLE,0,0};
    Read=M::CopyManagedRXUnderGlobalLease(C->Dispatcher->GetPearSnapshot(),*Fresh,Thread,Offset,
      {reinterpret_cast<uint8_t*>(Words.data()),sizeof(Words)});
    if (!Read) return Read.Outcome;
    const auto Again=A::PrepareUnalignedPatchSnapshot(Mode,Words);
    if (Words!=Prepared.Next || Again.Kind!=A::UnalignedPatchKind::AlreadyPatched ||
        Again.ResumeDelta!=(Half && Store ? -4 : 0)) return {PEAR_FEX_STALE_IDENTITY,0,0};
  }
  return {PEAR_FEX_OK,0,0};
}

static FEXCore::Utils::PearFEXMemory::Result ExecutePearFiniteBufferLifetimes(
    FEXCore::Core::CpuStateFrame* Frame, uintptr_t ResumePC) {
  namespace M=FEXCore::Utils::PearFEXMemory;
  auto Life=M::AcquireCurrentSourceLifetime();
  auto* Thread=Life ? Life.ActualThread() : nullptr;
  auto* C=Life ? const_cast<ContextImpl*>(static_cast<const ContextImpl*>(Life.ActualContext())) : nullptr;
  if (!Thread || !C || Frame!=Thread->CurrentFrame || Frame->Thread!=Thread || !C->Dispatcher ||
      !M::HasManagedActive(C->Dispatcher->GetPearSnapshot())) return {PEAR_FEX_UNAVAILABLE,0,0};
  ContextImpl::PearDispatcherGate Gate {};
  auto Outcome=C->BeginPearDispatcherGate(Frame,ResumePC,Gate);if (!Outcome) return Outcome;
  M::Allocation Previous {};
  for (uint32_t I=0;I<4;++I) {
    PearFiniteCheckpoint=320+I;
    const size_t Size=size_t(16*1024*1024)<<I;
    auto Buffer=FEXCore::CPU::CodeBuffer::CreatePear(Size,false,Outcome);
    if (!Buffer || !Outcome) return Outcome ? M::Result{PEAR_FEX_UNAVAILABLE,0,0} : Outcome;
    auto Facts=Buffer->GetPearSnapshot();
    if (!Facts || Facts.Token.extent_size!=Size || Facts.Token.expected_state!=PEAR_FEX_RESERVED_NONE ||
        Facts.Base || Buffer->UsableSize()!=Size-4096 || !Buffer->LookupCache)
      return {PEAR_FEX_STALE_IDENTITY,0,0};
    if (Previous.Token.allocation_id) {
      const auto Stale=M::Retire(Previous);
      if (Stale.Status!=PEAR_FEX_STALE_IDENTITY || Stale.ErrorDomain || Stale.ErrorCode ||
          (Facts.Token.allocation_id==Previous.Token.allocation_id && Facts.Token.generation==Previous.Token.generation))
        return {PEAR_FEX_STALE_IDENTITY,0,0};
    }
    // The final strong reference, not a weak reference or elapsed time,
    // controls original CodeBuffer destruction and retirement enqueue.
    std::weak_ptr<FEXCore::CPU::CodeBuffer> Weak=Buffer;
    auto Held=Buffer;Buffer.reset();
    if (Weak.expired()) return {PEAR_FEX_STALE_IDENTITY,0,0};
    Outcome=M::Retirement::DrainAtNativeGate();if (!Outcome) return Outcome;
    const auto Before=Held->GetPearSnapshot();auto Transaction=Before;
    {
      M::WriteGuard Probe{Transaction,0,16};
      if (!Probe) return Probe.Status();
      // No code or metadata is written. Observe native admission, then restore
      // the actual reserved state through the existing source abort path.
      Outcome=Probe.Abort();
      if (!Outcome) return Outcome;
      if (!Held->ComparePearUpdate(Before,Transaction) || Transaction.Base ||
          Transaction.Token.expected_state!=PEAR_FEX_RESERVED_NONE)
        return M::Retirement::PoisonSourceAdmission({PEAR_FEX_STALE_IDENTITY,0,0});
    }
    Facts=Held->GetPearSnapshot();
    Held.reset();
    if (!Weak.expired()) return {PEAR_FEX_STALE_IDENTITY,0,0};
    Outcome=M::Retirement::DrainAtNativeGate();if (!Outcome) return Outcome;
    Previous=Facts;
    const auto Retired=M::Retire(Facts);
    if (Retired.Status!=PEAR_FEX_STALE_IDENTITY || Retired.ErrorDomain || Retired.ErrorCode)
      return {PEAR_FEX_STALE_IDENTITY,0,0};
    Weak.reset();
  }
  return C->FinishPearDispatcherGate(Gate);
}

void ContextImpl::PearFiniteNativeTransfer(FEXCore::Core::CpuStateFrame* Frame, uintptr_t ResumePC,
                                          uintptr_t NativeTarget, FEXCore::Utils::PearFEXMemory::Result* Output) {
  namespace M=FEXCore::Utils::PearFEXMemory;
  // Only the fixed source wrapper calls this private experiment. Its x3 output
  // points into that still-live native frame; x2 retains the actual target.
  if (NativeTarget!=reinterpret_cast<uintptr_t>(&PearFiniteNativeTransfer)) return;
  PearFiniteCheckpoint=1;
  auto Life=M::AcquireCurrentSourceLifetime();
  auto* Thread=Life ? Life.ActualThread() : nullptr;
  if (!Thread || Frame!=Thread->CurrentFrame || Frame->Thread!=Thread || !Thread->CTX) return;
  auto* CTX=static_cast<ContextImpl*>(Thread->CTX);
  // Capture real header/tail and bounded instruction bytes under the actual
  // dispatcher ACTIVE lease. The retained target is minted by this backend.
  PearFrameBlockSnapshot Snapshot;
  PearFiniteCheckpoint=2;
  *Output=GetPearFrameBlockInfo(CTX,Thread,Snapshot);
  if (!*Output) return;
  PearFiniteCheckpoint=3;
  if (Snapshot.Tail.RIP!=0x1000 || Snapshot.Tail.GuestSize!=4 || !Snapshot.Tail.SingleInst ||
      CTX->GetGuestBlockEntry(Thread)!=0x1000 || !CTX->IsCurrentBlockSingleInst(Thread) ||
      !CTX->IsAddressInCurrentBlock(Thread,0x1000,1) ||
      CTX->RestoreRIPFromHostPC(Thread,Snapshot.BlockBegin)!=0x1000 ||
      CTX->RestoreRIPFromHostPC(Thread,Snapshot.BlockBegin+4)!=0x1001) {
    *Output={PEAR_FEX_STALE_IDENTITY,0,0};return;
  }
  std::array<uint32_t,13> Instructions {};
  PearFiniteCheckpoint=4;
  auto Read=M::CopyManagedRXUnderGlobalLease(Snapshot.Protection,*Snapshot.Target,Thread,128,
    {reinterpret_cast<uint8_t*>(Instructions.data()),sizeof(Instructions)});
  if (!Read) { *Output=Read.Outcome;return; }
  namespace A=FEXCore::ArchHelpers::Arm64;
  PearFiniteCheckpoint=5;
  const auto Prepared=A::PrepareUnalignedPatchSnapshot(A::UnalignedHandlerType::HalfBarrier,Instructions);
  if (Prepared.Kind!=A::UnalignedPatchKind::Candidate || Prepared.StoreCount!=2 ||
      Prepared.StoreOrder[0]!=2 || Prepared.StoreOrder[1]!=1 || Prepared.ResumeDelta!=0 ||
      Prepared.Next[1]!=0xf87f6820 || Prepared.Next[2]!=0xd5033dbf) {
    *Output={PEAR_FEX_INVALID_REQUEST,0,0};return;
  }
  auto Window=Thread->CPUBackend->FindPearManagedWindow(Snapshot.BlockBegin);
  if (!Window) { *Output={PEAR_FEX_UNAVAILABLE,0,0};return; }
  PearDispatcherGate Gate {};
  PearFiniteCheckpoint=6;
  *Output=CTX->BeginPearDispatcherGate(Frame,ResumePC,Gate);
  if (!*Output) return;
  // The actual original pin must block retirement. A deletion attempt closes
  // source admission permanently, so it belongs to a separate terminal control.
  auto Retired=Gate.Facts;
  const auto Refusal=M::Retire(Retired);
  if (Refusal.Status!=PEAR_FEX_UNAVAILABLE || Refusal.ErrorDomain || Refusal.ErrorCode) {
    *Output=Refusal ? M::Result{PEAR_FEX_STALE_IDENTITY,0,0} : Refusal; return;
  }
  PearFiniteCheckpoint=8;
  *Output=M::Poll(Gate.Facts,Gate.ResumeOffset,Gate.Continuation,Gate.OriginalPinEpoch);
  if (!*Output) return;
  // No managed read occurs while pinned. Validate the copied expected bytes
  // inside the actual closed write transaction, then apply upstream store order.
  auto Patched=Window->Owner->GetPearSnapshot();
  const auto BeforePatch=Patched;
  {
  PearFiniteCheckpoint=9;
    M::WriteGuard Write{Patched,128,sizeof(Instructions)};
    if (!Write) { *Output=Write.Status();return; }
    const auto Expected=std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(Prepared.Expected.data()),sizeof(Prepared.Expected)};
    const std::array<uint8_t,4> Wrong{};
  PearFiniteCheckpoint=10;
    if (Write.Matches(4,Wrong) || !Write.Matches(0,Expected)) {
      *Output={PEAR_FEX_STALE_IDENTITY,0,0};
      const auto Aborted=Write.Abort();
      if (!Window->Owner->ComparePearUpdate(BeforePatch,Patched)) M::Retirement::PoisonSourceAdmission(*Output);
      if (!Aborted) M::Retirement::PoisonSourceAdmission(Aborted);
      return;
    }
    for (uint32_t I=0;I<Prepared.StoreCount;++I) {
      const auto Index=Prepared.StoreOrder[I];
      std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(Write.Data()+4*Index)).store(Prepared.Next[Index],std::memory_order_release);
    }
  PearFiniteCheckpoint=11;
    *Output=Write.Publish();
    if (!*Output) {
      const auto Aborted=Write.Abort();
      if (!Window->Owner->ComparePearUpdate(BeforePatch,Patched)) M::Retirement::PoisonSourceAdmission(*Output);
      if (!Aborted) M::Retirement::PoisonSourceAdmission(Aborted);
      return;
    }
    if (!Window->Owner->ComparePearUpdate(BeforePatch,Patched)) {
      *Output=M::Retirement::PoisonSourceAdmission({PEAR_FEX_STALE_IDENTITY,0,0});return;
    }
  }
  PearFiniteCheckpoint=12;
  *Output=CTX->FinishPearDispatcherGate(Gate);
  if (!*Output) return;
  // Only the fixed original resume leaf is called, after atomic pin consumption
  // and the source's original expected-byte revalidation. No guest instruction.
  PearFiniteCheckpoint=13;
  auto Fresh=Thread->CPUBackend->FindPearRetainedTarget(Snapshot.BlockBegin);
  if (!Fresh) { *Output={PEAR_FEX_UNAVAILABLE,0,0};return; }
  Read=M::CopyManagedRXUnderGlobalLease(CTX->Dispatcher->GetPearSnapshot(),*Fresh,Thread,128,
    {reinterpret_cast<uint8_t*>(Instructions.data()),sizeof(Instructions)});
  if (!Read) { *Output=Read.Outcome;return; }
  PearFiniteCheckpoint=14;
  if (Instructions!=Prepared.Next) { *Output={PEAR_FEX_STALE_IDENTITY,0,0};return; }
  PearFiniteCheckpoint=15;
  const auto Again=A::PrepareUnalignedPatchSnapshot(A::UnalignedHandlerType::HalfBarrier,Instructions);
  if (Again.Kind!=A::UnalignedPatchKind::AlreadyPatched || Again.ResumeDelta!=0) {
    *Output={PEAR_FEX_INVALID_REQUEST,0,0};return;
  }
  PearFiniteCheckpoint=16;
  *Output=FEXCore::CPU::Arm64JITCore::ExecutePearFiniteLinks(Frame,ResumePC);
  if (!*Output) return;
  *Output=ExecutePearFinitePatchMatrix(Frame,ResumePC);
  if (!*Output) return;
  *Output=ExecutePearFiniteBufferLifetimes(Frame,ResumePC);
  if (!*Output) return;
  *Output=FEXCore::CPU::Arm64JITCore::ExecutePearFinitePublication(Frame,ResumePC);
  if (!*Output) return;
  // Earlier snapshots have completed their reads. Release their actual strong
  // references before testing last-reference retirement of the old backend.
  Fresh.reset(); Window.reset(); Snapshot.Target.reset();
  *Output=FEXCore::CPU::Arm64JITCore::ExecutePearFiniteBufferGrowth(Frame,ResumePC);
  if (!*Output) return;
  const auto Value=reinterpret_cast<uint32_t (*)()>(ResumePC)();
  if (Value!=42) *Output={PEAR_FEX_STALE_IDENTITY,0,0};
  if (*Output) PearFiniteCheckpoint=17;
}

uintptr_t ContextImpl::CompilePearFromDispatcher(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP,
                                                uint64_t MaxInst, uintptr_t ResumePC) {
  PearDispatcherGate Gate {};
  const auto Begun = BeginPearDispatcherGate(Frame, ResumePC, Gate);
  PEAR_FEX_REQUIRE_RESULT(!!Begun, "Pear dispatcher native handoff refused: status {}, domain {}, code {}", Begun);
  // D is native-pinned and this wrapper holds no source locks. Detached
  // generations may now wait/retire without blocking their own lookup lock.
  const auto Drained = FEXCore::Utils::PearFEXMemory::Retirement::DrainAtNativeGate();
  if (!Drained) LogMan::Msg::EFmt("Pear detached generation remains pending: status {}, domain {}, code {}",
                                 Drained.Status, Drained.ErrorDomain, Drained.ErrorCode);
  uintptr_t HostCode {};
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
  try {
    HostCode = CompilePearBlock(Frame, GuestRIP, MaxInst);
  } catch (...) {
    // Original compilation errors propagate only after the checked native gate
    // attempts to restore D; preserve failed cleanup as an additional error.
    const auto Finished = FinishPearDispatcherGate(Gate);
    if (!Finished) LogMan::Msg::EFmt("Pear compilation-exception resume refused: status {}, domain {}, code {}",
                                    Finished.Status, Finished.ErrorDomain, Finished.ErrorCode);
    throw;
  }
#else
  // No claim of exception/fatal unwinding on the selected no-exceptions target.
  HostCode = CompilePearBlock(Frame, GuestRIP, MaxInst);
#endif
  const auto Finished = FinishPearDispatcherGate(Gate);
  PEAR_FEX_REQUIRE_RESULT(!!Finished, "Pear dispatcher native resume refused: status {}, domain {}, code {}", Finished);
  PEAR_FEX_REQUIRE(HostCode, "Pear dispatcher compilation produced no admitted code target");
  return HostCode;
}
uintptr_t ContextImpl::CompilePearBlock(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP, uint64_t MaxInst) {
  auto Life=FEXCore::Utils::PearFEXMemory::AcquireCurrentSourceLifetime(this);
  auto* Thread=Life ? Life.ActualThread() : nullptr;
  const auto Executor=Life ? Life.Executor() : 0;
  if (!FEXCore::Utils::PearFEXMemory::Retirement::AdmissionOpen() || !Thread || !Thread->CPUBackend || Thread->CTX != this || Frame != Thread->CurrentFrame || !Frame || Frame->Thread!=Thread || !Executor ||
      CodeCache.IsGeneratingCache || FEXCore::Config::Get_ENABLECODECACHINGWIP() ||
      FEXCore::Config::Get_ENABLELAZYCODECACHINGWIP() || FEXCore::Config::Get_ENABLECODECACHEVALIDATION() ||
      DiskCache.IsReadingDiskCache() || DiskCache.IsWritingDiskCache() || DiskCache.IsValidating()) {
    LogMan::Msg::EFmt("Pear source thread, publication policy or native admission is unavailable"); { LogMan::Msg::EFmt("Pear compilation refusal step 1 guest {:X}",GuestRIP); return 0; }
  }
  FEXCore::Utils::PearFEXMemory::SourceMutationTurn Mutation {Life};
  if (!Mutation) {
    const auto E=Mutation.Status();
    LogMan::Msg::EFmt("Pear source mutation turn refused: status {}, domain {}, code {}",E.Status,E.ErrorDomain,E.ErrorCode);
    return 0;
  }
  SyscallHandler->PreCompile();
  CompileCodeResult Prepared {};
  fextl::vector<uint64_t> CodePages;
  uint64_t Revision {};
  {
    auto Guard = GuardSignalDeferringSection<std::shared_lock>(CodeInvalidationMutex, Thread);
    Revision = GetPearInvalidationRevision();
    if (!Revision || Revision == UINT64_MAX) { LogMan::Msg::EFmt("Pear compilation refusal step 2 guest {:X}",GuestRIP); return 0; }
    if (MaxInst != 1) if (const auto Found = Thread->LookupCache->FindBlock(Thread, GuestRIP)) {
      if (Thread->CPUBackend->FindPearManagedWindow(Found)) return Found;
      LogMan::Msg::EFmt("Pear compilation refusal step 3 guest {:X}",GuestRIP); return 0;
    }
    Thread->FrontendDecoder->SetupDecodeInstructionsAtEntry(Thread, GuestRIP, MaxInst);
    Prepared = CompileCode(Thread, GuestRIP, MaxInst);
    const auto Entry = Prepared.CompiledCode.EntryPoints.find(GuestRIP);
    if (Entry == Prepared.CompiledCode.EntryPoints.end() || !Entry->second) {
      Thread->CPUBackend->DiscardPreparedPublication(); { LogMan::Msg::EFmt("Pear compilation refusal step 4 guest {:X}",GuestRIP); return 0; }
    }
    if (!Prepared.DebugData) {
      const auto Found = reinterpret_cast<uintptr_t>(Entry->second);
      if (Thread->CPUBackend->FindPearManagedWindow(Found)) return Found;
      LogMan::Msg::EFmt("Pear compilation refusal step 5 guest {:X}",GuestRIP); return 0;
    }
    if (!Prepared.CompiledCode.PearPendingEmission || Prepared.CompiledCode.PearOwnerPublished) {
      Thread->CPUBackend->DiscardPreparedPublication(); { LogMan::Msg::EFmt("Pear compilation refusal step 6 guest {:X}",GuestRIP); return 0; }
    }
    if (Prepared.NeedsAddGuestCodeRanges) {
      const auto* Info = Thread->FrontendDecoder->GetDecodedBlockInfo();
      if (Info->CodePages.size() > 4096) {
        Thread->CPUBackend->DiscardPreparedPublication(); { LogMan::Msg::EFmt("Pear compilation refusal step 7 guest {:X}",GuestRIP); return 0; }
      }
      CodePages.assign(Info->CodePages.begin(), Info->CodePages.end());
    }
  }
  // No invalidation, list, lookup or thread-creation lock is held while the
  // exact owner request closes its gate and waits for actual native park ack.
  if (!Thread->CPUBackend->BeginPreparedPublication(Prepared.CompiledCode)) { LogMan::Msg::EFmt("Pear compilation refusal step 8 guest {:X}",GuestRIP); return 0; }
  {
    auto Guard = GuardSignalDeferringSection<std::shared_lock>(CodeInvalidationMutex, Thread);
    const bool Valid = Revision == GetPearInvalidationRevision() && Frame->Thread == Thread &&
      Thread->CTX == this && Frame == Thread->CurrentFrame &&
      Executor == FEXCore::Utils::PearFEXMemory::CurrentExecutor();
    if (!Thread->CPUBackend->FinishPreparedPublication(Prepared.CompiledCode, Valid)) { LogMan::Msg::EFmt("Pear compilation refusal step 9 guest {:X}",GuestRIP); return 0; }
    auto& Compiled = Prepared.CompiledCode;
    const auto Entry = Compiled.EntryPoints.find(GuestRIP);
    if (!Compiled.PearOwnerPublished || Compiled.PearPendingEmission || Entry == Compiled.EntryPoints.end() || !Entry->second) { LogMan::Msg::EFmt("Pear compilation refusal step 10 guest {:X}",GuestRIP); return 0; }
    // Preserve existing cache metadata semantics only after real publication
    // and local token compare/update. Disk-cache/signature profiling stays off.
    if (Prepared.NeedsAddGuestCodeRanges) {
      const auto Entries = Compiled.EntryPoints | std::views::keys;
      for (auto Page : CodePages) {
        if (Thread->LookupCache->AddBlockExecutableRange(Thread, Entries, Page, FEXCore::Utils::FEX_PAGE_SIZE))
          SyscallHandler->MarkGuestExecutableRange(Thread, Page, FEXCore::Utils::FEX_PAGE_SIZE);
      }
    }
    for (const auto& EntryPoint : Compiled.EntryPoints)
      Thread->LookupCache->AddBlockMapping(Thread, EntryPoint.first, CodePages, EntryPoint.second);
    Thread->CPUBackend->ClearRelocations();
    Thread->FrontendDecoder->ValidateDisownedOrFree();
    Thread->OpDispatcher->ValidateDisownedOrFree();
    return reinterpret_cast<uintptr_t>(Entry->second);
  }
}
#endif

uintptr_t ContextImpl::CompileBlock(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP, uint64_t MaxInst) {
  if constexpr (BLOCK_DEBUGGING) {
    // Block debugging logic is hand-written and needs to be handled with care.
    // Force MaxInst to only be one in this case.
    MaxInst = 1;

    // If the entrypoint is part of the single step targets then single step it.
    if (BlockDebuggerTracker.IsSingleStepTarget(GuestRIP)) {
      return CompileSingleStep(Frame, GuestRIP);
    }
  }

  auto Thread = Frame->Thread;

#ifdef PEAR_FEX_MEMORY_OWNER
  return CompilePearBlock(Frame, GuestRIP, MaxInst);
#endif
  FEXCORE_PROFILE_SCOPED("CompileBlock");
  FEXCORE_PROFILE_ACCUMULATION(Thread, AccumulatedJITTime);

  static_cast<ContextImpl*>(Thread->CTX)->SyscallHandler->PreCompile();

  // Invalidate might take a unique lock on this, to guarantee that during invalidation no code gets compiled
  auto lk = GuardSignalDeferringSection<std::shared_lock>(CodeInvalidationMutex, Thread);

  // Is the code in the cache?
  // The backends only check L1 and L2, not L3
  if (auto HostCode = Thread->LookupCache->FindBlock(Thread, GuestRIP)) {
    return HostCode;
  }

  Thread->FrontendDecoder->SetupDecodeInstructionsAtEntry(Thread, GuestRIP, MaxInst);

  std::optional<ExecutableFileSectionInfo> Region = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);
  std::optional<DiskCache::CodeHitData> Hit;
  std::optional<uint64_t> DiskCacheGuestCodeKey;
  {
    FEXCORE_PROFILE_ACCUMULATION(Thread, AccumulatedDiskCacheLookupTime);
    Hit = DiskCache.Lookup(Thread, Region, GuestRIP, DiskCacheGuestCodeKey);
    if (Hit && !DiskCache.IsValidating()) {
      auto LoadedCode = Thread->CPUBackend->LoadCachedCode(Hit->HostCode);
      if (LoadedCode.BlockBegin) {
        for (auto& CodePage : Hit->GuestPages) {
          if (Thread->LookupCache->AddBlockExecutableRange(Thread, Hit->EntryPointRIPs, CodePage, FEXCore::Utils::FEX_PAGE_SIZE)) {
            SyscallHandler->MarkGuestExecutableRange(Thread, CodePage, FEXCore::Utils::FEX_PAGE_SIZE);
          }
        }

        PEAR_FEX_REQUIRE(Hit->EntryPointRIPs.size() == Hit->EntryPointHostOffsets.size(), "Mismatched Disk Cache entrypoint pairs!");

        uintptr_t CachedHostCode = 0;
        for (size_t i = 0; i < Hit->EntryPointRIPs.size(); i++) {
          void* HostAddr = LoadedCode.BlockBegin + Hit->EntryPointHostOffsets[i];
          Thread->LookupCache->AddBlockMapping(Thread, Hit->EntryPointRIPs[i], Hit->GuestPages, HostAddr);
          if (Hit->EntryPointRIPs[i] == GuestRIP) {
            CachedHostCode = reinterpret_cast<uintptr_t>(HostAddr);
          }
        }

        PEAR_FEX_REQUIRE(CachedHostCode != 0, "Couldn't find GuestRIP in Disk Cache entrypoints!");

        FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedDiskCacheHitCount, 1);
        Thread->FrontendDecoder->DelayedDisownBuffer();

        Thread->FrontendDecoder->ValidateDisownedOrFree();
        Thread->OpDispatcher->ValidateDisownedOrFree();
        return CachedHostCode;
      }
    }
    FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedDiskCacheMissCount, 1);
  }

  // Accumulate a JIT count now, as even if another thread raced us, it should count as a compile.
  FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedJITCount, 1);

  auto [CompiledCode, DebugData, StartAddr, Length, NeedsAddGuestCodeRanges] = CompileCode(Thread, GuestRIP, MaxInst);
  auto CodePtr = CompiledCode.EntryPoints[GuestRIP];
  if (CodePtr == nullptr) {
    return 0;
  } else if (!DebugData) {
    // DebugData wasn't populated, indicating another thread raced us for compiling this block
    return reinterpret_cast<uintptr_t>(CodePtr);
  }

  if (DiskCacheGuestCodeKey && Hit && DiskCache.IsValidating()) {
    DiskCache.Validate(*DiskCacheGuestCodeKey, *Hit, CompiledCode, Region);
  }

  // if this ever fires, we need to serialize the offset into disk cache
  PEAR_FEX_REQUIRE(StartAddr == GuestRIP, "StartAddr offset from GuestRIP");

  // The core managed to compile the code.
  if (Config.BlockJITNaming()) {
    auto FragmentBasePtr = CompiledCode.BlockBegin;

    auto GuestRIPLookup = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);

    if (DebugData->Subblocks.size()) {
      for (auto& Subblock : DebugData->Subblocks) {
        auto BlockBasePtr = FragmentBasePtr + Subblock.HostCodeOffset;
        if (GuestRIPLookup) {
          Symbols.Register(Thread->SymbolBuffer.get(), BlockBasePtr, CompiledCode.Size, GuestRIPLookup->FileInfo.Filename,
                           GuestRIP - GuestRIPLookup->FileStartVA);
        } else {
          Symbols.Register(Thread->SymbolBuffer.get(), BlockBasePtr, GuestRIP, Subblock.HostCodeSize);
        }
      }
    } else {
      if (GuestRIPLookup) {
        Symbols.Register(Thread->SymbolBuffer.get(), FragmentBasePtr, CompiledCode.Size, GuestRIPLookup->FileInfo.Filename,
                         GuestRIP - GuestRIPLookup->FileStartVA);
      } else {
        Symbols.Register(Thread->SymbolBuffer.get(), FragmentBasePtr, GuestRIP, CompiledCode.Size);
      }
    }
  }

  if (Config.LibraryJITNaming() || Config.GDBSymbols()) {
    auto MappedSection = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);
    if (MappedSection) {
      if (Config.LibraryJITNaming()) {
        Symbols.RegisterNamedRegion(Thread->SymbolBuffer.get(), CodePtr, DebugData->HostCodeSize, MappedSection->FileInfo.Filename);
      }

      if (Config.GDBSymbols()) {
        GDBJITRegister(MappedSection->FileInfo, MappedSection->FileStartVA, GuestRIP, (uintptr_t)CodePtr, *DebugData);
      }
    }
  }

  fextl::vector<uint64_t> CodePages;

  if (NeedsAddGuestCodeRanges) {
    // Track in the guest to host map all entrypoints for all pages the compiled block touches, if any page didn't previously
    // contain code, inform the frontend so it can setup SMC detection.
    auto BlockInfo = Thread->FrontendDecoder->GetDecodedBlockInfo();
    CodePages.reserve(BlockInfo->CodePages.size());
    CodePages.insert(CodePages.end(), BlockInfo->CodePages.begin(), BlockInfo->CodePages.end());
    for (auto CodePage : BlockInfo->CodePages) {
      if (Thread->LookupCache->AddBlockExecutableRange(Thread, BlockInfo->EntryPoints, CodePage, FEXCore::Utils::FEX_PAGE_SIZE)) {
        SyscallHandler->MarkGuestExecutableRange(Thread, CodePage, FEXCore::Utils::FEX_PAGE_SIZE);
      }
    }
  }

  // Disk Cache
  if (!CodeCache.IsGeneratingCache) {
    if (DiskCacheGuestCodeKey) {
      std::span<const FEXCore::CPU::Relocation> Relocations;
      if (DebugData && DebugData->Relocations) {
        Relocations = *DebugData->Relocations;
      }
      std::span<const uint8_t> GuestCode = {reinterpret_cast<const uint8_t*>(StartAddr), Length};
      const Frontend::Decoder::DecodedBlockInformation* BlockInfo =
        NeedsAddGuestCodeRanges ? Thread->FrontendDecoder->GetDecodedBlockInfo() : nullptr;
      DiskCache.Store(Thread, Region, GuestRIP, *DiskCacheGuestCodeKey, GuestCode, CompiledCode, Relocations, BlockInfo);
    }

    if (CodeMapWriter && Region && Region->FileStartVA != 0) {
      CodeMapWriter->AppendBlock(*Region, GuestRIP);
    }
  }

  // Insert to lookup cache
  for (auto [GuestAddr, HostAddr] : CompiledCode.EntryPoints) {
    Thread->LookupCache->AddBlockMapping(Thread, GuestAddr, CodePages, HostAddr);
  }

  // Clear any relocations that might have been generated
  if (!CodeCache.IsGeneratingCache) {
    Thread->CPUBackend->ClearRelocations();
  }

  Thread->FrontendDecoder->ValidateDisownedOrFree();
  Thread->OpDispatcher->ValidateDisownedOrFree();

  return (uintptr_t)CodePtr;
}

uintptr_t ContextImpl::CompileSingleStep(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP) {

#ifdef PEAR_FEX_MEMORY_OWNER
  return CompilePearBlock(Frame, GuestRIP, 1);
#endif
  FEXCORE_PROFILE_SCOPED("CompileSingleStep");
  auto Thread = Frame->Thread;

  static_cast<ContextImpl*>(Thread->CTX)->SyscallHandler->PreCompile();

  // Invalidate might take a unique lock on this, to guarantee that during invalidation no code gets compiled
  auto lk = GuardSignalDeferringSection<std::shared_lock>(CodeInvalidationMutex, Thread);

  Thread->FrontendDecoder->SetupDecodeInstructionsAtEntry(Thread, GuestRIP, 1);
  auto [CompiledCode, DebugData, StartAddr, Length, _] = CompileCode(Thread, GuestRIP, 1);
  auto CodePtr = CompiledCode.EntryPoints[GuestRIP];
  if (CodePtr == nullptr) {
    return 0;
  }

  // Clear any relocations that might have been generated
  Thread->CPUBackend->ClearRelocations();

  return (uintptr_t)CodePtr;
}

#ifdef PEAR_FEX_MEMORY_OWNER
FEXCore::Utils::PearFEXMemory::Result ContextImpl::BeginPearLinkInvalidation(FEXCore::Core::InternalThreadState* Thread) {
  // Actual guest mutation must not start until this real retained target guard
  // succeeds outside every invalidation/lookup/list/ThreadCreation source lock.
  return FEXCore::CPU::PearJITLinks::BeginBatch(this,Thread);
}
FEXCore::Utils::PearFEXMemory::Result ContextImpl::FinishPearLinkInvalidation(FEXCore::Core::InternalThreadState* Thread) {
  return FEXCore::CPU::PearJITLinks::FinishBatch(this,Thread);
}
bool ContextImpl::PearLinkInvalidationAdmitted() const {
  return FEXCore::Utils::PearFEXMemory::Links::MutationAdmitted(this);
}
bool ContextImpl::RecordPearInvalidation() {
  auto Revision = PearInvalidationRevision.load(std::memory_order_acquire);
  while (Revision != UINT64_MAX) {
    if (PearInvalidationRevision.compare_exchange_weak(Revision, Revision+1, std::memory_order_acq_rel)) return true;
  }
  return false;
}
#endif
void ContextImpl::InvalidateCodeBuffersCodeRange(uint64_t Start, uint64_t Length) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearContextHold=FEXCore::Utils::PearFEXMemory::SourceLifecycle::HoldContext(this);
  PEAR_FEX_REQUIRE(!!PearContextHold,"Pear actual Context lifetime is unavailable");
#endif

#ifdef PEAR_FEX_MEMORY_OWNER
  PEAR_FEX_REQUIRE(PearLinkInvalidationAdmitted(),"Pear invalidation has no real pre-lock target write admission");
  PEAR_FEX_REQUIRE(RecordPearInvalidation(), "Pear invalidation revision exhausted");
#endif
  FEXCORE_PROFILE_SCOPED("InvalidateCodeBuffersCodeRange");

  PEAR_FEX_REQUIRE(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");
  std::scoped_lock lk {CodeBufferListLock};
  auto it = CodeBufferList.begin();
  while (it != CodeBufferList.end()) {
    if (auto Strong = it->lock()) {
      Strong->LookupCache->InvalidateRange(Start, Length);
      it++;
    } else {
      it = CodeBufferList.erase(it);
    }
  }
}

void ContextImpl::InvalidateThreadCachedCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearActor=FEXCore::Utils::PearFEXMemory::AcquireCurrentSourceLifetime(this);
  auto PearSourceHold=FEXCore::Utils::PearFEXMemory::SourceInvalidationHold::Acquire(PearActor,Thread);
  PEAR_FEX_REQUIRE(!!PearSourceHold,"Pear invalidation target lifetime is unavailable");
#endif

#ifdef PEAR_FEX_MEMORY_OWNER
  PEAR_FEX_REQUIRE(PearLinkInvalidationAdmitted(),"Pear invalidation has no real pre-lock target write admission");
  PEAR_FEX_REQUIRE(RecordPearInvalidation(), "Pear invalidation revision exhausted");
#endif
  PEAR_FEX_REQUIRE(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");

  // Ensures now-modified mappings aren't cached as being in their previous non-executable state.
  // Accessing FrontendDecoder is safe as the thread's code invalidation mutex must be locked here.
  Thread->FrontendDecoder->ResetExecutableRangeCache();

  if (Thread->LookupCache->InvalidateCacheRange(Start, Length)) {
    FEXCORE_PROFILE_SCOPED("InvalidateCallRet");

    // This may cause access violations in the thread on Windows as zeroing is not atomic, this is handled by the frontend
    Allocator::VirtualDontNeed(Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
  }
}

void ContextImpl::ThreadRemoveCodeEntryFromJit(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=FEXCore::Utils::PearFEXMemory::AcquireCurrentSourceLifetime();
  auto* ActualThread=PearSourceHold ? PearSourceHold.ActualThread() : nullptr;
  PEAR_FEX_REQUIRE(ActualThread && Frame==ActualThread->CurrentFrame && Frame->Thread==ActualThread && PearSourceHold.Validate(),
                    "Pear frame lifetime is unavailable");
#endif

  static_cast<ContextImpl*>(Frame->Thread->CTX)->SyscallHandler->InvalidateGuestCodeRange(Frame->Thread, GuestRIP, 1);
}

std::optional<CustomIRResult>
ContextImpl::AddCustomIREntrypoint(uintptr_t Entrypoint, CustomIREntrypointHandler Handler, void* Creator, void* Data) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearContextHold=FEXCore::Utils::PearFEXMemory::SourceLifecycle::HoldContext(this);
  PEAR_FEX_REQUIRE(!!PearContextHold,"Pear actual Context lifetime is unavailable");
#endif

  PEAR_FEX_REQUIRE(Config.Is64BitMode || !(Entrypoint >> 32), "64-bit Entrypoint in 32-bit mode {:x}", Entrypoint);

  std::unique_lock lk(CustomIRMutex);

  auto InsertedIterator = CustomIRHandlers.emplace(Entrypoint, CustomIRHandlerEntry {Handler, Creator, Data});
  HasCustomIRHandlers = true;

  if (!InsertedIterator.second) {
    const auto& [fn, Creator, Data] = InsertedIterator.first->second;
    return CustomIRResult(Creator, Data);
  }

  return std::nullopt;
}

void ContextImpl::AddThunkTrampolineIRHandler(uintptr_t Entrypoint, uintptr_t GuestThunkEntrypoint) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearContextHold=FEXCore::Utils::PearFEXMemory::SourceLifecycle::HoldContext(this);
  PEAR_FEX_REQUIRE(!!PearContextHold,"Pear actual Context lifetime is unavailable");
#endif

  PEAR_FEX_REQUIRE(Entrypoint, "Tried to link null pointer address to guest function");
  PEAR_FEX_REQUIRE(GuestThunkEntrypoint, "Tried to link address to null pointer guest function");
  if (!Config.Is64BitMode) {
    PEAR_FEX_REQUIRE((Entrypoint >> 32) == 0, "Tried to link 64-bit address in 32-bit mode");
    PEAR_FEX_REQUIRE((GuestThunkEntrypoint >> 32) == 0, "Tried to link 64-bit address in 32-bit mode");
  }

  LogMan::Msg::DFmt("Thunks: Adding guest trampoline from address {:#x} to guest function {:#x}", Entrypoint, GuestThunkEntrypoint);

  auto Result = AddCustomIREntrypoint(
    Entrypoint,
    [this, GuestThunkEntrypoint](uintptr_t Entrypoint, FEXCore::IR::IREmitter* emit) {
      auto IRHeader = emit->_IRHeader(emit->Invalid(), Entrypoint, 0, 0, 0, 0);
      auto Block = emit->CreateCodeNode(true, 0);
      IRHeader.first->Blocks = emit->WrapNode(Block);
      emit->SetCurrentCodeBlock(Block);

      const auto GPRSize = this->Config.Is64BitMode ? IR::OpSize::i64Bit : IR::OpSize::i32Bit;

      // Thunk entry-points don't get cached, don't need to be padded.
      if (GPRSize == IR::OpSize::i64Bit) {
        IR::Ref R = emit->_StoreRegister(emit->Constant(Entrypoint), GPRSize);
        R->Reg = IR::PhysicalRegister(IR::RegClass::GPRFixed, X86State::REG_R11).Raw;
      } else {
        emit->_StoreContextFPR(GPRSize, emit->_VCastFromGPR(IR::OpSize::i64Bit, IR::OpSize::i64Bit, emit->Constant(Entrypoint)),
                               offsetof(Core::CPUState, mm[0][0]));
      }
      emit->_ExitFunction(IR::OpSize::i64Bit, emit->Constant(GuestThunkEntrypoint), IR::BranchHint::None, emit->Invalid(), emit->Invalid());
    },
    ThunkHandler, (void*)GuestThunkEntrypoint);

  if (Result.has_value()) {
    if (Result->Creator != ThunkHandler) {
      ERROR_AND_DIE_FMT("Input address for AddThunkTrampoline is already linked by another module");
    }
    if (Result->Data != (void*)GuestThunkEntrypoint) {
      // NOTE: This may happen in Vulkan thunks if the Vulkan driver resolves two different symbols
      //       to the same function (e.g. vkGetPhysicalDeviceFeatures2/vkGetPhysicalDeviceFeatures2KHR)
      LogMan::Msg::EFmt("Input address for AddThunkTrampoline is already linked elsewhere");
    }
  }
}

void ContextImpl::AddForceTSOInformation(const IntervalList<uint64_t>& ValidRanges, fextl::set<uint64_t>&& Instructions) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearContextHold=FEXCore::Utils::PearFEXMemory::SourceLifecycle::HoldContext(this);
  PEAR_FEX_REQUIRE(!!PearContextHold,"Pear actual Context lifetime is unavailable");
#endif

#ifdef PEAR_FEX_MEMORY_OWNER
  PEAR_FEX_REQUIRE(CodeInvalidationMutex.try_lock() == false, "Pear source invalidation lock must already be owned");
#else
  LogMan::Throw::AFmt(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");
#endif
  ForceTSOValidRanges.Insert(ValidRanges);
  ForceTSOInstructions.merge(std::move(Instructions));
}

void ContextImpl::RemoveForceTSOInformation(uint64_t Address, uint64_t Size) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearContextHold=FEXCore::Utils::PearFEXMemory::SourceLifecycle::HoldContext(this);
  PEAR_FEX_REQUIRE(!!PearContextHold,"Pear actual Context lifetime is unavailable");
#endif

#ifdef PEAR_FEX_MEMORY_OWNER
  PEAR_FEX_REQUIRE(CodeInvalidationMutex.try_lock() == false, "Pear source invalidation lock must already be owned");
#else
  LogMan::Throw::AFmt(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");
#endif

  ForceTSOValidRanges.Remove({Address, Address + Size});
  ForceTSOInstructions.erase(ForceTSOInstructions.lower_bound(Address), ForceTSOInstructions.upper_bound(Address + Size));
}

void ContextImpl::MarkMonoBackpatcherBlock(uint64_t BlockEntry) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearContextHold=FEXCore::Utils::PearFEXMemory::SourceLifecycle::HoldContext(this);
  PEAR_FEX_REQUIRE(!!PearContextHold,"Pear actual Context lifetime is unavailable");
#endif

  MonoBackpatcherBlock.store(BlockEntry, std::memory_order_relaxed);
}

void ContextImpl::RemoveCustomIREntrypoint(FEXCore::Core::InternalThreadState* Thread, uintptr_t Entrypoint) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=RequirePearSourceThread(this,Thread);
#endif

  PEAR_FEX_REQUIRE(Config.Is64BitMode || !(Entrypoint >> 32), "64-bit Entrypoint in 32-bit mode {:x}", Entrypoint);

  std::scoped_lock lk(CustomIRMutex);

  CustomIRHandlers.erase(Entrypoint);
  HasCustomIRHandlers = !CustomIRHandlers.empty();
  SyscallHandler->InvalidateGuestCodeRange(Thread, Entrypoint, 1);
}

void ContextImpl::MonoBackpatcherWrite(FEXCore::Core::CpuStateFrame* Frame, uint8_t Size, uint64_t Address, uint64_t Value) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=FEXCore::Utils::PearFEXMemory::AcquireCurrentSourceLifetime();
  auto* ActualThread=PearSourceHold ? PearSourceHold.ActualThread() : nullptr;
  PEAR_FEX_REQUIRE(ActualThread && Frame==ActualThread->CurrentFrame && Frame->Thread==ActualThread && PearSourceHold.Validate(),
                    "Pear frame lifetime is unavailable");
#endif

  auto Thread = Frame->Thread;
  auto CTX = static_cast<ContextImpl*>(Thread->CTX);
  {
    auto lk = GuardSignalDeferringSection(CTX->CodeInvalidationMutex, Thread);

    if (Size == 8) {
      *reinterpret_cast<uint64_t*>(Address) = Value;
    } else if (Size == 4) {
      *reinterpret_cast<uint32_t*>(Address) = Value;
    } else {
      ERROR_AND_DIE_FMT("Unexpected write size for backpatcher: {}", Size);
    }
  }

  CTX->SyscallHandler->InvalidateGuestCodeRange(Thread, Address, Size);
}

void ContextImpl::ConfigureAOTGen(FEXCore::Core::InternalThreadState* Thread, fextl::set<uint64_t>* ExternalBranches, uint64_t SectionMaxAddress) {
#ifdef PEAR_FEX_MEMORY_OWNER
  auto PearSourceHold=RequirePearSourceThread(this,Thread);
#endif

  Thread->FrontendDecoder->SetExternalBranches(ExternalBranches);
}
} // namespace FEXCore::Context
