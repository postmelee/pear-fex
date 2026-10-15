#ifdef PEAR_FEX_DARWIN
#include "Common/DarwinConfigPolicy.h"
#endif
// SPDX-License-Identifier: MIT
/*
$info$
tags: Bin|WOW64
desc: Implements the WOW64 BT module API using FEXCore
$end_info$
*/

// Thanks to André Zwing, whose ideas from https://github.com/AndreRH/hangover this code is based upon

#include <FEXCore/fextl/fmt.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/Context.h>
#ifdef PEAR_FEX_MEMORY_OWNER
#include <FEXCore/Utils/PearFEXMemory.h>
#include <atomic>
#include <mutex>
#endif
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/DiskCacheFileMapper.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/SHMStats.h>
#include <FEXCore/Utils/EnumOperators.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/FPState.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Utils/SignalScopeGuards.h>

#include "Windows/Common/Allocator.h"
#include "Windows/Common/EnvironmentVariablesHandling.h"
#include "Windows/Common/FEXUnixLib.h"
#include "Common/CallRetStack.h"
#include "Common/JITGuardPage.h"
#include "Common/Config.h"
#include "Common/Exception.h"
#include "Common/TSOHandlerConfig.h"
#include "Common/ImageTracker.h"
#include "Common/InvalidationTracker.h"
#include "Common/Threads.h"
#include "Common/OvercommitTracker.h"
#include "Common/CPUFeatures.h"
#include "Common/Logging.h"
#include "Common/Module.h"
#include "Common/CRT/CRT.h"
#include "Common/PortabilityInfo.h"
#include "Common/Handle.h"
#include "DummyHandlers.h"
#include "BTInterface.h"
#include "Windows/Common/SHMStats.h"

#include <cstdint>
#include <type_traits>
#include <atomic>
#include <mutex>
#include <utility>
#include <unordered_map>
#include <ntstatus.h>
#include <windef.h>
#include <winternl.h>
#include <wine/debug.h>
#include <wine/unixlib.h>

struct TLS {
  enum class Slot : size_t {
    ENTRY_CONTEXT = WOW64_TLS_MAX_NUMBER - 1,
    CONTROL_WORD = WOW64_TLS_MAX_NUMBER - 2,
    THREAD_STATE = WOW64_TLS_MAX_NUMBER - 3,
    CACHED_CALLRET_SP = WOW64_TLS_MAX_NUMBER - 4,
  };

  _TEB* TEB;

  explicit TLS(_TEB* TEB)
    : TEB(TEB) {}

  WOW64INFO& Wow64Info() const {
    return *reinterpret_cast<WOW64INFO*>(TEB->TlsSlots[WOW64_TLS_WOW64INFO]);
  }

  std::atomic<uint32_t>& ControlWord() const {
    // TODO: Change this when libc++ gains std::atomic_ref support
    return reinterpret_cast<std::atomic<uint32_t>&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::CONTROL_WORD)]);
  }

  uint32_t* ControlWordAddress() const {
    return reinterpret_cast<uint32_t*>(&TEB->TlsSlots[FEXCore::ToUnderlying(Slot::CONTROL_WORD)]);
  }

  CONTEXT*& EntryContext() const {
    return reinterpret_cast<CONTEXT*&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::ENTRY_CONTEXT)]);
  }

  FEXCore::Core::InternalThreadState*& ThreadState() const {
    return reinterpret_cast<FEXCore::Core::InternalThreadState*&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::THREAD_STATE)]);
  }

  // This is used to work around user callback handling (see Wow64KiUserCallbackDispatcher in wine) unbalancing the
  // call-ret stace since user callbacks are returned from using a syscall that we can't really intercept.
  uint64_t& CachedCallRetSp() const {
    return reinterpret_cast<uint64_t&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::CACHED_CALLRET_SP)]);
  }
};

CHPE_V2_CPU_AREA_INFO*& GetCpuArea() {
  return ((__TEB*)NtCurrentTeb())->ChpeV2CpuAreaInfo;
}

WOW64_CONTEXT* GetWow64Context() {
  WOW64_CONTEXT* WowContext;
  RtlWow64GetCurrentCpuArea(nullptr, reinterpret_cast<void**>(&WowContext), nullptr);
  return WowContext;
}

struct FrontendThreadData {
  bool InLockedRWXRead {};
  CHPE_V2_CPU_AREA_INFO CpuArea {};

  FrontendThreadData(FEXCore::Core::InternalThreadState* Thread) {
    CpuArea.SuspendDoorbell = reinterpret_cast<ULONG*>(&Thread->CurrentFrame->SuspendDoorbell);
#ifndef PEAR_FEX_MEMORY_OWNER
    GetCpuArea() = &CpuArea;
#endif
  }

  ~FrontendThreadData() {
#ifdef PEAR_FEX_MEMORY_OWNER
    if (GetCpuArea() == &CpuArea) GetCpuArea() = nullptr;
#else
    GetCpuArea() = nullptr;
#endif
  }
};

class WowSyscallHandler;

namespace {
namespace BridgeInstrs {
  // These directly jumped to by the guest to make system calls
  void* Syscall {};
  void* UnixCall {};
} // namespace BridgeInstrs

#ifdef PEAR_FEX_MEMORY_OWNER
FEXCore::Context::PearContextOwner CTX;
#else
fextl::unique_ptr<FEXCore::Context::Context> CTX;
#endif
fextl::unique_ptr<FEX::DummyHandlers::DummySignalDelegator> SignalDelegator;
fextl::unique_ptr<WowSyscallHandler> SyscallHandler;
fextl::unique_ptr<FEX::Windows::StatAlloc> StatAllocHandler;

std::optional<FEX::Windows::InvalidationTracker> InvalidationTracker;
std::optional<FEX::Windows::CPUFeatures> CPUFeatures;
std::optional<FEX::Windows::OvercommitTracker> OvercommitTracker;
std::optional<FEX::Windows::ImageTracker> ImageTracker;

std::mutex ThreadCreationMutex;
// Map of TIDs to their FEX thread state, `ThreadCreationMutex` must be locked when accessing
std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*> Threads;

#ifdef PEAR_FEX_MEMORY_OWNER
namespace PearMemory = FEXCore::Utils::PearFEXMemory;
std::atomic<bool> PearSourceReady {false};
std::atomic<NTSTATUS> PearSourceStatus {STATUS_NOT_SUPPORTED};
static_assert(std::atomic<NTSTATUS>::is_always_lock_free, "Raw refusal status must not acquire a hidden lock");
// Actual bridge/source-construction results retain their native error domain.
// These private records are not exports and do not assert runtime admission.
std::mutex PearOutcomeMutex;
PearMemory::Result PearPrimaryOutcome {};
PearMemory::Result PearCleanupOutcome {};
bool PearHasPrimaryOutcome {};
bool PearHasCleanupOutcome {};
void PearRecordPrimary(PearMemory::Result Outcome) {
  std::scoped_lock Lock(PearOutcomeMutex);
  if (!PearHasPrimaryOutcome) { PearPrimaryOutcome = Outcome; PearHasPrimaryOutcome = true; }
}
void PearRecordCleanup(PearMemory::Result Outcome) {
  std::scoped_lock Lock(PearOutcomeMutex);
  if (!PearHasCleanupOutcome || PearCleanupOutcome) {
    PearCleanupOutcome = Outcome; PearHasCleanupOutcome = true;
  }
}
NTSTATUS PearFailureStatus(const PearMemory::Result& Outcome) {
  // Only a real signed NTSTATUS domain is forwarded as the source NTSTATUS.
  // Other native domains stay intact in the private Result, not reinterpreted.
  return Outcome.ErrorDomain == PEAR_FEX_ERROR_NTSTATUS && Outcome.ErrorCode ?
    static_cast<NTSTATUS>(Outcome.ErrorCode) : STATUS_NOT_SUPPORTED;
}
// One bounded in-progress slot per actual TID prevents owner-wait reentry from
// constructing an additional source ThreadState before final publication.
DWORD PearPendingTIDs[64] {};
static_assert(sizeof(PearPendingTIDs) == 256, "Bounded Module pending NX ledger");
inline constexpr size_t PearModuleNXMetadataBytes = sizeof(PearPendingTIDs) +
  sizeof(PearSourceReady) + sizeof(PearSourceStatus) + sizeof(PearOutcomeMutex) +
  sizeof(PearPrimaryOutcome) + sizeof(PearCleanupOutcome) +
  sizeof(PearHasPrimaryOutcome) + sizeof(PearHasCleanupOutcome);
static_assert(PearModuleNXMetadataBytes <= 1024, "Module ledger enters aggregate NX accounting");
class PearThreadPreparation {
public:
  PearThreadPreparation() : TID(GetCurrentThreadId()) {
    std::scoped_lock Lock(ThreadCreationMutex);
    if (!TID || Threads.contains(TID)) return;
    DWORD* Empty {};
    for (auto& Pending : PearPendingTIDs) {
      if (Pending == TID) return;
      if (!Pending && !Empty) Empty = &Pending;
    }
    if (!Empty) { Failure = STATUS_NO_MEMORY; return; }
    *Empty = TID; Owned = true;
  }
  ~PearThreadPreparation() {
    if (!Owned) return;
    // A constructor/ordinary metadata exception preserves the original
    // exception. It cannot leave mandatory followups treating setup as ready.
    if (!Committed) PearSourceReady.store(false, std::memory_order_release);
    std::scoped_lock Lock(ThreadCreationMutex);
    for (auto& Pending : PearPendingTIDs) if (Pending == TID) { Pending = 0; break; }
  }
  void Commit() { Committed = true; }
  explicit operator bool() const { return Owned; }
  DWORD ID() const { return TID; }
  NTSTATUS Status() const { return Failure; }
private:
  DWORD TID {};
  NTSTATUS Failure {STATUS_NOT_SUPPORTED};
  bool Owned {};
  bool Committed {};
};
#endif


decltype(__wine_unix_call_dispatcher) WineUnixCall;

std::pair<NTSTATUS, TLS> GetThreadTLS(HANDLE Thread) {
  THREAD_BASIC_INFORMATION Info;
  const NTSTATUS Err = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), nullptr);
  return {Err, TLS {reinterpret_cast<_TEB*>(Info.TebBaseAddress)}};
}

TLS GetTLS() {
  return TLS {NtCurrentTeb()};
}

FrontendThreadData* GetFrontendThreadData(FEXCore::Core::InternalThreadState* Thread) {
  return static_cast<FrontendThreadData*>(Thread->FrontendPtr);
}

uint64_t GetWowTEB(void* TEB) {
  static constexpr size_t WowTEBOffsetMemberOffset {0x180c};
  return static_cast<uint64_t>(
    *reinterpret_cast<LONG*>(reinterpret_cast<uintptr_t>(TEB) + WowTEBOffsetMemberOffset) + reinterpret_cast<uint64_t>(TEB));
}

bool IsDispatcherAddress(uint64_t Address) {
  const auto& Config = SignalDelegator->GetConfig();
  return Address >= Config.DispatcherBegin && Address < Config.DispatcherEnd;
}

bool IsAddressInJit(uint64_t Address) {
  if (IsDispatcherAddress(Address)) {
    return true;
  }

  auto Thread = GetTLS().ThreadState();
  return Thread->CTX->IsAddressInCodeBuffer(Thread, Address);
}

void HandleImageMap(uint64_t Address, bool MainImage = false) {
  fextl::string ModulePath = FEX::Windows::GetSectionFilePath(Address);
  fextl::string ModuleName = fextl::string {FEX::Windows::BaseName(ModulePath)};
  InvalidationTracker->HandleImageMap(ModuleName, Address);
  ImageTracker->HandleImageMap(ModulePath, Address, MainImage);
}

void HandleImageUnmap(uint64_t Address, uint64_t Size) {
  ImageTracker->HandleImageUnmap(Address, Size);
}
} // namespace

namespace Context {
void LoadStateFromWowContext(FEXCore::Core::InternalThreadState* Thread) {
  auto& State = Thread->CurrentFrame->State;
  WOW64_CONTEXT* Context = GetWow64Context();

  // General register state

  State.gregs[FEXCore::X86State::REG_RAX] = Context->Eax;
  State.gregs[FEXCore::X86State::REG_RBX] = Context->Ebx;
  State.gregs[FEXCore::X86State::REG_RCX] = Context->Ecx;
  State.gregs[FEXCore::X86State::REG_RDX] = Context->Edx;
  State.gregs[FEXCore::X86State::REG_RSI] = Context->Esi;
  State.gregs[FEXCore::X86State::REG_RDI] = Context->Edi;
  State.gregs[FEXCore::X86State::REG_RBP] = Context->Ebp;
  State.gregs[FEXCore::X86State::REG_RSP] = Context->Esp;

  State.rip = Context->Eip;
  CTX->SetFlagsFromCompactedEFLAGS(Thread, Context->EFlags);

  State.es_idx = Context->SegEs & 0xffff;
  State.cs_idx = Context->SegCs & 0xffff;
  State.ss_idx = Context->SegSs & 0xffff;
  State.ds_idx = Context->SegDs & 0xffff;
  State.fs_idx = Context->SegFs & 0xffff;
  State.gs_idx = Context->SegGs & 0xffff;

  // The TEB is the only populated GDT entry by default
  auto GDT = State.GetSegmentFromIndex(State, (Context->SegFs & 0xffff));
  uint64_t WowTEB = GetWowTEB(NtCurrentTeb());
  State.SetGDTBase(GDT, WowTEB);
  State.SetGDTLimit(GDT, 0xF'FFFFU);
  State.fs_cached = WowTEB;
  State.es_cached = 0;
  State.cs_cached = 0;
  State.ss_cached = 0;
  State.ds_cached = 0;

  // Floating-point register state
  const auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters);

  CTX->SetXMMRegistersFromState(Thread, reinterpret_cast<const __uint128_t*>(XSave->XmmRegisters), nullptr);
  memcpy(State.mm, XSave->FloatRegisters, sizeof(State.mm));

  State.FCW = XSave->ControlWord;
  State.flags[FEXCore::X86State::X87FLAG_IE_LOC] = XSave->StatusWord & 1;
  State.flags[FEXCore::X86State::X87FLAG_C0_LOC] = (XSave->StatusWord >> 8) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C1_LOC] = (XSave->StatusWord >> 9) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = (XSave->StatusWord >> 10) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C3_LOC] = (XSave->StatusWord >> 14) & 1;
  State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = (XSave->StatusWord >> 11) & 0b111;
  State.AbridgedFTW = XSave->TagWord;
}

void StoreWowContextFromState(WOW64_CONTEXT* Context) {
  auto Thread = GetTLS().ThreadState();
  auto& State = Thread->CurrentFrame->State;

  // General register state

  Context->Eax = State.gregs[FEXCore::X86State::REG_RAX];
  Context->Ebx = State.gregs[FEXCore::X86State::REG_RBX];
  Context->Ecx = State.gregs[FEXCore::X86State::REG_RCX];
  Context->Edx = State.gregs[FEXCore::X86State::REG_RDX];
  Context->Esi = State.gregs[FEXCore::X86State::REG_RSI];
  Context->Edi = State.gregs[FEXCore::X86State::REG_RDI];
  Context->Ebp = State.gregs[FEXCore::X86State::REG_RBP];
  Context->Esp = State.gregs[FEXCore::X86State::REG_RSP];

  Context->Eip = State.rip;
  Context->EFlags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);

  Context->SegEs = State.es_idx;
  Context->SegCs = State.cs_idx;
  Context->SegSs = State.ss_idx;
  Context->SegDs = State.ds_idx;
  Context->SegFs = State.fs_idx;
  Context->SegGs = State.gs_idx;

  // Floating-point register state

  auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters);

  CTX->ReconstructXMMRegisters(Thread, reinterpret_cast<__uint128_t*>(XSave->XmmRegisters), nullptr);
  memcpy(XSave->FloatRegisters, State.mm, sizeof(State.mm));

  XSave->ControlWord = State.FCW;
  XSave->StatusWord = (State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] << 11) | (State.flags[FEXCore::X86State::X87FLAG_C0_LOC] << 8) |
                      (State.flags[FEXCore::X86State::X87FLAG_C1_LOC] << 9) | (State.flags[FEXCore::X86State::X87FLAG_C2_LOC] << 10) |
                      (State.flags[FEXCore::X86State::X87FLAG_C3_LOC] << 14) | State.flags[FEXCore::X86State::X87FLAG_IE_LOC];
  XSave->TagWord = State.AbridgedFTW;

  Context->FloatSave.ControlWord = XSave->ControlWord;
  Context->FloatSave.StatusWord = XSave->StatusWord;
  Context->FloatSave.TagWord = FEXCore::FPState::ConvertFromAbridgedFTW(XSave->StatusWord, State.mm, XSave->TagWord);
  Context->FloatSave.ErrorOffset = XSave->ErrorOffset;
  Context->FloatSave.ErrorSelector = XSave->ErrorSelector | (XSave->ErrorOpcode << 16);
  Context->FloatSave.DataOffset = XSave->DataOffset;
  Context->FloatSave.DataSelector = XSave->DataSelector;
  Context->FloatSave.Cr0NpxState = XSave->StatusWord | 0xffff0000;
}

void FlushThreadStateContext() {
  StoreWowContextFromState(GetWow64Context());
}

void ReconstructThreadState(CONTEXT* Context) {
  const auto& Config = SignalDelegator->GetConfig();
  auto* Thread = GetTLS().ThreadState();
  auto& State = Thread->CurrentFrame->State;

  State.rip = CTX->RestoreRIPFromHostPC(Thread, Context->Pc);

  // Spill all SRA GPRs
  for (size_t i = 0; i < Config.SRAGPRCount; i++) {
    State.gregs[i] = Context->X[Config.SRAGPRMapping[i]];
  }

  // Spill all SRA FPRs
  for (size_t i = 0; i < Config.SRAFPRCount; i++) {
    memcpy(State.xmm.sse.data[i], &Context->V[Config.SRAFPRMapping[i]], sizeof(__uint128_t));
  }

  // Spill EFlags
  uint32_t EFlags = CTX->ReconstructCompactedEFLAGS(Thread, true, Context->X, Context->Cpsr);
  CTX->SetFlagsFromCompactedEFLAGS(Thread, EFlags);
}

WOW64_CONTEXT* ReconstructWowContext(CONTEXT* Context) {
  if (!IsDispatcherAddress(Context->Pc)) {
    ReconstructThreadState(Context);
  }

  WOW64_CONTEXT* WowContext = GetWow64Context();
  auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(WowContext->ExtendedRegisters);
  XSave->ControlWord = 0x27f;
  XSave->MxCsr = 0x1f80;

  StoreWowContextFromState(WowContext);
  return WowContext;
}

static std::optional<FEX::Windows::TSOHandlerConfig> HandlerConfig;

bool HandleUnalignedAccess(CONTEXT* Context) {
  auto Thread = GetTLS().ThreadState();
  if (!Thread->CTX->IsAddressInCodeBuffer(Thread, Context->Pc)) {
    return false;
  }

  const auto Result =
    FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(Thread, HandlerConfig->GetUnalignedHandlerType(), Context->Pc, &Context->X0);
  Context->Pc += Result.value_or(0);
  return Result.has_value();
}

void LockJITContext() {
  GetCpuArea()->InSimulation = -1;
  LoadStateFromWowContext(GetTLS().ThreadState());
}

void UnlockJITContext() {
  CHPE_V2_CPU_AREA_INFO* CpuArea = GetCpuArea();
  CpuArea->InSimulation = 0;
  if (*CpuArea->SuspendDoorbell) {
    CONTEXT ResumeContext;
    RtlCaptureContext(&ResumeContext);
    if (*CpuArea->SuspendDoorbell) {
      NtContinue(&ResumeContext, FALSE);
    }
  }
}

bool HandleSuspendInterrupt(CONTEXT* Context) {
  static constexpr uint32_t SuspendTrapMagic {0xD4395FC0}; // brk #0xCAFE
  if (*reinterpret_cast<uint32_t*>(Context->Pc) != SuspendTrapMagic) {
    return false;
  }

  // Since interrupts only happen at the start of blocks, the reconstructed state should be entirely accurate
  ReconstructThreadState(Context);
  FlushThreadStateContext();

  // Yield to the suspender
  UnlockJITContext();
  LockJITContext();

  // Adjust context to return to the dispatcher, reloading SRA from thread state
  const auto& Config = SignalDelegator->GetConfig();
  Context->Pc = Config.AbsoluteLoopTopAddressFillSRA;
  Context->X1 = 0; // Set ENTRY_FILL_SRA_SINGLE_INST_REG
  return true;
}
} // namespace Context

// Calls a 1-argument function `Func` setting the parent unwind frame information to the given SP and PC
__attribute__((naked)) extern "C" uint64_t SEHFrameTrampoline1Args(void* Arg0, void* Func, uint64_t Sp, uint64_t Pc) {
  asm(".seh_proc SEHFrameTrampoline1Args;"
      "stp x2, x3, [sp, #-0x10]!;"
      ".seh_pushframe;"
      "stp x29, x30, [sp, #-0x10]!;"
      ".seh_save_fplr_x 16;"
      ".seh_endprologue;"
      "blr x1;"
      "ldp x29, x30, [sp], 0x20;"
      "ret;"
      ".seh_endproc;");
}

// Calls a 2-argument function `Func` setting the parent unwind frame information to the given SP and PC
__attribute__((naked)) extern "C" uint64_t SEHFrameTrampoline2Args(void* Arg0, void* Arg1, void* Func, uint64_t Sp, uint64_t Pc) {
  asm(".seh_proc SEHFrameTrampoline2Args;"
      "stp x3, x4, [sp, #-0x10]!;"
      ".seh_pushframe;"
      "stp x29, x30, [sp, #-0x10]!;"
      ".seh_save_fplr_x 16;"
      ".seh_endprologue;"
      "blr x2;"
      "ldp x29, x30, [sp], 0x20;"
      "ret;"
      ".seh_endproc;");
}

class WowSyscallHandler : public FEXCore::HLE::SyscallHandler, public FEXCore::Allocator::FEXAllocOperators {
public:
  WowSyscallHandler() = default;

  static void HandleSyscallImpl(FEXCore::Core::CpuStateFrame* Frame) {
    const uint64_t ReturnRIP = *(uint32_t*)(Frame->State.gregs[FEXCore::X86State::REG_RSP]); // Return address from the stack
    uint64_t ReturnRSP = Frame->State.gregs[FEXCore::X86State::REG_RSP] + 4;                 // Stack pointer after popping return address
    uint64_t ReturnRAX = 0;

    if (Frame->State.rip == (uint64_t)BridgeInstrs::UnixCall) {
      struct StackLayout {
        unixlib_handle_t Handle;
        UINT32 ID;
        ULONG32 Args;
      }* StackArgs = reinterpret_cast<StackLayout*>(ReturnRSP);

      Frame->State.gregs[FEXCore::X86State::REG_RSP] = ReturnRSP + sizeof(StackLayout);
      Frame->State.rip = ReturnRIP;

      Context::FlushThreadStateContext();
      Context::UnlockJITContext();
      ReturnRAX = static_cast<uint64_t>(WineUnixCall(StackArgs->Handle, StackArgs->ID, ULongToPtr(StackArgs->Args)));
      Context::LockJITContext();
      Frame->State.gregs[FEXCore::X86State::REG_RAX] = ReturnRAX;
    } else if (Frame->State.rip == (uint64_t)BridgeInstrs::Syscall) {
      const uint64_t EntryRAX = Frame->State.gregs[FEXCore::X86State::REG_RAX];

      Frame->State.gregs[FEXCore::X86State::REG_RSP] = ReturnRSP;
      Frame->State.rip = ReturnRIP;

      Context::FlushThreadStateContext();
      Context::UnlockJITContext();
      Wow64ProcessPendingCrossProcessItems();
      ReturnRAX = static_cast<uint64_t>(Wow64SystemServiceEx(static_cast<UINT>(EntryRAX), reinterpret_cast<UINT*>(ReturnRSP + 4)));
      Context::LockJITContext();
      Frame->State.gregs[FEXCore::X86State::REG_RAX] = ReturnRAX;
    }
  }

  void HandleSyscall(FEXCore::Core::CpuStateFrame* Frame) override {
    const auto TLS = GetTLS();
    // Stash the the context pointer on the stack, as Simulate can be called from this syscall handler which would overwrite it
    CONTEXT* EntryContext = TLS.EntryContext();
    // Call the syscall handler with unwind information pointing to Simulate as its caller
    SEHFrameTrampoline1Args(reinterpret_cast<void*>(Frame), reinterpret_cast<void*>(&HandleSyscallImpl), EntryContext->Sp, EntryContext->Pc);
    TLS.EntryContext() = EntryContext;
  }

  std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(FEXCore::Core::InternalThreadState*, uint64_t Address) override {
    return ImageTracker->LookupExecutableFileSection(Address);
  }

  void MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {
    InvalidationTracker->ReprotectRWXIntervals(Start, Length);
  }

  void InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {
    InvalidationTracker->InvalidateAlignedInterval(Start, Length, false);
  }

  void MarkOvercommitRange(uint64_t Start, uint64_t Length) override {
    OvercommitTracker->MarkRange(Start, Length);
  }

  void UnmarkOvercommitRange(uint64_t Start, uint64_t Length) override {
    OvercommitTracker->UnmarkRange(Start, Length);
  }

  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) override {
    return InvalidationTracker->QueryExecutableRange(Address);
  }

  void PreCompile() override {
    Wow64ProcessPendingCrossProcessItems();
  }
};


#ifdef PEAR_FEX_MEMORY_OWNER
static void PearCleanupPartialContext(NTSTATUS Status, const PearMemory::Result* Primary = nullptr) {
  PearSourceReady.store(false, std::memory_order_release);
  PearSourceStatus.store(Status, std::memory_order_release);
  if (Primary) PearRecordPrimary(*Primary);
  if (CTX) {
    const auto ActualPrimary = PearMemory::GetOriginalAttachFailure(CTX.get());
    if (ActualPrimary.Status != PEAR_FEX_UNAVAILABLE) PearRecordPrimary(ActualPrimary);
    if (PearMemory::CleanupWasAttempted(CTX.get()))
      PearRecordCleanup(PearMemory::GetCleanupOutcome(CTX.get()));
    // Core verifies the actual matching bootstrap/native-idle while Context
    // stays alive, detaches dispatcher/source buffers, drains retirement while
    // registered, and observes UNREGISTER before source-bound release proof.
    // Any refused/unknown step retains the actual Context and first failure.
    PearMemory::Result ConstructionCleanup {};
    const bool Cleaned = CTX->PreparePearConstructionCleanup(ConstructionCleanup);
    PearRecordCleanup(ConstructionCleanup);
    if (!Cleaned || !ConstructionCleanup || !PearMemory::SourceContextCanRelease(CTX.get())) return;
  }
  Context::HandlerConfig.reset();
  CPUFeatures.reset(); ImageTracker.reset(); InvalidationTracker.reset();
  CTX.reset();
}
#endif

void BTCpuProcessInit() {
#ifdef PEAR_FEX_MEMORY_OWNER
  if (CTX || PearSourceReady.load(std::memory_order_acquire)) {
    PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
    return;
  }
#endif

  FEX::Windows::InitCRTProcess();
  FEX::Windows::SetupThreadHandlers();
  const auto ExecutablePath = FEX::Windows::GetExecutableFilePath();
  const auto ExecutableName = FEX::Windows::BaseName(ExecutablePath);
  FEX::Config::LoadConfig(fextl::string {ExecutableName}, _environ, FEX::ReadPortabilityInformation());
  FEXCore::Config::ReloadMetaLayer();
#ifdef PEAR_FEX_DARWIN
  if (!FEX::Windows::DarwinPolicy::Apply()) {
#ifdef PEAR_FEX_MEMORY_OWNER
    PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
#endif
    return;
  }
#endif
  FEX::Windows::Logging::Init();

  FEXCore::Config::Set(FEXCore::Config::CONFIG_INTERPRETER_INSTALLED, "0");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "0");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_FILENAME, ExecutablePath);
  FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_CONFIG_NAME, ExecutableName);

  FEXCore::Profiler::Init("", "");

  SignalDelegator = fextl::make_unique<FEX::DummyHandlers::DummySignalDelegator>();
  SyscallHandler = fextl::make_unique<WowSyscallHandler>();
  const auto NtDll = GetModuleHandleW(L"ntdll.dll");
  const bool IsWine = !!GetProcAddress(NtDll, "wine_get_version");
  OvercommitTracker.emplace(IsWine);

  FEX::Windows::Allocator::SetupHooks(NtDll);
  FEX::Windows::UnixLib::Init(NtDll);
#ifdef PEAR_FEX_MEMORY_OWNER
  const auto OwnerInit = PearMemory::Init(NtDll, FEX::Windows::UnixLib::GetPID());
  if (!OwnerInit) {
    PearRecordPrimary(OwnerInit); PearSourceStatus.store(PearFailureStatus(OwnerInit), std::memory_order_release);
    return;
  }
#endif
  if (FEX::Windows::UnixLib::Available()) {
    FEXCore::DiskCache::SetFileMapper(FEX::Windows::UnixLib::MapFile);
  }

  {
    auto HostFeatures =
      FEX::Windows::CPUFeatures::FetchHostFeatures(IsWine, FEXCore::HostFeatures::HostTypeEnum::Wow64, FEX::Windows::UnixLib::GetPID());
#ifdef PEAR_FEX_MEMORY_OWNER
    PearMemory::Result Created;
    CTX=FEXCore::Context::Context::CreatePearContext(HostFeatures,Created);
    if (!Created) PearRecordPrimary(Created);
#else
    CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);
#endif
  }

#ifdef PEAR_FEX_MEMORY_OWNER
  if (!CTX) { PearCleanupPartialContext(STATUS_NO_MEMORY); return; }
#endif
  CTX->SetSignalDelegator(SignalDelegator.get());
  CTX->SetSyscallHandler(SyscallHandler.get());
#ifdef PEAR_FEX_MEMORY_OWNER
  const auto Bootstrap = PearMemory::BindBootstrapContext(CTX.get());
  if (!Bootstrap) {
    const auto BootstrapStatus = PearFailureStatus(Bootstrap);
    PearCleanupPartialContext(BootstrapStatus, &Bootstrap);
    return;
  }
  const auto Registered = PearMemory::RegisterExecutor(PEAR_FEX_ROLE_NATIVE);
  if (!Registered) {
    const auto RegisterStatus = PearFailureStatus(Registered);
    PearCleanupPartialContext(RegisterStatus, &Registered);
    return;
  }
  // Actual Context bootstrap may publish only its source dispatcher. It cannot
  // reserve a shared JIT class, enter managed code or fabricate a ThreadState.
  PearMemory::Result CoreOutcome {};
  bool CoreReady {};
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
  try {
#endif
    CoreReady = CTX->InitPearCore(CoreOutcome);
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
  } catch (...) {
    PearSourceReady.store(false, std::memory_order_release);
    throw; // Preserve the actual upstream construction exception.
  }
#endif
  if (!CoreReady || !CoreOutcome) {
    const auto CoreStatus = PearFailureStatus(CoreOutcome);
    PearCleanupPartialContext(CoreStatus, &CoreOutcome);
    return;
  }
#else
  CTX->InitCore();
#endif
  Context::HandlerConfig.emplace(*CTX);
  InvalidationTracker.emplace(*CTX, Threads);
  ImageTracker.emplace(*CTX, false);

  auto MainModule = reinterpret_cast<__TEB*>(NtCurrentTeb())->Peb->ImageBaseAddress;
  HandleImageMap(reinterpret_cast<uint64_t>(MainModule), true);

  auto NtDllX86 = reinterpret_cast<SYSTEM_DLL_INIT_BLOCK*>(GetProcAddress(NtDll, "LdrSystemDllInitBlock"))->ntdll_handle;
  HandleImageMap(NtDllX86);

  CPUFeatures.emplace(*CTX);

  // Allocate the syscall/unixcall trampolines in the lower 2GB of the address space
  SIZE_T Size = 4;
  void* Addr = nullptr;
#ifdef PEAR_FEX_MEMORY_OWNER
  // Low guest INT2E bytes remain NX data. Actual low-address admission is a later gate.
  const NTSTATUS GuestDataStatus = NtAllocateVirtualMemory(NtCurrentProcess(), &Addr,
      (1U << 31) - 1, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (GuestDataStatus || !Addr || Size < 4) {
    PearCleanupPartialContext(GuestDataStatus ? GuestDataStatus : STATUS_NOT_SUPPORTED);
    return;
  }
#else
  NtAllocateVirtualMemory(NtCurrentProcess(), &Addr, (1U << 31) - 1, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#endif
  InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Addr), Size, PAGE_EXECUTE);
  *reinterpret_cast<uint32_t*>(Addr) = 0x2ecd2ecd;
  BridgeInstrs::Syscall = Addr;
  BridgeInstrs::UnixCall = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(Addr) + 2);

  const auto Sym = GetProcAddress(NtDll, "__wine_unix_call_dispatcher");
  if (Sym) {
    WineUnixCall = *reinterpret_cast<decltype(WineUnixCall)*>(Sym);
  }

  FEX::Windows::SetupEnvironmentVariableValues(NtDll);

  // wow64.dll will only initialise the cross-process queue if this is set
  GetTLS().Wow64Info().CpuFlags = WOW64_CPUFLAGS_SOFTWARE;

  FEX_CONFIG_OPT(ProfileStats, PROFILESTATS);
  FEX_CONFIG_OPT(StartupSleep, STARTUPSLEEP);
  FEX_CONFIG_OPT(StartupSleepProcName, STARTUPSLEEPPROCNAME);

  if (IsWine && ProfileStats()) {
    StatAllocHandler = fextl::make_unique<FEX::Windows::StatAlloc>(FEXCore::SHMStats::AppType::WIN_WOW64);
  }

  if (StartupSleep() && (StartupSleepProcName().empty() || ExecutableName == StartupSleepProcName())) {
    LogMan::Msg::IFmt("[{}][{}] Sleeping for {} seconds", GetCurrentProcessId(), ExecutableName, StartupSleep());
    std::this_thread::sleep_for(std::chrono::seconds(StartupSleep()));
  }
#ifdef PEAR_FEX_MEMORY_OWNER
  PearSourceStatus.store(STATUS_SUCCESS, std::memory_order_release);
  PearSourceReady.store(true, std::memory_order_release);
#endif
}

void BTCpuProcessTerm(HANDLE Handle, BOOL After, ULONG Status) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return;
#endif
}

void BTCpuThreadInit() {
#ifdef PEAR_FEX_MEMORY_OWNER

  if (!PearSourceReady.load(std::memory_order_acquire) || !CTX) {
    PearSourceReady.store(false, std::memory_order_release); PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release); return;
  }
  PearThreadPreparation Preparation;
  if (!Preparation) {
    PearSourceReady.store(false, std::memory_order_release); PearSourceStatus.store(Preparation.Status(), std::memory_order_release); return;
  }

  static constexpr size_t DefaultWow64CS {4};
  const auto TLS = GetTLS();
  if (TLS.ThreadState() || GetCpuArea()) {
    PearSourceReady.store(false, std::memory_order_release); PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release); return;
  }
  FEX::Windows::InitCRTThread();
  PearMemory::Result ThreadOutcome {}, ThreadCleanup {};
  bool ThreadCleanupAttempted {};
  FEXCore::Core::InternalThreadState* Thread {};
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
  try {
#endif
    Thread = CTX->CreatePearThread(nullptr, ThreadOutcome, &ThreadCleanup, &ThreadCleanupAttempted);
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
  } catch (...) {
    PearSourceReady.store(false, std::memory_order_release);
    throw; // Keep the original exception and native result history unchanged.
  }
#endif
  // Core binds/registers this actual state before InitializeCompiler and
  // retains/quarantines any source object with unresolved owner registration.
  if (!Thread || !ThreadOutcome) {
    PearRecordPrimary(ThreadOutcome);
    // An explicit cleanup failure may itself return UNAVAILABLE. Preserve the
    // actual Core attempted flag even after a clean binding was released.
    if (ThreadCleanupAttempted)
      PearRecordCleanup(ThreadCleanup);
    const auto ThreadStatus = PearFailureStatus(ThreadOutcome);
    PearSourceReady.store(false, std::memory_order_release);
    PearSourceStatus.store(ThreadStatus, std::memory_order_release);
    return;
  }

  // Default segment setup.
  auto Frame = Thread->CurrentFrame;
  auto NewSegments = new FEXCore::Core::CPUState::gdt_segment[32]();

  // Setup initial code-segment GDT
  auto& GDT = NewSegments[DefaultWow64CS];
  FEXCore::Core::CPUState::SetGDTBase(&GDT, 0);
  FEXCore::Core::CPUState::SetGDTLimit(&GDT, 0xF'FFFFU);
  GDT.L = 0; // L = Long Mode = 32-bit
  GDT.D = 1; // D = Default Operand Size = 32-bit

  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &NewSegments[0];
  // TODO: LDTs are currently unsupported, mirror them to GDT.
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &NewSegments[0];

  Frame->State.cs_idx = DefaultWow64CS << 3;
  Frame->State.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(GDT);

  FEX::Windows::CallRetStack::InitializeThread(Thread);



  Thread->FrontendPtr = new FrontendThreadData(Thread);

  bool Published {};
  {
    std::scoped_lock Lock(ThreadCreationMutex);
    const auto TID = Preparation.ID();
    if (!Threads.contains(TID) && !TLS.ThreadState() && !GetCpuArea()) {
      Threads.emplace(TID, Thread);
      if (StatAllocHandler) Thread->ThreadStats = StatAllocHandler->AllocateSlot(TID);
      GetCpuArea() = &static_cast<FrontendThreadData*>(Thread->FrontendPtr)->CpuArea;
      TLS.ThreadState() = Thread;
      Published = true;
    }
  }
  if (!Published) {
    // The actual constructed state remains retained pending reviewed cleanup.
    PearSourceReady.store(false, std::memory_order_release); PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release); return;
  }
  Preparation.Commit();
#else

  static constexpr size_t DefaultWow64CS {4};
  std::scoped_lock Lock(ThreadCreationMutex);
  FEX::Windows::InitCRTThread();
  auto* Thread = CTX->CreateThread();

  // Default segment setup.
  auto Frame = Thread->CurrentFrame;
  auto NewSegments = new FEXCore::Core::CPUState::gdt_segment[32]();

  // Setup initial code-segment GDT
  auto& GDT = NewSegments[DefaultWow64CS];
  FEXCore::Core::CPUState::SetGDTBase(&GDT, 0);
  FEXCore::Core::CPUState::SetGDTLimit(&GDT, 0xF'FFFFU);
  GDT.L = 0; // L = Long Mode = 32-bit
  GDT.D = 1; // D = Default Operand Size = 32-bit

  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &NewSegments[0];
  // TODO: LDTs are currently unsupported, mirror them to GDT.
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &NewSegments[0];

  Frame->State.cs_idx = DefaultWow64CS << 3;
  Frame->State.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(GDT);

  FEX::Windows::CallRetStack::InitializeThread(Thread);

  const auto TLS = GetTLS();
  TLS.ThreadState() = Thread;

  Thread->FrontendPtr = new FrontendThreadData(Thread);

  auto ThreadTID = GetCurrentThreadId();
  Threads.emplace(ThreadTID, Thread);
  if (StatAllocHandler) {
    Thread->ThreadStats = StatAllocHandler->AllocateSlot(ThreadTID);
  }
#endif
}

void BTCpuThreadTerm(HANDLE Thread, LONG ExitCode) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return;
#endif

  if (!FEX::Windows::ValidateHandleAccess(Thread, THREAD_TERMINATE)) {
    return;
  }

  auto ThreadDup = FEX::Windows::DupHandle(Thread, THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME);

  THREAD_BASIC_INFORMATION Info;
  if (auto Err = NtQueryInformationThread(*ThreadDup, ThreadBasicInformation, &Info, sizeof(Info), nullptr); Err) {
    return;
  }

  const auto ThreadTID = reinterpret_cast<uint64_t>(Info.ClientId.UniqueThread);
  bool Self = ThreadTID == GetCurrentThreadId();
  if (!Self) {
    // If we are suspending a thread that isn't ourselves, try to suspend it first so we know internal JIT locks aren't being held.
    RtlWow64SuspendThread(*ThreadDup, NULL);
  }

  auto [Err, TLS] = GetThreadTLS(*ThreadDup);
  if (Err) {
    return;
  }

  {
    std::scoped_lock Lock(ThreadCreationMutex);
    auto it = Threads.find(ThreadTID);
    if (it == Threads.end()) {
      // Thread already terminated
      return;
    }

    Threads.erase(it);
    if (StatAllocHandler) {
      StatAllocHandler->DeallocateSlot(TLS.ThreadState()->ThreadStats);
    }
  }
  auto ThreadState = TLS.ThreadState();

  delete GetFrontendThreadData(ThreadState);

  // GDT and LDT are mirrored, only free one.
  delete[] ThreadState->CurrentFrame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT];

  FEX::Windows::CallRetStack::DestroyThread(ThreadState);
  CTX->DestroyThread(ThreadState);
  if (Self) {
    FEX::Windows::DeinitCRTThread();
  }
}

void* BTCpuGetBopCode() {
#ifdef PEAR_FEX_MEMORY_OWNER
  if (!PearSourceReady.load(std::memory_order_acquire) || true) {
    PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release); return nullptr;
  }
#endif

  return BridgeInstrs::Syscall;
}

void* __wine_get_unix_opcode() {
#ifdef PEAR_FEX_MEMORY_OWNER
  if (!PearSourceReady.load(std::memory_order_acquire) || true) {
    PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release); return nullptr;
  }
#endif

  return BridgeInstrs::UnixCall;
}

NTSTATUS BTCpuGetContext(HANDLE Thread, HANDLE Process, void* Unknown, WOW64_CONTEXT* Context) {
#ifdef PEAR_FEX_MEMORY_OWNER
  if (!PearSourceReady.load(std::memory_order_acquire) || true) {
    PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release); return STATUS_NOT_SUPPORTED;
  }
#endif

  return RtlWow64GetThreadContext(Thread, Context);
}

NTSTATUS BTCpuSetContext(HANDLE Thread, HANDLE Process, void* Unknown, WOW64_CONTEXT* Context) {
#ifdef PEAR_FEX_MEMORY_OWNER
  if (!PearSourceReady.load(std::memory_order_acquire) || true) {
    PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release); return STATUS_NOT_SUPPORTED;
  }
#endif

  return RtlWow64SetThreadContext(Thread, Context);
}

// .seh_pushframe doesn't restore the frame pointer, so if when unwinding from RtlCaptureContext an operation is used
// that sets SP from FP, the unwound SP value will be incorrect. Wrap RtlCaptureContext so the correct FP is immediately
// restored from the stack to prevent this.
__attribute__((naked)) void BTCpuSimulate() {
  asm(".seh_proc BTCpuSimulate;"
      "sub sp, sp, #0x390;"
      ".seh_stackalloc 0x390;"
      "stp x29, x30, [sp, #-0x10]!;"
      ".seh_save_fplr_x 16;"
      ".seh_endprologue;"
      "add x0, sp, #0x10;"
      "bl RtlCaptureContext;"
      "add x0, sp, #0x10;"
      "bl BTCpuSimulateImpl;"
      "ldp x29, x30, [sp], 0x10;"
      "add sp, sp, #0x390;"
      "ret;"
      ".seh_endproc;");
}

extern "C" void BTCpuSimulateImpl(CONTEXT* entry_context) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return;
#endif

  const auto TLS = GetTLS();
  TLS.EntryContext() = entry_context;
  TLS.CachedCallRetSp() = TLS.ThreadState()->CurrentFrame->State.callret_sp;

  Context::LockJITContext();
  CTX->ExecuteThread(TLS.ThreadState());
  Context::UnlockJITContext();
}

NTSTATUS BTCpuSuspendLocalThread(HANDLE Thread, ULONG* Count) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return STATUS_NOT_SUPPORTED;
#endif

  return NtSuspendThread(Thread, Count);
}

// Returns true if exception dispatch should be halted and the execution context restored to Ptrs->Context
bool BTCpuResetToConsistentStateImpl(EXCEPTION_POINTERS* Ptrs) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return false;
#endif

  auto* Context = Ptrs->ContextRecord;
  auto* Exception = Ptrs->ExceptionRecord;
  auto Thread = GetTLS().ThreadState();
  FEXCORE_PROFILE_ACCUMULATION(Thread, AccumulatedSignalTime);

  if (Exception->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    const auto FaultAddress = static_cast<uint64_t>(Exception->ExceptionInformation[1]);

    if (FEX::Windows::CallRetStack::HandleAccessViolation(Thread, FaultAddress, Context->X25)) {
      return true;
    }

    if (OvercommitTracker && OvercommitTracker->HandleAccessViolation(FaultAddress)) {
      return true;
    }

    if (FEX::Windows::JITGuardPage::HandleJITGuardPage(Thread, reinterpret_cast<void*>(FaultAddress), Context->X,
                                                       reinterpret_cast<__uint128_t*>(Context->V), &Context->Pc)) {
      return true;
    }

    if (Thread) {
      std::scoped_lock Lock(ThreadCreationMutex);
      FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSMCCount, 1);
      if (InvalidationTracker->HandleRWXAccessViolation(Thread, Context->Pc, FaultAddress)) {
        if (CTX->IsAddressInCodeBuffer(Thread, Context->Pc) && !CTX->IsCurrentBlockSingleInst(Thread) &&
            CTX->IsAddressInCurrentBlock(Thread, FaultAddress & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::Utils::FEX_PAGE_SIZE)) {
          Context::ReconstructThreadState(Context);
          LogMan::Msg::DFmt("Handled inline self-modifying code: pc: {:X} rip: {:X} fault: {:X}", Context->Pc,
                            Thread->CurrentFrame->State.rip, FaultAddress);

          // Adjust context to return to the dispatcher, reloading SRA from thread state
          const auto& Config = SignalDelegator->GetConfig();
          Context->Pc = Config.AbsoluteLoopTopAddressFillSRA;
          Context->X1 = 1; // Set ENTRY_FILL_SRA_SINGLE_INST_REG to force a single step
        } else {
          LogMan::Msg::DFmt("Handled self-modifying code: pc: {:X} fault: {:X}", Context->Pc, FaultAddress);
        }
        return true;
      }
    }
  }

  if (!Thread || !IsAddressInJit(Context->Pc)) {
    return false;
  }

  if (Exception->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION && Context::HandleSuspendInterrupt(Context)) {
    LogMan::Msg::DFmt("Resumed from suspend");
    return true;
  }

  FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSIGBUSCount, 1);
  if (Exception->ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT && Context::HandleUnalignedAccess(Context)) {
    LogMan::Msg::DFmt("Handled unaligned atomic: new pc: {:X}", Context->Pc);
    return true;
  }

  LogMan::Msg::DFmt("Reconstructing context");

  WOW64_CONTEXT* WowContext = Context::ReconstructWowContext(Context);
  LogMan::Msg::DFmt("pc: {:X} eip: {:X} code: {:X}", Context->Pc, WowContext->Eip, Exception->ExceptionCode);

  auto& Fault = Thread->CurrentFrame->SynchronousFaultData;
  BOOL FirstChance = TRUE;
  EXCEPTION_RECORD GuestException =
    FEX::Windows::HandleGuestException(Fault, *Exception, WowContext->Eip, WowContext->Eax, WowContext->Ecx, FirstChance);
  if (GuestException.ExceptionCode == EXCEPTION_SINGLE_STEP) {
    WowContext->EFlags &= ~(1 << FEXCore::X86State::RFLAG_TF_RAW_LOC);
  }
  // wow64.dll will handle adjusting PC in the dispatched context after a breakpoint

  Context::UnlockJITContext();
  NtRaiseException(&GuestException, GetTLS().EntryContext(), FirstChance);
  return false;
}

NTSTATUS BTCpuResetToConsistentState(EXCEPTION_POINTERS* Ptrs) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return STATUS_NOT_SUPPORTED;
#endif

  if (BTCpuResetToConsistentStateImpl(Ptrs)) {
    NtContinue(Ptrs->ContextRecord, FALSE);
  }

  return STATUS_SUCCESS;
}

void BTCpuFlushInstructionCache2(const void* Address, SIZE_T Size) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return;
#endif

  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpuFlushInstructionCacheHeavy(const void* Address, SIZE_T Size) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return;
#endif

  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpuNotifyMemoryDirty(void* Address, SIZE_T Size) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return;
#endif

  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpuNotifyMemoryAlloc(void* Address, SIZE_T Size, ULONG Type, ULONG Prot, BOOL After, ULONG Status) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return;
#endif

  if (!After) {
    ThreadCreationMutex.lock();
  } else {
    // MEM_RESET(_UNDO) ignores the passed permissions
    if (!Status && !(Type & (MEM_RESET | MEM_RESET_UNDO))) {
      InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), Prot);
    }
    ThreadCreationMutex.unlock();
  }
}

void BTCpuNotifyMemoryProtect(void* Address, SIZE_T Size, ULONG NewProt, BOOL After, ULONG Status) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return;
#endif

  if (!After) {
    ThreadCreationMutex.lock();
  } else {
    if (!Status) {
      InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), NewProt);
    }
    ThreadCreationMutex.unlock();
  }
}

void BTCpuNotifyMemoryFree(void* Address, SIZE_T Size, ULONG FreeType, BOOL After, ULONG Status) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return;
#endif

  if (!After) {
    ThreadCreationMutex.lock();
  } else {
    if (!Status) {
      InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), true);
    }
    ThreadCreationMutex.unlock();
  }
}

NTSTATUS BTCpuNotifyMapViewOfSection(void* Unk1, void* Address, void* Unk2, SIZE_T Size, ULONG AllocType, ULONG Prot) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return STATUS_NOT_SUPPORTED;
#endif

  std::scoped_lock Lock(ThreadCreationMutex);
  HandleImageMap(reinterpret_cast<uint64_t>(Address));
  return STATUS_SUCCESS;
}

void BTCpuNotifyUnmapViewOfSection(void* Address, BOOL After, ULONG Status) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return;
#endif

  if (!After) {
    ThreadCreationMutex.lock();
    auto [Start, Size] = InvalidationTracker->InvalidateContainingSection(reinterpret_cast<uint64_t>(Address), true);
    if (Size) {
      HandleImageUnmap(Start, Size);
    }
  } else {
    ThreadCreationMutex.unlock();
  }
}

void BTCpuNotifyReadFile(HANDLE Handle, void* Address, SIZE_T Size, BOOL After, NTSTATUS Status) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return;
#endif

  auto* ThreadState = GetTLS().ThreadState();
  if (!InvalidationTracker || !ThreadState) {
    return;
  }

  // See arm64ec `BTCpu64NotifyReadFile` for why this like this.
  if (After && Status == STATUS_SUCCESS) {
    std::scoped_lock Lock(ThreadCreationMutex);
    InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
  }
}

void BTCpuNotifyProcessExecuteFlagsChange(ULONG Flags) {
#ifdef PEAR_FEX_MEMORY_OWNER
  // Delivered/source notification behavior is unqualified in this profile.
  PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release);
  return;
#endif

  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->HandleProcessExecuteFlagsChange(Flags);
}

BOOLEAN WINAPI BTCpuIsProcessorFeaturePresent(UINT Feature) {
#ifdef PEAR_FEX_MEMORY_OWNER
  if (!PearSourceReady.load(std::memory_order_acquire) || !CPUFeatures) {
    PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release); return FALSE;
  }
#endif

  return CPUFeatures->IsFeaturePresent(Feature) ? TRUE : FALSE;
}

void BTCpuUpdateProcessorInformation(SYSTEM_CPU_INFORMATION* Info) {
#ifdef PEAR_FEX_MEMORY_OWNER
  if (!PearSourceReady.load(std::memory_order_acquire) || !CPUFeatures || !Info) {
    PearSourceStatus.store(STATUS_NOT_SUPPORTED, std::memory_order_release); return;
  }
#endif

  CPUFeatures->UpdateInformation(Info);
}
